"""What every backend shares: reading the job, talking to the service, exiting.

A backend is the command a verb of the reference shim runs. It turns one job —
the prompt, `params.json`, `options.json` and the inputs in `in/` — into one
call to a service, and the service's answer into the declared files in
`out/`. It runs in the job's directory with the shim's minimal environment, so
everything it needs beyond the job (the service's address, a model directory)
comes from fixed arguments in the shim's configuration, never from the caller.

It exits with the shim's vocabulary: 0 with every required file written, 65
when the job asked for something the service cannot do, 75 when the service
is out of memory or busy and the same job may succeed later, and anything else
for a fault of the service or of this command.
"""

from __future__ import annotations

import argparse
import base64
import http.client
import json
import os
import secrets
import sys
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, NoReturn

EX_DATAERR = 65
EX_TEMPFAIL = 75
EX_SOFTWARE = 70

# What one reply from a service may be. A base64 reply carrying four
# 1536-pixel PNGs is well under it.
MAX_REPLY_BYTES = 256 * 1024 * 1024
MAX_PROMPT_BYTES = 64 * 1024


class Invalid(Exception):
    """The job asks for something this service cannot do."""


class Busy(Exception):
    """The service is out of memory or occupied; the job may succeed later."""


class Broken(Exception):
    """The service or this command failed."""


def run(main: Any) -> NoReturn:
    """Run a backend's `main`, mapping what it raises onto the exit codes."""
    try:
        main()
    except Invalid as error:
        say(f"invalid input: {error}")
        sys.exit(EX_DATAERR)
    except Busy as error:
        say(f"service busy: {error}")
        sys.exit(EX_TEMPFAIL)
    except Broken as error:
        say(f"failed: {error}")
        sys.exit(EX_SOFTWARE)
    sys.exit(0)


def say(text: str) -> None:
    """A line in the job's own log, which the shim removes with the job."""
    print(text, file=sys.stderr, flush=True)


# --------------------------------------------------------------------------
# The job
# --------------------------------------------------------------------------


def arguments(description: str, *extra: tuple[str, dict[str, Any]]) -> argparse.Namespace:
    """The fixed arguments every backend takes, plus its own."""
    parser = argparse.ArgumentParser(description=description)
    parser.add_argument("--service", required=True, help="the service's base URL, fixed in the shim's configuration")
    parser.add_argument("--prompt", default="")
    parser.add_argument("--params", required=True)
    parser.add_argument("--options", required=True)
    parser.add_argument("--out", required=True)
    for flag, settings in extra:
        parser.add_argument(flag, **settings)
    return parser.parse_args()


def read_json(path: str) -> dict[str, Any]:
    with open(path, "rb") as handle:
        document = json.loads(handle.read(1024 * 1024))
    if not isinstance(document, dict):
        raise Broken(f"{os.path.basename(path)} is not an object")
    return document


def params(path: str, allowed: tuple[str, ...]) -> dict[str, int]:
    """The job's params, refusing any this backend cannot honour.

    A job generated without a parameter its caller set is a job generated
    wrong, so a param the service has no use for is invalid, not ignored.
    """
    document = read_json(path)
    unknown = sorted(set(document) - set(allowed))
    if unknown:
        raise Invalid(f"this service takes no {', '.join(unknown)}")
    return {k: v for k, v in document.items() if isinstance(v, int) and not isinstance(v, bool)}


def options(path: str, schema: dict[str, Any]) -> dict[str, Any]:
    """The job's options, each checked against `schema`.

    A schema entry is a type (`bool`, `str`), a `(low, high)` pair of numbers,
    a `Choice` of allowed values, or a `Subset` of them for a list. Unknown
    options are refused for the same reason unknown params are.
    """
    document = read_json(path)
    unknown = sorted(set(document) - set(schema))
    if unknown:
        raise Invalid(f"unknown options: {', '.join(unknown)}")
    checked: dict[str, Any] = {}
    for key, value in document.items():
        rule = schema[key]
        if isinstance(rule, Subset):
            if (
                not isinstance(value, list)
                or not all(v in rule.values for v in value)
                or len(set(map(str, value))) != len(value)
            ):
                raise Invalid(f"{key} must be a list of distinct values from {', '.join(map(str, rule.values))}")
        elif isinstance(rule, Choice):
            if value not in rule.values or isinstance(value, bool) != any(isinstance(v, bool) for v in rule.values):
                raise Invalid(f"{key} must be one of {', '.join(map(str, rule.values))}")
        elif rule is bool:
            if not isinstance(value, bool):
                raise Invalid(f"{key} must be true or false")
        elif rule is str:
            if not isinstance(value, str) or len(value.encode()) > MAX_PROMPT_BYTES or "\0" in value:
                raise Invalid(f"{key} must be a string of at most {MAX_PROMPT_BYTES} bytes")
        elif isinstance(rule, tuple):
            low, high = rule
            if isinstance(value, bool) or not isinstance(value, (int, float)) or not low <= value <= high:
                raise Invalid(f"{key} must be a number from {low} to {high}")
        else:
            raise Broken(f"no rule for option {key}")
        checked[key] = value
    return checked


class Choice:
    def __init__(self, *values: Any) -> None:
        self.values = values


class Subset(Choice):
    pass


def within(name: str, value: int | None, low: int, high: int, default: int | None) -> int | None:
    if value is None:
        return default
    if not low <= value <= high:
        raise Invalid(f"{name} must be from {low} to {high}")
    return value


def a_seed(value: int | None) -> int:
    """The caller's seed, or a fresh one; never the same default for everyone."""
    if value is None:
        return secrets.randbelow(2**31)
    if value >= 2**63:
        raise Invalid("seed must be below 2^63")
    return value


def input_file(name: str) -> tuple[str, bytes] | None:
    """An input the shim wrote to `in/<name>.<ext>`, as (extension, bytes)."""
    directory = "in"
    if not os.path.isdir(directory):
        return None
    for entry in sorted(os.listdir(directory)):
        stem, _, extension = entry.partition(".")
        if stem == name:
            with open(os.path.join(directory, entry), "rb") as handle:
                return extension, handle.read()
    return None


def require_input(name: str) -> tuple[str, bytes]:
    found = input_file(name)
    if found is None:
        raise Invalid(f"the {name} input is required")
    return found


def write_output(out: str, name: str, data: bytes) -> None:
    """Write one declared output whole, or not at all: a reader never sees half."""
    if "/" in name or name in (".", ".."):
        raise Broken(f"refusing output name {name!r}")
    partial = os.path.join(out, f".{name}.part")
    with open(partial, "wb") as handle:
        handle.write(data)
    os.replace(partial, os.path.join(out, name))


def progress(out: str, permille: int) -> None:
    """The verb's progress file, which the shim reports while the job runs."""
    try:
        write_output(out, "progress", str(max(0, min(999, permille))).encode())
    except OSError:
        pass


# --------------------------------------------------------------------------
# The service
# --------------------------------------------------------------------------


class NoRedirect(urllib.request.HTTPRedirectHandler):
    """A service that redirects is answering a question it was not asked."""

    def redirect_request(self, *_args: Any, **_kwargs: Any) -> None:
        return None


OPENER = urllib.request.build_opener(NoRedirect, urllib.request.ProxyHandler({}))


class Service:
    """One service, at the base URL fixed in the shim's configuration."""

    def __init__(self, base: str) -> None:
        parsed = urllib.parse.urlsplit(base)
        if parsed.scheme not in ("http", "https") or not parsed.hostname or parsed.query or parsed.fragment:
            raise Broken("--service must be an http(s) base URL")
        self.base = base.rstrip("/")

    def url(self, path: str, query: dict[str, str] | None = None) -> str:
        if not path.startswith("/") or "//" in path or "/../" in path + "/":
            raise Broken(f"refusing path {path!r}")
        text = self.base + urllib.parse.quote(path, safe="/=:")
        if query:
            text += "?" + urllib.parse.urlencode(query)
        return text

    def request(
        self,
        method: str,
        path: str,
        body: bytes | None = None,
        content_type: str = "application/json",
        timeout: float = 30,
        query: dict[str, str] | None = None,
        limit: int = MAX_REPLY_BYTES,
    ) -> tuple[int, bytes]:
        """One request; the status and a bounded body, errors included."""
        headers = {"Accept": "*/*"}
        if body is not None:
            headers["Content-Type"] = content_type
        request = urllib.request.Request(self.url(path, query), data=body, method=method, headers=headers)
        try:
            with OPENER.open(request, timeout=timeout) as response:
                return response.status, read_bounded(response, limit)
        except urllib.error.HTTPError as error:
            return error.code, read_bounded(error, 64 * 1024)
        except (urllib.error.URLError, http.client.HTTPException, OSError) as error:
            raise Broken(f"{method} {path}: {error}") from error

    def json(self, method: str, path: str, document: Any = None, timeout: float = 30, ok: tuple[int, ...] = (200,)) -> Any:
        body = None if document is None else json.dumps(document).encode()
        status, data = self.request(method, path, body, timeout=timeout)
        if status not in ok:
            raise for_status(status, data, f"{method} {path}")
        try:
            return json.loads(data)
        except ValueError as error:
            raise Broken(f"{method} {path}: the reply is not JSON") from error


def read_bounded(response: Any, limit: int) -> bytes:
    data = response.read(limit + 1)
    if len(data) > limit:
        raise Broken("the service's reply is larger than this backend accepts")
    return data


def for_status(status: int, data: bytes, what: str) -> Exception:
    """What a service's error status means for the job."""
    detail = data[:400].decode("utf-8", "replace")
    if status in (400, 404, 413, 422):
        return Invalid(f"{what}: {status} {detail}")
    if status in (503, 507, 429):
        return Busy(f"{what}: {status} {detail}")
    return Broken(f"{what}: {status} {detail}")


def json_body(document: Any) -> bytes:
    return json.dumps(document).encode()


def b64(data: bytes) -> str:
    return base64.b64encode(data).decode()


def check_magic(data: bytes, kind: str) -> None:
    """The bytes are what the part's media type says, or the job fails."""
    signatures = {
        "png": lambda d: d.startswith(b"\x89PNG\r\n\x1a\n"),
        "webp": lambda d: d[:4] == b"RIFF" and d[8:12] == b"WEBP",
        "glb": lambda d: d.startswith(b"glTF"),
        "flac": lambda d: d.startswith(b"fLaC"),
        "wav": lambda d: d[:4] == b"RIFF" and d[8:12] == b"WAVE",
        "mp4": lambda d: d[4:8] == b"ftyp",
    }
    if not signatures[kind](data):
        raise Broken(f"the service returned something that is not {kind}")
