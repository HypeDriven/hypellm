#!/usr/bin/env python3
"""audio-to-video on a MiniMax-H3 Gradio app, with its prompt conditioner.

    prompt     the shot; required
    params     duration_ms (2-6 s at 1080p, 2-14 s at 960x544; default 6 s),
               steps (1-40, default 28), seed
    options    resolution: "1080p" (default) or "960x544"
    inputs     audio (wav or flac), required; keyframe (png or webp), optional
    outputs    video.mp4

Two services, as in the deployment's own client: the conditioner encodes the
prompt (and keyframe) into a file the app reads from its conditioning cache,
which is a directory this backend can write; then the app's `generate` is
called through Gradio's queue API with the uploaded audio and keyframe.

A cancel stops this command, not a render the app has already started: Gradio
offers no cancel for a call made through its API.
"""

from __future__ import annotations

import hashlib
import json
import os
import secrets
import struct
import urllib.error
import urllib.request
from typing import Any

import _common as c

CANVAS = "960x544 · 16:9 fast"
WIDTH, HEIGHT = 960, 544
FPS, FRAMES_PER_CHUNK, LATENTS_PER_CHUNK = 24, 17, 5
# A render streams heartbeats; this is how long one read may wait between them.
READ_TIMEOUT_S = 900


def main() -> None:
    args = c.arguments(
        __doc__ or "",
        ("--conditioner", {"required": True, "help": "the conditioner's base URL"}),
        ("--cond-dir", {"required": True, "help": "the app's conditioning cache, writable here"}),
    )
    service = c.Service(args.service)
    conditioner = c.Service(args.conditioner)
    if not os.path.isabs(args.cond_dir) or not os.path.isdir(args.cond_dir):
        raise c.Broken("--cond-dir must be an existing absolute directory")
    params = c.params(args.params, ("duration_ms", "steps", "seed"))
    options = c.options(args.options, {"resolution": c.Choice("1080p", "960x544")})
    prompt = args.prompt.strip()
    if not prompt:
        raise c.Invalid("audio-to-video needs a prompt")
    hd = options.get("resolution", "1080p") == "1080p"
    duration_ms = c.within("duration_ms", params.get("duration_ms"), 2_000, 6_000 if hd else 14_000, 6_000) or 6_000
    steps = c.within("steps", params.get("steps"), 1, 40, 28) or 28
    seed = c.a_seed(params.get("seed"))
    audio_extension, audio = c.require_input("audio")
    keyframe = c.input_file("keyframe")

    c.progress(args.out, 0)
    seconds = duration_ms / 1000
    condition(conditioner, args.cond_dir, prompt, keyframe[1] if keyframe else None, snap_frames(seconds))
    c.progress(args.out, 100)

    audio_file = upload(service, "audio." + audio_extension, audio)
    keyframe_file = upload(service, "keyframe." + keyframe[0], keyframe[1]) if keyframe else None
    started = service.json("POST", "/gradio_api/call/generate", {
        "data": [prompt, keyframe_file, audio_file, CANVAS, seconds, steps, seed, False, hd],
    })
    event = started.get("event_id") if isinstance(started, dict) else None
    if not isinstance(event, str) or not event.replace("-", "").isalnum():
        raise c.Broken("Gradio did not start the call")
    result = outcome(service, event)
    path = video_path(result)
    status, data = service.request("GET", "/gradio_api/file=" + path, timeout=600)
    if status != 200:
        raise c.for_status(status, data, "GET the video")
    c.check_magic(data, "mp4")
    c.write_output(args.out, "video.mp4", data)


def snap_frames(seconds: float) -> int:
    """The frame count the app's video VAE decodes: the next 17n + 5 at 24 fps."""
    frames = max(1, round(seconds * FPS))
    while frames % FRAMES_PER_CHUNK != LATENTS_PER_CHUNK:
        frames += 1
    return frames


def cond_key(prompt: str, keyframe: bytes | None) -> str:
    """The app's cache key: the prompt, and the keyframe's bytes when there is one."""
    digest = hashlib.sha256(prompt.encode("utf-8"))
    if keyframe is not None:
        digest.update(b"|")
        digest.update(keyframe)
    return digest.hexdigest()[:32]


def condition(conditioner: c.Service, cond_dir: str, prompt: str, keyframe: bytes | None, frames: int) -> None:
    path = os.path.join(cond_dir, cond_key(prompt, keyframe) + ".safetensors")
    if os.path.isfile(path) and os.path.getsize(path) > 0:
        return
    fields = [("prompt", prompt), ("width", str(WIDTH)), ("height", str(HEIGHT)), ("num_frames", str(frames))]
    files = [("keyframe", "keyframe.png", keyframe)] if keyframe is not None else []
    body, content_type = multipart(fields, files)
    # The first encode after the conditioner starts loads its encoder.
    status, data = conditioner.request("POST", "/encode", body, content_type=content_type, timeout=900)
    if status != 200:
        raise c.for_status(status, data, "the conditioner")
    if not is_safetensors(data):
        raise c.Broken("the conditioner's reply is not a safetensors file")
    # Whole or not at all, under a name no other writer uses: the cache is
    # shared with the deployment's own client.
    partial = path + "." + secrets.token_hex(6) + ".part"
    with open(partial, "wb") as handle:
        handle.write(data)
    os.replace(partial, path)


def is_safetensors(data: bytes) -> bool:
    if len(data) < 9:
        return False
    (length,) = struct.unpack("<Q", data[:8])
    return 2 <= length <= len(data) - 8 and data[8:9] == b"{"


def upload(service: c.Service, name: str, data: bytes) -> dict[str, Any]:
    body, content_type = multipart([], [("files", name, data)])
    status, reply = service.request("POST", "/gradio_api/upload", body, content_type=content_type, timeout=300)
    if status != 200:
        raise c.for_status(status, reply, "the upload")
    try:
        paths = json.loads(reply)
    except ValueError as error:
        raise c.Broken("the upload's reply is not JSON") from error
    if not isinstance(paths, list) or len(paths) != 1 or not isinstance(paths[0], str):
        raise c.Broken("the upload's reply names no file")
    return {"path": paths[0], "orig_name": name, "meta": {"_type": "gradio.FileData"}}


def outcome(service: c.Service, event: str) -> Any:
    """Read the call's event stream to its end: the result, or its error."""
    request = urllib.request.Request(
        service.url(f"/gradio_api/call/generate/{event}"), headers={"Accept": "text/event-stream"})
    try:
        response = c.OPENER.open(request, timeout=READ_TIMEOUT_S)
    except urllib.error.HTTPError as error:
        raise c.for_status(error.code, c.read_bounded(error, 64 * 1024), "the call's events") from error
    except OSError as error:
        raise c.Broken(f"the call's events: {error}") from error
    name = None
    received = 0
    with response:
        while True:
            try:
                line = response.readline(1024 * 1024)
            except OSError as error:
                raise c.Broken(f"the call's events: {error}") from error
            if not line:
                raise c.Broken("the call's events ended without a result")
            received += len(line)
            if received > c.MAX_REPLY_BYTES:
                raise c.Broken("the call's events are larger than this backend accepts")
            text = line.decode("utf-8", "replace").rstrip("\r\n")
            if text.startswith("event:"):
                name = text[6:].strip()
            elif text.startswith("data:") and name in ("complete", "error"):
                data = text[5:].strip()
                try:
                    document = json.loads(data) if data else None
                except ValueError:
                    document = data
                if name == "error":
                    raise app_error(document)
                return document


def app_error(document: Any) -> Exception:
    text = document if isinstance(document, str) else json.dumps(document)
    lowered = text.lower()
    if "still loading" in lowered:
        return c.Busy("the app is still loading its model")
    if "out of memory" in lowered or "outofmemory" in lowered:
        return c.Busy("the app ran out of memory")
    for refusal in ("soundtrack is required", "always takes a prompt", "1080p output supports"):
        if refusal in lowered:
            return c.Invalid(text[:400])
    return c.Broken("the app failed: " + text[:400])


def video_path(result: Any) -> str:
    """The rendered file's path on the app's side, from the call's outputs."""
    if not isinstance(result, list) or not result:
        raise c.Broken("the call returned no outputs")
    video = result[0]
    if isinstance(video, dict) and isinstance(video.get("video"), dict):
        video = video["video"]
    path = video.get("path") if isinstance(video, dict) else None
    if not isinstance(path, str) or not path.endswith(".mp4") or ".." in path.split("/"):
        raise c.Broken("the call returned no video file")
    return path


def multipart(fields: list[tuple[str, str]], files: list[tuple[str, str, bytes]]) -> tuple[bytes, str]:
    boundary = "hypellm" + secrets.token_hex(16)
    body = bytearray()
    for name, value in fields:
        body += f'--{boundary}\r\nContent-Disposition: form-data; name="{name}"\r\n\r\n'.encode()
        body += value.encode() + b"\r\n"
    for name, filename, data in files:
        body += (
            f'--{boundary}\r\nContent-Disposition: form-data; name="{name}"; filename="{filename}"\r\n'
            "Content-Type: application/octet-stream\r\n\r\n"
        ).encode()
        body += data + b"\r\n"
    body += f"--{boundary}--\r\n".encode()
    return bytes(body), f"multipart/form-data; boundary={boundary}"


if __name__ == "__main__":
    c.run(main)
