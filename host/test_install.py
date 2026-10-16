#!/usr/bin/env python3
"""Tests for the host kit: the install script and its forced-command shim.

Run with `python3 host/test_install.py`. No network, no SSH, no Docker, no
root: every tool the script would call is a stub on PATH that records its
arguments, and the router is a stub `curl` that answers from a script.

The shim is the security boundary on the slave — the one program the fleet
agent's key may run — so most of these tests are about what it refuses.
"""

from __future__ import annotations

import json
import os
import shlex
import shutil
import stat
import subprocess
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
SCRIPT = HERE / "install.sh"
TOKEN = "0123456789abcdef" * 4
AGENT_KEY = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAINaR4JuJGhj5Y/y0fV0dwnAAHCoxBRNiBi5JkRlcQU2M"
HOST_KEY = AGENT_KEY + " root@rig"
# dash by default, the strictest common /bin/sh. HYPELLM_TEST_SH and
# HYPELLM_TEST_AWK run the same suite under another shell or awk.
SH = os.environ.get("HYPELLM_TEST_SH") or shutil.which("dash") or "/bin/sh"
AWK = os.environ.get("HYPELLM_TEST_AWK")

# The tools the script and the shim use from the system. Linked into a private
# PATH so a test controls exactly what exists.
BASICS = [
    "awk", "sed", "grep", "uname", "id", "cut", "tr", "head", "tail", "cat",
    "mkdir", "chmod", "mv", "touch", "openssl", "getent", "basename", "rm",
    "printf", "sh",
]


def shim_source() -> str:
    text = SCRIPT.read_text()
    start = text.index("<<'SHIM'\n") + len("<<'SHIM'\n")
    end = text.index("\nSHIM\n", start)
    return text[start:end] + "\n"


def stub(directory: Path, name: str, body: str) -> None:
    path = directory / name
    # Replace a linked system tool rather than writing through the link.
    if path.is_symlink():
        path.unlink()
    path.write_text("#!/bin/sh\n" + body)
    path.chmod(0o755)


def recording_stub(directory: Path, name: str) -> None:
    # One argument per line, so a test compares argument vectors exactly.
    stub(directory, name, f'printf "%s\\n" {name} "$@" > "$RECORD"\n')


def basics(directory: Path) -> None:
    for tool in BASICS:
        found = AWK if tool == "awk" and AWK else shutil.which(tool)
        if found:
            (directory / tool).symlink_to(found)


class ShimTest(unittest.TestCase):
    """The forced command: parse without a shell, then allow a fixed list."""

    def setUp(self) -> None:
        self.dir = Path(tempfile.mkdtemp(prefix="hypellm-shim-"))
        self.bin = self.dir / "bin"
        self.bin.mkdir()
        basics(self.bin)
        for name in ("df", "nvidia-smi", "docker", "curl", "mkdir"):
            recording_stub(self.bin, name)
        # Where the installer puts it: the shim finds the data directory from
        # its own path, so the tests run it from the same place.
        self.data = self.dir / "data"
        (self.data / "bin").mkdir(parents=True)
        self.shim = self.data / "bin" / "hypellm-host-shim"
        self.shim.write_text(shim_source())
        self.shim.chmod(0o755)
        self.record = self.dir / "record"
        self.marker = self.dir / "pwned"

    def tearDown(self) -> None:
        shutil.rmtree(self.dir, ignore_errors=True)

    def run_shim(self, command: str) -> tuple[int, list[str] | None, str]:
        if self.record.exists():
            self.record.unlink()
        completed = subprocess.run(
            [SH, str(self.shim)],
            env={
                "PATH": str(self.bin),
                "SSH_ORIGINAL_COMMAND": command,
                "RECORD": str(self.record),
            },
            capture_output=True,
            text=True,
            timeout=10,
        )
        ran = self.record.read_text().split("\n")[:-1] if self.record.exists() else None
        return completed.returncode, ran, completed.stderr

    def assert_runs(self, argv: list[str], expected: list[str] | None = None) -> None:
        code, ran, err = self.run_shim(shlex.join(argv))
        self.assertEqual(code, 0, f"{argv}: {err}")
        self.assertEqual(ran, expected or argv)

    def assert_refused(self, command: str) -> None:
        code, ran, err = self.run_shim(command)
        self.assertEqual(code, 126, f"{command!r} was not refused")
        self.assertIsNone(ran, f"{command!r} ran {ran}")
        self.assertIn("hypellm-host-shim: refused", err)
        self.assertFalse(self.marker.exists(), f"{command!r} executed an injection")

    # -- What the agent actually sends ------------------------------------

    def test_every_command_the_reference_agent_sends_is_passed_through_exactly(self) -> None:
        self.assert_runs(["df", "-B1", "--output=avail", "/home/albert/.hypellm"])
        self.assert_runs(
            ["nvidia-smi", "--query-gpu=index,memory.used,memory.total",
             "--format=csv,noheader,nounits"]
        )
        # The tab survives: it is the separator the agent splits on.
        self.assert_runs(["docker", "ps", "--format", "{{.Names}}\t{{.Status}}"])
        self.assert_runs(["docker", "start", "qwen38-27b-mtp"])
        self.assert_runs(["docker", "stop", "--timeout", "30", "qwen38-27b-mtp"])
        self.assert_runs(
            ["docker", "image", "inspect", "--format", "{{index .RepoDigests 0}}",
             "ghcr.io/ggml-org/llama.cpp:server-cuda"]
        )
        self.assert_runs(["docker", "image", "inspect", "--format", "{{.Id}}", "art-1"])
        self.assert_runs(["docker", "pull", "ghcr.io/ggml-org/llama.cpp@sha256:abc"])

    def test_a_probe_reaches_loopback_with_the_shims_own_flags(self) -> None:
        url = "http://127.0.0.1:8000/v1/models"
        self.assert_runs(
            ["curl", "-fsS", "--max-time", "5", url],
            ["curl", "--proto", "=http", "--max-redirs", "0", "-fsS", "--max-time", "10", url],
        )

    def test_a_quote_inside_an_argument_is_kept_as_a_quote(self) -> None:
        self.assert_runs(["docker", "inspect", "--format", "it's {{.Id}}", "name"])

    # -- Containers and image sync (host kit 1.1) --------------------------

    def create(self, *options: str, image: str = "llama-server:b5000") -> list[str]:
        return ["docker", "create", "--name", "hypellm-qwen", *options, image]

    def test_the_agents_container_and_sync_commands_are_passed_through_exactly(self) -> None:
        state = f"{self.data}/containers/qwen"
        self.assert_runs(["mkdir", "-p", state])
        self.assert_runs(
            self.create(
                "--label", "hypellm.template=" + "ab" * 32,
                "--gpus", "device=0",
                "-p", "192.168.1.20:8080:8080",
                "-v", f"{state}:/state",
                "-e", "LLAMA_ARG_CTX_SIZE=131072",
                "--restart", "no",
            )
            # The container's own command line follows the image and runs
            # inside the container, so it is not held to the vocabulary.
            + ["--model", "/state/model.gguf", "--port", "8080"]
        )
        self.assert_runs(["docker", "rm", "hypellm-qwen"])
        self.assert_runs(["docker", "save", "llama-server:b5000"])
        self.assert_runs(["docker", "load"])
        self.assert_runs(["docker", "load", "-q"])
        self.assert_runs(
            ["docker", "inspect", "--format",
             '{{index .Config.Labels "hypellm.template"}}', "hypellm-qwen"]
        )

    def test_a_container_cannot_be_created_with_more_than_the_vocabulary_allows(self) -> None:
        state = f"{self.data}/containers/qwen"
        for options in [
            ["--privileged"],
            ["--network", "host"],
            ["--net=host"],
            ["--pid", "host"],
            ["--cap-add", "SYS_ADMIN"],
            ["--device", "/dev/sda"],
            ["--security-opt", "seccomp=unconfined"],
            ["--user", "0"],
            ["-v", "/:/host"],
            ["-v", "/home/albert/.ssh:/ssh"],
            ["-v", f"{self.data}:/data"],
            ["-v", f"{self.data}/containers/../bin:/x"],
            ["-v", f"{self.data}/containers/qwen/../..:/x"],
            ["-v", f"{state}:/state:rw"],
            ["-v", f"{state}"],
            ["--mount", f"type=bind,src=/,dst=/host"],
            ["-p", "8080:8080"],
            ["-p", "0.0.0.0:99999:80"],
            ["--gpus", "all"],
            ["--gpus", "device=0;id"],
            ["-e", "=x"],
            ["-e", "BAD-KEY=x"],
            ["--label", "other=1"],
            ["--restart", "always"],
            ["--name"],
        ]:
            with self.subTest(options=options):
                self.assert_refused(shlex.join(self.create(*options)))
        # No name, no image, or an image that is an option.
        self.assert_refused(shlex.join(["docker", "create", "llama-server:b5000"]))
        self.assert_refused(shlex.join(["docker", "create", "--name", "x"]))

    def test_mkdir_and_rm_reach_only_a_containers_own_state_and_name(self) -> None:
        for argv in [
            ["mkdir", "-p", f"{self.data}/bin"],
            ["mkdir", "-p", f"{self.data}/containers"],
            ["mkdir", "-p", f"{self.data}/containers/.hidden"],
            ["mkdir", "-p", f"{self.data}/containers/a/b"],
            ["mkdir", "-p", "/etc/cron.d"],
            ["mkdir", "/tmp/x"],
            ["docker", "rm", "-f", "x"],
            ["docker", "rm", "-v", "x"],
            ["docker", "rm", "a", "b"],
            ["docker", "save", "-o", "/tmp/x", "image"],
            ["docker", "load", "-i", "/etc/passwd"],
        ]:
            with self.subTest(argv=argv):
                self.assert_refused(shlex.join(argv))

    def test_a_shim_outside_a_data_directory_creates_nothing(self) -> None:
        # The data directory comes from where the shim was installed. A copy
        # run from anywhere else has none, so nothing that writes to it runs.
        stray = self.dir / "hypellm-host-shim"
        stray.write_text(shim_source())
        stray.chmod(0o755)
        self.shim = stray
        self.assert_refused(shlex.join(["mkdir", "-p", f"{self.data}/containers/qwen"]))
        self.assert_runs(["docker", "ps"])

    # -- What a compromised agent might try --------------------------------

    def test_shell_syntax_in_the_raw_command_is_refused_before_anything_runs(self) -> None:
        marker = shlex.quote(str(self.marker))
        for command in [
            f"docker ps; touch {marker}",
            f"docker ps && touch {marker}",
            f"docker ps | touch {marker}",
            f"docker start $(touch {marker})",
            f"docker start `touch {marker}`",
            f"docker ps\ntouch {marker}",
            f"docker ps\rtouch {marker}",
            f"docker start x > {marker}",
            "docker  ps",
            " docker ps",
            "docker ps ",
            "docker start 'unterminated",
            "docker start \"x\"",
            "",
        ]:
            with self.subTest(command=command):
                self.assert_refused(command)

    def test_shell_syntax_quoted_as_data_still_fails_the_allowlist(self) -> None:
        # Properly quoted, these reach the allowlist as literal arguments —
        # where a container name may not hold them.
        marker = str(self.marker)
        for argv in [
            ["docker", "start", f"$(touch {marker})"],
            ["docker", "start", f"`touch {marker}`"],
            ["docker", "start", f"x;touch {marker}"],
            ["docker", "start", "-H"],
            ["docker", "pull", "--all-tags"],
        ]:
            with self.subTest(argv=argv):
                self.assert_refused(shlex.join(argv))

    def test_anything_beyond_the_fixed_list_is_refused(self) -> None:
        for argv in [
            ["sh", "-c", "id"],
            ["bash"],
            ["rm", "-rf", "/"],
            ["docker", "run", "-v", "/:/host", "alpine"],
            ["docker", "exec", "c", "sh"],
            ["docker", "--host", "tcp://evil:2375", "ps"],
            ["docker", "cp", "x:/", "/"],
            ["docker", "ps", "-a", "--format", "x"],
            ["docker", "start", "a", "b"],
            ["docker", "stop", "--timeout", "1e9", "c"],
            ["docker", "image", "rm", "x"],
            ["df", "-B1", "--output=avail", "/../etc"],
            ["df", "-h"],
            ["nvidia-smi", "-pm", "1"],
            ["nvidia-smi", "--query-gpu=index", "--format=csv"],
            ["curl", "http://evil.example/x"],
            ["curl", "-o", "/home/albert/.ssh/authorized_keys", "http://127.0.0.1:8000/"],
            ["curl", "-K", "/etc/passwd", "http://127.0.0.1:8000/"],
            ["curl", "http://127.0.0.1:8000/", "http://127.0.0.1:8001/"],
            ["curl", "http://127.0.0.1.evil.example:80/"],
            ["curl", "http://localhost:/x"],
            ["curl", "file:///etc/passwd"],
            ["curl", "-fsS"],
        ]:
            with self.subTest(argv=argv):
                self.assert_refused(shlex.join(argv))


class InstallTest(unittest.TestCase):
    """The installer: preflight first, a plan, approval, then exactly the plan."""

    def setUp(self) -> None:
        self.dir = Path(tempfile.mkdtemp(prefix="hypellm-install-"))
        self.bin = self.dir / "bin"
        self.bin.mkdir()
        basics(self.bin)
        self.home = self.dir / "home"
        self.home.mkdir()
        self.calls = self.dir / "curl-calls"
        self.host_key = self.dir / "ssh_host_ed25519_key.pub"
        self.host_key.write_text(HOST_KEY + "\n")
        stub(self.bin, "docker", 'exit 0\n')
        stub(self.bin, "sshd", 'exit 0\n')
        stub(
            self.bin,
            "nvidia-smi",
            'printf "0, NVIDIA GeForce RTX 4090, 24564\\n1, NVIDIA GeForce RTX 4090, 24564\\n"\n',
        )
        begin = json.dumps(
            {"host": "rig", "agent": "local", "agent_ssh_key": AGENT_KEY, "kit_version": "1.1.0"}
        )
        complete = json.dumps(
            {"id": "00000000000000a1", "host": "rig", "state": "registered",
             "ssh_host_key_fingerprint": "SHA256:hostkey", "device_key_fingerprint": "SHA256:device"}
        )
        # The router. Records each URL and body, answers by URL.
        stub(
            self.bin,
            "curl",
            f"""for last; do :; done
body=$(cat)
printf '%s\\n%s\\n' "$last" "$body" >> {shlex.quote(str(self.calls))}
case $last in
  *enroll:begin) printf '%s\\n200' {shlex.quote(begin)} ;;
  *enroll:complete) printf '%s\\n201' {shlex.quote(complete)} ;;
  *) printf '{{}}\\n404' ;;
esac
""",
        )

    def tearDown(self) -> None:
        shutil.rmtree(self.dir, ignore_errors=True)

    def install(self, *extra: str, path: Path | None = None) -> subprocess.CompletedProcess[str]:
        args = [
            SH, str(SCRIPT), "--router", "https://router.test", "--token", TOKEN,
            "--address", "192.168.1.20", "--ssh-host-key", str(self.host_key), *extra,
        ]
        return subprocess.run(
            args,
            env={"PATH": str(path or self.bin), "HOME": str(self.home)},
            capture_output=True,
            text=True,
            timeout=60,
            # No controlling terminal, as under `curl | sh` from a pipeline.
            start_new_session=True,
            stdin=subprocess.DEVNULL,
        )

    def posted(self) -> list[tuple[str, str]]:
        if not self.calls.exists():
            return []
        lines = self.calls.read_text().split("\n")
        return [(lines[i], lines[i + 1]) for i in range(0, len(lines) - 1, 2)]

    def data(self) -> Path:
        return self.home / ".hypellm"

    def test_a_version_the_router_does_not_serve_is_refused_before_anything(self) -> None:
        result = self.install("--version", "9.9.9", "--yes")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("serves host kit 1.1.0", result.stderr)
        self.assertEqual(self.posted(), [])

    def test_a_malformed_token_or_origin_is_refused(self) -> None:
        for args in (["--token", "short"], ["--router", "http://router.test"],
                     ["--router", "https://router.test/evil path"]):
            result = subprocess.run(
                [SH, str(SCRIPT), "--router", "https://router.test", "--token", TOKEN, *args],
                env={"PATH": str(self.bin), "HOME": str(self.home)},
                capture_output=True, text=True, timeout=30,
            )
            self.assertNotEqual(result.returncode, 0, args)
        self.assertEqual(self.posted(), [])

    def test_preflight_reports_every_missing_dependency_before_contacting_the_router(self) -> None:
        bare = self.dir / "bare"
        bare.mkdir()
        basics(bare)
        (bare / "curl").symlink_to(self.bin / "curl")
        os.unlink(bare / "openssl") if (bare / "openssl").exists() else None
        result = self.install("--yes", path=bare)
        self.assertNotEqual(result.returncode, 0)
        for missing in ("docker is not installed", "sshd is not installed", "openssl"):
            self.assertIn(missing, result.stderr)
        self.assertEqual(self.posted(), [], "the router was contacted before preflight passed")

    def test_docker_that_needs_sudo_fails_preflight(self) -> None:
        stub(self.bin, "docker", "exit 1\n")
        result = self.install("--yes")
        self.assertIn("cannot use it without sudo", result.stderr)
        self.assertFalse(self.data().exists())

    def test_without_a_terminal_it_asks_for_flags_rather_than_guessing(self) -> None:
        result = self.install()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("no terminal to ask on", result.stderr)
        self.assertFalse(self.data().exists(), "it changed something without approval")

    def test_a_dry_run_shows_the_plan_and_changes_nothing(self) -> None:
        result = self.install("--dry-run", "--data-dir", str(self.data()))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("It will:", result.stdout)
        self.assertIn("add one line to", result.stdout)
        self.assertIn(f'restrict,command="{self.data()}/bin/hypellm-host-shim" {AGENT_KEY} hypellm-agent', result.stdout)
        self.assertFalse(self.data().exists())
        self.assertFalse((self.home / ".ssh").exists())
        urls = [url for url, _ in self.posted()]
        self.assertEqual(urls, ["https://router.test/fleet/v1/enroll:begin"], "begin only")

    def test_a_hostile_data_directory_is_refused(self) -> None:
        for bad in ("relative", "/tmp/a b", "/tmp/../etc", "/tmp/$(id)"):
            result = self.install("--yes", "--data-dir", bad)
            self.assertNotEqual(result.returncode, 0, bad)
        self.assertEqual(
            [url for url, _ in self.posted() if url.endswith("complete")], [],
            "nothing registered",
        )

    def test_an_approved_install_does_exactly_the_plan_and_registers(self) -> None:
        ssh = self.home / ".ssh"
        ssh.mkdir()
        (ssh / "authorized_keys").write_text("ssh-ed25519 AAAAexisting someone@laptop\n")

        result = self.install("--yes")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("SHA256:hostkey", result.stdout)

        data = self.data()
        self.assertEqual(stat.S_IMODE(data.stat().st_mode), 0o700)
        for sub in ("bin", "containers", "state"):
            self.assertTrue((data / sub).is_dir(), sub)
        key = data / "device.key"
        self.assertEqual(stat.S_IMODE(key.stat().st_mode), 0o600)
        shim = data / "bin" / "hypellm-host-shim"
        self.assertTrue(os.access(shim, os.X_OK))
        self.assertEqual(shim.read_text(), shim_source())

        lines = (ssh / "authorized_keys").read_text().splitlines()
        self.assertIn("ssh-ed25519 AAAAexisting someone@laptop", lines, "other keys survive")
        ours = [l for l in lines if l.endswith(" hypellm-agent")]
        self.assertEqual(ours, [f'restrict,command="{shim}" {AGENT_KEY} hypellm-agent'])

        (url, body), = [c for c in self.posted() if c[0].endswith("enroll:complete")]
        report = json.loads(body)
        self.assertEqual(report["token"], TOKEN)
        self.assertEqual(report["address"], "192.168.1.20")
        self.assertEqual(report["data_dir"], str(data))
        self.assertEqual(report["ssh_host_key"], AGENT_KEY, "the host key line, without comment")
        self.assertEqual(report["kit_version"], "1.1.0")
        self.assertEqual(
            report["gpus"],
            [{"index": 0, "name": "NVIDIA GeForce RTX 4090", "memory_bytes": 24564 * 1048576},
             {"index": 1, "name": "NVIDIA GeForce RTX 4090", "memory_bytes": 24564 * 1048576}],
        )
        self.assertTrue(report["device_key"].startswith("-----BEGIN PUBLIC KEY-----\n"))
        self.assertGreater(report["memory_bytes"], 0)

        # Re-running replaces the line rather than adding a second, and keeps
        # the device key the router already pinned.
        before = key.read_bytes()
        again = self.install("--yes")
        self.assertEqual(again.returncode, 0, again.stderr)
        lines = (ssh / "authorized_keys").read_text().splitlines()
        self.assertEqual(len([l for l in lines if l.endswith(" hypellm-agent")]), 1)
        self.assertEqual(key.read_bytes(), before)

    def test_a_cpu_only_machine_registers_with_no_gpus(self) -> None:
        os.unlink(self.bin / "nvidia-smi")
        result = self.install("--yes")
        self.assertEqual(result.returncode, 0, result.stderr)
        (_, body), = [c for c in self.posted() if c[0].endswith("enroll:complete")]
        self.assertEqual(json.loads(body)["gpus"], [])


if __name__ == "__main__":
    unittest.main()
