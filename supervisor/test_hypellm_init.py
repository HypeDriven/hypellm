#!/usr/bin/env python3
"""Tests for the reference init.

Run with `python3 supervisor/test_hypellm_init.py`.

Not part of `cargo test --workspace`: like `agent/` and `verifier/`, this
component is deliberately outside the Rust workspace, so nothing in the build
could run it. The init itself is bash, because that is what the router's image
already has; the test is Python, because it runs on a developer's machine and
nothing about the image constrains it.

The behaviours under test are the ones that are invisible right up until a real
`docker stop` during an incident: that a signal becomes `--shutdown` rather than
a kill, that a second signal does not escalate and cut the drain the first one
started, that a router which ignores the drain is killed rather than hanging
PID 1 forever, and that a failure to drain is reported instead of absorbed.

The router is replaced by a script the test controls. There is no real router,
no control socket, and no container.
"""

from __future__ import annotations

import os
import signal
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

INIT = str(Path(__file__).with_name("hypellm-init"))

# The init's own exit codes, mirrored here so a change to either is a visible
# failure rather than a test that quietly stops checking anything.
EXIT_DRAIN_FAILED = 70
EXIT_ARGUMENTS = 71


class InitTest(unittest.TestCase):
    def setUp(self) -> None:
        self.dir = tempfile.TemporaryDirectory()
        self.root = Path(self.dir.name)
        self.log = self.root / "calls.log"
        self.sentinel = self.root / "stop"
        self.config = str(self.root / "hypellm.conf")
        self.secrets = str(self.root / "secrets")
        self.router = self.root / "hypellm-router"

    def tearDown(self) -> None:
        self.dir.cleanup()

    def fake_router(self, *, obeys: bool = True, refuses_with: int = 0, exits: int = 0) -> None:
        """A stand-in for the router binary.

        Invoked two ways, exactly as the real one is: once to *run*, and once
        with `--shutdown` to stop the first. Both append to a log so a test can
        assert on what the init actually asked for.

        The two invocations are connected the way the real ones are — through a
        side channel, not through the init. `--shutdown` drops a sentinel and
        the running instance notices it and exits, which is what the control
        socket does. A fake whose `--shutdown` did nothing would make every
        drain look failed and would prove nothing about the init.
        """
        obey = f'touch "{self.sentinel}"' if obeys else "true"
        self.router.write_text(
            "#!/usr/bin/env bash\n"
            f'echo "$@" >> "{self.log}"\n'
            'if [ "$1" = "--shutdown" ]; then\n'
            f"  {obey}\n"
            f"  exit {refuses_with}\n"
            "fi\n"
            # The real router's one-shot commands do their work and exit. The
            # fake has to do the same, or a passthrough test waits out the
            # long-running branch below.
            'case "$1" in\n'
            "  --generate-secrets|--check|--version|-V|--help|-h|--hash-password) exit 0 ;;\n"
            "esac\n"
            'trap "" TERM INT\n'
            "for _ in $(seq 1 600); do\n"
            f'  if [ -f "{self.sentinel}" ]; then exit {exits}; fi\n'
            "  sleep 0.05\n"
            "done\n"
            f"exit {exits}\n"
        )
        self.router.chmod(0o755)

    def start(self, deadline: float = 3.0) -> subprocess.Popen[bytes]:
        environment = dict(os.environ)
        environment["HYPELLM_ROUTER_BIN"] = str(self.router)
        environment["HYPELLM_DRAIN_DEADLINE"] = str(deadline)
        process = subprocess.Popen(
            [INIT, "--config", self.config, "--secrets", self.secrets, "--log", "info"],
            env=environment,
            stderr=subprocess.PIPE,
        )
        self.addCleanup(self.close, process)
        return process

    @staticmethod
    def close(process: subprocess.Popen[bytes]) -> None:
        if process.poll() is None:
            process.kill()
            process.wait(timeout=5)
        if process.stderr is not None:
            process.stderr.close()

    def calls(self) -> list[str]:
        if not self.log.exists():
            return []
        return [line for line in self.log.read_text().splitlines() if line]

    def wait_for_start(self, process: subprocess.Popen[bytes]) -> None:
        deadline = time.monotonic() + 5.0
        while time.monotonic() < deadline:
            if self.calls():
                return
            if process.poll() is not None:
                self.fail("the init exited before the router started")
            time.sleep(0.02)
        self.fail("the router never started")

    # -- The gap this component closes -------------------------------------

    def test_a_signal_becomes_the_routers_own_shutdown_command(self) -> None:
        # The whole point. A container's PID 1 gets no default signal action, so
        # a router running as PID 1 ignores SIGTERM entirely and is SIGKILLed at
        # the end of the grace period. This must turn the signal into exactly
        # the command the documentation tells operators to run — with the same
        # config and secrets paths, or it authenticates against the wrong
        # control socket and silently fails.
        #
        # The fake router traps and ignores TERM itself, so a passing result
        # cannot come from the signal reaching the child directly.
        self.fake_router()
        process = self.start()
        self.wait_for_start(process)

        process.send_signal(signal.SIGTERM)
        status = process.wait(timeout=15)

        shutdowns = [c for c in self.calls() if c.startswith("--shutdown")]
        self.assertEqual(len(shutdowns), 1, self.calls())
        self.assertIn(f"--config {self.config}", shutdowns[0])
        self.assertIn(f"--secrets {self.secrets}", shutdowns[0])
        self.assertEqual(status, 0, process.stderr.read().decode() if process.stderr else "")

    def test_the_routers_own_arguments_are_passed_through(self) -> None:
        # The init must never have to learn what flags the router accepts.
        self.fake_router()
        process = self.start()
        self.wait_for_start(process)
        process.send_signal(signal.SIGTERM)
        process.wait(timeout=15)

        run = [c for c in self.calls() if not c.startswith("--shutdown")]
        self.assertEqual(len(run), 1, self.calls())
        self.assertIn("--log info", run[0], "an argument was dropped on the way through")

    def test_a_second_signal_does_not_cut_the_drain_the_first_started(self) -> None:
        # An operator pressing Ctrl-C twice, or a supervisor retrying.
        # Escalating on the second signal would kill the drain — the exact
        # behaviour this component exists to remove, reintroduced by the
        # impatient path.
        self.fake_router(obeys=False)
        process = self.start(deadline=3.0)
        self.wait_for_start(process)

        for _ in range(3):
            process.send_signal(signal.SIGTERM)
            time.sleep(0.3)
        process.wait(timeout=15)

        shutdowns = [c for c in self.calls() if c.startswith("--shutdown")]
        self.assertEqual(
            len(shutdowns), 1, f"a repeated signal ran shutdown again: {self.calls()}"
        )

    def test_a_router_that_ignores_the_drain_is_killed_and_reported(self) -> None:
        # PID 1 hanging forever outlives every supervisor's patience and leaves
        # a container nothing can stop. The kill is the honest end — and it is
        # reported, because a silent fallback to SIGKILL is indistinguishable
        # from having no init at all.
        self.fake_router(obeys=False)
        process = self.start(deadline=1.0)
        self.wait_for_start(process)

        started = time.monotonic()
        process.send_signal(signal.SIGTERM)
        status = process.wait(timeout=20)
        elapsed = time.monotonic() - started

        self.assertLess(elapsed, 15.0, "the init waited past its deadline")
        self.assertEqual(
            status,
            EXIT_DRAIN_FAILED,
            "a killed router was reported as a clean shutdown",
        )

    def test_a_refused_shutdown_is_reported_rather_than_absorbed(self) -> None:
        # `--shutdown` exits non-zero when the control key does not match the
        # running router — a real misconfiguration, and one an operator has to
        # be told about, because the container would otherwise appear to have
        # stopped cleanly while its streams were cut.
        self.fake_router(obeys=False, refuses_with=5)
        process = self.start(deadline=1.0)
        self.wait_for_start(process)

        process.send_signal(signal.SIGTERM)
        stderr = process.stderr.read().decode() if process.stderr else ""
        status = process.wait(timeout=20)

        self.assertEqual(status, EXIT_DRAIN_FAILED, stderr)
        self.assertIn("refused", stderr)

    def test_the_child_exit_status_is_forwarded(self) -> None:
        # A supervisor reads the exit code. The router's own codes — 2
        # configuration, 3 state, 4 listener, 5 secrets — have to survive, or
        # every startup failure looks the same from outside.
        self.fake_router(exits=4)
        process = self.start()
        self.wait_for_start(process)
        self.sentinel.touch()
        self.assertEqual(process.wait(timeout=15), 4)

    def test_missing_arguments_are_refused_before_anything_starts(self) -> None:
        # Without both, a signal would run `--shutdown` against the wrong
        # control socket, or none, and the drain would silently not happen.
        # None of these is a one-shot command, so each has to reach the
        # argument check rather than being handed to the router.
        for arguments in ([], ["--config", self.config], ["--secrets", self.secrets]):
            self.fake_router()
            environment = dict(os.environ)
            environment["HYPELLM_ROUTER_BIN"] = str(self.router)
            completed = subprocess.run(
                [INIT, *arguments], env=environment, capture_output=True, check=False
            )
            self.assertEqual(completed.returncode, EXIT_ARGUMENTS, f"{arguments}")
            self.assertEqual(self.calls(), [], "the router ran without a usable shutdown path")

    def test_a_one_shot_command_reaches_the_router_unchanged(self) -> None:
        # The image's contract is "append arguments and they reach the router",
        # and `docker run hypellm-router:local --generate-secrets <dir>` is how
        # a fresh checkout creates its secret bundle — `just _secrets` and
        # `just bootstrap` both do exactly that. An init that required
        # `--config` and `--secrets` before running anything would break the
        # first command anyone runs.
        self.fake_router()
        environment = dict(os.environ)
        environment["HYPELLM_ROUTER_BIN"] = str(self.router)

        for arguments in (
            ["--generate-secrets", "/etc/hypellm/secrets"],
            ["--check", "--config", "/etc/hypellm/hypellm.conf"],
            ["--version"],
            ["--help"],
        ):
            self.log.unlink(missing_ok=True)
            completed = subprocess.run(
                [INIT, *arguments], env=environment, capture_output=True, check=False, timeout=15
            )
            self.assertEqual(completed.returncode, 0, f"{arguments}: {completed.stderr!r}")
            self.assertEqual(
                self.calls(),
                [" ".join(arguments)],
                f"{arguments} did not reach the router verbatim",
            )

    def test_the_drain_deadline_exceeds_the_routers_own(self) -> None:
        # The ordering that makes the whole thing work: the default deadline
        # must be longer than the inference listener's 30-second drain, or the
        # init kills the router part-way through the drain it just asked for.
        text = Path(INIT).read_text()
        line = next(l for l in text.splitlines() if l.startswith("DRAIN_DEADLINE="))
        default = int(line.split(":-")[1].split("}")[0])
        self.assertGreater(default, 30)


if __name__ == "__main__":
    unittest.main()
