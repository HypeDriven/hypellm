#!/usr/bin/env python3
"""Tests for the reference fleet agent's fetch path.

Run with `python3 -m unittest discover -s agent` or `agent/test_fleet_agent.py`.

This is not part of `cargo test --workspace`: the agent is deliberately outside
the Rust workspace (specification 4.1), so nothing in the build could run it.
It is here because `FETCH` is the one verb that commits a host to hours of
bandwidth and hundreds of gigabytes of disk, and its failure modes — a retry
that restarts from zero, two pulls racing on one disk, a cancel noticed only
after the budget expires, a wrong image accepted because the pull exited zero —
are all invisible until they happen on a real 40 GB artifact.

Nothing here runs `ssh` or `docker`. `run_on` is replaced by a script the test
controls, which is the only way to exercise a transient failure deterministically.
"""

from __future__ import annotations

import importlib.machinery
import importlib.util
import os
import socket
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path

_SPEC = importlib.util.spec_from_loader(
    "fleet_agent",
    importlib.machinery.SourceFileLoader(
        "fleet_agent", str(Path(__file__).with_name("fleet-agent"))
    ),
)
assert _SPEC is not None
agent_module = importlib.util.module_from_spec(_SPEC)
assert _SPEC.loader is not None
# Registered before execution: `@dataclass` resolves its own module through
# `sys.modules`, so a module executed outside it fails at import.
sys.modules["fleet_agent"] = agent_module
_SPEC.loader.exec_module(agent_module)


FLEET = {
    "hosts": [
        {"id": "h1", "arch": "aarch64", "ssh": "hypellm@h1.test"},
        {"id": "h2", "arch": "x86_64", "ssh": "hypellm@h2.test"},
    ],
    "deployments": [],
    "artifacts": [
        {
            "id": "model-arm",
            "arch": "aarch64",
            "digest": "sha256:abc123",
            "host_pull": {"h1": ["docker", "pull", "model:arm"]},
        },
        {
            "id": "other-arm",
            "arch": "aarch64",
            "digest": "sha256:def456",
            "host_pull": {"h1": ["docker", "pull", "other:arm"]},
        },
    ],
}


class FetchTest(unittest.TestCase):
    """Each test drives `fetch` with a scripted `run_on`."""

    def setUp(self) -> None:
        # Backoff shrunk so a test that exercises three attempts takes
        # milliseconds. The values under test are the *counts* and the ordering,
        # not the wall-clock constants.
        self._saved = (
            agent_module.FETCH_BACKOFF_SECONDS,
            agent_module.MAX_FETCH_BACKOFF_SECONDS,
        )
        agent_module.FETCH_BACKOFF_SECONDS = 0.01
        agent_module.MAX_FETCH_BACKOFF_SECONDS = 0.01

        self.agent = agent_module.Agent(
            agent_module.Fleet(FLEET), b"a-test-fleet-key", 120
        )
        self.pulls: list[list[str]] = []
        self.verifies = 0

    def tearDown(self) -> None:
        (
            agent_module.FETCH_BACKOFF_SECONDS,
            agent_module.MAX_FETCH_BACKOFF_SECONDS,
        ) = self._saved

    def script(self, exits: list[int], hold: float = 0.0) -> None:
        """Make `run_on` return `exits` in order, then repeat the last one."""
        remaining = list(exits)

        def run_on(host, argv, timeout=None):  # noqa: ANN001, ARG001
            self.pulls.append(list(argv))
            if hold:
                time.sleep(hold)
            code = remaining.pop(0) if len(remaining) > 1 else remaining[0]
            return (code, "")

        self.agent.run_on = run_on  # type: ignore[method-assign]

    def verifies_as(self, ok: bool) -> None:
        def verify(host, artifact):  # noqa: ANN001, ARG001
            self.verifies += 1
            return ok

        self.agent.verify = verify  # type: ignore[method-assign]

    def settle(self, activation_id: str, timeout: float = 5.0) -> str:
        """Wait for the fetch thread to leave `fetching`, and return the state."""
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            reply = self.agent.status(activation_id)
            state = reply.split(" ")[1]
            if state != "fetching":
                return reply
            time.sleep(0.005)
        self.fail(f"the fetch never settled: {self.agent.status(activation_id)}")

    # -- Resumption ---------------------------------------------------------

    def test_a_transient_failure_is_retried_within_the_budget(self) -> None:
        # The property specification-extension 12 asks for: a 40 GB download
        # that fails partway must not be abandoned. Two failures then a success
        # must end `ready`, and must have made three attempts — a single attempt
        # would mean the retry loop is not running, and four would mean it does
        # not stop on success.
        self.script([1, 1, 0])
        self.verifies_as(True)

        reply = self.agent.fetch("model-arm", "h1", "600000")
        self.assertTrue(reply.startswith("ACCEPTED "), reply)
        settled = self.settle(reply.split(" ")[1])

        self.assertIn(" ready ", settled, settled)
        self.assertIn("verified", settled)
        self.assertEqual(len(self.pulls), 3, self.pulls)
        # Every attempt runs the same pull, which is what makes it a resume:
        # the host's content store keeps what the last attempt finished.
        self.assertEqual(self.pulls[0], self.pulls[-1])

    def test_attempts_are_bounded(self) -> None:
        # "Retry until the deadline" against a source returning an immediate
        # error is a busy loop that holds the host's fetch slot for the whole
        # budget.
        self.script([1])
        self.verifies_as(True)

        reply = self.agent.fetch("model-arm", "h1", "600000")
        settled = self.settle(reply.split(" ")[1])

        self.assertIn(" failed ", settled, settled)
        self.assertEqual(len(self.pulls), agent_module.MAX_FETCH_ATTEMPTS, self.pulls)

    def test_a_digest_mismatch_is_not_retried(self) -> None:
        # A pull that exited zero and produced the wrong image will produce the
        # wrong image again. Retrying it spends the budget to reach the same
        # refusal, and the refusal is the point: an unverified artifact must
        # never become activatable.
        self.script([0])
        self.verifies_as(False)

        reply = self.agent.fetch("model-arm", "h1", "600000")
        settled = self.settle(reply.split(" ")[1])

        self.assertIn(" failed ", settled, settled)
        self.assertIn("digest_mismatch", settled)
        self.assertEqual(len(self.pulls), 1, self.pulls)

    # -- One fetch per host -------------------------------------------------

    def test_a_repeated_fetch_returns_the_same_activation(self) -> None:
        # A router that retries a FETCH it never saw accepted must not start a
        # second pull against the same disk and the same link.
        self.script([0], hold=0.2)
        self.verifies_as(True)

        first = self.agent.fetch("model-arm", "h1", "600000")
        second = self.agent.fetch("model-arm", "h1", "600000")
        self.assertEqual(first, second, "a second FETCH started a second pull")

        self.settle(first.split(" ")[1])
        self.assertEqual(len(self.pulls), 1, self.pulls)

    def test_a_different_artifact_on_a_busy_host_is_refused(self) -> None:
        self.script([0], hold=0.2)
        self.verifies_as(True)

        first = self.agent.fetch("model-arm", "h1", "600000")
        self.assertEqual(self.agent.fetch("other-arm", "h1", "600000"), "ERR host_busy")

        self.settle(first.split(" ")[1])
        # And the host is free again once it finishes, or one failed fetch would
        # take the host out of service until a restart.
        self.assertTrue(
            self.agent.fetch("other-arm", "h1", "600000").startswith("ACCEPTED ")
        )

    # -- Cancellation and the budget ----------------------------------------

    def test_a_cancel_is_noticed_between_attempts(self) -> None:
        agent_module.FETCH_BACKOFF_SECONDS = 5.0
        agent_module.MAX_FETCH_BACKOFF_SECONDS = 5.0
        self.script([1])
        self.verifies_as(True)

        reply = self.agent.fetch("model-arm", "h1", "600000")
        activation_id = reply.split(" ")[1]
        # Once the first attempt has failed and the agent is backing off.
        deadline = time.monotonic() + 5.0
        while not self.pulls and time.monotonic() < deadline:
            time.sleep(0.005)
        self.assertEqual(self.agent.cancel(activation_id), "OK")

        settled = self.settle(activation_id, timeout=3.0)
        self.assertIn(" cancelled ", settled, settled)
        self.assertEqual(len(self.pulls), 1, "a cancelled fetch made another attempt")

    def test_the_routers_deadline_bounds_the_fetch(self) -> None:
        # The deadline used to be dropped on the floor: the verb carried it and
        # `fetch` never read it, so a fetch ran for as long as its attempts took
        # regardless of what the router asked for.
        # Each attempt consumes more than half the budget, so the fetch must
        # stop on the deadline rather than on the attempt cap. Asserting the
        # detail code rather than the attempt count is what distinguishes the
        # two: both end `failed`, and only one of them means the router's
        # deadline was honoured.
        self.script([1], hold=0.6)
        self.verifies_as(True)

        reply = self.agent.fetch("model-arm", "h1", "1000")
        settled = self.settle(reply.split(" ")[1], timeout=10.0)

        self.assertIn(" failed ", settled, settled)
        self.assertIn("deadline_after_", settled, settled)
        self.assertLess(len(self.pulls), agent_module.MAX_FETCH_ATTEMPTS, self.pulls)

    # -- Input -------------------------------------------------------------

    def test_malformed_input_is_refused_before_anything_runs(self) -> None:
        self.script([0])
        self.verifies_as(True)

        for artifact, host, deadline in [
            ("model-arm", "h1", "not-a-number"),
            ("model-arm", "h1", "9" * 13),
            ("model arm", "h1", "1000"),
            ("model-arm", "h nope", "1000"),
        ]:
            self.assertEqual(
                self.agent.fetch(artifact, host, deadline), "ERR malformed",
                f"{artifact} {host} {deadline}",
            )

        self.assertEqual(self.agent.fetch("nope", "h1", "1000"), "ERR unknown_artifact")
        self.assertEqual(self.agent.fetch("model-arm", "nope", "1000"), "ERR unknown_host")
        # An aarch64 image on an x86-64 host. Hours of bandwidth is the most
        # expensive way to learn this.
        self.assertEqual(self.agent.fetch("model-arm", "h2", "1000"), "ERR arch_mismatch")
        self.assertEqual(self.pulls, [], "a refused fetch ran a command")


ACTUATED = {
    "hosts": [
        {
            "id": "h1",
            "arch": "aarch64",
            "ssh": "hypellm@h1.test",
            "max_activations_per_hour": 1000,
        },
    ],
    "deployments": [
        {
            "id": "d1",
            "host": "h1",
            "accelerator": "gpu0",
            "start": ["start-it"],
            "stop": ["stop-it"],
            "probe": ["probe-it"],
        },
    ],
    "artifacts": [],
}


def wait_for(predicate, timeout: float = 5.0) -> bool:  # noqa: ANN001
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return True
        time.sleep(0.005)
    return predicate()


class RemoteQuotingTest(unittest.TestCase):
    """`ssh` joins its command with spaces and the remote shell re-splits it.

    Nothing here runs `ssh`: `subprocess.run` is captured, and the remote side
    is simulated exactly as sshd does it — the words after the destination
    joined with single spaces and handed to `sh -c`.
    """

    ARGS = [
        "{{.Names}}\t{{.Status}}",
        "{{index .RepoDigests 0}}",
        "two  spaces",
        "x;echo INJECTED",
        "$(echo INJECTED)",
        "`echo INJECTED`",
        "it's",
        '"quoted"',
        "*",
        "",
        "-starts-with-dash",
    ]

    def remote(self, argv: list[str]) -> str:
        captured: list[list[str]] = []

        def fake_run(command, **kwargs):  # noqa: ANN001, ANN003
            self.assertFalse(kwargs.get("shell"), "the local side must not use a shell")
            captured.append(list(command))
            return subprocess.CompletedProcess(command, 0, b"", b"")

        agent = agent_module.Agent(agent_module.Fleet(FLEET), b"k" * 32, 5)
        saved = agent_module.subprocess.run
        agent_module.subprocess.run = fake_run
        try:
            agent.run_on(agent.fleet.hosts["h1"], argv)
        finally:
            agent_module.subprocess.run = saved
        self.assertEqual(len(captured), 1)
        command = captured[0]
        # ssh's own options end before the destination, so neither it nor the
        # command can be read as an option.
        destination = command.index("hypellm@h1.test")
        self.assertEqual(command[destination - 1], "--", command)
        remote_words = command[destination + 1 :]
        completed = subprocess.run(
            ["sh", "-c", " ".join(remote_words)],
            capture_output=True,
            timeout=10,
            check=False,
        )
        return completed.stdout.decode("utf-8")

    def test_every_argument_reaches_the_remote_program_intact(self) -> None:
        # Unquoted, `docker ps --format "{{.Names}}\t{{.Status}}"` arrived as
        # several words with the tab gone, so every deployment read `stopped`,
        # and `{{index .RepoDigests 0}}` split in three, so every FETCH failed
        # `digest_mismatch`.
        output = self.remote(["printf", "<%s>\\n", *self.ARGS])
        self.assertEqual(output, "".join(f"<{a}>\n" for a in self.ARGS))

    def test_no_table_value_runs_as_a_remote_command(self) -> None:
        output = self.remote(["printf", "%s", "x;echo INJECTED", "$(echo INJECTED)"])
        self.assertNotIn("\nINJECTED", "\n" + output.replace("x;echo INJECTED", ""))
        self.assertEqual(output, "x;echo INJECTED$(echo INJECTED)")


class LineBoundTest(unittest.TestCase):
    """A peer that never sends a newline cannot grow the read buffer."""

    def test_an_endless_line_is_refused_before_its_newline(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = os.path.join(directory, "agent.sock")
            server = agent_module.Server(path, agent_module.Handler)
            server.agent = agent_module.Agent(  # type: ignore[attr-defined]
                agent_module.Fleet(FLEET), b"k" * 32, 5
            )
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                client.settimeout(5.0)
                client.connect(path)
                # More than a line, less than one read, so the agent has consumed
                # everything sent when it replies and the close is orderly.
                client.sendall(b"A" * (agent_module.MAX_LINE + 100))
                reply = b""
                try:
                    while True:
                        chunk = client.recv(4096)
                        if not chunk:
                            break
                        reply += chunk
                except socket.timeout:
                    self.fail("the agent kept reading a line with no end")
                client.close()
                self.assertEqual(reply, b"ERR malformed\n")
            finally:
                server.shutdown()
                server.server_close()


class BackgroundBoundsTest(unittest.TestCase):
    """Verbs that start background work are bounded in number and in memory."""

    def setUp(self) -> None:
        self.agent = agent_module.Agent(agent_module.Fleet(ACTUATED), b"k" * 32, 120)
        self.release = threading.Event()
        self.release.set()
        self.probe_exit = 0
        self.saved_retained = agent_module.MAX_RETAINED_ACTIVATIONS

        def run_on(host, argv, timeout=None):  # noqa: ANN001, ARG001
            if argv == ["probe-it"]:
                return (self.probe_exit, "")
            self.release.wait(10.0)
            return (0, "")

        self.agent.run_on = run_on  # type: ignore[method-assign]

    def tearDown(self) -> None:
        self.release.set()
        agent_module.MAX_RETAINED_ACTIVATIONS = self.saved_retained

    def test_deactivations_cannot_spawn_unbounded_work(self) -> None:
        # DEACTIVATE is outside the activation rate limit, so before the cap a
        # stream of fresh leases started one thread and one `ssh` apiece.
        self.release.clear()
        cap = agent_module.MAX_INFLIGHT_OPERATIONS
        for n in range(cap):
            reply = self.agent.start_verb("d1", f"lease-{n}", False)
            self.assertTrue(reply.startswith("ACCEPTED "), reply)
        self.assertEqual(self.agent.start_verb("d1", "lease-over", False), "ERR busy")
        self.assertEqual(self.agent.start_verb("d1", "lease-over", True), "ERR busy")
        # A re-sent lease still answers with its activation: idempotence is not
        # new work.
        self.assertTrue(self.agent.start_verb("d1", "lease-0", False).startswith("ACCEPTED "))

        self.release.set()
        self.assertTrue(wait_for(lambda: self.agent._inflight == 0))
        self.assertTrue(self.agent.start_verb("d1", "lease-after", False).startswith("ACCEPTED "))

    def test_finished_activations_are_pruned(self) -> None:
        agent_module.MAX_RETAINED_ACTIVATIONS = 4
        last = ""
        for n in range(20):
            last = self.agent.start_verb("d1", f"lease-{n}", False).split(" ")[1]
            self.assertTrue(wait_for(lambda: self.agent._inflight == 0))
        self.assertLessEqual(len(self.agent._activations), 4)
        self.assertLessEqual(len(self.agent._leases), 4)
        # The newest one is still there for the router to read.
        self.assertTrue(self.agent.status(last).startswith("OK stopped "))

    def test_a_cancel_while_probing_reads_cancelled(self) -> None:
        # The probe loop's `while ... else` ran the `else` on a CANCEL too,
        # reporting `failed probe_timeout` for what the operator stopped.
        self.probe_exit = 1
        activation_id = self.agent.start_verb("d1", "lease-p", True).split(" ")[1]
        self.assertTrue(
            wait_for(lambda: self.agent.status(activation_id).startswith("OK probing "))
        )
        self.assertEqual(self.agent.cancel(activation_id), "OK")
        self.assertTrue(
            wait_for(
                lambda: not self.agent.status(activation_id).startswith("OK probing "),
                timeout=6.0,
            )
        )
        self.assertEqual(self.agent.status(activation_id), "OK cancelled cancelled 750")


if __name__ == "__main__":
    unittest.main()
