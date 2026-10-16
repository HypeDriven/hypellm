#!/usr/bin/env python3
"""Tests for the reference fleet agent: fetch, enrollment, image relay and templates.

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
import hashlib
import hmac
import json
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


class ReloadTest(unittest.TestCase):
    """The table on disk is re-read when it changes, and only when it is valid."""

    def setUp(self) -> None:
        self._dir = tempfile.TemporaryDirectory()
        self.path = os.path.join(self._dir.name, "fleet.json")
        self.write(FLEET)
        self.agent = agent_module.Agent(
            agent_module.Fleet(FLEET), b"k" * 32, 5, config_path=self.path
        )
        self.parses = 0
        original = agent_module.Fleet

        def counting(document, *rest):  # type: ignore[no-untyped-def]
            self.parses += 1
            return original(document, *rest)

        self._original_fleet = original
        agent_module.Fleet = counting  # type: ignore[assignment]

    def tearDown(self) -> None:
        agent_module.Fleet = self._original_fleet  # type: ignore[assignment]
        self._dir.cleanup()

    def write(self, document: object, raw: str | None = None) -> None:
        text = raw if raw is not None else json.dumps(document)
        with open(self.path, "w", encoding="utf-8") as handle:
            handle.write(text)
        # A later stamp even on a filesystem with coarse timestamps.
        stamp = time.time_ns() + 10_000_000_000
        os.utime(self.path, ns=(stamp, stamp))

    def check(self) -> bool:
        # The rate limit is a property of wall time, not of what is under test.
        self.agent._last_check = 0.0
        return self.agent.maybe_reload()

    def added_host(self) -> dict:
        document = json.loads(json.dumps(FLEET))
        document["hosts"].append(
            {"id": "h3", "arch": "x86_64", "ssh": "hypellm@gpu3.lan"}
        )
        return document

    def test_a_valid_change_is_adopted_and_changes_the_digest(self) -> None:
        before = self.agent.digest
        self.write(self.added_host())
        self.assertTrue(self.check())
        self.assertIn("h3", self.agent.fleet.hosts)
        self.assertEqual(self.agent.fleet.hosts["h3"].ssh, "hypellm@gpu3.lan")
        self.assertNotEqual(self.agent.digest, before)
        self.assertEqual(self.agent.digest, self._original_fleet(self.added_host()).digest())
        # The handshake reports the table now in force.
        nonce = "n1"
        tag = agent_module.hello_tag(b"k" * 32, agent_module.PROTOCOL_VERSION, nonce, "x")
        reply = self.agent.hello(agent_module.PROTOCOL_VERSION, nonce, "x", tag)
        self.assertTrue(reply.endswith(" " + self.agent.digest), reply)

    def test_an_invalid_change_keeps_the_old_table_and_digest(self) -> None:
        before_digest = self.agent.digest
        before_fleet = self.agent.fleet
        broken = self.added_host()
        # A deployment on an undeclared host: valid JSON, invalid table.
        broken["deployments"] = [
            {"id": "d9", "host": "nowhere", "accelerator": "a", "start": ["x"], "stop": ["y"]}
        ]
        for document, raw in [(broken, None), (None, '{"hosts": [')]:
            self.write(document, raw)
            self.assertFalse(self.check())
            self.assertIs(self.agent.fleet, before_fleet)
            self.assertEqual(self.agent.digest, before_digest)
        # A rejected version is not re-parsed on every check.
        parses = self.parses
        self.assertFalse(self.check())
        self.assertEqual(self.parses, parses)

    def test_an_unchanged_file_is_not_reparsed(self) -> None:
        for _ in range(3):
            self.assertFalse(self.check())
        self.assertEqual(self.parses, 0)

    def test_checks_are_rate_limited(self) -> None:
        self.write(self.added_host())
        self.agent._last_check = time.monotonic()
        self.assertFalse(self.agent.maybe_reload())
        self.assertEqual(self.parses, 0)

    def test_a_reload_does_not_reset_a_hosts_activation_window(self) -> None:
        self.assertTrue(self.agent.limiter.allow("h1", 1))
        self.write(self.added_host())
        self.assertTrue(self.check())
        self.assertFalse(self.agent.limiter.allow("h1", 1))

    def test_a_session_from_before_a_reload_is_closed(self) -> None:
        # Sessions are long-lived, so a mismatch is only noticed at a new
        # HELLO. A session authenticated against the old table must end.
        socket_path = os.path.join(self._dir.name, "agent.sock")
        server = agent_module.Server(socket_path, agent_module.Handler)
        server.agent = self.agent  # type: ignore[attr-defined]
        self.agent.observe = lambda: b"{}"  # type: ignore[method-assign]
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            client.settimeout(5.0)
            client.connect(socket_path)
            reader = client.makefile("rb")
            nonce = "n2"
            tag = agent_module.hello_tag(b"k" * 32, agent_module.PROTOCOL_VERSION, nonce, "x")
            client.sendall(f"HELLO {agent_module.PROTOCOL_VERSION} {nonce} x {tag}\n".encode())
            self.assertTrue(reader.readline().startswith(b"OK "))
            client.sendall(b"OBSERVE\n")
            self.assertEqual(reader.readline(), b"OK 2\n")
            self.assertEqual(reader.read(2), b"{}")
            self.write(self.added_host())
            self.agent._last_check = 0.0
            client.sendall(b"OBSERVE\n")
            self.assertEqual(reader.readline(), b"ERR fleet_configuration_changed\n")
            self.assertEqual(reader.readline(), b"", "a stale session stayed open")
            # A fresh session is served, and its HELLO reports the new digest.
            fresh = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            fresh.settimeout(5.0)
            fresh.connect(socket_path)
            fresh_reader = fresh.makefile("rb")
            nonce = "n3"
            tag = agent_module.hello_tag(b"k" * 32, agent_module.PROTOCOL_VERSION, nonce, "x")
            fresh.sendall(f"HELLO {agent_module.PROTOCOL_VERSION} {nonce} x {tag}\n".encode())
            self.assertTrue(
                fresh_reader.readline().rstrip().endswith(self.agent.digest.encode())
            )
            fresh.sendall(b"OBSERVE\n")
            self.assertEqual(fresh_reader.readline(), b"OK 2\n")
            fresh.close()
            client.close()
        finally:
            server.shutdown()
            server.server_close()


class HandshakeTest(unittest.TestCase):
    """The agent and the router must compute the same HELLO tag."""

    def test_the_tag_matches_the_routers_pinned_vector(self) -> None:
        # The same inputs and hex as `hypellm_fleet::protocol`'s
        # `the_handshake_hmac_matches_the_reference_agent_framing`.
        key = b"0123456789abcdef0123456789abcdef"
        self.assertEqual(
            agent_module.hello_tag(key, "1", "abc", "sha256:1111"),
            "aeec82313b85a93a6190222239c66851408850cd3e627a46ed9eaad95d47d73a",
        )
        # What the agent used to compute, which no real router could match.
        concatenated = hmac.new(key, b"1abcsha256:1111", hashlib.sha256).hexdigest()
        self.assertNotEqual(agent_module.hello_tag(key, "1", "abc", "sha256:1111"), concatenated)

    def test_a_router_tag_is_accepted_and_a_concatenated_one_is_not(self) -> None:
        agent = agent_module.Agent(agent_module.Fleet(FLEET), b"k" * 32, 5)
        framed = agent_module.hello_tag(b"k" * 32, "1", "n-ok", "d")
        self.assertTrue(agent.hello("1", "n-ok", "d", framed).startswith("OK "))
        concatenated = hmac.new(b"k" * 32, b"1n-badd", hashlib.sha256).hexdigest()
        self.assertEqual(agent.hello("1", "n-bad", "d", concatenated), "ERR unauthenticated")


class ObserveProbeTest(unittest.TestCase):
    """A running container is probed on the host it runs on."""

    def test_a_running_container_is_probed_without_error(self) -> None:
        fleet = agent_module.Fleet(
            {
                "hosts": [{"id": "h1", "arch": "aarch64", "ssh": "hypellm@h1.test"}],
                "deployments": [
                    {
                        "id": "d1", "host": "h1", "accelerator": "a1", "container": "c1",
                        "start": ["docker", "start", "c1"], "stop": ["docker", "stop", "c1"],
                        "probe": ["curl", "-fsS", "http://127.0.0.1:8000/"],
                    }
                ],
            }
        )
        agent = agent_module.Agent(fleet, b"k" * 32, 5)
        probed: list[str] = []

        def run_on(host, argv, timeout=None):  # type: ignore[no-untyped-def]
            if argv[0] == "df":
                return (0, "Avail\n100\n")
            if argv[:2] == ["docker", "ps"]:
                return (0, "c1\tUp 5 minutes\n")
            if argv[0] == "curl":
                probed.append(host.id)
                return (0, "")
            return (1, "")

        agent.run_on = run_on  # type: ignore[method-assign]
        report = json.loads(agent.observe())
        self.assertEqual(report["deployments"][0]["state"], "ready")
        self.assertEqual(probed, ["h1"])


RIG_KEY = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAINaR4JuJGhj5Y/y0fV0dwnAAHCoxBRNiBi5JkRlcQU2M"


def offered(**overrides):  # type: ignore[no-untyped-def]
    host = {
        "id": "rig", "arch": "x86_64", "address": "192.168.1.20", "ssh_user": "albert",
        "host_key": RIG_KEY, "data_dir": "/home/albert/.hypellm",
        "accelerators": [{"id": "rig-gpu0", "index": 0}],
    }
    host.update(overrides)
    return host


class EnrollTest(unittest.TestCase):
    """The router offers; the agent decides, within its own allowlist."""

    def setUp(self) -> None:
        self._dir = tempfile.TemporaryDirectory()
        self.state = os.path.join(self._dir.name, "enrolled.json")
        self.known = os.path.join(self._dir.name, "enrolled_known_hosts")
        self.document = json.loads(json.dumps(FLEET))
        self.document["enrollment"] = {
            "accept": True,
            "cidrs": ["192.168.1.0/24"],
            "state_file": self.state,
            "known_hosts_file": self.known,
        }
        self.agent = agent_module.Agent(agent_module.Fleet(self.document), b"k" * 32, 5)

    def tearDown(self) -> None:
        self._dir.cleanup()

    def offer(self, *hosts) -> str:  # type: ignore[no-untyped-def]
        return self.agent.enroll(json.dumps({"hosts": list(hosts)}).encode())

    def test_an_agent_that_has_not_opted_in_adopts_nothing(self) -> None:
        agent = agent_module.Agent(agent_module.Fleet(FLEET), b"k" * 32, 5)
        before = agent.digest
        self.assertEqual(
            agent.enroll(json.dumps({"hosts": [offered()]}).encode()), "ERR enrollment_disabled"
        )
        self.assertEqual(agent.digest, before)
        self.assertNotIn("rig", agent.fleet.hosts)

    def test_an_accepted_host_is_pinned_and_joins_the_digest_as_the_router_has_it(self) -> None:
        before = self.agent.digest
        self.assertEqual(self.offer(offered()), "OK 1")
        host = self.agent.fleet.hosts["rig"]
        self.assertEqual(host.ssh, "albert@192.168.1.20")
        self.assertEqual(host.disk_path, "/home/albert/.hypellm")
        self.assertIn("StrictHostKeyChecking=yes", host.ssh_options)
        self.assertIn(f"UserKnownHostsFile={self.known}", host.ssh_options)
        self.assertIn("HostKeyAlias=hypellm.rig", host.ssh_options)
        with open(self.known, encoding="utf-8") as handle:
            self.assertEqual(handle.read(), f"hypellm.rig {RIG_KEY}\n")
        self.assertEqual(os.stat(self.state).st_mode & 0o777, 0o600)
        self.assertNotEqual(self.agent.digest, before)
        canonical = self.agent.fleet.canonical_form()
        self.assertIn("host rig x86_64 local\n", canonical)
        self.assertIn("accelerator rig-gpu0 rig\n", canonical)

    def test_an_address_outside_the_allowlist_is_refused(self) -> None:
        # The control that keeps a compromised router from aiming this
        # agent's key at an arbitrary machine.
        for address in ("10.0.0.5", "192.168.2.20", "8.8.8.8", "::1", "not-an-ip"):
            with self.subTest(address=address):
                self.assertEqual(self.offer(offered(address=address)), "OK 0")
                self.assertNotIn("rig", self.agent.fleet.hosts)

    def test_a_malformed_entry_is_left_out_without_failing_the_rest(self) -> None:
        bad = [
            offered(id="bad-key", host_key="ssh-rsa AAAA"),
            offered(id="opt", host_key='command="sh" ' + RIG_KEY),
            offered(id="dots", data_dir="/home/../etc"),
            offered(id="user", ssh_user="-oProxyCommand=x"),
            offered(id="colon:id"),
            offered(id="idx", accelerators=[{"id": "x", "index": True}]),
            offered(id="arch", arch="mips"),
        ]
        self.assertEqual(self.offer(*bad, offered(id="good")), "OK 1")
        enrolled = self.agent.fleet.enrolled_ids
        self.assertEqual(enrolled, {"good"})

    def test_a_hand_written_host_outranks_an_offer_of_the_same_id(self) -> None:
        self.assertEqual(self.offer(offered(id="h1")), "OK 0")
        self.assertEqual(self.agent.fleet.hosts["h1"].ssh, "hypellm@h1.test")

    def test_a_withdrawn_host_is_dropped_and_its_key_unpinned(self) -> None:
        self.offer(offered())
        self.assertEqual(self.offer(), "OK 0")
        self.assertNotIn("rig", self.agent.fleet.hosts)
        with open(self.known, encoding="utf-8") as handle:
            self.assertEqual(handle.read(), "")

    def test_a_restart_rebuilds_the_same_table_from_the_state_file(self) -> None:
        self.offer(offered())
        config = agent_module.EnrollmentConfig.from_document(self.document)
        hosts, keys = agent_module.load_enrolled(config)
        restarted = agent_module.Fleet(self.document, hosts)
        self.assertEqual(restarted.digest(), self.agent.digest)
        self.assertEqual(keys, {"rig": RIG_KEY})

    def test_a_hand_written_deployment_may_run_on_an_enrolled_host(self) -> None:
        self.offer(offered())
        document = json.loads(json.dumps(self.document))
        document["deployments"] = [
            {"id": "rig-llm", "host": "rig", "accelerator": "rig-gpu0",
             "start": ["docker", "start", "llm"], "stop": ["docker", "stop", "llm"]}
        ]
        hosts, _ = agent_module.load_enrolled(
            agent_module.EnrollmentConfig.from_document(document)
        )
        fleet = agent_module.Fleet(document, hosts)
        self.assertIn("rig-llm", fleet.deployments)

    def test_accept_without_an_allowlist_is_a_configuration_error(self) -> None:
        document = json.loads(json.dumps(self.document))
        document["enrollment"]["cidrs"] = []
        with self.assertRaises(ValueError):
            agent_module.Fleet(document)

    def test_an_offer_over_the_socket_is_answered_and_the_session_ends(self) -> None:
        socket_path = os.path.join(self._dir.name, "agent.sock")
        server = agent_module.Server(socket_path, agent_module.Handler)
        server.agent = self.agent  # type: ignore[attr-defined]
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            client.settimeout(5.0)
            client.connect(socket_path)
            reader = client.makefile("rb")
            # The router's digest disagrees with the agent's; ENROLL is still
            # served, because it is how the disagreement resolves.
            tag = agent_module.hello_tag(b"k" * 32, "1", "n-enroll", "router-digest")
            client.sendall(f"HELLO 1 n-enroll router-digest {tag}\n".encode())
            self.assertTrue(reader.readline().startswith(b"OK "))
            payload = json.dumps({"hosts": [offered()]}).encode()
            client.sendall(f"ENROLL {len(payload)}\n".encode() + payload)
            self.assertEqual(reader.readline(), b"OK 1\n")
            self.assertEqual(reader.readline(), b"", "the session ended after the offer")
            client.close()

            unauthenticated = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            unauthenticated.settimeout(5.0)
            unauthenticated.connect(socket_path)
            unauthenticated.sendall(b"ENROLL 2\n{}")
            self.assertEqual(unauthenticated.makefile("rb").readline(), b"ERR unauthenticated\n")
            unauthenticated.close()

            oversize = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            oversize.settimeout(5.0)
            oversize.connect(socket_path)
            oversize_reader = oversize.makefile("rb")
            tag = agent_module.hello_tag(b"k" * 32, "1", "n-big", "d")
            oversize.sendall(f"HELLO 1 n-big d {tag}\n".encode())
            oversize_reader.readline()
            oversize.sendall(f"ENROLL {agent_module.MAX_OFFER_BYTES + 1}\n".encode())
            self.assertEqual(oversize_reader.readline(), b"ERR malformed\n")
            oversize.close()
        finally:
            server.shutdown()
            server.server_close()



# -- Specification 26.12: image relay, verification, and container templates --

import gzip
import io
import shlex
import shutil
import tarfile


def _tar_bytes(files: dict[str, bytes]) -> bytes:
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w") as tar:
        for name, data in files.items():
            info = tarfile.TarInfo(name)
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))
    return buffer.getvalue()


def _sha(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def build_image(layer_contents: list[bytes], *, oci: bool, extra: dict[str, bytes] | None = None):
    """A `docker save` archive of one image. Returns (archive bytes, image id)."""
    layers = [_tar_bytes({f"file{i}": content}) for i, content in enumerate(layer_contents)]
    config = json.dumps(
        {"architecture": "arm64", "rootfs": {"type": "layers", "diff_ids": [_sha(l) for l in layers]}}
    ).encode()
    image_id = _sha(config)
    files: dict[str, bytes] = {}
    if oci:
        names = []
        for layer in layers:
            # OCI blobs may be compressed; the diff_id is still the digest
            # of the uncompressed layer.
            blob = gzip.compress(layer, mtime=0)
            name = f"blobs/sha256/{hashlib.sha256(blob).hexdigest()}"
            files[name] = blob
            names.append(name)
        config_name = f"blobs/sha256/{image_id.split(':')[1]}"
        files[config_name] = config
        files["oci-layout"] = b'{"imageLayoutVersion":"1.0.0"}'
        files["index.json"] = b'{"schemaVersion":2,"manifests":[]}'
    else:
        names = []
        for i, layer in enumerate(layers):
            files[f"l{i}/layer.tar"] = layer
            names.append(f"l{i}/layer.tar")
        config_name = f"{image_id.split(':')[1]}.json"
        files[config_name] = config
    files["manifest.json"] = json.dumps(
        [{"Config": config_name, "RepoTags": ["model:arm"], "Layers": names}]
    ).encode()
    files.update(extra or {})
    return _tar_bytes(files), image_id


class ArchiveVerificationTest(unittest.TestCase):
    """A relayed archive is hashed against the image ID before anything loads it."""

    def setUp(self) -> None:
        self._dir = tempfile.TemporaryDirectory()

    def tearDown(self) -> None:
        self._dir.cleanup()

    def spool(self, data: bytes) -> str:
        path = os.path.join(self._dir.name, f"spool-{len(os.listdir(self._dir.name))}.tar")
        Path(path).write_bytes(data)
        return path

    def refused(self, data: bytes, image_id: str) -> str:
        with self.assertRaises(agent_module.ArchiveError) as caught:
            agent_module.verify_image_archive(self.spool(data), image_id)
        return caught.exception.code

    def test_both_layouts_docker_writes_verify(self) -> None:
        for oci in (False, True):
            with self.subTest(oci=oci):
                data, image_id = build_image([b"weights", b"server"], oci=oci)
                verified = agent_module.verify_image_archive(self.spool(data), image_id)
                self.assertEqual(verified.image_id, image_id)
                self.assertEqual(len(verified.layers), 2)
                self.assertEqual([l.compressed for l in verified.layers], [oci, oci])

    def test_a_tampered_layer_is_refused_though_the_config_is_untouched(self) -> None:
        honest, image_id = build_image([b"weights"], oci=False)
        # The same layer path with other content: the config, and so the ID,
        # still say what the layer should have been.
        layer = _tar_bytes({"file0": b"backdoor"})
        tampered = honest.replace(
            _tar_bytes({"file0": b"weights"}), layer
        )
        self.assertNotEqual(honest, tampered)
        self.assertEqual(self.refused(tampered, image_id), "checksum_mismatch")

    def test_a_tampered_config_or_the_wrong_id_is_refused(self) -> None:
        data, image_id = build_image([b"weights"], oci=True)
        other = "sha256:" + "0" * 64
        self.assertEqual(self.refused(data, other), "checksum_mismatch")
        # A config rewritten to describe the tampered layer hashes to a new ID.
        bad, bad_id = build_image([b"backdoor"], oci=True)
        self.assertNotEqual(bad_id, image_id)
        self.assertEqual(self.refused(bad, image_id), "checksum_mismatch")

    def test_an_oci_blob_that_does_not_hash_to_its_name_is_refused(self) -> None:
        data, image_id = build_image([b"weights"], oci=True)
        # Same uncompressed layer, recompressed differently: its diff_id still
        # matches, but it is no longer the blob its name claims.
        with tarfile.open(fileobj=io.BytesIO(data)) as tar:
            files = {m.name: tar.extractfile(m).read() for m in tar.getmembers()}
        blob = next(n for n, v in files.items() if n.startswith("blobs/") and v[:2] == b"\x1f\x8b")
        files[blob] = gzip.compress(gzip.decompress(files[blob]), compresslevel=1, mtime=1)
        self.assertEqual(self.refused(_tar_bytes(files), image_id), "checksum_mismatch")

    def test_an_archive_of_two_images_or_with_an_escaping_link_is_refused(self) -> None:
        data, image_id = build_image([b"weights"], oci=False)
        with tarfile.open(fileobj=io.BytesIO(data)) as tar:
            files = {m.name: tar.extractfile(m).read() for m in tar.getmembers()}
        manifest = json.loads(files["manifest.json"])
        files["manifest.json"] = json.dumps(manifest * 2).encode()
        self.assertEqual(self.refused(_tar_bytes(files), image_id), "archive_not_one_image")

        buffer = io.BytesIO()
        with tarfile.open(fileobj=buffer, mode="w") as tar:
            link = tarfile.TarInfo("manifest.json")
            link.type = tarfile.SYMTYPE
            link.linkname = "../../etc/passwd"
            tar.addfile(link)
        self.assertEqual(self.refused(buffer.getvalue(), image_id), "archive_member_invalid")
        self.assertEqual(self.refused(b"not a tar at all", image_id), "archive_invalid")

    def test_the_destination_gets_a_rebuilt_archive_of_only_the_verified_parts(self) -> None:
        # The relayed archive carries an index.json naming something else,
        # which a newer `docker load` might prefer. None of it is forwarded.
        data, image_id = build_image(
            [b"weights", b"server"], oci=True,
            extra={"repositories": b'{"evil":{"latest":"x"}}'},
        )
        path = self.spool(data)
        verified = agent_module.verify_image_archive(path, image_id)
        out = io.BytesIO()
        agent_module.write_clean_archive(path, verified, "model:arm", out)
        rebuilt = self.spool(out.getvalue())
        again = agent_module.verify_image_archive(rebuilt, image_id)
        self.assertEqual([l.diff_id for l in again.layers], [l.diff_id for l in verified.layers])
        with tarfile.open(rebuilt) as tar:
            names = sorted(m.name for m in tar.getmembers())
            manifest = json.loads(tar.extractfile("manifest.json").read())
        self.assertEqual(
            names,
            sorted(["0/layer.tar", "1/layer.tar", f"{image_id[7:]}.json", "manifest.json"]),
        )
        self.assertEqual(manifest[0]["RepoTags"], ["model:arm"])
        self.assertEqual(agent_module.tagged("registry.local/llama"), "registry.local/llama:latest")
        self.assertEqual(agent_module.tagged("registry.local:5000/llama"), "registry.local:5000/llama:latest")


COPY_FLEET = {
    "hosts": [
        {"id": "h1", "arch": "aarch64", "ssh": "hypellm@h1.test"},
        {"id": "h3", "arch": "aarch64", "ssh": "hypellm@h3.test"},
        {"id": "h2", "arch": "x86_64", "ssh": "hypellm@h2.test"},
    ],
    "artifacts": [
        {"id": "model-arm", "arch": "aarch64", "digest": "sha256:abc", "image": "model:arm"},
        {"id": "other-arm", "arch": "aarch64", "digest": "sha256:def",
         "host_pull": {"h3": ["docker", "pull", "other:arm"]}},
    ],
}


class CopyTest(unittest.TestCase):
    """COPY relays through this machine and loads only what verified."""

    def setUp(self) -> None:
        self._dir = tempfile.TemporaryDirectory()
        self.document = json.loads(json.dumps(COPY_FLEET))
        self.document["transfer"] = {"spool_dir": self._dir.name, "max_spool_bytes": 1 << 30}
        self.agent = agent_module.Agent(agent_module.Fleet(self.document), b"k" * 32, 5)
        self.archive, self.image_id = build_image([b"weights"], oci=False)
        self.loaded: list[bytes] = []
        self.dest_reports = self.image_id
        self.saved_from: list[str] = []

        def save_to_file(host, reference, path, limit, expires_at, cancelled):  # type: ignore[no-untyped-def]
            self.saved_from.append(f"{host.id}:{reference}")
            Path(path).write_bytes(self.archive)
            return (0, "")

        def load_archive(host, write, expires_at, cancelled):  # type: ignore[no-untyped-def]
            out = io.BytesIO()
            write(out)
            self.loaded.append(out.getvalue())
            return (0, "")

        def run_on(host, argv, timeout=None):  # type: ignore[no-untyped-def]
            if argv[:3] == ["docker", "image", "inspect"]:
                return (0, self.dest_reports + "\n")
            return (1, "")

        self.agent.save_to_file = save_to_file  # type: ignore[method-assign]
        self.agent.load_archive = load_archive  # type: ignore[method-assign]
        self.agent.run_on = run_on  # type: ignore[method-assign]

    def tearDown(self) -> None:
        self._dir.cleanup()

    def settle(self, reply: str) -> str:
        self.assertTrue(reply.startswith("ACCEPTED "), reply)
        activation = reply.split(" ", 1)[1]
        for _ in range(500):
            status = self.agent.status(activation)
            if status.split(" ")[1] in agent_module.TERMINAL_STATES:
                return status
            time.sleep(0.01)
        self.fail("the copy did not settle")

    def copy(self, image_id: str | None = None) -> str:
        return self.agent.copy("model-arm", "h1", "h3", "600000", image_id or self.image_id)

    def test_an_honest_copy_loads_the_rebuilt_archive_and_leaves_no_spool(self) -> None:
        self.assertEqual(self.settle(self.copy()), "OK ready verified 1000")
        self.assertEqual(self.saved_from, ["h1:model:arm"])
        self.assertEqual(len(self.loaded), 1)
        path = os.path.join(self._dir.name, "check.tar")
        Path(path).write_bytes(self.loaded[0])
        agent_module.verify_image_archive(path, self.image_id)
        os.unlink(path)
        self.assertEqual(os.listdir(self._dir.name), [], "the spool is removed")

    def test_a_source_serving_something_else_loads_nothing(self) -> None:
        self.archive, _ = build_image([b"backdoor"], oci=False)
        self.assertEqual(self.settle(self.copy()), "OK failed checksum_mismatch 0")
        self.assertEqual(self.loaded, [], "nothing reached docker load")
        self.assertEqual(os.listdir(self._dir.name), [])

    def test_a_destination_that_reports_another_id_after_loading_fails(self) -> None:
        self.dest_reports = "sha256:" + "f" * 64
        self.assertEqual(self.settle(self.copy()), "OK failed checksum_mismatch 0")

    def test_a_pinned_id_cannot_be_widened_by_the_router(self) -> None:
        self.document["artifacts"][0]["image_id"] = self.image_id
        self.agent.fleet = agent_module.Fleet(self.document)
        self.assertEqual(self.copy("sha256:" + "e" * 64), "ERR checksum_mismatch")
        self.assertEqual(self.saved_from, [])

    def test_refusals_before_anything_runs(self) -> None:
        cases = [
            (("model-arm", "h1", "h1", "1000", self.image_id), "ERR unknown_host"),
            (("model-arm", "h1", "h2", "1000", self.image_id), "ERR arch_mismatch"),
            (("model-arm", "h1", "nope", "1000", self.image_id), "ERR unknown_host"),
            (("nope", "h1", "h3", "1000", self.image_id), "ERR unknown_artifact"),
            (("model-arm", "h1", "h3", "1e9", self.image_id), "ERR malformed"),
            (("model-arm", "h1", "h3", "1000", self.image_id.upper()), "ERR malformed"),
            (("model-arm", "h1", "h3", "1000", "sha256:x; rm -rf /"), "ERR malformed"),
        ]
        for args, expected in cases:
            with self.subTest(args=args):
                self.assertEqual(self.agent.copy(*args), expected)
        self.assertEqual(self.saved_from, [])
        disabled = json.loads(json.dumps(COPY_FLEET))
        agent = agent_module.Agent(agent_module.Fleet(disabled), b"k" * 32, 5)
        self.assertEqual(
            agent.copy("model-arm", "h1", "h3", "1000", self.image_id), "ERR copy_disabled"
        )

    def test_one_transfer_per_destination_whichever_verb_asked(self) -> None:
        release = threading.Event()

        def slow_save(host, reference, path, limit, expires_at, cancelled):  # type: ignore[no-untyped-def]
            release.wait(5)
            Path(path).write_bytes(self.archive)
            return (0, "")

        self.agent.save_to_file = slow_save  # type: ignore[method-assign]
        first = self.copy()
        self.assertEqual(self.copy(), first, "a repeated COPY is the same transfer")
        self.assertEqual(self.agent.fetch("other-arm", "h3", "1000"), "ERR host_busy")
        release.set()
        self.settle(first)

    def test_a_cancel_during_the_save_ends_the_copy_as_cancelled(self) -> None:
        started = threading.Event()

        def blocking_save(host, reference, path, limit, expires_at, cancelled):  # type: ignore[no-untyped-def]
            started.set()
            cancelled.wait(5)
            return (124, "cancelled")

        self.agent.save_to_file = blocking_save  # type: ignore[method-assign]
        reply = self.copy()
        started.wait(5)
        self.assertEqual(self.agent.cancel(reply.split(" ")[1]), "OK")
        self.assertTrue(self.settle(reply).startswith("OK cancelled cancelled"))
        self.assertEqual(self.loaded, [])

    def test_a_source_that_outgrows_the_spool_is_cut_off(self) -> None:
        agent = agent_module.Agent(agent_module.Fleet(self.document), b"k" * 32, 5)
        saved = agent_module.ssh_command
        agent_module.ssh_command = lambda host, argv: [  # type: ignore[assignment]
            sys.executable, "-c",
            "import sys\nwhile True: sys.stdout.buffer.write(b'x' * 65536)",
        ]
        try:
            path = os.path.join(self._dir.name, "big.tar")
            code, detail = agent.save_to_file(
                agent.fleet.hosts["h1"], "model:arm", path, 1 << 20,
                time.monotonic() + 30, threading.Event(),
            )
        finally:
            agent_module.ssh_command = saved
        self.assertEqual((code, detail), (1, "spool_full"))
        self.assertLessEqual(os.path.getsize(path), 1 << 20)


RUN_FLEET = {
    "hosts": [
        {
            "id": "rig", "arch": "x86_64", "ssh": "albert@rig.test",
            "data_dir": "/home/albert/.hypellm",
            "accelerators": [{"id": "rig-gpu1", "index": 1}],
        },
        {"id": "bare", "arch": "x86_64", "ssh": "albert@bare.test"},
    ],
    "artifacts": [
        {"id": "llama-server", "arch": "x86_64", "digest": "sha256:abc",
         "image": "llama-server:b5000"},
    ],
    "deployments": [
        {
            "id": "rig-qwen", "host": "rig", "accelerator": "rig-gpu1",
            "run": {
                "image": "llama-server",
                "ports": [{"bind": "192.168.1.20", "host": 8080, "container": 8080}],
                "env": ["LLAMA_ARG_CTX_SIZE=131072"],
                "args": ["--model", "/state/qwen.gguf", "--port", "8080"],
                "state_path": "/state",
            },
            "probe": ["curl", "-fsS", "http://127.0.0.1:8080/health"],
        }
    ],
}


def _shim_source() -> str:
    text = (Path(__file__).resolve().parent.parent / "host" / "install.sh").read_text()
    start = text.index("<<'SHIM'\n") + len("<<'SHIM'\n")
    return text[start:text.index("\nSHIM\n", start)] + "\n"


class RunTemplateTest(unittest.TestCase):
    """A templated deployment creates its own container, inside the data directory."""

    def fleet(self, mutate=None):  # type: ignore[no-untyped-def]
        document = json.loads(json.dumps(RUN_FLEET))
        if mutate:
            mutate(document)
        return agent_module.Fleet(document)

    def test_the_create_command_is_built_from_the_table_and_the_data_directory(self) -> None:
        fleet = self.fleet()
        deployment = fleet.deployments["rig-qwen"]
        mkdir, create, label = agent_module.container_plan(
            deployment, fleet.hosts["rig"], fleet.artifacts["llama-server"]
        )
        self.assertEqual(mkdir, ["mkdir", "-p", "/home/albert/.hypellm/containers/rig-qwen"])
        self.assertEqual(
            create,
            [
                "docker", "create", "--name", "hypellm-rig-qwen",
                "--label", f"hypellm.template={label}",
                "--gpus", "device=1",
                "-p", "192.168.1.20:8080:8080",
                "-v", "/home/albert/.hypellm/containers/rig-qwen:/state",
                "-e", "LLAMA_ARG_CTX_SIZE=131072",
                "--restart", "no",
                "llama-server:b5000", "--model", "/state/qwen.gguf", "--port", "8080",
            ],
        )
        self.assertEqual(deployment.start, ["docker", "start", "hypellm-rig-qwen"])
        self.assertEqual(deployment.container, "hypellm-rig-qwen")
        # The label follows the template: any change recreates the container.
        changed = self.fleet(lambda d: d["deployments"][0]["run"]["env"].append("X=1"))
        _, _, other = agent_module.container_plan(
            changed.deployments["rig-qwen"], changed.hosts["rig"], changed.artifacts["llama-server"]
        )
        self.assertNotEqual(label, other)

    def test_a_template_that_could_escape_the_data_directory_is_refused_at_load(self) -> None:
        def run(**fields):  # type: ignore[no-untyped-def]
            return lambda d: d["deployments"][0]["run"].update(fields)

        for name, mutate in [
            ("dot-dot id", lambda d: d["deployments"][0].update(id="..")),
            ("colon id", lambda d: d["deployments"][0].update(id="a:b")),
            ("host without data dir", lambda d: d["deployments"][0].update(host="bare")),
            ("state path escape", run(state_path="/state/../../etc")),
            ("relative state path", run(state_path="state")),
            ("container name", run(container="-privileged")),
            ("bind not an address", run(ports=[{"bind": "0.0.0.0;id", "host": 1}])),
            ("port out of range", run(ports=[{"host": 70000}])),
            ("env key", run(env=["BAD-KEY=1"])),
            ("newline arg", run(args=["a\nb"])),
            ("unknown image", run(image="nope")),
            ("data dir traversal", lambda d: d["hosts"][0].update(data_dir="/home/../etc")),
        ]:
            with self.subTest(name):
                with self.assertRaises(ValueError):
                    self.fleet(mutate)

    def test_a_container_is_created_only_when_absent_or_stale(self) -> None:
        fleet = self.fleet()
        agent = agent_module.Agent(fleet, b"k" * 32, 5)
        deployment = fleet.deployments["rig-qwen"]
        _, _, label = agent_module.container_plan(
            deployment, fleet.hosts["rig"], fleet.artifacts["llama-server"]
        )
        for existing, rm_code, expected_verbs, expected in [
            (None, 0, ["mkdir", "inspect", "create"], None),
            (label, 0, ["mkdir", "inspect"], None),
            ("0" * 64, 0, ["mkdir", "inspect", "rm", "create"], None),
            ("0" * 64, 1, ["mkdir", "inspect", "rm"], "container_busy"),
        ]:
            with self.subTest(existing=existing, rm_code=rm_code):
                ran: list[str] = []

                def run_on(host, argv, timeout=None):  # type: ignore[no-untyped-def]
                    verb = argv[0] if argv[0] == "mkdir" else argv[1]
                    ran.append(verb)
                    if verb == "inspect":
                        return (0, existing + "\n") if existing else (1, "")
                    if verb == "rm":
                        return (rm_code, "")
                    return (0, "")

                agent.run_on = run_on  # type: ignore[method-assign]
                self.assertEqual(agent.ensure_container(deployment, fleet.hosts["rig"]), expected)
                self.assertEqual(ran, expected_verbs)

    def test_every_command_the_template_produces_passes_the_host_shim(self) -> None:
        # The agent and the shim are two ends of one contract. A template the
        # shim refused would fail on a real slave and nowhere else.
        shell = shutil.which("dash") or "/bin/sh"
        fleet = self.fleet()
        deployment = fleet.deployments["rig-qwen"]
        with tempfile.TemporaryDirectory() as work:
            data = Path(work) / "data"
            (data / "bin").mkdir(parents=True)
            shim = data / "bin" / "hypellm-host-shim"
            shim.write_text(_shim_source())
            shim.chmod(0o755)
            tools = Path(work) / "tools"
            tools.mkdir()
            for tool in ("awk", "sed", "grep", "cat", "printf", "sh"):
                found = shutil.which(tool)
                if found:
                    (tools / tool).symlink_to(found)
            for tool in ("docker", "mkdir"):
                (tools / tool).write_text("#!/bin/sh\nexit 0\n")
                (tools / tool).chmod(0o755)
            host = fleet.hosts["rig"]
            host.data_dir = str(data)
            mkdir, create, label = agent_module.container_plan(
                deployment, host, fleet.artifacts["llama-server"]
            )
            for argv in [
                mkdir,
                create,
                ["docker", "inspect", "--format",
                 '{{index .Config.Labels "hypellm.template"}}', deployment.run.container],
                ["docker", "rm", deployment.run.container],
                deployment.start,
                deployment.stop,
                ["docker", "save", "llama-server:b5000"],
                ["docker", "load", "-q"],
                ["docker", "image", "inspect", "--format",
                 '{{.Id}} {{join .RepoDigests ","}}', "llama-server:b5000"],
                ["docker", "image", "inspect", "--format", "{{.Id}}", "llama-server:b5000"],
            ]:
                with self.subTest(argv=argv[:2]):
                    completed = subprocess.run(
                        [shell, str(shim)],
                        env={"PATH": str(tools), "SSH_ORIGINAL_COMMAND": shlex.join(argv)},
                        capture_output=True, text=True, timeout=10,
                    )
                    self.assertEqual(completed.returncode, 0, f"{argv}: {completed.stderr}")


if __name__ == "__main__":
    unittest.main()
