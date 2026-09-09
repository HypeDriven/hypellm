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
import sys
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


if __name__ == "__main__":
    unittest.main()
