#!/usr/bin/env python3
"""Conformance tests for the reference job shim (orchestration §11.3).

Run with `python3 job-shim/test_job_shim.py`. No network beyond loopback, no
GPU, no service: the "generator" is a small Python script written per run, so
every behaviour the shim has to get right — refusing a caller without the key,
refusing an input that is a reference rather than bytes, running without a
shell, serving only declared outputs — is exercised against a command whose
behaviour the test chooses.

Each test names the property it would catch the absence of.
"""

from __future__ import annotations

import base64
import http.client
import importlib.machinery
import importlib.util
import json
import os
import re
import stat
import sys
import tempfile
import threading
import time
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
KEY = "a-shim-key-for-the-tests-0123456789"
PNG = base64.b64encode(b"\x89PNG\r\n\x1a\nfake").decode()

GENERATOR = r'''
import json, os, sys, time
args = sys.argv[1:]
opts = dict(zip(args[::2], args[1::2]))
prompt = opts.get("--prompt", "")
out = opts["--out"]
with open(os.path.join(os.path.dirname(out), "argv.json"), "w") as f:
    json.dump(args, f)
if "sleep" in prompt:
    with open(os.path.join(out, "progress"), "w") as f:
        f.write("250")
    time.sleep(60)
if "invalid" in prompt:
    sys.exit(65)
if "oom" in prompt:
    sys.exit(75)
if "crash" in prompt:
    sys.exit(1)
if "missing" in prompt:
    sys.exit(0)
if "symlink" in prompt:
    os.symlink("/etc/passwd", os.path.join(out, "mesh.glb"))
    sys.exit(0)
if "huge" in prompt:
    with open(os.path.join(out, "mesh.glb"), "wb") as f:
        f.write(b"x" * 5000)
    sys.exit(0)
with open(opts["--image"], "rb") as f:
    image = f.read()
# An optional input has no placeholder; it is in the working directory or not.
keyframe = b""
if os.path.exists(os.path.join("in", "keyframe.png")):
    with open(os.path.join("in", "keyframe.png"), "rb") as f:
        keyframe = b"KEYFRAME:" + f.read()
with open(os.path.join(out, "mesh.glb"), "wb") as f:
    f.write(b"MESH:" + image + keyframe)
'''


def load_shim():
    path = os.path.join(HERE, "hypellm-job-shim")
    loader = importlib.machinery.SourceFileLoader("hypellm_job_shim", path)
    spec = importlib.util.spec_from_loader("hypellm_job_shim", loader)
    module = importlib.util.module_from_spec(spec)
    sys.modules["hypellm_job_shim"] = module
    loader.exec_module(module)
    return module


shim_module = load_shim()


class Quiet:
    def write(self, _text: str) -> None:
        pass

    def flush(self) -> None:
        pass


class ShimCase(unittest.TestCase):
    def setUp(self) -> None:
        self.root = tempfile.mkdtemp(prefix="hypellm-job-shim-")
        self.key_file = os.path.join(self.root, "key")
        with open(self.key_file, "w") as f:
            f.write(KEY)
        os.chmod(self.key_file, 0o600)
        self.generator = os.path.join(self.root, "generator.py")
        with open(self.generator, "w") as f:
            f.write(GENERATOR)
        self.work = os.path.join(self.root, "work")
        self.config_path = os.path.join(self.root, "config.json")
        self.write_config()
        self.shim = shim_module.Shim(shim_module.load_config(self.config_path), shim_module.Log(Quiet()))
        self.thread = threading.Thread(target=self.shim.serve, daemon=True)
        self.thread.start()
        self.port = self.shim.address[1]

    def write_config(self, **overrides) -> None:
        document = {
            "listen": "127.0.0.1:0",
            "key_file": self.key_file,
            "work_dir": self.work,
            "max_body_bytes": 64 * 1024,
            "max_part_bytes": 1000,
            "verbs": {
                "image-to-3d": {
                    "argv": [sys.executable, self.generator, "--image", "{input:image}",
                             "--prompt", "{prompt}", "--params", "{params_file}", "--out", "{out_dir}"],
                    "inputs": {"image": ["image/png"]},
                    "parts": {"mesh": {"file": "mesh.glb", "media_type": "model/gltf-binary"}},
                    "timeout_s": 30,
                    "progress_file": "progress",
                }
            },
        }
        document.update(overrides)
        with open(self.config_path, "w") as f:
            json.dump(document, f)

    def tearDown(self) -> None:
        self.shim.close()
        self.thread.join(timeout=5)

    # -- client -----------------------------------------------------------

    def call(self, method: str, path: str, body=None, key: str | None = KEY, headers=None):
        connection = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        all_headers = dict(headers or {})
        if key is not None:
            all_headers["Authorization"] = f"Bearer {key}"
        payload = None
        if body is not None:
            payload = body if isinstance(body, bytes) else json.dumps(body).encode()
            all_headers.setdefault("Content-Type", "application/json")
        connection.request(method, path, body=payload, headers=all_headers)
        response = connection.getresponse()
        data = response.read()
        result = (response.status, dict(response.getheaders()), data)
        connection.close()
        return result

    def submit(self, prompt: str = "a chair", **extra):
        body = {"verb": "image-to-3d", "prompt": prompt,
                "inputs": [{"name": "image", "media_type": "image/png", "data": PNG}]}
        body.update(extra)
        return self.call("POST", "/job/v1/jobs", body)

    def wait(self, job: str, timeout: float = 15) -> dict:
        until = time.monotonic() + timeout
        while True:
            status, _, data = self.call("GET", f"/job/v1/jobs/{job}")
            self.assertEqual(status, 200, data)
            reply = json.loads(data)
            if reply["state"] in ("succeeded", "failed", "cancelled"):
                return reply
            self.assertLess(time.monotonic(), until, reply)
            time.sleep(0.05)

    def job_dirs(self) -> list[str]:
        return [e for e in os.listdir(self.work) if re.match(r"^j[0-9a-f]{24}$", e)]

    # -- tests ------------------------------------------------------------

    def test_every_route_refuses_a_caller_without_the_key(self) -> None:
        for key in (None, "wrong-key-of-a-decent-length"):
            for method, path, body in (
                ("GET", "/job/v1/health", None),
                ("POST", "/job/v1/jobs", {"verb": "image-to-3d"}),
                ("GET", "/job/v1/jobs/jabc", None),
                ("GET", "/job/v1/jobs/jabc/parts/mesh", None),
                ("DELETE", "/job/v1/jobs/jabc", None),
            ):
                status, _, _ = self.call(method, path, body, key=key)
                self.assertEqual(status, 401, (method, path, key))
        self.assertEqual(self.job_dirs(), [], "a refused caller started a job")

    def test_a_job_runs_without_a_shell_and_serves_only_its_declared_part(self) -> None:
        prompt = "a chair; rm -rf / $(id) `id` | cat"
        status, _, data = self.submit(prompt)
        self.assertEqual(status, 202, data)
        job = json.loads(data)["id"]
        self.assertRegex(job, r"^[A-Za-z0-9_-]{1,64}$")
        reply = self.wait(job)
        self.assertEqual(reply["state"], "succeeded", reply)
        self.assertEqual(reply["parts"], [{"name": "mesh", "media_type": "model/gltf-binary", "bytes": 17}])
        # The prompt reached the command as one argument, exactly.
        with open(os.path.join(self.work, job, "argv.json")) as f:
            argv = json.load(f)
        self.assertEqual(argv[argv.index("--prompt") + 1], prompt)
        status, headers, body = self.call("GET", f"/job/v1/jobs/{job}/parts/mesh")
        self.assertEqual(status, 200)
        self.assertEqual(body, b"MESH:" + base64.b64decode(PNG))
        self.assertEqual(headers["Content-Type"], "model/gltf-binary")
        self.assertEqual(headers["Content-Length"], str(len(body)))
        # Nothing undeclared is served: not the log, not the inputs.
        for name in ("log", "argv", "progress", "image"):
            self.assertEqual(self.call("GET", f"/job/v1/jobs/{job}/parts/{name}")[0], 404, name)

    def test_an_input_is_bytes_only_and_a_refused_submit_runs_nothing(self) -> None:
        image = {"name": "image", "media_type": "image/png", "data": PNG}
        for body in (
            {"verb": "image-to-3d", "inputs": [dict(image, url="http://169.254.169.254/")]},
            {"verb": "image-to-3d", "inputs": [{"name": "image", "media_type": "image/png", "path": "/etc/passwd"}]},
            {"verb": "image-to-3d", "inputs": [dict(image, name="../image")]},
            {"verb": "image-to-3d", "inputs": [dict(image, media_type="text/html")]},
            {"verb": "image-to-3d", "inputs": [dict(image, data="/etc/passwd")]},
            {"verb": "image-to-3d", "inputs": [dict(image, name="other")]},
            {"verb": "image-to-3d", "inputs": []},
            {"verb": "image-to-3d", "inputs": [image], "callback": "http://x"},
            {"verb": "teleport", "inputs": [image]},
            {"verb": "image-to-3d", "inputs": [image], "params": {"cfg": 7}},
            {"verb": "image-to-3d", "inputs": [image], "params": {"seed": -1}},
        ):
            status, _, data = self.call("POST", "/job/v1/jobs", body)
            self.assertEqual(status, 400, body)
            self.assertEqual(json.loads(data), {"error": "invalid_input"})
        self.assertEqual(self.job_dirs(), [], "a refused submit left a job behind")

    def test_a_commands_exit_code_maps_onto_the_closed_error_set(self) -> None:
        for prompt, error in (("invalid", "invalid_input"), ("oom", "out_of_memory"), ("crash", "internal")):
            status, _, data = self.submit(prompt)
            self.assertEqual(status, 202, data)
            reply = self.wait(json.loads(data)["id"])
            self.assertEqual((reply["state"], reply["error"]), ("failed", error), prompt)
            self.assertNotIn("parts", reply)

    def test_a_linked_missing_or_oversized_output_is_never_served(self) -> None:
        for prompt in ("symlink", "missing", "huge"):
            status, _, data = self.submit(prompt)
            job = json.loads(data)["id"]
            reply = self.wait(job)
            self.assertEqual((reply["state"], reply.get("error")), ("failed", "internal"), prompt)
            self.assertEqual(self.call("GET", f"/job/v1/jobs/{job}/parts/mesh")[0], 404, prompt)
            self.assertFalse(os.path.exists(os.path.join(self.work, job)), "a failed job kept its files")

    def test_one_job_runs_at_a_time_and_a_cancel_stops_it_and_its_files(self) -> None:
        status, _, data = self.submit("sleep")
        job = json.loads(data)["id"]
        until = time.monotonic() + 10
        while True:
            reply = json.loads(self.call("GET", f"/job/v1/jobs/{job}")[2])
            if reply.get("progress_permille") == 250:
                break
            self.assertLess(time.monotonic(), until, reply)
            time.sleep(0.05)
        busy, _, data = self.submit("a chair")
        self.assertEqual((busy, json.loads(data)), (503, {"error": "not_ready"}))
        pid = self.shim.jobs.jobs[job].process.pid
        status, _, data = self.call("DELETE", f"/job/v1/jobs/{job}")
        self.assertEqual((status, json.loads(data)), (202, {"stopped": True}))
        self.assertEqual(self.wait(job)["state"], "cancelled")
        with self.assertRaises(ProcessLookupError):
            os.kill(pid, 0)
        self.assertFalse(os.path.exists(os.path.join(self.work, job)))
        status, _, data = self.submit("a chair")
        self.assertEqual(status, 202, "the shim did not accept work after a cancel")
        self.wait(json.loads(data)["id"])

    def test_a_path_that_is_not_an_identifier_reaches_nothing(self) -> None:
        status, _, data = self.submit()
        job = json.loads(data)["id"]
        self.wait(job)
        for path in (
            f"/job/v1/jobs/{job}/parts/..%2Flog",
            f"/job/v1/jobs/{job}/parts/../log",
            "/job/v1/jobs/..",
            f"/job/v1/jobs/{job}?x=1",
            "/job/v1/jobs/nosuchjob",
        ):
            self.assertEqual(self.call("GET", path)[0], 404, path)

    def test_bodies_are_bounded_and_unambiguous(self) -> None:
        big = b'{"verb":"image-to-3d","prompt":"' + b"x" * 70_000 + b'"}'
        self.assertEqual(self.call("POST", "/job/v1/jobs", big)[0], 413)
        duplicate = b'{"verb":"image-to-3d","verb":"text-to-music"}'
        self.assertEqual(self.call("POST", "/job/v1/jobs", duplicate)[0], 400)
        chunked = self.call("POST", "/job/v1/jobs", b"{}", headers={"Transfer-Encoding": "chunked"})
        self.assertIn(chunked[0], (400, 411))

    def test_an_optional_input_may_be_left_out_and_a_required_one_may_not(self) -> None:
        self.shim.close()
        self.thread.join(timeout=5)
        verb = json.load(open(self.config_path))["verbs"]["image-to-3d"]
        verb["inputs"]["keyframe"] = {"media_types": ["image/png"], "optional": True}
        self.write_config(verbs={"image-to-3d": verb})
        self.shim = shim_module.Shim(shim_module.load_config(self.config_path), shim_module.Log(Quiet()))
        self.thread = threading.Thread(target=self.shim.serve, daemon=True)
        self.thread.start()
        self.port = self.shim.address[1]

        keyframe = base64.b64encode(b"K").decode()
        for inputs, expected in (
            ([], None),
            ([{"name": "keyframe", "media_type": "image/png", "data": keyframe}], b"KEYFRAME:K"),
        ):
            status, _, data = self.submit(inputs=[
                {"name": "image", "media_type": "image/png", "data": PNG}, *inputs])
            self.assertEqual(status, 202, data)
            job = json.loads(data)["id"]
            self.assertEqual(self.wait(job)["state"], "succeeded")
            _, _, mesh = self.call("GET", f"/job/v1/jobs/{job}/parts/mesh")
            self.assertEqual(mesh.endswith(b"KEYFRAME:K"), expected is not None, mesh)
        # The optional input does not make the required one optional, and is
        # still held to its own media types.
        status, _, _ = self.submit(inputs=[{"name": "keyframe", "media_type": "image/png", "data": keyframe}])
        self.assertEqual(status, 400)
        status, _, _ = self.submit(inputs=[
            {"name": "image", "media_type": "image/png", "data": PNG},
            {"name": "keyframe", "media_type": "audio/wav", "data": keyframe}])
        self.assertEqual(status, 400)
        self.assertEqual(self.job_dirs().__len__(), 2)

    def test_health_names_the_verbs_it_serves(self) -> None:
        status, _, data = self.call("GET", "/job/v1/health")
        self.assertEqual((status, json.loads(data)), (200, {"verbs": ["image-to-3d"]}))


class ConfigurationCase(unittest.TestCase):
    def setUp(self) -> None:
        self.root = tempfile.mkdtemp(prefix="hypellm-job-shim-config-")
        self.key_file = os.path.join(self.root, "key")
        with open(self.key_file, "w") as f:
            f.write(KEY)
        os.chmod(self.key_file, 0o600)

    def load(self, verb: dict, **top) -> object:
        document = {"listen": "127.0.0.1:0", "key_file": self.key_file,
                    "work_dir": os.path.join(self.root, "work"), "verbs": {"image-to-3d": verb}}
        document.update(top)
        path = os.path.join(self.root, "config.json")
        with open(path, "w") as f:
            json.dump(document, f)
        return shim_module.load_config(path)

    def good(self, **changes) -> dict:
        verb = {"argv": ["/opt/run", "{input:image}", "{out_dir}"],
                "inputs": {"image": ["image/png"]},
                "parts": {"mesh": {"file": "mesh.glb", "media_type": "model/gltf-binary"}}}
        verb.update(changes)
        return verb

    def test_a_configuration_that_could_escape_is_refused(self) -> None:
        self.load(self.good())
        for verb in (
            self.good(argv=["run", "{out_dir}"]),
            self.good(argv=["/opt/run", "{env}"]),
            self.good(argv=["/opt/run", "{input:other}"]),
            self.good(parts={"mesh": {"file": "../mesh.glb", "media_type": "model/gltf-binary"}}),
            self.good(parts={"mesh": {"file": "a/mesh.glb", "media_type": "model/gltf-binary"}}),
            self.good(parts={"page": {"file": "p.html", "media_type": "text/html"}}),
            self.good(inputs={"image": ["text/html"]}),
            self.good(shell=True),
            # An absent optional input has no whole value to stand in for it.
            self.good(inputs={"image": {"media_types": ["image/png"], "optional": True}}),
            self.good(inputs={"image": {"media_types": ["image/png"], "path": "/etc"}}),
            self.good(inputs={"image": {"media_types": ["image/png"], "optional": "yes"}}),
        ):
            with self.assertRaises(shim_module.ConfigError, msg=json.dumps(verb)):
                self.load(verb)

    def test_a_key_others_can_read_is_refused(self) -> None:
        os.chmod(self.key_file, 0o644)
        with self.assertRaises(shim_module.ConfigError):
            self.load(self.good())
        os.chmod(self.key_file, stat.S_IRUSR | stat.S_IWUSR)
        self.load(self.good())

    def test_a_restart_removes_what_the_last_process_left(self) -> None:
        config = self.load(self.good())
        leftover = os.path.join(config.work_dir, "j" + "0" * 24)
        os.makedirs(leftover)
        shim = shim_module.Shim(config, shim_module.Log(Quiet()))
        try:
            self.assertFalse(os.path.exists(leftover))
        finally:
            shim.close()


if __name__ == "__main__":
    unittest.main(verbosity=1)
