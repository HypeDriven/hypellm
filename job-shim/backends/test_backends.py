#!/usr/bin/env python3
"""Tests for the job-shim backends, each run the way the shim runs it.

Run with `python3 job-shim/backends/test_backends.py`. Every service is a fake
on loopback that records what it was sent, so each test can assert what a
backend sends, what it refuses to send, and which exit code it leaves for the
shim — not merely that it ran. No GPU, no network beyond loopback.
"""

from __future__ import annotations

import base64
import hashlib
import http.server
import json
import os
import shutil
import signal
import socketserver
import struct
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from typing import Any, Callable

HERE = os.path.dirname(os.path.abspath(__file__))
PNG = b"\x89PNG\r\n\x1a\n" + b"pixels"
GLB = b"glTF" + b"\x02\x00\x00\x00mesh"
FLAC = b"fLaC" + b"\x00audio"
MP4 = b"\x00\x00\x00\x18ftypmp42" + b"video"
WAV = b"RIFF\x24\x00\x00\x00WAVEfmt "
SAFETENSORS = struct.pack("<Q", 2) + b"{}" + b"tensors"

Reply = tuple[int, dict[str, str], bytes]


class FakeService:
    """A loopback HTTP server answering from `route`, recording every request."""

    def __init__(self, route: Callable[[str, str, bytes], Reply]) -> None:
        self.route = route
        self.requests: list[tuple[str, str, bytes]] = []
        self.lock = threading.Lock()
        fake = self

        class Handler(http.server.BaseHTTPRequestHandler):
            def log_message(self, *_args: Any) -> None:
                pass

            def handle_any(self) -> None:
                length = int(self.headers.get("Content-Length") or 0)
                body = self.rfile.read(length) if length else b""
                with fake.lock:
                    fake.requests.append((self.command, self.path, body))
                status, headers, data = fake.route(self.command, self.path, body)
                self.send_response(status)
                for key, value in headers.items():
                    self.send_header(key, value)
                self.send_header("Content-Length", str(len(data)))
                self.send_header("Connection", "close")
                self.end_headers()
                self.wfile.write(data)

            do_GET = do_POST = do_DELETE = handle_any  # noqa: N815

        class Server(socketserver.ThreadingMixIn, http.server.HTTPServer):
            daemon_threads = True

        self.server = Server(("127.0.0.1", 0), Handler)
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        self.url = f"http://127.0.0.1:{self.server.server_address[1]}"

    def close(self) -> None:
        self.server.shutdown()
        self.server.server_close()

    def sent(self, method: str | None = None, prefix: str = "") -> list[tuple[str, str, bytes]]:
        with self.lock:
            return [r for r in self.requests if (method is None or r[0] == method) and r[1].startswith(prefix)]


def json_reply(document: Any, status: int = 200) -> Reply:
    return status, {"Content-Type": "application/json"}, json.dumps(document).encode()


class Job:
    """A job directory laid out as the shim lays it out."""

    def __init__(self, root: str, prompt: str = "", params: dict | None = None,
                 options: dict | None = None, inputs: dict[str, tuple[str, bytes]] | None = None) -> None:
        self.directory = tempfile.mkdtemp(dir=root)
        self.out = os.path.join(self.directory, "out")
        os.makedirs(os.path.join(self.directory, "in"))
        os.makedirs(self.out)
        for name, (extension, data) in (inputs or {}).items():
            with open(os.path.join(self.directory, "in", f"{name}.{extension}"), "wb") as f:
                f.write(data)
        for name, document in (("params.json", params or {}), ("options.json", options or {})):
            with open(os.path.join(self.directory, name), "w") as f:
                json.dump(document, f)
        self.prompt = prompt

    def argv(self, backend: str, service: str, *extra: str) -> list[str]:
        return [sys.executable, os.path.join(HERE, backend), "--service", service, "--prompt", self.prompt,
                "--params", os.path.join(self.directory, "params.json"),
                "--options", os.path.join(self.directory, "options.json"),
                "--out", self.out, *extra]

    def run(self, backend: str, service: str, *extra: str, timeout: float = 60) -> int:
        process = self.start(backend, service, *extra)
        return process.wait(timeout=timeout)

    def start(self, backend: str, service: str, *extra: str) -> subprocess.Popen[bytes]:
        # The shim's environment, plus a canary nothing should pass on.
        environment = {"PATH": "/usr/local/bin:/usr/bin:/bin", "HOME": self.directory,
                       "LANG": "C.UTF-8", "CANARY": "leaked"}
        return subprocess.Popen(self.argv(backend, service, *extra), cwd=self.directory, env=environment,
                                stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                start_new_session=True)

    def outputs(self) -> dict[str, bytes]:
        found = {}
        for name in os.listdir(self.out):
            if name != "progress" and not name.startswith("."):
                with open(os.path.join(self.out, name), "rb") as f:
                    found[name] = f.read()
        return found


class Case(unittest.TestCase):
    def setUp(self) -> None:
        self.root = tempfile.mkdtemp(prefix="hypellm-backends-")
        self.services: list[FakeService] = []

    def tearDown(self) -> None:
        for service in self.services:
            service.close()
        shutil.rmtree(self.root, ignore_errors=True)

    def fake(self, route: Callable[[str, str, bytes], Reply]) -> FakeService:
        service = FakeService(route)
        self.services.append(service)
        return service

    def job(self, **kwargs: Any) -> Job:
        return Job(self.root, **kwargs)


# --------------------------------------------------------------------------
# FLUX.2
# --------------------------------------------------------------------------


class FluxCase(Case):
    def flux(self, status: int = 200, image: bytes = PNG) -> FakeService:
        def route(method: str, path: str, body: bytes) -> Reply:
            if (method, path) != ("POST", "/generate"):
                return json_reply({"detail": "not found"}, 404)
            if status != 200:
                return json_reply({"detail": "no"}, status)
            count = json.loads(body)["num_images"]
            return json_reply({"images": [{"base64": base64.b64encode(image + bytes([i])).decode()}
                                          for i in range(count)], "seed": 1})
        return self.fake(route)

    def test_an_edit_sends_the_references_bytes_and_every_image_is_written(self) -> None:
        service = self.flux()
        job = self.job(prompt="a teapot", params={"count": 2, "width": 512, "seed": 9},
                       options={"guidance_scale": 3.5}, inputs={"reference": ("png", b"REFERENCE")})
        self.assertEqual(job.run("flux.py", service.url), 0)
        (_, _, body), = service.sent("POST", "/generate")
        sent = json.loads(body)
        self.assertEqual(sent["images"], [base64.b64encode(b"REFERENCE").decode()])
        self.assertEqual((sent["num_images"], sent["width"], sent["height"], sent["seed"]), (2, 512, 1024, 9))
        self.assertEqual(sent["guidance_scale"], 3.5)
        self.assertEqual(job.outputs(), {"image.png": PNG + b"\x00", "image-2.png": PNG + b"\x01"})

    def test_a_param_or_option_the_service_cannot_honour_sends_nothing(self) -> None:
        service = self.flux()
        for kwargs in (
            {"params": {"duration_ms": 5000}},
            {"options": {"images": ["/etc/passwd"]}},
            {"params": {"width": 1000}},
            {"params": {"count": 5}},
        ):
            job = self.job(prompt="a teapot", **kwargs)
            self.assertEqual(job.run("flux.py", service.url), 65, kwargs)
        self.assertEqual(service.sent(), [])

    def test_a_services_status_maps_onto_the_shims_exit_codes(self) -> None:
        for status, code in ((507, 75), (400, 65), (500, 70)):
            job = self.job(prompt="a teapot")
            self.assertEqual(job.run("flux.py", self.flux(status=status).url), code, status)
            self.assertEqual(job.outputs(), {})

    def test_bytes_that_are_not_a_png_are_not_written(self) -> None:
        job = self.job(prompt="a teapot")
        self.assertEqual(job.run("flux.py", self.flux(image=b"<html>").url), 70)
        self.assertEqual(job.outputs(), {})


# --------------------------------------------------------------------------
# TRELLIS
# --------------------------------------------------------------------------


class TrellisCase(Case):
    def trellis(self, url_for: Callable[[str], str] = lambda f: f"/outputs/x.{f}") -> FakeService:
        def route(method: str, path: str, body: bytes) -> Reply:
            if (method, path) == ("POST", "/generate"):
                formats = json.loads(body)["formats"]
                return json_reply({"files": {f: {"url": url_for(f)} for f in formats}})
            if method == "GET" and path.startswith("/outputs/"):
                return 200, {}, GLB if path.endswith("glb") else b"ply " + path.encode()
            return json_reply({}, 404)
        return self.fake(route)

    def test_a_mesh_is_always_made_and_each_file_is_fetched_from_outputs(self) -> None:
        service = self.trellis()
        job = self.job(options={"formats": ["gaussian_ply"], "texture_size": 2048}, params={"steps": 20},
                       inputs={"image": ("png", PNG)})
        self.assertEqual(job.run("trellis.py", service.url), 0)
        (_, _, body), = service.sent("POST", "/generate")
        sent = json.loads(body)
        self.assertEqual(sent["formats"], ["glb", "gaussian_ply"])
        self.assertEqual(sent["image"], base64.b64encode(PNG).decode())
        self.assertEqual((sent["ss_sampling_steps"], sent["slat_sampling_steps"], sent["texture_size"]), (20, 20, 2048))
        self.assertEqual(sorted(job.outputs()), ["gaussians.ply", "mesh.glb"])

    def test_a_reply_naming_a_file_outside_outputs_is_not_followed(self) -> None:
        for url in ("/etc/passwd", "http://169.254.169.254/latest", "/outputs/../secret.glb", "/outputs/a/b.glb"):
            service = self.trellis(url_for=lambda _f, u=url: u)
            job = self.job(inputs={"image": ("png", PNG)})
            self.assertEqual(job.run("trellis.py", service.url), 70, url)
            self.assertEqual(service.sent("GET"), [], url)

    def test_a_prompt_or_a_missing_image_sends_nothing(self) -> None:
        service = self.trellis()
        self.assertEqual(self.job(prompt="a chair", inputs={"image": ("png", PNG)}).run("trellis.py", service.url), 65)
        self.assertEqual(self.job().run("trellis.py", service.url), 65)
        self.assertEqual(self.job(options={"formats": ["obj"]}, inputs={"image": ("png", PNG)})
                         .run("trellis.py", service.url), 65)
        self.assertEqual(service.sent(), [])


# --------------------------------------------------------------------------
# YuE2 on ComfyUI
# --------------------------------------------------------------------------


class ComfyCase(Case):
    def comfy(self, phase: str = "done", saved_in: str | None = None, status_str: str = "success") -> tuple[FakeService, dict]:
        """A ComfyUI whose one prompt sits in `phase`: pending, running, done or lost."""
        state: dict[str, Any] = {"prompt": None}

        def route(method: str, path: str, body: bytes) -> Reply:
            if (method, path) == ("POST", "/prompt"):
                state["prompt"] = json.loads(body)["prompt"]
                return json_reply({"prompt_id": "p-ours", "number": 7, "node_errors": {}})
            if path == "/queue" and method == "GET":
                other = [3, "p-other", {}, {}, []]
                ours = [7, "p-ours", {}, {}, []]
                running = [ours] if phase == "running" else [other]
                pending = [ours] if phase == "pending" else []
                return json_reply({"queue_running": running, "queue_pending": pending})
            if path == "/history/p-ours":
                if phase != "done":
                    return json_reply({})
                prefix = state["prompt"]["8"]["inputs"]["filename_prefix"]
                subfolder = saved_in if saved_in is not None else prefix.split("/")[0]
                return json_reply({"p-ours": {"status": {"status_str": status_str, "messages": []},
                                              "outputs": {"8": {"audio": [{"filename": "song_00001_.flac",
                                                                           "subfolder": subfolder,
                                                                           "type": "output"}]}}}})
            if path.startswith("/view?"):
                return 200, {}, FLAC
            if method == "POST" and path in ("/queue", "/interrupt"):
                return json_reply({})
            return json_reply({}, 404)
        return self.fake(route), state

    def test_style_and_lyrics_are_values_in_a_fixed_graph(self) -> None:
        service, state = self.comfy()
        job = self.job(prompt="Delta blues, slide guitar", params={"duration_ms": 30_000, "seed": 5})
        self.assertEqual(job.run("comfy_yue.py", service.url), 0)
        graph = state["prompt"]
        self.assertEqual({n["class_type"] for n in graph.values()} >= {"YuE2GenerateABC", "SaveAudioAdvanced"}, True)
        self.assertEqual(graph["3"]["inputs"]["style"], "Delta blues, slide guitar")
        self.assertEqual(graph["3"]["inputs"]["lyrics"], "[instrumental]")
        self.assertEqual(graph["3"]["inputs"]["max_duration"], 30.0)
        self.assertEqual(graph["1"]["inputs"]["ckpt_name"], "yue2_3b_bf16.safetensors")
        self.assertTrue(graph["8"]["inputs"]["filename_prefix"].startswith("hypellm/"))
        self.assertEqual(job.outputs(), {"audio.flac": FLAC})
        (_, view, _), = service.sent("GET", "/view")
        self.assertIn("type=output", view)

    def test_an_option_cannot_become_a_node_or_a_file_name(self) -> None:
        service, _ = self.comfy()
        for options in ({"ckpt_name": "../../x"}, {"filename_prefix": "/etc"}, {"lyrics": 7}):
            self.assertEqual(self.job(prompt="pop", options=options).run("comfy_yue.py", service.url), 65, options)
        self.assertEqual(service.sent(), [])

    def test_audio_saved_anywhere_but_the_jobs_own_folder_is_not_fetched(self) -> None:
        service, _ = self.comfy(saved_in="iron-curtain")
        job = self.job(prompt="pop")
        self.assertEqual(job.run("comfy_yue.py", service.url), 70)
        self.assertEqual(service.sent("GET", "/view"), [])

    def test_a_failed_or_forgotten_prompt_fails_the_job(self) -> None:
        service, _ = self.comfy(status_str="error")
        self.assertEqual(self.job(prompt="pop").run("comfy_yue.py", service.url), 70)
        service, _ = self.comfy(phase="lost")
        self.assertEqual(self.job(prompt="pop").run("comfy_yue.py", service.url, timeout=30), 70)

    def cancel_while(self, phase: str) -> FakeService:
        service, _ = self.comfy(phase=phase)
        job = self.job(prompt="pop")
        process = job.start("comfy_yue.py", service.url)
        until = time.monotonic() + 15
        while not service.sent("GET", "/queue"):
            self.assertLess(time.monotonic(), until)
            time.sleep(0.05)
        os.killpg(process.pid, signal.SIGTERM)
        self.assertNotEqual(process.wait(timeout=15), 0)
        return service

    def test_a_cancel_removes_its_own_pending_prompt_and_nothing_else(self) -> None:
        service = self.cancel_while("pending")
        (_, _, body), = service.sent("POST", "/queue")
        self.assertEqual(json.loads(body), {"delete": ["p-ours"]})
        self.assertEqual(service.sent("POST", "/interrupt"), [])

    def test_a_cancel_interrupts_only_its_own_running_prompt(self) -> None:
        service = self.cancel_while("running")
        (_, _, body), = service.sent("POST", "/interrupt")
        # A bare /interrupt would stop whatever is running, another client's included.
        self.assertEqual(json.loads(body), {"prompt_id": "p-ours"})
        self.assertEqual(service.sent("POST", "/queue"), [])


# --------------------------------------------------------------------------
# MiniMax-H3 on Gradio
# --------------------------------------------------------------------------


class H3Case(Case):
    def setUp(self) -> None:
        super().setUp()
        self.cond_dir = os.path.join(self.root, "cond")
        os.makedirs(self.cond_dir)
        self.conditioner = self.fake(lambda m, p, b: (200, {}, SAFETENSORS) if (m, p) == ("POST", "/encode")
                                     else json_reply({}, 404))

    def app(self, event: str = "complete", data: Any = None) -> FakeService:
        def route(method: str, path: str, body: bytes) -> Reply:
            if (method, path) == ("POST", "/gradio_api/upload"):
                name = b"keyframe" if b'filename="keyframe' in body else b"audio"
                return json_reply(["/tmp/gradio/up/" + name.decode()])
            if (method, path) == ("POST", "/gradio_api/call/generate"):
                return json_reply({"event_id": "e123"})
            if path == "/gradio_api/call/generate/e123":
                document = data if data is not None else [
                    {"video": {"path": "/tmp/gradio/out/video.mp4", "url": "http://elsewhere/x.mp4"}}, "report"]
                stream = f"event: heartbeat\ndata: null\n\nevent: {event}\ndata: {json.dumps(document)}\n\n"
                return 200, {"Content-Type": "text/event-stream"}, stream.encode()
            if path == "/gradio_api/file=/tmp/gradio/out/video.mp4":
                return 200, {}, MP4
            return json_reply({}, 404)
        return self.fake(route)

    def run_h3(self, app: FakeService, **kwargs: Any) -> tuple[Job, int]:
        kwargs.setdefault("prompt", "a singer on a rooftop")
        kwargs.setdefault("inputs", {"audio": ("wav", WAV), "keyframe": ("png", PNG)})
        job = self.job(**kwargs)
        code = job.run("gradio_h3.py", app.url, "--conditioner", self.conditioner.url, "--cond-dir", self.cond_dir)
        return job, code

    def test_conditioning_is_cached_under_the_apps_key_and_reused(self) -> None:
        app = self.app()
        job, code = self.run_h3(app, params={"duration_ms": 4000, "seed": 3})
        self.assertEqual(code, 0)
        key = hashlib.sha256("a singer on a rooftop".encode() + b"|" + PNG).hexdigest()[:32]
        self.assertEqual(os.listdir(self.cond_dir), [key + ".safetensors"])
        (_, _, encode), = self.conditioner.sent("POST", "/encode")
        self.assertIn(b'name="num_frames"\r\n\r\n107\r\n', encode)  # 96 frames, snapped to 17n + 5
        (_, _, call), = app.sent("POST", "/gradio_api/call/generate")
        data = json.loads(call)["data"]
        self.assertEqual(data[0], "a singer on a rooftop")
        self.assertEqual(data[1]["path"], "/tmp/gradio/up/keyframe")
        self.assertEqual(data[2]["path"], "/tmp/gradio/up/audio")
        self.assertEqual(data[3:], ["960x544 · 16:9 fast", 4.0, 28, 3, False, True])
        self.assertEqual(job.outputs(), {"video.mp4": MP4})
        # The video comes from the configured app, never from a URL in the reply.
        self.assertEqual(len(app.sent("GET", "/gradio_api/file=")), 1)

        _, code = self.run_h3(self.app())
        self.assertEqual(code, 0)
        self.assertEqual(len(self.conditioner.sent()), 1)

    def test_an_apps_error_maps_onto_the_closed_set(self) -> None:
        for message, code in (("The denoiser is still loading.", 75), ("A soundtrack is required.", 65),
                              ("Traceback: boom", 70)):
            job, got = self.run_h3(self.app(event="error", data=message))
            self.assertEqual(got, code, message)
            self.assertEqual(job.outputs(), {})

    def test_a_job_the_app_cannot_render_sends_nothing(self) -> None:
        app = self.app()
        for kwargs in ({"params": {"duration_ms": 8000}}, {"inputs": {"keyframe": ("png", PNG)}},
                       {"options": {"canvas": "1344x768 · 16:9 full"}}, {"prompt": " "}):
            _, code = self.run_h3(app, **kwargs)
            self.assertEqual(code, 65, kwargs)
        self.assertEqual(app.sent(), [])
        self.assertEqual(self.conditioner.sent(), [])


# --------------------------------------------------------------------------
# Kimodo
# --------------------------------------------------------------------------

FAKE_KIMODO = r'''#!PYTHON
import json, os, sys
with open(os.path.join(os.environ["HOME"], "kimodo.json"), "w") as f:
    json.dump({"argv": sys.argv[1:], "env": dict(os.environ)}, f)
prompt = sys.argv[sys.argv.index("--") + 1]
for i in range(1, 5):
    print(f" {i*25}%|##| {i}/4 [00:01<00:00]", file=sys.stderr, flush=True)
if "oom" in prompt:
    print("RuntimeError: CUDA out of memory", file=sys.stderr)
    sys.exit(1)
if "crash" in prompt:
    sys.exit(2)
open("motion.npz", "wb").write(b"NPZ")
if "--bvh" in sys.argv and "nobvh" not in prompt:
    open("motion.bvh", "wb").write(b"HIERARCHY")
'''


class KimodoCase(Case):
    def setUp(self) -> None:
        super().setUp()
        self.kimodo_gen = os.path.join(self.root, "kimodo_gen")
        with open(self.kimodo_gen, "w") as f:
            f.write(FAKE_KIMODO.replace("PYTHON", sys.executable))
        os.chmod(self.kimodo_gen, 0o755)

    def run_kimodo(self, **kwargs: Any) -> tuple[Job, int]:
        job = self.job(**kwargs)
        code = job.run("kimodo.py", "http://kimodo-textencoder:9551", "--kimodo-gen", self.kimodo_gen,
                       "--hf-cache", "/models/hf-cache")
        return job, code

    def recorded(self, job: Job) -> dict:
        with open(os.path.join(job.directory, "kimodo.json")) as f:
            return json.load(f)

    def test_the_prompt_is_one_argument_and_the_environment_is_built_not_inherited(self) -> None:
        job, code = self.run_kimodo(prompt="--constraints /etc/passwd", params={"duration_ms": 3000, "steps": 50})
        self.assertEqual(code, 0)
        seen = self.recorded(job)
        self.assertEqual(seen["argv"][-2:], ["--", "--constraints /etc/passwd"])
        self.assertNotIn("--constraints", seen["argv"][:-1])
        self.assertEqual(seen["argv"][seen["argv"].index("--duration") + 1], "3.00")
        self.assertEqual(seen["env"]["TEXT_ENCODER_URL"], "http://kimodo-textencoder:9551/")
        self.assertEqual(seen["env"]["HF_HUB_OFFLINE"], "1")
        self.assertNotIn("CANARY", seen["env"])
        self.assertEqual(job.outputs(), {"motion.npz": b"NPZ", "motion.bvh": b"HIERARCHY"})
        with open(os.path.join(job.out, "progress")) as f:
            self.assertEqual(f.read(), "999")

    def test_a_failure_maps_onto_the_closed_set_and_a_missing_file_is_a_failure(self) -> None:
        for prompt, code in (("A person oom", 75), ("A person crash", 70), ("A person nobvh", 70)):
            _, got = self.run_kimodo(prompt=prompt)
            self.assertEqual(got, code, prompt)
        _, got = self.run_kimodo(prompt="A person nobvh", options={"bvh": False})
        self.assertEqual(got, 0)

    def test_a_model_or_a_long_clip_cannot_be_asked_for(self) -> None:
        for kwargs in ({"options": {"model": "kimodo-g1-rp"}}, {"params": {"duration_ms": 20_000}},
                       {"params": {"count": 4}}):
            job, code = self.run_kimodo(prompt="A person waves.", **kwargs)
            self.assertEqual(code, 65, kwargs)
            self.assertFalse(os.path.exists(os.path.join(job.directory, "kimodo.json")))


# --------------------------------------------------------------------------
# Shared
# --------------------------------------------------------------------------


class SharedCase(Case):
    def test_a_redirect_is_not_followed(self) -> None:
        # A GET, since urllib would follow one there; it never follows a POST.
        elsewhere = self.fake(lambda m, p, b: (200, {}, GLB))

        def route(method: str, path: str, body: bytes) -> Reply:
            if method == "POST":
                return json_reply({"files": {"glb": {"url": "/outputs/x.glb"}}})
            return 302, {"Location": elsewhere.url + path}, b""

        job = self.job(inputs={"image": ("png", PNG)})
        self.assertEqual(job.run("trellis.py", self.fake(route).url), 70)
        self.assertEqual(elsewhere.sent(), [])
        self.assertEqual(job.outputs(), {})


if __name__ == "__main__":
    unittest.main()
