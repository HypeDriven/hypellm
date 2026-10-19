#!/usr/bin/env python3
"""text-to-motion with Kimodo (`kimodo_gen`), run in this process's session.

    prompt     the motion, ideally "A person …"; several sentences make a
               sequence, one clip per sentence; required
    params     duration_ms (0.5-10 s per sentence, default 5 s), seed,
               steps (10-1000 diffusion steps, default 100)
    options    bvh (default true): also write a BVH; postprocess (default
               true): foot-skate cleanup
    outputs    motion.npz, and motion.bvh

Kimodo-SOMA-RP is the one model this deployment holds offline, so the model is
fixed rather than an option a job could name and fail on. The text encoder is
the service; the motion model runs here, in the shim's container. A cancel
stops it, since the shim stops the whole session.
"""

from __future__ import annotations

import os
import re
import subprocess
import sys

import _common as c

TQDM = re.compile(rb"(\d+)/(\d+) \[")


def main() -> None:
    args = c.arguments(
        __doc__ or "",
        ("--kimodo-gen", {"required": True, "help": "absolute path of kimodo_gen"}),
        ("--hf-cache", {"required": True, "help": "the read-only checkpoint cache"}),
    )
    service = c.Service(args.service)
    if not os.path.isabs(args.kimodo_gen) or not os.path.isabs(args.hf_cache):
        raise c.Broken("--kimodo-gen and --hf-cache must be absolute")
    params = c.params(args.params, ("duration_ms", "seed", "steps"))
    options = c.options(args.options, {"bvh": bool, "postprocess": bool})
    prompt = args.prompt.strip()
    if not prompt:
        raise c.Invalid("text-to-motion needs a prompt")
    duration_ms = c.within("duration_ms", params.get("duration_ms"), 500, 10_000, 5_000) or 5_000
    steps = c.within("steps", params.get("steps"), 10, 1000, 100) or 100
    seed = c.a_seed(params.get("seed"))

    argv = [
        args.kimodo_gen,
        "--duration", f"{duration_ms / 1000:.2f}",
        "--diffusion_steps", str(steps),
        "--seed", str(seed),
        "--output", "motion",
    ]
    if options.get("bvh", True):
        argv.append("--bvh")
    if not options.get("postprocess", True):
        argv.append("--no-postprocess")
    # After `--` a prompt that starts with a dash is still the prompt.
    argv += ["--", prompt]

    home = os.getcwd()
    environment = {
        "PATH": os.path.dirname(args.kimodo_gen) + ":/usr/local/bin:/usr/bin:/bin",
        "HOME": home,
        "LANG": "C.UTF-8",
        "TEXT_ENCODER_MODE": "api",
        "TEXT_ENCODER_URL": service.base + "/",
        "HF_HUB_CACHE": args.hf_cache,
        "HF_HUB_OFFLINE": "1",
        "MPLCONFIGDIR": os.path.join(home, "mpl"),
        "PYTHONUNBUFFERED": "1",
    }
    c.progress(args.out, 0)
    process = subprocess.Popen(
        argv, cwd=args.out, env=environment, stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
    )
    output = process.stdout
    if output is None:
        raise c.Broken("kimodo_gen has no output stream")
    tail = b""
    for chunk in iter(lambda: output.read1(4096), b""):
        sys.stderr.buffer.write(chunk)
        tail = (tail + chunk)[-8192:]
        found = TQDM.findall(tail)
        if found:
            done, total = (int(x) for x in found[-1])
            if total:
                c.progress(args.out, done * 1000 // total)
    code = process.wait()
    if code != 0:
        text = tail.decode("utf-8", "replace").lower()
        if "out of memory" in text:
            raise c.Busy("kimodo ran out of memory")
        raise c.Broken(f"kimodo_gen exited {code}")
    for name in ("motion.npz",) + (("motion.bvh",) if options.get("bvh", True) else ()):
        path = os.path.join(args.out, name)
        if not os.path.isfile(path) or os.path.islink(path):
            raise c.Broken(f"kimodo_gen wrote no {name}")


if __name__ == "__main__":
    c.run(main)
