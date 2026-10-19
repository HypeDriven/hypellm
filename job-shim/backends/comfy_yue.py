#!/usr/bin/env python3
"""text-to-music on a ComfyUI serving YuE2 (`POST /prompt`, then `/history`).

    prompt     the style: genre, instruments, mood, tempo; required
    params     duration_ms (1 s - 6 min, an upper bound; default 2 min),
               seed, steps (1-100 sampler steps, default 32)
    options    lyrics (sections such as [verse]; default [instrumental])
    outputs    audio.flac

The graph is fixed here: full ABC planning, BF16 checkpoint, lossless FLAC.
Nothing the caller sends becomes a node, a file name or a model name.

ComfyUI runs one prompt at a time from a queue it shares with every other
client, so a job may wait behind someone else's. A cancel removes the job's
prompt from that queue, or interrupts it if it is the one running — and only
then, so a cancel never stops another client's work.
"""

from __future__ import annotations

import secrets
import signal
import time
from typing import Any

import _common as c

CHECKPOINT = "yue2_3b_bf16.safetensors"
POLL_S = 2.0
# How many polls in a row may find the prompt neither queued, running nor
# finished before it is taken to be lost (a ComfyUI restart forgets its queue).
LOST_AFTER = 3


class Cancelled(Exception):
    pass


def on_term(_signum: int, _frame: Any) -> None:
    raise Cancelled()


def node(kind: str, **inputs: Any) -> dict[str, Any]:
    return {"class_type": kind, "inputs": inputs}


def graph(style: str, lyrics: str, seed: int, seconds: float, steps: int, prefix: str) -> dict[str, Any]:
    common = {"style": style, "lyrics": lyrics, "seed": seed, "mode": "full"}
    return {
        "1": node("CheckpointLoaderSimple", ckpt_name=CHECKPOINT),
        "2": node("YuE2GenerateABC", clip=["1", 1], **common, max_abc_tokens=8192,
                  temperature=0.7, top_p=0.9, top_k=30, repetition_penalty=1.005, penalty_window=100),
        "3": node("YuE2GenerateMusic", clip=["1", 1], abc=["2", 0], **common,
                  max_duration=seconds, temperature=1.0, top_p=0.95, top_k=100,
                  repetition_penalty=1.2, cfg_scale=1.0),
        "4": node("EmptyYuE2LatentAudio", seconds=["3", 1], batch_size=1),
        "5": node("ConditioningZeroOut", conditioning=["3", 0]),
        "6": node("KSampler", model=["1", 0], positive=["3", 0], negative=["5", 0],
                  latent_image=["4", 0], seed=seed, steps=steps, cfg=1.0,
                  sampler_name="dpm_2", scheduler="sgm_uniform", denoise=1.0),
        "7": node("VAEDecodeAudio", samples=["6", 0], vae=["1", 2]),
        "8": node("SaveAudioAdvanced", audio=["7", 0], filename_prefix=prefix, format="flac"),
    }


def main() -> None:
    args = c.arguments(__doc__ or "")
    service = c.Service(args.service)
    params = c.params(args.params, ("duration_ms", "seed", "steps"))
    options = c.options(args.options, {"lyrics": str})
    style = args.prompt.strip()
    if not style:
        raise c.Invalid("text-to-music needs a prompt describing the style")
    lyrics = options.get("lyrics", "").strip() or "[instrumental]"
    duration_ms = c.within("duration_ms", params.get("duration_ms"), 1_000, 360_000, 120_000) or 120_000
    steps = c.within("steps", params.get("steps"), 1, 100, 32) or 32
    # ComfyUI's own seed is unsigned 64-bit.
    seed = c.a_seed(params.get("seed"))
    prefix = "hypellm/" + secrets.token_hex(8)

    signal.signal(signal.SIGTERM, on_term)
    prompt_id = None
    try:
        reply = service.json("POST", "/prompt", {
            "prompt": graph(style, lyrics, seed, duration_ms / 1000, steps, prefix),
            "client_id": "hypellm-" + secrets.token_hex(8),
        }, ok=(200,))
        prompt_id = reply.get("prompt_id") if isinstance(reply, dict) else None
        if not isinstance(prompt_id, str) or reply.get("node_errors"):
            raise c.Broken(f"ComfyUI refused the graph: {str(reply)[:400]}")
        c.progress(args.out, 0)
        result = wait(service, prompt_id)
    except Cancelled:
        signal.signal(signal.SIGTERM, signal.SIG_DFL)
        if prompt_id is not None:
            cancel(service, prompt_id)
        raise c.Broken("cancelled") from None
    audio = saved_audio(result)
    status, data = service.request("GET", "/view", query={
        "filename": audio["filename"], "subfolder": audio["subfolder"], "type": "output"}, timeout=300)
    if status != 200:
        raise c.for_status(status, data, "GET /view")
    c.check_magic(data, "flac")
    c.write_output(args.out, "audio.flac", data)


def wait(service: c.Service, prompt_id: str) -> dict[str, Any]:
    missing = 0
    while True:
        history = service.json("GET", f"/history/{prompt_id}")
        if isinstance(history, dict) and prompt_id in history:
            return history[prompt_id]
        queue = service.json("GET", "/queue")
        if place(queue, prompt_id) is None:
            # Finished between the two reads, or forgotten by a restart.
            missing += 1
            if missing >= LOST_AFTER:
                raise c.Broken("ComfyUI no longer knows the prompt; it was probably restarted")
        else:
            missing = 0
        time.sleep(POLL_S)


def place(queue: Any, prompt_id: str) -> str | None:
    """Where the prompt is: "running", "pending", or nowhere."""
    if not isinstance(queue, dict):
        return None
    for where, key in (("running", "queue_running"), ("pending", "queue_pending")):
        for item in queue.get(key) or []:
            if isinstance(item, list) and len(item) > 1 and item[1] == prompt_id:
                return where
    return None


def cancel(service: c.Service, prompt_id: str) -> None:
    """Take the prompt out of ComfyUI, touching nothing else.

    `/interrupt` without a prompt id stops whatever is running, which may be
    another client's; it is only ever sent with ours, and only when ours is
    the one running.
    """
    try:
        where = place(service.json("GET", "/queue", timeout=3), prompt_id)
        if where == "pending":
            service.request("POST", "/queue", c.json_body({"delete": [prompt_id]}), timeout=3)
        elif where == "running":
            service.request("POST", "/interrupt", c.json_body({"prompt_id": prompt_id}), timeout=3)
    except (c.Broken, c.Invalid, c.Busy):
        pass


def saved_audio(result: Any) -> dict[str, str]:
    status = result.get("status") if isinstance(result, dict) else None
    if not isinstance(status, dict) or status.get("status_str") != "success":
        raise failure(status)
    outputs = result.get("outputs") or {}
    saved = (outputs.get("8") or {}).get("audio") if isinstance(outputs, dict) else None
    if not isinstance(saved, list) or not saved or not isinstance(saved[0], dict):
        raise c.Broken("the prompt finished without saving audio")
    audio = saved[0]
    names = {k: audio.get(k) for k in ("filename", "subfolder")}
    if not all(isinstance(v, str) for v in names.values()) or not names["filename"].endswith(".flac"):
        raise c.Broken("the saved audio is not a FLAC file")
    if not names["subfolder"].startswith("hypellm"):
        raise c.Broken("the saved audio is not where this job asked for it")
    return names  # type: ignore[return-value]


def failure(status: Any) -> Exception:
    text = str(status)[:2000]
    if "OutOfMemory" in text or "out of memory" in text.lower():
        return c.Busy("ComfyUI ran out of memory")
    if "interrupted" in text.lower():
        return c.Broken("the prompt was interrupted")
    return c.Broken("the prompt failed: " + text[:400])


if __name__ == "__main__":
    c.run(main)
