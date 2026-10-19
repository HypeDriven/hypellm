#!/usr/bin/env python3
"""text-to-image on a FLUX.2 [klein] service (`POST /generate`).

    prompt     what to draw; required
    params     width, height (multiples of 16, at most 1536), steps (1-60),
               seed, count (1-4 images)
    options    guidance_scale (0-20)
    inputs     reference (optional, png or webp): makes the job an edit of it
    outputs    image.png, and image-2.png … image-4.png when count asks

The service's own `images` field also takes a path inside its container; this
backend only ever sends the reference's bytes, so a caller cannot name one.
"""

from __future__ import annotations

import base64
import binascii

import _common as c

MAX_SIDE = 1536


def main() -> None:
    args = c.arguments(__doc__ or "")
    service = c.Service(args.service)
    params = c.params(args.params, ("width", "height", "steps", "seed", "count"))
    options = c.options(args.options, {"guidance_scale": (0, 20)})
    prompt = args.prompt.strip()
    if not prompt:
        raise c.Invalid("text-to-image needs a prompt")

    body: dict[str, object] = {
        "prompt": prompt,
        "width": side("width", params.get("width")),
        "height": side("height", params.get("height")),
        "num_inference_steps": c.within("steps", params.get("steps"), 1, 60, 28),
        "seed": c.a_seed(params.get("seed")),
        "num_images": c.within("count", params.get("count"), 1, 4, 1),
        "return_base64": True,
    }
    if "guidance_scale" in options:
        body["guidance_scale"] = options["guidance_scale"]
    reference = c.input_file("reference")
    if reference is not None:
        body["images"] = [c.b64(reference[1])]

    c.progress(args.out, 0)
    # The service holds one request at a time and makes the rest wait on a
    # lock, and its first request after a restart loads the weights first.
    reply = service.json("POST", "/generate", body, timeout=1800)
    images = reply.get("images") if isinstance(reply, dict) else None
    if not isinstance(images, list) or len(images) != body["num_images"]:
        raise c.Broken("the reply does not carry the images asked for")
    for index, image in enumerate(images):
        data = image_bytes(service, image)
        c.check_magic(data, "png")
        c.write_output(args.out, "image.png" if index == 0 else f"image-{index + 1}.png", data)


def side(name: str, value: int | None) -> int:
    chosen = c.within(name, value, 16, MAX_SIDE, 1024) or 1024
    if chosen % 16:
        raise c.Invalid(f"{name} must be a multiple of 16")
    return chosen


def image_bytes(service: c.Service, image: object) -> bytes:
    if not isinstance(image, dict):
        raise c.Broken("an image in the reply is not an object")
    encoded = image.get("base64")
    if isinstance(encoded, str):
        try:
            return base64.b64decode(encoded, validate=True)
        except (binascii.Error, ValueError) as error:
            raise c.Broken("an image in the reply is not base64") from error
    # An older service answers with a file under /outputs only.
    url = image.get("url")
    if isinstance(url, str) and url.startswith("/outputs/") and url.count("/") == 2:
        status, data = service.request("GET", url, timeout=120)
        if status != 200:
            raise c.for_status(status, data, "GET " + url)
        return data
    raise c.Broken("an image in the reply has neither bytes nor a file")


if __name__ == "__main__":
    c.run(main)
