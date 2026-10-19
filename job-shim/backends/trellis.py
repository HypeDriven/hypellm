#!/usr/bin/env python3
"""image-to-3d on a TRELLIS service (`POST /generate`).

    prompt     none: TRELLIS reconstructs the image it is given
    params     seed, steps (1-100, both sampling stages)
    options    formats (any of mesh_ply, gaussian_ply; glb is always made),
               remove_background, ss_guidance_strength, slat_guidance_strength,
               simplify, texture_size
    inputs     image (png or webp): one object, ideally centred
    outputs    mesh.glb, and geometry.ply / gaussians.ply when asked for

The service's `image` field also takes a path inside its container; this
backend only ever sends the image's bytes.
"""

from __future__ import annotations

import _common as c

# The service's format name, the file this backend writes, and its signature.
FORMATS = {
    "glb": ("mesh.glb", "glb"),
    "mesh_ply": ("geometry.ply", None),
    "gaussian_ply": ("gaussians.ply", None),
}


def main() -> None:
    args = c.arguments(__doc__ or "")
    service = c.Service(args.service)
    params = c.params(args.params, ("seed", "steps"))
    options = c.options(args.options, {
        "formats": c.Subset(*FORMATS),
        "remove_background": bool,
        "ss_guidance_strength": (0, 20),
        "slat_guidance_strength": (0, 20),
        "simplify": (0, 0.99),
        "texture_size": c.Choice(512, 1024, 2048),
    })
    if args.prompt.strip():
        raise c.Invalid("image-to-3d takes no prompt; the image is the whole request")
    _, image = c.require_input("image")

    formats = ["glb"] + [f for f in options.pop("formats", []) if f != "glb"]
    body: dict[str, object] = {"image": c.b64(image), "formats": formats, "seed": c.a_seed(params.get("seed"))}
    steps = c.within("steps", params.get("steps"), 1, 100, None)
    if steps is not None:
        body["ss_sampling_steps"] = steps
        body["slat_sampling_steps"] = steps
    body.update(options)

    c.progress(args.out, 0)
    # Serialised by the service; the first request after a restart compiles
    # its CUDA kernels for minutes.
    reply = service.json("POST", "/generate", body, timeout=1800)
    files = reply.get("files") if isinstance(reply, dict) else None
    if not isinstance(files, dict):
        raise c.Broken("the reply carries no files")
    for name in formats:
        entry = files.get(name)
        url = entry.get("url") if isinstance(entry, dict) else None
        if not isinstance(url, str) or not url.startswith("/outputs/") or url.count("/") != 2:
            raise c.Broken(f"the reply has no {name} file")
        status, data = service.request("GET", url, timeout=300)
        if status != 200:
            raise c.for_status(status, data, "GET " + url)
        file, magic = FORMATS[name]
        if magic is not None:
            c.check_magic(data, magic)
        c.write_output(args.out, file, data)


if __name__ == "__main__":
    c.run(main)
