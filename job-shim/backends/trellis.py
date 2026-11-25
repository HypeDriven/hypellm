#!/usr/bin/env python3
"""image-to-3d on a TRELLIS.2 service (`POST /generate`).

    prompt     none: TRELLIS.2 reconstructs the image it is given
    params     seed, steps (1-50, all three sampling stages)
    options    formats (any of glb, mesh_ply; glb is always made),
               resolution (512, 1024, 1536), texture_size (1024, 2048, 4096),
               decimation_target (1000-2000000 faces),
               ss_guidance_strength, shape_guidance_strength, tex_guidance_strength
    inputs     image (png or webp): one object, ideally centred; an alpha
               cut-out is kept, anything else has its background removed
    outputs    mesh.glb (PBR-textured), and geometry.ply when asked for

The service's `image` field also takes a path inside its container; this
backend only ever sends the image's bytes.
"""

from __future__ import annotations

import _common as c

# The service's format name, the file this backend writes, and its signature.
FORMATS = {
    "glb": ("mesh.glb", "glb"),
    "mesh_ply": ("geometry.ply", None),
}


def main() -> None:
    args = c.arguments(__doc__ or "")
    service = c.Service(args.service)
    params = c.params(args.params, ("seed", "steps"))
    options = c.options(args.options, {
        "formats": c.Subset(*FORMATS),
        "resolution": c.Choice(512, 1024, 1536),
        "texture_size": c.Choice(1024, 2048, 4096),
        "decimation_target": (1000, 2_000_000),
        "ss_guidance_strength": (0, 20),
        "shape_guidance_strength": (0, 20),
        "tex_guidance_strength": (0, 20),
    })
    if args.prompt.strip():
        raise c.Invalid("image-to-3d takes no prompt; the image is the whole request")
    if not isinstance(options.get("decimation_target", 0), int):
        raise c.Invalid("decimation_target must be a whole number of faces")
    _, image = c.require_input("image")

    formats = ["glb"] + [f for f in options.pop("formats", []) if f != "glb"]
    body: dict[str, object] = {"image": c.b64(image), "formats": formats, "seed": c.a_seed(params.get("seed"))}
    steps = c.within("steps", params.get("steps"), 1, 50, None)
    if steps is not None:
        for stage in ("ss", "shape", "tex"):
            body[f"{stage}_sampling_steps"] = steps
    if "resolution" in options:
        body["resolution"] = str(options.pop("resolution"))
    body.update(options)

    c.progress(args.out, 0)
    # Serialised by the service; the first request after a restart compiles
    # its kernels, and one after idle reloads the model.
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
