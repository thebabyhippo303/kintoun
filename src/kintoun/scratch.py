"""One-command `decomp.me` scratch importer and local Kintoun runner (`kintoun scratch`).

Fetches a scratch by slug or URL (`https://decomp.me/scratch/<slug>`) using Python's stdlib
`urllib.request`—or loads an offline JSON/directory bundle (`--from-json`)—maps its compiler
and flags onto Kintoun's presets, downloads `target.o`, merges `context` + `source_code`, and
runs Kintoun's local multi-core beam search + near-miss closer.
"""
from __future__ import annotations

import base64
from dataclasses import replace
import json
from pathlib import Path
import re
import shlex
import tempfile
from typing import Any
import urllib.request

from kintoun.closer import close_near_miss
from kintoun.compiler import make_compiler
from kintoun.config import CompilerConfig, KintounConfig
from kintoun.search.runner import run_search
from kintoun.targets import load_target_from_object
from kintoun.verify import verify_source

_SLUG_RE = re.compile(r"(?:decomp\.me/scratch/|/api/scratch/)?([A-Za-z0-9_-]{3,32})/?$")


def map_decompme_compiler(compiler_name: str) -> str:
    """Map a `decomp.me` compiler identifier onto the closest Kintoun compiler preset."""
    c = (compiler_name or "").strip().lower()
    if "prodg" in c and "psp" not in c:
        return "prodg-wine"
    if c.startswith("mwcc") and ("gc" in c or "wii" in c or "eppc" in c or re.search(r"mwcc_\d{3}", c)):
        return "mwcc-wine"
    if "mwccps2" in c or ("mwcc" in c and "ps2" in c):
        return "mwccps2"
    if "mwccpsp" in c:
        return "mwccpsp"
    if "mwccarm" in c or ("mwcc" in c and ("arm" in c or "nds" in c)):
        return "mwccarm"
    if "pspsnc" in c or ("snc" in c and "psp" in c):
        return "pspsnc"
    if "psp" in c:
        return "psp-gcc"
    if "ee-gcc" in c or "iop-gcc" in c or "ps2" in c:
        return "ee-gcc"
    if "agbcc" in c:
        return "agbcc"
    if "armcc" in c:
        return "armcc"
    if "arm" in c:
        return "arm-none-eabi-gcc"
    if "mips" in c or "ido" in c:
        return "mips-gcc"
    return "custom"


def parse_scratch_slug(spec: str, api_base: str = "https://decomp.me") -> tuple[str, str]:
    s = spec.strip()
    if s.startswith(("http://", "https://")):
        m = re.search(r"^(https?://[^/]+).*?/scratch/([A-Za-z0-9_-]+)", s)
        if m:
            return m.group(1), m.group(2)
    m2 = _SLUG_RE.search(s)
    if not m2:
        raise ValueError(f"could not parse decomp.me scratch slug from '{spec}'")
    return api_base.rstrip("/"), m2.group(1)


def fetch_scratch_bundle(
    spec: str,
    *,
    api_base: str = "https://decomp.me",
    from_json: Path | None = None,
    timeout_s: float = 20.0,
) -> dict[str, Any]:
    """Fetch scratch metadata and `target.o` bytes from `decomp.me` API or an offline JSON file."""
    if from_json is not None:
        doc = json.loads(Path(from_json).read_text(encoding="utf-8"))
        if "target_obj_b64" in doc:
            target_bytes = base64.b64decode(doc["target_obj_b64"])
        elif "target_obj_path" in doc:
            tp = Path(doc["target_obj_path"])
            if not tp.is_absolute():
                tp = Path(from_json).parent / tp
            target_bytes = tp.read_bytes()
        else:
            raise ValueError("offline scratch JSON must provide 'target_obj_b64' or 'target_obj_path'")
        return {"meta": doc, "target_bytes": target_bytes}

    host, slug = parse_scratch_slug(spec, api_base=api_base)
    headers = {"Accept": "application/json", "User-Agent": "kintoun-scratch/0.4"}
    meta_req = urllib.request.Request(f"{host}/api/scratch/{slug}", headers=headers)
    with urllib.request.urlopen(meta_req, timeout=timeout_s) as resp:
        meta = json.loads(resp.read().decode("utf-8"))

    # Download compiled target object (`target.o`) from `/api/scratch/<slug>/export` or `/target.o`
    obj_req = urllib.request.Request(
        f"{host}/api/scratch/{slug}/target.o",
        headers={"User-Agent": "kintoun-scratch/0.4"},
    )
    try:
        with urllib.request.urlopen(obj_req, timeout=timeout_s) as o_resp:
            target_bytes = o_resp.read()
    except Exception:
        # Fallback: extract `target.o` from `/api/scratch/<slug>/export` zip archive
        import io
        import zipfile

        exp_req = urllib.request.Request(
            f"{host}/api/scratch/{slug}/export",
            headers={"User-Agent": "kintoun-scratch/0.4"},
        )
        with urllib.request.urlopen(exp_req, timeout=timeout_s) as z_resp:
            zbytes = z_resp.read()
        with zipfile.ZipFile(io.BytesIO(zbytes)) as zf:
            obj_name = next((n for n in zf.namelist() if n.endswith("target.o")), "")
            if not obj_name:
                raise RuntimeError(f"scratch '{slug}' export archive did not contain target.o")
            target_bytes = zf.read(obj_name)

    return {"meta": meta, "target_bytes": target_bytes}


def run_scratch(
    spec: str,
    cfg: KintounConfig,
    *,
    from_json: Path | None = None,
    compiler_dir: str = "",
    budget_s: float = 60.0,
    max_candidates: int = 800,
    workers: int = 0,
    save_dir: Path | None = None,
    out_source: Path | None = None,
    compiler_override: Any = None,
) -> dict[str, Any]:
    """Import a `decomp.me` scratch and run Kintoun's search + near-miss closer locally."""
    bundle = fetch_scratch_bundle(spec, from_json=from_json)
    meta = bundle["meta"]
    target_bytes = bundle["target_bytes"]

    func_name = str(meta.get("diff_label") or meta.get("name") or "").strip()
    ctx_code = str(meta.get("context") or "").strip()
    src_code = str(meta.get("source_code") or "").strip()
    combined_c = (ctx_code + "\n\n" + src_code + "\n").lstrip() if ctx_code else (src_code + "\n")

    raw_flags = str(meta.get("compiler_flags") or "").strip()
    parsed_flags = shlex.split(raw_flags) if raw_flags else list(cfg.compiler.flags)
    mapped_preset = map_decompme_compiler(str(meta.get("compiler") or ""))
    if mapped_preset != "agbcc" and "-c" not in parsed_flags:
        parsed_flags.append("-c")

    with tempfile.TemporaryDirectory(prefix="kintoun_scratch_") as tmp:
        work_dir = Path(save_dir) if save_dir else Path(tmp)
        work_dir.mkdir(parents=True, exist_ok=True)
        target_o = work_dir / "target.o"
        cand_c = work_dir / "candidate.c"
        meta_j = work_dir / "scratch.json"
        target_o.write_bytes(target_bytes)
        cand_c.write_text(combined_c, encoding="utf-8")
        meta_j.write_text(json.dumps(meta, indent=2), encoding="utf-8")

        ctx, target_fn = load_target_from_object(target_o, func_name or None)
        if compiler_override is not None:
            compiler = compiler_override
        elif cfg.compiler.command or (cfg.compiler.preset != "custom" and cfg.compiler.compiler_dir):
            # Prefer user's already-configured compiler in `kintoun.toml` when compatible, overriding flags if provided
            cc = replace(
                cfg.compiler,
                flags=parsed_flags or list(cfg.compiler.flags),
                compiler_dir=compiler_dir or cfg.compiler.compiler_dir,
            )
            compiler = make_compiler(replace(cfg, compiler=cc))
        else:
            cc = CompilerConfig(
                preset=mapped_preset,
                flags=parsed_flags,
                compiler_dir=compiler_dir or cfg.compiler.compiler_dir,
                wine=cfg.compiler.wine,
                wineprefix=cfg.compiler.wineprefix,
                timeout_s=cfg.compiler.timeout_s,
            )
            compiler = make_compiler(replace(cfg, compiler=cc))

        cache_dir = cfg.resolve_path(cfg.search.cache_dir)
        priors_path = cfg.resolve_path(cfg.search.priors_file)
        if budget_s <= 0:
            ver = verify_source(combined_c, target_fn, ctx, compiler, forbid_asm=cfg.search.forbid_asm)
            return {
                "slug": meta.get("slug", spec),
                "function": target_fn.name,
                "arch": ctx.arch,
                "preset": mapped_preset,
                "verified": bool(ver.get("verified")),
                "best": {**ver, "code": combined_c},
            }

        search_res = run_search(
            source=combined_c,
            target_fn=target_fn,
            ctx=ctx,
            compiler=compiler,
            budget_s=budget_s,
            max_candidates=max_candidates,
            strategies=cfg.search.strategies,
            workers=workers or cfg.search.workers,
            cache_dir=cache_dir,
            priors_path=priors_path,
            forbid_asm=cfg.search.forbid_asm,
        )
        best = search_res.get("best") or {}
        verified = bool(search_res.get("verified"))
        aligned = float((best.get("search") or {}).get("aligned_pct") or 0.0)

        if not verified and aligned >= 85.0 and best.get("code"):
            closed = close_near_miss(
                best["code"],
                target_fn,
                ctx,
                compiler,
                budget_s=min(45.0, max(10.0, budget_s * 0.5)),
                cache_dir=cache_dir,
                priors_path=priors_path,
                forbid_asm=cfg.search.forbid_asm,
                governor_check=False,
            )
            if closed.get("verified") or (closed.get("improved") and (closed.get("best") or {}).get("code")):
                best = closed["best"]
                verified = bool(closed.get("verified"))

        if out_source is not None and best.get("code"):
            Path(out_source).write_text(best["code"], encoding="utf-8")

        return {
            "slug": meta.get("slug", spec),
            "function": target_fn.name,
            "arch": ctx.arch,
            "preset": mapped_preset,
            "flags": parsed_flags,
            "verified": verified,
            "evaluated": search_res.get("evaluated"),
            "elapsed_s": search_res.get("elapsed_s"),
            "best": best,
        }
