"""End-to-end local setup health check and local compiler directory scanner (`kintoun doctor`).

Validates configuration, target binary/symbols, Wine/`wibo` runner, and performs a 2-line C compile
smoke test against the configured compiler without ever downloading proprietary SDK binaries.
"""
from __future__ import annotations

from pathlib import Path
import shutil
import struct
import tempfile
from typing import Any

from kintoun.compiler import CompilerBackend, make_compiler
from kintoun.config import KintounConfig
from kintoun.targets import load_target_from_config

_KNOWN_COMPILER_BINARIES: tuple[tuple[str, str, str], ...] = (
    ("ngccc.exe", "prodg-wine", "ppc_elf"),
    ("mwcceppc.exe", "mwcc-wine", "ppc_elf"),
    ("mwccps2.exe", "mwccps2", "mips_elf"),
    ("mwcpsp.exe", "mwccpsp", "mips_elf"),
    ("pspsnc.exe", "pspsnc", "mips_elf"),
    ("mwccarm.exe", "mwccarm", "arm_elf"),
    ("armcc.exe", "armcc", "arm_elf"),
    ("ee-gcc", "ee-gcc", "mips_elf"),
    ("psp-gcc", "psp-gcc", "mips_elf"),
    ("agbcc", "agbcc", "arm_elf"),
    ("arm-none-eabi-gcc", "arm-none-eabi-gcc", "arm_elf"),
    ("mips-linux-gnu-gcc", "mips-gcc", "mips_elf"),
    ("mipsel-linux-gnu-gcc", "mips-gcc", "mips_elf"),
)

_EXPECTED_ELF_MACHINE = {
    "ppc_elf": 20,
    "mips_elf": 8,
    "arm_elf": 40,
}


def scan_local_compilers(scan_dir: Path, max_files: int = 4000) -> list[dict[str, str]]:
    """Scan an existing local directory (e.g. `tools/`) for known compiler binaries and map to presets."""
    root = Path(scan_dir).resolve()
    if not root.is_dir():
        return []
    lookup = {bname.lower(): (preset, arch) for bname, preset, arch in _KNOWN_COMPILER_BINARIES}
    found: list[dict[str, str]] = []
    seen_dirs: set[tuple[str, str]] = set()
    for idx, p in enumerate(sorted(root.rglob("*"))):
        if idx >= max_files:
            break
        if not p.is_file():
            continue
        lname = p.name.lower()
        if lname in lookup:
            preset, arch = lookup[lname]
            key = (preset, str(p.parent))
            if key not in seen_dirs:
                seen_dirs.add(key)
                found.append(
                    {
                        "preset": preset,
                        "arch": arch,
                        "binary": str(p),
                        "compiler_dir": str(p.parent),
                    }
                )
    return found


def run_doctor(
    cfg: KintounConfig,
    *,
    compiler_override: CompilerBackend | None = None,
    scan_dir: Path | None = None,
) -> dict[str, Any]:
    """Run deterministic setup diagnostics on `cfg` (config, Wine/`wibo`, compiler smoke test, target)."""
    checks: list[dict[str, Any]] = []

    # 1. Config & project root check
    toml_path = cfg.root / "kintoun.toml"
    checks.append(
        {
            "check": "config",
            "ok": True,
            "detail": (
                f"loaded {toml_path}"
                if toml_path.is_file()
                else f"using auto-detected/default config at {cfg.root} (preset={cfg.compiler.preset}, arch={cfg.target.arch})"
            ),
        }
    )

    # 2. Wine / wibo runner check for `-wine` / Windows presets
    needs_wine = cfg.compiler.preset in ("prodg-wine", "mwcc-wine", "mwccps2", "mwccpsp", "pspsnc", "armcc")
    if needs_wine:
        wine_bin = shutil.which(cfg.compiler.wine)
        wibo_bin = shutil.which("wibo")
        checks.append(
            {
                "check": "wine_runner",
                "ok": bool(wine_bin or wibo_bin),
                "detail": (
                    f"found '{cfg.compiler.wine}' at {wine_bin}"
                    if wine_bin
                    else (
                        f"'{cfg.compiler.wine}' missing, but fast 'wibo' found at {wibo_bin} (set wine = \"wibo\" in kintoun.toml)"
                        if wibo_bin
                        else f"neither '{cfg.compiler.wine}' nor 'wibo' found on PATH"
                    )
                ),
            }
        )

    # 3. Compiler instantiation + live 2-line C smoke compile
    comp_ok = False
    comp_detail = ""
    try:
        compiler = compiler_override if compiler_override is not None else make_compiler(cfg)
        with tempfile.TemporaryDirectory(prefix="kintoun_doc_") as tmp:
            src_p = Path(tmp) / "smoke.c"
            obj_p = Path(tmp) / "smoke.o"
            src_p.write_text("int KintounDoctorSmoke(int a) {\n    return a + 1;\n}\n", encoding="utf-8")
            smoke_res = compiler.compile_c(src_p, obj_p)
            obj_bytes = obj_p.read_bytes() if (smoke_res.returncode == 0 and obj_p.is_file()) else b""
        if smoke_res.returncode != 0 or not obj_bytes:
            comp_detail = f"compile smoke test failed: {(smoke_res.stderr or smoke_res.stdout or 'empty object').strip()[:160]}"
        elif len(obj_bytes) >= 20 and obj_bytes[:4] == b"\x7fELF":
            em_fmt = "<H" if obj_bytes[5] == 1 else ">H"
            em = struct.unpack_from(em_fmt, obj_bytes, 18)[0]
            exp_em = _EXPECTED_ELF_MACHINE.get(cfg.target.arch)
            if exp_em and em != exp_em:
                comp_detail = f"ELF e_machine={em} does not match target.arch={cfg.target.arch} (expected {exp_em})"
            else:
                comp_ok = True
                comp_detail = f"compiled valid ELF32 object ({len(obj_bytes)} bytes, e_machine={em})"
        else:
            comp_detail = "compiler output is not a valid ELF32 relocatable object"
    except Exception as exc:
        comp_detail = str(exc)

    checks.append({"check": "compiler_smoke", "ok": comp_ok, "detail": comp_detail})

    # 4. Target binary & symbols check (or objdiff.json unit presence)
    tgt_path_s = cfg.target.dol or cfg.target.binary
    objdiff_p = cfg.root / "objdiff.json"
    if tgt_path_s:
        try:
            ctx = load_target_from_config(cfg)
            has_img = len(ctx._image) > 0
            n_fns = len(ctx.funcs)
            checks.append(
                {
                    "check": "target_binary",
                    "ok": has_img and n_fns > 0,
                    "detail": f"mapped {len(ctx._image)} bytes, {n_fns} function symbol(s), {len(ctx.objs)} object symbol(s)",
                }
            )
        except Exception as exc:
            checks.append({"check": "target_binary", "ok": False, "detail": str(exc)})
    elif objdiff_p.is_file():
        checks.append(
            {
                "check": "target_binary",
                "ok": True,
                "detail": f"found {objdiff_p} (standalone per-unit .o verification active)",
            }
        )
    else:
        checks.append(
            {
                "check": "target_binary",
                "ok": False,
                "detail": "no target binary/DOL configured in kintoun.toml (pass --target file.o or configure [target])",
            }
        )

    discovered = scan_local_compilers(scan_dir) if scan_dir else []
    overall_ok = all(c["ok"] for c in checks if c["check"] in ("compiler_smoke",)) and (
        all(c["ok"] for c in checks if c["check"] == "wine_runner")
    )
    return {
        "ok": overall_ok,
        "all_checks_passed": all(c["ok"] for c in checks),
        "project": cfg.project_name,
        "arch": cfg.target.arch,
        "preset": cfg.compiler.preset,
        "checks": checks,
        "discovered_compilers": discovered,
    }
