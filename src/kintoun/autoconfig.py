"""Zero-config repository auto-detection for `objdiff.json`, `dtk` (`config.yml`), and `splat.yaml`.

Lets Kintoun ingest existing GameCube/Wii, PS2, PSP, MIPS, GBA, and NDS decompilation repositories
without manual path wiring, and export `objdiff.json` unit manifests for visual diffing.
"""
from __future__ import annotations

import json
from pathlib import Path
import re
from typing import Any

from kintoun.config import CompilerConfig, KintounConfig, SearchConfig, TargetConfig

_OBJDIFF_ARCH_MAP = {
    "ppc": "ppc_elf",
    "powerpc": "ppc_elf",
    "mips": "mips_elf",
    "mipsel": "mips_elf",
    "arm": "arm_elf",
    "arm32": "arm_elf",
    "thumb": "arm_elf",
    "gba": "arm_elf",
    "nds": "arm_elf",
}

_SPLAT_PLATFORM_MAP: dict[str, tuple[str, str, str]] = {
    "ps2": ("mips_elf", "ee-gcc", "little"),
    "psp": ("mips_elf", "psp-gcc", "little"),
    "psx": ("mips_elf", "mips-gcc", "little"),
    "n64": ("mips_elf", "mips-gcc", "big"),
    "gc": ("ppc_elf", "mwcc-wine", "big"),
    "wii": ("ppc_elf", "mwcc-wine", "big"),
    "gba": ("arm_elf", "agbcc", "little"),
    "nds": ("arm_elf", "mwccarm", "little"),
}


def _parse_simple_yaml_kv(text: str) -> dict[str, str]:
    """Parse top-level and `options:` scalar `key: value` entries from `dtk` or `splat` YAML files."""
    out: dict[str, str] = {}
    for raw in text.splitlines():
        line = raw.split("#", 1)[0].rstrip()
        if not line.strip() or line.lstrip().startswith("-"):
            continue
        m = re.match(r"^\s*([A-Za-z_][A-Za-z0-9_]*)\s*:\s*(.+?)\s*$", line)
        if not m:
            continue
        k, v = m.group(1), m.group(2).strip()
        if v in ("", "|", ">", "{", "["):
            continue
        if (v.startswith('"') and v.endswith('"')) or (v.startswith("'") and v.endswith("'")):
            v = v[1:-1]
        out.setdefault(k, v)
    return out


def parse_objdiff_config(objdiff_path: Path) -> dict[str, Any]:
    """Parse an `objdiff.json` manifest into normalized architecture and per-unit `.o`/`.c` mappings."""
    root = Path(objdiff_path).resolve().parent
    doc = json.loads(Path(objdiff_path).read_text(encoding="utf-8", errors="replace"))
    raw_arch = str(doc.get("arch", "")).strip().lower()
    arch = _OBJDIFF_ARCH_MAP.get(raw_arch, "")

    units: list[dict[str, Any]] = []
    for u in doc.get("units", []) if isinstance(doc.get("units"), list) else []:
        if not isinstance(u, dict):
            continue
        meta = u.get("metadata") if isinstance(u.get("metadata"), dict) else {}
        scratch = u.get("scratch") if isinstance(u.get("scratch"), dict) else {}
        src_p = str(meta.get("source_path") or u.get("source_path") or "")
        tgt_p = str(u.get("target_path") or "")
        base_p = str(u.get("base_path") or "")
        if not arch and scratch.get("platform"):
            plat = str(scratch["platform"]).lower()
            if plat in _SPLAT_PLATFORM_MAP:
                arch = _SPLAT_PLATFORM_MAP[plat][0]
        units.append(
            {
                "name": str(u.get("name") or ""),
                "target_path": tgt_p,
                "base_path": base_p,
                "source_path": src_p,
                "compiler": str(scratch.get("compiler") or ""),
                "c_flags": str(scratch.get("c_flags") or ""),
            }
        )

    # Sniff first existing target `.o` header if `arch` wasn't explicitly set in `objdiff.json`
    if not arch:
        for u in units:
            tp = (root / u["target_path"]) if u["target_path"] else None
            if tp and tp.is_file():
                hdr = tp.read_bytes()[:20]
                if len(hdr) >= 20 and hdr[:4] == b"\x7fELF":
                    em_fmt = "<H" if hdr[5] == 1 else ">H"
                    import struct as _st

                    e_machine = _st.unpack_from(em_fmt, hdr, 18)[0]
                    arch = {20: "ppc_elf", 8: "mips_elf", 40: "arm_elf"}.get(e_machine, "")
                    if arch:
                        break

    return {
        "source": str(objdiff_path),
        "root": str(root),
        "arch": arch or "ppc_elf",
        "units": units,
    }


def resolve_objdiff_target_object(
    project_root: Path,
    *,
    source_file: Path | None = None,
    func_name: str | None = None,
) -> Path | None:
    """Resolve a standalone target `.o` from `objdiff.json` by matching `.c` source path or unit/symbol name."""
    objdiff_p = Path(project_root) / "objdiff.json"
    if not objdiff_p.is_file():
        return None
    try:
        parsed = parse_objdiff_config(objdiff_p)
    except Exception:
        return None

    root = Path(project_root).resolve()
    rel_src = ""
    stem_src = ""
    if source_file is not None:
        sp = Path(source_file).resolve()
        stem_src = sp.stem
        try:
            rel_src = sp.relative_to(root).as_posix()
        except ValueError:
            rel_src = sp.as_posix()

    # 1. Exact `source_path` or unit stem match
    for u in parsed["units"]:
        tp = (root / u["target_path"]) if u["target_path"] else None
        if tp is None or not tp.is_file():
            continue
        u_src = u["source_path"].replace("\\", "/")
        u_name = u["name"].replace("\\", "/")
        if rel_src and (u_src == rel_src or u_src.endswith("/" + rel_src)):
            return tp
        if stem_src and (Path(u_name).stem == stem_src or Path(u_src).stem == stem_src):
            return tp

    # 2. Symbol name search inside target `.o` symtabs when only `--func` is known
    if func_name:
        needle = func_name.encode("utf-8") + b"\x00"
        for u in parsed["units"][:400]:
            tp = (root / u["target_path"]) if u["target_path"] else None
            if tp and tp.is_file():
                try:
                    if needle in tp.read_bytes():
                        return tp
                except OSError:
                    continue
    return None


def parse_dtk_config(dtk_path: Path, project_root: Path | None = None) -> dict[str, Any]:
    """Parse a GameCube/Wii `dtk` `config.yml` file."""
    p = Path(dtk_path).resolve()
    root = Path(project_root).resolve() if project_root else p.parent
    kv = _parse_simple_yaml_kv(p.read_text(encoding="utf-8", errors="replace"))
    dol = kv.get("object", "") or kv.get("dol", "")
    symbols = kv.get("symbols", "")
    preset = "mwcc-wine"
    if (root / "tools").is_dir():
        tool_names = " ".join(x.name.lower() for x in (root / "tools").rglob("*") if x.is_file())
        if "ngccc" in tool_names or "prodg" in tool_names:
            preset = "prodg-wine"
    return {
        "kind": "dtk",
        "source": str(p),
        "arch": "ppc_elf",
        "preset": preset,
        "dol": dol,
        "symbols": symbols,
    }


def parse_splat_config(splat_path: Path, project_root: Path | None = None) -> dict[str, Any]:
    """Parse a `splat.yaml` project file."""
    p = Path(splat_path).resolve()
    root = Path(project_root).resolve() if project_root else p.parent
    kv = _parse_simple_yaml_kv(p.read_text(encoding="utf-8", errors="replace"))
    plat = kv.get("platform", "ps2").lower()
    arch, default_preset, endian = _SPLAT_PLATFORM_MAP.get(plat, ("mips_elf", "mips-gcc", "little"))
    comp = kv.get("compiler", "").upper()
    preset = default_preset
    if "MWCC" in comp:
        preset = "mwccps2" if plat == "ps2" else "mwccpsp" if plat == "psp" else "mwcc-wine"
    elif "SNC" in comp or "PRODG" in comp:
        preset = "pspsnc" if plat == "psp" else "prodg-wine"
    elif "AGBCC" in comp:
        preset = "agbcc"

    sym_addrs = kv.get("symbol_addrs_path", "")
    if not sym_addrs:
        for cand in ("symbol_addrs.txt", "config/symbol_addrs.txt"):
            if (root / cand).is_file():
                sym_addrs = cand
                break
    return {
        "kind": "splat",
        "source": str(p),
        "name": kv.get("name") or kv.get("basename") or root.name,
        "platform": plat,
        "arch": arch,
        "preset": preset,
        "endian": kv.get("endianness", endian),
        "binary": kv.get("target_path", ""),
        "symbols": sym_addrs,
        "gp": kv.get("gp_value", "0x0"),
    }


def detect_repo_layout(start_dir: Path) -> dict[str, Any] | None:
    """Inspect `start_dir` for `dtk` `config.yml`, `splat.yaml`, or `objdiff.json`."""
    root = Path(start_dir).resolve()
    out: dict[str, Any] = {
        "root": str(root),
        "name": root.name,
        "sources": [],
        "arch": "ppc_elf",
        "preset": "custom",
        "dol": "",
        "binary": "",
        "symbols": "",
        "gp": "0x0",
        "thumb": False,
        "endian": "",
        "flags": [],
        "unit_count": 0,
    }

    # 1. Check `splat.yaml`
    for sp_name in ("splat.yaml", "splat.yml", "config/splat.yaml"):
        sp = root / sp_name
        if sp.is_file():
            sdata = parse_splat_config(sp, project_root=root)
            out["sources"].append(sp_name)
            out["name"] = sdata["name"]
            out["arch"] = sdata["arch"]
            out["preset"] = sdata["preset"]
            out["binary"] = sdata["binary"]
            out["symbols"] = sdata["symbols"]
            out["gp"] = sdata["gp"]
            out["endian"] = sdata["endian"]
            if sdata["platform"] == "gba":
                out["thumb"] = True
            break

    # 2. Check `dtk` config (`config/config.yml` or `config/*/config.yml`)
    dtk_candidates = [root / "config.yml", root / "dtk.yml", *sorted((root / "config").glob("**/config.yml"))]
    for dp in dtk_candidates:
        if dp.is_file():
            ddata = parse_dtk_config(dp, project_root=root)
            rel_d = dp.relative_to(root).as_posix()
            out["sources"].append(rel_d)
            out["arch"] = "ppc_elf"
            out["preset"] = ddata["preset"]
            out["dol"] = ddata["dol"]
            out["symbols"] = ddata["symbols"]
            break

    # 3. Check `objdiff.json`
    objdiff_p = root / "objdiff.json"
    if objdiff_p.is_file():
        odata = parse_objdiff_config(objdiff_p)
        out["sources"].append("objdiff.json")
        out["unit_count"] = len(odata["units"])
        if not out["dol"] and not out["binary"]:
            out["arch"] = odata["arch"]
        for u in odata["units"]:
            if u["c_flags"] and not out["flags"]:
                out["flags"] = [tok for tok in u["c_flags"].split() if tok.startswith("-")]
                break

    if not out["sources"]:
        return None
    if not out["flags"]:
        default_flags = {
            "mwcc-wine": ["-O4,p", "-nodefaults", "-proc", "gekko", "-fp", "hardware", "-c"],
            "prodg-wine": ["-O2", "-c"],
            "ee-gcc": ["-O2", "-mno-abicalls", "-fno-pic", "-G8", "-c"],
            "psp-gcc": ["-O2", "-mno-abicalls", "-fno-pic", "-G8", "-c"],
            "mips-gcc": ["-O2", "-mno-abicalls", "-fno-pic", "-c"],
            "agbcc": ["-O2"],
            "mwccarm": ["-O4,p", "-proc", "arm946e", "-c"],
            "custom": ["-O2", "-c"],
        }
        out["flags"] = default_flags.get(out["preset"], ["-O2", "-c"])
    return out


def render_detected_toml(detected: dict[str, Any]) -> str:
    """Render a clean `kintoun.toml` from `detect_repo_layout` output."""
    preset = detected["preset"]
    arch = detected["arch"]
    flags_json = json.dumps(detected["flags"])
    lines = [
        f"# Auto-generated from: {', '.join(detected['sources'])}",
        "[project]",
        f'name = {json.dumps(detected["name"])}',
        "",
        "[compiler]",
        f'preset = {json.dumps(preset)}',
    ]
    if "wine" in preset:
        lines.append('wine = "wibo"')
    lines.extend(
        [
            'compiler_dir = ""',
            f"flags = {flags_json}",
            "timeout_s = 30.0",
            "",
            "[target]",
            f'arch = {json.dumps(arch)}',
        ]
    )
    if arch == "ppc_elf":
        lines.append(f'dol = {json.dumps(detected["dol"])}')
        lines.append(f'symbols = {json.dumps(detected["symbols"])}')
        lines.append('sda_r13 = "0x0"')
        lines.append('sda_r2 = "0x0"')
    elif arch == "mips_elf":
        lines.append(f'binary = {json.dumps(detected["binary"])}')
        lines.append(f'symbols = {json.dumps(detected["symbols"])}')
        lines.append(f'gp = {json.dumps(detected["gp"] or "0x0")}')
    else:
        lines.append(f'binary = {json.dumps(detected["binary"])}')
        lines.append('base_addr = "0x08000000"')
        lines.append(f'symbols = {json.dumps(detected["symbols"])}')
        lines.append(f"thumb = {'true' if detected['thumb'] else 'false'}")

    lines.extend(
        [
            "",
            "[search]",
            "budget_s = 180.0",
            "max_candidates = 2500",
            'mode = "standard"',
            "workers = 0",
            'strategies = ["systematic", "register_focus", "random"]',
            'cache_dir = ".kintoun/cache"',
            "forbid_asm = true",
            "",
        ]
    )
    return "\n".join(lines)


def config_from_detected(detected: dict[str, Any]) -> KintounConfig:
    """Build an in-memory `KintounConfig` directly from `detect_repo_layout` when `kintoun.toml` is absent."""
    root = Path(detected["root"])
    preset = detected["preset"]
    gp_raw = detected.get("gp", "0x0")
    try:
        gp_val = int(str(gp_raw), 0)
    except ValueError:
        gp_val = 0
    return KintounConfig(
        root=root,
        project_name=detected["name"],
        compiler=CompilerConfig(
            preset=preset,
            flags=list(detected["flags"]),
            wine="wibo" if "wine" in preset else "wine",
        ),
        target=TargetConfig(
            arch=detected["arch"],
            dol=detected["dol"],
            binary=detected["binary"],
            symbols=detected["symbols"],
            gp=gp_val,
            thumb=bool(detected["thumb"]),
            endian=detected["endian"],
        ),
        search=SearchConfig(),
    )


def export_objdiff_config(
    project_root: Path,
    arch: str,
    *,
    src_dir: Path | None = None,
    target_obj_dir: str = "build/orig",
    base_obj_dir: str = "build/src",
    out_path: Path | None = None,
) -> dict[str, Any]:
    """Export a clean `objdiff.json` unit manifest from `src/*.c` files for two-way `objdiff` integration."""
    root = Path(project_root).resolve()
    eff_src = Path(src_dir).resolve() if src_dir else (root / "src")
    rev_arch = {"ppc_elf": "ppc", "mips_elf": "mips", "arm_elf": "arm"}.get(arch, "ppc")
    units: list[dict[str, Any]] = []
    if eff_src.is_dir():
        for cf in sorted(eff_src.rglob("*.c"))[:2000]:
            rel = cf.relative_to(root).as_posix()
            rel_no_src = cf.relative_to(eff_src).with_suffix("").as_posix()
            units.append(
                {
                    "name": rel_no_src,
                    "target_path": f"{target_obj_dir}/{rel_no_src}.o",
                    "base_path": f"{base_obj_dir}/{rel_no_src}.o",
                    "metadata": {"source_path": rel},
                }
            )
    doc = {
        "$schema": "https://raw.githubusercontent.com/encounter/objdiff/main/config.schema.json",
        "arch": rev_arch,
        "units": units,
    }
    if out_path is not None:
        Path(out_path).write_text(json.dumps(doc, indent=2) + "\n", encoding="utf-8")
    return doc
