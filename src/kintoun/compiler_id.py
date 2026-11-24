"""Dedicated per-architecture compiler codegen fingerprinter (`ppc_elf`, `mips_elf`, `arm_elf`).

Detects when a target function in a mixed-compiler binary (such as MWCC SDK routines linked
into a ProDG GameCube DOL, SN/MWCC middleware in a PS2/PSP ELF, or ARM/ASM sound/BIOS libraries
in an `agbcc` GBA ROM) exhibits codegen tells incompatible with the active compiler preset,
preventing wasted search clocks and guiding `[[compiler_bands]]` configuration.
"""
from __future__ import annotations

import struct
from typing import Any

from kintoun.targets import TargetContext, TargetFunction


def _fingerprint_ppc(data: bytes) -> dict[str, Any]:
    words = [struct.unpack_from(">I", data, off)[0] for off in range(0, len(data) - (len(data) % 4), 4)]
    if not words:
        return {"detected_family": "unknown", "confidence": "low", "evidence": []}

    evidence: list[str] = []
    mwcc_score = 0
    prodg_score = 0

    head = words[:10]
    stwu_idx = next((i for i, w in enumerate(head) if (w >> 26) == 37 and ((w >> 16) & 0x1F) == 1), None)
    mflr_idx = next((i for i, w in enumerate(head) if w == 0x7C0802A6), None)
    stmw_idx = next((i for i, w in enumerate(head) if (w >> 26) == 47), None)

    # MWCC vs ProDG prologue ordering
    if stwu_idx == 0 and mflr_idx == 1:
        # Check whether stw r0 comes immediately at idx 2 before stmw (MWCC 1.2.5 / 2.x standard)
        if len(head) > 2 and (head[2] & 0xFFFF0000) == 0x90010000 and stmw_idx is not None and stmw_idx >= 3:
            mwcc_score += 2
            evidence.append("MWCC prologue order: stwu r1 -> mflr r0 -> stw r0 -> stmw")
    elif mflr_idx == 0 and stwu_idx is not None and stwu_idx >= 1:
        prodg_score += 2
        evidence.append("GCC/ProDG prologue order: mflr r0 before stwu r1")

    for w in words:
        op = (w >> 26) & 0x3F
        # `addi rD, rS, 0` register copy (`op=14`, `ra!=0`, `simm==0`) - MWCC emits this; GCC emits `mr` (`or`)
        if op == 14 and ((w >> 16) & 0x1F) != 0 and (w & 0xFFFF) == 0:
            mwcc_score += 2
            evidence.append("MWCC idiom: `addi rD, rS, 0` register move")
            break

    for w in words:
        # `cror` (`op=19`, `xo=449`) before float branch - classic GCC/ProDG float compare idiom
        if (w >> 26) == 19 and ((w >> 1) & 0x3FF) == 449:
            prodg_score += 2
            evidence.append("GCC/ProDG idiom: `cror` condition-register combine")
            break

    if mwcc_score >= prodg_score + 2:
        return {"detected_family": "mwcc", "confidence": "high" if mwcc_score >= 3 else "medium", "evidence": evidence}
    if prodg_score >= mwcc_score + 2:
        return {"detected_family": "prodg-gcc", "confidence": "high" if prodg_score >= 3 else "medium", "evidence": evidence}
    return {"detected_family": "any-ppc", "confidence": "low", "evidence": evidence}


def _fingerprint_mips(data: bytes, little_endian: bool = True) -> dict[str, Any]:
    fmt = "<I" if little_endian else ">I"
    words = [struct.unpack_from(fmt, data, off)[0] for off in range(0, len(data) - (len(data) % 4), 4)]
    if not words:
        return {"detected_family": "unknown", "confidence": "low", "evidence": []}

    evidence: list[str] = []
    gcc_score = 0
    mwcc_snc_score = 0

    for w in words:
        op = (w >> 26) & 0x3F
        if op in (20, 21, 22, 23):  # beql / bnel / blezl / bgtzl
            gcc_score += 1
            if "MIPS branch-likely (`beql`/`bnel`)" not in evidence:
                evidence.append("MIPS branch-likely (`beql`/`bnel`)")
        if op == 0x1F and (w & 0x3F) == 0x20:  # Allegrex `seb`/`seh`
            gcc_score += 1
        # R5900 `sq` (`op=0x1F` on EE is special2/MMI, `sq` is `op=0x1F`? No, R5900 `lq`=0x1E, `sq`=0x1F!)
        if op in (0x1E, 0x1F) and (((w >> 21) & 0x1F) == 29):
            gcc_score += 2
            evidence.append("PS2 EE 128-bit `lq`/`sq` stack save (`ee-gcc`)")
            break

    if gcc_score >= 2 and mwcc_snc_score == 0:
        return {"detected_family": "mips-gcc", "confidence": "medium", "evidence": evidence}
    return {"detected_family": "any-mips", "confidence": "low", "evidence": evidence}


def _fingerprint_arm(data: bytes, is_thumb: bool = False) -> dict[str, Any]:
    if not data:
        return {"detected_family": "unknown", "confidence": "low", "evidence": []}
    evidence: list[str] = []
    agbcc_score = 0
    eabi_mw_score = 0

    if is_thumb and len(data) >= 6:
        hws = [struct.unpack_from("<H", data, off)[0] for off in range(0, len(data) - (len(data) % 2), 2)]
        # `agbcc` Thumb-1 epilogue on ARMv4T: `pop {r0}` (`0xBC01` / `0xBC02`) followed by `bx r0` (`0x4700` / `0x4708`)
        # vs modern EABI / ARMv5+ `pop {..., pc}` (`0xBDxx`)
        for idx in range(len(hws) - 1):
            if (hws[idx] & 0xFF00) == 0xBC00 and (hws[idx + 1] & 0xFF87) == 0x4700:
                agbcc_score += 3
                evidence.append("ARMv4T `agbcc` epilogue: `pop {rX}; bx rX`")
                break
        # `agbcc` high-reg prologue: `push {..., lr}` followed by `mov r7, r8; push {r7}` (`0x4647`, `0xB480`)
        for idx in range(min(8, len(hws) - 1)):
            if hws[idx] in (0x4647, 0x4646) and (hws[idx + 1] & 0xFF00) == 0xB400:
                agbcc_score += 3
                evidence.append("`agbcc` high-register save: `mov r7, r8; push {r7}`")
                break
        # Thumb-2 32-bit `push.w` (`0xE92D`) or `blx` (`0xF000` + `0xE800`) -> not `agbcc`!
        for idx in range(len(hws) - 1):
            if hws[idx] == 0xE92D:
                eabi_mw_score += 3
                evidence.append("Thumb-2 `push.w` (`arm-none-eabi-gcc` / `armcc`, incompatible with `agbcc`)")
                break

    if agbcc_score >= eabi_mw_score + 2:
        return {"detected_family": "agbcc", "confidence": "high", "evidence": evidence}
    if eabi_mw_score >= agbcc_score + 2:
        return {"detected_family": "arm-eabi-or-mwcc", "confidence": "high", "evidence": evidence}
    return {"detected_family": "any-arm", "confidence": "low", "evidence": evidence}


def fingerprint_compiler(
    target_fn: TargetFunction,
    ctx: TargetContext,
    configured_preset: str = "",
) -> dict[str, Any]:
    """Detect target function compiler family and warn on mismatch against `configured_preset`."""
    if ctx.arch in ("mips", "mips_elf"):
        fp = _fingerprint_mips(target_fn.data, little_endian=(ctx.endian != "big"))
    elif ctx.arch in ("arm", "arm_elf"):
        fp = _fingerprint_arm(target_fn.data, is_thumb=target_fn.is_thumb)
    else:
        fp = _fingerprint_ppc(target_fn.data)

    preset = configured_preset.strip().lower()
    det = fp["detected_family"]
    warning: str | None = None
    mismatch = False

    if preset == "prodg-wine" and det == "mwcc" and fp["confidence"] == "high":
        mismatch = True
        warning = (
            "Target function shows Metrowerks MWCC prologue/register-move idioms while preset is 'prodg-wine'. "
            "Consider adding a [[compiler_bands]] entry with preset = 'mwcc-wine' for this address range."
        )
    elif preset == "mwcc-wine" and det == "prodg-gcc" and fp["confidence"] == "high":
        mismatch = True
        warning = (
            "Target function shows GCC/ProDG prologue/cror idioms while preset is 'mwcc-wine'. "
            "Check if this range belongs to a GCC/ProDG library band."
        )
    elif preset == "agbcc" and det == "arm-eabi-or-mwcc":
        mismatch = True
        warning = "Target uses Thumb-2 instructions that GBA `agbcc` cannot emit."

    return {
        "configured_preset": preset or "custom",
        "detected_family": det,
        "confidence": fp["confidence"],
        "mismatch": mismatch,
        "warning": warning,
        "evidence": fp["evidence"],
    }
