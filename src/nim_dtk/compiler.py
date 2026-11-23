"""Pluggable compiler backends for NIM-DTK (ProDG/Wine, MWCC/Wine, or any custom CLI)."""
from __future__ import annotations

from dataclasses import dataclass
import os
from pathlib import Path
import subprocess
from typing import Protocol

from nim_dtk.config import CompilerConfig, NimDtkConfig


def compile_failure(output: str, limit: int = 2000) -> str:
    """Trim noisy compiler/Wine banners down to the actionable diagnostics."""
    lines = [
        line.rstrip()
        for line in (output or "").splitlines()
        if line.strip() and not line.lstrip().startswith(("wine:", "00", "fixme:"))
    ]
    text = "\n".join(lines[-40:]) if lines else (output or "").strip()
    return text[-limit:] if len(text) > limit else text


@dataclass(frozen=True)
class CompileResult:
    returncode: int
    stdout: str
    stderr: str
    obj_path: Path


class CompilerBackend(Protocol):
    compiler_id: str
    flags: tuple[str, ...]

    def compile_c(self, src: Path, out_obj: Path) -> CompileResult: ...


class CommandCompiler:
    """Runs any native or Wine-hosted compiler via a command template.

    Supported placeholders in `command`:
      {in} / {src}     input C source path
      {out} / {obj}    output .o path
      {compiler_dir}   resolved compiler directory
      {flags}          expanded in-place as individual flag arguments
    """

    def __init__(
        self,
        command: list[str],
        flags: list[str] | None = None,
        compiler_dir: Path | None = None,
        env: dict[str, str] | None = None,
        timeout_s: float = 30.0,
        compiler_id: str = "custom",
    ) -> None:
        self.command = list(command)
        self.flags = tuple(flags or [])
        self.compiler_dir = compiler_dir
        self.extra_env = dict(env or {})
        self.timeout_s = timeout_s
        self.compiler_id = compiler_id

    def _build_argv(self, src: Path, out_obj: Path) -> list[str]:
        cdir = str(self.compiler_dir) if self.compiler_dir else ""
        argv: list[str] = []
        has_flags = False
        for token in self.command:
            if token == "{flags}":
                argv.extend(self.flags)
                has_flags = True
            else:
                argv.append(
                    token.format(
                        src=str(src),
                        obj=str(out_obj),
                        compiler_dir=cdir,
                        **{"in": str(src), "out": str(out_obj)},
                    )
                )
        if not has_flags and self.flags:
            argv.extend(self.flags)
        return argv

    def compile_c(self, src: Path, out_obj: Path) -> CompileResult:
        argv = self._build_argv(src.resolve(), out_obj.resolve())
        env = os.environ.copy()
        env.update(self.extra_env)
        try:
            proc = subprocess.run(
                argv,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=self.timeout_s,
                env=env,
            )
            return CompileResult(proc.returncode, proc.stdout, proc.stderr, out_obj)
        except subprocess.TimeoutExpired as exc:
            return CompileResult(
                124,
                str(exc.stdout or ""),
                f"compiler timed out after {self.timeout_s:.1f}s",
                out_obj,
            )
        except FileNotFoundError as exc:
            return CompileResult(127, "", f"compiler executable not found: {exc}", out_obj)


def make_compiler(cfg: NimDtkConfig) -> CommandCompiler:
    """Instantiate a CompilerBackend from NimDtkConfig."""
    cc: CompilerConfig = cfg.compiler
    cdir = cfg.resolve_path(cc.compiler_dir)
    env = dict(cc.env)
    env.setdefault("WINEDEBUG", "-all")
    if cc.wineprefix:
        prefix = cfg.resolve_path(cc.wineprefix)
        if prefix is not None:
            env["WINEPREFIX"] = str(prefix)

    preset = cc.preset.lower().strip()
    if cc.command:
        cmd = list(cc.command)
        flags = list(cc.flags)
    elif preset == "prodg-wine":
        if cdir is None:
            raise ValueError("compiler.compiler_dir (or PRODG_DIR) is required for preset 'prodg-wine'")
        exe = cdir / "ngccc.exe"
        flags = list(cc.flags) or ["-O2", "-c"]
        cmd = [cc.wine, str(exe), "{flags}", "-o", "{out}", "{in}"]
    elif preset == "mwcc-wine":
        if cdir is None:
            raise ValueError("compiler.compiler_dir is required for preset 'mwcc-wine'")
        exe = cdir / "mwcceppc.exe"
        flags = list(cc.flags) or ["-O4,p", "-nodefaults", "-proc", "gekko", "-fp", "hardware", "-c"]
        cmd = [cc.wine, str(exe), "{flags}", "{in}", "-o", "{out}"]
    elif preset == "gcc":
        flags = list(cc.flags) or ["-O2", "-c"]
        cmd = ["gcc", "{flags}", "-o", "{out}", "{in}"]
    else:
        raise ValueError(
            f"Unsupported compiler preset '{cc.preset}'. "
            "Use 'prodg-wine', 'mwcc-wine', 'gcc', or set compiler.command in nim-dtk.toml."
        )

    return CommandCompiler(
        command=cmd,
        flags=flags,
        compiler_dir=cdir,
        env=env,
        timeout_s=cc.timeout_s,
        compiler_id=f"{preset}:{':'.join(cmd[:2])}",
    )
