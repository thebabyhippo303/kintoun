"""Pluggable compiler backends for Kintoun (ProDG/Wine, MWCC/Wine, or any custom CLI)."""
from __future__ import annotations

from dataclasses import dataclass
import os
from pathlib import Path
import re
import shutil
import subprocess
from typing import Protocol

from kintoun.config import CompilerConfig, KintounConfig


def compile_failure(output: str, limit: int = 2000) -> str:
    """Trim noisy compiler/Wine/pspspecs banners down to the actionable diagnostics."""
    lines = [
        line.rstrip()
        for line in (output or "").splitlines()
        if line.strip()
        and not line.lstrip().startswith(("wine:", "00", "fixme:"))
        and "'pspspecs' not found" not in line
        and "Please install 'pspspecs'" not in line
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
    """Runs any native or Wine/wibo-hosted compiler via a command template.

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
                stdin=subprocess.DEVNULL,
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


def _resolve_tool(cdir: Path | None, candidates: tuple[str, ...], allow_path: bool = True) -> str:
    """Find a compiler executable in `compiler_dir` (including nested `*/bin` layouts) or system PATH."""
    if cdir is not None and cdir.is_dir():
        for name in candidates:
            for probe in (cdir / name, cdir / "bin" / name):
                if probe.is_file():
                    return str(probe)
            for pat in (f"*/bin/{name}", f"*/*/bin/{name}", f"*/{name}"):
                hits = sorted(p for p in cdir.glob(pat) if p.is_file())
                if hits:
                    return str(hits[0])
    if allow_path:
        for name in candidates:
            found = shutil.which(name)
            if found:
                return found
    return str(cdir / candidates[0]) if cdir is not None else candidates[0]


def _resolve_win32_runner(wine_cfg: str, cdir: Path | None, prefer_wibo: bool = False) -> str:
    """Resolve `wine` or `wibo` runner for Win32 console compilers."""
    if wine_cfg and wine_cfg != "wine":
        return wine_cfg
    if prefer_wibo:
        found_wibo = shutil.which("wibo")
        if found_wibo:
            return found_wibo
        if cdir is not None:
            for parent in (cdir, cdir.parent):
                for probe in (parent / "wibo" / "wibo", parent / "wibo"):
                    if probe.is_file() and os.access(probe, os.X_OK):
                        return str(probe)
    return wine_cfg or "wine"


_NEEDS_CPP_RE = re.compile(r"(?m)^\s*#|//|/\*")


class AgbccCompiler(CommandCompiler):
    """Multi-stage compiler backend for GBA `agbcc` (`cpp` -> `agbcc` -> `arm-none-eabi-as`).

    `agbcc` is `cc1` without an integrated C preprocessor; when `#define`/`#include`
    directives or `//` line comments are present, we preprocess with `arm-none-eabi-gcc -E -P`
    (or `cpp -P`) before running `agbcc` and assembling with `arm-none-eabi-as`.
    """

    def __init__(
        self,
        agbcc_exe: str,
        as_command: list[str],
        cpp_exe: str | None = None,
        flags: list[str] | None = None,
        compiler_dir: Path | None = None,
        env: dict[str, str] | None = None,
        timeout_s: float = 30.0,
        compiler_id: str = "agbcc",
    ) -> None:
        super().__init__(
            command=[agbcc_exe],
            flags=flags or ["-O2"],
            compiler_dir=compiler_dir,
            env=env,
            timeout_s=timeout_s,
            compiler_id=compiler_id,
        )
        self.agbcc_exe = agbcc_exe
        self.as_command = list(as_command)
        self.cpp_exe = cpp_exe

    def compile_c(self, src: Path, out_obj: Path) -> CompileResult:
        src_abs = src.resolve()
        out_abs = out_obj.resolve()
        asm_path = out_abs.with_suffix(".s")
        env = os.environ.copy()
        env.update(self.extra_env)

        cc_input = src_abs
        cpp_Flags: list[str] = []
        other_flags: list[str] = []
        for f in self.flags:
            if f.startswith(("-I", "-D", "-U", "-include")):
                cpp_Flags.append(f)
            else:
                other_flags.append(f)

        try:
            raw_txt = src_abs.read_text(encoding="utf-8", errors="replace")
            if self.cpp_exe and (cpp_Flags or _NEEDS_CPP_RE.search(raw_txt)):
                i_path = out_abs.with_suffix(".i")
                cpp_argv = [self.cpp_exe, "-E", "-P", *cpp_Flags, "-x", "c", str(src_abs), "-o", str(i_path)]
                proc_cpp = subprocess.run(
                    cpp_argv,
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    timeout=self.timeout_s,
                    env=env,
                )
                if proc_cpp.returncode != 0 or not i_path.is_file():
                    return CompileResult(proc_cpp.returncode or 1, proc_cpp.stdout, proc_cpp.stderr, out_obj)
                cc_input = i_path

            cc_argv = [self.agbcc_exe, *other_flags, str(cc_input), "-o", str(asm_path)]
            proc1 = subprocess.run(
                cc_argv,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=self.timeout_s,
                env=env,
            )
            if proc1.returncode != 0 or not asm_path.is_file():
                return CompileResult(proc1.returncode or 1, proc1.stdout, proc1.stderr, out_obj)
            as_argv = [*self.as_command, str(asm_path), "-o", str(out_abs)]
            proc2 = subprocess.run(
                as_argv,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=self.timeout_s,
                env=env,
            )
            return CompileResult(
                proc2.returncode,
                (proc1.stdout or "") + (proc2.stdout or ""),
                (proc1.stderr or "") + (proc2.stderr or ""),
                out_obj,
            )
        except subprocess.TimeoutExpired as exc:
            return CompileResult(
                124,
                str(exc.stdout or ""),
                f"compiler timed out after {self.timeout_s:.1f}s",
                out_obj,
            )
        except FileNotFoundError as exc:
            return CompileResult(127, "", f"compiler executable not found: {exc}", out_obj)


def make_compiler(cfg: KintounConfig) -> CommandCompiler:
    """Instantiate a CompilerBackend from KintounConfig."""
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
    elif preset == "ee-gcc":
        exe_s = _resolve_tool(cdir, ("mips64r5900el-ps2-elf-gcc", "ee-gcc"))
        # Historic Sony `ee-gcc` (2.95/2.96/3.2) is bare-metal non-PIC by default and rejects `-mno-abicalls` in 3.2;
        # modern PS2DEV `mips64r5900el-ps2-elf-gcc` defaults to `-mabicalls` and requires `-mno-abicalls -fno-pic`.
        if cc.flags:
            flags = list(cc.flags)
        elif Path(exe_s).name == "ee-gcc":
            flags = ["-O2", "-G8", "-c"]
        else:
            flags = ["-O2", "-mno-abicalls", "-fno-pic", "-G8", "-c"]
        exe_parent = Path(exe_s).parent
        if exe_parent.is_dir():
            env["PATH"] = f"{exe_parent}:{env.get('PATH', os.environ.get('PATH', ''))}"
        cmd = [exe_s, "{flags}", "-o", "{out}", "{in}"]
    elif preset in ("mwccps2", "mwcps2", "mwccps2-wine"):
        exe_s = _resolve_tool(cdir, ("mwccps2.exe", "mwccps2", "mwccmips.exe"))
        flags = list(cc.flags) or ["-O4,p", "-nodefaults", "-c"]
        if "-c" not in flags:
            flags.append("-c")
        if exe_s.endswith(".exe"):
            runner = _resolve_win32_runner(cc.wine, cdir, prefer_wibo=True)
            cmd = [runner, exe_s, "{flags}", "{in}", "-o", "{out}"]
        else:
            cmd = [exe_s, "{flags}", "{in}", "-o", "{out}"]
    elif preset in ("psp-gcc", "allegrex"):
        exe_s = _resolve_tool(cdir, ("psp-gcc", "mipsallegrexel-psp-elf-gcc"))
        if not Path(exe_s).is_file() and cdir is not None and (cdir / "psp" / "bin" / "gcc").is_file():
            exe_s = str(cdir / "psp" / "bin" / "gcc")
        flags = list(cc.flags) or ["-O2", "-mno-abicalls", "-fno-pic", "-G8", "-c"]
        exe_path = Path(exe_s)
        # Auto-resolve or strip `-specs=pspspecs` on relocated PSPDEV / historic PSP GCC installs
        specs_dirs: list[Path] = []
        for root_cand in ([cdir] if cdir else []) + ([exe_path.resolve().parent.parent] if exe_path.is_file() else []):
            for sub in (root_cand / "psp" / "lib", root_cand / "psp" / "sdk" / "lib", root_cand / "lib"):
                if (sub / "pspspecs").is_file() and sub not in specs_dirs:
                    specs_dirs.append(sub)
        if specs_dirs:
            flags = [f"-B{specs_dirs[0]}/", *flags]
        else:
            flags = [f for f in flags if not (f.startswith("-specs=") and f.endswith("pspspecs"))]
        # Relocated historic Sony `psp-gcc` (`lib/gcc-lib/psp/<ver>/cc1`) support
        if cdir is not None and (cdir / "lib" / "gcc-lib" / "psp").is_dir():
            # Historic Sony `psp-gcc` 3.3.x is bare-metal non-PIC by default and rejects `-mno-abicalls` if incompatible
            ver_dirs = sorted(p for p in (cdir / "lib" / "gcc-lib" / "psp").iterdir() if p.is_dir())
            if ver_dirs:
                flags = [f"-B{ver_dirs[-1]}/", *flags]
            pspdev_as_dirs = (
                sorted((cdir.parent / "pspdev").glob("**/psp/bin"))
                if (cdir.parent / "pspdev").is_dir()
                else []
            )
            if pspdev_as_dirs:
                flags = [f"-B{pspdev_as_dirs[0]}/", *flags]
        exe_parent = exe_path.parent
        if exe_parent.is_dir():
            env["PATH"] = f"{exe_parent}:{env.get('PATH', os.environ.get('PATH', ''))}"
        cmd = [exe_s, "{flags}", "-o", "{out}", "{in}"]
    elif preset in ("mwccpsp", "mwccpsp-wine"):
        exe_s = _resolve_tool(cdir, ("mwccpsp.exe", "mwccpsp"))
        flags = list(cc.flags) or ["-O4,p", "-nodefaults", "-c"]
        if "-c" not in flags:
            flags.append("-c")
        if exe_s.endswith(".exe"):
            runner = _resolve_win32_runner(cc.wine, cdir, prefer_wibo=True)
            cmd = [runner, exe_s, "{flags}", "{in}", "-o", "{out}"]
        else:
            cmd = [exe_s, "{flags}", "{in}", "-o", "{out}"]
    elif preset in ("pspsnc", "prodg-psp"):
        exe_s = _resolve_tool(cdir, ("pspsnc.exe", "pspsnc"))
        flags = list(cc.flags) or ["-O2", "-c"]
        if "-c" not in flags:
            flags.append("-c")
        if exe_s.endswith(".exe"):
            runner = _resolve_win32_runner(cc.wine, cdir, prefer_wibo=True)
            cmd = [runner, exe_s, "{flags}", "-o", "{out}", "{in}"]
        else:
            cmd = [exe_s, "{flags}", "-o", "{out}", "{in}"]
    elif preset == "mips-gcc":
        exe_s = _resolve_tool(
            cdir,
            ("mips-linux-gcc", "mips-linux-gnu-gcc", "mips-elf-gcc", "mipsel-elf-gcc", "mipsel-linux-gnu-gcc"),
        )
        flags = list(cc.flags) or ["-O2", "-mno-abicalls", "-fno-pic", "-c"]
        exe_parent = Path(exe_s).parent
        if exe_parent.is_dir():
            env["PATH"] = f"{exe_parent}:{env.get('PATH', os.environ.get('PATH', ''))}"
        cmd = [exe_s, "{flags}", "-o", "{out}", "{in}"]
    elif preset == "arm-none-eabi-gcc":
        exe_s = _resolve_tool(cdir, ("arm-none-eabi-gcc",))
        flags = list(cc.flags) or ["-O2", "-c"]
        exe_parent = Path(exe_s).parent
        if exe_parent.is_dir():
            env["PATH"] = f"{exe_parent}:{env.get('PATH', os.environ.get('PATH', ''))}"
        cmd = [exe_s, "{flags}", "-o", "{out}", "{in}"]
    elif preset == "agbcc":
        agbcc_s = _resolve_tool(cdir, ("agbcc", "old_agbcc", "agbcc.exe"))
        arm_gnu_dir = cdir.parent / "arm-gnu" if (cdir and (cdir.parent / "arm-gnu").is_dir()) else None
        as_exe = _resolve_tool(arm_gnu_dir, ("arm-none-eabi-as",))
        cpp_exe = _resolve_tool(arm_gnu_dir, ("arm-none-eabi-gcc", "cpp", "gcc"))
        as_cmd = list(cc.assembler) if cc.assembler else [as_exe, "-mcpu=arm7tdmi", "-mthumb-interwork"]
        flags = [f for f in (cc.flags or ["-O2", "-mthumb-interwork"]) if f != "-c"]
        return AgbccCompiler(
            agbcc_exe=agbcc_s,
            as_command=as_cmd,
            cpp_exe=cpp_exe if (Path(cpp_exe).is_file() or shutil.which(cpp_exe)) else None,
            flags=flags,
            compiler_dir=cdir,
            env=env,
            timeout_s=cc.timeout_s,
            compiler_id=f"agbcc:{agbcc_s}:{as_cmd[0]}",
        )
    elif preset in ("mwccarm", "mwccarm-wine"):
        flags = list(cc.flags) or ["-O4,p", "-proc", "arm946e", "-c"]
        if "-c" not in flags:
            flags.append("-c")
        exe_s = _resolve_tool(cdir, ("mwccarm", "mwccarm.exe"))
        if exe_s.endswith(".exe"):
            runner = _resolve_win32_runner(cc.wine, cdir, prefer_wibo=True)
            cmd = [runner, exe_s, "{flags}", "{in}", "-o", "{out}"]
        else:
            cmd = [exe_s, "{flags}", "{in}", "-o", "{out}"]
    elif preset in ("armcc", "rvct"):
        exe_s = _resolve_tool(cdir, ("armcc.exe", "armcc", "tcc.exe", "tcc"))
        flags = list(cc.flags) or ["--thumb", "-O2", "-c"]
        if "-c" not in flags:
            flags.append("-c")
        if exe_s.endswith(".exe"):
            runner = _resolve_win32_runner(cc.wine, cdir, prefer_wibo=True)
            cmd = [runner, exe_s, "{flags}", "-o", "{out}", "{in}"]
        else:
            cmd = [exe_s, "{flags}", "-o", "{out}", "{in}"]
    else:
        raise ValueError(
            f"Unsupported compiler preset '{cc.preset}'. "
            "Use 'prodg-wine', 'mwcc-wine', 'ee-gcc', 'mwccps2', 'psp-gcc', 'mwccpsp', 'pspsnc', "
            "'mips-gcc', 'arm-none-eabi-gcc', 'agbcc', 'mwccarm', 'armcc', 'gcc', "
            "or set compiler.command in kintoun.toml."
        )

    return CommandCompiler(
        command=cmd,
        flags=flags,
        compiler_dir=cdir,
        env=env,
        timeout_s=cc.timeout_s,
        compiler_id=f"{preset}:{':'.join(cmd[:2])}",
    )
