import os, re, shlex, subprocess, pathlib
from typing import List, Optional

def _run(cmd: str) -> Optional[str]:
    try:
        return subprocess.check_output(
            shlex.split(cmd),
            text=True,
            stderr=subprocess.STDOUT
        ).strip()
    except Exception:
        return None

def _clang_search_paths(compiler: str, lang: str) -> list[str]:
    try:
        p = subprocess.run(
            shlex.split(f"{compiler} -v -E -x {lang} -"),
            input="",
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            check=False,
        )
        text = p.stdout or ""
        m = re.search(r"search starts here:\n(.*?)\nEnd of search list\.", text, re.S)
        if not m:
            return []
        paths = []
        for line in m.group(1).splitlines():
            line = re.sub(r"\s*\(.*\)$", "", line.strip())
            if line and os.path.isabs(line):
                paths.append(line)
        return paths
    except Exception:
        return []

def add_isystem(args: list[str], *dirs: str) -> list[str]:
    out = list(args)
    seen = set()
    # 记录已有 -isystem <dir>
    i = 0
    while i < len(out):
        if out[i] == "-isystem" and i + 1 < len(out):
            seen.add(out[i+1]); i += 2
        else:
            i += 1
    for d in dirs:
        if d and d not in seen:
            out += ["-isystem", d]
            seen.add(d)
    return out

def enrich_clang_args_for_analysis(
    args: List[str],
    *,
    compiler: str = "clang",
    lang: str = "c",  # "c" or "c++"
    force_resource_dir: Optional[str] = None,  # 如 "/opt/llvm21/lib/clang/21"
    also_add_usr_include: bool = True,
) -> List[str]:
    
    out = [a for a in args if a not in ("-nostdinc", "-nostdinc++")]

    has_resdir = any(a == "-resource-dir" for a in out)
    if not has_resdir:
        rd = force_resource_dir or _run(f"{compiler} -print-resource-dir")
        if rd:
            out += ["-resource-dir", rd]

    has_sysroot = any(a.startswith("--sysroot=") or a == "--sysroot" for a in out)
    if not has_sysroot:
        sr = _run(f"{compiler} --print-sysroot") or _run("gcc --print-sysroot")
        if sr and sr != "/":
            out += [f"--sysroot={sr}"]

    to_add: list[str] = []

    gcc_inc = _run("gcc -print-file-name=include")
    if gcc_inc and gcc_inc != "include" and pathlib.Path(gcc_inc).exists():
        to_add.append(gcc_inc)

    multiarch = _run("gcc -print-multiarch")
    if multiarch:
        ma_inc = f"/usr/include/{multiarch}"
        if pathlib.Path(ma_inc).exists():
            to_add.append(ma_inc)

    lang_flag = "c++" if lang == "c++" else "c"
    for p in _clang_search_paths(compiler, lang_flag):
        if pathlib.Path(p).exists():
            to_add.append(p)

    if also_add_usr_include and pathlib.Path("/usr/include").exists():
        to_add.append("/usr/include")

    out = add_isystem(out, *to_add)

    return out
