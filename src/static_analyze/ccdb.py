import json, os, re, pathlib, shlex, dataclasses, subprocess, collections
from typing import Iterable, List, Dict, Optional, Tuple, Set
from ..utils.utils import get_logger

logger = get_logger(__name__)

LANG_EXT = {
    'c': {'.c'},
    'c++': {'.cc', '.cpp', '.cxx', '.C', '.cp', '.c++', '.CPP'},
}
HEADER_EXT = {'.h', '.hpp', '.hh', '.hxx', '.H', '.inl'}

WRAPPER_BINS = ('ccache', 'sccache', 'distcc', 'icecc', 'gomacc')
COMPILER_HINTS = ('clang', 'clang++', 'gcc', 'g++', 'clang-cl', 'gclang', 'gclang++', 'wllvm', 'wllvm++')

STRIP_FLAGS = {'-c', '-o'}
STRIP_PREFIXES = (
    '-M', '-MD', '-MF', '-MT', '-MP',
    '-fcolor-diagnostics', '-fdiagnostics-color', '-fno-color-diagnostics', '-fno-caret-diagnostics',
    '-fuse-ld', '-gsplit-dwarf', '-gsplit-dwarf=', '-gz', '-gz=',
    '-Wp,', '-Wl,', '-Xlinker', '-B', '-emit-llvm',
)
KEEP_PREFIXES = (
    '-I', '-isystem', '-iquote', '-isysroot', '-include', '-imacros',
    '-D', '-U', '-std=', '--sysroot=', '-resource-dir',
    '-m', '-fms-compatibility', '-fms-extensions',
    '-nostdinc', '-nostdinc++',
)
FLAGS_NEED_VALUE = {'-I','-isystem','-iquote','-isysroot','-include','-imacros','-D','-U','-MF','-MT','-o','-resource-dir'}

@dataclasses.dataclass
class TU:
    file: str
    directory: str
    arguments: List[str]
    language: str
    compiler: Optional[str] = None
    is_virtual: bool = False

class CCDB:
    def __init__(self, entries: List[Dict]):
        self._raw = entries
        self._tus: List[TU] = self._normalize(entries)

    @staticmethod
    def from_path(path: str | os.PathLike) -> "CCDB":
        p = pathlib.Path(path)
        if p.is_dir():
            p = p / "compile_commands.json"
        if not p.exists():
            logger.error(f"compile_commands.json not found: {p}")
        data = json.loads(p.read_text(encoding='utf-8'))
        if not isinstance(data, list):
            logger.error("the top of compile_commands.json should be an array")
        return CCDB(data)

    def _normalize(self, entries: List[Dict]) -> List[TU]:
        tus: Dict[str, TU] = {}
        for e in entries:
            directory = e.get('directory') or os.getcwd()
            file = e.get('file') or ''
            if 'arguments' in e and isinstance(e['arguments'], list):
                argv = list(e['arguments'])
            else:
                cmd = e.get('command') or ''
                argv = shlex.split(cmd) if cmd else []

            # try to detect compiler/token and record it
            compiler_hint = None
            if argv:
                first = argv[0]
                base = os.path.basename(first)
                # unwrap wrappers like ccache / sccache
                if base in WRAPPER_BINS and len(argv) > 1:
                    base2 = os.path.basename(argv[1])
                    if any(h in base2 for h in COMPILER_HINTS):
                        compiler_hint = base2
                elif any(h in base for h in COMPILER_HINTS):
                    compiler_hint = base

            file_abs = str(pathlib.Path(directory, file).resolve())
            lang = self._guess_lang(file_abs)
            tu = TU(file=file_abs, directory=directory, arguments=argv, language=lang, compiler=compiler_hint)
            tus[file_abs] = tu

        return list(tus.values())

    @staticmethod
    def _guess_lang(path: str) -> str:
        suff = pathlib.Path(path).suffix

        for type, suffixs in LANG_EXT.items():
            if suff in suffixs:
                return type

        if suff in HEADER_EXT:
            return 'header'

        return 'unknown'

    def _expand_response_file(self, argv: List[str], basedir: str) -> List[str]:
        """
        Expand @response-files recursively.
        Returns a new argv list (does not modify input list).
        """
        out: List[str] = []
        seen: Set[str] = set()

        def _expand(token: str):
            if not token.startswith('@'):
                out.append(token)
                return
            rsp_path = token[1:]
            p = pathlib.Path(rsp_path)
            if not p.is_absolute():
                p = pathlib.Path(basedir) / rsp_path

            try:
                p = p.resolve()
            except Exception:
                # can't resolve, just treat token as-is
                out.append(token)
                return

            if not p.exists():
                out.append(token)
                return

            if str(p) in seen:
                return
            seen.add(str(p))

            try:
                text = p.read_text(encoding='utf-8', errors='ignore')
            except Exception:
                return

            # split with posix/shlex, allow comments inside response file
            for t in shlex.split(text, comments=True, posix=True):
                if t.startswith('@'):
                    _expand(t)
                else:
                    out.append(t)

        for a in argv:
            _expand(a)

        return out

    def iter_tus(self, lang: Tuple[str, ...] = ('c','c++')) -> Iterable[TU]:
        for tu in self._tus:
            if tu.language in lang:
                yield tu

    def clang_args_for(self, tu: TU, extra: Optional[List[str]] = None, abs_path: bool = True) -> List[str]:
        argv = list(tu.arguments)
        argv = self._expand_response_file(argv, tu.directory)

        # detect and drop compiler/wrapper token at head, record compiler if missing
        if argv:
            head = argv[0]
            base = os.path.basename(head)
            # if it's a wrapper, drop it and try to record next
            if base in WRAPPER_BINS and len(argv) > 1:
                maybe = os.path.basename(argv[1])
                if any(h in maybe for h in COMPILER_HINTS):
                    if not tu.compiler:
                        tu.compiler = maybe
                argv = argv[1:]
            else:
                if any(h in base for h in COMPILER_HINTS):
                    if not tu.compiler:
                        tu.compiler = base
                # drop the compiler token (it will be re-provided by caller if needed)
                if not head.startswith('-'):
                    argv = argv[1:]

        cleaned: List[str] = []
        skip_next = False
        for i, a in enumerate(argv):
            if skip_next:
                skip_next = False
                continue
            if a in STRIP_FLAGS:
                if a in ('-o', '-c'):
                    skip_next = True
                continue
            if any(a.startswith(pref) for pref in STRIP_PREFIXES):
                continue
            if a == '-Xclang':
                cleaned.append(a)
                if i+1 < len(argv):
                    cleaned.append(argv[i+1])
                    skip_next = True
                continue
            if a == '-cc1':
                continue

            keep = any(a == pref or a.startswith(pref) for pref in KEEP_PREFIXES)
            if keep:
                if abs_path and a in FLAGS_NEED_VALUE and i+1 < len(argv):
                    val = argv[i+1]
                    if not val.startswith('-') and not os.path.isabs(val):
                        val = str(pathlib.Path(tu.directory, val).resolve())
                    cleaned += [a, val]
                    skip_next = True
                else:
                    # handle -I/similar with concatenated form: -Irelative or -isystem/path
                    if a.startswith(('-I','-isystem','-iquote')) and not a.startswith('--sysroot='):
                        # split prefix and path if concatenated
                        if a.startswith('-I') and len(a) > 2:
                            prefix, val = '-I', a[2:]
                        elif a.startswith('-isystem') and len(a) > len('-isystem'):
                            prefix, val = '-isystem', a[len('-isystem'):]
                        elif a.startswith('-iquote') and len(a) > len('-iquote'):
                            prefix, val = '-iquote', a[len('-iquote'):]
                        else:
                            prefix, val = None, None

                        if prefix and val:
                            if not os.path.isabs(val):
                                val = str(pathlib.Path(tu.directory, val).resolve())
                            cleaned.append(prefix + val)
                        else:
                            cleaned.append(a)
                    else:
                        cleaned.append(a)
                continue

            if a.startswith('-W') or a.startswith('-O') or a.startswith('-g'):
                continue
            if a.startswith('-std='):
                cleaned.append(a)
                continue

        if not any(x.startswith('-std=') for x in cleaned):
            if tu.language == 'c++':
                cleaned.append('-std=c++17')
            elif tu.language == 'c':
                cleaned.append('-std=c17')

        if tu.is_virtual:
            if tu.language == 'c++':
                cleaned += ['-x','c++']
            elif tu.language == 'c':
                cleaned += ['-x','c']

        if extra:
            cleaned.extend(extra)
        return cleaned

    def clang_args_profile(self) -> Dict[str, List[str]]:
        per_lang: Dict[str, collections.Counter] = {'c': collections.Counter(), 'c++': collections.Counter()}
        std_seen: Dict[str, str] = {}

        for tu in self.iter_tus():
            args = self.clang_args_for(tu, abs_path=True)
            std = next((a for a in args if a.startswith('-std=')), None)
            if std:
                std_seen[tu.language] = std_seen.get(tu.language, std)
            for i, a in enumerate(args):
                if a in FLAGS_NEED_VALUE and i+1 < len(args) and not args[i+1].startswith('-'):
                    per_lang[tu.language][(a, args[i+1])] += 1
                elif a.startswith(('-I','-isystem','-iquote','-D','-U','--sysroot=','-resource-dir','-nostdinc','-nostdinc++')):
                    per_lang[tu.language][(a, None)] += 1

        profile: Dict[str, List[str]] = {}
        for lang, counter in per_lang.items():
            if not counter:
                continue

            total = sum(counter.values())
            kept: List[str] = []

            for (flag, val), count in counter.most_common():
                freq = count / total

                if flag.startswith(('-I','-isystem','-iquote','-D','-U')):
                    if freq < 0.15:
                        continue
                if val is not None:
                    kept += [flag, val]
                else:
                    kept.append(flag)

            if lang in std_seen:
                kept.append(std_seen[lang])

            uniq, seen = [], set()
            for k in kept:
                if k not in seen:
                    uniq.append(k)
                    seen.add(k)

            profile[lang] = uniq

        return profile

    def get_headers_depend(self, include_system: bool = False, max_tus: Optional[int] = None) -> Dict[str, Set[str]]:
        depend: Dict[str, Set[str]] = collections.defaultdict(set)
        count = 0
        for tu in self.iter_tus(('c', 'c++')):
            if max_tus and count >= max_tus:
                break
            count += 1

            compiler = tu.compiler or 'clang'
            args = self.clang_args_for(tu, abs_path=True)

            # build clang -M/-MM command
            get_depend_cmd = [compiler, '-M'] if include_system else [compiler, '-MM']
            if tu.language == 'c' and '-x' not in args:
                get_depend_cmd += ['-x', 'c']
            elif tu.language == 'c++' and '-x' not in args:
                get_depend_cmd += ['-x', 'c++']

            get_depend_cmd += args + ['-c', tu.file] #-c avoid actual link

            try:
                proc = subprocess.run(get_depend_cmd, cwd=tu.directory, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, check=False, text=True)
            except Exception as e:
                logger.warning(f"[get_headers_depend] failed for {tu.file}, {e}")
                continue

            line = (proc.stdout or '').replace('\\\n', ' ').strip()
            if not line:
                continue

            try:
                _, deps = line.split(':', 1)
            except ValueError:
                deps = line
            # deps is a space separated list of headers (possibly with paths)
            for token in shlex.split(deps, comments=True, posix=True):
                if token.endswith(('.c', '.cc', '.cpp', 'cxx')):
                    continue

                p = pathlib.Path(token)
                if not p.is_absolute():
                    p = pathlib.Path(tu.directory) / p
                try:
                    hp = str(p.resolve())
                except Exception:
                    continue
                if os.path.isfile(hp):
                    depend[hp].add(tu.file)

        return depend

    def macros_dump(self, lang: Optional[str] = 'c', from_tu: Optional[TU] = None, extra: Optional[List[str]] = None) -> Dict[str, str]:
        if from_tu:
            compiler = from_tu.compiler or ('clang' if from_tu.language == 'c' else 'clang++')
            args = self.clang_args_for(from_tu, abs_path=True, extra=extra)
            cmd = [compiler, "-dM", "-E"] + args + [from_tu.file]
        else:

            profile = self.clang_args_profile().get(lang, [])
            compiler = 'clang++' if lang == 'c++' else 'clang'
            args = list(profile)
            if extra:
                args.extend(extra)

            # only pre-process; pass empty input
            cmd = [compiler, '-dM', '-E'] + args + ['-']

        try:
            # use text mode so proc.stdout is a str
            proc = subprocess.run(cmd, input='', text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
        except Exception as e:
            logger.error(f"[macros_dump] failed for lang={lang}, {e}")
            return {}

        out_lines = (proc.stdout or '').splitlines()
        macros: Dict[str, str] = {}

        for line in out_lines:
            line = line.strip()
            if not line.startswith('#define'):
                continue

            parts = line.split(None, 2)
            if len(parts) == 3:
                name = parts[1]; val = parts[2]
            elif len(parts) == 2:
                name = parts[1]; val = "1"
            else:
                continue
            macros[name] = val

        return macros

    def virtual_tu_for_header(self, header_path: str) -> TU:
        hp = pathlib.Path(header_path).resolve()
        candidates = [tu for tu in self._tus if tu.language in ('c','c++')]

        if not candidates:
            logger.error("No reusable source file TU found in CCDB")
        def score(tu: TU) -> int:
            sp = pathlib.Path(tu.file).resolve()
            try:
                return len(os.path.commonpath([hp, sp]))
            except Exception:
                return 0

        best = max(candidates, key=score)
        lang = best.language
        vtu = TU(file=str(hp), directory=str(hp.parent), arguments=list(best.arguments), language=lang, is_virtual=True, compiler=best.compiler)
        return vtu

    def stats(self) -> Dict[str,int]:
        total = len(self._tus)
        by_lang = {}
        for tu in self._tus:
            by_lang[tu.language] = by_lang.get(tu.language, 0) + 1
        return {'total': total, **{f'lang_{k}': v for k, v in by_lang.items()}}


if __name__ == "__main__":
    import sys, json

    db = CCDB.from_path("/root/libxml2/bear_build/compile_commands.json")
    print("\n[+] CCDB stats:", db.stats())

    print("\n[+] First few translation units:")
    for i, tu in enumerate(db.iter_tus()):
        print(f"  [{i}] {tu.language} -> {tu.file}")
        if i >= 4:
            break

    print("\n[+] Testing clang_args_for() on first TU:")
    sample_tu = next(db.iter_tus())
    args = db.clang_args_for(sample_tu)
    print("  Compiler:", sample_tu.compiler or "(unknown)")
    print("  Args sample:", " ".join(args[:15]), "...")
    print("  Total args:", len(args))

    print("\n[+] clang_args_profile():")
    profile = db.clang_args_profile()
    for lang, flags in profile.items():
        print(f"  - {lang}: {len(flags)} common flags")
        print("    Sample:", flags[:8])

    print("\n[+] get_headers_depend():")
    deps = db.get_headers_depend(include_system=False, max_tus=3)
    print(f"  Extracted {len(deps)} header dependencies (limited to 3 TU).")
    for i, (hdr, users) in enumerate(deps.items()):
        print(f"    {hdr} <- {list(users)[:1]}")
        if i >= 4:
            break

    print("\n[+] macros_dump():")
    for tu in db.iter_tus():
        if tu.file.endswith('parser.c'):
            macros_test = db.macros_dump(from_tu=tu)

    macros = db.macros_dump(lang='c')

    print(f"  Total macros: {len(macros)}")
    sample_items = list(macros.items())[:8]
    for k, v in sample_items:
        print(f"    {k} = {v}")
    if not macros:
        print("maybe failed to dump macros")

    print("\n[+] virtual_tu_for_header():")
    example_header = next(iter(deps.keys()), None)
    if example_header:
        vtu = db.virtual_tu_for_header(example_header)
        print("  Header:", example_header)
        print("  Virtual TU:", vtu)
        print("  Args (truncated):", db.clang_args_for(vtu)[:8])
    else:
        print("  (No headers found for testing.)")

    print("\n[+] CCDB self-test completed successfully.")