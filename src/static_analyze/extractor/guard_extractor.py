import re
from dataclasses import dataclass, asdict
from typing import List, Dict, Any, Optional, Iterable, Tuple, Set
from clang import cindex
from src.utils.libclang_load import load_libclang

#load_libclang()
cindex.Config.set_library_file('/opt/llvm21/lib/libclang.so.21.1.0')  # Adjust path as necessary


@dataclass
class GuardCond:
    kind: str       # "runtime" | "pre-process"
    expr: str       # the condition expression
    location: str   # "path:line:column"
    func_context: Optional[str] = None
    file: Optional[str] = None       # source file path
    tags: List[str] = None      # ["null_check", "flag_check", ...]
    ids: List[str] = None       # extracted ids from the condition expression
    bitmask_hint: List[Dict[str, Any]] = None       # the bitmask hints for the ids(if any), like: [{"name": "...", "group": "...", "bit_width": 32 / 16, ...}, ...]

#   matching rules
ID_RE = re.compile(r'[A-Za-z_]\w*(?:::\w+)*')     # match identifiers, including C++ qualified names

BITMASK_PATTERNS = [
    # some matching rules for bitmask operations
    re.compile(r'([A-Za-z_]\w*)\s*&\s*([A-Za-z_]\w*)'),         # like a & b
    re.compile(r'([A-Za-z_]\w*)\s*&\s*\(([^)]+)\)'),      # like a & (b | c)
    re.compile(r'\(\s*([A-Za-z_]\w*)\s*&\s*([A-Za-z_]\w*)\s*\)\s*(?:==|!=|<=|>=)\s*(?:0|[A-Za-z_]\w*)'),   # like (a & b) == 0 or != 0
    re.compile(r'([A-Za-z_]\w*)\s*\|\s*([A-Za-z_]\w*)'),       # like a | b
    re.compile(r'~\s*([A-Za-z_]\w*)\s*&\s*([A-Za-z_]\w*)'),     # like ~a & b
    re.compile(r'\b[A-Z_]\w*\s*\(\s*([A-Za-z_]\w*)\s*,\s*([A-Za-z_]\w*)\s*\)'), # like FLAG_CHECK(a, b)
    re.compile(r'([A-Za-z_]\w*)\s*==\s*([A-Za-z_]\w*)'),      # like a == b
    re.compile(r'([A-Za-z_]\w*)\s*\|=\s*([A-Za-z_]\w*)'),      # like a |= b
]

NULL_PATTERNS = [
    re.compile(r'!\s*([A-Za-z_]\w*)\b'),
    re.compile(r'\b([A-Za-z_]\w*)\s*==\s*(?:0|NULL|nullptr)\b'),
    re.compile(r'\b([A-Za-z_]\w*)\s*!=\s*(?:0|NULL|nullptr)\b'),
]

LEN_PATTERNS = [
    re.compile(r'\b([A-Za-z_]\w*)\s*(?:>|>=|<|<=)\s*(?:\d+|[A-Za-z_]\w*)')
]

RUNTIME_NONE_KINDS = [
    cindex.CursorKind.IF_STMT,
    cindex.CursorKind.WHILE_STMT,
    cindex.CursorKind.FOR_STMT,
    cindex.CursorKind.DO_STMT,
    cindex.CursorKind.SWITCH_STMT,
    cindex.CursorKind.CONDITIONAL_OPERATOR
]

PP_LINE_RE = re.compile(r'#\s*(if|ifdef|ifndef|elif)\b(.*)$')

def tokens_text(cur: cindex.Cursor, max_len: int = 512) -> str:
    try:
        toks = list(cur.get_tokens())
        s = " ".join(t.spelling for t in toks)
        return s if len(s) <= max_len else s[:max_len] + "..."
    except Exception:
        return ""

def cursor_loc(cur: cindex.Cursor) -> str:
    loc = cur.location
    if loc and loc.file:
        return f"{loc.file}:{loc.line}:{loc.column}"
    else:
        return "<unknown>"

def owning_function_name(cur: cindex.Cursor) -> Optional[str]:
    visited = set()
    p = cur
    while p:
        key = (str(p.location.file), p.location.line, p.location.column, p.kind)
        if key in visited:
            break
        visited.add(key)

        if p.kind in (
            cindex.CursorKind.FUNCTION_DECL,
            cindex.CursorKind.CXX_METHOD,
            cindex.CursorKind.CONSTRUCTOR,
            cindex.CursorKind.DESTRUCTOR,
        ):
            return p.spelling
        
        parent = p.lexical_parent or p.semantic_parent

        if not parent and hasattr(p.extent, "start") and hasattr(p.extent.start, "file"):
            parent = getattr(p.extent.start, "cursor", None)

        p = parent
    
    return "__runtime__"

def collect_ids(text: str) -> List[str]:
    # collect identifiers from the given text
    return list({m.group(0) for m in ID_RE.finditer(text)})


def build_bitmask_index(groups: List[Dict]) -> Dict[str, Dict[str, Any]]:
    # build a cross-reference index from the bitmask groups
    idx: Dict[str, Dict[str, Any]] = {}
    for g in groups:
        key = g.get("key")
        bit_width = g.get("bit_width_hint")
        strategy = g.get("strategy")
        bind_param = g.get("bind_param")
        for bv in g.get("value", []):
            name = bv.get("name")
            if not name:
                continue
            idx[name] = {
                "group": key,
                "bit_width": bit_width,
                "strategy": strategy,
                "bind_param": bind_param,
                "used_as_bit": bv.get("used_as_bit"),
                "resolved_value": bv.get("resolved_value"),
                "decl": bv.get("declaration_location"),
                "origin": bv.get("original")
            }
    
    return idx

class GuardExtractor:
    def __init__(self, known_bitmask_index: Optional[Dict[str, Dict[str, Any]]] = None,
                known_bitmask_names: Optional[Set[str]] = None):
        
        """
        known_bitmask_index: build by build_bitmask_index(), contains cross-reference info for bitmask variables(extract from bitmask extractor)
        known_bitmask_names: to judge whether an identifier is a bitmask variable or not (if build_bitmask_index isn't provided, can onlu provide names set)
        """
        self.bm_index = known_bitmask_index
        self.bm_names = set(known_bitmask_names or set())
    
    def _classify_runtime(self, text: str) -> List[str]:
        # runtime guarding conditions
        tags: List[str] = []
        if any(p.search(text) for p in NULL_PATTERNS):
            tags.append("null-check")
        if any(ptn in text for ptn in ["&", "~", "|", "==", "!", "HAS_", "FLAG", "MASK"]):
            if any(p.search(text) for p in BITMASK_PATTERNS):
                tags.append("flag-check")
        if any(p.search(text) for p in LEN_PATTERNS):
            tags.append("length-check")
        if not tags:
            tags.append("generic-cond")
        
        return tags
    
    def _extract_condition_text(self, cur: cindex.Cursor) -> str:
    # extract the condition expression text from the given cursor
        try:
            for c in cur.get_children():
                if c.kind in(
                    cindex.CursorKind.PAREN_EXPR,
                    cindex.CursorKind.BINARY_OPERATOR,
                    cindex.CursorKind.UNARY_OPERATOR,
                    cindex.CursorKind.CONDITIONAL_OPERATOR,
                    cindex.CursorKind.CALL_EXPR,
                    cindex.CursorKind.MEMBER_REF_EXPR,
                    cindex.CursorKind.DECL_REF_EXPR
                ):
                    txt = tokens_text(c)
                    if txt and len(txt.strip()) > 0:
                        return txt
            
            all_tokens = list(cur.get_tokens())
            if all_tokens:
                s = " ".join(t.spelling for t in all_tokens)
                m = re.search(r'\((.*)\)', s, re.S)         # try to extract inside the parentheses
                if m:
                    inside = m.group(1).strip()
                    if inside:
                        if len(inside) > 512:
                            return inside[:512] + "..."
                        return inside
                    
            return tokens_text(cur)
        except Exception:
            return tokens_text(cur)
    
    def _bitmask_hits_in_text(self, text: str) -> List[Dict[str, Any]]:
        if not any(ptn in text for ptn in ["&", "~", "|", "==", "!", "HAS_", "FLAG", "MASK"]):      # do a quick check first, if no bitmask-related tokens, skip
            return []

        hits: List[Dict[str, Any]] = []
        for pattern in BITMASK_PATTERNS:
            for m in pattern.finditer(text):
                groups = [g for g in m.groups() if g]
                for const in groups:
                    if not const.isidentifier():
                        continue
                
                meta = self.bm_index.get(const)
                if meta:
                    hits.append({"name": const, **meta})
                elif const in self.bm_names:
                    hits.append({"name": const})

        seen = set()
        uniq = []
        for h in hits:
            n = h.get("name")
            if n and n not in seen:
                seen.add(n)
                uniq.append(h)
        
        return uniq
    
    def _emit_func_guard(self, cur:cindex.Cursor, out: List[GuardCond], func_ctx: Optional[str]):
        text = self._extract_condition_text(cur)
        loc = cursor_loc(cur)
        file_path = loc.split(":", 1)[0] if ":" in loc else None
        cond = GuardCond(
            kind="runtime",
            expr=text,
            location=loc,
            file=file_path,
            func_context=func_ctx or "__global__",
            tags=self._classify_runtime(text),
            ids=collect_ids(text),
            bitmask_hint=self._bitmask_hits_in_text(text)
        )
        out.append(cond)
    
    def _extract_pp_lines(self, tu: cindex.TranslationUnit) -> List[GuardCond]:
        results: List[GuardCond] = []
        try:
            tokens = list(tu.get_tokens(extent=tu.cursor.extent))
        except Exception:
            return results
        
        #cluster the tokens in the same line
        lines: Dict[Tuple[str, int], List[str]] = {}
        for tk in tokens:
            loc = tk.location
            if not loc or not loc.file:
                continue

            key = (str(loc.file), loc.line)
            lines.setdefault(key, []).append(tk.spelling)

        for (f, ln), toks in lines.items():
            line = " ".join(toks)
            m = PP_LINE_RE.search(line)
            if not m:
                continue
            expr = m.group(2).strip()
            cond = GuardCond(
                kind="pre-process",
                expr=expr,
                location=f"{f}:{ln}:1",
                file=f,
                func_context="_pre_process_",
                tags=["pre-process-cond"],
                ids=collect_ids(expr),
                bitmask_hint=self._bitmask_hits_in_text(expr)
            )
            
            results.append(cond)
        
        return results

    def extract_from_tu(self, tu:cindex.TranslationUnit) -> List[GuardCond]:
        results: List[GuardCond] = []

        # set up a context stack to track function context
        FUNC_LIKE_KIND = {
            cindex.CursorKind.FUNCTION_DECL,
            cindex.CursorKind.CXX_METHOD,
            cindex.CursorKind.CONSTRUCTOR,
            cindex.CursorKind.DESTRUCTOR,
            getattr(cindex.CursorKind, "FUNCTION_TEMPLATE", None),
            getattr(cindex.CursorKind, "LAMBDA_EXPR", None),
        }
        FUNC_LIKE_KINDS = {k for k in FUNC_LIKE_KIND if k is not None}

        def function_label(cur: cindex.Cursor) -> str:
            name = (cur.spelling or "").strip()
            if name:
                return name
            loc = cursor_loc(cur)
            return f"__anon@{loc}"
        

        def visit(cur:cindex.Cursor, func_ctx: Optional[str]):
            if cur.kind in FUNC_LIKE_KINDS:
                func_ctx = function_label(cur)
            if cur.kind in RUNTIME_NONE_KINDS:
                self._emit_func_guard(cur, results, func_ctx)
            for c in cur.get_children():
                visit(c, func_ctx=func_ctx)

        visit(tu.cursor, func_ctx=None)
        results.extend(self._extract_pp_lines(tu))

        seen: Set[Tuple[Optional[str], str]] = set()
        depuped: List[GuardCond] = []
        for cond in results:
            key = (cond.location,cond.func_context, cond.expr)
            if key and key not in seen:
                seen.add(key)
                depuped.append(cond)

        return depuped

if __name__ == "__main__":
    import json
    from src.static_analyze.extractor.bitmask_extractor import BitmaskExtractor
    from src.static_analyze.ccdb import CCDB

    db = CCDB.from_path("/root/libxml2/bear_build/compile_commands.json")
    #bitext = BitmaskExtractor(require_bit_operator=False, min_group_size=2)
    bitext = BitmaskExtractor(require_bit_operator=True, min_group_size=2)
    idx = cindex.Index.create()

    bitmask_dump: List[Dict] = []

    for tu_meta in db.iter_tus():
        args = db.clang_args_for(tu_meta)
        tu = idx.parse(tu_meta.file, args=args, options=cindex.TranslationUnit.PARSE_DETAILED_PROCESSING_RECORD)

        print(f"Analyzing TU: {tu_meta.file}\n")
        macros = db.macros_dump(tu_meta.language, tu_meta)
        
        groups_list = bitext.extract_from_tu(tu, macros)
        groups_dict = bitext.groups_to_dict(groups_list)

        bm_index = build_bitmask_index(groups_dict)
        bm_names = set(bm_index.keys())

        extractor = GuardExtractor(known_bitmask_index=bm_index, known_bitmask_names=bm_names)
        guards = extractor.extract_from_tu(tu)
        print(f"  Found {len(guards)} guarding conditions.\n")
        for g in guards:
            print(f"{g}\n")