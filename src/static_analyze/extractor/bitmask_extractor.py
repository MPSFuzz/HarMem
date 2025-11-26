import re
from dataclasses import dataclass, asdict
from typing import List, Dict, Optional, Tuple, Set, Iterable, DefaultDict
from collections import defaultdict
from clang import cindex
from src.utils.libclang_load import load_libclang

#load_libclang()
cindex.Config.set_library_file('/opt/llvm21/lib/libclang.so.21.1.0')  # Adjust path as necessary

@dataclass
class BitmaskValue:
    name: str
    value: str
    resolved_value: Optional[int]
    original: Optional[str] = None  # Original definition line, if needed for reference
    declaration_location: Optional[str] = None
    bit_width_hint: Optional[int] = None
    used_as_bit: bool = False

@dataclass
class BitmaskGroup:
    key: str         # the prefix of this bitmask group(like XML_PARAMTERS_*) or binding parameter
    value: List[BitmaskValue]
    composed_value: Dict[str, List[str]]    # the composed bitmask values: NAME -> [part1m, part2,...]
    bind_param: Optional[str] = None        # Bit constants that appear on the same parameter (with names like flags/options/mode/access) will are grouped together.
    strategy: str = "param"

_INT_SUFFIX = re.compile(r'([uU]ll|[uU]l|[uU]LL|[uU]L|[uU])$')   # for C++ types like 0xffU, 0x1ull
# _CAST_PREFIX = re.compile(r'^\s*(?:\([^)]+\)|static_cast<[^>]+>\s*\(|const_cast<[^>]+>\s*\(|reinterpret_cast<[^>]+>\s*\()')   
# _CAST_SUFFIX = re.compile(r'\)\s*$')


_ALLOWED_CHAR = re.compile(r'^[0-9xXa-fA-F_ \t()|&~^<>+\-*/%A-Za-z]+$')
ID_RE = re.compile(r'^[A-Za-z_]\w*(?:::\w+)*$')         #allow the qualified names like NAMESPACE::CONST_NAME

CTYPE_RE = re.compile(
    r'^(?:const\s+|volatile\s+)?'                 # CV 
    r'(?:unsigned\s+|signed\s+)?'                 # sign
    r'(?:short\s+|long\s+long\s+|long\s+)?'       # width
    r'(?:char|int|bool|float|double|size_t|ssize_t|'
    r'u?int\d+|[A-Za-z_]\w*(?:::\w+)*)(?:\s*\*+)?$'  # built-in / user-defined types / pointers
)

def looks_like_bit_expr(s: str) -> bool:
    if not s:
        return False
    
    s = s.strip()
    if not _ALLOWED_CHAR.match(s):
        return False
    
    return bool(re.search(r'(0x[0-9A-Fa-f]+|\d+|<<|>>|\||&|~|\^)', s))

def strip_int_suffix(s: str) -> str:
    return _INT_SUFFIX.sub('', s.strip())

def looks_like_ctype(s: str) -> bool:
    s = s.strip()
    if not s:
        return False
    if re.search(r'[+\-*/%|&^<>\d]', s):
        return False        # likely an calculate expression, not a type

    return bool(CTYPE_RE.match(s))

def strip_casts(expr: str) -> str:
    s = expr.strip()
    if not s:
        return s
    
    cpp_cast = re.compile(
        r'^\s*(?:static_cast|const_cast|reinterpret_cast)\s*<[^>]+>\s*\((.*)\)\s*$'
    )

    m = cpp_cast.match(s)
    if m:
        return m.group(1).strip()
    
    changed = True
    while changed:
        changed = False
        m = re.match(r'^\s*\(([^)]+)\)\s*(.*)\s*$', s)
        if not m:
            break
        head, tail = m.group(1), m.group(2)
        if looks_like_ctype(head):
            s = tail.strip()
            changed = True
        else:
            break
    
    return s

def _bit_width_from_values(int_vals: List[int]) -> Optional[int]:       # infer the bit width from the integer values
    bits = []
    for v in int_vals:
        if v is None or not isinstance(v, int) or v < 0:
            continue
        bits.append(1 if v == 0 else v.bit_length())
    if not bits:
        return None
    m = max(bits)
    return 8 if m <= 8 else 16 if m <= 16 else 32 if m <= 32 else 64

def _group_quality(values: List[Optional[int]]) -> Tuple[float, float]:         #socre the quality of a bitmask group: single bit rate and overlap rate
    ints = [v for v in values if isinstance(v, int)]
    if not ints:
        return 0.0, 1.0
    single = sum(1 for v in ints if v > 0 and (v & (v - 1)) == 0)
    single_rate = single / len(ints)
    seen = 0
    overlapped = 0
    for v in ints:
        if v > 0 and (seen & v) != 0:
            overlapped += 1
        if isinstance(v, int) and v > 0:
            seen |= v
    overlap_rate = overlapped / max(1, len(ints))
    return single_rate, overlap_rate

def _is_single_bit(v: int) -> bool:
    return isinstance(v, int) and v > 0 and (v & (v - 1)) == 0

def _is_bitmasky_expr(s: str) -> bool:
    return bool(re.search(r'(<<|>>|\||&|~|\^)', s or ""))

def _is_probably_bitmask(bv: BitmaskValue) -> bool:
    if _is_bitmasky_expr(bv.value):
        return True
    if isinstance(bv.resolved_value, int) and _is_single_bit(bv.resolved_value):
        return True
    if bv.used_as_bit:
        return True
    return False

class SafeBitEvaluator:
    _tok = re.compile(
        r"""
        (?P<hex>0x[0-9A-Fa-f]+)|
        (?P<dec>\d+)|
        (?P<op>\|\||&&|<<|>>|[|&~^+\-*/%()])|
        (?P<id>[A-Za-z_]\w*(?:::\w+)*)
        """, re.X
    )

    _allowed_ops = {"|", "&", "~", "^", "<<", ">>", "+", "-", "*", "/", "%", "(", ")"}

    def __init__(self, symbol_to_expr: Dict[str, str], max_depth: int = 48):
        self.table = symbol_to_expr
        self.max_depth = max_depth
        self.memo: Dict[str, Optional[int]] = {}

    def evaluate(self, expr: str) -> Optional[int]:
        expr = strip_casts(expr)
        try:
            val, _ = self._eval_inner(expr, seen=set(), depth = 0)
            return val
        except Exception:
            return None

    def _eval_inner(self, expr: str, seen: Set[str], depth: int) -> Tuple[Optional[int], str]:
        if depth > self.max_depth:
            return None, expr
        
        tokens: List[str] = []
        for m in self._tok.finditer(expr):
            if m.lastgroup == "hex":
                tokens.append(str(int(strip_int_suffix(m.group()), 16)))
            elif m.lastgroup == "dec":
                tokens.append(str(int(strip_int_suffix(m.group()), 10)))
            elif m.lastgroup == "op":
                op = m.group()
                if op in ("&&", "||") or op not in self._allowed_ops:
                    return None, expr
                tokens.append(op)
            elif m.lastgroup == "id":
                name = m.group()
                v = self._resolve_ident(name ,seen, depth+1)
                if v is None:
                    tokens.append(name)
                else:
                    tokens.append(str(v))
            else:
                return None, expr
            
        for t in tokens:
            if ID_RE.match(t):
                return None, expr # if there is still unresolved identifier, give up
        
        expr2 = " ".join(tokens)
        try:
            val = eval(expr2, {"__builtins__": None}, {})
            return (int(val) if isinstance(val, int) else None), expr2
        except Exception:
            return None, expr2
        
    def _resolve_ident(self, name: str, seen: Set[str], depth: int) -> Optional[int]:
        if name in self.memo:
            return self.memo[name]
        if name in seen:
            return None
        if name not in self.table:
            return None
        
        seen2 = set(seen); seen2.add(name)
        rhs = self.table[name]
        val, _ = self._eval_inner(rhs, seen2, depth)
        self.memo[name] = val
        return val

class ASTEvidenceCollector:
    BINOPS = {cindex.CursorKind.BINARY_OPERATOR, cindex.CursorKind.COMPOUND_ASSIGNMENT_OPERATOR}
    BIT_TOKENS = {"|", "&", "^", "<<", ">>"}

    def __init__(self):
        self.used_in_bit: Set[str] = set()      # the identifiers that are used in bitwise operations
        self.param_to_symbols: DefaultDict[str, Set[str]] = defaultdict(set)    # parameter name -> set of symbol names used on it
        self.candidates: Dict[str, Tuple[str, str, Optional[str], Optional[int]]] = {}  # name -> (origin, expr, location, bit_width_hint)

    @staticmethod
    def _cursor_loc(cur: cindex.Cursor) -> Optional[str]:
        try:
            loc = cur.location
            if loc and loc.file:
                return f"{loc.file}:{loc.line}:{loc.column}"
        except Exception:
            pass

        return None
    
    @staticmethod
    def _is_bit_operator(tokens: Iterable[cindex.Token]) -> bool:
        ops = {t.spelling for t in tokens}
        return any(op in ops for op in ASTEvidenceCollector.BIT_TOKENS)
    
    @staticmethod
    def _param_key(cur: cindex.Cursor) -> Optional[str]:
        # try to get the "param_key":file:line:function:param_name

        #try to find the closest function/method parent
        p = cur.semantic_parent
        while p and p.kind not in (cindex.CursorKind.FUNCTION_DECL, cindex.CursorKind.CXX_METHOD):
            p = p.semantic_parent
        if not p:
            return None
        
        func_loc = ASTEvidenceCollector._cursor_loc(p) or "<unknown>"

        names = [t.spelling for t in cur.get_tokens() if ID_RE.match(t.spelling)]    # get the parameter name token(like "flags" "options" in function call)

        for nm in names:
            if re.search(r"(flags|options|mode|access|perm|attrs?)$", nm, re.I):  # Give priority to params with obvious bitmask features_name
                return f"{func_loc}:{p.spelling}:{nm}"
        
        return f"{func_loc}:{p.spelling}:{names[0]}" if names else None     # if no obvious param name, use the first identifier as param name
    
    def visit(self, cursor: cindex.Cursor):
        # 1) collect the evidence of identifiers used in bitwise operations
        if cursor.kind in self.BINOPS:
            tokens = list(cursor.get_tokens())
            if self._is_bit_operator(tokens):
                ids = [t.spelling for t in tokens if ID_RE.match(t.spelling)]
                self.used_in_bit.update(ids)
                key = self._param_key(cursor)

                if key and ids:
                    for s in ids:
                        self.param_to_symbols[key].add(s)
        
        if cursor.kind == cindex.CursorKind.ENUM_CONSTANT_DECL:
            name = cursor.spelling
            txt = ''.join(t.spelling for t in cursor.get_tokens())
            rhs: Optional[str] = None
            if "=" in txt:
                rhs = txt.split("=", 1)[1].strip().rstrip(',;').strip()
            
            ival: Optional[str] = None
            try:
                ival = int(cursor.enum_value)
            except Exception:
                pass

            # two conditions to be a bitmask candidate: 1) looks like bit expr; 2) ival is single bit value
            if (rhs and looks_like_bit_expr(rhs)) or (isinstance(ival, int)) and _is_single_bit(ival):
                self.candidates[name] = ("enum", rhs, self._cursor_loc(cursor), None, ival)

        
        # 3) collect ValDecl: static const/constexpr variables
        if cursor.kind == cindex.CursorKind.VAR_DECL:
            try:
                ty = cursor.type.spelling or ""
            except Exception:
                ty = ""
            
            int_like = re.search(r'\b(unsigned|signed|short|long|char|int|size_t|ssize_t|u?int\d+)\b', ty)

            if int_like:
                txt = " ".join(t.spelling for t in cursor.get_tokens())
                if "=" in txt and ("constexpr" in txt or "const" in ty):
                    rhs = txt.split('=', 1)[1].strip().rstrip(';').strip()
                    if looks_like_bit_expr(rhs):
                        self.candidates[cursor.spelling] = ("constexpr", rhs, self._cursor_loc(cursor), None)
        
        #recursively visit children
        for child in cursor.get_children():
            self.visit(child)

def name_to_prefix(name: str) -> str:
    # use the first two uppercase parts as the prefix if possible
    parts = name.split("_")
    if len(parts) >= 2 and all(p.isupper() for p in parts[:2]):
        return "_".join(parts[:2])
    
    if '_' in name:
        return name.rsplit('_', 1)[0]
    
    if '::' in name:
        return name.rsplit('::', 1)[0]
    
    m = re.match(r'^([A-Z]+)[A-Z0-9].*', name)  # A universally applicable classification method
    return m.group(1) if m else name

def _is_upper_snake(s: str) -> bool:    # like THIS_STYLE_CONSTANT
    return bool(re.match(r'^[A-Z]+(?:_[A-Z0-9]+)+$', s))

class BitmaskExtractor:
    def __init__(self, require_bit_operator: bool = False, min_group_size: int = 2):
        self.require_bit_operator = require_bit_operator
        self.min_group_size = min_group_size
    
    def extract_from_tu(self, tu: cindex.TranslationUnit, macros: Dict[str, str]) -> List[BitmaskGroup]:
        #macros : from CCDB.dump_macros()

        evidence_collector = ASTEvidenceCollector()
        evidence_collector.visit(tu.cursor)

        candidates: Dict[str, BitmaskValue] = {}        #this contains macros and enum/const variables

        #1) process macros
        for k, v in macros.items():
            if not v:
                continue

            rhs = strip_casts(v.strip())
            if not looks_like_bit_expr(rhs):
                continue
            if self.require_bit_operator and not re.search(r'(<<|>>|\||&|~|\^)', rhs):
                continue
            candidates[k] = BitmaskValue(
                name=k,
                value=rhs,
                resolved_value=None,
                original="macro",
                declaration_location=None,
                bit_width_hint=None,
                used_as_bit=(k in evidence_collector.used_in_bit)
            )
        
        #2) process enum/const variables collected from AST
        for name, payload in evidence_collector.candidates.items():
            if len(payload) == 5:
                origin, expr, loc, hint, ival = payload
            else:
                origin, expr, loc, hint = payload
                ival = None
            
            # two path to be a bitmask candidate: 1) looks like bit expr; 2) ival is single bit value
            allow_by_expr = bool(expr and (not self.require_bit_operator or re.search(r'(<<|>>|\||&|~|\^)', expr)))
            allow_by_ival = bool(ival is not None and _is_single_bit(ival))
            if not(allow_by_expr or allow_by_ival):
                continue

            if name not in candidates:
                candidates[name] = BitmaskValue(
                    name=name,
                    value=expr,
                    resolved_value=None,
                    original=origin,
                    declaration_location=loc,
                    bit_width_hint=hint,
                    used_as_bit=(name in evidence_collector.used_in_bit)
                )
        
        #3) evaluate the values
        sym_table = {n: bv.value for n, bv in candidates.items()}
        evaluator = SafeBitEvaluator(sym_table)
        for bv in candidates.values():
            if bv.resolved_value is not None:   # if already has resolved value(e.g., from enum constant)
                bv.resolved_value = evaluator.evaluate(bv.value)
        
        # a sample filter for candidates
        filtered: Dict[str, BitmaskValue] = {}
        for n, bv in candidates.items():
            if _is_probably_bitmask(bv):
                filtered[n] = bv
        candidates = filtered

        #4) composites (grouped by "|")
        composites: Dict[str, List[str]] = {}
        bar_split = re.compile(r'(?<!\|)\|(?!\|)')
        for name, bv in candidates.items():
            raw = getattr(bv, "value", None)
            if raw is None:
                continue
            #rhs = bv.value.strip()
            rhs = str(raw).strip()
            if not rhs:
                continue
            while rhs.startswith("(") and rhs.endswith(")"):
                inner = rhs[1:-1].strip()
                # 仅在括号计数匹配时剥一层，避免像 "(A|B))" 这类不匹配时误删
                if inner.count("(") == inner.count(")"):
                    rhs = inner
                else:
                    break

            # if rhs.startswith('(') and rhs.endswith(')'):
            #     rhs_inner = rhs[1:-1].strip()
            #     if rhs_inner.count('(') == rhs_inner.count(')'):
            #         rhs = rhs_inner

            parts = [x.strip() for x in bar_split.split(rhs) if x.strip()]
            ids = [p for p in parts if ID_RE.match(p)]
            if len(ids) >= 2:
                composites[name] = ids
        
        #5)  bind to parameters group in ASTEvidenceCollector
        groups_parameters: List[BitmaskGroup] = []
        for param_key, symbol_names in evidence_collector.param_to_symbols.items():
            #only keep the symbols that are in candidates
            keep = [s for s in symbol_names if s in candidates]
            if len(keep) >= self.min_group_size:
                vals = [candidates[s] for s in keep]
                comp = {n: composites[n] for n in keep if n in composites}
                groups_parameters.append(BitmaskGroup(
                    key=param_key, value=vals, composed_value=comp,
                    bind_param=param_key, strategy="param"
                ))
        
        #6) group by name prefix, complete parts not covered by parameters grouping
        covered: Set[str] = set()
        for g in groups_parameters:
            covered.update(bv.name for bv in g.value)
        
        by_prefix: DefaultDict[str, List[str]] = defaultdict(list)
        for n in candidates.keys():
            if n in covered:
                continue
            pref = name_to_prefix(n)
            by_prefix[pref].append(n)

        groups_prefix: List[BitmaskGroup] = []
        for pref, names in by_prefix.items():
            min_size = 1 if _is_upper_snake(pref) else self.min_group_size      # relaxed size for UPPER_SNAKE_CASE groups
            if len(names) < self.min_group_size:
                continue

            vals = [candidates[s] for s in names]
            comp = {n: composites[n] for n in names if n in composites}

            groups_prefix.append(BitmaskGroup(
                key=pref, value=vals, composed_value=comp,
                bind_param=None, strategy="prefix"
            ))

        #7) Parameter grouping takes precedence, followed by prefix grouping; within each group, sorting can be based on the order of used_as_bit / parsed successfully.
        def sort_key(bv: BitmaskValue):
            single = 0 if (isinstance(bv.resolved_value, int) and _is_single_bit(bv.resolved_value)) else 1
            return (0 if bv.used_as_bit else 1, 
                    0 if bv.resolved_value is not None else 1, 
                    bv.name)
        
        for g in groups_parameters + groups_prefix:
            g.value.sort(key=sort_key)

        for g in groups_parameters + groups_prefix:
            ints = [bv.resolved_value for bv in g.value]
            width = _bit_width_from_values(ints)
            single_rate, overlap_rate = _group_quality(ints)
            for bv in g.value:
                if width is not None:
                    bv.bit_width_hint = width
            
            g._single_rate = single_rate
            g._overlap_rate = overlap_rate
        
        return groups_parameters + groups_prefix

    def groups_to_dict(self, groups: List[BitmaskGroup]) -> List[Dict]:
        out = []
        for g in groups:
            single_rate = getattr(g, '_single_rate', None)
            overlap_rate = getattr(g, '_overlap_rate', None)
            out.append({
                "key": g.key,
                "strategy": g.strategy,
                "bind_param": g.bind_param,
                "value": [asdict(bv) for bv in g.value],
                "composed_value": g.composed_value,
                "quality":{
                    "single_bit_rate": single_rate,
                    "overlap_rate": overlap_rate
                },
                "bit_width_hint": max((bv.bit_width_hint or 0) for bv in g.value) or None
            })
        
        return out

if __name__ == "__main__":
    import json
    from src.static_analyze.ccdb import CCDB
    db = CCDB.from_path("/root/libxml2/bear_build/compile_commands.json")
    bitext = BitmaskExtractor(require_bit_operator=False, min_group_size=1)
    #bitext = BitmaskExtractor(require_bit_operator=True, min_group_size=2)
    idx = cindex.Index.create()

    bitmask_dump: List[Dict] = []

    for tu_meta in db.iter_tus():
        args = db.clang_args_for(tu_meta)
        tu = idx.parse(tu_meta.file, args=args, options=cindex.TranslationUnit.PARSE_DETAILED_PROCESSING_RECORD)

        print(f"Analyzing TU: {tu_meta.file}\n")
        macros = db.macros_dump(tu_meta.language, tu_meta)
        
        out = bitext.extract_from_tu(tu, macros)
        out = bitext.groups_to_dict(out)
        print(f"  Found {len(out)} bitmask groups.\n")
        print(out)
        print(json.dumps(out, indent=2, ensure_ascii=False))

        bitmask_dump.extend(out)
    
    print("the final bitmask dump:\n")
    print(json.dumps(bitmask_dump, indent=2, ensure_ascii=False))