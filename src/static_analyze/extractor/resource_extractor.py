import re
from dataclasses import dataclass, asdict
from typing import List, Dict, Any, Optional, Iterable, Tuple, Set
from clang import cindex
from src.utils.libclang_load import load_libclang

#load_libclang()
cindex.Config.set_library_file('/opt/llvm21/lib/libclang.so.21.1.0')  # Adjust path as necessary


@dataclass
class ResourceOp:
    kind: str           # "alloc" | "free" | "transfer" | "unknown"
    func: str           # function name
    location: str       # "path:line:column"
    func_context: Optional[str] # owning function name
    file: Optional[str]  # source file path
    tags: List[str]      # source type tag e.g., ["malloc", "new", "custom-alloc"]
    related: Optional[str] = None # related resource operation (e.g., for free, the alloc it frees)
    ids: Optional[List[str]] = None  # identifiers involved in the operation


class ResourceExtractor:
    DEFAULT_ALLOC_HINTS = [
        "alloc", "malloc", "calloc", "new", "create", "open",
        "init", "acquire", "generate", "dup", "start"
    ]

    DEFAULT_FREE_HINTS = [
        "free", "delete", "destroy", "close", "release",
        "cleanup", "unref", "stop"
    ]

    BASE_TYPE_HINTS = {
        "memory": ("alloc", "free"),
        "file": ("open", "close"),
        "network": ("connect", "close"),
        "object": ("create", "destroy"),
        "reference": ("incref", "decref"),
    }

    IGNORE_PREFIXES = [
        "str", "mem", "fprintf", "printf", "scanf", "put", "get",
        "exit", "abort", "assert", "va_", "set", "clock", "time",
        "fopen", "fclose", "fread", "fwrite", "fseek", "ftell",
        "rewind", "fflush", "perror", "sprintf", "snprintf"
    ]

    # ID_CHAIN_RE = re.compile(
    # r'[A-Za-z_]\w*'                       # base identifier
    # r'(?:'                               
    #     r'(?:(?:\:\:)[A-Za-z_]\w*)|'      # ::qualifier (C++ namespace/class)
    #     r'(?:->)[A-Za-z_]\w*|'            # ->member
    #     r'(?:\.)[A-Za-z_]\w*'             # .member
    # r')*'                                 
    # )
    ID_CHAIN_RE = re.compile(r'[A-Za-z_]\w*(?:::\w+)*(?:->\w+|\.\w+)*')

    FUNC_CALL_RE = re.compile(r'^\s*([A-Za-z_]\w*(?:::\w+)*)\s*\(')

    def __init__(self, alloc_hints: Optional[List[str]] = None,
                 free_hints: Optional[List[str]] = None,
                 extra_type_hints: Optional[Dict[str, Tuple[str, str]]] = None
                 ):
        
        # extra_type is an interface for users to add more resource types
        self.alloc_hints = alloc_hints or self.DEFAULT_ALLOC_HINTS
        self.free_hints = free_hints or self.DEFAULT_FREE_HINTS
        self.type_hints = dict(self.BASE_TYPE_HINTS)
        if extra_type_hints:
            self.type_hints.update(extra_type_hints)
    
    def _owning_function_name(self, cur: cindex.Cursor) -> Optional[str]:
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

            p = p.lexical_parent or p.semantic_parent
        return "__runtime__"
    
    def _should_ignore(self, name: str) -> bool:
        lname = name.lower()
        return any(lname.startswith(pref) for pref in self.IGNORE_PREFIXES)
    
    def _classify_call(self, name: str) -> Tuple[str, List[str], Optional[str]]:
        # classify the function call based on its name
        lname = name.lower()
        kind = "unknown"
        tags = []
        related = None

        # key-word matching
        if any(ptn in lname for ptn in self.alloc_hints):
            kind = "alloc"
        elif any(ptn in lname for ptn in self.free_hints):
            kind = "free"
        
        # type-based matching
        for tname, (alloc_pref, free_pref) in self.type_hints.items():
            if alloc_pref.lower() in lname:
                tags.append(tname)
                related = free_pref
            elif free_pref.lower() in lname:
                tags.append(tname)
                related = alloc_pref
        
        if not tags:
            tags.append("generic")
        
        return kind, tags, related
    
    # def _collect_call_ids(self, cur: cindex.Cursor) -> List[str]:
    #     # extract function/variable identifiers from the call text
    #     try:
    #         toks = [t.spelling for t in cur.get_tokens() if t.spelling]
    #         expr = "".join(toks)

    #         mfn = self.FUNC_CALL_RE.match(expr)
    #         fn_name = mfn.group(1) if mfn else None

    #         raw_ids = self.ID_CHAIN_RE.findall(expr)

    #         filt = []
    #         KEYWORDS = {
    #             'if','else','for','while','return','switch','case','break','continue',
    #             'sizeof','typedef','struct','union','enum','goto','do','static','const',
    #             'volatile','inline','register','auto','extern'
    #         }

    #         for ident in raw_ids:
    #             if not ident:
    #                 continue
    #             low = ident.lower()
    #             if low in KEYWORDS:
    #                 continue
    #             if re.fullmatch(r'\d+', ident):     # pure number
    #                 continue
    #             if fn_name and ident == fn_name:   # function name itself
    #                 continue
    #             filt.append(ident)

    #         seen = set()
    #         uniq = []
            
    #         for x in filt:
    #             if x not in seen:
    #                 seen.add(x)
    #                 uniq.append(x)
            
    #         return uniq
    #     except Exception:
    #         return []
    def _collect_call_ids(self, call_cur: cindex.Cursor, callee_name: str) -> List[str]:
        ids: Set[str] = set()
        def walk(n: cindex.Cursor):
            try:
                if n.kind in (cindex.CursorKind.DECL_REF_EXPR, cindex.CursorKind.MEMBER_REF_EXPR):
                    sp = (n.spelling or "").strip()
                    if sp and sp != callee_name:
                        ids.add(sp)
            except Exception:
                pass

            for c in n.get_children():
                walk(c)

        walk(call_cur)
        
        return list(ids)            
    
    def _cursor_location(self, cur: cindex.Cursor) -> str:
        loc = cur.location

        if loc and loc.file:
            return f"{loc.file.name}:{loc.line}:{loc.column}"
        
        return "unknown"
    
    def _function_label(self, cur:cindex.Cursor) -> str:
        # process fucntion name, handle anonymous \ lambda functions
        name = (cur.spelling or "").strip()
        if name:
            return name
        
        loc = self._cursor_location(cur)
        return f"__anon@{loc}"
    
    def extract_from_tu(self, tu:cindex.TranslationUnit) -> List[ResourceOp]:
        seen: Set[str] = set()
        results: List[ResourceOp] = []

        FUNC_LIKE_KIND = {
            cindex.CursorKind.FUNCTION_DECL,
            cindex.CursorKind.CXX_METHOD,
            cindex.CursorKind.CONSTRUCTOR,
            cindex.CursorKind.DESTRUCTOR,
            getattr(cindex.CursorKind, "FUNCTION_TEMPLATE", None),
            getattr(cindex.CursorKind, "LAMBDA_EXPR", None),
        }
        FUNC_LIKE_KINDS = {k for k in FUNC_LIKE_KIND if k is not None}

        def visit(cur: cindex.Cursor, func_ctx: Optional[str]):
            # update function context when entering function visit
            if cur.kind in FUNC_LIKE_KINDS:
                func_ctx = self._function_label(cur)

            if cur.kind == cindex.CursorKind.CALL_EXPR:
                name = cur.spelling or (cur.displayname or "")
                if not name:
                    for ch in cur.get_children():
                        if ch.kind == cindex.CursorKind.DECL_REF_EXPR:
                            name = ch.spelling or name
                            if name:
                                break
                
                if name and not self._should_ignore(name):
                    kind, tags, related = self._classify_call(name)
                    loc = self._cursor_location(cur)
                    file_path = str(cur.location.file) if cur.location and cur.location.file else None
                    # func_context = self._owning_function_name(cur)
                    ids = self._collect_call_ids(cur, name)

                    op = ResourceOp(
                        kind=kind,
                        func=name,
                        location=loc,
                        file=file_path,
                        func_context=func_ctx or "__global__",
                        tags=tags,
                        related=related,
                        ids=ids
                    )

                    key = (op.func or "", op.func_context or "", op.location or "")
                    if key not in seen:
                        seen.add(key)
                        results.append(op)
            
            for c in cur.get_children():
                visit(c, func_ctx)
        
        visit(tu.cursor, func_ctx=None)
        return results

if __name__ == "__main__":
    import json
    from src.static_analyze.extractor.bitmask_extractor import BitmaskExtractor
    from src.static_analyze.ccdb import CCDB

    db = CCDB.from_path("/root/libxml2/bear_build/compile_commands.json")
    idx = cindex.Index.create()

    extra_rules = {
        "xml": ("xmlNew", "xmlFree"),
        "ssl": ("SSL_new", "SSL_free"),
        "json": ("json_object_new", "json_object_put")
    }

    extractor = ResourceExtractor(extra_type_hints=extra_rules)

    for tu_meta in db.iter_tus():
        args = db.clang_args_for(tu_meta)
        tu = idx.parse(tu_meta.file, args=args, options=cindex.TranslationUnit.PARSE_DETAILED_PROCESSING_RECORD)
        
        print(f"Analyzing TU: {tu_meta.file}\n")

        ops = extractor.extract_from_tu(tu)

        print(f"  Found {len(ops)} resource-related operations.")
        for op in ops[:10]:
            print(op)