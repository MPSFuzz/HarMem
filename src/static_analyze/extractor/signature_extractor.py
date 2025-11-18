import os
from dataclasses import dataclass, asdict
from typing import List, Dict, Any, Optional, Iterable, Tuple, Set
from clang import cindex
from src.utils.static_analyze_clang_args import enrich_clang_args_for_analysis
from src.utils.libclang_load import load_libclang
from src.utils.utils import get_logger

#load_libclang()
cindex.Config.set_library_file('/opt/llvm21/lib/libclang.so.21.1.0')  # Adjust path as necessary

logger = get_logger(__name__)

SYSHEADERS_PREFIXES = { "/usr/", "/lib/", "/Library/", "/opt/" }

@dataclass
class FunctionParam:
    name: str
    type: str

@dataclass
class FunctionSignature:
    usr: str            # a unique identifier for the function
    name: str
    qualified_name: str
    return_type: str
    parameters: List[FunctionParam]
    is_variadic: bool
    is_method: bool
    is_constructor: bool
    is_destructor: bool
    is_inline: bool
    location: str       # "path:line:column"
    file: str           # source file path
    parent: Optional[str]  # owning class/namespace, or empty if none

def _in_main_file(cursor: cindex.Cursor) -> bool:
    #check if the cursor is in the main file

    try:
        f = cursor.location.file
        if not f :
            logger.warning("Cursor location file is None")
            return False
        return cursor.translation_unit.spelling == str(f)
    
    except Exception as e:
        logger.error(f"Error accessing cursor location file: {e}")
        return False

def _cursor_location(cursor: cindex.Cursor) -> Tuple[str, int, int]:
    # get the location of the cursor as (file path, line, column), if not avalibale(like macroes), return ("<inavailable>", 0, 0)
    loc = cursor.location
    if loc and loc.file:
        return (str(loc.file), loc.line, loc.column)
    else:
        return ("<inavailable>", 0, 0)

def _join_qualname(scopes: List[str], name: str) -> str:
    scopes = [s for s in scopes if s]
    return "::".join(scopes + [name]) if name else "::".join(scopes)

def _safe_is_inline(cursor: cindex.Cursor) -> bool:
    try:
        if cursor.kind == cindex.CursorKind.CXX_METHOD:
            fn = getattr(cursor, "is_inline_method", None)
            if callable(fn):
                return bool(fn())
    except:
        pass

    for name in ("is_function_inlined", "is_inline_method"):
        fn = getattr(cursor, name, None)
        if callable(fn):
            try:
                return bool(fn())
            except:
                pass
    try:
        it = cursor.get_tokens()
        for i, t in zip(range(12), it):
            if t.spelling == "inline":
                return True
    except:
        pass

    return False

def _safe_is_variadic(cursor: cindex.Cursor) -> bool:
    try:
        t = getattr(cursor.type, "type", None)
        if t is None:
            return False
        fn = getattr(t, "is_function_variadic", None)
        if callable(fn):
            return bool(fn())
    except Exception:
        pass
    
    return False
    
class SignatureExtractor:
    """
    get function/method from TU. there are two key args: -include_headers and -system_includes
    -include_headers: whether to recursively record functions decalaration/inline defintion from included headers (default: False)
    -system_includes: whether to include system headers(like /usr/include/) (default: False)
    """
    def __init__(
            self,
            clang_args: Optional[List[str]] = None,
            include_headers: bool = False,
            system_includes: bool = False
    ):
        self.clang_args = clang_args or []
        self.include_headers = include_headers
        self.system_includes = system_includes
        self.index = cindex.Index.create()
    
    def build_TU(self, file_path: str) -> Optional[cindex.TranslationUnit]:
        #idx = cindex.Index.create() # an abstract representation of TU
        try:
            tu = self.index.parse(
                file_path,
                args=self.clang_args,
                options=(
                    cindex.TranslationUnit.PARSE_DETAILED_PROCESSING_RECORD
                    | cindex.TranslationUnit.PARSE_INCOMPLETE
                    | cindex.TranslationUnit.PARSE_PRECOMPILED_PREAMBLE
                    | cindex.TranslationUnit.PARSE_SKIP_FUNCTION_BODIES
                )
            )
            for d in tu.diagnostics:
                if d.severity >= cindex.Diagnostic.Warning:
                    logger.debug(f"Clang Diagnostic: {d.severity} - {d.spelling} at {d.location}")
                    pass
            
            return tu
        
        except Exception as e:
            logger.error(f"Error parsing file {file_path}: {e}")
            return None
    
    def _build_signature(self, cursor: cindex.Cursor, scopes_stack: List[str]) -> Optional[FunctionSignature]:
        try:
            usr = cursor.get_usr() or ""
            name = cursor.spelling or ""
            qualified_name = _join_qualname(scopes_stack, name)
            if cursor.kind in (cindex.CursorKind.CONSTRUCTOR, cindex.CursorKind.DESTRUCTOR): # no return type for constructor/destructor
                return_type = ""
            else:
                return_type = cursor.result_type.spelling or ""
            
            #paramters:
            parameters: List[FunctionParam] = []
            for arg in cursor.get_arguments() or []:
                parameters.append(FunctionParam(
                    name = arg.spelling or "",
                    type = arg.type.spelling if arg.type else ""
                ))
            
            is_variadic = _safe_is_variadic(cursor)
            is_method = cursor.kind == cindex.CursorKind.CXX_METHOD
            is_constructor = cursor.kind == cindex.CursorKind.CONSTRUCTOR
            is_destructor = cursor.kind == cindex.CursorKind.DESTRUCTOR
            is_inline = _safe_is_inline(cursor)

            loc_file, line, column = _cursor_location(cursor)
            location = f"{loc_file}:{line}:{column}"

            parent = "::".join(scopes_stack) if scopes_stack else None

            return FunctionSignature(
                usr=usr,
                name=name,
                qualified_name=qualified_name,
                return_type=return_type,
                parameters=parameters,
                is_variadic=is_variadic,
                is_method=is_method,
                is_constructor=is_constructor,
                is_destructor=is_destructor,
                is_inline=is_inline,
                location=location,
                file=loc_file,
                parent=parent
            )

        except Exception as e:
            logger.error(f"Error getting USR for cursor {cursor.spelling}: {e}")
            return None
        
    def extract_from_file(self, file_path: str) -> List[Dict]:
        tu = self.build_TU(file_path)
        if not tu:
            return []
        sigs = self.extract_from_tu(tu)

        return [asdict(s) for s in sigs]        

    def extract_from_tu(self, tu: cindex.TranslationUnit) -> List[FunctionSignature]:
        # recursively traverse the AST to extract function/method signatures. Using USR to depulicate functions

        signatures: List[FunctionSignature] = []
        seen_usr: Set[str] = set()

        scopes_stack: List[str] = [] # a stack to keep track of the current scopes (namespaces/classes)

        def should_keep(cursor: cindex.Cursor) -> bool:
            # this is a filter function to decide whether to keep the cursor

            loc_file, _, _ = _cursor_location(cursor)
            if loc_file == "<inavailable>":
                return False
            
            if not self.include_headers: # only the main file
                return _in_main_file(cursor)
            
            if self.include_headers and not self.system_includes: # only include non-system headers
                if any(loc_file.startswith(prefix) for prefix in SYSHEADERS_PREFIXES):
                    return False
            
            return True
        
        def get_signatures(cursor: cindex.Cursor):
            kind = cursor.kind

            # get into the new scope
            if kind in (
                cindex.CursorKind.NAMESPACE,
                cindex.CursorKind.STRUCT_DECL,
                cindex.CursorKind.CLASS_DECL,
                cindex.CursorKind.CLASS_TEMPLATE,
            ):
                scopes_stack.append(cursor.spelling or "")
                for child in cursor.get_children():
                    get_signatures(child)
                scopes_stack.pop()
                return
            
            # extract target : function/method/constructor/destructor
            if kind in (
                cindex.CursorKind.FUNCTION_DECL,
                cindex.CursorKind.CXX_METHOD,
                cindex.CursorKind.CONSTRUCTOR,
                cindex.CursorKind.DESTRUCTOR
            ):
                if should_keep(cursor):
                    sig = self._build_signature(cursor, scopes_stack)
                    if sig and sig.usr not in seen_usr:
                        seen_usr.add(sig.usr)
                        signatures.append(sig)
            
            for child in cursor.get_children():
                get_signatures(child)

        get_signatures(tu.cursor)
        return signatures

if __name__ == "__main__":
    from ..ccdb import CCDB
    db = CCDB.from_path("/root/libxml2/bear_build/compile_commands.json")
    for tu in db.iter_tus():
        args = db.clang_args_for(tu)
        
        args = enrich_clang_args_for_analysis(args=args, compiler=tu.compiler, force_resource_dir="/opt/llvm21/lib/clang/21")
        print("[ANALYZE ARGS]", " ".join(args))

        extractor = SignatureExtractor(clang_args=args, include_headers=False, system_includes=False)
        sigs = extractor.extract_from_file(tu.file)
        print(f"File: {tu.file}, Functions found: {len(sigs)}\n")
        print("the signatures information:\n")
        print(sigs)
