# src/static_analyze/extractor/impl_extractor_fast.py
from __future__ import annotations
import os
import textwrap
import hashlib
from typing import Dict, List, Optional, Tuple
from clang import cindex

cindex.Config.set_library_file('/opt/llvm21/lib/libclang.so.21.1.0')

def _safe_read_text(path: str) -> Tuple[str, List[int]]:
    with open(path, "rb") as f:
        b = f.read()
    try:
        s = b.decode("utf-8")
    except UnicodeDecodeError:
        s = b.decode("latin-1", errors="replace")
    offs = [0]
    for i, ch in enumerate(s):
        if ch == "\n":
            offs.append(i + 1)
    return s, offs

def _slice_by_extent(src: str, line_offsets: List[int],
                     start_line: int, start_col: int,
                     end_line: int, end_col: int) -> str:
    start_off = line_offsets[start_line - 1] + max(0, start_col - 1)
    end_base = line_offsets[end_line - 1]
    end_off = end_base + max(0, end_col - 1)
    return src[start_off:end_off]

def _dedent_preserve_first_line(code: str) -> str:
    if not code:
        return code
    lines = code.splitlines(True)
    head = lines[:1]
    tail = lines[1:]
    return "".join(head + [textwrap.dedent("".join(tail))])

def _grab_leading_comments(src: str, line_offsets: List[int],
                           start_line: int, max_lines: int = 30) -> str:
    if start_line <= 1:
        return ""
    lines = src.splitlines()
    i = start_line - 2
    taken = 0
    out: List[str] = []
    in_block = False
    while i >= 0 and taken < max_lines:
        ln = lines[i].rstrip("\n")
        stripped = ln.strip()
        if in_block:
            out.append(ln)
            if "/*" in stripped:
                in_block = False
            i -= 1; taken += 1
            continue
        if stripped == "" or stripped.startswith("//"):
            out.append(ln)
            i -= 1; taken += 1
            continue
        if "*/" in stripped:
            out.append(ln)
            in_block = True
            i -= 1; taken += 1
            continue
        break
    out.reverse()
    return "\n".join(out).rstrip()

def _parse_location_str(loc: str) -> Tuple[int, int]:
    """
    将 '/path/file.c:LINE:COL' 的 'LINE:COL' 部分解析为 (line, col)。
    允许 loc 为空或不规范，此时返回 (1,1)。
    """
    if not loc:
        return (1, 1)
    try:
        parts = loc.split(":")
        line = int(parts[-2]); col = int(parts[-1])
        return (max(1, line), max(1, col))
    except Exception:
        return (1, 1)

def _ascend_to_function(cur: cindex.Cursor) -> Optional[cindex.Cursor]:
    if not cur or cur.kind is cindex.CursorKind.NO_DECL_FOUND:
        return None
    kinds = (
        cindex.CursorKind.FUNCTION_DECL,
        cindex.CursorKind.CXX_METHOD,
        cindex.CursorKind.FUNCTION_TEMPLATE,
    )
    node = cur
    visited = 0
    # 优先尝试 current→definition
    if node.kind in kinds:
        if node.is_definition():
            return node
        d = node.get_definition()
        if d and d.kind in kinds and d.is_definition():
            return d
    while node and visited < 64:
        if node.kind in kinds and node.is_definition():
            return node

        par = getattr(node, "semantic_parent", None) or getattr(node, "lexical_parent", None)
        if not par or par == node:
            break
        node = par
        visited += 1

    if cur.kind in kinds:
        d = cur.get_definition()
        if d and d.kind in kinds and d.is_definition():
            return d
    return None

class ImplementationExtractor:
    def __init__(self,
                 ccdb,
                 enrich_args_fn,  # 传入你的 enrich_clang_args_for_analysis
                 include_headers: bool = False,
                 with_leading_comment: bool = True,
                 dedent: bool = True,
                 context_lines: int = 0) -> None:
        self.ccdb = ccdb
        self.enrich_args_fn = enrich_args_fn
        self.include_headers = include_headers
        self.with_leading_comment = with_leading_comment
        self.dedent = dedent
        self.context_lines = max(0, int(context_lines))
        self._idx = cindex.Index.create()
        self._tu_cache: Dict[str, cindex.TranslationUnit] = {}  # file -> TU

    def _get_tu_for_file(self, tu_meta) -> cindex.TranslationUnit:
        fpath = tu_meta.file
        if fpath in self._tu_cache:
            return self._tu_cache[fpath]
        args = self.ccdb.clang_args_for(tu_meta)
        args = self.enrich_args_fn(args, compiler=tu_meta.compiler)
        tu = self._idx.parse(
            fpath,
            args=args,
            options=cindex.TranslationUnit.PARSE_DETAILED_PROCESSING_RECORD
        )
        self._tu_cache[fpath] = tu
        return tu

    def extract_for_plan_nodes(self, plan: Dict) -> Dict:
        # 1) 收集按文件聚合的目标 (line,col)
        wants_by_file: Dict[str, List[Tuple[str, Tuple[int, int]]]] = {}
        for n in plan.get("chain", {}).get("nodes", []):
            fp = n.get("file"); loc = n.get("location"); name = n.get("name")
            if not fp or not name:
                continue
            line_col = _parse_location_str(loc)
            wants_by_file.setdefault(fp, []).append((name, line_col))

        # 2) 为每个涉及文件构造 TU（只一次），并逐个按坐标定位函数
        tu_meta_by_file = {tu.file: tu for tu in self.ccdb.iter_tus() if tu.file in wants_by_file}
        for fpath, reqs in wants_by_file.items():
            tu_meta = tu_meta_by_file.get(fpath)
            if not tu_meta:
                # 若不在 ccdb 里，跳过
                continue
            tu = self._get_tu_for_file(tu_meta)
            code_text, line_offsets = _safe_read_text(fpath)
            cfile = cindex.File.from_name(tu, fpath)

            # 为避免重复 I/O，先构建 name->(line,col) map
            for (name, (line, col)) in reqs:
                try:
                    loc = cindex.SourceLocation.from_position(tu, cfile, line, col)
                    cur = cindex.Cursor.from_location(tu, loc)
                    fcur = _ascend_to_function(cur)
                    if not fcur or not fcur.is_definition():
                        # 再试一次：有些位置可能落在注释/空白，向后偏移少量列
                        loc2 = cindex.SourceLocation.from_position(tu, cfile, line, max(1, col + 1))
                        cur2 = cindex.Cursor.from_location(tu, loc2)
                        fcur = _ascend_to_function(cur2)
                    if not fcur or not fcur.is_definition():
                        continue  # 找不到就跳过（不做正则回退）

                    extent = fcur.extent
                    sline, scol = extent.start.line, extent.start.column
                    eline, ecol = extent.end.line, extent.end.column

                    sc = getattr(fcur, "storage_class", None)
                    storage: Optional[str] = None
                    if sc is not None and sc != cindex.StorageClass.INVALID:
                        storage = sc.name.lower()

                    # 扩展上下文行再切片
                    sl_for_slice = max(1, sline - self.context_lines)
                    el_for_slice = min(len(line_offsets), eline + self.context_lines)
                    block = _slice_by_extent(
                        code_text, line_offsets,
                        start_line=sl_for_slice,
                        start_col=1 if sl_for_slice < sline else scol,
                        end_line=el_for_slice,
                        end_col=ecol if el_for_slice == eline else 1_000_000
                    )
                    lead = _grab_leading_comments(code_text, line_offsets, sline) if self.with_leading_comment else ""
                    if self.dedent:
                        block = _dedent_preserve_first_line(block)
                        if lead:
                            lead = textwrap.dedent(lead)

                    # 回填到 plan
                    for n in plan["chain"]["nodes"]:
                        if n.get("file") == fpath and n.get("name") == name:
                            n["impl"] = {
                                "usr": fcur.get_usr() or "",
                                "name": name,
                                "file": fpath,
                                "start": {"line": sline, "col": scol},
                                "end": {"line": eline, "col": ecol},
                                "leading_comment": lead,
                                "code": block,
                                "storage_class": storage
                            }
                            # 根据storage_class转换external节点为internal
                            if storage == "static":
                                n["visibility"] = "internal"
                            elif "visibility" not in n:
                                n["visibility"] = "external"
                            break
                except Exception:
                    continue

        return plan


    if __name__ == "__main__":
        import json
        with open("/root/auto_harness/src/temp/xmlNodeGetContent_plans.json", "r", encoding="utf-8") as f:
            plan = json.load(f)
        
        from src.static_analyze.ccdb import CCDB
        from src.utils.static_analyze_clang_args import enrich_clang_args_for_analysis
        from src.static_analyze.extractor.sourcecode_extractor import ImplementationExtractor

        db = CCDB.from_path("/root/libxml2/bear_build/compile_commands.json")
        
        extractor = ImplementationExtractor(
            ccdb=db,
            enrich_args_fn=enrich_clang_args_for_analysis,
            include_headers=False,
            with_leading_comment=True,
            dedent=True,
            context_lines=0
        )

        new_plan = extractor.extract_for_plan_nodes(plan)
