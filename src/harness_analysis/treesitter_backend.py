from __future__ import annotations

from typing import Any, Dict, List, Optional

import tree_sitter  # type: ignore
import tree_sitter_c  # type: ignore

from .backend_base import HarnessAnalysisBackend


class TreeSitterCBackend(HarnessAnalysisBackend):
    backend_name = "tree-sitter-c"

    def __init__(self) -> None:
        self._lang = tree_sitter.Language(tree_sitter_c.language())
        self._parser = tree_sitter.Parser(self._lang)

    def parse_code(self, code: str) -> Any:
        return self._parser.parse(code.encode("utf-8", errors="ignore"))

    def extract_raw(self, code: str) -> Dict[str, Any]:
        tree = self.parse_code(code)
        root = tree.root_node

        raw: Dict[str, Any] = {
            "parser_has_error": bool(root.has_error),
            "function_defs": [],
            "calls": [],
            "assignments": [],
            "identifiers": [],
            "loops": [],
            "ifs": [],
            "string_literals": [],
        }

        def text(node) -> str:
            return code[node.start_byte:node.end_byte]

        def collect_identifiers(node) -> List[str]:
            if node is None:
                return []
            out: List[str] = []
            stack = [node]
            while stack:
                cur = stack.pop()
                if cur.type == "identifier":
                    out.append(text(cur))
                stack.extend(reversed(cur.named_children))
            return out

        def first_named_child_of_type(node, typ: str):
            for c in node.named_children:
                if c.type == typ:
                    return c
            return None

        def walk(node, in_loop: bool = False):
            ntype = node.type

            if ntype == "function_definition":
                declarator = first_named_child_of_type(node, "function_declarator")
                fname = None
                if declarator is not None:
                    ids = collect_identifiers(declarator)
                    if ids:
                        fname = ids[0]
                raw["function_defs"].append({
                    "name": fname,
                    "start_line": node.start_point[0] + 1,
                    "end_line": node.end_point[0] + 1,
                })

            elif ntype in ("while_statement", "for_statement", "do_statement"):
                raw["loops"].append({
                    "type": ntype,
                    "start_line": node.start_point[0] + 1,
                    "end_line": node.end_point[0] + 1,
                })
                for c in node.named_children:
                    walk(c, in_loop=True)
                return

            elif ntype == "if_statement":
                raw["ifs"].append({
                    "start_line": node.start_point[0] + 1,
                    "end_line": node.end_point[0] + 1,
                    "text": text(node),
                    "in_loop": in_loop,
                })

            elif ntype == "call_expression":
                callee = None
                callee_node = node.child_by_field_name("function")
                if callee_node is not None:
                    callee = text(callee_node).strip()

                arg_node = node.child_by_field_name("arguments")
                args = collect_identifiers(arg_node)

                raw["calls"].append({
                    "callee": callee,
                    "args": args,
                    "line": node.start_point[0] + 1,
                    "in_loop": in_loop,
                    "text": text(node),
                })

            elif ntype == "assignment_expression":
                lhs = node.child_by_field_name("left")
                rhs = node.child_by_field_name("right")
                raw["assignments"].append({
                    "lhs_text": text(lhs).strip() if lhs else None,
                    "rhs_text": text(rhs).strip() if rhs else None,
                    "rhs_identifiers": collect_identifiers(rhs),
                    "line": node.start_point[0] + 1,
                    "in_loop": in_loop,
                })

            elif ntype == "init_declarator":
                decl = node.child_by_field_name("declarator")
                val = node.child_by_field_name("value")
                raw["assignments"].append({
                    "lhs_text": text(decl).strip() if decl else None,
                    "rhs_text": text(val).strip() if val else None,
                    "rhs_identifiers": collect_identifiers(val),
                    "line": node.start_point[0] + 1,
                    "in_loop": in_loop,
                })

            elif ntype == "identifier":
                raw["identifiers"].append({
                    "name": text(node),
                    "line": node.start_point[0] + 1,
                })

            elif ntype == "string_literal":
                raw["string_literals"].append({
                    "text": text(node),
                    "line": node.start_point[0] + 1,
                })

            for c in node.named_children:
                walk(c, in_loop=in_loop)

        walk(root, in_loop=False)
        return raw