from __future__ import annotations

from typing import Any, Dict, List, Set

from .facts import HarnessFacts, TargetCallFact


def _count_identifier_occurs(name: str, raw: Dict[str, Any]) -> int:
    cnt = 0
    for item in raw.get("identifiers", []):
        if item.get("name") == name:
            cnt += 1
    return cnt


def _extract_constructed_vars(raw: Dict[str, Any]) -> List[str]:
    """
    Constructed vars are variables whose values come from call results or clear build steps.
    We do NOT rely on specific library type names.
    """
    out: Set[str] = set()
    for a in raw.get("assignments", []):
        lhs = a.get("lhs_text")
        rhs = a.get("rhs_text") or ""
        if lhs and "(" in rhs:
            out.add(lhs)
    return sorted(out)


def _extract_input_source_vars(raw: Dict[str, Any]) -> List[str]:
    """
    We still need some notion of input roots, but keep it generic:
    argv / read / fread / recv / getline style entrypoints.
    These are generic IO entrypoints rather than library-specific hints.
    """
    source_vars: Set[str] = set()

    for a in raw.get("assignments", []):
        lhs = a.get("lhs_text")
        rhs_ids = set(a.get("rhs_identifiers", []) or [])
        rhs_text = a.get("rhs_text") or ""
        if not lhs:
            continue

        if "argv" in rhs_ids:
            source_vars.add(lhs)

        if any(tok in rhs_text for tok in ("fread", "read(", "recv(", "getline(", "getdelim(")):
            source_vars.add(lhs)

    for c in raw.get("calls", []):
        callee = (c.get("callee") or "").strip()
        args = c.get("args", []) or []
        if callee in {"fread", "read", "recv", "getline", "getdelim"}:
            for arg in args:
                source_vars.add(arg)

    return sorted(source_vars)


def _propagate_input_dependence(raw: Dict[str, Any], seed_vars: List[str], max_steps: int = 3) -> List[str]:
    dep = set(seed_vars)
    assigns = raw.get("assignments", []) or []

    for _ in range(max_steps):
        changed = False
        for a in assigns:
            lhs = a.get("lhs_text")
            rhs_ids = set(a.get("rhs_identifiers", []) or [])
            if lhs and (rhs_ids & dep) and lhs not in dep:
                dep.add(lhs)
                changed = True
        if not changed:
            break

    return sorted(dep)


def _infer_target_calls(raw: Dict[str, Any], target_api: str) -> List[TargetCallFact]:
    facts: List[TargetCallFact] = []
    if not target_api:
        return facts

    for c in raw.get("calls", []):
        callee = c.get("callee")
        if callee == target_api or (callee and callee.endswith(target_api)):
            facts.append(
                TargetCallFact(
                    name=callee,
                    line=c.get("line"),
                    args=c.get("args", []) or [],
                )
            )
    return facts


def normalize_raw_to_facts(raw: Dict[str, Any], target_api: str) -> HarnessFacts:
    facts = HarnessFacts()
    facts.backend = raw.get("backend", "unknown")
    facts.parser_has_error = bool(raw.get("parser_has_error", False))

    fdefs = raw.get("function_defs", []) or []
    facts.has_main = any((x.get("name") == "main") for x in fdefs)

    facts.loop_count = len(raw.get("loops", []) or [])
    facts.has_persistent_loop = facts.loop_count > 0

    facts.constructed_vars = _extract_constructed_vars(raw)
    facts.active_constructed_vars = [
        v for v in facts.constructed_vars if _count_identifier_occurs(v, raw) >= 2
    ]

    facts.input_source_vars = _extract_input_source_vars(raw)
    facts.has_file_input = bool(facts.input_source_vars) or any(
        c.get("callee") in {"fopen", "fread", "read", "recv", "getline", "getdelim"}
        for c in raw.get("calls", [])
    )

    facts.input_dependent_vars = _propagate_input_dependence(
        raw,
        facts.input_source_vars,
        max_steps=3,
    )

    facts.target_calls = _infer_target_calls(raw, target_api=target_api)
    facts.target_call_inside_loop = any(tc.in_loop for tc in facts.target_calls)

    target_args = []
    for tc in facts.target_calls:
        target_args.extend(tc.args)
    target_arg_set = set(target_args)

    facts.target_args_from_constructed_signal = bool(target_arg_set & set(facts.active_constructed_vars))
    facts.target_args_from_input_signal = bool(target_arg_set & set(facts.input_dependent_vars))

    facts.pre_target_call_count = len(raw.get("calls", []) or [])
    facts.pre_target_assignment_count = len(raw.get("assignments", []) or [])
    facts.pre_target_guard_count = len(raw.get("ifs", []) or [])

    facts.fallback_branch_count = len(raw.get("ifs", []) or [])

    long_strings = 0
    for s in raw.get("string_literals", []):
        txt = s.get("text") or ""
        if len(txt) >= 24:
            long_strings += 1
    facts.constant_template_count = long_strings

    facts.role_separation_signal = len(facts.active_constructed_vars) >= 2
    facts.target_data_dependency_signal = (
        facts.target_args_from_constructed_signal or facts.target_args_from_input_signal
    )

    facts.masking_risk_signal = (
        facts.fallback_branch_count >= 6 and facts.constant_template_count >= 2
    )

    facts.extra = {
        "raw_loop_count": facts.loop_count,
        "raw_call_count": len(raw.get("calls", []) or []),
        "raw_assignment_count": len(raw.get("assignments", []) or []),
    }
    return facts