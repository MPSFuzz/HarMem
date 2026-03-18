from __future__ import annotations

from typing import Any, Dict, List

from .plugin import HarnessAnalysisResult


def distill_structural_guidance(
    analysis_result: HarnessAnalysisResult,
    constraints: Dict[str, Any],
    cve_hints: Dict[str, Any] | None = None,
    phase_a_context: Dict[str, Any] | None = None,
) -> Dict[str, Any]:
    cve_hints = cve_hints or {}
    phase_a_context = phase_a_context or {}

    facts = analysis_result.facts
    ev = analysis_result.evaluation

    preserve: List[str] = []
    avoid: List[str] = []
    adjust: List[str] = []
    do_not_touch: List[str] = []
    issues: List[Dict[str, Any]] = []
    confidence: Dict[str, str] = {}

    if facts.role_separation_signal:
        preserve.append("Preserve semantic role separation and multi-object construction.")
        confidence["role_model"] = "high"

    if facts.target_data_dependency_signal:
        preserve.append("Preserve target data dependency from fuzz input to target invocation.")
        confidence["target_dependency"] = "high"

    if facts.target_calls:
        preserve.append("Preserve explicit target API invocation path.")
        confidence["target_path"] = "high"

    if facts.masking_risk_signal:
        avoid.append("Avoid excessive fallback branches and heavy fixed-template masking.")
        adjust.append("Reduce non-essential fallback logic while preserving minimal validity scaffolding.")
        confidence["masking_risk"] = "high"

    for issue in ev.issues:
        issues.append({
            "name": issue.name,
            "confidence": issue.confidence,
            "repairable": issue.repairable,
            "evidence": issue.evidence,
        })

    # 更保守：低置信度问题不要直接驱动大改
    for issue in ev.issues:
        if issue.name == "TARGET_CALL_OUTSIDE_LOOP":
            adjust.append("Verify loop-local placement conservatively before changing control structure.")
            do_not_touch.append("Do not rewrite the top-level control skeleton solely based on loop-placement inference.")
            confidence["loop_inference"] = issue.confidence

        elif issue.name == "MISSING_OR_WEAK_LOOP_SIGNAL":
            adjust.append("Preserve the existing fuzz loop unless stronger evidence shows it is structurally wrong.")
            do_not_touch.append("Do not remove or rewrite the persistent fuzz loop based on weak parser inference.")
            confidence["loop_signal"] = issue.confidence

        elif issue.name == "ROLE_COLLAPSE_RISK" and issue.repairable:
            adjust.append("Re-introduce or strengthen separation between semantic input roles / constructed objects.")

        elif issue.name == "TARGET_CALL_INPUT_INDEPENDENT_RISK" and issue.repairable:
            adjust.append("Increase input influence on objects and values that reach the target call.")

    # 若当前 bug_model 明确要求多角色，禁止大改布局
    bug_model = phase_a_context.get("contextual_bug_model", {}) or {}
    if bug_model.get("multi_input_roles", False):
        do_not_touch.append("Do not collapse multiple semantic input roles into a single generic blob.")
        confidence["layout_preservation"] = "high"

    return {
        "preserve": list(dict.fromkeys(preserve)),
        "avoid": list(dict.fromkeys(avoid)),
        "adjust": list(dict.fromkeys(adjust)),
        "do_not_touch": list(dict.fromkeys(do_not_touch)),
        "issues": issues,
        "confidence": confidence,
    }