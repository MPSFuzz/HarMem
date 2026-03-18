from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List

from .facts import HarnessFacts


@dataclass
class IssueRecord:
    name: str
    confidence: str
    repairable: bool
    evidence: List[str] = field(default_factory=list)


@dataclass
class ConstraintEvalResult:
    passed: bool
    score: float
    violations: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    issues: List[IssueRecord] = field(default_factory=list)
    used_constraints: Dict[str, Any] = field(default_factory=dict)


def evaluate_constraints(
    facts: HarnessFacts,
    constraints: Dict[str, Any],
) -> ConstraintEvalResult:
    violations: List[str] = []
    warnings: List[str] = []
    issues: List[IssueRecord] = []
    score = 100.0

    input_constraints = constraints.get("input_model_constraints", {}) or {}
    lifecycle_constraints = constraints.get("lifecycle_constraints", {}) or {}
    reach_constraints = constraints.get("reachability_constraints", {}) or {}

    if not facts.has_main:
        violations.append("MISSING_MAIN")
        issues.append(IssueRecord(
            name="MISSING_MAIN",
            confidence="high",
            repairable=False,
            evidence=["main function not detected"],
        ))
        score -= 40

    if not facts.has_persistent_loop:
        warnings.append("MISSING_OR_WEAK_LOOP_SIGNAL")
        issues.append(IssueRecord(
            name="MISSING_OR_WEAK_LOOP_SIGNAL",
            confidence="low" if facts.parser_has_error else "medium",
            repairable=False,
            evidence=[f"loop_count={facts.loop_count}", f"parser_has_error={facts.parser_has_error}"],
        ))
        score -= 10

    if not facts.target_calls:
        violations.append("MISSING_TARGET_CALL")
        issues.append(IssueRecord(
            name="MISSING_TARGET_CALL",
            confidence="high",
            repairable=True,
            evidence=["no target call detected"],
        ))
        score -= 50

    if reach_constraints.get("require_target_data_dependency", True):
        if not facts.target_data_dependency_signal:
            violations.append("TARGET_CALL_INPUT_INDEPENDENT_RISK")
            issues.append(IssueRecord(
                name="TARGET_CALL_INPUT_INDEPENDENT_RISK",
                confidence="high",
                repairable=True,
                evidence=[
                    f"target_args_from_constructed_signal={facts.target_args_from_constructed_signal}",
                    f"target_args_from_input_signal={facts.target_args_from_input_signal}",
                ],
            ))
            score -= 25

    if input_constraints.get("require_role_separation", False):
        if not facts.role_separation_signal:
            violations.append("ROLE_COLLAPSE_RISK")
            issues.append(IssueRecord(
                name="ROLE_COLLAPSE_RISK",
                confidence="high",
                repairable=True,
                evidence=[
                    f"active_constructed_vars={len(facts.active_constructed_vars)}"
                ],
            ))
            score -= 25

    if lifecycle_constraints.get("prefer_iteration_objects_inside_loop", True):
        if facts.target_calls and not facts.target_call_inside_loop:
            warnings.append("TARGET_CALL_OUTSIDE_LOOP")
            issues.append(IssueRecord(
                name="TARGET_CALL_OUTSIDE_LOOP",
                confidence="low" if facts.parser_has_error else "medium",
                repairable=False,
                evidence=[
                    f"target_call_inside_loop={facts.target_call_inside_loop}",
                    f"parser_has_error={facts.parser_has_error}",
                ],
            ))
            score -= 10

    if facts.masking_risk_signal:
        warnings.append("MASKING_RISK_SIGNAL")
        issues.append(IssueRecord(
            name="MASKING_RISK_SIGNAL",
            confidence="high",
            repairable=True,
            evidence=[
                f"fallback_branch_count={facts.fallback_branch_count}",
                f"constant_template_count={facts.constant_template_count}",
            ],
        ))
        score -= 10

    passed = (len(violations) == 0 and score >= 50)
    return ConstraintEvalResult(
        passed=passed,
        score=max(0.0, score),
        violations=violations,
        warnings=warnings,
        issues=issues,
        used_constraints=constraints,
    )