from __future__ import annotations

from typing import Any, Dict, Optional


def build_generation_constraints(
    plan: Dict[str, Any],
    phase_a_context: Dict[str, Any],
    cve_hints: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    cve_hints = cve_hints or {}
    bug_model = phase_a_context.get("contextual_bug_model", {}) or {}
    lifecycle = phase_a_context.get("lifecycle_summary", {}) or {}

    return {
        "input_model_constraints": {
            "input_roles": bug_model.get("input_roles", []) or [],
            "require_role_separation": bool(bug_model.get("multi_input_roles", False)),
            "preferred_layout": bug_model.get("preferred_layout", "unknown"),
            "pattern_kind": bug_model.get("pattern_kind", "unknown"),
        },
        "lifecycle_constraints": {
            "prefer_iteration_objects_inside_loop": True,
            "prefer_global_init_outside_loop": bool(lifecycle.get("global_initializers")),
        },
        "reachability_constraints": {
            "target_api": phase_a_context.get("target_api", {}).get("name", ""),
            "require_target_data_dependency": True,
        },
    }