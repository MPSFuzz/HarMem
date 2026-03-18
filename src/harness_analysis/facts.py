from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List


@dataclass
class TargetCallFact:
    name: str
    line: int | None = None
    args: List[str] = field(default_factory=list)
    in_loop: bool = False


@dataclass
class HarnessFacts:
    backend: str = "unknown"
    parser_has_error: bool = False

    has_main: bool = False
    has_persistent_loop: bool = False
    loop_count: int = 0

    has_file_input: bool = False
    input_source_vars: List[str] = field(default_factory=list)
    input_dependent_vars: List[str] = field(default_factory=list)

    constructed_vars: List[str] = field(default_factory=list)
    active_constructed_vars: List[str] = field(default_factory=list)

    target_calls: List[TargetCallFact] = field(default_factory=list)
    target_call_inside_loop: bool = False

    target_args_from_constructed_signal: bool = False
    target_args_from_input_signal: bool = False

    pre_target_call_count: int = 0
    pre_target_assignment_count: int = 0
    pre_target_guard_count: int = 0

    fallback_branch_count: int = 0
    constant_template_count: int = 0

    role_separation_signal: bool = False
    target_data_dependency_signal: bool = False
    masking_risk_signal: bool = False

    extra: Dict[str, Any] = field(default_factory=dict)