from __future__ import annotations

import re

from dataclasses import dataclass

from .treesitter_backend import TreeSitterCBackend
from .fact_extractor import normalize_raw_to_facts
from .constraint_engine import evaluate_constraints, ConstraintEvalResult
from .facts import HarnessFacts


@dataclass
class HarnessAnalysisResult:
    facts: HarnessFacts
    evaluation: ConstraintEvalResult
    raw_backend_name: str


def analyze_harness_structure(
    code: str,
    target_api: str,
    constraints: dict,
) -> HarnessAnalysisResult:
    backend = TreeSitterCBackend()
    raw = backend.extract_raw(code)
    raw["backend"] = backend.backend_name

    match = re.match(r'^([^_]+)', target_api)
    target_api = match.group(1) if match else target_api

    facts = normalize_raw_to_facts(raw, target_api=target_api)
    evaluation = evaluate_constraints(facts, constraints)

    return HarnessAnalysisResult(
        facts=facts,
        evaluation=evaluation,
        raw_backend_name=backend.backend_name,
    )

if __name__ == "__main__":
    from src.cve_helper.constraint_model import build_generation_constraints
    from src.llm.build_phase_A_context import build_phase_A_context
    import json

    plan_path = "/root/auto_harness/src/harness_plans/xmlSchematronValidateDoc_plans.json"
    plan = json.load(open(plan_path))
    plan = plan["xmlSchematronValidateDoc"]

    cve_hints_path = "/root/temp/cve_rules/information/cve_hints_CVE-2025-49794.json"
    cve_hints_obj = json.load(open(cve_hints_path))

    harness_path = "/root/auto_harness/src/harness/20260313_020352/20260313_020352_xmlSchematronValidateDoc.c"
    with open(harness_path, "r") as f:
        code = f.read()

    if cve_hints_obj is not None and plan is not None:
        phase_a_context = build_phase_A_context(plan, cve_hints_obj)
        constraints = build_generation_constraints(plan, phase_a_context, cve_hints_obj)
        analysis_result = analyze_harness_structure(code=code, target_api="xmlSchematronValidateDoc", constraints=constraints)
        print("Facts:", analysis_result)

