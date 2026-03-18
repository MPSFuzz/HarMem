from __future__ import annotations

import json
from typing import Any, Dict, Optional

from src.utils.utils import get_logger
from src.harness_analysis import analyze_harness_structure, distill_structural_guidance
from src.cve_helper.constraint_model import build_generation_constraints
from src.llm.LLM_class import LLM
from .harness_class import harness

logger = get_logger(__name__)


def _structural_better(new_result, old_result) -> bool:
    """
    Conservative acceptance rule:
    - no compile regression should be handled outside
    - prefer fewer high-confidence repairable issues
    - otherwise require score improvement
    """

    def count_high_repairable(res):
        cnt = 0
        for issue in res.evaluation.issues:
            if issue.repairable and issue.confidence == "high":
                cnt += 1
        return cnt

    old_hr = count_high_repairable(old_result)
    new_hr = count_high_repairable(new_result)

    if new_hr < old_hr:
        return True

    if new_result.evaluation.score > old_result.evaluation.score:
        return True

    # 额外：如果 masking risk 消失了，也算净收益
    if old_result.facts.masking_risk_signal and not new_result.facts.masking_risk_signal:
        return True

    return False


def structural_refine_harness(
    llm: LLM,
    h: harness,
    plan: Dict[str, Any],
    phase_a_context: Dict[str, Any],
    cve_hints_obj: Optional[Dict[str, Any]] = None,
    max_rounds: int = 1,
) -> Dict[str, Any]:
    cve_hints_obj = cve_hints_obj or {}
    constraints = build_generation_constraints(plan, phase_a_context, cve_hints_obj)

    base_analysis = analyze_harness_structure(
        code=h.code,
        target_api=llm.target_func,
        constraints=constraints,
    )

    guidance = distill_structural_guidance(
        analysis_result=base_analysis,
        constraints=constraints,
        cve_hints=cve_hints_obj,
        phase_a_context=phase_a_context,
    )

    logger.info(
        f"[structural-refine][before] score={base_analysis.evaluation.score}, "
        f"violations={base_analysis.evaluation.violations}, "
        f"warnings={base_analysis.evaluation.warnings}, "
        f"guidance={json.dumps(guidance, ensure_ascii=False)}"
    )

    accepted = False
    rounds = 0

    while rounds < max_rounds:
        rounds += 1

        old_code = h.code
        old_compile_command = h.compile_command
        old_analysis = base_analysis

        refined = llm.structural_refine_harness(h, guidance, cve_hints_obj, phase_a_context)
        if refined is None:
            logger.warning("[structural-refine] LLM returned no refinement result")
            break

        # compile test after refine
        h.complete_compile_command()
        h.update_code_file()
        compile_ok = h.compile_test()

        fix_count = 0

        while not compile_ok and fix_count < 3:
            llm.harness_fix(h)
            h.complete_compile_command()
            h.update_code_file()
            compile_ok = h.compile_test()
            fix_count += 1
        
        if not compile_ok:
            llm.harness_fix(h)
            logger.warning("[structural-refine] refined harness failed compile, rollback")
            h.code = old_code
            h.compile_command = old_compile_command
            h.update_code_file()
            break

        new_analysis = analyze_harness_structure(
            code=h.code,
            target_api=llm.target_func,
            constraints=constraints,
        )

        logger.info(
            f"[structural-refine][after] score={new_analysis.evaluation.score}, "
            f"violations={new_analysis.evaluation.violations}, "
            f"warnings={new_analysis.evaluation.warnings}"
        )

        if _structural_better(new_analysis, old_analysis):
            accepted = True
            base_analysis = new_analysis
            logger.info("[structural-refine] accepted refined harness")
            break
        else:
            logger.info("[structural-refine] no net structural gain, rollback")
            h.code = old_code
            h.compile_command = old_compile_command
            h.update_code_file()
            break

    return {
        "accepted": accepted,
        "rounds": rounds,
        "analysis_result": base_analysis,
        "guidance": guidance,
    }