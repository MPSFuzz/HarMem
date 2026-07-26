import os
import json

from pathlib import Path
from typing import Dict, Any, List, Set, Tuple, Optional

from src.batch.batch_class import Batch
from src.cve_helper.cve_partial_prompt_render import render_cve_hints_for_seed_generation
from src.utils.utils import get_logger, parse_target_file, extract_target_func_code_from_plan, load_source_snippet, clip_text

logger = get_logger(__name__)

def _read_text_file(path: Path, max_len: int = 4096) -> str:
    try:
        text = path.read_text(encoding="utf-8", errors="ignore")
        if len(text) > max_len:
            return text[:max_len] + "\n...[truncated]..."
        return text
    except Exception as e:
        logger.warning(f"[LLM_feedback] Failed to read seed file {path}: {e}")
        return ""

def build_seed_generation_prompt(batch: Batch,
    trace_summary: Dict[str, Any],
    harness_path: Optional[str] = None,
    baseline_seeds: Optional[List[Path]] = None,
    ):
    root_api = trace_summary.get("root_api", "<unknown>")
    target_func = batch.target_func
    plan_path = batch.harness_info.get("harness_plans_files", "{}")
    plan = json.loads(Path(plan_path).read_text(encoding="utf-8", errors="ignore")).get(root_api, {})
    call_chain = plan.get("chain", {}).get("id", "<unknown>")

    targets_file = os.environ.get("TRACE_MARKER_TARGETS_FILE", "").strip()
    target_func_source_code = extract_target_func_code_from_plan(plan, target_func)
    bug_points = parse_target_file(targets_file, plan, target_func)
    bug_point_source_code_snippets: List[Tuple[str, int, str]] = []
    for f, ln in bug_points:
        snippet = load_source_snippet(f, ln, context=4)
        if snippet:
            bug_point_source_code_snippets.append((f, ln, clip_text(snippet, max_chars=1500)))
    
    lines = []
    lines.append(
        f"You are an expert in fuzz testing and C programming, and you are testing an open-source library called {batch.lib_name}."
        f"We are currently trying to trigger a target bug(or vulnerability) point in the target function:{target_func}. We already have a harness that can reach the target bug point at the functional level."  
        f"Now we need you to generate several seeds to help the harness reach the target bug point."
        f"If the bug model requires multiple semantic input roles, the generated seeds must match the harness input layout and should not degenerate into generic."
    )
    lines.append("")

    lines.append("=== Your task and output format (MUST FOLLOW) ===")
    lines.append(
        "Provide several high-quality seeds that can reach the bug(or vulnerability) points under the current harness."
        "- Ensure the correctness, usability, and high quality of the seeds, DO NOT generate garbled data that has no practical meaning."
        "- You MUST reply with a single JSON object and nothing else.\n"
        "- Prefer generating a Python SEED GENERATOR script that produces diverse, structured seeds automatically.\n"
        "- Only fall back to direct base64 seeds if the input model is too simple to benefit from a generator.\n"
        "- The JSON structure must be exactly ONE of these two forms:\n"
        "\n"
        "Form 1 (PREFERRED) - Python seed generator:\n"
        "{\n"
        "  \"type\": \"generator\",\n"
        "  \"generator_code\": \"<complete Python script as a single string with \\\\n for newlines>\",\n"
        "  \"expected_count\": <integer, recommended 10-30>,\n"
        "  \"description\": \"<1-2 sentences describing what this generator produces>\"\n"
        "}\n"
        "The generator script MUST:\n"
        "- Accept one command-line argument: the output directory path.\n"
        "- Write seed files into that directory (e.g. seed_0001, seed_0002, ...).\n"
        "- Only use stdlib modules (struct, random, os, sys, string, itertools, etc.).\n"
        "- Print the count of generated seeds to stdout on success.\n"
        "- NOT use network, subprocess, or filesystem outside the output directory.\n"
        "- Use controlled randomness (random module with fixed seeds is OK) to ensure reproducibility.\n"
        "- Generate binary seeds that match the harness input format derived from the harness code.\n"
        "\n"
        "Form 2 (FALLBACK) - Direct base64 seeds:\n"
        "{\n"
        "  \"type\": \"seeds\",\n"
        "  \"seeds\": {\"seed1\": \"<BASE64 seed bytes>\", \"seed2\": \"<BASE64 seed bytes>\", ...}\n"
        "}\n"
        "- Do NOT return raw seed text; always use base64-encoded content.\n"
        "- Keep the response compact: avoid unnecessary comments/blank lines while keeping correctness.\n"
        "- Do NOT add any other keys, fields, text, or symbols outside this JSON object.\n"
        "- Do NOT wrap the JSON in code fences. Reply with RAW JSON only."
    )

    cve_hints_block = render_cve_hints_for_seed_generation(getattr(batch, "cve_hints", {}) or {})
    if cve_hints_block:
        lines.append("The vulnerability (or bug) you are helping to reproduce has the following characteristics in its occurrence or exploitation.")
        lines.append("=== Vulnerability/Bug Characteristics (from dynamic analysis) ===")
        lines.append(cve_hints_block)

    lines.append(f"The harness provided below is used to call the target function based on this call chain: {call_chain}")
    lines.append("=== Current harness source code (the harness code we are using now) ===")
    if harness_path and Path(harness_path).is_file():
        harness_code = Path(harness_path).read_text(encoding="utf-8", errors="ignore")
        lines.append("```c")
        lines.append(harness_code)
        lines.append("```")
    lines.append("")

    lines.append("The target function source code in the specific particular library version is as follows:")
    lines.append("=== Source Code of The Target Function ===")
    lines.append("```c")
    lines.append(target_func_source_code)
    lines.append("```")
    lines.append("")

    if bug_point_source_code_snippets:
        lines.append("The code snippets around the target bug point are as follows:")
        lines.append("=== Code Snippets of The Target Bug Point ===")
        for f, ln, snippet in bug_point_source_code_snippets:
            lines.append(f"--- File: {f}, Line: {ln} ---")
            lines.append("```c")
            lines.append(snippet)
            lines.append("```")
        lines.append("")
    
    if baseline_seeds:
        lines.append("There are some seeds we have used in the previous fuzzing test, many of them may not reach the target bug location or low quality, but you can use these seeds as a reference. ")
        lines.append("=== Example baseline seeds (good prefixes that usually reach the chain/target) ===")
        for p in baseline_seeds[-5:]:
            snippet = _read_text_file(p, max_len=4096)
            if snippet:
                lines.append("```text")
                lines.append(snippet)
                lines.append("```")
        lines.append("")
    
    return "\n".join(lines)