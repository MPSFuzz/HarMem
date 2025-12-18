import json

from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Any, List, Set, Tuple, Optional

from src.batch.batch_class import Batch
from src.utils.utils import get_logger

logger = get_logger(__name__)

@dataclass
class LLMEvent:
    type: str
    short_summary: str
    details: str
    suggested_foucs: str

def _extract_reached_func_set(per_trace_entry: Dict[str, Any]) -> Set[Tuple[int, int]]:
    s: Set[Tuple[int, int]] = set()
    for f in per_trace_entry.get("reached_functions", []):
        try:
            mod = int(f["module_id"])
            loc = int(f["local_id"])
            s.add((mod, loc))
        except Exception as e:
            logger.warning(f"[LLM_feedback] Failed to parse function entry {f} with error: {e}")
            continue
    
    return s

def _build_index_from_filtered_metadata(filtered_metadata: Dict[str, Any]) -> Dict[Tuple[int, int], Dict[str, Any]]:
    idx: Dict[Tuple[int, int], Dict[str, Any]] = {}
    
    for f in filtered_metadata.get("functions", []):
        try:
            key = (int(f["module_id"]), int(f["local_id"]))
            idx[key] = f
        except Exception as e:
            logger.warning(f"[LLM_feedback] Failed to parse function metadata {f} with error: {e}")
            continue
    
    return idx

def _pick_representative_traces(queue_traces: Dict[str, Any], max_per_category: int = 2) -> Dict[str, List[Tuple[str, Dict[str, Any]]]]:
    buckets: Dict[str, List[Tuple[str, Dict[str, Any]]]] = {}
    per_traces = queue_traces.get("per_trace", {})

    for tid, info in per_traces.items():
        cat = info.get("coverage_category", "unknown")
        buckets.setdefault(cat, [])
        if len(buckets[cat]) < max_per_category:
            buckets[cat].append((tid, info))
    
    return buckets

def _load_source_snippet(file_path: str, line: int, context: int = 3) -> str:
    try:
        p = Path(file_path)
        if not p.is_file():
            return ""
        lines = p.read_text(encoding="utf-8", errors="ignore").splitlines()
        if line <= 0:
            line = 1
        start = max(1, line - context)
        end = min(len(lines), line + context)
        snippet_lines = lines[start - 1 : end]

        numbered = [
            f"{start + i:6d}: {snippet_lines[i]}" for i in range(len(snippet_lines))
        ]
        header = f"{file_path}:L{start}-L{end}"
        return header + "\n" + "\n".join(numbered)
    except Exception as e:
        logger.warning(
            f"[LLM_feedback] Failed to load source snippet from {file_path}:{line} - {e}"
        )
        return ""

def _read_text_file(path: Path, max_len: int = 512) -> str:
    try:
        text = path.read_text(encoding="utf-8", errors="ignore")
        if len(text) > max_len:
            return text[:max_len] + "\n...[truncated]..."
        return text
    except Exception as e:
        logger.warning(f"[LLM_feedback] Failed to read seed file {path}: {e}")
        return ""

def analyze_trace_summary_for_llm(trace_summary: Dict[str, Any], queue_seed_examples: List[Path]) -> List[LLMEvent]:
    events: List[LLMEvent] = []

    root_api = trace_summary.get("root_api", "<unknown>")
    filtered_metadata_path = trace_summary.get("filtered_metadata_path", "")
    queue_traces = trace_summary.get("queue_traces", {})
    queue_stats = trace_summary.get("queue_coverage_category_stats", {})

    baseline_trace = trace_summary.get("baseline_trace")    # this part may be null

    filtered_metadata: Dict[str, Any] = {}
    func_index: Dict[Tuple[int, int], Dict[str, Any]] = {}

    if filtered_metadata_path and Path(filtered_metadata_path).is_file():
        try:
            filtered_metadata = json.loads(Path(filtered_metadata_path).read_text(encoding="utf-8"))
            func_index = _build_index_from_filtered_metadata(filtered_metadata)
        except Exception as e:
            logger.error(f"[LLM_feedback] Failed to load filtered metadata from {filtered_metadata_path} with error: {e}")
    
    # the overall stats of coverage in the target call chain
    if queue_stats:
        total_traces = sum(queue_stats.values())
        no_cov = queue_stats.get("no_chain_coverage", 0)
        degraded = queue_stats.get("degraded_from_baseline", 0)
        better = queue_stats.get("good_or_better_than_baseline", 0)

        details_line = [
            f"For the call chain starting from root API '{root_api}', we replayed {total_traces} seeds from the fuzzer queue.",
            f"- {no_cov} seeds nerver reached ant functions in the call chain.",
            f"- {degraded} seeds only reached a subset of baseline coverage.",
            f"- {better} seeds maintained or improved coverage relative to baseline."
        ]
        details = "\n".join(details_line)

        if no_cov > 0 and total_traces > 0 and no_cov >= total_traces * 0.5:
            foucs = (
                "Many inputs after mutation appear stucturally invalid and fail before reaching the target call chain."
                "Please foucs on preserving the basic input structure (e.g., well-formed XML/JSON format) and avoid mutations "
                "that cause early parse failures. "
            )
        else:
            foucs = (
                "Please prioritize generating inputs that go beyond shallow paths and exercise deeper nodes in the call chain."
                "on the exteranl call chain, rather than only repeating the same prefix."
            )
        
        events.append(LLMEvent(
            type = "chain_coverage_summary",
            short_summary="Overall coverage categories of queue seeds for the target call chain.",
            details = details,
            suggested_foucs=foucs
        ))

    # which functions are not reached by any of the queue seeds
    agg_funcs = queue_traces.get("aggregate", {}).get("functions", [])
    # a hit map to record the frequency of functions are reached by at least one seed
    hit_map: Dict[Tuple[int, int], int] = {}
    for f in agg_funcs:
        try:
            key = (int(f["module_id"]), int(f["local_id"]))
            hit_map[key] = int(f.get("hit_traces", 0))
        except Exception as e:
            continue
    
    never_hit_funcs: List[Dict[str, Any]] = []
    for key, meta in func_index.items():
        if hit_map.get(key, 0) == 0:
            never_hit_funcs.append(meta)
    
    if never_hit_funcs:
        preview = never_hit_funcs[:5]   # preview up to 5 functions as example
        lines: List[str] = []
        for f in preview:
            lines.append(
                f"- {f.get('name', '<unknown>')} ({f.get('file', '?')}:{f.get('line', 0)})"
            )
        
        if len(never_hit_funcs) > len(preview):
            lines.append(
                f"... and {len(never_hit_funcs) - len(preview)} more functions on the call chain not reached."
            )
        
        details = (
            f"For the external call chain starting from root API '{root_api}', the following functions"
            f"were **never** reached by any replayed fuzzer queue seeds:\n" + "\n".join(lines)
        )

        foucs = (
            "Please infer what input properties or preconditions are required for these functions to be invoked, "
            "adjust the harness or provide a better initial seed so that execution can progress deeper along the chain."
        )

        events.append(LLMEvent(
            type = "missing_chain_functions",
            short_summary = "Some functions on the target call chain are never reached by any fuzzer queue seeds.",
            details=details,
            suggested_foucs=foucs
        ))
    
    # branch bias
    baseline_branch_map: Dict[Tuple[int, int], int] = {}
    if baseline_trace:
        for b in baseline_trace.get("aggregate", {}).get("branches", []):
            try:
                key = (int(b["module_id"]), int(b["local_id"]))
                bt = int(b.get("total_true", 0))
                bf = int(b.get("total_false", 0))
                baseline_branch_map[key] = {"true": bt, "false": bf}
            except Exception as e:
                logger.warning(
                    f"[LLM_feedback] Failed to parse baseline branch entry {b} with error: {e}"
                )
                continue
    
    queue_branch_map: Dict[Tuple[int, int], Dict[str, Any]] = {}
    agg_branches = queue_traces.get("aggregate", {}).get("branches", [])
    for b in agg_branches:
        try:
            key = (int(b["module_id"]), int(b["local_id"]))
            qt = int(b.get("total_true", 0))
            qf = int(b.get("total_false", 0))
            queue_branch_map[key] = {"true": qt, "false": qf, "meta": b}
        except Exception as e:
            logger.warning(
                f"[LLM_feedback] Failed to parse queue branch entry {b} with error: {e}"
            )
            continue
    
    # analyze branches by combing queue and baseline info
    # Classification: baseline (two sides) → queue (one side) ⇒ degenerate coverage; baseline & queue (both one side) ⇒ structural/invariant
    biased_regressions: List[Tuple[int, int], Dict[str, Any], Dict[str, Any], Dict[str, Any]] = []
    structural_invariants: List[Tuple[int, int], Dict[str, Any], Dict[str, Any], Dict[str, Any]] = []

    for key, qinfo in queue_branch_map.items():
        qt = qinfo["true"]
        qf = qinfo["false"]
        q_total = qt + qf
        if q_total == 0:
            continue

        queue_single = (qt == 0) ^ (qf == 0)    # queue case only hits one side
        if not queue_single:
            continue

        base = baseline_branch_map.get(key)
        if base is None:
            continue

        bt = base["true"]
        bf = base["false"]
        b_total = bt + bf
        if b_total == 0:
            continue

        base_dual = (bt > 0 and bf > 0)
        base_singel = (bt == 0 or bf == 0)

        meta = qinfo["meta"]
        if base_dual and queue_single:
            biased_regressions.append((key, meta, base, qinfo))
        elif base_singel and queue_single:
            structural_invariants.append((key, meta, base, qinfo))
    
    # coverage degradation branch biaes:
    if biased_regressions:
        preview = biased_regressions[:5]
        lines: List[str] = []
        for key, meta, base, qinfo in preview:
            file = meta.get("file", "?")
            line_no = int(meta.get("line", 0))
            snippet = _load_source_snippet(file, line_no, context=3)

            bt = base["true"]
            bf = base["false"]
            qt = qinfo["true"]
            qf = qinfo["false"]

            lines.append(
                f"- Branch at {file}:{line_no}\n"
                f"  Baseline initial seed in fuzz coverage: true={bt}, false={bf} (both sides explored)\n"
                f"  Queue case in fuzz coverage:    true={qt}, false={qf} (only one side explored)\n"
                f"  Source snippet:\n{snippet}"
            )

        if len(biased_regressions) > len(preview):
            lines.append(
                f"... and {len(biased_regressions) - len(preview)} more branches with similar regression patterns."
            )

        details = (
            "On the target call chain, we observed several conditional branches for which baseline seeds "
            "covered **both** sides, but queue seeds now only take **one** side:\n"
            + "\n\n".join(lines)
        )

        foucs = (
            "These branches previously had more diverse behavior with the baseline inputs, but now the mutated "
            "queue seeds only exercise one side. This suggests that newer seeds may have lost certain structural "
            "or semantic properties. Please adjust the harness or seed generation so that both sides of these "
            "conditions can be reached again (while still preserving overall input validity)."
        )

        events.append(
            LLMEvent(
                type="branch_bias_regression",
                short_summary=(
                    "Some chain-related branches regress from two-sided coverage (baseline) to one-sided (queue)."
                ),
                details=details,
                suggested_foucs=foucs,
            )
        )
    
    if structural_invariants:
        preview = structural_invariants[:3]
        lines: List[str] = []
        for key, meta, base, qinfo in preview:
            file = meta.get("file", "?")
            line_no = int(meta.get("line", 0))
            snippet = _load_source_snippet(file, line_no, context=3)

            bt = base["true"]
            bf = base["false"]

            lines.append(
                f"- Branch at {file}:{line_no}\n"
                f"  Baseline coverage: true={bt}, false={bf} (single-sided)\n"
                f"  Source snippet:\n{snippet}"
            )

        if len(structural_invariants) > len(preview):
            lines.append(
                f"... and {len(structural_invariants) - len(preview)} more branches "
                f"with stable single-sided behavior in both baseline and queue runs."
            )

        details = (
            "There are also branches on the call chain that are **single-sided** both in baseline and queue runs. "
            "These are likely structural or invariant checks (e.g., basic validity conditions):\n"
            + "\n\n".join(lines)
        )

        foucs = (
            "You generally do not need to force these branches to flip just for the sake of diversity. "
            "They are likely enforcing invariants or required preconditions. You may still use the code snippet "
            "to better understand what structural assumptions the library is making about the input."
        )

        events.append(
            LLMEvent(
                type="branch_invariants_context",
                short_summary=(
                    "Some branches on the chain are single-sided in both baseline and queue runs (likely invariants)."
                ),
                details=details,
                suggested_foucs=foucs,
            )
        )

    # representative case in every category
    rep_by_cat = _pick_representative_traces(queue_traces, max_per_category=2)
    if rep_by_cat:
        lines: List[str] = []
        for cat, traces in rep_by_cat.items():
            lines.append(f"Category `{cat}` example traces:")
            for tid, info in traces:
                fn_names = [f.get("name", "<unknown>") for f in info.get("reached_functions", [])]
                fn_str = ", ".join(fn_names) if fn_names else "(no chain functions reached)"

                id = tid[tid.find("id:"):]
                for p in queue_seed_examples:
                    if p.name == id:
                        case_content = _read_text_file(p, max_len=512)
                        break

                lines.append(f"  - trace_id={tid}, reached_functions={fn_str}, this_queue_case_content:\n```text\n{case_content}\n```")
        details = (
            "Here are example traces from different coverage categories. "
            "Each trace_id corresponds to one queue file used during replay:\n"
            + "\n".join(lines)
        )
        foucs = (
            "Please compare these categories: understand why `no_chain_coverage` seeds fail early, and what "
            "properties enable `good_or_better_than_baseline` seeds to go deeper, then generalize patterns "
            "to propose better harness logic or new seed templates."
        )

        events.append(
            LLMEvent(
                type="representative_traces",
                short_summary="Representative traces from different coverage categories.",
                details=details,
                suggested_foucs=foucs,
            )
        )

    return events


def build_llm_feedback_prompt(
    batch: Batch,
    trace_summary: Dict[str, Any],
    harness_path: Optional[str] = None,
    baseline_seeds: Optional[List[Path]] = None,
    queue_seed_examples: Optional[List[Path]] = None,
) -> str:
    root_api = trace_summary.get("root_api", "<unknown>")
    plan = Path(batch.harness_info.get("harness_plans_files", "{}"))
    plan = json.loads(plan.read_text(encoding="utf-8", errors="ignore")).get(root_api, {})
    call_chain = plan.get("chain", {}).get("id", "<unknown>")
    events = analyze_trace_summary_for_llm(trace_summary, queue_seed_examples)

    lines: List[str] = []

    lines.append(
        f"You are helping to improve a fuzzing harness and seed corpus for a C library named: {batch.lib_name} "
        f"that contains a call chain: {call_chain} which starts from {root_api} and whose ultimate target function is "
        f"`{batch.target_func}`.\n"
        f"We collected runtime traces by replaying both baseline seeds and sampled fuzzer queue seeds "
        f"on a trace-instrumented version of the target library."
    )
    lines.append("")

    lines.append("=== Your task and output format (MUST FOLLOW) ===")
    lines.append(
        "Your task:\n"
        "- You may modify ONLY the harness code, ONLY the seeds, or BOTH.\n"
        "- The current harness already follows the basic call-chain structure and input handling; "
        "you MUST treat it as the base.\n"
        "- If you decide to modify the harness, you MUST:\n"
        "  * ONLY change code between the markers @@CHAIN_LOGIC_BEGIN@@ and @@CHAIN_LOGIC_END@@,\n"
        "  * NOT change the __AFL_LOOP fallback macro,\n"
        "  * NOT change how argv[1] is read and the buffer is allocated,\n"
        "  * NOT change the overall structure of main(), global init/cleanup, or error-handling outside that region.\n"
        "- Any modified harness must remain valid C code, keep reading fuzz input from argv[1], "
        "and preserve the persistent fuzzing loop and init/cleanup patterns.\n"
        "- Any modified seed must be a complete input example that is likely to drive execution deeper along the call chain.\n"
        "- Prefer to fix or redesign seeds first; only modify the harness logic if it clearly helps preserve input structure "
        "or propagate fuzz input deeper along the call chain.\n\n"
        "Output format requirements (VERY IMPORTANT):\n"
        "- You MUST reply with a single JSON object and nothing else (no explanations, no markdown, no comments).\n"
        "- The JSON structure must be exactly ONE of the following forms:\n"
        "  1) If you ONLY need to modify the seeds(if there are serval seeds you want to modify, the key is like seedn), reply as:\n"
        '     { "seed1": "<FULL seed content>" ,\n' 
        '       "seed2": "<FULL seed content>" ...}\n'
        "  2) If you ONLY need to modify the harness, reply as:\n"
        '     { "harness": "<FULL harness C source code>",\n'
        '       "compile_command": "<the compile command, e.g., \'aflgo-clang -g -O2 a.c -o a.out $(pkg-config --cflags --libs libxml-2.0)\'>" }\n"'
        "  3) If you need to modify BOTH, reply as:\n"
        '     { "seed": "<FULL seed content>",\n'
        '       "harness": "<FULL harness C source code>",\n'
        '       "compile_command": "<the compile command>" }\n\n'
        "- Whenever you output a harness, you MUST also provide a valid compile_command in the same JSON object.\n"
        "- The compile_command should follow the pattern:\n"
        "    aflgo-clang -g -O2 <harness_file_name>.c -o <output_binary> $(pkg-config --cflags --libs <PKG_NAME>)\n"
        '  Use the appropriate pkg-config name for the target library (e.g., "libxml-2.0") based on the harness and plan.\n'
        "- The seed and harness values must each contain the COMPLETE content (not a diff, not a partial snippet).\n"
        "- To keep the response compact, avoid unnecessary comments and blank lines in the harness and seed, "
        "while keeping them correct and readable.\n"
        "- Do NOT add any other keys, fields, text, or symbols outside this JSON object.\n"
        "- Do NOT wrap the JSON in code fences. Reply with RAW JSON only."
    )
    if harness_path:
        try:
            h_text = Path(harness_path).read_text(encoding="utf-8", errors="ignore")
        except Exception as e:
            logger.warning(f"[LLM_feedback] Failed to read harness file {harness_path}: {e}")
            h_text = ""

        if h_text:
            lines.append("=== Current harness source code ===")
            lines.append("```c")
            lines.append(h_text)
            lines.append("```")
            lines.append("")

    if baseline_seeds:
        lines.append("=== Example baseline seeds (usually well-formed and known to reach the call chain and used as the initial seed in the fuzzing process) ===")
        for p in baseline_seeds:
            snippet = _read_text_file(p, max_len=512)
            lines.append(f"- Baseline seed file: {p.name}")
            if snippet:
                lines.append("```text")
                lines.append(snippet)
                lines.append("```")
        lines.append("")
    
    # if queue_seed_examples:
    #     lines.append("=== Example queue seeds (the mutated inputs in fuzz progress in the fuzzer queue) ===")
    #     for p in queue_seed_examples:
    #         snippet = _read_text_file(p, max_len=512)
    #         lines.append(f"- Queue seed file: {p.name}")
    #         if snippet:
    #             lines.append("```text")
    #             lines.append(snippet)
    #             lines.append("```")
    #     lines.append("")
    
    lines.append("=== High-level observations from runtime traces ===")
    lines.append("The following observations are extracted from analyzing the runtime traces of both baseline and queue seeds. Please use these insights to guide your suggestions for improving the harness and seed corpus.\n")
    for ev in events:
        lines.append(f"- [{ev.type}] {ev.short_summary}")
    lines.append("")

    lines.append("=== Technical details ===")
    lines.append("Below are detailed analyses and findings from the runtime trace data:\n")
    for ev in events:
        lines.append(f"[*] {ev.type}:")
        lines.append(ev.details)
        lines.append("")
    lines.append("")

    lines.append("=== What you should focus on ===")
    lines.append("Based on the above observations, please focus on the following aspects when proposing improvements:\n")
    for ev in events:
        lines.append(f"- ({ev.type}) {ev.suggested_foucs}")
    lines.append("")

    return "\n".join(lines)