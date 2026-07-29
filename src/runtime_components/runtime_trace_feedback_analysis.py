import json
import math
import os

from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Any, List, Set, Tuple, Optional
from collections import defaultdict

from src.batch.batch_class import Batch
from src.utils.utils import get_logger, parse_target_file, extract_target_func_code_from_plan, load_source_snippet, clip_text
from src.utils._global_vars import regularized_fuzz_root_apis
from src.cve_helper.cve_partial_prompt_render import render_cve_hints_for_upgrade

logger = get_logger(__name__)

@dataclass
class LLMEvent:
    type: str
    short_summary: str
    details: str
    suggested_foucs: str

# [fine3] marker-based analysis <<<
def _marker_extract_bug_points(trace_summary: Dict[str, Any]) -> List[Dict[str, Any]]:
    qt = trace_summary.get("queue_traces", {}) or trace_summary
    agg = (qt.get("aggregate", {}) or {})
    markers = agg.get("markers", []) or []

    num_traces = qt.get("num_traces", None)
    if num_traces is None:
        num_traces = trace_summary.get("num_traces", 0)
    try:
        num_traces = int(num_traces or 0)
    except Exception:
        num_traces = 0

    out = []
    for mk in markers:
        tag = (mk.get("tag", "") or "").lower()
        if tag != "bug_point":
            continue
        hit_tr = int(mk.get("hit_traces", 0) or 0)
        hit_rate = (hit_tr / num_traces) if num_traces > 0 else 0.0
        out.append({
            "module_id": mk.get("module_id"),
            "local_id": mk.get("local_id"),
            "file": mk.get("file", ""),
            "line": int(mk.get("line", 0) or 0),
            "hit_traces": hit_tr,
            "hit_rate": float(hit_rate),
            "num_traces": num_traces,
        })

    out.sort(key=lambda x: x["hit_rate"])
    return out


def _marker_extract_furthest_summary(trace_summary: Dict[str, Any], topk: int = 5) -> List[Tuple[str, int]]:
    qt = trace_summary.get("queue_traces", {}) or trace_summary
    per_trace = qt.get("per_trace", {}) or {}

    cnt: Dict[str, int] = {}
    for _, info in per_trace.items():
        seq = info.get("marker_seq", []) or []
        if not seq:
            continue
        last = seq[-1]
        tag = last.get("tag", "") or ""
        f = last.get("file", "") or ""
        ln = int(last.get("line", 0) or 0)
        desc = f"{tag}@{Path(f).name if f else f}:{ln}"
        cnt[desc] = cnt.get(desc, 0) + 1

    items = sorted(cnt.items(), key=lambda kv: kv[1], reverse=True)[:topk]
    return items


def _marker_build_kpi_block(trace_summary: Dict[str, Any]) -> str:
    bug_points = _marker_extract_bug_points(trace_summary)
    furthest = _marker_extract_furthest_summary(trace_summary, topk=5)

    lines = []
    if bug_points:
        lines.append("=== Marker milestone status (PRIMARY KPI) ===")
        for bp in bug_points[:3]:
            f = bp["file"]
            ln = bp["line"]
            hit_tr = bp["hit_traces"]
            n = bp["num_traces"]
            r = bp["hit_rate"]
            lines.append(f"- bug_point @ {Path(f).name if f else f}:{ln}  hit_traces={hit_tr}/{n}  hit_rate={r:.3f}")
        lines.append(
            "KPI: Improve bug_point hit_rate (or push furthest_marker beyond current bottleneck) WITHOUT reducing target reach_rate."
        )
        lines.append("")

    if furthest:
        lines.append("=== Marker bottleneck summary (where executions tend to stop) ===")
        for desc, c in furthest:
            lines.append(f"- furthest_marker {desc} : {c} traces")
        lines.append("")

    return "\n".join(lines).strip()

def _micro_tune_event_rank(ev) -> int:
    """
    marker 事件优先，其次 target reach，其次 windowed entropy/bias，再其次其他。
    """
    t = (getattr(ev, "type", "") or "").lower()

    # marker first
    if "marker" in t:
        return 0
    # target reach second
    if t.startswith("target_"):
        return 1
    # prefer windowed entropy/bias over global
    if ("entropy" in t or "bias" in t) and ("window" in t or "marker" in t or "between" in t):
        return 2
    # global entropy/bias (still useful, but lower priority)
    if "entropy" in t or "bias" in t:
        return 3
    # coverage/missing/others last
    if "missing" in t or "coverage" in t:
        return 4
    return 5


def _micro_tune_event_filter(events: List[Any]) -> List[Any]:
    keep = []
    for ev in events:
        t = (getattr(ev, "type", "") or "").lower()
        if "marker" in t:
            keep.append(ev)
        elif t.startswith("target_"):
            keep.append(ev)
        elif "entropy" in t or "bias" in t:
            keep.append(ev)
        else:
            # 其他类型根据你实际情况决定是否保留
            keep.append(ev)
    return keep
# >>>

def _entropy_from_tf(true_cnt: int, false_cnt: int) -> float:
    total = true_cnt + false_cnt
    if total <= 0:
        return 0.0
    p = true_cnt / total
    if p <= 0.0 or p >= 1.0:
        return 0.0
    return -(p * math.log2(p) + (1.0 - p) * math.log2(1.0 - p))


def _infer_external_chain(filtered_metadata: Dict[str, Any]) -> List[str]:
    chain = filtered_metadata.get("external_chain", [])
    if isinstance(chain, list):
        return [str(x) for x in chain if x]
    return []

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

def _read_text_file(path: Path, max_len: int = 512) -> str:
    try:
        text = path.read_text(encoding="utf-8", errors="ignore")
        if len(text) > max_len:
            return text[:max_len] + "\n...[truncated]..."
        return text
    except Exception as e:
        logger.warning(f"[LLM_feedback] Failed to read seed file {path}: {e}")
        return ""

# [regularized fuzz judge] >>>
def add_to_regularized_fuzz(trace_summary: Dict[str, Any]) -> bool:
    root_api = trace_summary.get("root_api", "<unknown>")
    queue_traces = trace_summary.get("queue_traces", {})

    baseline_trace = trace_summary.get("baseline_trace")    # this part may be null

    queue_trace_agg_markers = queue_traces.get("aggregate", {}).get("markers", []) or []
    baseline_trace_agg_markers = baseline_trace.get("aggregate", {}).get("markers", []) or [] if baseline_trace else []
    total_num_traces = int(queue_traces.get("num_traces", 0) or 0) + int((baseline_trace.get("num_traces", 0) or 0) if baseline_trace else 0)

    bug_markers = []
    bug_marker_hit_rate = 0
    total_hit_times = 0
    
    for mk in queue_trace_agg_markers:
        tag = (mk.get("tag", "") or "").lower()
        if tag == "bug_point":
            bug_markers.append(mk)
        total_hit_times += mk.get("total_hits", 0) or 0

    for mk in baseline_trace_agg_markers:
        tag = (mk.get("tag", "") or "").lower()
        if tag == "bug_point":
            bug_markers.append(mk)
        total_hit_times += mk.get("total_hits", 0) or 0

    if bug_markers and total_num_traces > 0 and total_hit_times > 0:
        bug_marker_hit_rate = total_hit_times / total_num_traces if total_num_traces > 0 else 0.0
    
        if bug_marker_hit_rate >= 0.15:
            logger.info(f"[regularized_fuzz] Trace summary for root API {root_api} shows bug_point hit rate {bug_marker_hit_rate:.3f}, adding to regularized fuzz set.")
            regularized_fuzz_root_apis.add(root_api)
            return True
        else:
            return False
    
    return False

# <<<

def analyze_trace_summary_for_llm(trace_summary: Dict[str, Any], queue_seed_examples: List[Path], target_func_name: str) -> List[LLMEvent]:
    events: List[LLMEvent] = []

    root_api = trace_summary.get("root_api", "<unknown>")
    filtered_metadata_path = trace_summary.get("filtered_metadata_path", "")
    queue_traces = trace_summary.get("queue_traces", {})
    queue_stats = trace_summary.get("queue_coverage_category_stats", {})

    baseline_trace = trace_summary.get("baseline_trace")    # this part may be null

    with open(filtered_metadata_path, "r", encoding="utf-8") as f:
        filtered_metadata: Dict[str, Any] = json.load(f)

    func_index: Dict[Tuple[int, int], Dict[str, Any]] = {}
    external_chain = _infer_external_chain(filtered_metadata)

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
    # [fine2] A target reachability and chain progress distribution analysis <<<
    per_traces: Dict[str, Any] = queue_traces.get("per_trace", {})
    if per_traces and external_chain and target_func_name:
        idx_map = {name: i for i, name in enumerate(external_chain)}
        depth_hist = defaultdict(int)
        reached_target_ids: List[str] = []
        not_reached_ids: List[str] = []

        reached_target_count = 0
        total = 0

        for tid, info in per_traces.items():
            reached_names = {str(x.get("name", "")) for x in info.get("reached_functions", []) if x}
            max_idx = -1
            for n in reached_names:
                if n in idx_map:
                    max_idx = max(max_idx, idx_map[n])
            depth_hist[max_idx] += 1
            total += 1

            if target_func_name in reached_names:
                reached_target_count += 1
                if len(reached_target_ids) < 5:
                    reached_target_ids.append(tid)
            else:
                if len(not_reached_ids) < 5:
                    not_reached_ids.append(tid)
        
        rate = (reached_target_count / total) if total > 0 else 0.0

        hist_lines: List[str] = []
        for k in sorted(depth_hist.keys()):
            if k < 0:
                label = "no_chain_hit"
            else:
                label = f"max_chain_index={k} function={external_chain[k]}"
            c = depth_hist[k]
            pct = (c / total * 100.0) if total > 0 else 0.0
            hist_lines.append(f"- {label} count={c} pct={pct:.1f}%")    # This calculates the proportion of each call chain's execution depth across all traces
        
        details = (
            f"External chain length {len(external_chain)}\n"
            f"Target function {target_func_name}\n"
            f"Replay queue traces {total}\n"
            f"Target reach traces {reached_target_count} reach_rate={rate:.1%}\n"
            f"Max chain progress distribution\n"
            + "\n".join(hist_lines)
        )

        if rate >= 0.6:
            foucs = (
                "Most queue seeds already reach the target function. Focus on fine-grained adjustments to flip "
                "single-sided branches inside the target function, while keeping the existing call-chain prefix stable."
            )
        elif rate >= 0.2:
            foucs = (
                "A non-trivial portion of seeds reach the target function but many still do not. First stabilize "
                "reachability to target by fixing input structure and prerequisites, then optimize target-internal branches."
            )
        else:
            foucs = (
                "Only a small portion of seeds reach the target function. Prioritize harness correctness and seed structure "
                "so execution can progress further along the external chain toward the target function."
            )
        
        
        events.append(
            LLMEvent(
                type="target_reach_rate_and_chain_progress",
                short_summary="Target reachability rate and how far queue seeds progress along the external chain.",
                details=details,
                suggested_foucs=foucs,
            )
        )
        
    # >>>

    # [fine3] marker-based analysis <<<
    agg_markers = queue_traces.get("aggregate", {}).get("markers", []) or []
    num_traces = int(queue_traces.get("num_traces", 0) or trace_summary.get("num_traces", 0) or 0)
    if num_traces <= 0:
        num_traces = sum(queue_stats.values()) if queue_stats else 0

    bug_markers = []
    for mk in agg_markers:
        tag = (mk.get("tag", "") or "").lower()
        if tag == "bug_point":
            bug_markers.append(mk)

    if bug_markers and num_traces > 0:
        logger.info(f"[LLM_feedback] BUG_POINT MARKERS DETECTED!")
        lines = []
        total_hit_rates = []
        for mk in bug_markers[:5]:
            hit_tr = int(mk.get("hit_traces", 0))
            hit_rate = hit_tr / float(num_traces) if num_traces else 0.0
            total_hit_rates.append(hit_rate)
            f = mk.get("file", "")
            ln = int(mk.get("line", 0))
            lines.append(f"- bug_point @ {f}:{ln} hit_traces={hit_tr}/{num_traces} (hit_rate={hit_rate:.3f})")
        
        if len(total_hit_rates) > 0 and all(total_hit_rates[i] < 0.05 for i in range(len(total_hit_rates))):
            details = (
                "We instrumented explicit BUG-POINT markers at specific source locations (file:line). "
                "The following marker reachability was observed when replaying fuzzer queue seeds:\n"
                + "\n".join(lines)
            )

            first = bug_markers[0]
            snippet = load_source_snippet(first.get("file", ""), int(first.get("line", 0)), context=3)
            if snippet:
                details += "\n\n[Source snippet of the first bug_point marker]\n" + snippet

            foucs = (
                "Many inputs may already reach the target function, but a much smaller portion reaches the bug-point marker. "
                "Please micro-tune seeds (preferred) or minimally adjust the harness to satisfy the exact guard conditions "
                "near the bug point. Preserve the existing input prefix/path that reaches the target."
            )

            events.append(LLMEvent(
                type="bug_point_marker_reachability",
                short_summary="Reach rate of explicit bug-point markers (file:line) during replay.",
                details=details,
                suggested_foucs=foucs
            ))

    per_tr = queue_traces.get("per_trace", {}) or {}
    if agg_markers and per_tr:
        # furthest marker = last element in marker_seq (by first occurrence order)
        furthest_cnt = {}
        for _, info in per_tr.items():
            seq = info.get("marker_seq", []) or []
            if not seq:
                continue
            last = seq[-1]
            key = f'{last.get("tag","")}@{last.get("file","")}:{last.get("line",0)}'
            furthest_cnt[key] = furthest_cnt.get(key, 0) + 1

        if furthest_cnt:
            top = sorted(furthest_cnt.items(), key=lambda kv: kv[1], reverse=True)[:5]
            lines = [f"- {k} : {v} traces" for k, v in top]
            details = (
                "We summarize the most common *furthest* marker reached per trace (based on marker_seq). "
                "This indicates where executions tend to stop progressing.\n" + "\n".join(lines)
            )
            foucs = (
                "Please focus on pushing executions beyond the most common furthest marker: "
                "adjust seed structure/fields to satisfy subsequent checks; if needed, expose a small input-controlled "
                "parameter in the harness but keep the call chain and resource lifecycle unchanged."
            )
            events.append(LLMEvent(
                type="marker_bottleneck_summary",
                short_summary="Most common furthest marker reached (helps locate bottleneck stage).",
                details=details,
                suggested_foucs=foucs
            ))
    # >>>

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
            snippet = load_source_snippet(file, line_no, context=3)

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
            snippet = load_source_snippet(file, line_no, context=3)

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

    # [fine2] target-internal branch entropy and conditional bias <<<
    if per_traces and target_func_name and filtered_metadata.get("functions"):
        target_gids: Set[int] = set()
        for f in filtered_metadata.get("functions", []):
            try:
                if str(f.get("name", "")) == target_func_name:
                    target_gids.add(int(f["global_id"]))
            except Exception as e:
                continue
        
        if target_gids:
            cond_branch: Dict[Tuple[int, int], Dict[str, Any]] = {}
            reached_target_trace_ids: Set[str] = set()

            for tid, info in per_traces.items():
                reached_names = {str(x.get("name", "")) for x in info.get("reached_functions", []) if x}
                if target_func_name not in reached_names:
                    continue
                reached_target_trace_ids.add(tid)

                for b in info.get("branches", []):      # only consider branches reached in traces that hit the target function
                    try:
                        fg = int(b.get("func_global_id", -1))
                    except Exception:
                        fg = -1
                    if fg not in target_gids:
                        continue

                    try:
                        key = (int(b["module_id"]), int(b["local_id"]))
                        ht = int(b.get("hist_true", 0))
                        hf = int(b.get("hist_false", 0))
                    except Exception:
                        continue

                    st = cond_branch.setdefault(key, {"true": 0, "false": 0, "hist_traces": set()})     # only analyze target-internal branches
                    st["true"] += ht
                    st["false"] += hf
                    st["hist_traces"].add(tid)
            
            if reached_target_ids and cond_branch:
                low_entropy  = []
                regressions = []

                for key, st in cond_branch.items():
                    t = int(st["true"])
                    f = int(st["false"])
                    total_hits = t + f
                    if total_hits <= 0:
                        continue
                    H = _entropy_from_tf(t, f)
                    st["entropy"] = H
                    st["total"] = total_hits
                    low_entropy.append((H, -total_hits, key, st))

                    base = baseline_branch_map.get(key)
                    if base:
                        bt, bf = int(base.get("true", 0)), int(base.get("false", 0))
                        if (bt > 0 and bf > 0) and ((t == 0) ^ (f == 0)):   # always one-sided in queue traces
                            regressions.append((key, st, base))
                
                low_entropy.sort()      # ascending by entropy
                regressions.sort(key=lambda x: -(x[1].get("total", 0)))   # descending by total hits

                preview_low = low_entropy[:5]
                preview_reg = regressions[:5]

                line_low: List[str] = []
                for H, _, key, st in preview_low:
                    meta = st["meta"]
                    file = st.get("file", "?")
                    line_no = int(st.get("line", 0))
                    snippet = load_source_snippet(file, line_no, context=3)
                    line_low.append(f"- {file}:{line_no} entropy={H:.3f} true={st['true']} false={st['false']}\n Source snippet: {snippet}")
                
                details = (
                    f"Target function {target_func_name}\n"
                    f"Conditioned on reached-target traces {len(reached_target_trace_ids)}\n"
                    f"Low-entropy branches inside target function\n"
                    + "\n\n".join(line_low)
                )

                if preview_reg:
                    line_reg: List[str] = []
                    for key, st, base in preview_reg:
                        meta = st["meta"]
                        file = st.get("file", "?")
                        line_no = int(st.get("line", 0))
                        snippet = load_source_snippet(file, line_no, context=3)
                        line_reg.append(
                            f"- {file}:{line_no} baseline true={base['true']} false={base['false']} "
                            f"cond true={st['true']} false={st['false']}\n Source snippet: {snippet}"
                        )
                    details += "\n\nRegressions baseline seeds execute two-sided but conditioned target-run single-sided\n" + "\n\n".join(line_reg)
                
                foucs = (
                    "Make fine-grained seed or harness adjustments that preserve reaching the target function, "
                    "then flip the listed low-entropy branches. Focus on parameters, flags, sizes, and field constraints "
                    "that gate alternative paths inside the target function."
                )

                events.append(
                    LLMEvent(
                        type="target_branch_entropy_bias",
                        short_summary="Within reached-target traces, some branches inside target function stay low-entropy or regress from baseline.",
                        details=details,
                        suggested_foucs=foucs,
                    )
                )
    # >>>

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
    target_func_name: str,
    harness_path: Optional[str] = None,
    baseline_seeds: Optional[List[Path]] = None,
    queue_seed_examples: Optional[List[Path]] = None,
    harness_memory_text: Optional[str] = None,
) -> str:
    root_api = trace_summary.get("root_api", "<unknown>")
    plan = Path(batch.harness_info.get("harness_plans_files", "{}"))
    plan = json.loads(plan.read_text(encoding="utf-8", errors="ignore")).get(root_api, {})
    call_chain = plan.get("chain", {}).get("id", "<unknown>")
    events = [] if harness_memory_text else analyze_trace_summary_for_llm(trace_summary, queue_seed_examples, target_func_name)

    lines: List[str] = []

    lines.append(
        f"You are helping to improve a fuzzing harness and seed corpus for a C library named: {batch.lib_name}.The purpose of this harness and seed courpus is to verify and reproduce a specific bug(or vulnerability) within this library through fuzzing."
        f"that contains a call chain: {call_chain} which starts from {root_api} and whose ultimate target function is "
        f"`{batch.target_func}` (ignoring suffixes such as __internal_alias after the function name).\n"
        f"We collected runtime traces by replaying both baseline seeds and sampled fuzzer queue seeds "
        f"on a trace-instrumented version of the target library."
    )
    lines.append("")

    lines.append("=== Your task and output format (MUST FOLLOW) ===")
    lines.append(
        "Your task:\n"
        "- You may modify ONLY the harness code, ONLY the seeds, or BOTH.\n"
        "- The current harness was already generated with vulnerability(or bug)-aware structural constraints. " \
        "Do not discard the existing semantic input-role separation unless runtime trace evidence strongly indicates the current structure is fundamentally wrong." \
        "Prefer localized repairs over structural simplification; "
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
        "- You MUST reply with a **single JSON object** and nothing else (no explanations, no markdown, no comments).\n"
        "- The JSON structure must be exactly ONE of the following forms:\n"
        "  1) If you ONLY need to modify the seeds(if there are serval seeds you want to modify, the key is like seedn), reply as:\n"
        '     { "seed1": "<BASE64 FULL seed bytes>" ,\n' 
        '       "seed2": "<BASE64 FULL seed bytes>" ...}\n'
        "  2) If you ONLY need to modify the harness, reply as:\n"
        '     { "harness": "<FULL harness C source code>",\n'
        '       "compile_command": "<the compile command, e.g., \'aflgo-clang -g -O2 a.c -o a.out $(pkg-config --cflags --libs libxml-2.0)\'>" }\n"'
        "  3) If you need to modify BOTH, reply as:\n"
        '     { "seed": "<BASE64 FULL seed bytes>",\n'
        '       "harness": "<FULL harness C source code>",\n'
        '       "compile_command": "<the compile command>" }\n\n'
        "- Whenever you output a harness, you MUST also provide a valid compile_command in the same JSON object.\n"
        "- Every seed you output must be base64-encoded complete seed bytes."
        "- The compile_command should follow the pattern:\n"
            "* use aflgo-clang (or afl-clang-fast/afl-clang) as the compiler,"
            "* refer to the harness file as a.c and the output as a.out, e.g.:\n"
        "    aflgo-clang -g -O2 a.c -o a.out $(pkg-config --cflags --libs <PKG_NAME>)\n"
        '  Use the appropriate pkg-config name for the target library (e.g., "libxml-2.0") based on the harness and plan, and DO NOT replace placeholders like a.c and a.out with anything else. \n'
        "  If you need to add sanitizer-related options like '-fsanitize=address, undefined', add them to the compilation command (but be aware of the availability of the compilation command,hat is, DO NOT add them if they are not necessary)."
        "- The seed and harness values must each contain the COMPLETE content (not a diff, not a partial snippet).\n"
        "- To keep the response compact, avoid unnecessary comments and blank lines in the harness and seed, "
        "while keeping them correct and readable.\n"
        "- Do NOT add any other keys, fields, text, or symbols outside this JSON object.\n"
        "- Do NOT wrap the JSON in code fences. Reply with RAW JSON only."
    )
    # [cve_helper] CVE hints block (if applicable) <<<
    cve_block = render_cve_hints_for_upgrade(getattr(batch, "cve_hints", {}) or {})
    if cve_block:
        lines.append(cve_block)
    # >>>

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
    if harness_memory_text:
        lines.append(harness_memory_text)
    else:
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

def build_llm_micro_tune_prompt(
    batch: Batch,
    trace_summary: Dict[str, Any],
    target_func_name: str,
    harness_path: Optional[str] = None,
    baseline_seeds: Optional[List[Path]] = None,
    queue_seed_examples: Optional[List[Path]] = None,
    harness_memory_text: Optional[str] = None,
) -> str:

    root_api = trace_summary.get("root_api", "<unknown>")
    target_func = batch.target_func
    plan_path = batch.harness_info.get("harness_plans_files", "{}")
    plan = json.loads(Path(plan_path).read_text(encoding="utf-8", errors="ignore")).get(root_api, {})
    call_chain = plan.get("chain", {}).get("id", "<unknown>")

    reach_stats = trace_summary.get("target_reach_stats", {}) or {}
    total_traces = int(reach_stats.get("total_traces", 0) or 0)
    reached_traces = int(reach_stats.get("reached_traces", 0) or 0)
    reach_rate = float(reach_stats.get("reach_rate", 0.0) or 0.0)
    mode = trace_summary.get("target_reach_mode", "micro")
    
    #[fine3] target function source code + bug-point locations <<<
    targets_file = os.environ.get("TRACE_MARKER_TARGETS_FILE", "").strip()
    target_func_source_code = extract_target_func_code_from_plan(plan, target_func)
    bug_points = parse_target_file(targets_file, plan, target_func)
    bug_point_source_code_snippets: List[Tuple[str, int, str]] = []
    for f, ln in bug_points:
        snippet = load_source_snippet(f, ln, context=4)
        if snippet:
            bug_point_source_code_snippets.append((f, ln, clip_text(snippet, max_chars=1500)))
    # >>>

    marker_kpi_block = _marker_build_kpi_block(trace_summary)

    events = [] if harness_memory_text else analyze_trace_summary_for_llm(trace_summary, queue_seed_examples, target_func_name)

    # [MOD] 事件过滤 + 排序：marker 先，target_ 次之，windowed entropy/bias 再次
    events = _micro_tune_event_filter(events)
    events_sorted: List[LLMEvent] = sorted(events, key=_micro_tune_event_rank) if events else []

    lines: List[str] = []

    # Intro
    lines.append(
        f"You are helping to MICRO-TUNE a fuzzing harness and seed corpus for a C library named: {batch.lib_name}. The purpose of this harness and seed courpus is to verify and reproduce a specific bug(or vulnerability) within this library through fuzzing."
        f"The harness starts from root API '{root_api}' and targets the call chain '{call_chain}', with ultimate target function "
        f"`{batch.target_func}`.\n"
        f"We collected runtime traces by replaying baseline seeds and sampled fuzzer queue seeds on a trace-instrumented build.\n"
        f"This round is MICRO-TUNE mode. Even if bug-point markers are not hit yet, the objective is to make progress "
        f"towards the bug point inside/around the target while preserving target reachability."
    )
    lines.append("")

    # Task & output format
    lines.append("=== Your task and output format (MUST FOLLOW) ===")
    lines.append(
        "Your task (MICRO-TUNE, marker-driven):\n"
        f"- Keep the ability to reach the target function `{batch.target_func}` (ignoring suffixes such as __internal_alias after the function name) (do not break the working path).\n"
        "- The current harness was already generated with vulnerability(or bug)-aware structural constraints. " \
        "Do not discard the existing semantic input-role separation unless runtime trace evidence strongly indicates the current structure is fundamentally wrong." \
        "Prefer localized repairs over structural simplification; "
        "- **YOUR PRIMARY GOAL**: To improve the reproducibility of the given vulnerabilities in this harness. (given below).\n"
        "- Identify 1~3 biased / low-entropy branches that BLOCK progress beyond the current furthest_marker or prevent reaching bug_point, "
        "and propose minimal changes that flip them.\n"
        "- Prefer seed-only changes first. Only modify the harness if you need to expose a small piece of fuzz input to a critical parameter.\n"
        "- Any harness change MUST be small and localized: keep the call-chain structure, resource lifecycle, and overall main() structure unchanged.\n"
        "- Do NOT optimize for generic coverage. Optimize only for advancing marker progress and reaching bug_point.\n\n"
        "Output format requirements:\n"
        "- You MUST reply with a single JSON object and nothing else.\n"
        "- The JSON structure must be exactly ONE of these forms:\n"
        "  1) { \"seed1\": \"<BASE64 FULL seed bytes>\", \"seed2\": \"<BASE64 FULL seed bytes>\", ... }     (seeds only)\n"
        "  2) { \"harness\": \"<FULL harness C source code>\", \"compile_command\": \"<compile cmd>\" }     (harness only)\n"
        "  3) { \"seed1\": \"<BASE64 FULL seed bytes>\", \"seed2\": \"<BASE64 FULL seed bytes>\", ..., \"harness\": \"<FULL harness C source code>\", \"compile_command\": \"<compile cmd>\" }     (both)\n"
        "- Whenever you output a harness, you MUST also provide a valid compile_command in the same JSON object.\n"
        "- Every seed you output must be base64-encoded complete seed bytes."
        "- The compile_command should follow the pattern:\n"
            "* use aflgo-clang (or afl-clang-fast/afl-clang) as the compiler,"
             "* refer to the harness file as a.c and the output as a.out, e.g.:\n"
        "    aflgo-clang -g -O2 a.c -o a.out $(pkg-config --cflags --libs <PKG_NAME>)\n"
        "  If you need to add sanitizer-related options like '-fsanitize=address, undefined', add them to the compilation command (but be aware of the availability of the compilation command,hat is, DO NOT add them if they are not necessary)."
        '  Use the appropriate pkg-config name for the target library (e.g., "libxml-2.0") based on the harness and plan, and DO NOT replace placeholders like a.c and a.out.\n'
        "- The seed and harness values must each contain the COMPLETE content (not a diff, not a partial snippet).\n"
        "- Keep the response compact: avoid unnecessary comments/blank lines while keeping correctness.\n"
        "- Do NOT add any other keys, fields, text, or symbols outside this JSON object.\n"
        "- Do NOT wrap the JSON in code fences. Reply with RAW JSON only."
    )
    lines.append("")

    # [cve_helper] CVE hints block (if applicable) <<<
    cve_block = render_cve_hints_for_upgrade(getattr(batch, "cve_hints", {}) or {})
    if cve_block:
        lines.append(cve_block)
    # >>>

    # [fine3] bug_point source code and something related <<<
    if target_func_source_code:
        lines.append("=== Target function context (from plan, for semantic guidance) ===")
        lines.append("```c")
        lines.append(target_func_source_code)
        lines.append("```")
        lines.append("")
    
    if bug_point_source_code_snippets:
        lines.append("=== Bug-point locations (Your PRIMARY task is to be able to reach the point where this bug occurs) ===")
        for f, ln, snip in bug_point_source_code_snippets:
            lines.append(f"- bug_point: {f}:{ln}")
            if snip:
                lines.append("```text")
                lines.append(snip)
                lines.append("```")
        lines.append(
            "Guidance: Treat these bug-point locations as milestone objectives. If current traces do not reach them, "
            "adjust seeds/harness minimally to satisfy the required guards/structure that lead execution into these regions."
        )
        lines.append("")
    # >>>

    # Target reach status
    if total_traces > 0:
        lines.append("=== Target reach status (MUST NOT DEGRADE) ===")
        lines.append(
            f"Replayed queue seeds: total={total_traces}, reached_target={reached_traces}, reach_rate={reach_rate:.3f}."
        )
        ex_r = reach_stats.get("example_reached_trace_ids", []) or []
        ex_u = reach_stats.get("example_unreached_trace_ids", []) or []
        if ex_r:
            lines.append(f"Example reached trace ids: {', '.join(ex_r)}")
        if ex_u:
            lines.append(f"Example unreached trace ids: {', '.join(ex_u)}")
        lines.append(
            "Guidance: DO NOT make changes that reduce the target reach rate. Preserve the existing prefix/path that reaches the target."
        )
        lines.append("")

    # Marker milestone status (insert right after target reach)
    if marker_kpi_block:
        lines.append(marker_kpi_block)
        lines.append("")

    # Harness
    if harness_path:
        try:
            h_text = Path(harness_path).read_text(encoding="utf-8", errors="ignore")
        except Exception as e:
            logger.warning(f"[LLM_feedback] Failed to read harness file {harness_path}: {e}")
            h_text = ""
        if h_text:
            lines.append("=== Current harness source code (the harness code we are using now) ===")
            lines.append("```c")
            lines.append(h_text)
            lines.append("```")
            lines.append("")

    # Baseline seeds (good prefixes)
    if baseline_seeds:
        lines.append("=== Example baseline seeds (good prefixes that usually reach the chain/target) ===")
        for p in baseline_seeds[-3:]:
            snippet = _read_text_file(p, max_len=4096)
            lines.append(f"- Baseline seed file: {p.name}")
            if snippet:
                lines.append("```text")
                lines.append(snippet)
                lines.append("```")
        lines.append("")

    # High-level observations (marker events should come first by rank)
    lines.append("=== High-level observations from runtime traces ===")
    if harness_memory_text:
        lines.append(harness_memory_text)
    else:
        lines.append("Use the following observations to steer MICRO-TUNING. Keep the focus on marker progress and target-internal gating conditions.\n")
        for ev in events_sorted:
            lines.append(f"- [{ev.type}] {ev.short_summary}")
        lines.append("")

        # Technical details
        lines.append("=== Technical details ===")
        lines.append("Below are detailed analyses extracted from the runtime trace data:\n")
        for ev in events_sorted:
            lines.append(f"[*] {ev.type}:")
            lines.append(ev.details)
            lines.append("")
        lines.append("")

        # Focus list (marker first, entropy/bias second)
        lines.append("=== What you should focus on ===")
        lines.append(
            "Prioritize these MICRO-TUNE objectives:\n"
            "1) Preserve target reachability (do not reduce reach_rate).\n"
            "2) Advance marker progress (furthest_marker -> bug_point) and improve bug_point hit_rate.\n"
            "3) Flip biased / low-entropy branches that block marker progress (prefer windowed/marker-related signals).\n"
            "4) Keep changes minimal and controlled; prefer seed edits over harness rewrites.\n"
        )
        for ev in events_sorted:
            lines.append(f"- ({ev.type}) {ev.suggested_foucs}")
    lines.append("")

    return "\n".join(lines)