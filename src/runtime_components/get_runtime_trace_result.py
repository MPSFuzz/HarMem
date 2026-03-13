import os
import json
import random
import subprocess
import shutil

from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import List, Dict, Any, Optional, Tuple, Set

from src.batch.batch_class import Batch
from src.utils.utils import get_logger

logger = get_logger(__name__)

@dataclass
class TraceConfig:
     
    cc: str = os.environ.get("TRACE_CC", "clang")
    cxx: str = os.environ.get("TRACE_CXX", "clang++")
    cflags: str = os.environ.get("TRACE_CFLAGS", "-g -O0")

    trace_pkg_name = os.environ.get("TRACE_PKG_NAME", "")
    trace_libdir = os.environ.get("TRACE_LIBDIR", "") # the actual path to the library which is instrumented by trace pass

    num_recent: int = int(os.environ.get("TRACE_NUM_RECENT", "5"))
    num_random: int = int(os.environ.get("TRACE_NUM_RANDOM", "5"))

def _parse_ys_fields_from_stderr(stderr_text: str) -> Dict[str, str]:   # for controllability_report, optional, can be used to extract some custom fields from trace binary's stderr output
    """
    Parse lines like:
      YS_FIELD pattern=...
    Returns dict field->value (last one wins).
    """
    out: Dict[str, str] = {}
    if not stderr_text:
        return out
    for line in stderr_text.splitlines():
        line = line.strip()
        if not line.startswith("YS_FIELD"):
            continue
        # support: "YS_FIELD key=value"
        parts = line.split(None, 1)
        if len(parts) != 2:
            continue
        kv = parts[1]
        if "=" not in kv:
            continue
        k, v = kv.split("=", 1)
        k = k.strip()
        v = v.strip()
        if k:
            out[k] = v
    return out

# a helper function to extract reached function set from per-trace entry
def _extract_reached_func_set(per_trace_entry: Dict[str, Any]) -> Set[Tuple[int, int]]:
    s = set()
    for f in per_trace_entry.get("reached_functions", []):
        s.add((int(f["module_id"]), int(f["local_id"])))
    return s

def _clean_up_trace_dir(base_path: Path):
    trace_files_path = base_path / "runtime_trace_information"
    if trace_files_path.exists():
        if trace_files_path.is_dir():
            shutil.rmtree(trace_files_path)
        else:
            trace_files_path.unlink()
            
    trace_files_path.mkdir(parents=True, exist_ok=True)
    logger.info(f"[Trace] Cleaned up trace output directory at {trace_files_path}")

# compile harness with tracing instrumentation
def compile_trace_binary(batch: Batch, root_api: str, t_config: TraceConfig) -> Path:
    try:
        pkg_cflags = subprocess.check_output(
            ["pkg-config", "--cflags", t_config.trace_pkg_name],
            text=True
        ).strip()
        pkg_libs = subprocess.check_output(
            ["pkg-config", "--libs", t_config.trace_pkg_name],
            text=True
        ).strip()
    except subprocess.CalledProcessError as e:
        logger.error(f"[runtime components] Error occurred while checking pkg-config: {e}")
        raise RuntimeError
    
    harness_path: str = batch.harness_info.get("harness_files", "").get(root_api, "")
    trace_out_dir = Path(harness_path).parent / "trace_out"
    trace_out_dir.mkdir(parents=True, exist_ok=True)
    harness_id = Path(harness_path).stem
    trace_binary_path = trace_out_dir / f"trace_{harness_id}"

    try:
        cmd = [
            t_config.cc,
            *t_config.cflags.split(),
            str(harness_path),
            *pkg_cflags.split(),
            *pkg_libs.split(),
            f"-Wl,-rpath,{t_config.trace_libdir}",
            "-Wl,--disable-new-dtags",
            "-o", str(trace_binary_path)
        ]
        subprocess.check_call(cmd)
        logger.info(f"[Trace] Compiled trace binary at {trace_binary_path}")

        return trace_binary_path
        
    except subprocess.CalledProcessError as e:
        logger.error(f"Error compiling trace binary: {e}")
        raise RuntimeError

# sampling fuzzer out queue 
# first, sorted by modification time, take num_recent most recent files
# then, randomly sample num_random files from the rest
def sample_fuzzer_queue_cases(harness_path: str, t_config: TraceConfig) -> List[Path]:
    queue_path = Path(os.path.join(os.path.dirname(harness_path), "out", "queue"))
    if not queue_path.is_dir():
        logger.error(f"Fuzzer queue path does not exist: {queue_path}")
        raise FileNotFoundError
    
    cases = [c for c in queue_path.iterdir() if c.is_file()]
    if not cases:
        logger.error(f"No cases found in fuzzer queue: {queue_path}")
        raise FileNotFoundError

    cases.sort(key=lambda c: c.stat().st_mtime, reverse=True)
    recent_cases = cases[:t_config.num_recent]
    
    remaining = cases[t_config.num_recent:]
    random.shuffle(remaining)
    remaining_cases = remaining[:t_config.num_random]

    sampled_cases = recent_cases + remaining_cases

    logger.info(f"[Trace] Sampled {len(sampled_cases)} cases from fuzzer queue")
    
    return sampled_cases

# run trace binary on sampled cases and collect trace information
def run_trace_on_sampled_cases(sampled_case: List[Path], trace_binary_path: Path, t_config: TraceConfig) -> List[Path]:
    trace_json: List[Path] = []

    trace_output_dir = trace_binary_path.parent / "runtime_trace_information"

    for case in sampled_case:
        trace_json_output_name = trace_output_dir /f"trace_{case.name}.json"
        trace_stderr_output_name = trace_output_dir /f"trace_{case.name}.stderr"    # for controllability_report
        trace_json_output_name.parent.mkdir(parents=True, exist_ok=True)
        env = os.environ.copy()
        env["TRACE_RUNTIME_OUTPUT"] = str(trace_json_output_name)

        cmd = [str(trace_binary_path), str(case)]

        try:
            # subprocess.run(cmd, env=env)
            # capture stderr for controllability analysis; does not affect normal fuzzing.
            r = subprocess.run(cmd, env=env, capture_output=True, text=True)
            if r.stderr:
                try:
                    trace_stderr_output_name.write_text(r.stderr, encoding="utf-8", errors="ignore")
                except Exception:
                    pass

            if trace_json_output_name.exists():
                trace_json.append(trace_json_output_name)
            else:
                logger.warning(f"[Trace] Trace binary exit normally but no output generated for case {case}")
        except OSError as e:
            logger.error(f"[Trace] Error running trace binary on case {case}: {e}")
            continue
    
    logger.info(f"[Trace] Collected trace json for {len(trace_json)} cases")
    
    return trace_json

# collect trace information from json files
def collect_trace_information(trace_json_files: List[Path], filtered_metadata_path: str) -> Dict[str, Any]:
    filtered_metadata = json.load(open(filtered_metadata_path, "r", encoding="utf-8"))

    root_api = filtered_metadata.get("root_api", "<unknown>")
    external_chain = filtered_metadata.get("external_chain", [])
    callee_depth = int(filtered_metadata.get("callee_depth", 0) or 0)

    func_gid_to_name: Dict[int, str] = {}
    for f in filtered_metadata.get("functions", []):
        try:
            gid = int(f.get("global_id"))
            func_gid_to_name[gid] = str(f.get("name", ""))
        except Exception:
            continue

    func_meta_map: Dict[tuple, dict] = {}
    branch_meta_map: Dict[tuple, dict] = {}
    call_meta_map: Dict[tuple, dict] = {}
    marker_meta_map: Dict[tuple, dict] = {}

    for f in filtered_metadata.get("functions", []):
        key = (int(f["module_id"]), int(f["local_id"]))
        func_meta_map[key] = f

    for b in filtered_metadata.get("branches", []):
        key = (int(b["module_id"]), int(b["local_id"]))
        branch_meta_map[key] = b

    for c in filtered_metadata.get("calls", []):
        key = (int(c["module_id"]), int(c["local_id"]))
        call_meta_map[key] = c
    
    for mk in filtered_metadata.get("markers", []):
        key = (int(mk["module_id"]), int(mk["local_id"]))
        marker_meta_map[key] = mk

    logger.info(
        f"[Trace] Built metadata maps: funcs={len(func_meta_map)}, "
        f"branches={len(branch_meta_map)}, calls={len(call_meta_map)}, markers={len(marker_meta_map)}"
    )

    func_agg_map: Dict[tuple, Dict[str, Any]] = {}
    for key, meta in func_meta_map.items():
        func_agg_map[key] = {
            "meta": meta,
            "total_enters": 0,
            "hit_traces": set()
        }

    branch_agg_map: Dict[tuple, Dict[str, Any]] = {}
    for key, meta in branch_meta_map.items():
        branch_agg_map[key] = {
            "meta": meta,
            "total_true": 0,
            "total_false": 0,
            "hit_traces": set()
        }

    call_agg_map: Dict[tuple, Dict[str, Any]] = {}
    for key, meta in call_meta_map.items():
        call_agg_map[key] = {
            "meta": meta,
            "total_calls": 0,
            "hit_traces": set()
        }

    # marker aggregation for future marker instrumentation (kind==4)
    marker_agg_map: Dict[int, Dict[str, Any]] = {}
    for key, meta in marker_meta_map.items():
        marker_agg_map[key] = {
            "meta": meta,
            "total_hits": 0,
            "hit_traces": set()
        }

    per_trace: Dict[str, Any] = {}
    for trace_file in trace_json_files:
        trace_id = trace_file.stem
        try:
            data = json.loads(trace_file.read_text(encoding="utf-8"))
        except Exception as e:
            logger.warning(f"[Trace] Failed to parse trace json {trace_file} with error: {e}")
            continue

        # optional: parse harness-provided fields from stderr sidecar
        ys_fields: Dict[str, str] = {}
        try:
            stderr_path = trace_file.with_suffix(".stderr")
            if stderr_path.exists():
                stderr_text = stderr_path.read_text(encoding="utf-8", errors="ignore")
                ys_fields = _parse_ys_fields_from_stderr(stderr_text)
        except Exception:
            ys_fields = {}

        events = data.get("events", [])
        if not isinstance(events, list) or not events:
            logger.warning(f"[Trace] Invalid events format in trace file {trace_file}")
            continue

        funcs_hit_in_this_trace = set()
        branches_hit_in_this_trace = set()
        calls_hit_in_this_trace = set()
        markers_hit_in_this_trace: Set[int] = set()
        marker_hit_counts = defaultdict(int)
        marker_first_pos = {} # marker_id -> first position in events

        branch_tf_counts: Dict[tuple, Dict[str, int]] = defaultdict(lambda: {"true": 0, "false": 0})

        for idx, ev in enumerate(events):
            try:
                kind = int(ev.get("kind", 0))
                mod_id = int(ev.get("module_id", 0))
                func_id = int(ev.get("func_id", 0))
                aux_id = int(ev.get("aux_id", 0))
                aux_val1 = ev.get("aux_val1", 0)
            except Exception:
                continue

            if kind in (0, 1):
                key = (mod_id, func_id)
                if key in func_agg_map:
                    if kind == 0:
                        func_agg_map[key]["total_enters"] += 1
                    funcs_hit_in_this_trace.add(key)

            elif kind == 2:
                bkey = (mod_id, aux_id)
                if bkey in branch_agg_map:
                    taken = 1 if int(aux_val1) != 0 else 0
                    if taken:
                        branch_agg_map[bkey]["total_true"] += 1
                        branch_tf_counts[bkey]["true"] += 1
                    else:
                        branch_agg_map[bkey]["total_false"] += 1
                        branch_tf_counts[bkey]["false"] += 1
                    branches_hit_in_this_trace.add(bkey)

            elif kind == 3:
                ckey = (mod_id, aux_id)
                if ckey in call_agg_map:
                    call_agg_map[ckey]["total_calls"] += 1
                    calls_hit_in_this_trace.add(ckey)

            elif kind == 4:
                mkey = (mod_id, aux_id)     # aux_id == marker_id
                if mkey in marker_agg_map:
                    marker_agg_map[mkey]["total_hits"] += 1
                    marker_hit_counts[mkey] += 1
                    markers_hit_in_this_trace.add(mkey)
                    if mkey not in marker_first_pos:
                        marker_first_pos[mkey] = idx

        for key in funcs_hit_in_this_trace:
            func_agg_map[key]["hit_traces"].add(trace_id)
        for key in branches_hit_in_this_trace:
            branch_agg_map[key]["hit_traces"].add(trace_id)
        for key in calls_hit_in_this_trace:
            call_agg_map[key]["hit_traces"].add(trace_id)
        for key in markers_hit_in_this_trace:
            marker_agg_map[key]["hit_traces"].add(trace_id)

        reached_func_list = []
        for key in funcs_hit_in_this_trace:
            meta = func_meta_map[key]
            reached_func_list.append({
                "module_id": meta["module_id"],
                "local_id": meta["local_id"],
                "global_id": meta.get("global_id"),
                "name": meta.get("name", ""),
                "file": meta.get("file", ""),
                "line": meta.get("line", 0),
            })

        branch_list = []
        for bkey in branches_hit_in_this_trace:
            meta = branch_meta_map[bkey]
            tf = branch_tf_counts[bkey]
            hits_true = tf["true"]
            hits_false = tf["false"]
            if hits_true > 0 and hits_false > 0:
                pattern = "both"
            elif hits_true > 0:
                pattern = "always_true"
            elif hits_false > 0:
                pattern = "always_false"
            else:
                pattern = "unknown"

            fg = meta.get("func_global_id", -1)
            try:
                fg_i = int(fg)
            except Exception:
                fg_i = -1

            branch_list.append({
                "module_id": meta["module_id"],
                "local_id": meta["local_id"],
                "func_global_id": fg_i,
                "func_name": func_gid_to_name.get(fg_i, ""),
                "file": meta.get("file", ""),
                "line": meta.get("line", 0),
                "hits_true": hits_true,
                "hits_false": hits_false,
                "pattern": pattern,
            })

        call_list = []
        for ckey in calls_hit_in_this_trace:
            meta = call_meta_map[ckey]
            from_gid = meta.get("from_func_global_id", -1)
            to_gid = meta.get("to_func_global_id", -1)
            try:
                from_gid_i = int(from_gid)
            except Exception:
                from_gid_i = -1
            try:
                to_gid_i = int(to_gid)
            except Exception:
                to_gid_i = -1

            call_list.append({
                "module_id": meta["module_id"],
                "local_id": meta["local_id"],
                "from_func_global_id": from_gid_i,
                "to_func_global_id": to_gid_i,
                "from_func_name": func_gid_to_name.get(from_gid_i, ""),
                "to_func_name": func_gid_to_name.get(to_gid_i, ""),
                "file": meta.get("file", ""),
                "line": meta.get("line", 0),
                "callee": meta.get("callee", ""),
            })
        
        marker_list = []
        seq = sorted(marker_first_pos.items(), key=lambda kv: kv[1])    # build seq by first occurrence
        marker_seq = []
        for mkey, _ in seq:
            meta = marker_meta_map[mkey]
            marker_seq.append({
                "module_id": meta["module_id"],
                "local_id": meta["local_id"],
                "tag": meta.get("tag", ""),
                "file": meta.get("file", ""),
                "line": meta.get("line", 0),
            })
        
        for mkey in markers_hit_in_this_trace:
            meta = marker_meta_map[mkey]
            marker_list.append({
                "module_id": meta["module_id"],
                "local_id": meta["local_id"],
                "tag": meta.get("tag", ""),
                "file": meta.get("file", ""),
                "line": meta.get("line", 0),
                "hits": int(marker_hit_counts.get(mkey, 0)),
                "first_pos": int(marker_first_pos.get(mkey, -1)),
            })

        per_trace[trace_id] = {
            "reached_functions": reached_func_list,
            "branches": branch_list,
            "calls": call_list,
            "markers": marker_list,
            "marker_seq": marker_seq,
            "ys_fields": ys_fields,   # for controllability_report, optional
        }

    aggregate_funcs = []
    for key, st in func_agg_map.items():
        meta = st["meta"]
        aggregate_funcs.append({
            "module_id": meta["module_id"],
            "local_id": meta["local_id"],
            "global_id": meta.get("global_id"),
            "name": meta.get("name", ""),
            "file": meta.get("file", ""),
            "line": meta.get("line", 0),
            "hit_traces": len(st["hit_traces"]),
            "hit_trace_ids": sorted(st["hit_traces"]),
            "total_enters": st["total_enters"]
        })

    aggregate_branches = []
    for key, st in branch_agg_map.items():
        meta = st["meta"]
        fg = meta.get("func_global_id", -1)
        try:
            fg_i = int(fg)
        except Exception:
            fg_i = -1

        aggregate_branches.append({
            "module_id": meta["module_id"],
            "local_id": meta["local_id"],
            "func_global_id": fg_i,
            "func_name": func_gid_to_name.get(fg_i, ""),
            "file": meta.get("file", ""),
            "line": meta.get("line", 0),
            "total_true": st["total_true"],
            "total_false": st["total_false"],
            "hit_traces": len(st["hit_traces"]),
            "hit_trace_ids": sorted(st["hit_traces"]),
        })

    aggregate_calls = []
    for key, st in call_agg_map.items():
        meta = st["meta"]
        from_gid = meta.get("from_func_global_id", -1)
        to_gid = meta.get("to_func_global_id", -1)
        try:
            from_gid_i = int(from_gid)
        except Exception:
            from_gid_i = -1
        try:
            to_gid_i = int(to_gid)
        except Exception:
            to_gid_i = -1

        aggregate_calls.append({
            "module_id": meta["module_id"],
            "local_id": meta["local_id"],
            "from_func_global_id": from_gid_i,
            "to_func_global_id": to_gid_i,
            "from_func_name": func_gid_to_name.get(from_gid_i, ""),
            "to_func_name": func_gid_to_name.get(to_gid_i, ""),
            "file": meta.get("file", ""),
            "line": meta.get("line", 0),
            "callee": meta.get("callee", ""),
            "total_calls": st["total_calls"],
            "hit_traces": len(st["hit_traces"]),
            "hit_trace_ids": sorted(st["hit_traces"]),
        })

    aggregate_markers = []
    for key, st in marker_agg_map.items():
        meta = st["meta"]
        aggregate_markers.append({
            "module_id": meta["module_id"],
            "local_id": meta["local_id"],
            "tag": meta.get("tag", ""),
            "file": meta.get("file", ""),
            "line": meta.get("line", 0),
            "total_hits": st["total_hits"],
            "hit_traces": len(st["hit_traces"]),
            "hit_trace_ids": sorted(st["hit_traces"]),
        })

    result: Dict[str, Any] = {
        "root_api": root_api,
        "external_chain": external_chain,
        "callee_depth": callee_depth,
        "num_traces": len(trace_json_files),
        "per_trace": per_trace,
        "aggregate": {
            "functions": aggregate_funcs,
            "branches": aggregate_branches,
            "calls": aggregate_calls,
            "markers": aggregate_markers,
        }
    }

    return result


def merge_baseline_and_sampled_trace_information(sampled_cases_trace_info: Dict[str, Any], baseline_info: Optional[Dict[str, Any]] = None, filtered_metadata_path: str = "") -> Dict[str, Any]:
    baseline_reached_union: Set[Tuple[int, int]] = set()
    
    if baseline_info and baseline_info.get("per_trace"):
        for _, entry in baseline_info["per_trace"].items():
            baseline_reached_union |= _extract_reached_func_set(entry)

        logger.info(
            f"[Trace] Baseline union reached {len(baseline_reached_union)} "
            f"functions on target chain"
        )

    category_stats = defaultdict(int)

    for trace_id, info in sampled_cases_trace_info.get("per_trace", {}).items():
        reached = _extract_reached_func_set(info)

        if not reached:
            category = "no_chain_coverage"
        elif baseline_reached_union:
            if reached.issubset(baseline_reached_union) and reached != baseline_reached_union:
                category = "degraded_from_baseline"
            elif baseline_reached_union.issubset(reached):
                category = "good_or_better_than_baseline"
            else:
                category = "mixed"
        else:
            category = "no_baseline"

        info["coverage_category"] = category
        category_stats[category] += 1

    result: Dict[str, Any] = {
        "root_api": sampled_cases_trace_info.get("root_api"),
        "filtered_metadata_path": filtered_metadata_path,

        "baseline_trace": baseline_info,
        "baseline_union_reached_funcs_count": len(baseline_reached_union),

        "queue_traces": sampled_cases_trace_info,
        "queue_coverage_category_stats": dict(category_stats),
    }

    return result

def get_aggregate_runtime_trace_information(batch: Batch, root_api: str, filtered_metadata_path: str, baseline_seed_path: Optional[str] = None):
    t_config = TraceConfig()
    harness_path: str = batch.harness_info.get("harness_files", "").get(root_api, "")
    if not harness_path:
        logger.error(f"[Trace] No harness path found for root API: {root_api}")
        raise ValueError
    
    trace_binary_path: Path = compile_trace_binary(batch, root_api, t_config)

    _clean_up_trace_dir(trace_binary_path.parent)

    # if basline seed path is provided, run trace binary on it first to collect baseline trace information
    if baseline_seed_path:
        baseline_seed_path = Path(baseline_seed_path)
        if not baseline_seed_path.is_dir():
            logger.error(f"[Trace] Baseline seed path is not a valid dir: {baseline_seed_path}")
            raise FileNotFoundError
        baseline_seeds = [p for p in baseline_seed_path.iterdir() if p.is_file()]
        if not baseline_seeds:
            logger.error(f"[Trace] No seed files found in baseline seed path: {baseline_seed_path}")
            raise FileNotFoundError
        
        baseline_trace_json_files: List[Path] = run_trace_on_sampled_cases(
            baseline_seeds,
            trace_binary_path,
            t_config,
        )

        baseline_seeds_trace_info = collect_trace_information(baseline_trace_json_files, filtered_metadata_path)

    sampled_cases: List[Path] = sample_fuzzer_queue_cases(harness_path, t_config)
    trace_json_files: List[Path] = run_trace_on_sampled_cases(sampled_cases, trace_binary_path, t_config)

    sampled_queue_seed_runtime_trace: Dict[str, Any] = collect_trace_information(trace_json_files, filtered_metadata_path)

    result = merge_baseline_and_sampled_trace_information(
        sampled_queue_seed_runtime_trace,
        baseline_seeds_trace_info,
        filtered_metadata_path
    )

    return sampled_cases, result