import json
import os

from typing import Dict, Any, List, Optional, Tuple, Set
from pathlib import Path
from collections import defaultdict, deque

from src.utils.utils import get_logger
from src.batch.batch_class import Batch

logger = get_logger(__name__)

META_GOLB = "trace_meta_*.json"

def _expand_with_callees(merged_metadata: Dict[str, Any], seed_func_global_ids: Set[int], depth: int ) -> Set[int]:
    """Expand a seed set of function global_ids with their callees up to a given depth.

    This is used to optionally include a small neighborhood around the external call chain,
    without changing the default behavior when depth is 0.
    """
    if depth <= 0:
        return set(seed_func_global_ids)
    
    adj: Dict[int, Set[int]] = defaultdict(set)
    for c in merged_metadata.get("calls", []):
        fg = c.get("from_func_global_id")
        tg = c.get("to_func_global_id")
        if fg in None or tg is None:
            continue
        try:
            fg_i = int(fg)
            tg_i = int(tg)
        except Exception:
            continue
        adj[fg_i].add(tg_i)
    
    expanded: Set[int] = set(seed_func_global_ids)
    q = deque([(fid, 0) for fid in seed_func_global_ids])

    while q:
        fid, d = q.popleft()
        if d >= depth:
            continue
        for nxt in adj.get(fid, []):
            if nxt not in expanded:
                expanded.add(nxt)
                q.append((nxt, d + 1))
    
    return expanded


def load_all_meta(meta_dir: str = "/tmp") -> Dict[str, dict]:
    modules = {}
    for p in Path(meta_dir).glob(META_GOLB):
        m = json.loads(p.read_text(encoding="utf-8"))
        module_id = m.get("module_id", "")

        if not module_id:
            logger.warning(f"[runtime_components] Skipping trace meta file with missing module_id: {p}")
            continue
        
        modules[module_id] = m
    
    return modules

def build_global_ids(modules: Dict[str, dict]) -> dict:
    func_global : Dict[Tuple[str, int], int] = {}
    branch_global : Dict[Tuple[str, int], int] = {}
    call_global : Dict[Tuple[str, int], int] = {}
    marker_global : Dict[Tuple[str, int], int] = {}

    next_fid = 0
    next_bid = 0
    next_cid = 0
    next_mid = 0

    for module_id, m in modules.items():
        for f in m.get("functions", []):
            local_id = int(f["id"])
            key = (module_id, local_id)
            if key not in func_global:
                func_global[key] = next_fid
                next_fid += 1
    
    for module_id, m in modules.items():
        for b in m.get("branches", []):
            local_id = int(b["id"])
            key = (module_id, local_id)
            if key not in branch_global:
                branch_global[key] = next_bid
                next_bid += 1

    for module_id, m in modules.items():
        for c in m.get("calls", []):
            local_id = int(c["id"])
            key = (module_id, local_id)
            if key not in call_global:
                call_global[key] = next_cid
                next_cid += 1
    
    for module_id, m in modules.items():
        for mk in m.get("markers", []):
            local_id = int(mk["id"])
            key = (module_id, local_id)
            if key not in marker_global:
                marker_global[key] = next_mid
                next_mid += 1

    merged = {
        "functions": [],
        "branches": [],
        "calls": [],
        "markers": [],
        "index": {
            "func": {},
            "branch": {},
            "call": {},
            "marker": {}
        }
    }

    for module_id, m in modules.items():
        for f in m.get("functions", []):
            local_id = int(f["id"])
            g_id = func_global[(module_id, local_id)]
            merged["functions"].append({
                "global_id": g_id,
                "module_id": module_id,
                "local_id": local_id,
                "name": f["name"],
                "file": f.get("file", ""),
                "line": f.get("line", 0),
            })

            merged["index"]["func"][f"{module_id}:{local_id}"] = g_id
    
    for module_id, m in modules.items():
        for b in m.get("branches", []):
            local_id = int(b["id"])
            g_id = branch_global[(module_id, local_id)]

            func_local = int(b["func_id"])
            func_global_id = func_global[(module_id, func_local)]

            merged["branches"].append({
                "global_id": g_id,
                "module_id": module_id,
                "local_id": local_id,
                "func_global_id": func_global_id,
                "file": b.get("file", ""),
                "line": b.get("line", 0),
            })
            merged["index"]["branch"][f"{module_id}:{local_id}"] = g_id
    
    for module_id, m in modules.items():
        for c in m.get("calls", []):
            local_id = int(c["id"])
            g_id = call_global[(module_id, local_id)]

            from_local = int(c["from_func_id"])
            to_local   = int(c["to_func_id"])
            from_global_id = func_global[(module_id, from_local)]
            to_global_id   = func_global[(module_id, to_local)]

            merged["calls"].append({
                "global_id": g_id,
                "module_id": module_id,
                "local_id": local_id,
                "from_func_global_id": from_global_id,
                "to_func_global_id": to_global_id,
                "callee": c.get("callee", ""),
                "file": c.get("file", ""),
                "line": c.get("line", 0),
            })
            merged["index"]["call"][f"{module_id}:{local_id}"] = g_id
    
    for module_id, m in modules.items():
        for mk in m.get("markers", []):
            local_id = int(mk["id"])
            g_id = marker_global[(module_id, local_id)]

            func_local = int(mk["func_id"])
            func_global_id = func_global.get((module_id, func_local), None)        # marker is always inside a function we saw in this module

            merged["markers"].append({
                "global_id": g_id,
                "module_id": module_id,
                "local_id": local_id,
                "func_global_id": func_global_id,
                "tag": mk.get("tag", ""),
                "file": mk.get("file", ""),
                "line": mk.get("line", 0),
            })
            merged["index"]["marker"][f"{module_id}:{local_id}"] = g_id
    
    return merged

def get_merged_metadata(meta_dir: str = "/tmp") -> dict:
    modules = load_all_meta(meta_dir)
    merged_metadata = build_global_ids(modules)

    logger.info(f"[runtime_components] Merged compile pass trace metadata from {len(modules)} modules")

    return merged_metadata

def build_filtered_metadata(
    merged_metadata: dict,
    plan_json: Dict[str, Any],
    root_api: str,
    callee_depth: int = 0,
) -> dict:
    external_chain = plan_json.get("external_chain", [])
    target_func_names = set(external_chain)

    func_name_to_ids: Dict[str, Set[int]] = {}
    for f in merged_metadata.get("functions", []):
        name = f.get("name", "")
        gid = f.get("global_id")
        if name and gid is not None:
            try:
                func_name_to_ids.setdefault(name, set()).add(int(gid))
            except Exception:
                continue

    target_func_global_ids: Set[int] = set()
    missing: List[str] = []
    for name in target_func_names:
        ids = func_name_to_ids.get(name)
        if not ids:
            missing.append(name)
        else:
            target_func_global_ids.update(ids)

    if missing:
        logger.warning(f"[runtime_components] Missing target functions in merged metadata: {missing}")

    if callee_depth and callee_depth > 0:
        target_func_global_ids = _expand_with_callees(merged_metadata, target_func_global_ids, callee_depth)

    filtered_funcs = [
        f for f in merged_metadata.get("functions", [])
        if int(f.get("global_id", -1)) in target_func_global_ids
    ]

    filtered_branches = [
        b for b in merged_metadata.get("branches", [])
        if int(b.get("func_global_id", -1)) in target_func_global_ids
    ]

    filtered_calls: List[Dict[str, Any]] = []
    for c in merged_metadata.get("calls", []):
        fg = int(c.get("from_func_global_id", -1))
        tg = int(c.get("to_func_global_id", -1))
        if fg in target_func_global_ids and tg in target_func_global_ids:
            filtered_calls.append(c)
    
    filtered_markers = []
    for mk in merged_metadata.get("markers", []):
        fg = mk.get("func_global_id")
        tag = (mk.get("tag", "") or "").lower()
        if (fg in target_func_global_ids) or (tag == "bug_point"):
            filtered_markers.append(mk)

    filtered_metadata = {
        "root_api": root_api,
        "external_chain": external_chain,
        "callee_depth": int(callee_depth) if callee_depth else 0,
        "functions": filtered_funcs,
        "branches": filtered_branches,
        "calls": filtered_calls,
        "markers": filtered_markers,
    }

    return filtered_metadata

def get_filtered_metadata_for_specific_root_api(meta_dir: str, batch: Batch, root_api: str) -> str:
    merged_metadata = get_merged_metadata(meta_dir)
    plan_path = batch.harness_info.get("harness_plans_files", "")
    if not plan_path or not os.path.isfile(plan_path):
        logger.error(f"[runtime_components] Invalid harness plan path: {plan_path}")
        raise ValueError
    
    with open(plan_path, "r", encoding="utf-8") as f:
        plan_json = json.load(f)
    
    root_api_plan = plan_json.get(root_api)
    if not root_api_plan:
        logger.error(f"[runtime_components] No plan found for root API: {root_api}")
        raise ValueError
    
    filtered_metadata = build_filtered_metadata(merged_metadata, root_api_plan, root_api)

    save_path = Path(__file__).parent.parent / "filtered_trace_metadata"
    save_path.mkdir(parents=True, exist_ok=True)
    save_file = save_path / f"{root_api}_{batch.batch_id}_filtered_metadata.json"
    with open(save_file, "w", encoding="utf-8") as f:
        json.dump(filtered_metadata, f, indent=2)

    logger.info(f"[runtime_components] Saved filtered metadata for root API {root_api} to {save_file}")
    
    return str(save_file)

if __name__ == "__main__":
    batch = Batch.load_metadata("/root/auto_harness/src/batch_metadata/cebdd898-5d7c-453a-9601-ab1d49ed2798.json")
    filtered_metadata_path = get_filtered_metadata_for_specific_root_api("/tmp", batch, "xmlDocCopyNodeList")
    
    from src.runtime_components.get_runtime_trace_result import get_aggregate_runtime_trace_information
    from src.runtime_components.runtime_trace_feedback_analysis import build_llm_feedback_prompt, build_llm_micro_tune_prompt
    harness_path = batch.harness_info.get("harness_files", "").get("xmlDocCopyNodeList", "")
    baseline_seeds_path = Path(harness_path).parent / "in"
    baseline_seeds = [p for p in baseline_seeds_path.iterdir() if p.is_file()]

    sampled_cases_pathes, sampled_queue_seed_runtime_trace_result = get_aggregate_runtime_trace_information(batch, "xmlDocCopyNodeList", filtered_metadata_path, "/root/auto_harness/src/harness/20260108_091611/in")
    
    prompt = build_llm_feedback_prompt(batch, sampled_queue_seed_runtime_trace_result, batch.target_func, harness_path, baseline_seeds, sampled_cases_pathes)
    print(prompt)

    prompt = build_llm_micro_tune_prompt(batch, sampled_queue_seed_runtime_trace_result, batch.target_func, harness_path, baseline_seeds, sampled_cases_pathes)
    print(prompt)