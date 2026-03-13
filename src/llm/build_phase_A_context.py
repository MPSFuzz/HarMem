from src.cve_helper.cve_partial_prompt_render import extract_structural_cve_model

from collections import Counter, defaultdict
from typing import List, Dict, Any, Optional
from src.utils.utils import get_logger

logger = get_logger(__name__)

_INIT_KEYWORDS = (
    "init",
    "initialize",
    "startup",
    "setup",
    "libinit",
    "libraryinit",
    "globalinit",
    "moduleinit",
)

_CLEANUP_KEYWORDS = (
    "cleanup",
    "clean_up",
    "deinit",
    "deinitialize",
    "shutdown",
    "terminate",
    "finalize",
    "fini",
    "destroy",
    "teardown",
    "globalfree",
)

def _is_init_like(fname: str) -> bool:
    if not fname:
        return False
    fl = fname.lower()
    return any(kw in fl for kw in _INIT_KEYWORDS)

def _is_cleanup_like(fname: str) -> bool:
    if not fname:
        return False
    fl = fname.lower()
    return any(kw in fl for kw in _CLEANUP_KEYWORDS)

def build_lifecycle_summary(plan: Dict[str, Any]) -> Dict[str, Any]:
    lifecycle = plan.get("lifecycle_plan", []) or []
    func_counts = Counter()
    for step in lifecycle:
        fname = step.get("func")
        if fname:
            func_counts[fname] += 1
    
    global_init = set()
    global_cleanup = set()
    
    for step in lifecycle:
        fname = step.get("func")
        if not fname:
            continue

        kind = step.get("step")  # "alloc" / "free" / "transfer" ...

        if kind == "alloc" and _is_init_like(fname) and func_counts[fname] <= 2:
            global_init.add(fname)

        if kind == "free" and _is_cleanup_like(fname) and func_counts[fname] <= 2:
            global_cleanup.add(fname)
        
    by_res_id: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
    for idx, step in enumerate(lifecycle):
        ids = step.get("ids") or []
        for rid in ids:
            by_res_id[rid].append({"idx": idx, "step": step})
    
    iteration_resources = []
    for rid, steps in by_res_id.items():
        alloc_step = None
        free_step = None

        for s in steps:
            st = s["step"]
            skind = st.get("step")
            if skind == "alloc" and alloc_step is None:
                alloc_step = st
            if skind == "free":
                free_step = st
        
        if alloc_step and free_step:
            alloc_func = alloc_step.get("func")
            free_func = free_step.get("func")
            if alloc_func and free_func:
                iteration_resources.append({
                    "resource_id": rid,
                    "alloc_func": alloc_func,
                    "free_func": free_func
                })
    
    seen_pairs = set()
    unique_iteration_resources = []
    for r in iteration_resources:
        key = (r["alloc_func"], r["free_func"], r["resource_id"])
        if key in seen_pairs:
            continue

        seen_pairs.add(key)
        unique_iteration_resources.append(r)
    
    return {
        "global_initializers": list(global_init),
        "global_cleanups": list(global_cleanup),
        "iteration_resources": unique_iteration_resources
    }

def build_phase_A_context(plan: Dict[str, Any], cve_hints: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    chain = plan.get("chain", {})
    nodes: List[Dict[str, Any]] = chain.get("nodes", [])

    if not nodes:
        logger.warning("No nodes found in call chain.")
        return {}
    
    root = nodes[0]
    target = nodes[-1]

    call_chain = [n.get("name") for n in nodes if n.get("name")]
    lifecycle_sum = build_lifecycle_summary(plan)

    contextual_bug_model = extract_structural_cve_model(cve_hints or {})

    context = {
        "call_chain": call_chain,
        "root_api": {
            "name": root.get("name"),
            "signature": root.get("signature", {}),
            "file": root.get("file"),
            "location": root.get("location")
        },
        "target_api":{
            "name": target.get("name"),
            "signature": target.get("signature", {}),
            "file": target.get("file"),
            "location": target.get("location")
        },
        "contextual_bug_model": contextual_bug_model,
        "lifecycle_summary": lifecycle_sum
    }

    return context
