import json
import os
import glob
from pathlib import Path
from typing import Dict, Any, List, Optional
from src.utils.utils import get_logger

logger = get_logger(__name__)


class HarnessMemory:
    """Memory for a single harness (one root_api). Tracks iterations of the same harness."""
    
    def __init__(self,
                 target_func: str,
                 root_api: str,
                 lib_name: str = "",
                 cve_id: str = "",
                 bug_class: str = "unknown"):
        self.target_func = target_func
        self.root_api = root_api
        self.lib_name = lib_name
        self.cve_id = cve_id
        self.bug_class = bug_class
        self.iterations: List[Dict[str, Any]] = []
        self.distance_floor: Optional[float] = None
        self.conclusion: str = ""

    def add_iteration(self, iteration_data: Dict[str, Any]):
        iteration_data.setdefault("id", len(self.iterations) + 1)
        self.iterations.append(iteration_data)
        self._update_conclusion()
        logger.info(f"[harness_memory] {self.root_api}: added iteration {iteration_data['id']}")

    def populate_trace_data(self, iteration_idx: int, trace_summary: Dict[str, Any]) -> bool:
        if iteration_idx < 0 or iteration_idx >= len(self.iterations):
            return False
        iteration = self.iterations[iteration_idx]
        if not trace_summary:
            return False

        fmt = trace_summary.get("format")
        if fmt == "derived":
            iteration["actual_chain"] = trace_summary.get("actual_chain", [])
            iteration["marker_hit"] = trace_summary.get("marker_hit", {})
            # derive gap from actual_chain, not from pre-filled values
            iteration["gap"] = self._derive_gap(iteration["actual_chain"])
            self._update_conclusion()
            return True

        qt = trace_summary.get("queue_traces", {}) or {}
        per_trace = trace_summary.get("per_trace", qt.get("per_trace", {})) or {}
        total = len(per_trace)
        if total == 0:
            return False

        expected_chain = iteration.get("expected_chain", [])
        func_counts: Dict[str, int] = {}
        for tid, info in per_trace.items():
            seen = set()
            for f in info.get("reached_functions", []) or []:
                name = f.get("name", "")
                if name and name not in seen:
                    func_counts[name] = func_counts.get(name, 0) + 1
                    seen.add(name)

        actual_chain = []
        for func in expected_chain:
            rate = func_counts.get(func, 0) / total if total > 0 else 0.0
            actual_chain.append({"func": func, "reach_rate": round(rate, 3)})
        iteration["actual_chain"] = actual_chain
        iteration["gap"] = self._derive_gap(actual_chain)

        agg_markers = trace_summary.get("aggregate", {}).get("markers", []) or []
        if not agg_markers:
            qt = trace_summary.get("queue_traces", {}) or trace_summary
            agg = qt.get("aggregate", {}) or {}
            agg_markers = agg.get("markers", []) or []
        marker_hit = {}
        for mk in agg_markers:
            if (mk.get("tag", "") or "").lower() == "bug_point":
                f = mk.get("file", "")
                ln = mk.get("line", 0)
                hit_tr = mk.get("hit_traces", 0) or 0
                rate = hit_tr / total if total > 0 else 0.0
                key = f"{f}:{ln}" if f else str(mk.get("local_id", "?"))
                marker_hit[key] = round(rate, 3)
        iteration["marker_hit"] = marker_hit

        self._update_conclusion()
        return True

    @staticmethod
    def _derive_gap(actual_chain: List[Dict]) -> Dict[str, Any]:
        if not actual_chain:
            return {"broken_edge": [], "furthest_hit": ""}
        furthest_hit = ""
        broken_edge = []
        for i, entry in enumerate(actual_chain):
            if entry.get("reach_rate", 0) == 0:
                if i == 0:
                    continue  # first function inlined by compiler, skip
                if furthest_hit:
                    broken_edge = [furthest_hit, entry["func"]]
                break
            furthest_hit = entry["func"]
        if not furthest_hit:
            furthest_hit = actual_chain[-1]["func"]
        return {"broken_edge": broken_edge, "furthest_hit": furthest_hit}

    def _update_conclusion(self):
        dist_vals = [
            it.get("metrics", {}).get("min_distance")
            for it in self.iterations
            if it.get("metrics", {}).get("min_distance") is not None
        ]
        self.distance_floor = min(dist_vals) if dist_vals else None
        crashes = sum(
            it.get("metrics", {}).get("crashes", 0) or 0
            for it in self.iterations
        )
        if crashes > 0:
            self.conclusion = "crashes_found"
        elif len(self.iterations) >= 2:
            self.conclusion = "multiple_iterations"
        elif self.iterations:
            g = (self.iterations[0].get("gap", {}) or {}).get("broken_edge", []) or []
            self.conclusion = "broken_at_" + ("_".join(g)) if g else "running"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "target_func": self.target_func,
            "root_api": self.root_api,
            "lib_name": self.lib_name,
            "cve_id": self.cve_id,
            "bug_class": self.bug_class,
            "distance_floor": self.distance_floor,
            "conclusion": self.conclusion,
            "iterations": self.iterations,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "HarnessMemory":
        obj = cls(
            target_func=data.get("target_func", ""),
            root_api=data.get("root_api", ""),
            lib_name=data.get("lib_name", ""),
            cve_id=data.get("cve_id", ""),
            bug_class=data.get("bug_class", "unknown"),
        )
        obj.iterations = data.get("iterations", [])
        obj.distance_floor = data.get("distance_floor")
        obj.conclusion = data.get("conclusion", "")
        return obj

    @classmethod
    def from_batch_and_plan(cls,
                            batch_json_path: str,
                            plan_json_path: str,
                            root_api: str) -> Optional["HarnessMemory"]:
        batch = json.loads(Path(batch_json_path).read_text(encoding="utf-8"))
        plan = json.loads(Path(plan_json_path).read_text(encoding="utf-8"))

        harness_files = batch.get("harness_info", {}).get("harness_files", {})
        if root_api not in harness_files:
            return None

        stats = (batch.get("fuzz_feedback", {}).get("fuzzer_stats_feedback", {}) or {}).get(root_api, {})
        if not stats:
            return None

        target_func = batch.get("target_func", "")
        lib_name = batch.get("lib_name", "")
        cve_id = (batch.get("cve_hints", {}) or {}).get("cve_id", "")
        bug_class = (batch.get("cve_hints", {}) or {}).get("bug_class", "unknown")
        root_plan = plan.get(root_api, {})
        expected_chain = root_plan.get("external_chain", []) or []
        if not expected_chain:
            nodes = root_plan.get("chain", {}).get("nodes", [])
            expected_chain = [n.get("name", "?") for n in nodes]

        start = stats.get("start_time", 0) or 0
        update = stats.get("last_update", 0) or 0
        duration_h = (update - start) / 3600 if start and update else 0
        analysis = (batch.get("fuzz_feedback", {}).get("fuzzer_stats_analysis", {}) or {}).get(root_api, {}) or {}

        mem = cls(target_func=target_func, root_api=root_api, lib_name=lib_name, cve_id=cve_id, bug_class=bug_class)
        mem.add_iteration({
            "harness_path": harness_files.get(root_api, ""),
            "duration": f"{duration_h:.1f}h",
            "expected_chain": expected_chain,
            "upgrade_reason": ", ".join(analysis.get("issues", []) or []),
            "llm_decision": "unknown",
            "metrics": {
                "coverage": stats.get("bitmap_cvg", 0),
                "stability": stats.get("stability", 0),
                "min_distance": stats.get("min_distance"),
                "max_distance": stats.get("max_distance"),
                "crashes": stats.get("unique_crashes", 0),
                "execs": stats.get("execs_done", 0),
            },
            "actual_chain": [],
            "gap": {},
            "marker_hit": {},
        })
        return mem

    def save(self, path: str):
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        Path(path).write_text(json.dumps(self.to_dict(), indent=2, ensure_ascii=False), encoding="utf-8")
        logger.info(f"[harness_memory] Saved {self.root_api} to {path}")

    @classmethod
    def load(cls, path: str) -> "HarnessMemory":
        return cls.from_dict(json.loads(Path(path).read_text(encoding="utf-8")))


# --- cross-harness analysis (operates on multiple HarnessMemory files) ---

def cross_harness_analysis(memories: List["HarnessMemory"]) -> Dict[str, Any]:
    if len(memories) < 2:
        return {"conclusion": "insufficient_data"}

    root_apis = [m.root_api for m in memories]
    dist_floor = min(
        m.distance_floor for m in memories if m.distance_floor is not None
    ) if any(m.distance_floor for m in memories) else None

    # compare broken_edge across harnesses
    broken_edges = []
    for m in memories:
        for it in m.iterations:
            be = (it.get("gap", {}) or {}).get("broken_edge", []) or []
            if be:
                broken_edges.append(tuple(be))

    same_gap = None
    if len(broken_edges) >= 2 and all(be == broken_edges[0] for be in broken_edges):
        same_gap = list(broken_edges[0])

    total_crashes = sum(
        sum(it.get("metrics", {}).get("crashes", 0) or 0 for it in m.iterations)
        for m in memories
    )

    if same_gap and total_crashes == 0:
        conclusion = "stop_harness_upgrade"
        recommendation = (
            f"All {len(memories)} harnesses hit the same bottleneck: "
            f"{' → '.join(same_gap)}. "
            f"Min distance floor={dist_floor}. "
            "Bottleneck is input diversity, not harness design."
        )
    elif total_crashes > 0:
        conclusion = "continue"
        recommendation = f"Crashes found ({total_crashes}). Harness chain is effective."
    else:
        conclusion = "inconclusive"
        recommendation = "Not enough iterations with consistent gaps."

    return {
        "root_apis_tried": root_apis,
        "distance_floor": dist_floor,
        "same_gap_across": same_gap,
        "total_crashes": total_crashes,
        "conclusion": conclusion,
        "recommendation": recommendation,
    }
