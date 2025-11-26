import json
import os

from typing import Dict, Any, List

def _safe_get(stat: Dict[str, Any], key: str,default: None):
    v = stat.get(key, default)
    return v if v is not None else default

def fuzzer_stats_analysis(fuzzer_stats: Dict[str, Any]) -> Dict[str, Any]:
    issues: List[str] = []
    hints: List[str] = []

    bitmap_cvg = _safe_get(fuzzer_stats, "bitmap_cvg", 0.0) or 0.0
    stability = _safe_get(fuzzer_stats, "stability", 100.0) or 100.0
    paths_total = _safe_get(fuzzer_stats, "paths_total", 0) or 0
    max_depth = _safe_get(fuzzer_stats, "max_depth", 0) or 0
    unique_crashes = _safe_get(fuzzer_stats, "unique_crashes", 0) or 0
    execs_done = _safe_get(fuzzer_stats, "execs_done", 0) or 0
    execs_per_sec = _safe_get(fuzzer_stats, "execs_per_sec", 0.0) or 0.0

    cur_distance = fuzzer_stats.get("cur_distance")
    min_distance = fuzzer_stats.get("min_distance")
    max_distance = fuzzer_stats.get("max_distance")

    # bitmap coverage analysis
    if execs_done > 10000:
        if bitmap_cvg < 3.0 and paths_total > 300:
            issues.append("very_low_coverage")
            hints.append("bitmap_cvg < 3%, paths_total is high, suggesting that most paths are blocked by early checks;"
                        "It is recommended to relax the early return after parsing failure or sanity-check, allowing the link to continue calling even with the minimum valid state.")
        elif bitmap_cvg < 6.0:
            issues.append("low_coverage")
            hints.append("A low bitmap_cvg value indicates a relatively simple execution path."
                         "consider reducing overly strict conditional checks, or constructing a simple fallback object to continue the call chain when input parsing fails.")
    
    coverage_score = min(bitmap_cvg / 15.0, 1.0) # 15%及以上视为满分

    # stability analysis
    if stability < 95.0 or unique_crashes > 0:
        issues.append("unstable_harness_or_target")
        hints.append(f"stability={stability:.2f}%, unique_crahes={unique_crashes};"
                     "This indicates a certain percentage of crashes. Prioritize checking if the harness continues to dereference objects when they are NULL or in an error state."
                     "Objects such as doc/root/schema are passed to subsequent APIs without being checked.")
    
    if stability >= 95.0:
        stability_score = 1.0
    elif stability < 80:
        stability_score = 0.
    else:
        stability_score = (stability - 80.0) / (95.0 - 80.0)
    
    # depth analysis
    if execs_done > 10000 and paths_total > 300 and max_depth <= 2:
        issues.append("shallow_exploration_depth")
        hints.append(
            f"max_depth={max_depth}, paths_total={paths_total}, indicating that most paths are staying at shallow calling depth;"
            "considering creating and passing more intermediate objects along the static call chain to reduce the early exit if higher-level wrappers."
        )
    
    # distance analysis (AFLGo)
    distance_score = None
    if isinstance(min_distance, (int, float)) and isinstance(max_distance, (int, float)) and max_distance > 0:
        norm_min = min_distance / max_distance
        norm_cur = cur_distance / max_distance if isinstance(cur_distance, (int, float)) else None

        # the smaller the distance, the better
        distance_score = max(0.0, min(1.0 - norm_min, 1.0))
        
        # no obvious distance reduction
        if norm_min > 0.8 and paths_total > 1000:
            issues.append("no_distance_progress")
            hints.append(
                f"min_distance={min_distance:.2f}, max_distance={max_distance:.2f},"
                "the normalized value is close to 1, indicating that many paths are still far from the target;"
                "this may be because the target function or the AFLGo marker is not a common success path."
                "it is recommended to ensure that the call chain always calls the target API when parsing is successful, and to insert a marker before it"
            )
        elif norm_min < 0.5 and norm_cur is not None and norm_cur > norm_min * 1.5:
            hints.append(
                "min_distance has decreased significantly compared to cur_distance, indicating the existence of paths closer to the target;"
                "this could continue fuzzing and replay these 'near-distance' samples in queue for refinement."
            )
        
        # plateau period detection
        if execs_done > 1000000 and paths_total > 1000:
            if 0.3 <= norm_min <= 0.7 and bitmap_cvg >= 8.0:
                issues.append("distance_plateau_period_suspected")
                hints.append(
                    "bitmap_cvg is at a medium level, min_distance/max_distance are in the middle range."
                    "This indicates that the basic path has been explored sufficiently, but there is still a significant gap from the target."
                    "Try combining static call chain analysis with runtime trace analysis to determine which layer of the chain is stuck."
                )
    
    # efiiciency recomendation
    if execs_per_sec < 100.0 and execs_per_sec > 100000:
        hints.append(
            f"exec_per_sec={execs_per_sec:.1f}, that is too slow."
            "consider reducing unnecessary duplicate parsing or large object allocation."
            "for example, move initializations that don't depend on fuzz input out of __AFL_LOOP ."
        )
    
    analysis_result = {
        "issues": issues,
        "hints": hints,
        "scores": {
            "coverage_score": coverage_score,
            "stability_score": stability_score,
            "distance_score": distance_score
        }
    }

    return analysis_result

def is_harness_qualified_in_coares_grain(fuzzer_stats: Dict[str, Any]) -> bool:
    # A coarse-grain qualification check for harnesses based on fuzzer stats, used to filter out obviously invalid harnesses.
    analysis_result = fuzzer_stats_analysis(fuzzer_stats)
    issues = analysis_result.get("issues", [])
    quality_blockers = {
        "unstable_harness_or_target",
        "very_low_coverage",
        "no_distance_progress"
    }

    if issues in quality_blockers:
        return False
    
    return True