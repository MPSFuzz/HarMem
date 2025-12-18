import time
from dataclasses import dataclass, field
from collections import deque
from typing import Dict, Any, List, Optional, Deque, Tuple

def _safe_get(stat: Dict[str, Any], key: str,default: None):
    v = stat.get(key, default)
    return v if v is not None else default

def _safe_num(stat: Dict[str, Any], key: str, default=0):
    v = stat.get(key, default)
    if v is None:
        return default
    return v

# plateau detection based on time windows
@dataclass
class PlateauConfig:
    window_seconds: int = 20 * 60          # 20 min
    require_points: int = 5                # at least 5 data points in the window
    min_paths_delta: int = 20              # Δpaths_total < 20
    min_bitmap_delta: float = 0.2          # Δbitmap_cvg < 0.2 (%)
    min_distance_improve_ratio: float = 0.01  # min_distance  < 1% improvement in the window considered as plateau
    min_execs_imporve: int = 5000

@dataclass
class StatsPoint:
    ts: float
    stats: Dict[str, Any]

@dataclass
class FuzzStatsWindow:
    cfg: PlateauConfig
    points: Deque[StatsPoint] = field(default_factory=lambda: deque(maxlen=2000))

    def push(self, stats: Dict[str, Any], ts: Optional[float] = None) -> None:
        ts = ts if ts is not None else time.time()
        self.points.append(StatsPoint(ts=ts, stats=stats))
        self._trim(ts)
    
    def _trim(self, now: float) -> None:
        # only keep points within the time window
        while self.points and (now - self.points[0].ts) > self.cfg.window_seconds:
            self.points.popleft()
    
    def plateau(self) -> Tuple[bool, Dict[str, Any]]:
        if len(self.points) < self.cfg.require_points:
            return False, {"reason": "insufficient_points", "points": len(self.points)}
        
        oldest = self.points[0].stats
        newest = self.points[-1].stats

        path_delta = int(_safe_num(newest, "paths_total", 0) or 0) - int(_safe_num(oldest, "paths_total", 0) or 0)
        bitmap_delta = float(_safe_num(newest, "bitmap_cvg", 0.0) or 0.0) - float(_safe_num(oldest, "bitmap_cvg", 0.0) or 0.0)
        exec_delta = int(_safe_num(newest, "execs_done", 0) or 0) - int(_safe_num(oldest, "execs_done", 0) or 0)

        if exec_delta < self.cfg.min_execs_imporve:
            return False, {
                "reason": "inactive_window",
                "execs_delta": exec_delta,
                "points": len(self.points)
            }
        
        old_min_dist = oldest.get("min_distance")
        new_min_dist = newest.get("min_distance")

        newest_exec_done = int(_safe_num(newest, "execs_done", 0) or 0)

        plateau_paths = path_delta < self.cfg.min_paths_delta
        plateau_bitmap = bitmap_delta < self.cfg.min_bitmap_delta

        plateau_dist = False
        dist_improve_ratio = None
        if isinstance(old_min_dist, (int, float)) and isinstance(new_min_dist, (int, float)) and old_min_dist > 0:
            dist_improve_ratio = (old_min_dist - new_min_dist) / old_min_dist
            plateau_dist = dist_improve_ratio < self.cfg.min_distance_improve_ratio
        
        hit = 0
        hit += 1 if plateau_paths else 0
        hit += 1 if plateau_bitmap else 0
        hit += 1 if plateau_dist else 0

        diag = {
            "exec_done": newest_exec_done,
            "exec_delta": exec_delta,
            "paths_delta": path_delta,
            "bitmap_delta": bitmap_delta,
            "dist_improve_ratio": dist_improve_ratio,
            "plateau_paths": plateau_paths,
            "plateau_bitmap": plateau_bitmap,
            "plateau_dist": plateau_dist,
            "hits": hit,
            "points": len(self.points),
        }

        return (hit>=2), diag

class FuzzStatsWindowManager:
    def __init__(self, cfg: Optional[PlateauConfig] = None):
        self.cfg = cfg or PlateauConfig()
        self._windows: Dict[str, FuzzStatsWindow] = {}
    
    def push(self, root_api: str, stats: Dict[str, Any], ts:Optional[float] = None) -> None:
        if root_api not in self._windows:
            self._windows[root_api] = FuzzStatsWindow(cfg=self.cfg)
        self._windows[root_api].push(stats, ts)
    
    def plateau(self, root_api: str) -> Tuple[bool, Dict[str, Any]]:
        w = self._windows.get(root_api)
        if not w:
            return False, {"reason": "no_window"}
        
        return w.plateau()
    
    def reset(self, root_api: str) -> None:
        if root_api in self._windows:
            del self._windows[root_api]

def fuzzer_stats_analysis(fuzzer_stats: Dict[str, Any], root_api: str, window_mgr: Optional[FuzzStatsWindowManager] = None) -> Dict[str, Any]:
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
    
    coverage_score = min(bitmap_cvg / 15.0, 1.0) # 15% and above is considered good coverage

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
    
    # efiiciency recomendation
    if execs_per_sec < 100.0:
        hints.append(
            f"exec_per_sec={execs_per_sec:.1f}, that is too slow."
            "consider reducing unnecessary duplicate parsing or large object allocation."
            "for example, move initializations that don't depend on fuzz input out of __AFL_LOOP ."
        )
    
    # window-based plateau augmentation
    plateau_diag = None
    if window_mgr is not None and root_api is not None and execs_done >= 100_000:
        window_mgr.push(root_api, fuzzer_stats)
        is_plateau, diag = window_mgr.plateau(root_api)
        plateau_diag = diag

        unhealthy_blockers = {"unstable_harness_or_target", "very_low_coverage"}
        if is_plateau and not any(i in unhealthy_blockers for i in issues):
            if "distance_plateau_period_suspected" not in issues:
                issues.append("distance_plateau_period_suspected")
            hints.append(
                f"Window plateau detected: paths_delta={diag.get('paths_delta')}, "
                f"bitmap_delta={diag.get('bitmap_delta')}, dist_improve_ratio={diag.get('dist_improve_ratio')}."
            )
    
    analysis_result = {
        "issues": issues,
        "hints": hints,
        "scores": {
            "coverage_score": coverage_score,
            "stability_score": stability_score,
            "distance_score": distance_score
        },
        "plateau_diag": plateau_diag
    }

    return analysis_result

def is_harness_qualified_in_coares_grain(fuzzer_stats: Dict[str, Any], root_api: str) -> bool:
    # A coarse-grain qualification check for harnesses based on fuzzer stats, used to filter out obviously invalid harnesses.
    analysis_result = fuzzer_stats_analysis(fuzzer_stats, root_api)
    issues = analysis_result.get("issues", [])
    quality_blockers = {
        "unstable_harness_or_target",
        "very_low_coverage",
        "no_distance_progress"
    }

    if any(i in quality_blockers for i in issues):
        return False
    
    return True