import time
import os
import errno
import signal

from dataclasses import dataclass
from enum import auto, Enum
from typing import Dict, Any, List, Optional, Tuple

from src.fuzz_components.fuzzer_feed_back_analysis import FuzzStatsWindowManager
from src.batch.operations_of_Batch import collect_fuzzer_feedback_to_batch, analyze_fuzzer_feedback
from src.batch.batch_class import Batch
from src.fuzz_components.fuzz_runner import start_fuzzing
from src.fuzz_components.fuzzer_feed_back_analysis import is_harness_qualified_in_coares_grain
from src.harness_class.harness_upgrade import harness_upgrade_procedure
from src.utils.utils import get_logger
from src.utils._global_vars import regularized_fuzz_root_apis

logger = get_logger(__name__)

class Phase(Enum):
    COARSE = auto()
    FINE = auto()
    REGULARIZED = auto()    # regularized fuzzing phase

@dataclass
class EpochConfig:
    poll_sec: int = 3
    collect_interval_sec: int = 30 # collect feedback every 30 seconds
    coarse_min_sec: int  = 2 * 60
    coarse_max_sec: int = 5 * 60
    fine_min_sec: int = 10 * 60
    fine_max_sec: int = 30 * 60
    target_reach_rate_micro_threshold: float = 0.60     # 65% queue cases reach target function
    target_reach_rate_repair_threshold: float = 0.15   # if target_func reach rate < 15%, consider repairing operation
    target_reach_rate_min_traces: int  = 10    # need at least 15 traces to consider reach rate
    plateau_k: int = 2            # require at least k points to consider plateau detection
    crash_k: int = 2              # require at least k points to consider process is dead
    empty_feedback_k: int = 3     # require at least k consecutive empty feedback collections to evict a root_api

class EpochScheduler:
    def __init__(self, config: Optional[EpochConfig]):
        self.epoch_config = config or EpochConfig()
        self.phase: Dict[str, Phase] = {}
        self.epoch_start_ts: Dict[str, float] = {}
        self.plateau_streak: Dict[str, int] = {}
        self.crash_streak: Dict[str, int] = {}
        #self.last_collect_ts: float = 0.0
        self.last_collect_ts: Dict[str, float] = {}
        self.upgrade_cooldown_until: Dict[str, float] = {}
        self.empty_feedback_streak: Dict[str, int] = {}
        self.window_mgr = FuzzStatsWindowManager()
    
    def _ensure(self, batch: Batch):
        now = time.time()
        for root_api in batch.harness_info.get("harness_files", {}).keys():
            self.phase.setdefault(root_api, Phase.COARSE)
            self.epoch_start_ts.setdefault(root_api, now)
            self.plateau_streak.setdefault(root_api, 0)
            self.crash_streak.setdefault(root_api, 0)
            self.last_collect_ts.setdefault(root_api, 0.0)
            self.empty_feedback_streak.setdefault(root_api, 0)
    
    def _sync_regularized(self, batch: Batch):
        now = time.time()
        for root_api in batch.harness_info.get("harness_files", {}).keys():
            self.phase.setdefault(root_api, Phase.COARSE)
            self.epoch_start_ts.setdefault(root_api, now)
            self.plateau_streak.setdefault(root_api, 0)
            self.crash_streak.setdefault(root_api, 0)
            self.last_collect_ts.setdefault(root_api, 0.0)
            self.empty_feedback_streak.setdefault(root_api, 0)

            if self._is_regularized(root_api) and self.phase.get(root_api) != Phase.REGULARIZED:
                logger.info(f"[scheduler] Root API {root_api} enters REGULARIZED mode (detach from optimization loop).")
                self.phase[root_api] = Phase.REGULARIZED
                self.window_mgr.reset(root_api)
                self.epoch_start_ts[root_api] = now
                self.plateau_streak[root_api] = 0
                self.empty_feedback_streak.setdefault(root_api, 0)
    
    def _epoch_due(self, root_api: str, *, force_condition: bool = False) -> bool:
        if self.phase[root_api] == Phase.REGULARIZED:
            return False

        now = time.time()
        elapsed = now - self.epoch_start_ts[root_api]
        ph = self.phase[root_api]

        if ph == Phase.COARSE:
            if elapsed < self.epoch_config.coarse_min_sec:
                return False
            elif elapsed >= self.epoch_config.coarse_max_sec:
                return True
            return force_condition
        else:
            if elapsed < self.epoch_config.fine_min_sec:
                return False
            elif elapsed >= self.epoch_config.fine_max_sec:
                return True
            return force_condition

    def _pid_alive(self, pid: int) -> bool:
        if not pid or pid <= 0:
            return False
        try:
            os.kill(pid, 0)
            return True
        except OSError as e:
            if e.errno == errno.ESRCH:
                return False
            return True

    def _stop_fuzzing_process(self, batch: Batch, root_api: str):
        pid = batch.fuzzer_pids.get(root_api, 0)
        if not pid or pid <= 0:
            return

        try:
            if self._pid_alive(pid):
                os.kill(pid, signal.SIGTERM)
                time.sleep(0.5)
                if self._pid_alive(pid):
                    os.kill(pid, signal.SIGKILL)
            logger.info(f"[scheduler] Stopped fuzzing process for root API {root_api} (pid={pid}).")
        except Exception as e:
            logger.warning(f"[scheduler] Failed to stop fuzzing process for root API {root_api} (pid={pid}): {e}")

    def _remove_root_api_from_batch(self, batch: Batch, root_api: str, reason: str = ""):
        self._stop_fuzzing_process(batch, root_api)

        harness_info = batch.harness_info or {}
        for key in ("harness_files", "harness_skeletons_files"):
            submap = harness_info.get(key, {}) or {}
            if isinstance(submap, dict):
                submap.pop(root_api, None)

        batch.fuzzer_pids.pop(root_api, None)

        fuzz_feedback = batch.fuzz_feedback or {}
        for key in ("fuzzer_stats_feedback", "fuzzer_stats_analysis"):
            submap = fuzz_feedback.get(key, {}) or {}
            if isinstance(submap, dict):
                submap.pop(root_api, None)

        self.phase.pop(root_api, None)
        self.epoch_start_ts.pop(root_api, None)
        self.plateau_streak.pop(root_api, None)
        self.crash_streak.pop(root_api, None)
        self.last_collect_ts.pop(root_api, None)
        self.upgrade_cooldown_until.pop(root_api, None)
        self.empty_feedback_streak.pop(root_api, None)
        self.window_mgr.reset(root_api)
        regularized_fuzz_root_apis.discard(root_api)

        batch.save_metadata()
        logger.warning(
            f"[scheduler] Removed root API {root_api} from batch {batch.batch_id} because "
            f"consecutive empty fuzzer feedback reached threshold ({reason or 'no reason provided'})."
        )

    def _collect_analyze(self, batch: Batch, root_apis: Optional[List[str]] = None, force: bool = False) -> bool:
        now = time.time()
        roots = root_apis if root_apis is not None else list(self.phase.keys())
        if not roots:
            return False

        eligible: List[str] = []
        for r in roots:
            last = self.last_collect_ts.get(r, 0.0)
            if force or (now - last >= self.epoch_config.collect_interval_sec):
                eligible.append(r)

        if not eligible:
            return False

        collect_fuzzer_feedback_to_batch(batch, eligible)

        analyze_roots: List[str] = []
        roots_to_remove: List[str] = []
        stats_map = (batch.fuzz_feedback.get("fuzzer_stats_feedback", {}) or {})

        for r in eligible:
            feedback = stats_map.get(r, {}) or {}
            if feedback:
                self.empty_feedback_streak[r] = 0
                analyze_roots.append(r)
            else:
                self.empty_feedback_streak[r] = self.empty_feedback_streak.get(r, 0) + 1
                logger.warning(
                    f"[scheduler] Empty fuzzer feedback collected for root API {r} in batch {batch.batch_id}; "
                    f"streak={self.empty_feedback_streak[r]}/{self.epoch_config.empty_feedback_k}."
                )
                if self.empty_feedback_streak[r] >= self.epoch_config.empty_feedback_k:
                    roots_to_remove.append(r)

        for r in roots_to_remove:
            self._remove_root_api_from_batch(batch, r, reason=f"empty feedback {self.empty_feedback_streak.get(r, 0)} times")

        if analyze_roots:
            analyze_roots = [r for r in analyze_roots if r in self.phase]
            if analyze_roots:
                analyze_fuzzer_feedback(batch, self.window_mgr, analyze_roots)

        for r in eligible:
            if r in self.phase:
                self.last_collect_ts[r] = now

        return True

    
    def _safe_upgrade(self, batch: Batch, root_api: str) -> bool:
        try:
            harness_upgrade_procedure(batch, root_api, 
                reach_rate_micro_threshold=self.epoch_config.target_reach_rate_micro_threshold,
                reach_rate_repair_threshold=self.epoch_config.target_reach_rate_repair_threshold,
                reach_rate_min_traces=self.epoch_config.target_reach_rate_min_traces)
            return True
        except Exception as e:
            logger.error(f"[scheduler] Harness upgrade for root API {root_api} in batch {batch.batch_id} failed: {e}")
            self.upgrade_cooldown_until[root_api] = time.time() + self.epoch_config.coarse_min_sec # cooldown
            return False

    def _reset_after_upgrade(self, root_api: str):
        self.window_mgr.reset(root_api)
        self.phase[root_api] = Phase.COARSE
        self.epoch_start_ts[root_api] = time.time()
        self.plateau_streak[root_api] = 0
        self.crash_streak[root_api] = 0

    def _is_regularized(self, root_api: str) -> bool:
        return root_api in regularized_fuzz_root_apis

    def run(self, batch_id: str, seeds_path: Optional[str] = None):
        batch = start_fuzzing(batch_id=batch_id, seeds_path=seeds_path)
        self._ensure(batch)

        while True:
            time.sleep(self.epoch_config.poll_sec)

            self._sync_regularized(batch)

            all_roots = list(self.phase.keys())
            non_reg_roots = [r for r in all_roots if self.phase.get(r) != Phase.REGULARIZED]
            reg_roots = [r for r in all_roots if self.phase.get(r) == Phase.REGULARIZED]
            
            self._collect_analyze(batch, root_apis=non_reg_roots, force=True)
            self._collect_analyze(batch, root_apis=reg_roots, force=False)

            for root_api in list(self.phase.keys()):
                pid = batch.fuzzer_pids.get(root_api, 0)
                if self._pid_alive(pid):
                    self.crash_streak[root_api] = 0
                    continue

                self.crash_streak[root_api] += 1
                if self.crash_streak[root_api] >= self.epoch_config.crash_k:
                    logger.info(f"[scheduler] Fuzzing process for root API {root_api} in batch {batch.batch_id} has crashed. Try to restart.")
                    start_fuzzing(batch=batch, selected_root_api=root_api)
                    self.crash_streak[root_api] = 0

                    self.window_mgr.reset(root_api)
                    # self.phase[root_api] = Phase.COARSE
                    self.epoch_start_ts[root_api] = time.time()
                    self.plateau_streak[root_api] = 0

                    if self.phase.get(root_api) != Phase.REGULARIZED:
                        self.phase[root_api] = Phase.COARSE

            force_due: Dict[str, bool] = {r: False for r in list(self.phase.keys())}

            for root_api in list(self.phase.keys()):
                if self.phase.get(root_api) == Phase.REGULARIZED:
                    continue

                analysis = (batch.fuzz_feedback.get("fuzzer_stats_analysis", {}) or {}).get(root_api, {}) or {}
                issues = analysis.get("issues", []) or []
                
                if self.phase[root_api] == Phase.COARSE:
                    blockers = {"unstable_harness_or_target", "very_low_coverage", "no_distance_progress"}
                    if any(i in blockers for i in issues):
                        force_due[root_api] = True
                else:
                    plat_diag = analysis.get("plateau_diag")
                    is_plat = bool(plat_diag) and plat_diag.get("hits", 0) >= 2
                    if is_plat:
                        self.plateau_streak[root_api] += 1
                    else:
                        self.plateau_streak[root_api] = 0
                    
                    if self.plateau_streak[root_api] >= self.epoch_config.plateau_k:
                        force_due[root_api] = True
            
            # due_roots = [r for r in self.phase.keys() if self._epoch_due(r, force_condition=force_due[r])]
            due_roots = [
                r for r in list(self.phase.keys())
                if self.phase.get(r) != Phase.REGULARIZED and self._epoch_due(r, force_condition=force_due[r])
            ]
            if not due_roots:
                continue

            # self._collect_analyze(batch)
            self._collect_analyze(batch, root_apis=due_roots, force=False)

            for root_api in due_roots:
                if root_api not in self.phase:
                    continue
                cooldown_until = self.upgrade_cooldown_until.get(root_api, 0.0)
                if time.time() < cooldown_until:
                    logger.info(f"[scheduler] Skipping harness upgrade for root API {root_api} in batch {batch.batch_id} due to cooldown.")
                    self.epoch_start_ts[root_api] = time.time()
                    continue

                analysis = (batch.fuzz_feedback.get("fuzzer_stats_analysis", {}) or {}).get(root_api, {}) or {}
                stats = (batch.fuzz_feedback.get("fuzzer_stats_feedback", {}) or {}).get(root_api, {}) or {}
                issues = analysis.get("issues", []) or []

                if self.phase[root_api] == Phase.COARSE:
                    if not is_harness_qualified_in_coares_grain(stats, root_api):
                        logger.info(f"[scheduler] Coarse grain analysis for root API {root_api} in batch {batch.batch_id} failed. Upgrading harness.")
                        #harness_upgrade_procedure(batch, root_api)
                        if self._safe_upgrade(batch, root_api):
                            self._reset_after_upgrade(root_api)
                        else:
                            pass
                    else:
                        self.phase[root_api] = Phase.FINE
                        self.epoch_start_ts[root_api] = time.time()
                        self.plateau_streak[root_api] = 0
                else:
                    if "distance_plateau_period_suspected" in issues and self.plateau_streak[root_api] >= self.epoch_config.plateau_k:
                        logger.info(f"[scheduler] Fine grain analysis for root API {root_api} in batch {batch.batch_id} detected distance plateau.")
                        if self._safe_upgrade(batch, root_api):
                            self._reset_after_upgrade(root_api)
                        else:
                            pass
                    else:
                        self.phase[root_api] = Phase.FINE
                        self.epoch_start_ts[root_api] = time.time()
                
        return batch

if __name__ == "__main__":
    scheduler = EpochScheduler(config=None)
    scheduler.run("65e4422b-65ad-4884-9eac-eaaada6ac894", "/root/seeds")