import time
import os
import errno

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

logger = get_logger(__name__)

class Phase(Enum):
    COARSE = auto()
    FINE = auto()

@dataclass
class EpochConfig:
    poll_sec: int = 3
    collect_interval_sec: int = 30 # collect feedback every 30 seconds
    coarse_min_sec: int  = 2 * 60
    coarse_max_sec: int = 8 * 60
    fine_min_sec: int = 15 * 60
    fine_max_sec: int = 30 * 60
    plateau_k: int = 2            # require at least k points to consider plateau detection
    crash_k: int = 2              # require at least k points to consider process is dead

class EpochScheduler:
    def __init__(self, config: Optional[EpochConfig]):
        self.epoch_config = config or EpochConfig()
        self.phase: Dict[str, Phase] = {}
        self.epoch_start_ts: Dict[str, float] = {}
        self.plateau_streak: Dict[str, int] = {}
        self.crash_streak: Dict[str, int] = {}
        self.last_collect_ts: float = 0.0
        self.window_mgr = FuzzStatsWindowManager()
    
    def _ensure(self, batch: Batch):
        now = time.time()
        for root_api in batch.harness_info.get("harness_files", {}).keys():
            self.phase.setdefault(root_api, Phase.COARSE)
            self.epoch_start_ts.setdefault(root_api, now)
            self.plateau_streak.setdefault(root_api, 0)
            self.crash_streak.setdefault(root_api, 0)
    
    def _epoch_due(self, root_api: str, *, force_condition: bool = False) -> bool:
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
        
    def _collect_analyze(self, batch: Batch, force: bool = False) -> bool:
        now = time.time()
        if not force and now - self.last_collect_ts < self.epoch_config.collect_interval_sec:
            return False
        collect_fuzzer_feedback_to_batch(batch)
        analyze_fuzzer_feedback(batch, self.window_mgr)
        self.last_collect_ts = now
        return True

    def _reset_after_upgrade(self, root_api: str):
        self.window_mgr.reset(root_api)
        self.phase[root_api] = Phase.COARSE
        self.epoch_start_ts[root_api] = time.time()
        self.plateau_streak[root_api] = 0
        self.crash_streak[root_api] = 0

    def run(self, batch_id: str):
        batch = start_fuzzing(batch_id=batch_id)
        self._ensure(batch)

        while True:
            time.sleep(self.epoch_config.poll_sec)
            
            self._collect_analyze(batch, force=True)

            for root_api in self.phase.keys():
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
                    self.phase[root_api] = Phase.COARSE
                    self.epoch_start_ts[root_api] = time.time()
                    self.plateau_streak[root_api] = 0

            force_due: Dict[str, bool] = {r: False for r in self.phase.keys()}

            for root_api in self.phase.keys():
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
            
            due_roots = [r for r in self.phase.keys() if self._epoch_due(r, force_condition=force_due[r])]
            if not due_roots:
                continue

            self._collect_analyze(batch)

            for root_api in due_roots:
                analysis = (batch.fuzz_feedback.get("fuzzer_stats_analysis", {}) or {}).get(root_api, {}) or {}
                stats = (batch.fuzz_feedback.get("fuzzer_stats_feedback", {}) or {}).get(root_api, {}) or {}
                issues = analysis.get("issues", []) or []

                if self.phase[root_api] == Phase.COARSE:
                    if not is_harness_qualified_in_coares_grain(stats, root_api):
                        logger.info(f"[scheduler] Coarse grain analysis for root API {root_api} in batch {batch.batch_id} failed. Upgrading harness.")
                        harness_upgrade_procedure(batch, root_api)
                        self._reset_after_upgrade(root_api)
                    else:
                        self.phase[root_api] = Phase.FINE
                        self.epoch_start_ts[root_api] = time.time()
                        self.plateau_streak[root_api] = 0
                else:
                    if "distance_plateau_period_suspected" in issues and self.plateau_streak[root_api] >= self.epoch_config.plateau_k:
                        logger.info(f"[scheduler] Fine grain analysis for root API {root_api} in batch {batch.batch_id} detected distance plateau. Upgrading harness.")
                        harness_upgrade_procedure(batch, root_api)
                        self._reset_after_upgrade(root_api)
                    else:
                        self.phase[root_api] = Phase.FINE
                        self.epoch_start_ts[root_api] = time.time()
                
        return batch

if __name__ == "__main__":
    scheduler = EpochScheduler(config=None)
    scheduler.run("ffc6b043-1a1a-4e95-a6f2-048f83159a55")