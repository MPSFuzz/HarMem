import json
import os
import subprocess
from pathlib import Path
from typing import Dict, Any, List, Set, Optional
from src.utils.utils import get_logger

logger = get_logger(__name__)


def extract_calls(harness_c_path: str, keywords: List[str]) -> Set[str]:
    """
    Extract external function calls from a compiled harness binary using nm -u.
    Filters symbols that contain at least one keyword.
    """
    out_path = os.path.splitext(harness_c_path)[0] + ".out"
    if not os.path.isfile(out_path):
        return set()

    try:
        result = subprocess.run(
            ["nm", "-u", out_path],
            capture_output=True, text=True, timeout=10
        )
    except Exception:
        return set()

    symbols: Set[str] = set()
    for line in result.stdout.splitlines():
        line = line.strip()
        parts = line.split()
        if len(parts) >= 2:
            name = parts[-1]
            if not keywords:
                symbols.add(name)
            else:
                for kw in keywords:
                    if kw in name:
                        symbols.add(name)
                        break
    logger.info(f"[harness_fusion] nm -u {Path(out_path).name} → {len(symbols)} symbols (keywords={keywords})")
    return symbols


def jaccard_similarity(a: Set[str], b: Set[str]) -> float:
    union = a | b
    if not union:
        return 0.0
    return len(a & b) / len(union)


class HarnessFusion:
    """Tracks similarity of harnesses in one directory to avoid redundant upgrades."""

    TOLERANCE = 2

    def __init__(self, root_api: str, harness_dir: str, keywords: Optional[List[str]] = None,
                 threshold: float = 0.85):
        self.root_api = root_api
        self.harness_dir = harness_dir
        self.keywords = keywords or []
        self.threshold = threshold
        self.tolerance_left = self.TOLERANCE
        self.upgrades_total = 0
        self.accepted: List[Dict[str, Any]] = []
        self.rejected: List[Dict[str, Any]] = []

    def evaluate_new_harness(self, harness_c_path: str, reached_target: bool = False) -> bool:
        """
        Returns True if the new harness should be ACCEPTED (novel enough),
        False if it should be rejected (too similar to an existing one).
        Only compares against previously accepted harnesses that reached the target function.
        """
        self.upgrades_total += 1

        if self.tolerance_left > 0:
            self.tolerance_left -= 1
            logger.info(f"[harness_fusion] {self.root_api}: upgrade {self.upgrades_total} within tolerance ({self.TOLERANCE - self.tolerance_left}/{self.TOLERANCE}), auto-accept")
            new_calls = extract_calls(harness_c_path, self.keywords)
            self.accepted.append({
                "id": self.upgrades_total,
                "calls": sorted(new_calls),
                "reached_target": reached_target,
                "harness_path": harness_c_path,
            })
            return True

        new_calls = extract_calls(harness_c_path, self.keywords)
        if not new_calls:
            logger.warning(f"[harness_fusion] {self.root_api}: no calls extracted, rejecting")
            return False

        # only compare against harnesses that reached the target
        target_harnesses = [acc for acc in self.accepted if acc.get("reached_target")]
        if not target_harnesses:
            target_harnesses = self.accepted
            logger.info(f"[harness_fusion] {self.root_api}: no accepted harness reached target, comparing all")

        # compute Jaccard against each reached_target harness
        scores = {}
        max_sim = 0.0
        for acc in target_harnesses:
            sim = jaccard_similarity(new_calls, set(acc["calls"]))
            scores[f"vs_{acc['id']}"] = round(sim, 3)
            max_sim = max(max_sim, sim)

        logger.info(f"[harness_fusion] {self.root_api}: new harness ({len(new_calls)} calls) vs {len(target_harnesses)} accepted, scores={scores}")

        if max_sim > self.threshold:
            self.rejected.append({
                "id": self.upgrades_total,
                "reason": f"too_similar (max_jaccard={max_sim:.3f})",
                "scores": scores,
                "harness_path": harness_c_path,
            })
            logger.info(f"[harness_fusion] {self.root_api}: rejected (max_jaccard={max_sim:.3f} > {self.threshold}, scores={scores})")
            return False

        self.accepted.append({
            "id": self.upgrades_total,
            "calls": sorted(new_calls),
            "reached_target": reached_target,
            "harness_path": harness_c_path,
        })
        logger.info(f"[harness_fusion] {self.root_api}: accepted (max_jaccard={max_sim:.3f} < {self.threshold})")
        return True

    def to_dict(self) -> Dict[str, Any]:
        return {
            "root_api": self.root_api,
            "harness_dir": self.harness_dir,
            "threshold": self.threshold,
            "tolerance_left": self.tolerance_left,
            "upgrades_total": self.upgrades_total,
            "accepted": self.accepted,
            "rejected": self.rejected,
        }

    def save(self, path: str):
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        Path(path).write_text(json.dumps(self.to_dict(), indent=2, ensure_ascii=False), encoding="utf-8")
        logger.info(f"[harness_fusion] Saved to {path}")

    @classmethod
    def load(cls, path: str, keywords: Optional[List[str]] = None, threshold: float = 0.85) -> "HarnessFusion":
        d = json.loads(Path(path).read_text(encoding="utf-8"))
        obj = cls(
            root_api=d.get("root_api", ""),
            harness_dir=d.get("harness_dir", ""),
            keywords=keywords or d.get("keywords", []),
            threshold=threshold or d.get("threshold", 0.85),
        )
        obj.tolerance_left = d.get("tolerance_left", obj.TOLERANCE)
        obj.upgrades_total = d.get("upgrades_total", 0)
        obj.accepted = d.get("accepted", [])
        obj.rejected = d.get("rejected", [])
        return obj

    @classmethod
    def from_harness_dir(cls, root_api: str, harness_dir: str, keywords: List[str],
                         threshold: float = 0.85) -> "HarnessFusion":
        fusion_path = os.path.join(harness_dir, "harness_fusion.json")
        if os.path.isfile(fusion_path):
            return cls.load(fusion_path, keywords=keywords, threshold=threshold)
        obj = cls(root_api=root_api, harness_dir=harness_dir, keywords=keywords, threshold=threshold)
        obj._bootstrap_from_memory_files()
        return obj

    def _bootstrap_from_memory_files(self):
        import glob as _glob
        import re
        mem_files = sorted(_glob.glob(os.path.join(self.harness_dir, "*_harness_memory.json")))
        if not mem_files:
            logger.info(f"[harness_fusion] No existing memory files in {self.harness_dir}")
            return

        pat = re.compile(r"(\d{8}_\d{6})_harness_memory\.json$")
        for mf in mem_files:
            m = pat.search(mf)
            if not m:
                continue
            ts = m.group(1)
            old_c = os.path.join(self.harness_dir, f"{ts}_old.c")
            if not os.path.isfile(old_c):
                logger.warning(f"[harness_fusion] Bootstrap: no old backup found for {ts}, skipping")
                continue

            reached_target = False
            try:
                mem = json.loads(Path(mf).read_text(encoding="utf-8"))
                for it in mem.get("iterations", []):
                    ac = it.get("actual_chain", [])
                    if ac and ac[-1].get("reach_rate", 0) > 0:
                        reached_target = True
                        break
            except Exception:
                pass

            calls = extract_calls(old_c, self.keywords)
            if calls:
                self.upgrades_total += 1
                self.accepted.append({
                    "id": self.upgrades_total,
                    "calls": sorted(calls),
                    "reached_target": reached_target,
                    "harness_path": old_c,
                })
                logger.info(f"[harness_fusion] Bootstrapped #{self.upgrades_total} from {os.path.basename(old_c)} "
                            f"({len(calls)} calls, reached_target={reached_target})")

        # mark already-seen upgrades as consumed from tolerance
        self.tolerance_left = max(0, self.TOLERANCE - len(self.accepted))
        logger.info(f"[harness_fusion] Bootstrapped {len(self.accepted)} from {len(mem_files)} memory files, "
                    f"tolerance_left={self.tolerance_left}")
