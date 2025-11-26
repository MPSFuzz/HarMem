import os
import json

from typing import Dict, Any, Optional
from src.utils.utils import get_logger

logger = get_logger(__name__)

def parse_fuzzer_stats_file(outdir_path: str) -> Dict[str, Any]:
    stats_file_path = os.path.join(outdir_path, "fuzzer_stats")
    
    if not os.path.isfile(stats_file_path):
        logger.warning(f"[fuzz feedback parser] fuzzer_stats file not found at {stats_file_path}")
        raise FileNotFoundError(f"fuzzer_stats file not found at {stats_file_path}")

    file_raw_data: Dict[str, Any] = {}
    with open(stats_file_path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.rstrip("\n")
            if ":" not in line:
                continue
            k, v = line.split(":", 1)
            key = k.strip()
            val = v.strip()
            file_raw_data[key] = val
    
    def _get(key: str, default=None) -> str:
        return file_raw_data.get(key, default)
    
    def _parse_int(key: str):
        v = _get(key)
        if v is None:
            return None
        try:
            return int(v)
        except ValueError:
            return None
    
    def _parse_float(key: str):
        v = _get(key)
        if v is None:
            return None
        if v.endswith("%"):
            v = v[:-1]
        try:
            return float(v)
        except ValueError:
            return None
    
    parsed_data: Dict[str, Any] = {
        "start_time": _parse_int("start_time"),
        "last_update": _parse_int("last_update"),
        "fuzzer_pid": _parse_int("fuzzer_pid"),
        "cycles_done": _parse_int("cycles_done"),
        "execs_done": _parse_int("execs_done"),
        "execs_per_sec": _parse_float("execs_per_sec"),
        "paths_total": _parse_int("paths_total"),
        "paths_favored": _parse_int("paths_favored"),
        "paths_found": _parse_int("paths_found"),
        "paths_imported": _parse_int("paths_imported"),
        "max_depth": _parse_int("max_depth"),
        "cur_path": _parse_int("cur_path"),
        "pending_favs": _parse_int("pending_favs"),
        "pending_total": _parse_int("pending_total"),
        "variable_paths": _parse_int("variable_paths"),
        "stability": _parse_float("stability"),
        "bitmap_cvg": _parse_float("bitmap_cvg"),
        "unique_crashes": _parse_int("unique_crashes"),
        "unique_hangs": _parse_int("unique_hangs"),
        "last_path": _parse_int("last_path"),
        "last_crash": _parse_int("last_crash"),
        "last_hang": _parse_int("last_hang"),
        "execs_since_crash": _parse_int("execs_since_crash"),
        "exec_timeout": _parse_int("exec_timeout"),
        "afl_banner": _get("afl_banner"),
        "afl_version": _get("afl_version"),
        "target_mode": _get("target_mode"),
        "command_line": _get("command_line"),
        "slowest_exec_ms": _parse_int("slowest_exec_ms"),
        # AFLGo 距离反馈
        "cur_distance": _parse_float("cur_distance"),
        "max_distance": _parse_float("max_distance"),
        "min_distance": _parse_float("min_distance"),
    }

    return parsed_data

if __name__ == "__main__":
    test_outdir = "/root/auto_harness/src/harness/20251118_080544/out"
    stats = parse_fuzzer_stats_file(test_outdir)