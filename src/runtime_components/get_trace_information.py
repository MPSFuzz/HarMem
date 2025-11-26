import os
import json
import random
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import List, Dict, Any

from src.batch.batch_class import Batch
from src.utils.utils import get_logger

logger = get_logger(__name__)

@dataclass
class TraceConfig:
    cc: str = os.environ.get("TRACE_CC", "clang")
    cxx: str = os.environ.get("TRACE_CXX", "clang++")
    cflags: str = os.environ.get("TRACE_CFLAGS", "-g -O0 -fsanitize=address")
    ldflags: str = os.environ.get("TRACE_LDFLAGS", "-ldl")

    trace_runtime_component: str = os.path.join(os.path.dirname(os.path.abspath(__file__)), "/trace_fn_instrument/trace_fn_instrument.c")

    trace_pkg_name = os.environ.get("TRACE_PKG_NAME", "")
    trace_libdir = os.environ.get("TRACE_LIBDIR", "")

    num_recent: int = int(os.environ.get("TRACE_NUM_RECENT", "10"))
    num_random: int = int(os.environ.get("TRACE_NUM_RANDOM", "20"))

# compile harness with tracing instrumentation
def compile_trace_binary(batch: Batch, root_api: str, t_config: TraceConfig):
    try:
        pkg_cflags = subprocess.check_output(
            ["pkg-config", "--cflags", t_config.trace_pkg_name],
            text=True
        ).strip()
        pkg_libs = subprocess.check_output(
            ["pkg-config", "--libs", t_config.trace_libdir],
            text=True
        ).strip()
    except subprocess.CalledProcessError as e:
        logger.error(f"Error occurred while checking pkg-config: {e}")
        raise RuntimeError
    
    harness_path: str = batch.harness_info.get("harness_files", "").get(root_api, "")
    trace_out_path = (Path(harness_path).parent / "trace_out").mkdir(parents=True, exist_ok=True)
    harness_id = Path(harness_path).stem
    trace_binary_path = Path(trace_out_path) / f"trace_{harness_id}"

    try:
        cmd = [
            t_config.cc,
            *t_config.cflags.split(),
            str(harness_path),
            str(t_config.trace_runtime_component),
            *pkg_cflags.split(),
            *pkg_libs.split(),
            *t_config.ldflags.split(),
            f"-Wl,-rpath,{t_config.trace_libdir}",
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

    for case in sampled_case:
        trace_json_output_name = trace_binary_path.parent / f"trace_{case.name}.json"
        env = os.environ.copy()
        env["TRACE_FN_OUTPUT"] = str(trace_json_output_name)

        cmd = [str(trace_binary_path), str(case)]

        try:
            subprocess.check_call(cmd, env=env)
            if trace_json_output_name.exists():
                trace_json.append(trace_json_output_name)
            else:
                logger.warning(f"[Trace] Trace binary exit normally but no output generated for case {case}")
        except subprocess.CalledProcessError as e:
            logger.error(f"[Trace] Error running trace binary on case {case}: {e}")
            continue
    
    logger.info(f"[Trace] Collected trace json for {len(trace_json)} cases")
    
    return trace_json