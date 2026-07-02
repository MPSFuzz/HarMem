import os
import subprocess

from typing import Dict, Any, Optional
from pathlib import Path
from src.utils.utils import get_logger
from src.utils.utils import get_path_in, copy_seeds_provided_by_user
from src.batch.batch_class import Batch

logger = get_logger(__name__)

_shell_env_cache: Optional[dict] = None

def _process_harness_path(harness_sourcecode_path: str) -> str:
    p = Path(harness_sourcecode_path)
    harness_path = p.with_suffix(".out")

    return str(harness_path)

def _ensure_seed_dir(input_path: str, seeds_path: Optional[str]=None) -> None:
    os.makedirs(input_path, exist_ok=True)

    if seeds_path:
        if copy_seeds_provided_by_user(Path(seeds_path), Path(input_path)):
            logger.info(f"[fuzz] copied seed inputs from {seeds_path} to {input_path}")
            return
        else:
            logger.warning(f"[fuzz] failed to copy seed inputs from {seeds_path} to {input_path}, will use default seed instead")

    has_files = any(Path(input_path).iterdir())
    if not has_files:
        seed_path = os.path.join(input_path, "seed_default")
        with open(seed_path, "w", encoding="utf-8") as f:
            f.write("111\n")
        logger.info(f"[fuzz] created default seed at {seed_path}")

def _generate_fuzz_command(harness_path: str, seeds_path: Optional[str]=None) -> str:
    p = Path(harness_path)
    harness_dir = str(p.parent)

    input_path = os.path.join(harness_dir, "in")
    output_path = os.path.join(harness_dir, "out")
    dict_path = os.path.join(harness_dir, "harness_dict.dict")

    _ensure_seed_dir(input_path, seeds_path)
    os.makedirs(output_path, exist_ok=True)

    dict_arg = f"-x {dict_path}" if os.path.exists(dict_path) else ""

    fuzz_command = (
        f"afl-fuzz -m none -z exp "
        f"-i {input_path} -o {output_path} {dict_arg} -- {harness_path} @@"
    )

    return fuzz_command

def _get_interactive_shell_env() -> dict:
    try:
        output = subprocess.check_output(
            ["bash", "-lc", "env"], text=True, timeout=5
        )
        env_vars = {}
        for line in output.strip().split("\n"):
            if "=" in line:
                k, v = line.split("=", 1)
                env_vars[k] = v
        return env_vars
    except Exception as e:
        logger.error(f"Failed to get interactive shell environment variables: {e}")
        return {}

def _get_env_var() -> dict:
    global _shell_env_cache
    if _shell_env_cache is None:
        shell_env = _get_interactive_shell_env()
        env = os.environ.copy()
        if shell_env:
            env.update(shell_env)
        for k in ("AFL_NO_AFFINITY", "AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES", "AFL_SKIP_CPUFREQ"):
            env.setdefault(k, "1")
        _shell_env_cache = env
    return _shell_env_cache

def _clean_out_dir(harness_sourcecode_path: str):
    p = Path(harness_sourcecode_path)
    harness_dir = str(p.parent)
    out_dir = os.path.join(harness_dir, "out")

    if os.path.exists(out_dir):
        try:
            for file in os.listdir(out_dir):
                file_path = os.path.join(out_dir, file)
                if os.path.isfile(file_path) or os.path.islink(file_path):
                    os.unlink(file_path)
                elif os.path.isdir(file_path):
                    import shutil
                    shutil.rmtree(file_path)
            logger.info(f"[fuzz] Cleaned output directory: {out_dir}")
        except Exception as e:
            logger.error(f"[fuzz] Failed to clean output directory {out_dir}: {e}")

def _run_fuzzer(harness_sourcecode_path: str, seeds_path: Optional[str] = None):
        harness_path = _process_harness_path(harness_sourcecode_path)
        fuzz_command = _generate_fuzz_command(harness_path, seeds_path=seeds_path)

        env = _get_env_var()

        if not os.path.exists(harness_path):
            logger.error(f"[fuzz] harness binary not found: {harness_path}")
            return ""

        try:
            p = Path(harness_path).with_suffix(".aflgo_log")
            log_file = open(p, "a", encoding="utf-8")

            proc = subprocess.Popen(
                fuzz_command,
                shell=True,
                executable="/bin/bash",
                stdout=subprocess.DEVNULL,
                stderr=log_file,
                env=env,
                text=True,
            )
            logger.info(
                f"[fuzz] Started fuzzing successfully (pid={proc.pid}) "
                f"with command: {fuzz_command}"
            )

            return proc.pid

        except subprocess.CalledProcessError as e:
            return ""

def start_fuzzing(batch_id: Optional[str] = None,  batch: Optional[Batch] = None, selected_root_api: Optional[str] = None, seeds_path: Optional[str] = None) -> Batch | bool:
    if batch and selected_root_api:
        harness_info = batch.harness_info
        harness_sourcecode_path = harness_info["harness_files"].get(selected_root_api, "")

        _clean_out_dir(harness_sourcecode_path)
        pid = _run_fuzzer(harness_sourcecode_path, seeds_path=seeds_path)
        if pid:
            batch.fuzzer_pids[selected_root_api] = pid
            logger.info(f"[fuzz] Fuzzing started successfully for selected root API: {selected_root_api}")
            return True
        else:
            logger.error(f"[fuzz] Fuzzing failed to start for selected root API: {selected_root_api}")
            return False

    elif batch_id:
        file_path = get_path_in("batch_metadata", f"{batch_id}.json")
        if not os.path.isfile(file_path):
            logger.error(f"[fuzz] batch metadata not found: {file_path}")
            return None
        batch_instance = Batch.load_metadata(file_path)

        harness_info: Dict[str, Any] = batch_instance.harness_info

        pids: Dict[str, int] = {}
        for root_api, harness_sourcecode_path in harness_info["harness_files"].items():
            _clean_out_dir(harness_sourcecode_path)
            pid = _run_fuzzer(harness_sourcecode_path, seeds_path=seeds_path)
            if pid:
                pids[root_api] = pid
                batch_instance.fuzzer_pids = pids
            else:
                logger.error(f"[fuzz] Fuzzing failed to start for root API: {root_api}")
        
        return batch_instance

if __name__ == "__main__":
    batch = start_fuzzing("281bed94-b819-4c8c-8b94-7657e9f40a88")
    from src.harness_class.harness_upgrade import harness_upgrade_procedure
    from src.batch.operations_of_Batch import collect_fuzzer_feedback_to_batch, analyze_fuzzer_feedback
    collect_fuzzer_feedback_to_batch(batch)
    analyze_fuzzer_feedback(batch)

    harness_upgrade_procedure(batch, "xmlDocCopyNodeList")