import os
import json
import shutil

from typing import List, Dict, Any, Optional
from src.batch.batch_class import Batch
from src.llm.LLM_class import LLM
from src.harness_class.harness_class import harness
from src.fuzz_components.fuzz_runner import start_fuzzing
from src.utils.utils import get_logger

logger = get_logger(__name__)

def _kill_fuzz_process(pid: str, harness_save_path: str):
    try:
        os.kill(pid, 9)
        outdir_path = os.path.join(harness_save_path, "out")
        for item in os.listdir(outdir_path):
            item_path = os.path.join(outdir_path, item)
            if os.path.isdir(item_path):
                shutil.rmtree(item_path)
            else:
                os.remove(item_path)

        logger.info(f"Killed fuzzing process with PID {pid} and the out dir has been cleared.")
    except ProcessLookupError as e:
        logger.error(f"pid: {pid} dose not exist or has already been terminated : {e}")
        return

def harness_upgrade_procedure(batch: Batch, root_api: str) -> bool:
    code = None
    code_file = batch.harness_info.get("harness_files", {}).get(root_api, "")
    code_save_folder = os.path.dirname(code_file)
    if not code_file:
        logger.error(f"No harness file found for root API {root_api} in batch {batch.batch_id}")
        raise FileNotFoundError(f"No harness file found for root API {root_api}")
    
    with open(code_file, "r", encoding="utf-8") as f:
        code = f.read()
    
    target_func = batch.target_func
    skeleton_path = batch.harness_info.get("harness_skeletons_files", {}).get(root_api, "")
    plan_path = batch.harness_info.get("harness_plans_files", "")
    fuzzer_stats = batch.fuzz_feedback.get("fuzzer_stats_feedback", {}).get(root_api, {})
    analysis_result = batch.fuzz_feedback.get("fuzzer_stats_analysis", {}).get(root_api, {})

    if not plan_path or not skeleton_path:
        logger.error(f"No plan or skeleton found for root API {root_api} in batch {batch.batch_id}")
        raise FileNotFoundError(f"No plan or skeleton found for root API {root_api}")
    
    with open(plan_path, "r", encoding="utf-8") as f:
        plan = json.load(f)

    h = harness(
        code=code,
        code_file=code_file,
        code_save_folder=code_save_folder,
        target_func=target_func,
        skeleton_path=skeleton_path
    )

    if "distance_plateau_period_suspected" in analysis_result.get("issues", ""):
    # TODO: when harness is suspected to be in a distance plateau, execute a specific upgrade strategy
        pass
    else:
        llm = LLM(target_func=batch.target_func)
        llm.get_harness_plan(plan)

        llm.phased_harness_upgrade_1(
            plan_path=plan_path,
            fuzzer_stats=fuzzer_stats,
            analysis_result=analysis_result,
            h=h
        )

        # terminate the ongoing fuzzing process for this root_api
        pid = batch.fuzzer_pids.get(root_api, None)
        if pid:
            _kill_fuzz_process(pid, code_save_folder)
        
        h.complete_compile_command()

        ava_flag = h.compile_test()
        fix_count = 0

        while ava_flag == False and fix_count < 3:
            h = llm.harness_fix(h)
            h.complete_compile_command()
            ava_flag = h.compile_test()
            fix_count += 1
        
        if ava_flag == True:
            logger.info(f"Harness upgrade success for root api {root_api} in function {batch.target_func}")

            # Restart the fuzz process for this root_api
            if start_fuzzing(batch=batch, selected_root_api=root_api):
                logger.info(f"Upgrade harness and restarted fuzzing process for upgraded harness of root API {root_api}")
                return True
            else:
                logger.error(f"Failed to restart fuzzing process for upgraded harness of root API {root_api}")
                return False
        