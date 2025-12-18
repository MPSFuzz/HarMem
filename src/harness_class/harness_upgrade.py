import os
import json
import shutil

from typing import List, Dict, Any, Optional
from pathlib import Path
from src.batch.batch_class import Batch
from src.llm.LLM_class import LLM
from src.harness_class.harness_class import harness, seed_for_harness
from src.fuzz_components.fuzz_runner import start_fuzzing
from src.runtime_components.filter_merged_compile_pass_metadata import get_filtered_metadata_for_specific_root_api
from src.runtime_components.get_runtime_trace_result import get_aggregate_runtime_trace_information
from src.runtime_components.runtime_trace_feedback_analysis import build_llm_feedback_prompt
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

def _save_modified_seeds(seeds: List[seed_for_harness]) -> bool:
    for s in seeds:
        try:
            with open(s.seed_save_path, "w", encoding="utf-8") as f:
                f.write(s.seed_content)
        except Exception as e:
            logger.error(f"[harness_upgrade] Failed to save modified seed to {s.seed_save_path}: {e}")
            return False
    
    return True

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
        baseline_seeds_path = Path(code_file).parent / "in"
        baseline_seeds = [p for p in baseline_seeds_path.iterdir() if p.is_file()]

        filtered_metadata_path = get_filtered_metadata_for_specific_root_api("/tmp", batch, root_api)
        sampled_cases_pathes, sampled_queue_seed_runtime_trace_result = get_aggregate_runtime_trace_information(batch, root_api, filtered_metadata_path, str(baseline_seeds_path))
        prompt = build_llm_feedback_prompt(batch, sampled_queue_seed_runtime_trace_result, code_file, baseline_seeds, sampled_cases_pathes)

        llm = LLM(target_func=batch.target_func)
        llm.get_harness_plan(plan)

        type, response = llm.phased_harness_upgrade_2(h, prompt)
        if type == "only_modified_seeds":
            upgrade_flag = _save_modified_seeds(response)
            if upgrade_flag:
                logger.info(f"[Harness_upgrade] Seeds upgrade success for root api {root_api} in function {batch.target_func}")
                
                # terminate the ongoing fuzzing process for this root_api
                pid = batch.fuzzer_pids.get(root_api, None)
                if pid:
                    _kill_fuzz_process(pid, code_save_folder)
                
                if start_fuzzing(batch=batch, selected_root_api=root_api):
                    logger.info(f"[Harness_upgrade] Upgrade seeds and restarted fuzzing process for upgraded seeds of root API {root_api}")
                    return True
                else:
                    logger.error(f"[Harness_upgrade] Failed to restart fuzzing process for upgraded seeds of root API {root_api}")
                    return False
            
            return True
        
        elif type == "only_modified_harness":
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
                logger.info(f"[Harness_upgrade] Harness upgrade success for root api {root_api} in function {batch.target_func}")

                # Restart the fuzz process for this root_api
                if start_fuzzing(batch=batch, selected_root_api=root_api):
                    logger.info(f"[Harness_upgrade] Upgrade harness and restarted fuzzing process for upgraded harness of root API {root_api}")
                    return True
                else:
                    logger.error(f"[Harness_upgrade] Failed to restart fuzzing process for upgraded harness of root API {root_api}")
                    return False
                
        elif type == "modified_seeds_and_harness":
            _save_modified_seeds(response)

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
                logger.info(f"[Harness_upgrade] Harness upgrade success for root api {root_api} in function {batch.target_func}")

                # Restart the fuzz process for this root_api
                if start_fuzzing(batch=batch, selected_root_api=root_api):
                    logger.info(f"[Harness_upgrade] Upgrade harness and restarted fuzzing process for upgraded harness of root API {root_api}")
                    return True
                else:
                    logger.error(f"[Harness_upgrade] Failed to restart fuzzing process for upgraded harness of root API {root_api}")
                    return False
                
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
            logger.info(f"[Harness_upgrade] Harness upgrade success for root api {root_api} in function {batch.target_func}")

            # Restart the fuzz process for this root_api
            if start_fuzzing(batch=batch, selected_root_api=root_api):
                logger.info(f"[Harness_upgrade] Upgrade harness and restarted fuzzing process for upgraded harness of root API {root_api}")
                return True
            else:
                logger.error(f"[Harness_upgrade] Failed to restart fuzzing process for upgraded harness of root API {root_api}")
                return False
        