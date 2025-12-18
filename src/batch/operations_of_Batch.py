import os

from src.utils import _global_vars
from src.utils.utils import extract_funcname_from_files, save_to_json, get_path_in, get_parent_dir, get_logger
from typing import List, Dict, Any, Optional
from src.batch.batch_class import Batch
from src.harness_class.gen_hanress import get_available_harness
from src.fuzz_components.fuzz_feedback_parser import parse_fuzzer_stats_file
from src.fuzz_components.fuzzer_feed_back_analysis import fuzzer_stats_analysis, FuzzStatsWindowManager

logger = get_logger(__name__)

def create_batch(lib_name: str, source_dir: str, dot_file: str, target_funcs:str, compile_commands_path: str) -> Any:
    funcs=extract_funcname_from_files(target_funcs)
    
    for func in funcs:
        _global_vars.root_api_and_call_chain.clear()
        _global_vars.root_api_and_harness.clear()
        _global_vars.target_func_plan.clear()

        get_available_harness(lib_name=lib_name, source_dir=source_dir, dot_file=dot_file, target_func=func, compile_commands_path=compile_commands_path)
        batch = Batch(target_func=func, lib_name=lib_name)
        batch.harness_info = {
            # "root_api_and_call_chain": _global_vars.root_api_and_call_chain,
            "harness_skeletons_files": _global_vars.harness_skeletons_files,
            "harness_plans_files": get_path_in("harness_plans", f"{func}_plans.json"),
            "harness_files": _global_vars.root_api_and_harness,
            # "fuzz_commands": _global_vars.fuzz_commands
        }

        json_path = batch.save_metadata()
        logger.info(f"Saved batch metadata to {json_path}")

        
        #save_to_json(batch, "./temp/batch_id_and_target_func.json")
        save_to_json(batch, get_path_in("temp", "batch_id_and_target_func.json"))

        _global_vars.root_api_and_call_chain.clear()
        _global_vars.root_api_and_harness.clear()
        _global_vars.harness_skeletons_files.clear()
        _global_vars.target_func_plan.clear()

    return batch.batch_id

def collect_fuzzer_feedback_to_batch(batch: Batch):
    for root_api, harness_file_path in batch.harness_info.get("harness_files", {}).items():
        outdir_path = get_parent_dir(harness_file_path)
        outdir_path = os.path.join(outdir_path, "out")
        fuzzer_feedback = parse_fuzzer_stats_file(outdir_path)

        if "fuzzer_stats_feedback" not in batch.fuzz_feedback:
            batch.fuzz_feedback["fuzzer_stats_feedback"] = {}

        batch.fuzz_feedback["fuzzer_stats_feedback"][root_api] = fuzzer_feedback
    
    batch.save_metadata()

def analyze_fuzzer_feedback(batch: Batch, window_mgr: Optional[FuzzStatsWindowManager] = None):
    for root_api, feedback in batch.fuzz_feedback.get("fuzzer_stats_feedback", {}).items():
        analysis_result = fuzzer_stats_analysis(feedback, root_api, window_mgr)
        if "fuzzer_stats_analysis" not in batch.fuzz_feedback:
            batch.fuzz_feedback["fuzzer_stats_analysis"] = {}

        batch.fuzz_feedback["fuzzer_stats_analysis"][root_api] = analysis_result
    
    batch.save_metadata()
