from src.utils import _global_vars

from src.utils.utils import extract_funcname_from_files, save_to_json, get_path_in
from typing import List, Dict, Any
from src.batch.batch_class import Batch
from src.harness_class.gen_hanress import get_available_harness

def create_batch(lib_name: str, source_dir: str, dot_file: str, target_funcs:str, compile_commands_path: str) -> Any:
    funcs=extract_funcname_from_files(target_funcs)
    
    for func in funcs:
        _global_vars.root_api_and_call_chain.clear()
        _global_vars.root_api_and_harness.clear()
        _global_vars.target_func_plan.clear()

        get_available_harness(lib_name=lib_name, source_dir=source_dir, dot_file=dot_file, target_func=func, compile_commands_path=compile_commands_path)
        batch = Batch(target_func=func)
        batch.harness_info = {
            "root_api_and_call_chain": _global_vars.root_api_and_call_chain,
            "harness_files": _global_vars.root_api_and_harness
        }

        json_path = batch.save_metadata()
        
        #save_to_json(batch, "./temp/batch_id_and_target_func.json")
        save_to_json(batch, get_path_in("temp", "batch_id_and_target_func.json"))

        _global_vars.root_api_and_call_chain.clear()
        _global_vars.root_api_and_harness.clear()

    return