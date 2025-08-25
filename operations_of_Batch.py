import _global_vars

from typing import List, Dict, Any
from batch_class import Batch
from gen_hanress import get_available_harness

def create_batch(lib_name: str, source_dir: str, dot_file: str, target_funcs:str) -> Any:
    with open(target_funcs, 'r', encoding="utf-8") as f:
        funcs = [line.strip() for line in f]
    
    for func in funcs:
        get_available_harness(lib_name=lib_name, source_dir=source_dir, dot_file=dot_file, target_func=func)
        batch = Batch(target_func=func)
        batch.harness_info = {
            "root_api_and_call_chain": _global_vars.root_api_and_call_chain,
            "harness_files": _global_vars.root_api_and_harness
        }

        json_path = batch.save_metadata()

        #TODO: 这里在utils中添加一个函数，将batch_id（代表一个batch）与target_func形成对应关系，并将这个对应关系存到一个json文件中

        _global_vars.root_api_and_call_chain.clear()
        _global_vars.root_api_and_harness.clear()

    return