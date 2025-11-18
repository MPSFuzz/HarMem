import random
import subprocess
import os
import multiprocessing
import concurrent.futures

from src.utils import _global_vars
from src.llm.LLM_class import LLM
from src.llm.build_phase_A_context import build_phase_A_context
from src.static_analyze.aggregator import aggregate_for_chain
from src.static_analyze.extract_call_chain import extract_target_call_chain, get_root_apis, load_call_graph
from src.utils.utils import *

logger = get_logger(__name__)

def get_target_func_location(func_dir: str, target_func: str) -> list: #获得包含目标函数的源文件
    try:
        #cp_command = ["cp", f"./scripts/get_target_func_location.sh", f"/{func_dir}/get_target_func_location.sh"]
        cp_command = ["cp", get_path_in_src("scripts", "get_target_func_location.sh"), f"/{func_dir}/get_target_func_location.sh"]
        subprocess.run(cp_command, capture_output=True, text=True, check=True)
    except subprocess.CalledProcessError as e:
        logger.error(f"Error copying script: {e}")
        raise
    except subprocess.FileNotFoundError:
        logger.error("The get_target_func_location.sh script not found.")
        raise

    func_dir = standarize_path(func_dir)
    command = [f"/{func_dir}/get_target_func_location.sh", f"/{func_dir}", target_func]
    try:
        result = subprocess.run(command, capture_output=True, text=True, check=True)
        output = result.stdout.strip()
        if output:
            file_paths = output.splitlines()
            filenames = [os.path.basename(file_path) for file_path in file_paths]
            assert filenames, "The target function dose not exist in the source code"
            return  filenames
    except subprocess.CalledProcessError as e:
        logger.error(f"Error executing command: {e}")
        raise

    except FileNotFoundError:
        logger.error("The get_target_func_location.sh script was not found.")
        raise

def _process_root_api(root_api, llm: LLM, call_chain, max_fix = 3):
    plan = _global_vars.target_func_plan[root_api]
    phase_A_context = build_phase_A_context(plan)
    llm.get_phase_A_context_and_harness_plan(phase_A_context, plan)
    h = llm.generate_harness_skeleton(call_chain)
    
    llm.generate_code(h, call_chain)
    fix_count = 0

    if h is None:
        logger.error(f"LLM failed to generate harness for root api {root_api} in function {llm.target_func}")
        return root_api, None
    
    ava_flag = h.compile_test()
    while ava_flag == False and fix_count < max_fix:
        h = llm.harness_fix(h)
        h.complete_compile_command()
        h.update_code_file()
        ava_flag = h.compile_test() #TODO: 调整aflgo-clang
        fix_count += 1

    if ava_flag == True:
        logger.info(f"Harness generation sunccess for root api {root_api} in function {llm.target_func}")
        return root_api, h.code_file
    else:
        logger.warning(f"Harness generation failed for root api {root_api} in function {llm.target_func}")
        return root_api, None
    
def _task(root_api, call_chain, compile_commands_path):
    try:
        harness_plan = aggregate_for_chain(call_chain, compile_commands_path)
        return root_api, harness_plan
    except Exception as e:
        logger.error(f"Error aggregating call chain for root api {root_api}: {e}")
        return root_api, None

def get_available_harness(lib_name: str, source_dir: str, dot_file: str, target_func: str, compile_commands_path: str):
    graph = load_call_graph(dot_file=dot_file)

    # for target_func in target_funcs:
    locations = get_target_func_location(source_dir, target_func)
    root_apis = get_root_apis(graph=graph, target_func=target_func)

    llm = LLM(target_func = target_func, target_location = str(locations))

    filtered_entry_apis = llm.entry_api_filter(api_list=root_apis)

    _global_vars.root_api_and_call_chain = extract_target_call_chain(graph=graph, target_func=target_func, root_apis=filtered_entry_apis)
    
    # [quick test] >>>
    test_set = {k: v for i, (k,v) in enumerate(_global_vars.root_api_and_call_chain.items()) if i < 2}
    # <<<

    cpu_counts = multiprocessing.cpu_count()
    logger.debug(f"CPU counts: {cpu_counts}")

    with concurrent.futures.ProcessPoolExecutor(max_workers=10) as executor:
        # futures = [
        #     executor.submit(task, root_api, call_chain, compile_commands_path)
        #     for root_api, call_chain in _global_vars.root_api_and_call_chain.items()
        # ]

        # [quick test] >>>
        futures = [
            executor.submit(_task, root_api, call_chain, compile_commands_path)
            for root_api, call_chain in test_set.items()
        ]
        # <<<

        for future in concurrent.futures.as_completed(futures):
            root_api, harness_plan = future.result()
            if harness_plan is not None:
                _global_vars.target_func_plan[root_api] = harness_plan

    # [save the plans for debug] >>>
    plan_save_path = get_path_in("temp", f"{target_func}_plans.json")
    with open(plan_save_path, "w", encoding="utf-8") as f:
        json.dump(_global_vars.target_func_plan, f, indent=4)
    logger.info(f"Saved harness plans to {plan_save_path}")

    call_chains_save_path = get_path_in("temp", f"{target_func}_call_chains.json")
    with open(call_chains_save_path, "w", encoding="utf-8") as f:
        json.dump(_global_vars.root_api_and_call_chain, f, indent=4)
    logger.info(f"Saved call chains to {call_chains_save_path}")
    # <<<

    with concurrent.futures.ThreadPoolExecutor(max_workers=3) as executor:
        futures = []
        for root_api, call_chain in _global_vars.root_api_and_call_chain.items():
            futures.append(executor.submit(_process_root_api, root_api, llm, call_chain))

        for future in concurrent.futures.as_completed(futures):
            root_api, harness_file = future.result()
            if harness_file:
                _global_vars.root_api_and_harness[root_api] = harness_file
    
    clean_up_harness_file()

if __name__ == "__main__":
    with open("/root/auto_harness/src/temp/xmlNodeGetContent_plans.json", "r", encoding="utf-8") as f:
        _global_vars.target_func_plan = json.load(f)
    
    with open("/root/auto_harness/src/temp/xmlNodeGetContent_call_chains.json", "r", encoding="utf-8") as f:
        _global_vars.root_api_and_call_chain = json.load(f)

    target_func = "xmlNodeGetContent"

    for root_api, call_chain in _global_vars.root_api_and_call_chain.items():
        llm = LLM(target_func=target_func, target_location="/root/libxml2/tree.c")
        _process_root_api(root_api, llm, call_chain)