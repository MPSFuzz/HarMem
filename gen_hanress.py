import argparse
import random
import subprocess
import os
import _global_vars

from LLM_class import LLM
from extract_call_chain import extract_target_call_chain, get_root_apis, load_call_graph
from utils import *

def get_target_func_location(func_dir: str, target_func: str) -> list: #获得包含目标函数的源文件
    try:
        cp_command = ["cp", f"./scripts/get_target_func_location.sh", f"/{func_dir}/get_target_func_location.sh"]
        subprocess.run(cp_command, capture_output=True, text=True, check=True)
    except subprocess.CalledProcessError as e:
        assert False, f"Error copying script: {e}"
    except subprocess.FileNotFoundError:
        assert False, "The get_target_func_location.sh script not found."

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
        print(f"Error executing command: {e}")
        assert False, "The get_target_func_location.sh execution failed"
    
    except FileNotFoundError:
        print("The get_target_func_location.sh script was not found.")
        assert False, "The get_target_func_location.sh script was not found."

def get_available_harness(lib_name: str, source_dir: str, dot_file: str, target_func: str): #暂定退出循环的条件是获得一个编译成功的harness后退出,返回存储harness的路径
    graph = load_call_graph(dot_file=dot_file)

    # for target_func in target_funcs:
    locations = get_target_func_location(source_dir, target_func)
    root_apis = get_root_apis(graph=graph, target_func=target_func)

    llm = LLM(target_func = target_func, target_location = str(locations))


    filtered_entry_apis = llm.entry_api_filter(api_list=root_apis)

    _global_vars.root_api_and_call_chain = extract_target_call_chain(graph=graph, target_func=target_func, root_apis=filtered_entry_apis)
    
    ava_flag = False
    gen_count = 0
    fix_count = 0
    #random.shuffle(_global_vars.root_api_and_call_chain)

    for root_api in _global_vars.root_api_and_call_chain:
        llm.update(lib_name=lib_name, target_func=target_func, call_chain=_global_vars.root_api_and_call_chain[root_api], target_location=str(locations))
        fix_count = 0
        try:
            llm.generate_code()
        except Exception as e:
            raise SystemExit(f"LLM generation failed with error: {e}")
        
        ava_flag = llm.harness_instance.compile_test()

        while ava_flag == False and fix_count < 3:
            try:
                llm.harness_fix()
                llm.harness_instance.complete_compile_command()
            except Exception as e:
                print(f"LLM fix failed with error: {e}")
            
            ava_flag = llm.harness_instance.compile_test()
            fix_count += 1
        
        if ava_flag == False:
            _global_vars.root_api_and_harness[root_api] = None
            print(f"Harness generation failed for root api {root_api} in function {target_func}")
        else:
            _global_vars.root_api_and_harness[root_api] = llm.harness_instance.code_file
            gen_count += 1

        print(f"harness for function:{llm.harness_instance.target_func} in call chain begin at: {root_api} generates successfully\n" \
            f" The harness for this function has saved to {llm.harness_instance.code_file}")
    
    clean_up_harness_file()


# if __name__ == "__main__":
