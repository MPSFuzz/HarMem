import argparse
import random
import subprocess
import os

from operations_of_LLM import LLM
from extract_the_call_chain import extract_target_call_chain
from utils import *

def extract_call_chains(target_func: str, dot_file: str) -> list: #提取目标函数的调用链
    call_chains = extract_target_call_chain(dot_file, target_func)

    assert call_chains, "call_chains not found"
    
    return call_chains

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
    
    except subprocess.FileNotFoundError:
        print("The get_target_func_location.sh script was not found.")
        assert False, "The get_target_func_location.sh script was not found."

def get_target_function(func_dir: str, old_commit: str, new_commit: str) -> list:
    try:
        cp_command = ["cp", f"./scripts/get_target_func_location.sh", f"{func_dir}/get_target_func_location.sh"]
        subprocess.run(cp_command, capture_output=True, text=True, check=True)
    except subprocess.CalledProcessError as e:
        assert False, f"Error copying script: {e}"
    except subprocess.FileNotFoundError:
        assert False, "The get_target_func_location.sh script or program file was not found."

    func_dir = standarize_path(func_dir)
    command = [f"/{func_dir}/get_modification.sh", old_commit, new_commit]
    try:
        result = subprocess.run(command, capture_output=True, text=True, check=True)
        output = result.stdout.strip()
        if output:
            function_names = output.splitlines()
            target_functions = [function_name for function_name in function_names]
            assert target_functions, "There is no function had been modified in the program"
            return  target_functions
    except subprocess.CalledProcessError as e:
        print(f"Error executing command: {e}")
        assert False, "The get_modification.sh execution failed"
    
    except subprocess.FileNotFoundError:
        assert False, "The get_modification.sh script was not found." 

def get_available_harness(source_dir: str, dot_file: str, target_func: str|None = None, old_commit: str|None = None, new_commit: str|None = None) -> str: #暂定退出循环的条件是获得一个编译成功的harness后退出,返回存储harness的路径
    if target_func == None:
        target_func = get_target_function(source_dir, old_commit, new_commit)
        assert target_func, "There is no function had been modified in the program"

    call_chains = extract_call_chains(target_func, dot_file)
    locations = get_target_func_location(source_dir, target_func)
    random.shuffle(call_chains)
    ava_flag = False
    gen_count = 0

    while ava_flag == False and gen_count < len(call_chains):
        current_call_chain = call_chains[gen_count]
        llm = LLM(target_func = target_func, call_chain = current_call_chain, target_location = str(locations))
        fix_count = 0
        try:
            llm.generate_code()
        except Exception as e:
            print(f"LLM generation failed with error: {e}")
        
        ava_flag = llm.harness_instance.compile_test()

        while ava_flag == False and fix_count < 3:
            try:
                llm.harness_fix()
                llm.harness_instance.complete_compile_command()
            except Exception as e:
                print(f"LLM fix failed with error: {e}")
            
            ava_flag = llm.harness_instance.compile_test()
            fix_count += 1
        
        gen_count += 1

        print(f"harness for function:{llm.harness_instance.target_func} generates successfully\n" \
            f" The harness for this function has saved to {llm.harness_instance.code_file}")
    
    return llm.harness_instance.code_file




