import os
import re
import shutil

FILES_DIR = {
    "DOT_FILE_DIR": "./bc_dot_files/"
}

def standarize_path(path: str) -> str:
    while path.startswith('/'):
        path = path[1:]
    while path.endswith('/'):
        path = path[:-1]
    
    return path

def extract_func_name(full_function_name: str) -> str:
    match = re.match(r'([_a-zA-Z][_a-zA-Z0-9]*)\s*\(.*\)', full_function_name)
    if match:
        return match.group(1)
    else:
        return full_function_name

def clean_up_harness_file():
    harness_dir = "./harness/"
    for dirpath, dirnames, filenames in os.walk(harness_dir):
        if dirpath == harness_dir:
            continue
        has_out_file = any(filename.endswith(".out") for filename in filenames)
        if not has_out_file:
            shutil.rmtree(dirpath)

if __name__ == "__main__":
    clean_up_harness_file()
