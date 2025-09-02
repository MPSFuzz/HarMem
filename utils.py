import os
import re
import shutil
import json
import logging
import colorlog

from typing import Any, List, Dict
from batch_class import Batch

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

def extract_funcname_from_files(file_path) -> list:
    with open(file_path, "r", encoding="utf-8") as f:
        funcs = [line.strip() for line in f]

    return funcs

def save_to_json(data:Any, filepath: str = "./temp/"):
    directory = os.path.dirname(filepath)

    if directory:
        os.makedirs(directory, exist_ok=True)
    metadata={data.batch_id: data.target_func}
    with open(filepath, "w", encoding="utf-8") as f:
        json.dump(metadata, f, indent=4)

def clean_up_global_vars():
    import _global_vars
    
    for key in _global_vars.root_api_and_harness:
        if _global_vars.root_api_and_harness[key] is None:
            del _global_vars.root_api_and_harness[key]
    
    return

def get_logger(name: str = __name__) -> logging.Logger:
    logger = logging.getLogger(name)
    logger.setLevel(logging.DEBUG)
    
    if not logger.handlers:
        formatter = colorlog.ColoredFormatter(
            fmt="%(log_color)s[%(levelname)s]%(reset)s %(cyan)s%(name)s:%(reset)s %(message)s",
            log_colors={
                'DEBUG':    'white',
                'INFO':     'green',
                'WARNING':  'yellow',
                'ERROR':    'red',
                'CRITICAL': 'bold_red',
            }
        )

        handler = logging.StreamHandler()
        handler.setFormatter(formatter)
        logger.addHandler(handler)

    return logger