import hashlib
import sqlite3

from typing import List, Dict, Any
from extract_call_chain import load_call_graph, get_root_apis, extract_target_call_chain
from gen_hanress import get_available_harness

def set_batch_info(lib_name: str, source_dir: str, dot_file: str, target_funcs: list):
    return
