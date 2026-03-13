import os
import re
import shutil
import json
import logging
import colorlog

from pathlib import Path
from typing import Any, List, Dict, Tuple
#from ..batch.batch_class import Batch


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
    harness_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "harness/")
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

def clean_markdown_format(text: str):
    text = re.sub(r"```(?:json)?\s*", "", text)
    text = re.sub(r"\s*```", "", text)
    return text.strip()

def extract_json_from_text(text: str):
    try:
        json_match = re.search(r'\{.*\}', text, re.DOTALL)
        if json_match:
            json_str = json_match.group(0)
            return json_str
    except Exception as e:
        logger = get_logger("DEBUG")
        logger.error(f"Error extracting JSON from text: {e}")

def get_path_subfolder(subfolder: str) -> str:
    root_dir = os.path.abspath(os.path.join(os.path.abspath(__file__), "..", ".."))
    dir_path = os.path.join(root_dir, subfolder)
    os.makedirs(dir_path, exist_ok=True)
    return dir_path

def get_path_in(subfolder: str, filename: str) -> str:
    root_dir = os.path.abspath(os.path.join(os.path.abspath(__file__), "..", ".."))
    dir_path = os.path.join(root_dir, subfolder)
    os.makedirs(dir_path, exist_ok=True)
    return os.path.join(dir_path, filename)

def get_path_in_src(subfolder: str, filename: str) -> str:
    root_dir = os.path.abspath(os.path.join(os.path.abspath(__file__), "..", "..", ".."))
    dir_path = os.path.join(root_dir, subfolder)
    os.makedirs(dir_path, exist_ok=True)
    return os.path.join(dir_path, filename)

def get_parent_dir(path: str) -> str:
    p = Path(path)
    return str(p.parent)

def parse_target_file(target_path: str, plan: Dict, target_func: str) -> List[Tuple[str, int]]:
    out : List[Tuple[str, int]] = []
    nodes = plan.get("chain", {}).get("nodes", {})
    for n in nodes:
        if n.get("name", "") == target_func:
            file_path = n.get("impl", {}).get("file", "")

    p = Path(target_path)
    if not p.is_file():
        return out
    
    for raw in p.read_text(encoding="utf-8", errors="ignore").splitlines():
        s = raw.strip()
        if not s or s.startswith("#"):
            continue
        if ":" not in s:
            continue
        _, ln = s.split(":", 1)
        try:
            out.append((file_path, int(ln.strip())))
        except Exception:
            continue

    return out

def extract_target_func_code_from_plan(plan: Dict, target_func: str) -> str:
    nodes = plan.get("chain", {}).get("nodes", {})
    for n in nodes:
        if n.get("name", "") == target_func:
            source_code = n.get("impl", {}).get("code", "")
            return source_code

def load_source_snippet(file_path: str, line: int, context: int = 3) -> str:
    try:
        p = Path(file_path)
        if not p.is_file():
            return ""
        lines = p.read_text(encoding="utf-8", errors="ignore").splitlines()
        if line <= 0:
            line = 1
        start = max(1, line - context)
        end = min(len(lines), line + context)
        snippet_lines = lines[start - 1 : end]

        numbered = [
            f"{start + i:6d}: {snippet_lines[i]}" for i in range(len(snippet_lines))
        ]
        header = f"{file_path}:L{start}-L{end}"
        return header + "\n" + "\n".join(numbered)
    except Exception as e:
        return ""


def clip_text(text: str, max_chars: int = 4000) -> str:
    text = text or ""
    if len(text) <= max_chars:
        return text
    return text[:max_chars] + "\n...[truncated]..."

def copy_seeds_provided_by_user(src_dir: Path, dest_dir: Path) -> bool:
    if not src_dir.exists() or not src_dir.is_dir():
        return False
    
    dest_dir.mkdir(parents=True, exist_ok=True)

    for item in src_dir.iterdir():
        target = dest_dir / item.name
        if item.is_dir():
            continue
        else:
            shutil.copy2(item, target)

    return True