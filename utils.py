import os

FILES_DIR = {
    "DOT_FILE_DIR": "./bc_dot_files/"
}


def standarize_path(path: str) -> str:
    while path.startswith('/'):
        path = path[1:]
    while path.endswith('/'):
        path = path[:-1]
    
    return path