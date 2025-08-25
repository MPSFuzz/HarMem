import argparse
import os

from gen_hanress import get_available_harness
from utils import FILES_DIR

def main():
    parser = argparse.ArgumentParser(description="Generate harnesses for those functions that were modified or added in the given program.")

    # args_group = parser.add_mutually_exclusive_group(required=True)

    #TODO: 当前的生成harness的粒度是函数级别的，后续需要将这个粒度细化到行级别的
    #TODO: 在utils中添加一个函数，后续目标函数名（或者是源文件行号）处理为包含相关信息的对应列表
    #TODO: 当前的所有操作都是单线程的，后续考虑将这些操作做成多线程

    parser.add_argument(
        "--lib_name", "-l",
        type=str,
        help="The name of the library to generate harnesses for. "
    )

    parser.add_argument(
        "--function-name", "-f",
        nargs='+',
        type=str,
        required=True,
        help="The names of the target function to generate a harness for."
    )

    parser.add_argument(
        "--project-path", "-p",
        type=str,
        required=True,
        help="The path to the project directory."
    )

    parser.add_argument(
        "--dot-file", "-d",
        type=str,
        required=True
    )

    args = parser.parse_args()

    assert os.path.isdir(args.project_path), f"Project path {args.project_path} is not a valid directory."
    assert os.path.exists(args.project_path), f"Project path {args.project_path} does not exist."
    assert os.path.isfile(args.dot_file), f"Dot file {args.dot_file} does not exist."

    lib_name = args.lib_name
    source_dir = args.project_path
    dot_file = args.dot_file
    target_funcs = args.function_name

    get_available_harness(lib_name=lib_name, source_dir=source_dir, dot_file=dot_file, target_funcs=target_funcs)

if __name__ == "__main__":
    main()

