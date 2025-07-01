import argparse
import os

from gen_hanress import get_available_harness
from utils import FILES_DIR

def main():
    parser = argparse.ArgumentParser(description="Generate harnesses for those functions that were modified or added in the given program.")

    args_group = parser.add_mutually_exclusive_group(required=True)

    parser.add_argument(
        "--lib_name", "-l",
        type=str,
        help="The name of the library to generate harnesses for. "
    )

    args_group.add_argument(
        "--function_name", "-f",
        type=str,
        help="The commit range: commit_from and commit_to (must be provided together)." \
        "This option is mutually exclusive with --commit_*"
    )
    args_group.add_argument(
        "--commit-range", "-cr",
        nargs=2,
        metavar=("commit_from", "commit_to"),
        help="The commit range to check for modified functions. This option is mutually exclusive with --function_name"
    )
    parser.add_argument(
        "--project-path", "-p",
        type=str,
        required=True,
        help="The path to the project directory."
    )

    args = parser.parse_args()

    assert os.path.isdir(args.project_path), f"Project path {args.project_path} is not a valid directory."
    assert os.path.exists(args.project_path), f"Project path {args.project_path} does not exist."
    assert os.path.isdir(os.path.join(args.project_path, ".git")), f"Project path {args.project_path} is not a git repository."

    source_dir = args.project_path
    dot_file = str(os.path.join(FILES_DIR["DOT_FILE_DIR"], "libxml2.so.bc.callgraph.dot"))
    
    if args.function_name:
        target_func = args.function_name
        get_available_harness(target_func= target_func, source_dir= source_dir, dot_file= dot_file)
    else:
        old_commit, new_commit = args.commit_range
        get_available_harness(old_commit=old_commit, new_commit=new_commit, source_dir=source_dir, dot_file=dot_file)

if __name__ == "__main__":
    main()

