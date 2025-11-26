import argparse
import os

from typing import Dict, Any, Optional, List

from src.harness_class.gen_hanress import get_available_harness
from src.utils.utils import extract_funcname_from_files
from src.batch.operations_of_Batch import create_batch, collect_fuzzer_feedback_to_batch, analyze_fuzzer_feedback
from src.batch.batch_class import Batch
from src.fuzz_components.fuzz_runner import start_fuzzing
from src.fuzz_components.fuzzer_feed_back_analysis import is_harness_qualified_in_coares_grain
from src.harness_class.harness_upgrade import harness_upgrade_procedure
from src.utils.utils import get_logger

logger = get_logger(__name__)

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
        #nargs='+',
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

    parser.add_argument(
        "--compile-commands-path", "-c",
        type=str,
        help="The path to the compile_commands.json file in target project."
    )

    args = parser.parse_args()

    assert os.path.isdir(args.project_path), f"Project path {args.project_path} is not a valid directory."
    assert os.path.exists(args.project_path), f"Project path {args.project_path} does not exist."
    assert os.path.isfile(args.dot_file), f"Dot file {args.dot_file} does not exist."

    lib_name = args.lib_name
    source_dir = args.project_path
    dot_file = args.dot_file
    target_funcs = args.function_name
    compile_commands_path = args.compile_commands_path

    # create batch (harness skeletons generation + harness plans generation + harness code generation)
    batch_id = create_batch(lib_name=lib_name, source_dir=source_dir, dot_file=dot_file, target_funcs=target_funcs, compile_commands_path=compile_commands_path)
    
    #start fuzzing, use Batch class to manage the fuzzing processes
    batch: Batch = start_fuzzing(batch_id)
    logger.info(f"Started fuzzing processes with PIDs: {batch.fuzzer_pids}")

    # TODO: design a scheduler to monitor the fuzzing processes and decide when to upgrade the harnesses after frame progress is ready
    # collect fuzzer feedback and store them in the Batch instance
    collect_fuzzer_feedback_to_batch(batch)

    # analyze fuzzer feedback and store analysis results in the Batch instance
    analyze_fuzzer_feedback(batch)

    # check if there is any harness need to be upgraded in coarse grain
    for root_api, analysis_result in batch.fuzz_feedback.get("fuzzer_stats_analysis", {}).items():
        need_to_upgrade = is_harness_qualified_in_coares_grain(analysis_result)
        if need_to_upgrade:
            continue

        logger.info(f"Try to upgrade the harness for root API {root_api} in batch {batch.batch_id}")
        if not harness_upgrade_procedure(batch, root_api):
            continue



if __name__ == "__main__":
    main()

"""
the aggregate_for_chain function from src/static_analyze/aggregator.py
the name chain and the ccdb_path parameters are required. Other parameters are optional, but set these optional parameters to argparse later

def aggregate_for_chain(name_chain: List[str], 
                        ccdb_path: str, 
                        include_headers: bool = False, 
                        system_includes: bool = False,
                        bitmask_require_op: bool = True,
                        max_guards_per_node: int = 4,
                        vendor_prefixes: Optional[List[str]] = None,
                        infer_vendor_prefixes: bool = True,
                        vendor_prefix_threshold: float = 0.25,
                        min_vendor_len: int = 2
                        ) -> Dict:
"""
