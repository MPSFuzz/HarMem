from typing import Dict, Any, Optional

root_api_and_call_chain = {}
root_api_and_harness = {}
harness_skeletons_files: Dict[str, Any] = {} # sotre the harness skeleton files, key is root_api
target_func_plan: Dict[str, Any] = {}  # store target function plans, key is root_api
fuzz_commands: Dict[str, Any] = {}  # store the commandlines to start AFLGo fuzzing
