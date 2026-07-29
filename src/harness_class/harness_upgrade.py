import os
import json
import shutil
import base64
import datetime

from typing import List, Dict, Any, Optional
from pathlib import Path
from src.batch.batch_class import Batch
from src.llm.LLM_class import LLM
from src.harness_class.harness_class import harness, seed_for_harness
from src.fuzz_components.fuzz_runner import start_fuzzing
from src.runtime_components.filter_merged_compile_pass_metadata import get_filtered_metadata_for_specific_root_api
from src.runtime_components.get_runtime_trace_result import get_aggregate_runtime_trace_information
from src.runtime_components.runtime_trace_feedback_analysis import add_to_regularized_fuzz, build_llm_feedback_prompt, build_llm_micro_tune_prompt
from src.seed_generation.build_seed_generation_prompt import build_seed_generation_prompt
from src.harness_memory.harness_memory import HarnessMemory
from src.harness_memory.harness_fusion import HarnessFusion
from src.utils.utils import get_logger

logger = get_logger(__name__)


def _kill_fuzz_process(pid: str, harness_save_path: str):
    try:
        os.kill(pid, 9)
        outdir_path = os.path.join(harness_save_path, "out")
        if not os.path.isdir(outdir_path):
            logger.info(f"Killed fuzzing process with PID {pid} (out dir already cleaned).")
            return
        for item in os.listdir(outdir_path):
            item_path = os.path.join(outdir_path, item)
            if os.path.isdir(item_path):
                shutil.rmtree(item_path)
            else:
                os.remove(item_path)

        logger.info(f"Killed fuzzing process with PID {pid} and the out dir has been cleared.")
    except ProcessLookupError as e:
        logger.error(f"pid: {pid} dose not exist or has already been terminated : {e}")
        return


def _preserve_crash_out(fuzzer_stats: dict, code_save_folder: str, code_file: str):
    crashes = int(fuzzer_stats.get("unique_crashes", 0) or 0)
    hangs = int(fuzzer_stats.get("unique_hangs", 0) or 0)
    if crashes <= 0 and hangs <= 0:
        return

    ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    suffix = f"_c{crashes}_h{hangs}_{ts}"

    out_dir = os.path.join(code_save_folder, "out")
    if os.path.exists(out_dir):
        preserved_out = out_dir + suffix
        shutil.move(out_dir, preserved_out)
        logger.info(f"[harness_upgrade] Preserved crash out dir to {preserved_out}")

    for ext in (".c", ".out"):
        src = os.path.splitext(code_file)[0] + ext
        if os.path.isfile(src):
            dst = os.path.splitext(code_file)[0] + suffix + ext
            shutil.copy2(src, dst)
            logger.info(f"[harness_upgrade] Preserved harness copy to {dst}")

def _save_modified_seeds(seeds: List[seed_for_harness]) -> bool:
    for s in seeds:
        try:
            seed_path = Path(s.seed_save_path)
            seed_path.parent.mkdir(parents=True, exist_ok=True)

            encoding = (s.seed_encoding or "base64").lower()
            if encoding == "file":
                if not seed_path.is_file():
                    logger.error(f"[harness_upgrade] seed file missing: {seed_path}")
                    return False
                continue

            if encoding == "base64":
                try:
                    seed_bytes = base64.b64decode(s.seed_content_b64, validate=True)
                except Exception as decode_err:
                    logger.error(
                        f"[harness_upgrade] Failed to base64 decode seed for {seed_path}: {decode_err}"
                    )
                    return False
            else:
                seed_bytes = s.seed_content_b64.encode("utf-8")

            with open(seed_path, "wb") as f:
                f.write(seed_bytes)
        except Exception as e:
            logger.error(f"[harness_upgrade] Failed to save modified seed to {s.seed_save_path}: {e}")
            return False

    return True
def _clean_up_seed_files(seed_save_folder: Path):
    if seed_save_folder.is_dir():
        for f in seed_save_folder.iterdir():
            if f.is_file():
                f.unlink()
            elif f.is_dir():
                shutil.rmtree(f)

def _compute_target_reach_rate(trace_summary: Dict[str, Any], target_func_name: str) -> Dict[str, Any]:     # compute the reach rate of target function in the queue traces
    queue_traces = trace_summary.get("queue_traces", {}) or {}
    per_trace = queue_traces.get("per_trace", {}) or {}

    total = 0
    reached = 0
    example_reached = []
    example_unreached = []

    for tid, info in per_trace.items():
        total += 1
        fn_names = set()
        for f in info.get("reached_functions", []) or []:
            n = f.get("name")
            if n:
                fn_names.add(n)

        if target_func_name in fn_names:
            reached += 1
            if len(example_reached) < 3:
                example_reached.append(tid)
        else:
            if len(example_unreached) < 3:
                example_unreached.append(tid)
    
    # add the baseline seeds if they reach the target
    baseline_seeds = trace_summary.get("baseline_trace", {}) or {}
    if baseline_seeds:
        baseline_seeds_per_trace = baseline_seeds.get("per_trace", {}) or {}
        for tid, info in baseline_seeds_per_trace.items():
            total += 1
            fn_names = set()
            for f in info.get("reached_functions", []) or []:
                n = f.get("name")
                if n:
                    fn_names.add(n)
        
            if target_func_name in fn_names:
                reached += 1
                if len(example_reached) < 3:
                    example_reached.append(tid)
            else:
                if len(example_unreached) < 3:
                    example_unreached.append(tid)

    rate = (reached / total) if total > 0 else 0.0
    return {
        "total_traces": total,
        "reached_traces": reached,
        "reach_rate": rate,
        "example_reached_trace_ids": example_reached,
        "example_unreached_trace_ids": example_unreached,
    }

    return True


def _build_harness_memory_text(batch: Batch, plan: Dict, root_api: str,
                                 target_func: str,
                                 trace_summary: Dict[str, Any]) -> str:
    root_plan = plan.get(root_api, {})
    expected = root_plan.get("external_chain", []) or [
        n.get("name", "?")
        for n in root_plan.get("chain", {}).get("nodes", [])
    ]

    qt = trace_summary.get("queue_traces", {}) or {}
    per_trace = trace_summary.get("per_trace", qt.get("per_trace", {})) or {}
    total = len(per_trace)

    func_counts = {}
    for tid, info in per_trace.items():
        seen = set()
        for f in info.get("reached_functions", []) or []:
            name = f.get("name", "")
            if name and name not in seen:
                func_counts[name] = func_counts.get(name, 0) + 1
                seen.add(name)

    actual_chain = []
    for func in expected:
        rate = func_counts.get(func, 0) / total if total > 0 else 0.0
        actual_chain.append({"func": func, "reach_rate": round(rate, 4)})

    furthest_hit = ""
    broken_edge = []
    for i, entry in enumerate(actual_chain):
        if entry["reach_rate"] == 0:
            if i == 0:
                continue
            if furthest_hit:
                broken_edge = [furthest_hit, entry["func"]]
            break
        furthest_hit = entry["func"]
    if not furthest_hit and actual_chain:
        furthest_hit = actual_chain[-1]["func"]

    agg_markers = trace_summary.get("aggregate", {}).get("markers", []) or []
    if not agg_markers:
        agg = qt.get("aggregate", {}) or {}
        agg_markers = agg.get("markers", []) or []
    marker_hit = {}
    for mk in agg_markers:
        if (mk.get("tag", "") or "").lower() == "bug_point":
            f = mk.get("file", "")
            ln = mk.get("line", 0)
            hit_tr = mk.get("hit_traces", 0) or 0
            rate = hit_tr / total if total > 0 else 0.0
            key = f"{Path(f).name}:{ln}" if f else str(mk.get("local_id", "?"))
            marker_hit[key] = round(rate, 3)

    memory_json = json.dumps({
        "expected_chain": expected,
        "actual_chain": actual_chain,
        "gap": {"broken_edge": broken_edge, "furthest_hit": furthest_hit},
        "marker_hit": marker_hit,
    }, indent=2, ensure_ascii=False)

    return f"""=== Harness Memory ===

Field explanations:
- expected_chain: the intended call chain from entry API to target function.
- actual_chain: functions in the chain that were ACTUALLY reached, with
  reach_rate = fraction of seeds that reached each function.
  IMPORTANT: reach_rate=0 for the FIRST function is NORMAL (compiler inlining).
  Only worry if a function AFTER the first has reach_rate=0.
- gap.broken_edge: first edge in the chain where a function is NEVER reached.
  Empty means all tracked functions are reachable.
- gap.furthest_hit: the deepest function reached in the chain.
- marker_hit: fraction of seeds hitting each bug-point marker location.

{memory_json}

Call chain: {' -> '.join(expected)}
Target: {target_func}"""


def _is_fusion_rejected(root_api: str, harness_dir: str, harness_c_path: str,
                        lib_name: str) -> bool:
    if lib_name == "libxml2":
        kw = "xml"
    elif lib_name.startswith("lib"):
        kw = lib_name[3:]
    else:
        kw = lib_name
    reached_target = False
    import glob as _glob
    mem_files = sorted(_glob.glob(os.path.join(harness_dir, "*_harness_memory.json")))
    if mem_files:
        try:
            mem = json.loads(Path(mem_files[-1]).read_text(encoding="utf-8"))
            for it in mem.get("iterations", []):
                ac = it.get("actual_chain", [])
                if ac and ac[-1].get("reach_rate", 0) > 0:
                    reached_target = True
                    break
        except Exception:
            pass
    logger.info(f"[harness_upgrade] Checking harness_fusion for {root_api} (reached_target={reached_target}, mem_files={len(mem_files)}, kw={kw})")
    fusion = HarnessFusion.from_harness_dir(root_api, harness_dir,
                                             keywords=[kw], threshold=0.85)
    accepted = fusion.evaluate_new_harness(harness_c_path, reached_target=reached_target)
    fusion.save(os.path.join(harness_dir, "harness_fusion.json"))
    return not accepted


def _retry_harness_until_novel(batch: Batch, root_api: str, h: harness,
                                 code_save_folder: str, code_file: str,
                                 llm: Any, plan: Dict, target_func: str,
                                 harness_memory_text: str, fuzzer_stats: Dict) -> bool:
    """Retry harness generation up to 5 times until fusion accepts it."""
    from src.llm.LLM_prompt import HARNESS_REGENERATE_PROMPT
    from src.utils.utils import extract_target_func_code_from_plan

    for i in range(5):
        target_source = extract_target_func_code_from_plan(plan, target_func)
        cve_block = ""
        try:
            from src.cve_helper.cve_partial_prompt_render import render_cve_hints_for_codegen
            cve_block = render_cve_hints_for_codegen(getattr(batch, "cve_hints", {}) or {}, target_api=target_func)
        except Exception:
            pass
        plan_text = json.dumps(plan, indent=2, ensure_ascii=False)
        prompt = HARNESS_REGENERATE_PROMPT.substitute(
            lib_name=batch.lib_name,
            target_func=target_func,
            plan_json=plan_text,
            harness_memory_text=harness_memory_text,
            cve_hints_block=cve_block,
            target_function_source=target_source,
            bug_point_source_code_snippets="[]",
        )
        if not llm.regenerate_harness(h, prompt, regen_temperature=0.7):
            logger.warning(f"[harness_upgrade] regenerate attempt {i+1} LLM call failed")
            continue

        if not h.compile_test():
            for _ in range(3):
                llm.harness_fix(h)
                h.complete_compile_command()
                if h.compile_test():
                    break

        if not _is_fusion_rejected(root_api, code_save_folder, code_file, batch.lib_name):
            logger.info(f"[harness_upgrade] Regenerate attempt {i+1} accepted by fusion")
            return True
        logger.info(f"[harness_upgrade] Regenerate attempt {i+1} rejected by fusion")

    logger.info(f"[harness_upgrade] All 5 regenerate attempts rejected, falling back to seed-only")
    return False


def harness_upgrade_procedure(batch: Batch, root_api: str, reach_rate_micro_threshold: float, reach_rate_repair_threshold: float, reach_rate_min_traces: int) -> bool:
    code = None
    code_file = batch.harness_info.get("harness_files", {}).get(root_api, "")
    code_save_folder = os.path.dirname(code_file)
    if not code_file:
        logger.error(f"No harness file found for root API {root_api} in batch {batch.batch_id}")
        raise FileNotFoundError(f"No harness file found for root API {root_api}")
    
    with open(code_file, "r", encoding="utf-8") as f:
        code = f.read()
    
    target_func = batch.target_func
    skeleton_path = batch.harness_info.get("harness_skeletons_files", {}).get(root_api, "")
    plan_path = batch.harness_info.get("harness_plans_files", "")
    fuzzer_stats = batch.fuzz_feedback.get("fuzzer_stats_feedback", {}).get(root_api, {})
    analysis_result = batch.fuzz_feedback.get("fuzzer_stats_analysis", {}).get(root_api, {})

    if not plan_path or not skeleton_path:
        logger.error(f"No plan or skeleton found for root API {root_api} in batch {batch.batch_id}")
        raise FileNotFoundError(f"No plan or skeleton found for root API {root_api}")
    
    with open(plan_path, "r", encoding="utf-8") as f:
        plan = json.load(f)

    h = harness(
        code=code,
        code_file=code_file,
        code_save_folder=code_save_folder,
        target_func=target_func,
        skeleton_path=skeleton_path
    )

    baseline_seeds_path = Path(code_file).parent / "in"
    baseline_seeds = [p for p in baseline_seeds_path.iterdir() if p.is_file()]

    filtered_metadata_path = get_filtered_metadata_for_specific_root_api("/tmp", batch, root_api)
    sampled_cases_pathes, sampled_queue_seed_runtime_trace_result = get_aggregate_runtime_trace_information(batch, root_api, filtered_metadata_path, str(baseline_seeds_path))

    # --- harness_memory ---
    try:
        plan_path = batch.harness_info.get("harness_plans_files", "")
        mem = HarnessMemory.from_batch_and_plan(
            batch.json_path, plan_path, root_api
        ) if os.path.isfile(batch.json_path) and os.path.isfile(plan_path) else None
        if mem is None:
            mem = HarnessMemory(
                target_func=batch.target_func,
                root_api=root_api,
                lib_name=batch.lib_name,
            )
            # bootstrap empty iteration from plan
            plan_data = json.loads(Path(plan_path).read_text(encoding="utf-8")) if os.path.isfile(plan_path) else {}
            root_plan = plan_data.get(root_api, {})
            expected = root_plan.get("external_chain", []) or root_plan.get("chain", {}).get("nodes", [])
            expected = [n.get("name", "?") for n in expected] if expected and isinstance(expected[0], dict) else expected
            mem.add_iteration({
                "harness_path": code_file,
                "duration": "0.0h",
                "expected_chain": expected,
                "upgrade_reason": "triggered",
                "llm_decision": "unknown",
                "metrics": {},
                "actual_chain": [],
                "gap": {},
                "marker_hit": {},
            })
        # re-index trace data to iteration 0 (latest)
        trace_idx = len(mem.iterations) - 1 if mem.iterations else 0
        mem.populate_trace_data(trace_idx, sampled_queue_seed_runtime_trace_result)
        ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        mem_file = os.path.join(code_save_folder, f"{ts}_harness_memory.json")
        mem.save(mem_file)
        # backup old harness
        for ext in (".c", ".out"):
            src = os.path.splitext(code_file)[0] + ext
            if os.path.isfile(src):
                dst = os.path.join(code_save_folder, f"{ts}_old{ext}")
                shutil.copy2(src, dst)
                logger.info(f"[harness_upgrade] Backed up old harness: {dst}")
        # dedup identical old.c copies (seed-only upgrades produce duplicates)
        import filecmp as _filecmp
        old_files = sorted([f for f in os.listdir(code_save_folder) if f.endswith("_old.c")])
        for i in range(len(old_files)):
            for j in range(i + 1, len(old_files)):
                fa = os.path.join(code_save_folder, old_files[i])
                fb = os.path.join(code_save_folder, old_files[j])
                if _filecmp.cmp(fa, fb, shallow=False):
                    # delete the older one (keep the newer timestamp)
                    os.remove(fa)
                    # also remove matching harness_memory and _old.out
                    prefix = old_files[i].replace("_old.c", "")
                    for suffix in ("_harness_memory.json", "_old.out"):
                        extra = os.path.join(code_save_folder, f"{prefix}{suffix}")
                        if os.path.isfile(extra):
                            os.remove(extra)
                    logger.info(f"[harness_upgrade] Dedup: removed duplicate {old_files[i]} (identical to {old_files[j]})")
                    break
    except Exception as e:
        logger.warning(f"[harness_upgrade] Failed to save harness_memory: {e}")
    # ---

    is_regularized = add_to_regularized_fuzz(sampled_queue_seed_runtime_trace_result)
    if is_regularized:
        logger.info(f"[harness_upgrade] Root API {root_api} has been added to regularized fuzzing set. Skip harness upgrade.")
        return True

    if "distance_plateau_period_suspected" in analysis_result.get("issues", ""):
        # when harness is suspected to be in a distance plateau, execute a specific upgrade strategy
        # [fine 2] <<<
        reach_stats = _compute_target_reach_rate(sampled_queue_seed_runtime_trace_result, target_func)
        sampled_queue_seed_runtime_trace_result["target_reach_stats"] = reach_stats

        total_traces = reach_stats.get("total_traces", 0)
        reach_rate = reach_stats.get("reach_rate", 0.0)

        if total_traces < reach_rate_min_traces:
            mode = "repair"
            logger.info(
                f"[harness_upgrade2] target reach stats: total={total_traces} (<{reach_rate_min_traces}), "
                f"reach_rate={reach_rate:.3f}. Use REPAIR prompt by default."
            )
        elif reach_rate >= reach_rate_micro_threshold:
            mode = "micro_upgrade"
            logger.info(
                f"[harness_upgrade2] target reach stats: total={total_traces}, reach_rate={reach_rate:.3f} "
                f">= {reach_rate_micro_threshold}. Use MICRO-TUNE prompt."
            )
        elif reach_rate <= reach_rate_repair_threshold:
            mode = "repair"
            logger.info(
                f"[harness_upgrade2] target reach stats: total={total_traces}, reach_rate={reach_rate:.3f} "
                f"<= {reach_rate_repair_threshold}. Use REPAIR prompt."
            )
        else:
            #mode = "repair"
            mode = "micro_upgrade"
            logger.info(
                f"[harness_upgrade2] target reach stats (grey-zone): total={total_traces}, reach_rate={reach_rate:.3f} in grey-zone "
                f"({reach_rate_repair_threshold}, {reach_rate_micro_threshold}). Use MICRO-TUNE prompt."
            )
        
        sampled_queue_seed_runtime_trace_result["mode"] = mode

        harness_memory_text = _build_harness_memory_text(
            batch, plan, root_api, target_func,
            sampled_queue_seed_runtime_trace_result,
        )

        if mode == "micro_upgrade":
            prompt = build_llm_micro_tune_prompt(batch, sampled_queue_seed_runtime_trace_result, target_func, code_file, baseline_seeds, sampled_cases_pathes, harness_memory_text=harness_memory_text)
        else:
            prompt = build_llm_feedback_prompt(batch, sampled_queue_seed_runtime_trace_result, target_func, code_file, baseline_seeds, sampled_cases_pathes, harness_memory_text=harness_memory_text)
        # >>>

        #prompt = build_llm_feedback_prompt(batch, sampled_queue_seed_runtime_trace_result, code_file, baseline_seeds, sampled_cases_pathes)

        llm = LLM(target_func=batch.target_func)
        llm.get_harness_plan(plan)

        type, response = llm.phased_harness_upgrade_2(h, prompt)
        if type == "only_modified_seeds":
            seed_generation_prompt = build_seed_generation_prompt(batch, sampled_queue_seed_runtime_trace_result, code_file, baseline_seeds)
            seeds_content = llm.llm_seed_generation(h, seed_generation_prompt)
            upgrade_flag = _save_modified_seeds(seeds_content)
            if upgrade_flag:
                logger.info(f"[Harness_upgrade2] Seeds upgrade success for root api {root_api} in function {batch.target_func}")
                _preserve_crash_out(fuzzer_stats, code_save_folder, code_file)
                try:
                    call_chain = plan[root_api].get("external_chain", []) or [
                        n.get("name", "?") for n in plan[root_api].get("chain", {}).get("nodes", [])
                    ]
                    llm.generate_dict(h, call_chain, harness_memory_text=harness_memory_text)
                except Exception as e:
                    logger.warning(f"[harness_upgrade] Dict upgrade failed: {e}")
            return True
        
        elif type == "only_modified_harness":
            # terminate the ongoing fuzzing process for this root_api
            pid = batch.fuzzer_pids.get(root_api, None)
            if pid:
                _preserve_crash_out(fuzzer_stats, code_save_folder, code_file)
                _kill_fuzz_process(pid, code_save_folder)
            
            h.complete_compile_command()

            ava_flag = h.compile_test()
            fix_count = 0

            while ava_flag == False and fix_count < 3:
                h = llm.harness_fix(h)
                h.complete_compile_command()
                ava_flag = h.compile_test()
                fix_count += 1
            
            if ava_flag == True:
                if _is_fusion_rejected(root_api, code_save_folder, code_file, batch.lib_name):
                    if not _retry_harness_until_novel(batch, root_api, h, code_save_folder, code_file, llm, plan, target_func, harness_memory_text, fuzzer_stats):
                        logger.info(f"[Harness_upgrade2] All retries rejected for {root_api}, falling back to seed-only")
                        return True
                logger.info(f"[Harness_upgrade2] Harness upgrade success for root api {root_api} in function {batch.target_func}")

                # Restart the fuzz process for this root_api
                if start_fuzzing(batch=batch, selected_root_api=root_api):
                    logger.info(f"[Harness_upgrade2] Upgrade harness and restarted fuzzing process for upgraded harness of root API {root_api}")
                    return True
                else:
                    logger.error(f"[Harness_upgrade2] Failed to restart fuzzing process for upgraded harness of root API {root_api}")
                    return False
                
        elif type == "modified_seeds_and_harness":
            #_save_modified_seeds(response)
            seed_generation_prompt = build_seed_generation_prompt(batch, sampled_queue_seed_runtime_trace_result, harness_path=code_file, baseline_seeds=baseline_seeds)
            seeds_content = llm.llm_seed_generation(h, seed_generation_prompt)
            # _clean_up_seed_files(baseline_seeds_path)
            upgrade_flag = _save_modified_seeds(seeds_content)

            if upgrade_flag:
                logger.info(f"[Harness_upgrade2] Seeds upgrade success for root api {root_api} in function {batch.target_func}")
            else:
                logger.error(f"[Harness_upgrade2] Seeds upgrade or save failed for root api {root_api} in function {batch.target_func}")
                return False

            # terminate the ongoing fuzzing process for this root_api
            pid = batch.fuzzer_pids.get(root_api, None)
            if pid:
                _preserve_crash_out(fuzzer_stats, code_save_folder, code_file)
                _kill_fuzz_process(pid, code_save_folder)
            
            h.complete_compile_command()

            ava_flag = h.compile_test()
            fix_count = 0

            while ava_flag == False and fix_count < 3:
                h = llm.harness_fix(h)
                h.complete_compile_command()
                ava_flag = h.compile_test()
                fix_count += 1
            
            if ava_flag == True:
                if _is_fusion_rejected(root_api, code_save_folder, code_file, batch.lib_name):
                    if not _retry_harness_until_novel(batch, root_api, h, code_save_folder, code_file, llm, plan, target_func, harness_memory_text, fuzzer_stats):
                        logger.info(f"[Harness_upgrade2] All retries rejected, falling back to seed-only for {root_api}")
                        return True
                logger.info(f"[Harness_upgrade2] Harness upgrade success for root api {root_api} in function {batch.target_func}")

                # Restart the fuzz process for this root_api
                if start_fuzzing(batch=batch, selected_root_api=root_api):
                    logger.info(f"[Harness_upgrade2] Upgrade harness and restarted fuzzing process for upgraded harness of root API {root_api}")
                    return True
                else:
                    logger.error(f"[Harness_upgrade2] Failed to restart fuzzing process for upgraded harness of root API {root_api}")
                    return False
                
    else:
        llm = LLM(target_func=batch.target_func)
        llm.get_harness_plan(plan)

        llm.phased_harness_upgrade_1(
            plan_path=plan_path,
            fuzzer_stats=fuzzer_stats,
            analysis_result=analysis_result,
            h=h
        )

        # terminate the ongoing fuzzing process for this root_api
        pid = batch.fuzzer_pids.get(root_api, None)
        if pid:
            _preserve_crash_out(fuzzer_stats, code_save_folder, code_file)
            _kill_fuzz_process(pid, code_save_folder)
        
        h.complete_compile_command()

        ava_flag = h.compile_test()
        fix_count = 0

        while ava_flag == False and fix_count < 3:
            h = llm.harness_fix(h)
            h.complete_compile_command()
            ava_flag = h.compile_test()
            fix_count += 1
        
        if ava_flag == True:
            if _is_fusion_rejected(root_api, code_save_folder, code_file, batch.lib_name):
                hm_text = _build_harness_memory_text(batch, plan, root_api, target_func, sampled_queue_seed_runtime_trace_result)
                if not _retry_harness_until_novel(batch, root_api, h, code_save_folder, code_file, llm, plan, target_func, hm_text, fuzzer_stats):
                    logger.info(f"[Harness_upgrade1] All retries rejected for {root_api}, falling back to seed-only")
                    return True
            logger.info(f"[Harness_upgrade1] Harness Upgrade1 success for root api {root_api} in function {batch.target_func}")
            if start_fuzzing(batch=batch, selected_root_api=root_api):
                logger.info(f"[Harness_upgrade1] Upgrade harness and restarted fuzzing process for upgraded harness of root API {root_api}")
                return True
            else:
                logger.error(f"[Harness_upgrade1] Failed to restart fuzzing process for upgraded harness of root API {root_api}")
                return False

if __name__ == "__main__":
     batch = Batch.load_metadata("/root/auto_harness/src/batch_metadata/5a3179a8-12cd-491c-aec3-2c9261f2056c.json")
     harness_upgrade_procedure(batch, "xmlParseContent", 0.65, 0.20, 25)