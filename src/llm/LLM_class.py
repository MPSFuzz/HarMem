import openai
import os
import json
import time
import string
from typing import Dict, Any, List, Optional, Tuple
from pathlib import Path

from src.utils.utils import get_logger, clean_markdown_format, extract_json_from_text, get_path_subfolder, parse_target_file, \
    extract_target_func_code_from_plan, load_source_snippet, clip_text, build_unique_llm_seed_path, \
    token_to_bytes, bytes_to_afl_dict_line
from src.llm.LLM_prompt import *
from src.harness_class.harness_class import harness, seed_for_harness
from src.cve_helper.cve_partial_prompt_render import render_cve_hints_for_skeleton, render_cve_hints_for_codegen

#TODO: 添加一个从LLM获得字典的接口

openai.api_key = "sk-f63c0c4930d74a27bf440dfb9c5cc51f"   #  DeepSeek 官方 key
openai.base_url = "https://api.deepseek.com"            #  DeepSeek 官方 API
openai.default_headers = {"x-foo": "true"}

logger = get_logger(__name__)

class LLM:
    def __init__(self, lib_name=None, target_func=None, target_location=None, max_retries=3, retry_delay=5, timeout: Optional[int] = None, model: Optional[str] = None):
        self.lib_name = lib_name
        self.target_func = target_func
        self.target_location = target_location
        self.max_retries = max_retries
        self.retry_delay = retry_delay
        self.timeout = timeout or int(os.environ.get("LLM_TIMEOUT", "180"))
        self.model = model or os.environ.get("LLM_MODEL") or "deepseek-chat"

        # cve_helper related attributes
        self.phase_A_context = {}
        self.plan = {}
        self.cve_hints = {}
    
    def get_phase_A_context(self, phase_A_context: Dict[str, Any]):
        self.phase_A_context = phase_A_context
    
    def get_harness_plan(self, plan: dict):
        self.plan = plan

    # cve_helper related methods
    def get_cve_hints(self, cve_hints: Dict[str, Any]):
        self.cve_hints = cve_hints or {}
        
    def entry_api_filter(self, api_list) -> list:
        api_filter_prompt = ENTRY_POINT_FILTER % (self.target_func, self.lib_name, api_list)

        for attempt in range(1, self.max_retries + 1):
            try:
                response = openai.chat.completions.create(
                    model= self.model,
                    messages=[{
                        "role": "user",
                        "content": [
                            {
                                "type": "text",
                                "text": f"{api_filter_prompt}"
                            }
                        ]
                    }],
                    timeout=self.timeout
                )

                result = extract_json_from_text(response.choices[0].message.content)
                result = clean_markdown_format(result)
                #print(result)
                content = json.loads(result)
                return content['filtered_apis']
            
            except Exception as e:
                logger.warning(f"[Warning] entry_api_filter attempt {attempt} failed: {e}")
                if attempt < self.max_retries:
                    time.sleep(self.retry_delay)
                else:
                    logger.error(f"[Error] entry_api_filter failed after {self.max_retries} attempts")
                    return []
    
    # [phase A: get the harness skeleton]
    def generate_harness_skeleton(self, call_chain) -> harness:
        h = harness()
        h.target_func = self.target_func

        phase_a_context = json.dumps(self.phase_A_context, indent=2, ensure_ascii=False)
        cve_hints_block = render_cve_hints_for_skeleton(self.cve_hints)

        for attempt in range(1, self.max_retries + 1):
            try:
                harness_skeleton_prompt = SKELETON_GENERATE_PROMPT.format(
                    lib_name=self.lib_name,
                    phase_a_context=phase_a_context,
                    cve_hints_block=cve_hints_block,
                )
                response = openai.chat.completions.create(
                    model=self.model,
                    messages=[{
                        "role": "user",
                        "content": [
                            {"type": "text",
                            "text": f"{harness_skeleton_prompt}",}
                            ]
                    }],
                    temperature=0.3,
                    top_p=1,
                    frequency_penalty=0,
                    presence_penalty=0,
                    timeout=self.timeout
                )

                result = response.choices[0].message.content
                result = extract_json_from_text(response.choices[0].message.content)
                result = clean_markdown_format(result)
                harness_skeleton = json.loads(result)

                skeleton_save_path = get_path_subfolder("harness_skeletons")
                os.makedirs(skeleton_save_path, exist_ok=True)
                fname = f"{skeleton_save_path}/{call_chain[0]}_to_{call_chain[-1]}_skeleton.json"
                with open(fname, "w", encoding="utf-8") as f:
                    json.dump(harness_skeleton, f, indent=2)
                
                h.skeleton_path = fname
                
                return h
            
            except Exception as e:
                logger.warning(f"[Warning] get_harness_skeleton attempt {attempt} failed: {e}")
                if attempt < self.max_retries:
                    time.sleep(self.retry_delay)
                else:
                    logger.error(f"[Error] get_harness_skeleton failed after {self.max_retries} attempts")
                    return None


    def regenerate_harness(self, h: harness, prompt: str, regen_temperature: float = 0.7):
        for attempt in range(1, self.max_retries + 1):
            try:
                response = openai.chat.completions.create(
                    model=self.model,
                    messages=[{"role": "user", "content": [{"type": "text", "text": prompt}]}],
                    temperature=regen_temperature,
                    top_p=1.0,
                    frequency_penalty=0,
                    presence_penalty=0,
                    timeout=self.timeout,
                )
                result = extract_json_from_text(response.choices[0].message.content)
                result = clean_markdown_format(result)
                content = json.loads(result)
                h.code = content["code"]
                h.compile_command = content["compile_command"]
                h.update_code_file()
                h.complete_compile_command()
                logger.info(f"[LLM] regenerate_harness attempt {attempt} succeeded")
                return True
            except Exception as e:
                logger.warning(f"[LLM] regenerate_harness attempt {attempt} failed: {e}")
                if attempt < self.max_retries:
                    time.sleep(self.retry_delay)
        return False

    def generate_code(self, h: harness, call_chain):
        # [more details] >>>
        targets_file = os.environ.get("TRACE_MARKER_TARGETS_FILE", "").strip()
        target_func_source_code = extract_target_func_code_from_plan(self.plan, self.target_func)
        bug_points = parse_target_file(targets_file, self.plan, self.target_func)
        bug_point_source_code_snippets: List[Tuple[str, int, str]] = []
        for f, ln in bug_points:
            snippet = load_source_snippet(f, ln, context=4)
            if snippet:
                bug_point_source_code_snippets.append((f, ln, clip_text(snippet, max_chars=1500)))
        #<<<

        # [optimization]
        with open(h.skeleton_path, "r", encoding="utf-8") as f:
            skeleton = json.load(f)

        plan_text = json.dumps(self.plan, indent=2, ensure_ascii=False)
        skeleton_text = json.dumps(skeleton, indent=2, ensure_ascii=False)
        bug_snippets_text = json.dumps(bug_point_source_code_snippets, indent=2, ensure_ascii=False)
        cve_hints_block = render_cve_hints_for_codegen(self.cve_hints, target_api=self.target_func)

        for attempt in range(1, self.max_retries + 1):
            try:
                # code_prompt = CODE_GENERATE_PROMPT % (self.lib_name, self.target_func, target_func_source_code, bug_point_source_code_snippets, json.dumps(self.plan, indent=2), skeleton, self.target_func)
                code_prompt = CODE_GENERATE_PROMPT.substitute(
                    lib_name=self.lib_name,
                    target_func=self.target_func,
                    target_function_source=target_func_source_code,
                    bug_point_source_code_snippets=bug_snippets_text,
                    plan_json=plan_text,
                    skeleton_json=skeleton_text,
                    cve_hints_block=cve_hints_block,
                    )
                response = openai.chat.completions.create(
                    model= self.model,
                    messages=[{
                        "role": "user",
                        "content": [
                            {"type": "text",
                            "text": f"{code_prompt}",}
                            ]
                    }],
                    temperature=0.3,
                    top_p=1,
                    frequency_penalty=0,
                    presence_penalty=0,
                    timeout=self.timeout
                )

                result = extract_json_from_text(response.choices[0].message.content)
                result = clean_markdown_format(result)

                content = json.loads(result)

                h.code = content['code']
                h.compile_command = content['compile_command']

                h.save_code_to_file()
                h.complete_compile_command()
                
                return 
                #return h
            
            except Exception as e:
                logger.warning(f"[Warning] generate_code attempt {attempt} failed for call_chain {call_chain}: {e}")
                if attempt < self.max_retries:
                    time.sleep(self.retry_delay)
                else:
                    logger.error(f"[Error] generate_code failed after {self.max_retries} attempts for call_chain {call_chain}")
                    return None
    
    def harness_fix(self, h: harness) -> harness:
        for attempt in range(1, self.max_retries + 1):
            try:
                # fix_prompt = HARNESS_FIX_PROMPT % (self.plan, h.code, h.compile_command, h.compile_result)
                if isinstance(h.compile_result, str):
                    h.compile_result = h.compile_result[:200]
                else:
                    h.compile_result = str(h.compile_result or "")[:200]
                fix_prompt = HARNESS_FIX_PROMPT % (h.code, h.compile_command, h.compile_result)

                response = openai.chat.completions.create(
                    model= self.model,
                    messages=[{
                        "role": "user",
                        "content": [
                            {"type": "text",
                            "text": f"{fix_prompt}",}
                            ]
                    }],
                    timeout=self.timeout
                )

                result = extract_json_from_text(response.choices[0].message.content)
                result = clean_markdown_format(result)

                try:
                    content = json.loads(result)
                except json.JSONDecodeError as e:
                    logger.error(f"JSON decode error during harness_fix: {e}")

                h.code = content['code']
                h.compile_command = content['compile_command']

                return h
            
            except Exception as e:
                logger.warning(f"[Warning] harness_fix attempt {attempt} failed: {e}")
                if attempt < self.max_retries:
                    time.sleep(self.retry_delay)
                else:
                    logger.error(f"[Error] harness_fix failed after {self.max_retries} attempts")
                    return h

    def generate_dict(self, h: harness, call_chain, min_weight: int = 3, harness_memory_text: str = ""):
        for attempt in range(1, self.max_retries + 1):
            try:
                plan_json = json.dumps(self.plan, indent=2)
                harness_code = h.code

                dict_prompt = DICT_GENERATE_PROMPT % (
                    self.lib_name,
                    self.target_func,
                    plan_json,
                    harness_code,
                    self.target_func,
                    harness_memory_text or "",
                )

                response = openai.chat.completions.create(
                    model= self.model,
                    messages=[
                        {
                            "role": "user",
                            "content": [
                                {
                                    "type": "text",
                                    "text": dict_prompt,
                                }
                            ],
                        }
                    ],
                    temperature=0.3,
                    top_p=1,
                    frequency_penalty=0,
                    presence_penalty=0,
                    timeout=self.timeout,
                )

                result = extract_json_from_text(response.choices[0].message.content)
                result = clean_markdown_format(result)

                try:
                    content = json.loads(result)
                except json.JSONDecodeError as e:
                    logger.error(f"JSON decode error during generate_dict: {e}")

                tokens = content.get("tokens", [])

                cleaned_tokens = []
                seen = set()
                for token in tokens:
                    v = token.get("value")
                    if v is None:
                        continue
                    if isinstance(v, str) and v == "":
                        continue
                    w = token.get("weight_hint", min_weight)
                    try:
                        w = int(w)
                    except Exception:
                        w = min_weight
                    if w < min_weight:
                        continue
                    if v in seen:
                        continue
                    seen.add(v)
                    cleaned_tokens.append(v)

                if not cleaned_tokens:
                    logger.warning(f"[Warning] No valid tokens generated for call_chain {call_chain}")
                    return

                p = Path(h.code_file)
                p = str(p.parent)
                dict_save_file = os.path.join(p, "harness_dict.dict")

                # merge with existing dict, dedup by line content
                old_lines = []
                if os.path.isfile(dict_save_file):
                    try:
                        with open(dict_save_file, "r", encoding="utf-8") as f:
                            old_lines = [l.rstrip("\n") for l in f.readlines() if l.strip()]
                    except Exception:
                        pass

                old_set = set(old_lines)
                new_lines = [bytes_to_afl_dict_line(token_to_bytes(v)) for v in cleaned_tokens]
                added = [l for l in new_lines if l not in old_set]
                merged = old_lines + added
                if len(merged) > 100:
                    merged = merged[-100:]
                    logger.info(f"[LLM] Dict truncated to 100 tokens")

                with open(dict_save_file, "w", encoding="utf-8") as f:
                    for line in merged:
                        f.write(line + "\n")

                logger.info(f"[LLM] Dict upgraded: {len(added)} new tokens added, {len(merged)} total in {dict_save_file}")
                return
                
            except Exception as e:
                logger.warning(f"[LLM] generate_dict attempt {attempt} failed: {e}")
                if attempt < self.max_retries:
                    time.sleep(self.retry_delay)
                else:
                    logger.error(f"[LLM] generate_dict failed after {self.max_retries} attempts")
                    return None
    
    def phased_harness_upgrade_1(self, plan_path: str, fuzzer_stats: Dict[str, Any], analysis_result: Dict[str, Any], h: harness):
        for attempt in range(1, self.max_retries + 1):
            try:
                with open(plan_path, "r", encoding="utf-8") as f:
                    plan = json.load(f)
                code = h.code
                upgrade_prompt = PHASED_FEEDBACK_IMPROVE_PROMPT % (
                    json.dumps(plan, indent=2),
                    code,
                    json.dumps(fuzzer_stats, indent=2),
                    json.dumps(analysis_result, indent=2),
                )
                response = openai.chat.completions.create(
                    model = self.model,
                    messages=[{
                        "role": "user",
                        "content": [
                            {"type": "text",
                            "text": f"{upgrade_prompt}",}
                            ]
                    }],
                # response_format={
                #     "type": "json_object",
                #     "schema": {
                #         "type": "object",
                #         "properties": {
                #             "code": {
                #                 "type": "string",
                #             },
                #             "compile_command": {
                #                 "type": "string",
                #             },
                #         },
                #         "required": ["code", "compile_command"],
                #         "additionalProperties": False
                #     }
                # },
                    temperature=0.4,
                    top_p=1,
                    frequency_penalty=0,
                    presence_penalty=0,
                    timeout=self.timeout
                )
                result = extract_json_from_text(response.choices[0].message.content)
                result = clean_markdown_format(result)

                content = json.loads(result)

                h.code = content['code']
                h.compile_command = content['compile_command']

                return

            except Exception as e:
                logger.warning(f"[LLM] generate_dict attempt {attempt} failed: {e}")
                if attempt < self.max_retries:
                    time.sleep(self.retry_delay)
                else:
                    logger.error(f"[LLM] Failed to generate upgrade prompt: {e}")
    
    def phased_harness_upgrade_2(self, h: harness, prompt: str):       # this part is for distance plateau
        for attempt in range(1, self.max_retries + 1):
            try:
                response = openai.chat.completions.create(
                    model = self.model,
                    messages=[{
                        "role": "user",
                        "content": [
                            {"type": "text",
                            "text": f"{prompt}",}
                            ]
                    }],
                    # response_format={
                    #     "type": "json_object",
                    # },
                    temperature=0.2,
                    top_p=1,
                    frequency_penalty=0,
                    presence_penalty=0,
                    timeout=self.timeout
                )
                result = extract_json_from_text(response.choices[0].message.content)
                result = clean_markdown_format(result)

                content = json.loads(result)

                if "seed1" in content and "harness" not in content:
                    seeds: List[seed_for_harness] = []
                    seed_save_path = Path(h.code_save_folder) / "in"
                    logger.info("[LLM] LLM suggests modifying the seed instead of the harness.")
                    
                    for key, value in content.items():
                        unique_seed_path = build_unique_llm_seed_path(seed_save_path, key)
                        s = seed_for_harness(
                            seed_content_b64 = value,
                            seed_save_path = unique_seed_path
                        )
                        
                        seeds.append(s)

                    return "only_modified_seeds", seeds
                
                elif "harness" in content and "seed1" not in content:
                    logger.info("[LLM] LLM suggests modifying the harness code.")
                    h.code = content['harness']
                    h.compile_command = content['compile_command']

                    return "only_modified_harness", None
                
                elif "seed1" in content and "harness" in content:
                    logger.info("[LLM] LLM suggests modifying both the seed and the harness code.")
                    h.code = content['harness']
                    h.compile_command = content['compile_command']

                    seeds: List[seed_for_harness] = []
                    seed_save_path = Path(h.code_save_folder) / "in"
                    
                    for key, value in content.items():
                        if key.startswith("seed"):
                            unique_seed_path = build_unique_llm_seed_path(seed_save_path, key)
                            s = seed_for_harness(
                                seed_content_b64 = value,
                                seed_save_path = unique_seed_path
                            )
                            
                            seeds.append(s)

                    return "modified_seeds_and_harness", seeds

            except Exception as e:
                logger.warning(f"[LLM] phased_harness_upgrade_2 attempt {attempt} failed: {e}")
                if attempt < self.max_retries:
                    time.sleep(self.retry_delay)
                else:
                    logger.error(f"[LLM] phased_harness_upgrade_2 failed after {self.max_retries} attempts")
                    return None, None
    
    def llm_seed_generation(self, h: harness, prompt: str):       # this part is for distance plateau
        for attempt in range(1, self.max_retries + 1):
            try:
                response = openai.chat.completions.create(
                    model = self.model,
                    messages=[{
                        "role": "user",
                        "content": [
                            {"type": "text",
                            "text": f"{prompt}",}
                            ]
                    }],
                    # response_format={
                    #     "type": "json_object",
                    # },
                    temperature=0.2,
                    top_p=1,
                    frequency_penalty=0,
                    presence_penalty=0,
                    timeout=self.timeout
                )
                result = extract_json_from_text(response.choices[0].message.content)
                result = clean_markdown_format(result)

                content = json.loads(result)

                seed_save_path = Path(h.code_save_folder) / "in"

                if content.get("type") == "generator":
                    generator_code = content.get("generator_code", "")
                    if not generator_code:
                        logger.warning("[LLM] generator type but no generator_code, falling back")
                        return None
                    from src.fuzz_components.fuzz_runner import _execute_seed_generator
                    generated_files = _execute_seed_generator(generator_code, str(seed_save_path),
                                                               script_dir=str(Path(h.code_save_folder)))
                    if not generated_files:
                        logger.warning("[LLM] seed generator produced no files")
                        return None
                    seeds = []
                    for filepath in generated_files:
                        s = seed_for_harness(
                            seed_content_b64 = filepath,
                            seed_save_path = filepath,
                            seed_encoding = "file"
                        )
                        seeds.append(s)
                    logger.info(f"[LLM] LLM seed generator produced {len(seeds)} seeds.")
                    return seeds

                elif content.get("type") == "seeds":
                    seeds_data = content.get("seeds", content)
                    if "seed1" in seeds_data:
                        seeds: List[seed_for_harness] = []
                        logger.info("[LLM] LLM has generated new seeds (direct).")

                        for key, value in seeds_data.items():
                            unique_seed_path = build_unique_llm_seed_path(seed_save_path, key)
                            s = seed_for_harness(
                                seed_content_b64 = value,
                                seed_save_path = unique_seed_path,
                                seed_encoding = "base64"
                            )

                            seeds.append(s)

                        return seeds

                elif "seed1" in content:
                    seeds: List[seed_for_harness] = []
                    logger.info("[LLM] LLM has generated new seeds (legacy).")

                    for key, value in content.items():
                        unique_seed_path = build_unique_llm_seed_path(seed_save_path, key)
                        s = seed_for_harness(
                            seed_content_b64 = value,
                            seed_save_path = unique_seed_path,
                            seed_encoding = "base64"
                        )

                        seeds.append(s)

                    return seeds

            except Exception as e:
                logger.warning(f"[LLM] llm_seed_generation attempt {attempt} failed: {e}")
                if attempt < self.max_retries:
                    time.sleep(self.retry_delay)
                else:
                    logger.error(f"[LLM] llm_seed_generation failed after {self.max_retries} attempts")
                    return None
    
    def raw_chat(self, prompt: str) -> str:
        response = openai.chat.completions.create(
        model=self.model,
        messages=[{
            "role": "user",
            "content": [{"type": "text", "text": prompt}]
        }],
        timeout=self.timeout
    )
        return response.choices[0].message.content
    
    def structural_refine_harness(self, h: harness, guidance: Dict[str, Any], cve_hints_obj: Dict[str, Any], phase_a_context: Dict[str, Any]):
        for attempt in range(1, self.max_retries + 1):
            try:
                refine_prompt = STRUCTURAL_REFINE_PROMPT.substitute(
                    harness_code=h.code,
                    cve_hints_obj=json.dumps(cve_hints_obj, indent=2, ensure_ascii=False),
                    phase_a_context_json=json.dumps(phase_a_context, indent=2, ensure_ascii=False),
                    guidance_json=json.dumps(guidance, indent=2, ensure_ascii=False),
                )

                response = openai.chat.completions.create(
                    model=self.model,
                    messages=[{
                        "role": "user",
                        "content": [
                            {
                                "type": "text",
                                "text": refine_prompt,
                            }
                        ],
                    }],
                    temperature=0.2,
                    top_p=1,
                    frequency_penalty=0,
                    presence_penalty=0,
                    timeout=self.timeout,
                )

                result = extract_json_from_text(response.choices[0].message.content)
                result = clean_markdown_format(result)
                content = json.loads(result)

                h.code = content["code"]
                h.compile_command = content["compile_command"]
                return h

            except Exception as e:
                logger.warning(f"[Warning] structural_refine_harness attempt {attempt} failed: {e}")
                if attempt < self.max_retries:
                    time.sleep(self.retry_delay)
                else:
                    logger.error("[Error] structural_refine_harness failed after max retries")
                    return None