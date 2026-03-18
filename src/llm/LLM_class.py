import openai
import os
import json
import time
import string
from typing import Dict, Any, List, Optional, Tuple
from pathlib import Path

from src.utils.utils import get_logger, clean_markdown_format, extract_json_from_text, get_path_subfolder, parse_target_file, extract_target_func_code_from_plan, load_source_snippet, clip_text
from src.llm.LLM_prompt import *
from src.harness_class.harness_class import harness, seed_for_harness
from src.cve_helper.cve_partial_prompt_render import render_cve_hints_for_skeleton, render_cve_hints_for_codegen

#TODO: 添加一个从LLM获得字典的接口

# openai.api_key = "sk-WXtqOuBZPY096KTcDdE866275274464d88943d068aA7Ff5d"
openai.api_key = "sk-tt38idkFn5fBhmvCF5AdB32fA90d4f71A8417d5b7fE77030" # group ys
# openai.base_url = "https://api.gpt.ge/v1/"
# openai.base_url = "https://api.v3.cm/v1/"
openai.base_url = "https://api.vveai.com/v1/"
openai.default_headers = {"x-foo": "true"}

logger = get_logger(__name__)

class LLM:
    def __init__(self, lib_name=None, target_func=None, target_location=None, max_retries=3, retry_delay=5, timeout=60, model: Optional[str] = "gpt-5.2"):
        self.lib_name = lib_name
        self.target_func = target_func
        self.target_location = target_location
        self.max_retries = max_retries
        self.retry_delay = retry_delay
        self.timeout = timeout
        self.model = model

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

    def generate_dict(self, h: harness, call_chain, min_weight: int = 3):
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
                    v = (token.get("value") or "").strip()
                    if not v:
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
                
                p = Path(h.code_file)
                p = str(p.parent)
                dict_save_file = os.path.join(p, "harness_dict.dict")
                with open(dict_save_file, "w", encoding="utf-8") as f:
                    for v in cleaned_tokens:
                        f.write(json.dumps(v))
                        f.write("\n")
                
                logger.info(f"Saved harness dictionary to {dict_save_file}")
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
                        s = seed_for_harness(
                            seed_content = value,
                            seed_save_path = seed_save_path / f"{key}_from_llm"
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
                            s = seed_for_harness(
                                seed_content = value,
                                seed_save_path = seed_save_path / f"{key}_from_llm"
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

                if "seed1" in content:
                    seeds: List[seed_for_harness] = []
                    seed_save_path = Path(h.code_save_folder) / "in"
                    logger.info("[LLM] LLM has generated new seeds.")
                    
                    for key, value in content.items():
                        s = seed_for_harness(
                            seed_content = value,
                            seed_save_path = seed_save_path / f"{key}_from_llm"
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