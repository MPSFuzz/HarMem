import openai
import subprocess
import sys
import json
import time

from utils import get_logger
from LLM_prompt import *
from harness_class import harness

openai.api_key = "sk-WXtqOuBZPY096KTcDdE866275274464d88943d068aA7Ff5d"
openai.base_url = "https://api.gpt.ge/v1/"
openai.default_headers = {"x-foo": "true"}

logger = get_logger(__name__)

#TODO: 当前的harness_fix函数只考虑了修复编译命令造成的错误，应该还要包含修复harness中本身编写造成的错误

class LLM:
    def __init__(self, lib_name=None, target_func=None, target_location=None,max_retries=3, retry_delay=5, timeout=60):
        self.lib_name = lib_name
        self.target_func = target_func
        self.target_location = target_location
        self.max_retries = max_retries
        self.retry_delay = retry_delay
        self.timeout = timeout

    def entry_api_filter(self, api_list) -> list:
        api_filter_prompt = ENTRY_POINT_FILTER % (self.target_func, self.lib_name, api_list)

        for attempt in range(1, self.max_retries + 1):
            try:
                response = openai.chat.completions.create(
                    model= "gpt-4o-all",
                    messages=[{
                        "role": "user",
                        "content": [
                            {
                                "type": "text",
                                "text": f"{api_filter_prompt}"
                            }
                        ]
                    }],
                    response_format={
                        "type": "json_object",
                        "schema": {
                            "type": "object",
                            "properties": {
                                "filtered_apis": {
                                    "type": "array",
                                    "items": {
                                        "type": "string"
                                    },
                                    "description": f"A list of APIs that are entry points for the target function {self.target_func} in the library {self.lib_name}."
                                }
                            },
                            "required": ["filtered_apis"],
                            "additionalProperties": False
                        }
                    },
                    timeout=self.timeout
                )

                result = response.choices[0].message.content
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
    
    def generate_code(self, call_chain) -> harness:
        h = harness()
        h.target_func = self.target_func

        for attempt in range(1, self.max_retries + 1):
            try:
                code_prompt = CODE_GENERATE_PROMPT % (self.lib_name,self.target_func, call_chain, self.target_location)
                response = openai.chat.completions.create(
                    model = "gpt-4o-all",
                    messages=[{
                        "role": "user",
                        "content": [
                            {"type": "text",
                            "text": f"{code_prompt}",}
                            ]
                    }],
                response_format={
                    "type": "json_object",
                    "schema": {
                        "type": "object",
                        "properties": {
                            "code": {
                                "type": "string",
                                "description": f"A C/C++ fuzz harness code for the target function.",
                            },
                            "compile_command": {
                                "type": "string",
                                "description": f"The compilation command for the generated code.Using a.c to refer to the code, and a.out to execution file."
                            },
                        },
                        "required": ["code", "compile_command"],
                        "additionalProperties": False
                    }
                },
                    temperature=0.4,
                    max_tokens=4096,
                    top_p=1,
                    frequency_penalty=0,
                    presence_penalty=0,
                    timeout=self.timeout
                )

                result = response.choices[0].message.content

                content = json.loads(result)

                h.code = content['code']
                h.compile_command = content['compile_command']

                h.save_code_to_file()
                h.complete_compile_command()

                return h
            
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
                fix_prompt = HARNESS_FIX % (h.code, h.compile_command, h.compile_result)

                response = openai.chat.completions.create(
                    model = "gpt-4o-all",
                    messages=[{
                        "role": "user",
                        "content": [
                            {"type": "text",
                            "text": f"{fix_prompt}",}
                            ]
                    }],
                    response_format={
                        "type": "json_object",
                        "schema": {
                            "type": "object",
                            "properties": {
                                "code": {
                                    "type": "string",
                                    "description": f"The code after fixing",
                                },
                                "compile_command": {
                                    "type": "string",
                                    "description": f"The compilation command after modifing.Using a.c to refer to the code, and a.out to execution file."
                                },
                            },
                            "required": ["code", "compile_command"],
                            "additionalProperties": False
                        }
                    },
                    timeout=self.timeout
                )

                result = response.choices[0].message.content

                try:
                    content = json.loads(result)
                except json.JSONDecodeError as e:
                    print(f"error:{e}")
                    print(result)

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


