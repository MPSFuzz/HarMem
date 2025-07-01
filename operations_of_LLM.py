import openai
import subprocess
import sys
import json

from LLM_prompt import *
from operations_of_hanress import harness

openai.api_key = "sk-il837fQ3G6l21IR1355f785d729c4e10B1A33b4aEa762e62"
openai.base_url = "https://api.gpt.ge/v1/"
openai.default_headers = {"x-foo": "true"}

class LLM:
    def __init__(self, **kwargs):
        self.harness_instance = harness()
        # if 'prompt' in kwargs:
        #     self.prompt = kwargs['prompt']
        if 'lib_name' in kwargs:
            self.lib_name = kwargs['lib_name']
        
        if 'target_func' in kwargs:
            self.target_func = kwargs['target_func']
            self.harness_instance.target_func = self.target_func
        
        if 'call_chain' in kwargs:
            self.call_chain = kwargs['call_chain']
        
        if 'target_location' in kwargs:
            self.target_location = kwargs['target_location']
    
    def generate_code(self) -> dict:
        code_prompt = CODE_GENERATE_PROMPT % (self.target_func, self.call_chain, self.target_location)

        response = openai.chat.completions.create(
            model = "gpt-4o-2024-11-20",
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
            presence_penalty=0
        )

        result = response.choices[0].message.content

        try:
            content = json.loads(result)
        except json.JSONDecodeError as e:
            print(f"error:{e}")
            print(result)

        self.harness_instance.code = content['code']
        self.harness_instance.compile_command = content['compile_command']

        self.harness_instance.save_code_to_file()
        self.harness_instance.complete_compile_command()

        return {'code': self.harness_instance.code, 'compile_command': self.harness_instance.compile_command}
    
    def harness_fix(self) -> dict:
        fix_prompt = HARNESS_FIX % (self.harness_instance.code, self.harness_instance.compile_command, self.harness_instance.compile_result)

        response = openai.chat.completions.create(
            model = "gpt-4o-2024-11-20",
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
            }
        )

        result = response.choices[0].message.content

        try:
            content = json.loads(result)
        except json.JSONDecodeError as e:
            print(f"error:{e}")
            print(result)

        self.harness_instance.code = content['code']
        self.harness_instance.compile_command = content['compile_command']

        return {'code': self.harness_instance.code, 'compile_command': self.harness_instance.compile_command}


if __name__ == "__main__":
    lib_name = "libxml2"
    target_func = "xmlNodeGetContent"
    target_location = f"/libxml2/tree.c"
    call_chain =  ['xmlSchematronParse', 'xmlReadFile', 'xmlCtxtNewInputFromUrl', 'xmlLoadResource', 'xmlResolveResourceFromCatalog', \
                   'xmlCatalogLocalResolve', 'xmlCatalogListXMLResolve', 'xmlFetchXMLCatalogFile', 'xmlGetProp', 'xmlNodeGetContent']
    
    llm_gen = LLM(target_func = target_func, target_location = target_location, call_chain = call_chain)
    content = llm_gen.generate_code()

    print(content['code'])
    print(content['compile_command'])
