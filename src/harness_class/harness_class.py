import subprocess
import re
import os
import shlex
import datetime

from dataclasses import dataclass
from src.utils.utils import get_logger, get_path_subfolder

logger = get_logger(__name__)

class harness:
    def __init__(self, code: str=None, target_func: str=None, 
                 code_file: str=None, code_save_folder: str=get_path_subfolder("harness"), 
                 skeleton_path: str=None):
        self.code = code
        self.code_file = code_file
        self.compile_command = None
        self.compile_result = None
        self.code_save_folder = code_save_folder
        self.target_func = target_func
        self.skeleton_path = skeleton_path
        self._shell_env_cache = None
    
    def _get_interactive_shell_path(self) -> dict:
        try:
            output=subprocess.check_output(['bash', '-lc', 'env'], text=True, timeout=5)
            env_vars = {}
            for line in output.strip().split('\n'):
                if '=' in line:
                    k, v = line.split('=', 1)
                    env_vars[k] = v
            return env_vars
    
        except:
            logger.error("Failed to get interactive shell environment variables.")
            return {}
    
    def _get_env_var(self):
        if self._shell_env_cache is None:
            shell_env = self._get_interactive_shell_path()
            env = os.environ.copy()
            if shell_env:
                env.update(shell_env)
            self._shell_env_cache = env
        
        return self._shell_env_cache

    def save_code_to_file(self):
        if not os.path.exists(self.code_save_folder):
            os.makedirs(self.code_save_folder)
        if self.code is not None:
            now = datetime.datetime.now()
            timestamp = now.strftime("%Y%m%d_%H%M%S")
            
            filename = os.path.join(self.code_save_folder, timestamp)
            if not os.path.exists(filename):
                os.makedirs(filename)

            filename = os.path.join(self.code_save_folder, f"{timestamp}/{timestamp}_{self.target_func}.c")

            try:
                with open(filename, "w") as f:
                    f.write(self.code)
                self.code_file = filename
            except Exception as e:
                logger.error(f"Error saving code to file: {e}")
    
    def update_code_file(self):
        with open(self.code_file, "w", encoding="utf-8") as f:
            f.write(self.code)
        return

    def complete_compile_command(self):
        filename, _ = os.path.splitext(self.code_file)
        compile_command_template = self.compile_command
        compile_command_modified = re.sub(r'\ba\.out\b', f"{filename}.out", compile_command_template)
        compile_command_modified = re.sub(r'\ba\.c\b', f"{filename}.c", compile_command_modified)

        self.compile_command = compile_command_modified

    def _ensure_compile_sanitizer(self):
        if self.compile_command and not re.search(r'-fsanitize=', self.compile_command):
            self.compile_command = re.sub(
                r'(aflgo-clang\S*|afl-clang\S*|clang\b)',
                r'\1 -fsanitize=address',
                self.compile_command,
                count=1
            )
            logger.info("Auto-appended -fsanitize=address to compile command")

    def compile_test(self) -> bool:
        env = os.environ.copy()
        env.update(self._get_env_var())
        self._ensure_compile_sanitizer()

        try:
            self.compile_result = subprocess.run(
                #["bash", "-lc", self.compile_command],
                self.compile_command,
                shell=True,
                executable="/bin/bash",
                stdout = subprocess.PIPE,
                stderr = subprocess.PIPE,
                text = True,
                check = True,
                env=env,
                timeout=60
                )
            logger.info("Compilation succeeded with output \n")
            return True
        except subprocess.CalledProcessError as e: #前面的subprocess中的check可以直接用于gcc编译的执行结果判断，如果执行失败了会抛出一个subprocess.CalledProcessError 异常
            logger.error(f"Compilation failed with error:\n{e.stderr}")
            self.compile_result = e.stderr 
            return False

@dataclass
class seed_for_harness:
    seed_content_b64: str
    seed_save_path: str
    seed_encoding: str = "base64"
