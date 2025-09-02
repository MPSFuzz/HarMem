import subprocess
import re
import os
import datetime

from utils import get_logger

logger = get_logger(__name__)

class harness:
    def __init__(self):
        self.code = None
        self.code_file = None
        self.compile_command = None
        self.compile_result = None
        self.save_folder = "./harness/"
        self.target_func = None
    
    def save_code_to_file(self):
        if not os.path.exists(self.save_folder):
            os.makedirs(self.save_folder)
        if self.code is not None:
            now = datetime.datetime.now()
            timestamp = now.strftime("%Y%m%d_%H%M%S")
            
            filename = os.path.join(self.save_folder, timestamp)
            if not os.path.exists(filename):
                os.makedirs(filename)

            filename = os.path.join(self.save_folder, f"{timestamp}/{timestamp}_{self.target_func}.c")

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

    def compile_test(self) -> bool:
        try:
            self.compile_result = subprocess.run(
                self.compile_command,
                stdout = subprocess.PIPE,
                stderr = subprocess.PIPE,
                text = True,
                check = True,
                shell=True)
            logger.info("Compilation succeeded with output \n")
            return True
        except subprocess.CalledProcessError as e: #前面的subprocess中的check可以直接用于gcc编译的执行结果判断，如果执行失败了会抛出一个subprocess.CalledProcessError 异常
            print(f"Compilation failed with error:\n{e.stderr}")
            self.compile_result = e.stderr 
            return False
    