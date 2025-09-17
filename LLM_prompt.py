CODE_GENERATE_PROMPT = """
        You are an expert in fuzz testing and you are testing an open source library called %s,please write a fuzz harness that could trigger the target function named "%s" in this open source library\
        Here is some data about this library to help you complete the harness generation: \
        1. This is a call chain that include the target function: %s \
        2. This target function is declared or used in %s in the source code of this library. \
        These information may be helpful when you generate the fuzz harness. \
        The harness you gernerate should include the libxml2 library and complie successfully. \
        
        Format requirements : The code should follow the C or C++ code specification, and the program code should be complete and properly formatted. \
        In the code, you should write a long sentence without using line breaks, avoiding the newline character \ n. \
        Do not use any output printing, logging, or debugging functions. Focus only on consuming the fuzz input and triggering the target call chain. \
        Use a loop such as while (__AFL_LOOP(10000)) to repeatedly call the target function with fuzzed data from stdin, and ensure the loop works even if __AFL_LOOP is undefined. \
        
        To support AFLGo directed fuzzing, insert dummy operations or volatile accesses around the target function call to create a unique basic block, 
            or use a macro such as volatile int afl_target = 0; afl_target++; near the target call to mark it as a target block.

        Ensure that the fuzz driver executes the target function in a way that exercises its main logic, for example by creating required objects and passing fuzzed data to the target function. \
        By the way, the fuzz driver you generate will be user by AFL-style fuzzers,so DO NOT use any other special fuzzers' API like "LLVMFuzzerTestOneInput" in the code. \
        
        Note that the fuzz driver you generate will be used for directional fuzzers such as aflgo, 
            so you need to pay attention to how external data is passed into the program.\
        The fuzz driver should read all fuzz input from standard input(stdin) into a memory buffer and pass this buffer to the target function, do not use any hard-coded files. \

        When you finish the code generation, please give me the compile command. In the compile command you give, use a.c to refer to the code, and a.out to execution file,\
            and make sure the compile command can compile the code successfully. \
        In addition, because this fuzz driver is to use aflgo type fuzzer, the compiler should use clang after afl packaging(like aflgo-clang or aflgo-clang++). \
        
        Your answer needs to be in json format containing two properties: code and compile_command.\
        **Your answer must be in a pure JSON format** without any Markdown. Just the raw JSON string (no Markdown formatting). 
        **Do not return your answer in any other format like markdown format, only raw JSON as a plain text string.** \
        Please ensure your response only contains:
        {
            "code": "<the generated C/C++ fuzz harness code>",
            "compile_command": "<the compile command for the generated code>"
        }
        Your answer should be the raw JSON string, and should contain only these two properties, nothing else. No additional explanations, comments, or details.

        """

HARNESS_FIX = """
        You are a code repair expert. \
        The code I give you had encountered some problems during compilation. \
        The code that encountered the problem is as follows: \
        %s \
        The compile command last time you give me that I use to compile the code is as follows: \
        %s \
        The error message is: \
        %s \
        
        Now you need to modify the code or compile command I gave you to fix the problem it encountered. \
        
        If there is a problem such as "No such file or directory" in the compilation error caused by the relevant library not being found, \
        give priority to using tools such as pkg-config to repair the compilation command. \
        
        When you finish the code or compile command modification, please give me the result. \
        In the compile command you give, use a.c to refer to the code, and a.out to execution file,\
        and make sure the compile command can compile the code successfully. \
        
        **Your answer must be in a pure JSON format** without any Markdown. Just the raw JSON string (no Markdown formatting). 
        **Do not return your answer in any other format like markdown format, only raw JSON as a plain text string.** \
        
        Please ensure your response only contains:
        {
            "code": "<the generated C/C++ fuzz harness code>",
            "compile_command": "<the compile command for the generated code>"
        }
        Your answer should be the raw JSON string, and should contain only these two properties, nothing else. No additional explanations, comments, or details.
"""

ENTRY_POINT_FILTER = """
        You are an expert in C/C++ library fuzz testing. You need to write some harnesses that can reach a target function %s in the %s library. \
        Here is a list of all root node functions extracted from the tested library CG that may reach the target function : %s. \
        You need to filter these functions to keep only those that may be worth writing harness tests for. \
        
        Return only a JSON object with the following shape (no extra text): {"filtered_apis": ["funcA", "funcB", ...]}.\
        **Your answer must be in a pure JSON format** without any Markdown. Just the raw JSON string (no Markdown formatting). 
        **Do not return your answer in any other format like markdown format, only raw JSON as a plain text string.** \
        
        In addition, your answer can ONLY be what I asked, no other explanatory content.
"""