SKELETON_GENERATE_PROMPT = """
        You are an expert C programmer and fuzzing practitioner.

        ATTENTION: Output Only JSON!!!
        You MUST strictly follow the output format requirements below:
        - Do NOT write any explanations.
        - Do NOT write markdown.
        - Do NOT write prose, lists, or headings.
        - Your entire reply MUST be a single valid JSON object and nothing else.

        We want to fuzz a library named %s using AFL/AFLGo. Below is a JSON context
        with static analysis information about a specific call chain and
        lifecycle hints extracted from the project:

        === STATIC CONTEXT (JSON) ===
        %s

        This static context may contain:
        - chain.nodes[*].name / signature / file / location
        - chain.nodes[*].visibility: "external" or "internal"
        - external_chain: an ordered list of APIs that are safe to call from a harness
        - lifecycle_plan: init/cleanup hints
        - (and possibly other analysis fields)

        Your task in THIS PHASE is NOT to implement the full call chain,
        but to:

        1) Design a reusable AFL/AFLGo fuzz harness SKELETON in C for this library,
        using lifecycle information (global init / global cleanup / per-iteration cleanup)
        and any root API / external_chain hints to decide how to structure main()
        and the fuzzing loop.

        2) Search for real-world usage examples (tests, sample code, tutorials, official docs)
        of the APIs in this call chain.

        3) Based on these examples, design a reusable AFL/AFLGo fuzz harness SKELETON in C,
        with a clear placeholder region for the future call-chain logic.

        4) Provide small, self-contained usage snippets and short documentation summaries
        for each API in the chain.

        === Requirements on the AFL/AFLGo harness skeleton ===
        The skeleton must be valid C code and should:

        1. Include a standard AFL persistent loop with a safe fallback:

        #ifndef __AFL_LOOP
        static int __afl_once = 1;
        #define __AFL_LOOP(x) (__afl_once-- > 0)
        #endif

        2. Read fuzz input from a FILE whose path is given as argv[1],
        read the entire file into a heap buffer, and keep both the pointer and size.
        (Assume AFL/AFLGo will use @@ to substitute the filename.)

        3. Have a main() function like:

        int main(int argc, char **argv) {
            // check argc
            // initialize the target library if needed
            while (__AFL_LOOP(10000)) {
                // read file at argv[1] into memory
                // parse it or create a basic input object if appropriate
                // @@CHAIN_LOGIC_BEGIN@@
                //   (this region will later be replaced by code that follows the call chain)
                // @@CHAIN_LOGIC_END@@
                // cleanup resources for this iteration
            }
            // global cleanup (e.g., xmlCleanupParser)
            return 0;
        }

        4. DO NOT implement the full call chain in this phase.
        Inside the @@CHAIN_LOGIC_BEGIN@@ / @@CHAIN_LOGIC_END@@ region, only put minimal
        placeholder comments or the simplest safe operations needed to keep the program
        logically consistent. The real call-chain logic will be generated in a later phase.

        5. The skeleton MUST NOT define any new functions whose names exactly match APIs in
        the call chain (do NOT stub internal APIs). Only call functions, do not
        re-implement them.

        6. When deciding which APIs (if any) to call inside the skeleton_code:
        - Prefer using public / external APIs:
            * functions that appear in external_chain, or
            * functions whose node.visibility == "external".
        - You MUST NOT call functions whose node.visibility == "internal" (these are
            typically internal or static library APIs). Such APIs may still appear in
            api_usage_snippets, but MUST NOT be called from skeleton_code.

        7. The skeleton should already contain an AFLGo target marker placeholder near where
        the target API will be called in the future, for example:

        // AFLGo target marker will be inserted here before calling the target API
        // volatile int afl_target = 0; afl_target++;

        8. The skeleton should be as generic as possible for this library, following common
        initialization and cleanup patterns inferred from real-world examples and
        official docs.

        === Requirements on API usage snippets ===
        For EACH API name in the call chain, you MUST:

        - Search for realistic usage in tests, examples, sample code, or documentation.
        - Provide a small, self-contained code snippet (C) that shows how the API is
        typically used (including required types/structures and surrounding calls).
        - Summarize, in one or two sentences:
        * what the API does,
        * key preconditions (e.g., which arguments must be non-NULL / allocated),
        * and any important flags or options.

        If an API is internal or rarely documented:
        - Try to infer its usage from nearby code or call sites in the library or tests.
        - Clearly state that the usage is inferred when summarizing.
        - Remember: internal APIs may appear in snippets and summaries, but MUST NOT be
        called inside skeleton_code.

        === Output Format (STRICT JSON) ===
        You MUST return a single JSON object with the following structure:

        {
        "language": "C",
        "skeleton_code": "<the complete C skeleton with @@CHAIN_LOGIC_BEGIN@@ and @@CHAIN_LOGIC_END@@ placeholders>",
        "compile_command_hint": "<a plausible aflgo-clang compile command, using a.c and a.out, e.g. 'aflgo-clang -g -O2 a.c -o a.out $(pkg-config --cflags --libs libxml-2.0)'>",
        "api_usage_snippets": [
            {
            "api": "<API name from the call chain>",
            "snippet": "<a small C code snippet showing realistic usage of this API>",
            "source_hint": "<short text indicating whether this seems to come from tests, examples, docs, etc. Do NOT include URLs.>",
            "summary": "<1–3 sentences about what the API does and important preconditions/flags>"
            }
            // one object per API in the chain
        ],
        "doc_summaries": {
            "<API name>": "<short documentation-style description>",
            "...": "..."
        }
        }
        """


CODE_GENERATE_PROMPT = """
        You are an expert in fuzz testing and C programming, and you are testing an open-source library called %s.
        Your goal is to generate a high-quality AFL/AFLGo fuzz harness that triggers the target function named "%s".

        In THIS PHASE, you MUST NOT write the harness from scratch.
        Instead, you are given:

        1) A detailed static analysis PLAN (JSON) for the target call chain.
        2) A pre-generated SKELETON (JSON) that already contains:
        - a complete C fuzz driver skeleton,
        - AFL/AFLGo loop and file-input handling,
        - and a placeholder region marked by:
            @@CHAIN_LOGIC_BEGIN@@
                // chain logic to be generated here
            @@CHAIN_LOGIC_END@@

        Your task is to:
        - Start from the given skeleton_code.
        - ONLY replace the code between @@CHAIN_LOGIC_BEGIN@@ and @@CHAIN_LOGIC_END@@.
        - Keep EVERYTHING outside that region unchanged (includes, main(), __AFL_LOOP fallback, file reading, init/cleanup patterns, etc.).
        - Inside the placeholder region, implement the call-chain logic that uses as many functions in the call chain as possible
        and correctly calls the target function.

        ==================== Static Analysis PLAN (JSON) ====================
        %s

        This JSON object provides:
        - "chain": a call chain from the root API to the target function (ordered from top-level to target).
        - "nodes": detailed function signatures, source locations, preconditions, required initialization patterns and specific implementation hints.
        - Each node may have a "visibility" field:
            * "external": safe to call from a harness.
            * "internal": static or internal helper; MUST NOT be called directly from the harness.
        - "external_chain": an ordered list of external APIs that should be preferred as the explicit call sequence in the harness.
        - "resources": allocation and release operations associated with each function.
        - "lifecycle_plan": alloc/free, init/cleanup steps that should be followed to maintain a valid program state.
        - "bitmask_bundles" and "preconditions": flag constraints, runtime checks, or conditional guards that may affect valid inputs.
        - "harness_hint": suggested default arguments, flag combinations, or parameter mappings.

        ==================== SKELETON & API USAGE INFO (JSON) ====================
        %s

        This JSON object provides:
        - "skeleton_code": a complete C fuzz driver that:
            * defines main(),
            * reads fuzz input from argv[1] into a heap buffer,
            * contains a persistent AFL loop with a safe fallback,
            * and has @@CHAIN_LOGIC_BEGIN@@ / @@CHAIN_LOGIC_END@@ placeholders.
        - "compile_command_hint": a plausible aflgo-clang compile command template.
        - "api_usage_snippets": realistic C usage examples for each API in the call chain.
        - "doc_summaries": short documentation-style descriptions for each API.

        ==================== YOUR TASK (STRICT) ====================

        You MUST:

        1. Use the skeleton_code as the base.
        - Do NOT change:
            * the __AFL_LOOP fallback macro,
            * the way argv[1] is read and the buffer is allocated,
            * the overall structure of main(),
            * global init/cleanup patterns that are already present (e.g., xmlInitParser/xmlCleanupParser),
            * error-handling and cleanup code outside the placeholder region.

        2. ONLY modify the code between:
        @@CHAIN_LOGIC_BEGIN@@
        @@CHAIN_LOGIC_END@@

        - Replace the placeholder comments with concrete C code that:
            * follows the call chain in "chain" (from root to target) as much as possible,
            * uses functions in "external_chain" as the primary explicit call sequence,
            * respects the function signatures and preconditions in "nodes",
            * respects resource usage in "resources" and "lifecycle_plan",
            * uses realistic patterns from "api_usage_snippets" when calling each API.
        - You MAY declare local variables inside this region if needed.
        - You MUST NOT redefine any functions whose names appear in the call chain.

        3. External vs internal APIs:
        - You MAY ONLY call functions that satisfy at least one of:
            * they appear in "external_chain", OR
            * the corresponding node has visibility == "external".
        - For any node whose visibility == "internal":
            * DO NOT call it directly from the harness.
            * DO NOT declare a prototype or stub with the same name.
            * Treat its "preconditions" and implementation hints as constraints on how
                to prepare arguments for surrounding external APIs.

        - You MUST NOT:
            * create fake stubs for internal/static functions in order to make calls compile;
            * cast opaque library context pointers to custom structs just to access internal fields.

        4. Target function and AFLGo marker:
        - Identify the target function "%s" in the call chain.
        - Immediately BEFORE the line that calls the target function, insert the AFLGo marker, for example:

            volatile int afl_target = 0;
            afl_target++;

        - Then call the target function using correctly prepared arguments (derived from earlier steps in the chain).

        5. Call chain coverage:
        - Attempt to call as MANY functions from the call chain as possible in logical order.
        - Prefer to follow the order given by "external_chain" for explicit calls.
        - Use the static analysis plan to propagate objects/handles between calls:
            * e.g., a doc or context created earlier should be reused by later APIs in the chain.
        - Use "bitmask_bundles" and "harness_hint.param_defaults" to choose reasonable default flags/options,
            while still allowing fuzz input to influence buffers, lengths, and sometimes options.

        6. Fuzz input influence:
        - Ensure that fuzz input (the buffer read from argv[1] and its size) meaningfully influences:
            * the data parsed into the library (e.g., XML/JSON/text),
            * or configuration / options where appropriate.
        - Do NOT ignore the fuzz buffer; it should flow into the library through the root/early APIs.

        7. Safety & cleanup:
        - Do NOT introduce printf/logging; focus on consuming fuzz input and driving the call chain.
        - Do NOT introduce network I/O.
        - Ensure all resources allocated in the chain-logic region are properly released before leaving the loop iteration,
            following "resources" and "lifecycle_plan" (e.g., free docs, contexts, buffers, validators).

        ==================== BUILD REQUIREMENTS (STRICT) ====================

        - The final harness MUST be valid C code.
        - It MUST still read fuzz input from argv[1] (as implemented in the skeleton).
        - It MUST still use a persistent fuzzing loop: while (__AFL_LOOP(10000)) { ... }.
        - The compile command MUST follow the pattern:

            aflgo-clang -g -O2 a.c -o a.out $(pkg-config --cflags --libs XXX)

        Replace XXX with the correct pkg-config name for the target library (e.g., "libxml-2.0")
        if this can be inferred from the plan or skeleton; otherwise, give your best guess.

        ==================== OUTPUT FORMAT (STRICT JSON) ====================

        Return a single JSON object with exactly two properties:

        {
        "code": "<the COMPLETE C source of the fuzz harness, based on skeleton_code, with the @@CHAIN_LOGIC@@ region filled in>",
        "compile_command": "<the compile command>"
        }

        ATTENTION:
        - "code" MUST contain the full C source (not just the @@CHAIN_LOGIC@@ region).
        - Do NOT use Markdown formatting.
        - Do NOT include any extra fields or text outside this JSON object.
        """


HARNESS_FIX_PROMPT = """
        You are an expert in C/C++ build and compilation, and in fuzz harness engineering.
        Your task is to REPAIR an existing fuzz harness that failed to compile or link,
        while preserving its overall structure and fuzzing intent.

        In particular, this harness may have been generated from a pre-defined skeleton
        that already encodes:

        - reading fuzz input from argv[1] into a heap buffer,
        - a persistent AFL/AFLGo loop (with a __AFL_LOOP fallback),
        - library initialization and cleanup patterns,
        - and a dedicated region for call-chain logic marked by:

            @@CHAIN_LOGIC_BEGIN@@
            ...
            @@CHAIN_LOGIC_END@@

        You MUST respect this structure.

        ATTENTION: Only output JSON!!!
        - Do NOT include Markdown, explanations, comments about your changes, or any extra fields.
        - Do NOT output anything other than this JSON object.

        ==================== Static Analysis Data (JSON) ====================
        %s

        The static analysis plan may include:
        - chain: ordered call chain from root API to target.
        - nodes: each node has name, signature, preconditions, and possibly "visibility":
            * "external": safe to call from a harness.
            * "internal": static/internal helper; MUST NOT be called directly from the harness.
        - external_chain: preferred sequence of external APIs.
        - resources, lifecycle_plan, bitmask_bundles, harness_hint, etc.

        ==================== Current Harness Code ====================
        %s

        ==================== Original Compile Command ====================
        %s

        ==================== Compiler / Linker Error Output ====================
        %s

        ==================== STRICT REPAIR RULES ====================

        1) Preserve the Skeleton Structure
        - Do NOT change:
        * the definition and usage of __AFL_LOOP (and its fallback),
        * how argv[1] is read and how the fuzz input buffer is allocated,
        * the overall shape of main() (arguments, control flow, return type),
        * global initialization / cleanup calls that already exist (e.g., xmlInitParser/xmlCleanupParser),
        * the persistent fuzzing loop structure (while (__AFL_LOOP(10000)) { ... }).

        - If the code contains @@CHAIN_LOGIC_BEGIN@@ and @@CHAIN_LOGIC_END@@ markers:
        * You SHOULD limit semantic changes to the code between these markers,
            except for:
            - adding #include directives,
            - adding forward declarations or typedefs,
            - adjusting global macros,
            - or modifying the compile command.
        * Do NOT remove or rename these markers if they exist.

        2) Preserve the Call Chain and Target Semantics
        - The harness is intended to drive a specific call chain and target function
        described in the static analysis data.
        - Do NOT delete or comment out calls to the target function.
        - For other functions in the chain:
        * Prefer to keep them and fix their usage, but you MAY drop a single problematic
            call if it is impossible to make it compile without violating other rules
            (e.g., when it is an internal/static API that should not be called directly).
        - Do NOT rename any functions that appear in the call chain.
        - If a call is incorrect (wrong arguments, types), FIX its arguments instead of removing it.

        3) External vs Internal APIs
        - Use the "visibility" and "external_chain" hints from the static analysis:
        * Functions with visibility == "external", or those in external_chain,
            are valid to call from the harness.
        * Functions with visibility == "internal" are internal/static helpers and
            MUST NOT be called directly from the harness.
        - If the current harness calls an internal function that causes compilation errors:
        * First, try to replace it with a semantically similar PUBLIC API from the same
            subsystem, using api_usage_snippets / PLAN hints if available.
        * If no safe public replacement exists, you MAY remove that single call,
            while keeping the rest of the chain intact.
        - You MUST NOT:
        * create new function definitions that shadow existing library APIs or internal helpers,
        * declare fake prototypes for internal/static functions just to silence the compiler,
        * cast opaque library pointer types to custom structs in order to access internal fields.

        4) AFLGo Target Marker
        - If there is an AFLGo target marker (e.g., volatile int afl_target = 0; afl_target++;),
        keep it and keep it close to the target function call.
        - If the compiler error suggests it is incorrectly placed (e.g., in an invalid scope),
        you may move it slightly, but it should still appear immediately before the target call.

        5) Fixing Function Signature or Argument Mismatch
        - When the compiler reports “too many arguments” / “too few arguments” / type mismatch:
        * Use the function signatures from the static analysis plan to correct the call.
        * Add, remove, or adjust arguments to match the real signature.
        * Prefer minimal changes that keep the intended data flow (doc/ctx/buffer) intact.

        6) Handling Missing Declarations / Headers
        - If a function, type, or macro is undeclared:
        * First, add the appropriate PUBLIC header (e.g., <libxml/parser.h>, <libxml/xmlreader.h>).
        * Use PUBLIC headers of the library, not private/internal headers whenever possible.
        - You may add forward declarations for structs or enums when necessary, but:
        * NEVER reimplement or stub any function whose name appears in the call chain or as the target.
        * Only stub small helper functions that are clearly NOT part of the analyzed call chain
            and NOT internal to the library (e.g., local utilities you own).

        7) Avoid Stubbing or Redefining Critical or Internal APIs
        - Do NOT define new functions that have the same name as existing library APIs or
        functions in the call chain (no shadowing / re-implementation).
        - Do NOT invent fake struct layouts to access internal fields of library types.
        - If an internal static function is missing and cannot be called directly, either:
        * replace it with a semantically similar PUBLIC API, OR
        * remove that single call and keep the rest of the chain intact,
            if there is no safe public replacement and keeping the call makes compilation impossible.

        8) Undeclared Variables or Types
        - If variables like ctx, doc, reader, schema, etc. are undeclared:
        * Infer their likely type and initialization pattern from the PLAN JSON and existing code.
        * Declare them with safe, minimal initializations consistent with typical usage.
        * Example:
            xmlDocPtr doc = xmlReadMemory(buffer, size, "fuzz.xml", NULL, XML_PARSE_RECOVER);
        - Do NOT introduce arbitrary complex logic; keep initialization simple and safe.

        9) Linker Errors (Undefined References)
        - If linking fails due to missing symbols:
        * Modify the compile command to include the correct library using pkg-config, e.g.:
            $(pkg-config --cflags --libs libxml-2.0)
        * You MAY append other standard libraries (-lm, -lz, -lpthread) only if they are clearly relevant.
        - Do NOT remove the function calls that cause the undefined references; fix the link line instead,
        unless those calls violate the internal/external rules above.

        10) Fuzzing Behavior Must Be Preserved
        - The harness MUST still:
        * read fuzz input from argv[1],
        * use a persistent loop (or its fallback),
        * pass fuzz-derived data into the library calls (doc/ctx/buffer/etc.).
        - Do NOT remove the main fuzzing loop, input reading, or all calls to the analyzed functions.

        11) Scope of Modifications
        - Only perform modifications that are necessary to make the code compile and link.
        - Do NOT perform large refactorings or rewrite the harness from scratch.
        - Keep your changes minimal, local, and logically consistent with the existing code
        and static analysis plan.

        ==================== OUTPUT FORMAT (STRICT JSON) ====================

        Return a single JSON object with exactly two properties:

        {
        "code": "<the corrected C/C++ fuzz harness code>",
        "compile_command": "<the corrected compile command>"
        }

        Constraints:
        - "code" must contain the FULL corrected harness (entire C/C++ source file).
        - Do NOT include Markdown, explanations, comments about your changes, or any extra fields.
        - Do NOT output anything other than this JSON object.
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

# CODE_GENERATE_PROMPT = """
#         You are an expert in fuzz testing, and you are testing an open-source library called %s.
#         Please write a fuzz harness that triggers the target function named "%s" in this library.

#         To help you generate a high-quality and semantically valid harness, here is a structured plan derived from static analysis and program understanding:
        
#         **
#         ATTENTION! Your primary task is to write an API that covers as many of the provided call chains as possible, \
#             while ensuring the logical soundness and usability of the entire fuzz driver so that fuzzers like AFLGO can fuzz to the target location more quickly.
#         **

#         === Static Analysis Data (JSON) ===
#         %s

#         This JSON object provides in-depth static analysis information, including:
#         - `chain`: a call chain from the root API to the target function (ordered from top-level to target);
#         - `nodes`: detailed function signatures, source locations, preconditions, required initialization patterns and SPECIFIC IMPLEMENTATION for each function in the chain;
#         - `resources`: allocation and release operations associated with each function;
#         - `lifecycle_plan`: alloc/free, init/cleanup steps that should be followed to maintain a valid program state;
#         - `bitmask_bundles` and `preconditions`: flag constraints, runtime checks, or conditional guards that may affect valid inputs;
#         - `harness_hint`: suggested default arguments, flag combinations, or parameter mapping inferred from analysis.

#         === Output Format Requirements (STRICT) ===
#         Return pure JSON with exactly two properties:
#         {
#         "code": "<the complete fuzz harness C source>",
#         "compile_command": "<the compile command>"
#         }
#         **ATTENTION! No Markdown, no extra text, just JSON.**

#         You must use this plan to reason about:
#         1. How to correctly initialize objects or structures before invoking the target function.
#         2. How to allocate and release resources following the `lifecycle_plan` and `resources` hints.
#         3. How to call **AS MANY FUNCTIONS from the CALL CHAIN AS POSSIBLE**, in order, with correct data dependencies.
#         4. Which parameters are influenced by fuzz input (buffers, sizes, configuration, file content).
#         5. How to propagate data/handles between chained calls (e.g., return values or pointers).

#         === Functional Requirements (STRICT) ===
#         1) Input:
#         - Read fuzz input from a file path provided at argv[1] (AFL/AFLGo @@).
#         - Allocate a buffer and read the entire file into memory.

#         2) Fuzzing Loop:
#         - Use a persistent loop: `while (__AFL_LOOP(10000)) { ... }`.

#         === Build Requirements (STRICT) ===
#         - The harness must compile using aflgo-clang/aflgo-clang++.
#         - The compile command format MUST be:
#             aflgo-clang -g -O2 a.c -o a.out $(pkg-config --cflags --libs XXX)
#         Replace `XXX` with the correct pkg-config name for the target library when it is known from the plan (e.g., `libxml-2.0`).
#         - The source file name MUST be `a.c`, and the output executable name MUST be `a.out`.

#         Checklist before you output:
#         - Reads input from argv[1] into a heap buffer.
#         - Includes all necessary headers (consider stdint.h, unistd.h, fcntl.h, sys/stat.h as needed).
#         - Uses memory-based APIs rather than file/network I/O when possible.
#         - When calling APIs, it is necessary to ensure the LOGICAL RATIONALITY of the entire program.
#         - Drives streaming/reader loops so that the target function is actually exercised.
#         - Satisfies required preconditions and cleans up all resources on all paths.
#         - Places the AFL target marker immediately before the target function call.
#         - Builds successfully with the specified compile command.
#         """


# HARNESS_FIX = """
#         You are a code repair expert. \
#         The code I give you had encountered some problems during compilation. \
#         The code that encountered the problem is as follows: \
#         %s \
#         The compile command last time you give me that I use to compile the code is as follows: \
#         %s \
#         The error message is: \
#         %s \
        
#         Now you need to modify the code or compile command I gave you to fix the problem it encountered. \
        
#         If there is a problem such as "No such file or directory" in the compilation error caused by the relevant library not being found, \
#         give priority to using tools such as pkg-config to repair the compilation command. \
        
#         When you finish the code or compile command modification, please give me the result. \
#         In the compile command you give, use a.c to refer to the code, and a.out to execution file,\
#         and make sure the compile command can compile the code successfully. \
        
#         **Your answer must be in a pure JSON format** without any Markdown. Just the raw JSON string (no Markdown formatting). 
#         **Do not return your answer in any other format like markdown format, only raw JSON as a plain text string.** \
        
#         Please ensure your response only contains:
#         {
#             "code": "<the generated C/C++ fuzz harness code>",
#             "compile_command": "<the compile command for the generated code>"
#         }
#         Your answer should be the raw JSON string, and should contain only these two properties, nothing else. No additional explanations, comments, or details.
# """

# ENTRY_POINT_FILTER = """
#         You are an expert in C/C++ library fuzz testing. You need to write some harnesses that can reach a target function %s in the %s library. \
#         Here is a list of all root node functions extracted from the tested library CG that may reach the target function : %s. \
#         You need to filter these functions to keep only those that may be worth writing harness tests for. \
        
#         Return only a JSON object with the following shape (no extra text): {"filtered_apis": ["funcA", "funcB", ...]}.\
#         **Your answer must be in a pure JSON format** without any Markdown. Just the raw JSON string (no Markdown formatting). 
#         **Do not return your answer in any other format like markdown format, only raw JSON as a plain text string.** \
        
#         In addition, your answer can ONLY be what I asked, no other explanatory content.
# """