from string import Template

SKELETON_GENERATE_PROMPT = """
        You are an expert C programmer and fuzzing practitioner.

        ATTENTION: Output Only JSON!!!
        You MUST strictly follow the output format requirements below:
        - Do NOT write any explanations.
        - Do NOT write markdown.
        - Do NOT write prose outside the JSON object.
        - Your entire reply MUST be a single valid JSON object and nothing else.

        We want to fuzz a library named {lib_name} using AFL/AFLGo.

        Below is a JSON context with static analysis information about a specific call chain and lifecycle hints extracted from the project:

        === STATIC CONTEXT (JSON) ===
        {phase_a_context}

        {cve_hints_block}

        Your task in THIS PHASE is NOT to implement the final bug-triggering logic in full detail.
        Your task is to design a reusable AFL/AFLGo fuzz harness SKELETON in C that will later be used to generate the final harness code.

        The skeleton must capture:
        1. The overall structure of main()
        2. Global initialization and cleanup
        3. The fuzzing loop
        4. Per-iteration parsing / object construction / cleanup
        5. The semantic input layout and object roles required to eventually reach the target API and the bug-relevant path
        6. A placeholder region where the concrete chain logic will be inserted later

        Important design goal:
        The skeleton is not only for generic API invocation.
        It must already preserve bug-relevant input structure if the CVE-aware constraints indicate that the bug depends on specific semantic input roles, parser objects, schemas, documents, contexts, flags, or object lifetimes.

        === General requirements on the harness skeleton ===

        1. The skeleton must be valid C code.

        2. It must include a standard AFL persistent loop with a safe fallback:

        #ifndef __AFL_LOOP
        static int __afl_once = 1;
        #define __AFL_LOOP(x) (__afl_once-- > 0)
        #endif

        3. It must read fuzz input from a file path given as argv[1], read the whole file into a heap buffer, and preserve both pointer and size.

        4. It must contain a main() like this in spirit:
        - check argc
        - perform global/library init if needed
        - enter AFL persistent loop
        - read fuzz input
        - build any per-iteration objects required by the bug model
        - @@CHAIN_LOGIC_BEGIN@@
        - placeholder for later concrete chain logic
        - @@CHAIN_LOGIC_END@@
        - per-iteration cleanup
        - final global cleanup

        5. The skeleton MUST NOT fully implement the final call-chain logic in this phase.
        Inside @@CHAIN_LOGIC_BEGIN@@ / @@CHAIN_LOGIC_END@@, only put placeholder comments or the minimum safe scaffolding needed to keep the structure coherent.

        6. The skeleton MUST NOT define any new functions whose names exactly match APIs in the call chain.
        Do not stub internal library APIs.

        7. If the bug depends on multiple semantic input roles, the skeleton MUST preserve those roles explicitly.
        For example:
        - schema vs instance document
        - control structure vs payload
        - context object vs input blob
        Do NOT collapse distinct semantic roles into one generic input object unless the provided constraints strongly justify that design.

        8. The skeleton should separate:
        - fixed components
        - fuzz-controlled components
        - hybrid components (fixed template + fuzz-controlled fields)

        9. Expensive and stable initialization should be placed outside the fuzz loop if safe.
        Per-input parsing and bug-triggering operations should stay inside the loop.

        10. The skeleton should include an AFLGo target marker placeholder near the future target API invocation site, for example:
            // AFLGo target marker will be inserted here before calling the target API
            // volatile int afl_target = 0; afl_target++;

        11. Prefer public / external APIs where such information is available.
        Do not directly call internal-only APIs from the skeleton unless they are actually callable public APIs according to the static context.

        === Output format (STRICT JSON) ===
        Return exactly one JSON object with this shape:

        {{
        "language": "C",
        "skeleton_code": "<complete C skeleton with @@CHAIN_LOGIC_BEGIN@@ and @@CHAIN_LOGIC_END@@ placeholders>",
        "compile_command_hint": "<plausible aflgo-clang compile command for this harness>",
        "input_layout_summary": {{
            "semantic_roles": ["<role1>", "<role2>"],
            "fixed_components": ["..."],
            "fuzz_components": ["..."],
            "hybrid_components": ["..."]
        }},
        "api_usage_snippets": [
            {{
            "api": "<API name>",
            "snippet": "<small realistic usage snippet in C>",
            "source_hint": "<tests/examples/docs/inferred>",
            "summary": "<1-3 sentences>"
            }}
        ],
        "doc_summaries": {{
            "<API name>": "<short documentation-style description>"
        }}
        }}
        """


CODE_GENERATE_PROMPT = Template("""
        You are an expert in fuzz testing and C programming.
        
        You are generating a vulnerability-oriented AFL/AFLGo harness for the open-source library ${lib_name}.
        
        The harness must drive the target API ${target_func} (ignoring suffixes such as __internal_alias after the function name) and maximize the practical chance of reaching the target bug point.
        This harness is for bug reproduction, not merely broad API coverage.
        
        IMPORTANT:
        - Mutated fuzz inputs must meaningfully influence control-flow and data-flow toward the bug-relevant path.
        - Do NOT produce a harness that trivially reaches the target independent of input.
        - Do NOT output explanations.
        - Your entire reply MUST be a single valid JSON object and nothing else.
        
        You are given:
        
        1) Source code of the target function
        2) Code snippets near the target bug point
        3) A static analysis plan
        4) A pre-generated skeleton JSON
        5) CVE-aware bug reproduction constraints (optional, may not be provided)
        
        ==================== Source Code of The Target Function ====================
        ```c
        ${target_function_source}
        ```

        ==================== Code Snippets of The Target Bug Point ====================

        ```
        ${bug_point_source_code_snippets}
        ```

        ==================== Static Analysis PLAN (JSON) ====================
        ${plan_json}
                                
        This plan may include:

        - chain.nodes
        - signatures
        - visibility information
        - resources
        - lifecycle hints
        - harness hints
        - external chain information

        ==================== SKELETON & API USAGE INFO (JSON) ====================
        ${skeleton_json}

        This skeleton JSON provides:

        - skeleton_code
        - compile_command_hint
        - input_layout_summary
        - api_usage_snippets
        - doc_summaries
        ==================== CVE(or bug) Hints ====================
        ${cve_hints_block}
        
        This block provide a structured summary of the CVE-aware(or bug) constraints relevant to the vulnerability, which include some essential aspects that the generated harness MUST follow to have a practical chance of reproducing the bug
        
        ==================== YOUR TASK ====================

        You MUST generate a COMPLETE, COMPILABLE harness in C or C++ in JSON form.

        You MUST start from the provided skeleton_code.

        Primary rule:

        - The skeleton already defines the overall driver structure.
        - Preserve the skeleton’s structure unless a very small local refinement is necessary for correctness.
        - The main goal is to fill in the concrete harness logic so the harness is aligned with the bug model.

        You MUST:

        1. Use the provided skeleton_code as the base harness.
        2. Keep global structure, AFL loop, argv[1] file reading, and outer init/cleanup patterns compatible with the skeleton.
        3. Replace or refine the @@CHAIN_LOGIC_BEGIN@@ / @@CHAIN_LOGIC_END@@ region with concrete bug-oriented chain logic.
        4. Eliminate unnecessary fallback checks and ensure that fuzz input covers the critical parts that affect vulnerability (or bug) triggering.
        5. Respect the static plan, but do NOT stop at generic API invocation.
        6. If CVE-aware constraints indicate multiple semantic input roles, preserve them in code.
        7. If the bug depends on specific schema constructs, parser options, object states, call ordering, or XPath/AST/format structure, implement those concretely.
        8. Treat bug-relevant deeper touchpoints as important internal reachability targets even if the externally callable target API is ${target_func}.

        External vs internal behavior:

        - Prefer public/external APIs for explicit calls from the harness.
        - Do NOT fabricate fake stubs for internal APIs.
        - Do NOT cast opaque pointers to made-up internal structs just to force reachability.
        - Internal-function information should be treated as guidance for preparing correct inputs and object states around public APIs.

        Target marker:

        - Immediately before the explicit call to the target API "${target_func}", insert:
        volatile int afl_target = 0;
        afl_target++;
        - Then perform the target API call.

        Fuzz influence requirements:

        - The fuzz input must influence meaningful values, structures, or parser decisions.
        - Avoid making the target path fully hardcoded and input-insensitive.
        - It is acceptable to use partially fixed templates if the bug model requires specific structure.
        - It is acceptable to derive multiple semantic objects from one input blob if that improves vulnerability reachability.

        Bug reproduction requirements:

        - This harness is for vulnerability reproduction, not only coverage.
        - It is NOT sufficient to merely call the target function with superficially valid inputs.
        - The generated code should reflect the bug-specific MUST / MUST AVOID constraints from the CVE hints whenever possible.
        - Do not add defensive logic that masks the bug.
        - If sanitizer-based observation is relevant, do not suppress the faulty behavior.

        Implementation requirements:

        - Include all required headers.
        - Include helper functions if necessary.
        - Ensure local resource cleanup is correct enough to keep fuzzing stable.
        - Keep the harness self-contained except for the target library and normal toolchain dependencies.
        ==================== BUILD REQUIREMENTS (STRICT) ====================

        - The final harness MUST be valid C code.
        - It MUST still read fuzz input from argv[1] (as implemented in the skeleton).
        - It MUST still use a persistent fuzzing loop: while (__AFL_LOOP(10000)) { ... }.
        - The compile command MUST follow the pattern :
            * use aflgo-clang (or afl-clang-fast/afl-clang) as the compiler,
            * refer to the harness file as a.c and the output as a.out, e.g.:

            aflgo-clang -g -O2 -fsanitize=address a.c -o a.out $$(pkg-config --cflags --libs XXX)

        Replace XXX with the correct pkg-config name for the target library (e.g., "libtiff-4" "libxml-2.0" "libpng" "lua")
        If you need to add sanitizer-related options like "-fsanitize=address, undefined", add them to the compilation command (but be aware of the availability of the compilation command,hat is, DO NOT add them if they are not necessary).
        if this can be inferred from the plan or skeleton; otherwise, give your best guess.

        ==================== OUTPUT FORMAT (STRICT JSON) ====================

        Return a single JSON object with exactly two properties:

        {{
        "code": "<the COMPLETE C source of the fuzz harness, based on skeleton_code, with the @@CHAIN_LOGIC@@ region filled in>",
        "compile_command": "<the compile command>"
        }}

        ATTENTION:
        - "code" MUST contain the full C source (not just the @@CHAIN_LOGIC@@ region).
        - Do NOT use Markdown formatting.
        - Do NOT include any extra fields or text outside this JSON object.
        """)


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
        * First, add the appropriate PUBLIC header.
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
        - Do NOT introduce arbitrary complex logic; keep initialization simple and safe.

        9) Linker Errors (Undefined References)
        - If linking fails due to missing symbols:
        * Modify the compile command to include the correct library using pkg-config, e.g.:
            $(pkg-config --cflags --libs libxml-2.0)
        * You MAY append other standard libraries (-lm, -lz, -lpthread) only if they are clearly relevant.
        - Do NOT remove the function calls that cause the undefined references; fix the link line instead,
        - If you need to add sanitizer-related options like "-fsanitize=address, undefined", add them to the compilation command (but be aware of the availability of the compilation command,hat is, DO NOT add them if they are not necessary).
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


DICT_GENERATE_PROMPT = """
        You are an expert in fuzzing (AFL / AFLGo) and input grammar design.

        Your task is to design a SMALL, TARGETED DICTIONARY (token list) to help AFL/AFLGo fuzz
        a harness for the C library "%s", focusing on driving a specific call chain
        towards the target function "%s".

        ==================== Static Analysis PLAN (JSON) ====================
        %s

        This JSON object describes:
        - "chain": the ordered call chain from root API to the target function.
        - "nodes": function signatures, implementation hints, resources and preconditions.
        - "edges": how arguments flow between functions (param_bindings, guards, etc.).
        - "lifecycle_plan": important allocation / free / init / cleanup steps.
        - "bitmask_bundles" and "harness_hint": flag / option combinations and parameter defaults.

        ==================== Harness Code (C) ====================
        %s

        This is the CURRENT fuzz harness code that:
        - reads fuzz input from a file (argv[1]),
        - parses it (often as some specific format, e.g., XML/JSON),
        - and calls the functions in the call chain, including the target "%s".

        ==================== YOUR GOAL ====================

        Design a SMALL dictionary of string tokens that will help AFL/AFLGo:
        - Quickly reach and explore the call chain
        - Trigger meaningful branches and preconditions in the PLAN and implementations.
        - Cover important options, attribute names, attribute values, type tags, protocol / URL fragments, etc.

        You SHOULD:
        - Look at:
        * string literals, attribute names, magic constants, enum-like values and prefixes
            visible in the PLAN and in the harness code (and, implicitly, in the implementations).
        * conditions that depend on certain keywords, attribute names, URLs, namespaces, IDs, etc.
        - Propose tokens that are useful as AFL dictionary entries, SUCH AS(adjust according to the actual fuzzing goals):
        * XML keywords and markup fragments (e.g., "<!DOCTYPE", "<xinclude", "xmlns", "xml:lang").
        * Attribute names (e.g., "id", "href", "lang", "system", "public").
        * Typical attribute values or type indicators (e.g., "SYSTEM", "PUBLIC", "catalog", "rewriteSystem").
        * Common protocol / URL prefixes or path fragments (e.g., "file://", "http://", "/etc/xml/catalog").
        * Any short strings that are likely to trigger different code paths in the chain.

        You MUST:
        - Focus on tokens that are relevant for THIS harness and THIS call chain.
        - Prefer a small but high-quality set of tokens (for example, 16–64 items).
        - Avoid extremely generic junk like "a", "foo", "test", "123" unless they really matter.
        - Ensure the generated dictionary content is encoded correctly to avoid errors like "Invalid escaping (some illegal character) in line 1" generated by fuzzers such as AFL.

        ==================== OUTPUT FORMAT (STRICT JSON) ====================

        Return a SINGLE JSON object of the form:

        {
        "tokens": [
            {
            "value": "<one AFL dictionary token string>",
            "kind": "<one of: keyword | attr_name | attr_value | url | flag | other>",
            "weight_hint": <integer 1..5, higher means more important>,
            "note": "<very short note why this token is useful for this harness>"
            },
            ...
        ]
        }

        Constraints:
        - "tokens" MUST be an array. It MAY be empty if you truly see nothing useful (try to avoid that).
        - Each "value" MUST be a single string WITHOUT newlines.
        - Do NOT include surrounding quotes in "value"; just the raw token content.
        - Do NOT output Markdown.
        - Do NOT output anything outside that single JSON object.
        """

PHASED_FEEDBACK_IMPROVE_PROMPT = """
        You are an expert in fuzzing, C/C++ programming, and AFLGo-directed fuzzing.

        In THIS PHASE, your job is NOT to write a new harness from scratch,
        but to IMPROVE an existing harness using runtime fuzzing feedback.

        You will receive:

        1) A STATIC ANALYSIS PLAN (JSON) describing the call chain and target function.
        2) The CURRENT HARNESS CODE (C/C++) that already compiles and runs.
        3) FUZZER_STATS (parsed from AFL/AFLGo's fuzzer_stats file).
        4) An ANALYSIS_RESULT object summarizing issues and hints extracted from fuzzer_stats.

        Your goal is to:
        - Keep the existing harness structure and intent.
        - Make MINIMAL, TARGETED changes that improve coverage, distance progression, and harness robustness.
        - Prefer editing the call-chain logic region between @@CHAIN_LOGIC_BEGIN@@ and @@CHAIN_LOGIC_END@@.
        - Output an UPDATED harness and a plausible compile command.

        ==================== STATIC ANALYSIS PLAN (JSON) ====================
        %s

        This JSON object contains:

        - "chain": ordered call chain from root API to target function.
        - "nodes": function signatures, files, locations, preconditions, resources, and implementation snippets.
        - "lifecycle_plan": important alloc/free, init/cleanup patterns.
        - "bitmask_bundles": flag / option constraints.
        - "externals": external functions and APIs that may need extra linking or initialization.
        - "harness_hint": suggested default arguments, flag combinations, or parameter mappings.

        Use this plan to understand:
        - Which functions should be called, and in what order.
        - Which arguments must be non-NULL, initialized, or set to safe values.
        - How resources should be allocated and freed.

        ==================== CURRENT HARNESS CODE ====================
        %s

        This is the current C/C++ fuzz harness. It already:

        - Defines main().
        - Reads fuzz input from a file path in argv[1].
        - Uses a persistent AFL/AFLGo loop with a __AFL_LOOP fallback macro.
        - Contains a dedicated region for call-chain logic, delimited by:

            @@CHAIN_LOGIC_BEGIN@@
                // call-chain logic lives here
            @@CHAIN_LOGIC_END@@

        You MUST treat this harness as the base. You are allowed to improve it,
        but you MUST NOT discard it and rewrite everything from scratch.

        ==================== FUZZING RUNTIME FEEDBACK: fuzzer_stats (JSON) ====================
        %s

        This is a JSON object parsed from AFL/AFLGo's fuzzer_stats file.
        It typically includes fields like:

        - start_time, last_update, execs_done, execs_per_sec
        - paths_total, paths_favored, pending_total, max_depth
        - bitmap_cvg, stability, unique_crashes, unique_hangs
        - cur_distance, max_distance, min_distance
        - command_line, afl_version, target_mode

        Use this to understand how the current harness is performing:
        - Is coverage low?
        - Is the current distance far from the target?
        - Is there any progress (min_distance decreasing) over time?
        - Is the fuzzing stable or frequently crashing?

        ==================== FUZZING RUNTIME FEEDBACK: analysis_result (JSON) ====================
        %s

        This JSON object summarizes your fuzzer_stats in a more semantic way. It contains, for example:

        - "summary": short natural-language description of harness performance.
        - "issues": a list of high-level issues, such as:
            - "very_low_coverage"
            - "no_distance_progress"
            - "distance_not_improving"
            - "shallow_paths"
            - "frequent_crashes"
            - "low_exec_speed"
            - "no_input_dependency"
        - "hints": a list of recommended actions, such as:
            - "increase_call_chain_coverage"
            - "let_fuzz_input_influence_more_arguments"
            - "relax_overly_strict_precondition_checks"
            - "add_safety_checks_to_avoid_harness_crashes"
            - "ensure_target_function_is_reached"
        - Additional numeric fields like:
            - "coverage_level", "distance_quality", "stability_level", the number indicates the status, and higher is better(maximum is 1).

        You MUST use these issues and hints to guide your modifications.

        ==================== STRICT RULES FOR IMPROVING THE HARNESS ====================

        1) DO NOT REWRITE FROM SCRATCH

        - You MUST treat the current harness as the base.
        - You MUST NOT discard the existing structure and generate a completely new harness.
        - You MUST preserve:
        * the __AFL_LOOP macro and how it is used,
        * how argv[1] is read and the fuzz input buffer is allocated,
        * the overall shape of main(),
        * existing global initialization / cleanup calls (e.g., xmlInitParser / xmlCleanupParser),
        * the persistent fuzzing loop: while (__AFL_LOOP(10000)) { ... }.

        - Outside of @@CHAIN_LOGIC_BEGIN@@ / @@CHAIN_LOGIC_END@@:
        * You SHOULD keep changes minimal.
        * Allowed small changes:
            - adding #include directives,
            - adding simple typedefs or forward declarations,
            - adding small helper local variables,
            - very minor adjustments needed to keep the harness compiling.
        * You MUST NOT radically restructure main(), remove the AFL loop, or change input handling.

        2) PRIMARY EDIT REGION: @@CHAIN_LOGIC_BEGIN@@ / @@CHAIN_LOGIC_END@@

        - Your main modifications SHOULD be inside this region.
        - In this region, you MAY:
        * change control flow,
        * add or remove calls to functions,
        * add additional checks to satisfy preconditions,
        * adjust resource lifetimes and cleanup logic,
        * use more of the call chain from "plan.chain".

        - You MUST:
        * Keep the AFLGo target marker (volatile int afl_target = 0; afl_target++;)
            immediately before the call to the target function.
        * Make sure fuzz input (buffer and size read from argv[1]) meaningfully influences:
            - parsed documents / contexts,
            - important arguments,
            - configuration / options when appropriate.

        3) RESPECT THE CALL CHAIN AND TARGET FUNCTION

        - The plan describes a chain from root API to the target function (e.g. xmlNodeGetContent).
        - You MUST try to call as many functions in this chain as possible in logical order.
        - Use "nodes" and "lifecycle_plan" to:
        * pass objects (doc, ctx, node, reader, etc.) from one function to the next,
        * allocate and free resources in a safe, consistent way,
        * respect preconditions (non-NULL pointers, required flags, etc.).

        - You MUST NOT:
        * rename functions in the chain,
        * define new functions with the same names as existing library APIs,
        * stub or reimplement internal APIs from the library.

        4) USE RUNTIME FEEDBACK TO GUIDE IMPROVEMENTS

        Based on fuzzer_stats and analysis_result:

        - If coverage is very low or there is no distance progress:
        * Reduce overly strict early exits in the chain logic.
        * Ensure that even malformed inputs can still exercise a meaningful code path,
            for example by:
            - constructing fallback objects when parsing fails,
            - creating minimal valid nodes/documents,
            - not returning too early before reaching the call chain.

        - If max_depth is small or paths are shallow:
        * Consider walking more of the parsed structure:
            - iterate over children / attributes,
            - create or traverse additional nodes,
            - call additional APIs from the chain where safe.

        - If distance is not improving (cur_distance ~ max_distance):
        * Make sure the target function is actually reachable.
        * Ensure that:
            - the AFLGo target marker is placed just before the target call,
            - the call chain is executed (not skipped due to conditions),
            - arguments to the target are non-NULL and realistically initialized.

        - If stability is low or there are frequent crashes:
        * Add harness-side safety checks:
            - check for NULL pointers before dereferencing,
            - ensure sizes / lengths are reasonable,
            - avoid undefined behavior like use-after-free or double free in the harness.
        * IMPORTANT: You can add such checks in the chain logic region to protect the harness,
            but you MUST NOT hide or bypass real library bugs in the target library.

        5) DO NOT STUB OR REDEFINE LIBRARY APIs

        - You MUST NOT:
        * define new functions with the same names as functions in the call chain,
        * create fake implementations of library functions that should come from the real library.

        - If a function is internal and cannot be called from the harness:
        * Prefer using a closely related PUBLIC API instead.
        * Or skip that particular internal step while keeping the rest of the chain intact.

        6) COMPILE COMMAND REQUIREMENTS

        - You MUST output a plausible compile command string that builds the harness into a single binary.
        - The compile command MUST:
        * use aflgo-clang (or afl-clang-fast/afl-clang) as the compiler,
        * refer to the harness file as a.c and the output as a.out, e.g.:

            aflgo-clang -g -O2 a.c -o a.out $(pkg-config --cflags --libs XXX)

        - If you need to add sanitizer-related options like "-fsanitize=address, undefined", add them to the compilation command (but be aware of the availability of the compilation command,hat is, DO NOT add them if they are not necessary).
        - Choose the pkg-config name based on the plan and headers used.
        * If unsure, pick the most reasonable guess based on headers and plan.

        - Do NOT introduce makefiles or multiple compile steps.
        - The compile command MUST be a single shell command line.

        ==================== OUTPUT FORMAT (STRICT JSON) ====================

        You MUST return a single JSON object with EXACTLY two properties:

        {
        "code": "<the FULL updated C/C++ fuzz harness code>",
        "compile_command": "<a single shell command to compile this harness (using a.c and a.out)>"
        }

        Constraints:

        - "code" MUST contain the COMPLETE source code (not just the @@CHAIN_LOGIC@@ region).
        - "compile_command" MUST be a single command string as described above.
        - DO NOT include Markdown, explanations, comments about your changes, or any extra fields.
        - DO NOT output anything other than this JSON object.
        """

CVE_RULES_GENERATE_PROMPT = """
        You are helping build structured reproduction priors for vulnerability reproduction automation.

        Return ONLY a single JSON object (NO markdown, NO extra text) with EXACTLY one top-level key: "%s".

        The value must be a CVE rule entry for cve_rules.json with the following fields:
        {
            "lib_name": "<string or empty>",
            "target_func": "<string or empty>",
            "bug_class": "<one of: unknown|null_deref|uaf|oob_read|oob_write|overflow|assert|other>",
            "must_contain": ["..."],
            "must_avoid": ["..."],
            "encourage": ["..."],
            "input_model": {
                "layout": "<string, e.g. pattern|xml|flags|other>",
                "critical_fields": ["<field1>", "<field2>"],
                "pattern_kind": "<text|bytes|unknown>",
                "templates": ["..."],
                "mutation_knobs": ["..."]
            },
            "repro_oracle": {
                "signal": ["crash", "asan_segv", "null_deref", "..."],
                "differential": <true|false>
            },
            "touchpoints": {
                "files": ["..."],
                "functions": ["..."],
                "tokens": ["..."]
            },
            "notes": "<short>"
        }

        Rules:
        - Do NOT invent facts not supported by intel. If unsure, keep conservative/empty.
        - Prefer actionable constraints only if clearly supported.
        - templates should be short and representative (0..12 items), may be empty.

        Context:
        - cve_id: %s
        - lib_name: %s
        - target_func: %s

        INTEL (patch/advisory/poc/notes):
        %s
        """

STRUCTURAL_REFINE_PROMPT = Template("""
        You are an expert in fuzz harness engineering for vulnerability reproduction.

        Your task is to perform a LIMITED structural refinement of an existing harness before fuzzing begins.

        **The harnesses provided below are designed to reproduce a specific cve or bug.**

        IMPORTANT:

        - Do NOT rewrite the harness from scratch.
        - Do NOT redesign the overall input model unless explicitly allowed.
        - Do NOT remove the target API call.
        - Do NOT collapse semantic roles that must be preserved.
        - Do NOT output explanations.
        - Your entire reply MUST be a single valid JSON object and nothing else.

        ==================== Existing Harness ====================

        ${harness_code}

        ==================== CVE(or bug) Hints (the harness wants to reproduce) ====================

        ${cve_hints_obj}

        ==================== Phase-A Context ====================
        ${phase_a_context_json}

        ==================== Structural Guidance ====================
        ${guidance_json}


        ==================== Task ====================

        You must apply a conservative, localized structural repair.

        Goals:

        1. Preserve the high-value properties listed under "preserve".
        2. Avoid or reduce the risks listed under "avoid".
        3. Apply only the localized changes listed under "adjust".
        4. Respect all "do_not_touch" constraints.
        5. Only act on issues that are marked as repairable and have medium/high confidence.
        6. Prefer reducing over-heavy fallback / fixed-template masking over changing the high-level architecture.
        7. Preserve target data dependency.
        8. Preserve semantic role separation when present.

        You MAY:

        - Eliminate unnecessary fallback checks and ensure that fuzz input covers the critical parts that affect vulnerability (or bug) triggering.
        - reduce excessive fixed-template substitution
        - strengthen input influence on objects that reach the target call
        - make local structural edits near parsing/build/target-invocation logic

        You MUST NOT:

        - rewrite the entire harness
        - replace the current semantic layout with a completely different one
        - remove the fuzz loop
        - remove the target API call
        - erase bug-relevant object construction paths

        ==================== Output format ====================
        Return exactly one JSON object(ONLY the JSON, no markdown, no explanations) with exactly two fields:
        {
        "code": "<refined complete harness source code>",
        "compile_command": "<compile command>"
        }
                                    
        - The compile command MUST follow the pattern :
            * use aflgo-clang (or afl-clang-fast/afl-clang) as the compiler,
            * refer to the harness file as a.c and the output as a.out, e.g.:

            aflgo-clang -g -O2 a.c -o a.out $$(pkg-config --cflags --libs XXX)
            Replace XXX with the correct pkg-config name for the target library (e.g., "libxml-2.0")
    """)



# CODE_GENERATE_PROMPT = """
#         You are an expert in fuzz testing and C programming, and you are testing an open-source library called %s.
#         Your goal is to generate a high-quality AFL/AFLGo fuzz harness that triggers the target function named "%s" and reaches the target bug point. The purpose of this harness is to verify and reproduce a specific bug(or vulnerability) within this library through fuzzing.
#         IMPORTANT: The harness should be fuzzable: mutated fuzz inputs must meaningfully influence control-flow and data reaching the bug point. Avoid harness logic that trivially forces reachability independent of input.

#         In THIS PHASE, you MUST NOT write the harness from scratch.
#         Instead, you are given:

#         1) Source code of the target function and snippets of the target bug point.
#         2) A detailed static analysis PLAN (JSON) for the target call chain.
#         3) A pre-generated SKELETON (JSON) that already contains:
#         - a complete C fuzz driver skeleton,
#         - AFL/AFLGo loop and file-input handling,
#         - and a placeholder region marked by:
#             @@CHAIN_LOGIC_BEGIN@@
#                 // chain logic to be generated here
#             @@CHAIN_LOGIC_END@@

#         Your task is to:
#         - Start from the given skeleton_code.
#         - ONLY replace the code between @@CHAIN_LOGIC_BEGIN@@ and @@CHAIN_LOGIC_END@@.
#         - Keep EVERYTHING outside that region unchanged (includes, main(), __AFL_LOOP fallback, file reading, init/cleanup patterns, etc.).
#         - Inside the placeholder region, implement the call-chain logic that uses as many functions in the call chain as possible
#         and correctly calls the target function.

#         ==================== Source Code of The Target Function ====================
#         ```c
#         %s
#         ```

#         ==================== Code Snippets of The Target Bug Point ====================
#         ```text
#         %s
#         ```

#         ==================== Static Analysis PLAN (JSON) ====================
#         %s

#         This JSON object provides:
#         - "chain": a call chain from the root API to the target function (ordered from top-level to target).
#         - "nodes": detailed function signatures, source locations, preconditions, required initialization patterns and specific implementation hints.
#         - Each node may have a "visibility" field:
#             * "external": safe to call from a harness.
#             * "internal": static or internal helper; MUST NOT be called directly from the harness.
#         - "external_chain": an ordered list of external APIs that should be preferred as the explicit call sequence in the harness.
#         - "resources": allocation and release operations associated with each function.
#         - "lifecycle_plan": alloc/free, init/cleanup steps that should be followed to maintain a valid program state.
#         - "bitmask_bundles" and "preconditions": flag constraints, runtime checks, or conditional guards that may affect valid inputs.
#         - "harness_hint": suggested default arguments, flag combinations, or parameter mappings.

#         ==================== SKELETON & API USAGE INFO (JSON) ====================
#         %s

#         This JSON object provides:
#         - "skeleton_code": a complete C fuzz driver that:
#             * defines main(),
#             * reads fuzz input from argv[1] into a heap buffer,
#             * contains a persistent AFL loop with a safe fallback,
#             * and has @@CHAIN_LOGIC_BEGIN@@ / @@CHAIN_LOGIC_END@@ placeholders.
#         - "compile_command_hint": a plausible aflgo-clang compile command template.
#         - "api_usage_snippets": realistic C usage examples for each API in the call chain.
#         - "doc_summaries": short documentation-style descriptions for each API.

#         ==================== YOUR TASK (STRICT) ====================

#         You MUST:

#         1. Use the skeleton_code as the base.
#         - Do NOT change:
#             * the __AFL_LOOP fallback macro,
#             * the way argv[1] is read and the buffer is allocated,
#             * the overall structure of main(),
#             * global init/cleanup patterns that are already present (e.g., xmlInitParser/xmlCleanupParser),
#             * error-handling and cleanup code outside the placeholder region.

#         2. ONLY modify the code between:
#         @@CHAIN_LOGIC_BEGIN@@
#         @@CHAIN_LOGIC_END@@

#         - Replace the placeholder comments with concrete C code that:
#             * follows the call chain in "chain" (from root to target) as much as possible,
#             * uses functions in "external_chain" as the primary explicit call sequence,
#             * respects the function signatures and preconditions in "nodes",
#             * respects resource usage in "resources" and "lifecycle_plan",
#             * uses realistic patterns from "api_usage_snippets" when calling each API.
#         - You MAY declare local variables inside this region if needed.
#         - You MUST NOT redefine any functions whose names appear in the call chain.

#         3. External vs internal APIs:
#         - You MAY ONLY call functions that satisfy at least one of:
#             * they appear in "external_chain", OR
#             * the corresponding node has visibility == "external".
#         - For any node whose visibility == "internal":
#             * DO NOT call it directly from the harness.
#             * DO NOT declare a prototype or stub with the same name.
#             * Treat its "preconditions" and implementation hints as constraints on how
#                 to prepare arguments for surrounding external APIs.

#         - You MUST NOT:
#             * create fake stubs for internal/static functions in order to make calls compile;
#             * cast opaque library context pointers to custom structs just to access internal fields.

#         4. Target function and AFLGo marker:
#         - Identify the target function "%s" in the call chain.
#         - Immediately BEFORE the line that calls the target function, insert the AFLGo marker, for example:

#             volatile int afl_target = 0;
#             afl_target++;

#         - Then call the target function using correctly prepared arguments (derived from earlier steps in the chain).

#         5. Call chain coverage:
#         - Attempt to call as MANY functions from the call chain as possible in logical order.
#         - Prefer to follow the order given by "external_chain" for explicit calls.
#         - Use the static analysis plan to propagate objects/handles between calls:
#             * e.g., a doc or context created earlier should be reused by later APIs in the chain.
#         - Use "bitmask_bundles" and "harness_hint.param_defaults" to choose reasonable default flags/options,
#             while still allowing fuzz input to influence buffers, lengths, and sometimes options.

#         6. Fuzz input influence:
#         - Place operations like fopen outside the __AFL_LOOP loop, not inside it, to avoid slowing down the process.
#         - Ensure that fuzz input (the buffer read from argv[1] and its size) meaningfully influences:
#             * the data parsed into the library (e.g., XML/JSON/text),
#             * or configuration / options where appropriate.
#         - Do NOT ignore the fuzz buffer; it should flow into the library through the root/early APIs.

#         7. Safety & cleanup:
#         - Do NOT introduce printf/logging; focus on consuming fuzz input and driving the call chain.
#         - Do NOT introduce network I/O.
#         - Ensure all resources allocated in the chain-logic region are properly released before leaving the loop iteration,
#             following "resources" and "lifecycle_plan" (e.g., free docs, contexts, buffers, validators).

#         ==================== BUILD REQUIREMENTS (STRICT) ====================

#         - The final harness MUST be valid C code.
#         - It MUST still read fuzz input from argv[1] (as implemented in the skeleton).
#         - It MUST still use a persistent fuzzing loop: while (__AFL_LOOP(10000)) { ... }.
#         - The compile command MUST follow the pattern:

#             aflgo-clang -g -O2 a.c -o a.out $(pkg-config --cflags --libs XXX)

#         Replace XXX with the correct pkg-config name for the target library (e.g., "libxml-2.0")
#         If you need to add sanitizer-related options like "-fsanitize=address, undefined", add them to the compilation command (but be aware of the availability of the compilation command,hat is, DO NOT add them if they are not necessary).
#         if this can be inferred from the plan or skeleton; otherwise, give your best guess.

#         ==================== OUTPUT FORMAT (STRICT JSON) ====================

#         Return a single JSON object with exactly two properties:

#         {
#         "code": "<the COMPLETE C source of the fuzz harness, based on skeleton_code, with the @@CHAIN_LOGIC@@ region filled in>",
#         "compile_command": "<the compile command>"
#         }

#         ATTENTION:
#         - "code" MUST contain the full C source (not just the @@CHAIN_LOGIC@@ region).
#         - Do NOT use Markdown formatting.
#         - Do NOT include any extra fields or text outside this JSON object.
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


        # ==================== Static Analysis Data (JSON) ====================
        # %s

        # The static analysis plan may include:
        # - chain: ordered call chain from root API to target.
        # - nodes: each node has name, signature, preconditions, and possibly "visibility":
        #     * "external": safe to call from a harness.
        #     * "internal": static/internal helper; MUST NOT be called directly from the harness.
        # - external_chain: preferred sequence of external APIs.
        # - resources, lifecycle_plan, bitmask_bundles, harness_hint, etc.