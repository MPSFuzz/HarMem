# HarMem(aka, Auto Harness) — Directed Fuzzing Framework


## I. Framework Overall Execution Flow

All end-to-end configurations enter via `src.main` (`"module": "src.main"`).

### Entry Parameters (accepted by main.py)

| Parameter | Short | Meaning |
|---|---|---|
| `--lib_name` | `-l` | Target library name (e.g., lua, libtiff) |
| `--function-name` | `-f` | Target function name (or file path containing target function name) |
| `--project-path` | `-p` | Target project source code directory |
| `--dot-file` | `-d` | Call graph dot file (`.bc.callgraph.dot`) |
| `--compile-commands-path` | `-c` | compile_commands.json path |
| `--seeds-path` | `-s` | User-provided seed input directory (optional) |
| `--cve-hints-path` | `-ch` | CVE hints JSON file (optional) |

### Complete Execution Flow

```
main.py
  │
  ├─ 1. create_batch()
  │     │
  │     ├─ 1a. get_available_harness()            ← Harness generation
  │     │    │
  │     │    ├─ load_call_graph()                 Load call graph from .dot file
  │     │    ├─ get_target_func_location()        Locate which source file contains target function
  │     │    ├─ get_root_apis()                   Find all entry APIs that can reach target from call graph
  │     │    ├─ LLM.entry_api_filter()            LLM filters candidate entry APIs
  │     │    ├─ extract_target_call_chain()       Extract call chain for each root_api → target
  │     │    │
  │     │    ├─ aggregate_for_chain() (parallel)  ★ Phase A: Static analysis for each chain
  │     │    │    ├─ SignatureExtractor           Extract function signatures, parameter types
  │     │    │    ├─ BitmaskExtractor             Identify bitmask/flags parameters
  │     │    │    ├─ GuardExtractor               Extract guard conditions like if/switch
  │     │    │    ├─ ResourceExtractor            Identify malloc/free/open/close etc.
  │     │    │    └─ ImplementationExtractor      Extract function source code snippets
  │     │    │    → Aggregate into harness_plan (JSON)
  │     │    │
  │     │    └─ _process_root_api() (parallel)    ★ Phase B: LLM generates harness
  │     │         ├─ build_phase_A_context()      Build prompt from plan + call chain info
  │     │         ├─ LLM.generate_harness_skeleton()   LLM generates harness skeleton
  │     │         ├─ LLM.generate_code()          LLM generates complete C code
  │     │         ├─ harness.compile_test()       Compile test; LLM fixes on failure
  │     │         ├─ LLM.generate_dict()          Generate AFL dictionary
  │     │         └─ [Optional] cve_helper constraint injection + harness_analysis structural analysis
  │     │
  │     └─ 1b. Batch.save_metadata()              Persist batch metadata to batch_metadata/
  │
  └─ 2. EpochScheduler.run()
        │
        ├─ start_fuzzing()                        Start afl-fuzz process for each harness
        │
        └─ Main loop (every poll_sec=3s):
             │
             ├─ _collect_analyze()                Collect fuzzer_stats feedback
             │    ├─ parse_fuzzer_stats_file()    Parse execs_done, paths_total, etc.
             │    └─ analyze_fuzzer_feedback()    Analyze distance progress/coverage/crashes
             │
             ├─ Crash detection + auto-restart    Restart fuzzer processes if they die
             │
             └─ Two-phase adaptive upgrade:
                  
                  Phase COARSE (2-5 min):
                    ├─ Detect unstable_harness / very_low_coverage
                    └─ Unqualified → harness_upgrade_procedure()
                         ├─ filter_merged_compile_pass_metadata()   Collect runtime trace
                         ├─ get_aggregate_runtime_trace_information()  Analyze trace
                         ├─ LLM generates improvement prompt + iterative harness
                         └─ Re-enter COARSE phase after improvement
                  ↓
                  Phase FINE (10-30 min):
                    ├─ Detect distance_plateau (distance no longer shrinking)
                    └─ Trigger harness_upgrade or continue
```

---

## II. Key Design Principles

1. **Call Graph Driven**: Starting from the target's `.bc.callgraph.dot`, find all external API entry points that can reach the target, rather than manually specified entry points.

2. **LLM Involvement Throughout**: API filtering, harness skeleton generation, code generation, compilation repair, dictionary generation, and harness upgrades all rely on LLM (default model `deepseek-v4-flash`, compatible with OpenAI API).

3. **Two-Phase Fuzzing**:
   - **Coarse**: 2-5 minutes, quickly screen qualified harnesses, detect unstable/low coverage
   - **Fine**: 10-30 minutes, deep fuzzing, monitor distance convergence (distance plateau)

4. **Feedback Loop**: AFL runtime statistics → fuzzer_stats analysis → harness upgrade → re-fuzzing, iterating until conditions met or timeout.

5. **Static Analysis**: C code static analysis based on libclang, extracting function signatures, guard conditions, resource operations, bitmask parameters, etc., to build structured harness plans.

6. **AFLGo Integration** (`aflgo_components/`): Uses directed greybox fuzzing distance calculation and LLVM Pass instrumentation to guide fuzzer toward target basic blocks.

7. **CVE Assistance** (`cve_helper/`): Generate hints from CVE intelligence/user rules, inject into LLM prompts to provide targeted constraints.

8. **Runtime Trace Feedback**: Collect runtime data (which basic blocks were visited) through Pass instrumentation, analyze whether harness can effectively reach target function, guide subsequent upgrades.

---

## III. Project Directory Structure

```
auto_harness/
├── .vscode/                    # VS Code configuration (launch.json, settings.json)
├── src/
│   ├── main.py                 # Entry: harness generation + scheduling
│   ├── batch/                  # Batch management (metadata persistence, feedback collection)
│   ├── harness_class/          # Harness generation and upgrade
│   │   ├── gen_hanress.py      # LLM-driven harness generation
│   │   ├── harness_class.py    # Harness data structure
│   │   ├── harness_upgrade.py  # Feedback-driven iterative harness upgrade
│   │   └── harness_structural_refine.py  # Refinement after structural analysis
│   ├── static_analyze/         # libclang-based static analysis
│   │   ├── aggregator.py       # Aggregate all extractor outputs
│   │   ├── ccdb.py             # compile_commands.json parsing
│   │   ├── extract_call_chain.py # Call graph analysis
│   │   └── extractor/          # Various extractors
│   ├── llm/                    # LLM interface
│   │   ├── LLM_class.py        # OpenAI-compatible API wrapper
│   │   ├── LLM_prompt.py       # Prompt templates
│   │   └── build_phase_A_context.py  # Build Phase A context
│   ├── fuzz_components/        # Fuzzing components
│   │   ├── fuzz_runner.py      # AFL fuzzer launcher
│   │   ├── fuzz_feedback_parser.py  # AFL stats parsing
│   │   └── fuzzer_feed_back_analysis.py  # Feedback analysis
│   ├── scheduler/              # Scheduler
│   │   └── schedule_controller.py  # EpochScheduler main loop
│   ├── runtime_components/     # Runtime trace analysis
│   ├── cve_helper/             # CVE intelligence assistance
│   ├── harness_analysis/       # Harness structural analysis
│   ├── seed_generation/        # Seed generation
│   ├── aflgo_dev/              # AFLGo development debugging
│   └── utils/                  # Utility functions
├── aflgo_components/           # AFLGo distance calculation
├── aflgo/                      # AFLGo source (LLVM Pass, clang wrapper)
├── batch_metadata/             # Batch metadata storage
├── scripts/                    # Auxiliary scripts
└── temp/                       # Temporary files
```

---

## IV. Running Methods

### Method 1: VS Code Run and Debug

1. Ensure the `autoharness` conda environment is activated
2. In VS Code, select the Python interpreter: `/root/miniconda3/envs/autoharness/bin/python`
3. Press `Ctrl+Shift+D` to open the Run and Debug panel
4. Select a configuration from the dropdown (e.g., `harness_gen_main1`)
5. Click the green play button or press `F5`

### Method 2: Command Line

```bash
conda activate autoharness
cd ~/auto_harness

python -m src.main \
  -l lua \
  -f /root/experiment/targets_for_lua/target3.txt \
  -p /root/experiment/magma_lua/repo \
  -d /root/experiment/magma_lua/repo/fuzz_temp/lua.bc.callgraph.dot \
  -c /root/experiment/magma_lua/repo/compile_commands.json \
  -ch /root/temp/cve_rules/information/LUA003_hints.json \
  -s /root/experiment/seeds_for_experiment/LUA003/
```


ps: The contents of folder exp_data/plot-sta are the analysis results of the call chain in the harness, while those in folder exp_data/cve_repo are the reproductions of the CVEs.