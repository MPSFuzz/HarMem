# Auto Harness Full Workflow: From CVE Description to Directed Fuzzing

This document describes the complete workflow for using auto_harness to perform directed fuzzing on a new target library.

## Prerequisites

- The `autoharness` conda environment is activated
- The source code of the target library has been cloned locally
- The LLVM toolchain is available (`opt`, `llvm-config`, etc.)
- AFLGo's `aflgo-clang`, `aflgo-pass.so`, `distance.bin` have been compiled and are ready
- The trace instrumentation components have been compiled (`TraceInstrumentationPass.so` and `trace_runtime.a` under `src/runtime_components/trace_fn_instrument/`)

---

## Workflow Overview

```
┌─────────────────────────────────────────────────────────────┐
│  0. Prepare CVE hints                                       │
├─────────────────────────────────────────────────────────────┤
│  1. First compilation: generate bitcode (.bc) + CFG dot + CG dot
│  2. Specify target basic blocks → BBtargets.txt             │
│  3. Compute distances → gen_distance_fast.py → distance.cfg.txt
│  4. Second compilation: inject distance info with -distance flag (AFLGo instrumentation)
│  4b. Third compilation: instrument with TraceInstrumentationPass (trace build library)
│  5. Generate compile_commands.json                          │
│  6. Start auto_harness → harness generation + directed fuzz  │
└─────────────────────────────────────────────────────────────┘
```

> **Note**: Steps 1-5 are manual prerequisite steps; step 6 is done automatically by auto_harness. Step 4b is optional, but if skipped, the scheduler's automatic harness upgrade feature will degrade to coarse-grained analysis based only on fuzzer_stats (no runtime trace feedback).

---

## Step 0: Prepare CVE Hints

When you only have a rough CVE description, turn the intelligence into a structured `cve_hints.json`.

### Option A: Hand-write hints.json (recommended, fast)

Extract key information from the CVE description and write it directly:

```json
{
  "cve_id": "CVE-2025-xxxxx",
  "lib_name": "mylib",
  "target_func": "parse_header",
  "bug_class": "buffer_overflow",
  "touchpoints": {
    "files": ["parser.c"],
    "functions": ["parse_header", "read_chunk"],
    "tokens": ["chunk_size", "data_len"]
  },
  "must_contain": ["memcpy", "alloca"],
  "must_avoid": ["size_check"],
  "encourage": ["oversized_chunk"],
  "input_model": {
    "layout": "binary",
    "pattern_kind": "bytes",
    "templates": ["magic:00 FF", "length_field:uint32"],
    "mutation_knobs": ["length_field"]
  },
  "repro_oracle": {
    "signal": ["crash", "asan"]
  }
}
```

**Field descriptions**:

| Field | Meaning |
|------|------|
| `target_func` | Name of the vulnerability function mentioned in the CVE description (required) |
| `touchpoints` | Involved source files, related functions, key tokens |
| `must_contain` | API calls or code patterns that must be included in the harness |
| `must_avoid` | Calls that must be avoided in the harness |
| `input_model` | Rough format of the input file (binary/text, magic bytes, etc.) |
| `repro_oracle` | Evidence of vulnerability reproduction (crash / asan / ubsan, etc.) |
| `bug_class` | Vulnerability type (buffer_overflow / use_after_free / ...) |

### Option B: LLM auto-generation

Suitable for scenarios with raw intelligence such as patches (patch diff), security advisories, PoC scripts, etc.

Create an intel file `my_cve_intel.txt`:

```
CVE_ID: CVE-2025-xxxxx
LIB_NAME: mylib
TARGET_FUNC: parse_header

=== PATCH ===
(diff or patch content)

=== ADVISORY ===
(original security advisory text)

=== POC ===
(public PoC or trigger sample)

=== EXTRA ===
(other information: trigger conditions, call stack, etc.)
```

Run cve_helper to auto-generate:

```bash
python -m src.cve_helper.cli \
  --intel /path/to/my_cve_intel.txt \
  --out /path/to/my_cve_hints.json
```

---

## Step 1: First Compilation — Generate bitcode and CFG / CG

Use AFLGo's clang to compile the target library, generating LLVM bitcode (`.bc`) and control-flow-graph dot files.

### 1a. Compile to generate bitcode

```bash
cd /path/to/mylib

# Clean
make clean 2>/dev/null || true

# Set AFLGo path
export AFLGO=/root/auto_harness/aflgo

# Compile with aflgo-clang
CC=/root/auto_harness/aflgo_components/instrument/aflgo-clang \
CXX=/root/auto_harness/aflgo_components/instrument/aflgo-clang++ \
  ./configure --prefix=/path/to/mylib/build

make -j$(nproc)
make install
```

Example compilation artifacts:
```
/path/to/mylib/build/lib/
├── libmylib.so.x.y.z         # shared library (instrumented)
├── libmylib.so.x.y.z.bc     # LLVM bitcode (for analysis)
└── temp/dot-files/
    ├── cfg.parse_header.dot  # CFG of parse_header
    ├── cfg.read_chunk.dot    # CFG of read_chunk
    └── ...
```

### 1b. Generate the call graph (Call Graph dot)

```bash
BC_FILE=$(ls /path/to/mylib/build/lib/*.bc | head -1)

opt -dot-callgraph -enable-new-pm=0 "$BC_FILE" -o /dev/null

# Output file: libmylib.so.x.y.z.bc.callgraph.dot
```

### 1c. Copy CFG dot files to a unified location

```bash
mkdir -p /path/to/mylib/build/temp/dot-files

# Find the cfg.*.dot generated during compilation and copy them
find /path/to/mylib/build -name "cfg.*.dot" \
  -exec cp {} /path/to/mylib/build/temp/dot-files/ \;
```

---

## Step 2: Specify Target Basic Blocks

AFLGo needs to know which basic blocks are the targets of directed fuzzing. You need to extract basic block labels from the CFG dot file of the target function.

### 2a. Find the CFG dot file of the target function

```bash
ls /path/to/mylib/build/temp/dot-files/cfg.parse_header.dot
```

### 2b. Prepare the target list file

Create `BBtargets.txt`, one target basic block label per line:

```bash
cat > /path/to/mylib/build/temp/BBtargets.txt << 'EOF'
%11
%23
EOF
```

> **How to get basic block labels**: Open the CFG dot file of the target function (`cfg.parse_header.dot`) and look at the Node label names. You can also use LLVM's `opt -dot-cfg` to generate the CFG of a single function separately to help locate them.

Also prepare `BBnames.txt` and `BBcalls.txt`:

```bash
# BBnames.txt: name of each basic block, in the format "label\tfunction_name"
# Extract from the CFG dot file
cat > /path/to/mylib/build/temp/BBnames.txt << 'EOF'
%0	parse_header
%11	parse_header
%23	parse_header
EOF

# BBcalls.txt: which function each basic block calls, in the format "BB_label\tcalled_function"
cat > /path/to/mylib/build/temp/BBcalls.txt << 'EOF'
%11	read_chunk
EOF

# Fnames.txt: list of function names
cat > /path/to/mylib/build/temp/Fnames.txt << 'EOF'
parse_header
read_chunk
EOF

# Ftargets.txt: target function names (corresponding to BBtargets)
cat > /path/to/mylib/build/temp/Ftargets.txt << 'EOF'
parse_header
EOF
```

---

## Step 3: Compute Distances — `gen_distance_fast.py`

This step computes the distance from each basic block to the target block on the call graph (CG) and control-flow graph (CFG).

```bash
python /root/auto_harness/aflgo_components/gen_distance/gen_distance_fast.py \
  /path/to/mylib/build/lib \                                 # binaries_directory (stores .bc files)
  /path/to/mylib/build/temp \                                # temporary_directory (stores targets files)
  --skip-cg \                                                 # skip CG generation (already generated manually in step 1b)
  --cfg-glob-format "cfg.*.dot" \
  --callgraph-path /path/to/mylib/build/lib/libmylib.so.x.y.z.bc.callgraph.dot \
  --cfg-dot-files-path /path/to/mylib/build/temp/dot-files/
```

**Argument descriptions**:

| Argument | Meaning |
|------|------|
| `binaries_directory` | Directory containing the `.bc` files |
| `temporary_directory` | Directory containing `BBtargets.txt`, `BBnames.txt`, `BBcalls.txt`, etc. |
| `--skip-cg` | Skip call graph generation (already done manually) |
| `--cfg-glob-format` | Glob matching pattern for CFG dot files |
| `--callgraph-path` | Path to the call graph dot file |
| `--cfg-dot-files-path` | Directory where the CFG dot files are located |

**Artifact**: `/path/to/mylib/build/temp/distance.cfg.txt`

Content format:
```
BB_label1,distance_1
BB_label2,distance_2
...
```

When the script finishes, it prints to the terminal the command template needed for the subsequent compilation.

---

## Step 4: Second Compilation — Inject Distance Information

After cleaning, recompile the target library with the compile command carrying the `-distance` flag.

```bash
cd /path/to/mylib

make clean

DISTANCE_CFG=$(readlink -f /path/to/mylib/build/temp/distance.cfg.txt)

CC=/root/auto_harness/aflgo_components/instrument/aflgo-clang \
CXX=/root/auto_harness/aflgo_components/instrument/aflgo-clang++ \
CFLAGS="-distance=$DISTANCE_CFG" \
CXXFLAGS="-distance=$DISTANCE_CFG" \
  ./configure --prefix=/path/to/mylib/build

make -j$(nproc)
make install
```

> **Key point**: The `.so` / `.a` compiled at this point already has the distance information of each basic block embedded inside. When running, the AFLGo fuzzer uses these distances to calculate how "close to the target" each seed is, thereby guiding the mutation direction.

---

## Step 4b (Optional): Third Compilation — Inject Trace Instrumentation

AFLGo's distance feedback can only tell us "how close to the target", but it cannot tell us exactly which functions were called or which side each branch took. To obtain finer-grained execution trace information during harness upgrades, a separate **trace-instrumented** build of the target library needs to be compiled.

> **Principle**: A custom LLVM Pass (`TraceInstrumentationPass.cpp`) inserts hooks into every function of the target library:
> - Function entry/exit (`trace_fn_enter` / `trace_fn_exit`)
> - Conditional branch direction (`trace_branch`, true/false counts)
> - Call edges (`trace_call_edge`, caller → callee)
> - Optional bug_point markers (specified via `TRACE_MARKER_TARGETS_FILE`)
>
> When the process exits, `trace_runtime.c` serializes all events to JSON for LLM analysis.

### Compile the trace build library

```bash
cd /path/to/mylib

make clean

CC=clang \
CXX=clang++ \
CFLAGS="-fpass-plugin=/root/auto_harness/src/runtime_components/trace_fn_instrument/TraceInstrumentationPass.so -g -O0" \
CXXFLAGS="-fpass-plugin=/root/auto_harness/src/runtime_components/trace_fn_instrument/TraceInstrumentationPass.so -g -O0" \
LDFLAGS="/root/auto_harness/src/runtime_components/trace_fn_instrument/trace_runtime.a" \
  ./configure --prefix=/path/to/mylib/trace_build

make -j$(nproc)
make install
```

Directory structure after compilation:
```
/path/to/mylib/
├── build/          # AFLGo distance-instrumented build (step 4 artifact, used for fuzzing)
└── trace_build/    # trace-instrumented build (step 4b artifact, used for offline diagnostics)
```

### Configure environment variables

```bash
export TRACE_LIBDIR=/path/to/mylib/trace_build/lib
export TRACE_PKG_NAME=mylib         # pkg-config package name, used to get cflags/libs when compiling the trace binary
```

### Automatic trigger flow

After `TRACE_LIBDIR` and `TRACE_PKG_NAME` are set, when the scheduler detects that a harness is unqualified (COARSE stage unstable/very_low_coverage/no_distance_progress, or FINE stage distance_plateau), it will automatically:

1. `compile_trace_binary()` — recompile the harness source with clang + the trace build library, producing `trace_harness`
2. `sample_fuzzer_queue_cases()` — sample fuzzer-mutated seeds from `out/queue/`
3. `run_trace_on_sampled_cases()` — replay the sampled seeds with `trace_harness`, each producing a `trace_*.json`
4. `collect_trace_information()` + `analyze_trace_summary_for_llm()` — aggregate and analyze the traces
5. The LLM decides based on the detailed traces: modify the harness code, generate new seeds, or both
6. `start_fuzzing()` — restart the fuzz process with the improved harness/seeds, returning to COARSE for re-evaluation

```
The same harness.c is compiled twice, linking different versions of the library:

  harness.c
     │
     ├── compile 1: aflgo-clang + build/lib/libxxx.so → harness.out
     │         └── afl-fuzz -i in -o out -- harness.out @@     ← fuzzing process
     │               └── produces out/queue/* (AFL mutated seeds)
     │
     └── compile 2: clang + trace_build/lib/libxxx.so → trace_harness
               └── trace_harness out/queue/id:000001            ← run temporarily during upgrade
               └── trace_harness out/queue/id:000002
               └── ... → trace_*.json → analysis → LLM decides on upgrade
```

> **Note**: If `TRACE_LIBDIR` and `TRACE_PKG_NAME` are not set, the scheduler's harness upgrade will skip trace analysis and make LLM improvements based only on coarse-grained metrics from `fuzzer_stats` (coverage, distance, stability).

---

## Step 5: Generate compile_commands.json

`compile_commands.json` is the compilation database required by libclang static analysis.

```bash
cd /path/to/mylib

# Capture compile commands with bear
bear -- make -j$(nproc)

# Generated file: /path/to/mylib/compile_commands.json
```

> If bear is not installed: `apt install bear` or `pip install scan-build`.

---

## Step 6: Start auto_harness

### 6a. Prepare the target file

```bash
echo "parse_header" > /root/experiment/targets/my_target.txt
```

### 6b. Prepare seed files (recommended)

Place well-formed input samples (1-2 is enough):

```bash
mkdir -p /root/experiment/seeds/MyCVE/
cp /path/to/some/valid/input.bin /root/experiment/seeds/MyCVE/
```

### 6c. Configure environment variables

Refer to the configuration in `.vscode/launch.json`:

```bash
export AFL_NO_AFFINITY=1
export LD_LIBRARY_PATH=/path/to/mylib/build/lib/
export PKG_CONFIG_PATH=/path/to/mylib/build/lib/pkgconfig/
# If trace instrumentation is enabled (step 4b):
export TRACE_LIBDIR=/path/to/mylib/trace_build/lib
export TRACE_PKG_NAME=mylib
# If using the Magma vulnerability detection framework:
# export MAGMA_STORAGE=/path/to/magma/canaries.raw
```

### 6d. Run

```bash
cd /root/auto_harness

python -m src.main \
  -l mylib \
  -f /root/experiment/targets/my_target.txt \
  -p /path/to/mylib \
  -d /path/to/mylib/build/lib/libmylib.so.x.y.z.bc.callgraph.dot \
  -c /path/to/mylib/compile_commands.json \
  -ch /path/to/my_cve_hints.json \
  -s /root/experiment/seeds/MyCVE/
```

---

## What Happens Inside Step 6

```
main.py
  │
  ├─ 1. create_batch()
  │     ├─ load_call_graph()             load call graph from .dot
  │     ├─ get_target_func_location()    locate the source file containing the target function
  │     ├─ get_root_apis()              find all public APIs that can reach the target
  │     ├─ LLM.entry_api_filter()        LLM filters candidate entries
  │     ├─ extract_target_call_chain()   extract the call chain
  │     ├─ aggregate_for_chain() (parallel)  ★ Phase A: static analysis
  │     │    ├─ SignatureExtractor       function signatures
  │     │    ├─ BitmaskExtractor         bitmask/flags arguments
  │     │    ├─ GuardExtractor           guard conditions such as if/switch
  │     │    ├─ ResourceExtractor        malloc/free/open/close
  │     │    └─ ImplementationExtractor  function source fragments
  │     │    → aggregated into harness_plan (JSON)
  │     ├─ _process_root_api() (parallel)    ★ Phase B: LLM generates harness
  │     │    ├─ build_phase_A_context()  build prompt context
  │     │    ├─ LLM.generate_harness_skeleton()
  │     │    ├─ LLM.generate_code()      generate complete C code
  │     │    ├─ harness.compile_test()   compile test, LLM fixes on failure
  │     │    ├─ LLM.generate_dict()      generate AFL dictionary
  │     │    └─ [optional] cve_helper constraint injection + harness structure analysis
  │     └─ Batch.save_metadata()         persist batch metadata
  │
  └─ 2. EpochScheduler.run()
        ├─ start_fuzzing()              start afl-fuzz for each harness
        └─ main loop (every 3s):
             ├─ collect fuzzer_stats feedback
             ├─ crash detection + auto restart
             └─ two-stage adaptive upgrade:
                  Phase COARSE (2-5 min):
                    └─ anomaly → harness_upgrade_procedure()
                  Phase FINE (10-30 min):
                    └─ distance convergence detection → continue or upgrade
```

---

## Environment Variable Reference

| Variable | Description | Required |
|------|------|----------|
| `AFL_NO_AFFINITY` | Disable AFL's CPU affinity binding | Recommended |
| `LD_LIBRARY_PATH` | Point to the `lib/` of the instrumented target library | Yes |
| `PKG_CONFIG_PATH` | Point to the pkgconfig directory of the target library | Recommended |
| `TRACE_PKG_NAME` | pkg-config package name used at runtime trace | Optional |
| `TRACE_LIBDIR` | lib path of the runtime trace library | Optional |
| `MAGMA_STORAGE` | Magma canaries file path (for vulnerability detection) | Optional |
| `TRACE_CC` | C compiler used for trace compilation | Optional (default `clang`) |
| `TRACE_CFLAGS` | CFLAGS for trace compilation | Optional (default `-g -O0`) |
| `TRACE_PKG_NAME` | pkg-config package name of the trace-instrumented library | Optional (required when trace is enabled) |
| `TRACE_LIBDIR` | lib path of the trace-instrumented library | Optional (required when trace is enabled) |
| `TRACE_MARKER_TARGETS_FILE` | bug_point marker location file (`file:line` format) | Optional |
| `TRACE_NUM_RECENT` | Number of most recent queue files to pick during trace sampling | Optional (default 10) |
| `TRACE_NUM_RANDOM` | Number of random queue files to pick during trace sampling | Optional (default 5) |

---

## Argument Quick Reference

| Argument | Short | Meaning |
|------|------|------|
| `--lib_name` | `-l` | Target library name |
| `--function-name` | `-f` | Target function name (or a file path containing the target function name) |
| `--project-path` | `-p` | Target project source directory |
| `--dot-file` | `-d` | Call graph dot file |
| `--compile-commands-path` | `-c` | Path to compile_commands.json |
| `--seeds-path` | `-s` | Directory of user-provided seed inputs |
| `--cve-hints-path` | `-ch` | CVE hints JSON file |
