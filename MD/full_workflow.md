# Auto Harness 完整工作流：从 CVE 描述到定向 Fuzz

本文档描述使用 auto_harness 对一个新的目标库进行定向模糊测试的完整流程。

## 前置条件

- 已激活 `autoharness` conda 环境
- 目标库的源码已克隆到本地
- LLVM 工具链可用（`opt`, `llvm-config` 等）
- AFLGo 的 `aflgo-clang`、`aflgo-pass.so`、`distance.bin` 已编译就绪

---

## 流程总览

```
┌─────────────────────────────────────────────────────────────┐
│  0. 准备 CVE hints                                          │
├─────────────────────────────────────────────────────────────┤
│  1. 首次编译：生成 bitcode (.bc) + CFG dot 文件 + CG dot    │
│  2. 指定目标基本块 → BBtargets.txt                          │
│  3. 计算距离 → gen_distance_fast.py → distance.cfg.txt      │
│  4. 二次编译：用 -distance 标志注入距离信息                  │
│  5. 生成 compile_commands.json                              │
│  6. 启动 auto_harness → harness 生成 + 定向 fuzz            │
└─────────────────────────────────────────────────────────────┘
```

> **注意**：步骤 1-5 为手动前置步骤，步骤 6 由 auto_harness 自动完成。

---

## 步骤 0：准备 CVE Hints

在只有 CVE 大概描述的情况下，将情报转化为结构化的 `cve_hints.json`。

### 方式 A：手写 hints.json（推荐，快速）

从 CVE 描述中提取关键信息，直接手写：

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

**字段说明**：

| 字段 | 含义 |
|------|------|
| `target_func` | CVE 描述中提到的漏洞函数名（必填） |
| `touchpoints` | 涉及的源文件、相关函数、关键 token |
| `must_contain` | harness 中必须包含的 API 调用或代码模式 |
| `must_avoid` | harness 中必须规避的调用 |
| `input_model` | 输入文件的大致格式（binary/text，magic bytes 等） |
| `repro_oracle` | 漏洞复现证据（crash / asan / ubsan 等） |
| `bug_class` | 漏洞类型（buffer_overflow / use_after_free / ...） |

### 方式 B：LLM 自动生成

适用于有补丁（patch diff）、安全公告、PoC 脚本等原始情报的场景。

创建一个 intel 文件 `my_cve_intel.txt`：

```
CVE_ID: CVE-2025-xxxxx
LIB_NAME: mylib
TARGET_FUNC: parse_header

=== PATCH ===
(diff 或补丁内容)

=== ADVISORY ===
(安全公告原文)

=== POC ===
(公开 PoC 或触发样本)

=== EXTRA ===
(其他信息：触发条件、调用栈等)
```

运行 cve_helper 自动生成：

```bash
python -m src.cve_helper.cli \
  --intel /path/to/my_cve_intel.txt \
  --out /path/to/my_cve_hints.json
```

---

## 步骤 1：首次编译 —— 生成 bitcode 和 CFG / CG

使用 AFLGo 的 clang 编译目标库，生成 LLVM bitcode（`.bc`）和控制流图 dot 文件。

### 1a. 编译生成 bitcode

```bash
cd /path/to/mylib

# 清理
make clean 2>/dev/null || true

# 设置 AFLGo 路径
export AFLGO=/root/auto_harness/aflgo

# 用 aflgo-clang 编译
CC=/root/auto_harness/aflgo_components/instrument/aflgo-clang \
CXX=/root/auto_harness/aflgo_components/instrument/aflgo-clang++ \
  ./configure --prefix=/path/to/mylib/build

make -j$(nproc)
make install
```

编译产物示例：
```
/path/to/mylib/build/lib/
├── libmylib.so.x.y.z         # 共享库（已插桩）
├── libmylib.so.x.y.z.bc     # LLVM bitcode（用于分析）
└── temp/dot-files/
    ├── cfg.parse_header.dot  # parse_header 的 CFG
    ├── cfg.read_chunk.dot    # read_chunk 的 CFG
    └── ...
```

### 1b. 生成调用图（Call Graph dot）

```bash
BC_FILE=$(ls /path/to/mylib/build/lib/*.bc | head -1)

opt -dot-callgraph -enable-new-pm=0 "$BC_FILE" -o /dev/null

# 输出文件: libmylib.so.x.y.z.bc.callgraph.dot
```

### 1c. 拷贝 CFG dot 文件到统一位置

```bash
mkdir -p /path/to/mylib/build/temp/dot-files

# 查找编译过程中生成的 cfg.*.dot 并拷贝
find /path/to/mylib/build -name "cfg.*.dot" \
  -exec cp {} /path/to/mylib/build/temp/dot-files/ \;
```

---

## 步骤 2：指定目标基本块

AFLGo 需要知道哪些基本块是定向 fuzz 的目标。需要从目标函数的 CFG dot 文件中提取基本块 label。

### 2a. 找到目标函数的 CFG dot 文件

```bash
ls /path/to/mylib/build/temp/dot-files/cfg.parse_header.dot
```

### 2b. 准备目标列表文件

创建 `BBtargets.txt`，每行一个目标基本块的 label：

```bash
cat > /path/to/mylib/build/temp/BBtargets.txt << 'EOF'
%11
%23
EOF
```

> **如何获取基本块 labels**：打开目标函数的 CFG dot 文件（`cfg.parse_header.dot`），查看 Node 的 label 名称。也可以使用 LLVM 的 `opt -dot-cfg` 单独生成某个函数的 CFG 来辅助定位。

同时准备 `BBnames.txt` 和 `BBcalls.txt`：

```bash
# BBnames.txt: 每个基本块的名称，格式为 "label\tfunction_name"
# 从 CFG dot 文件中提取
cat > /path/to/mylib/build/temp/BBnames.txt << 'EOF'
%0	parse_header
%11	parse_header
%23	parse_header
EOF

# BBcalls.txt: 每个基本块调用了哪个函数，格式为 "BB_label\tcalled_function"
cat > /path/to/mylib/build/temp/BBcalls.txt << 'EOF'
%11	read_chunk
EOF

# Fnames.txt: 函数名列表
cat > /path/to/mylib/build/temp/Fnames.txt << 'EOF'
parse_header
read_chunk
EOF

# Ftargets.txt: 目标函数名（与 BBtargets 对应）
cat > /path/to/mylib/build/temp/Ftargets.txt << 'EOF'
parse_header
EOF
```

---

## 步骤 3：计算距离 —— `gen_distance_fast.py`

这一步计算调用图（CG）和控制流图（CFG）上每个基本块到目标块的距离。

```bash
python /root/auto_harness/aflgo_components/gen_distance/gen_distance_fast.py \
  /path/to/mylib/build/lib \                                 # binaries_directory (存放 .bc 文件)
  /path/to/mylib/build/temp \                                # temporary_directory (存放 targets 文件)
  --skip-cg \                                                 # 跳过 CG 生成（步骤 1b 已手动生成）
  --cfg-glob-format "cfg.*.dot" \
  --callgraph-path /path/to/mylib/build/lib/libmylib.so.x.y.z.bc.callgraph.dot \
  --cfg-dot-files-path /path/to/mylib/build/temp/dot-files/
```

**参数说明**：

| 参数 | 含义 |
|------|------|
| `binaries_directory` | 存放 `.bc` 文件的目的录 |
| `temporary_directory` | 存放 `BBtargets.txt`、`BBnames.txt`、`BBcalls.txt` 等的目录 |
| `--skip-cg` | 跳过调用图生成（已手动完成） |
| `--cfg-glob-format` | CFG dot 文件的 glob 匹配模式 |
| `--callgraph-path` | 调用图 dot 文件路径 |
| `--cfg-dot-files-path` | CFG dot 文件所在目录 |

**产物**：`/path/to/mylib/build/temp/distance.cfg.txt`

内容格式：
```
BB_label1,distance_1
BB_label2,distance_2
...
```

脚本结束时终端会打印后续编译需要的命令模板。

---

## 步骤 4：二次编译 —— 注入距离信息

清理后，用带 `-distance` 标志的编译命令重新编译目标库。

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

> **关键**：此时编译出的 `.so` / `.a` 内部已嵌入每个基本块的距离信息。AFLGo fuzzer 在运行时会根据这些距离计算种子的"离目标有多近"，从而引导变异方向。

---

## 步骤 5：生成 compile_commands.json

`compile_commands.json` 是 libclang 静态分析所需的编译数据库。

```bash
cd /path/to/mylib

# 使用 bear 捕获编译命令
bear -- make -j$(nproc)

# 生成文件: /path/to/mylib/compile_commands.json
```

> 如果没有安装 bear：`apt install bear` 或 `pip install scan-build`。

---

## 步骤 6：启动 auto_harness

### 6a. 准备 target 文件

```bash
echo "parse_header" > /root/experiment/targets/my_target.txt
```

### 6b. 准备种子文件（推荐）

放入格式合法的输入样本（1-2 个即可）：

```bash
mkdir -p /root/experiment/seeds/MyCVE/
cp /path/to/some/valid/input.bin /root/experiment/seeds/MyCVE/
```

### 6c. 配置环境变量

参考 `.vscode/launch.json` 中的配置：

```bash
export AFL_NO_AFFINITY=1
export LD_LIBRARY_PATH=/path/to/mylib/build/lib/
export PKG_CONFIG_PATH=/path/to/mylib/build/lib/pkgconfig/
# 如果使用 Magma 漏洞检测框架：
# export MAGMA_STORAGE=/path/to/magma/canaries.raw
```

### 6d. 运行

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

## 步骤 6 内部发生了什么

```
main.py
  │
  ├─ 1. create_batch()
  │     ├─ load_call_graph()             从 .dot 加载调用图
  │     ├─ get_target_func_location()    定位目标函数所在源文件
  │     ├─ get_root_apis()              找到所有能到达目标的 public API
  │     ├─ LLM.entry_api_filter()        LLM 筛选候选入口
  │     ├─ extract_target_call_chain()   提取调用链
  │     ├─ aggregate_for_chain() (并行)  ★ Phase A: 静态分析
  │     │    ├─ SignatureExtractor       函数签名
  │     │    ├─ BitmaskExtractor         bitmask/flags 参数
  │     │    ├─ GuardExtractor           if/switch 等 guard 条件
  │     │    ├─ ResourceExtractor        malloc/free/open/close
  │     │    └─ ImplementationExtractor  函数源码片段
  │     │    → 汇总为 harness_plan (JSON)
  │     ├─ _process_root_api() (并行)    ★ Phase B: LLM 生成 harness
  │     │    ├─ build_phase_A_context()  构建 prompt 上下文
  │     │    ├─ LLM.generate_harness_skeleton()
  │     │    ├─ LLM.generate_code()      生成完整 C 代码
  │     │    ├─ harness.compile_test()   编译测试，失败则 LLM 修复
  │     │    ├─ LLM.generate_dict()      生成 AFL 字典
  │     │    └─ [可选] cve_helper 约束注入 + harness 结构分析
  │     └─ Batch.save_metadata()         持久化 batch 元数据
  │
  └─ 2. EpochScheduler.run()
        ├─ start_fuzzing()              对每个 harness 启动 afl-fuzz
        └─ 主循环 (每 3s):
             ├─ 收集 fuzzer_stats 反馈
             ├─ 崩溃检测 + 自动重启
             └─ 两阶段自适应升级:
                  Phase COARSE (2-5 min):
                    └─ 异常 → harness_upgrade_procedure()
                  Phase FINE (10-30 min):
                    └─ 距离收敛检测 → 继续或升级
```

---

## 环境变量参考

| 变量 | 说明 | 是否必需 |
|------|------|----------|
| `AFL_NO_AFFINITY` | 禁 AFL 的 CPU 亲和性绑定 | 推荐 |
| `LD_LIBRARY_PATH` | 指向插桩后目标库的 `lib/` | 是 |
| `PKG_CONFIG_PATH` | 指向目标库的 pkgconfig 目录 | 推荐 |
| `TRACE_PKG_NAME` | 运行时 trace 所用的 pkg-config 包名 | 可选 |
| `TRACE_LIBDIR` | 运行时 trace 库的 lib 路径 | 可选 |
| `MAGMA_STORAGE` | Magma canaries 文件路径（漏洞检测用） | 可选 |

---

## 参数速查

| 参数 | 简写 | 含义 |
|------|------|------|
| `--lib_name` | `-l` | 目标库名称 |
| `--function-name` | `-f` | 目标函数名（或包含目标函数名的文件路径） |
| `--project-path` | `-p` | 目标项目源码目录 |
| `--dot-file` | `-d` | 调用图 dot 文件 |
| `--compile-commands-path` | `-c` | compile_commands.json 路径 |
| `--seeds-path` | `-s` | 用户提供的种子输入目录 |
| `--cve-hints-path` | `-ch` | CVE hints JSON 文件 |
