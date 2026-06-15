# Auto Harness — 定向模糊测试框架

## 一、launch.json 中所有 Configuration 一览

### 端到端入口（从 `src.main` 进入）

| 配置名 | 目标库 | 说明 |
|---|---|---|
| `harness_gen_main1` | **lua** | 对 LUA003 目标生成 harness 并启动定向模糊测试 |
| `harness_gen_main2` | **lua** | 对 LUA004 目标生成 harness 并启动定向模糊测试 |
| `harness_gen_main3` | **libtiff** | 对 PNG004 目标生成 harness（seeds 是 PNG 的） |

这三个是完整的端到端流程配置，从 `main.py` 进入，执行 **harness 生成 + 模糊测试调度**。

### 独立子模块调试（无预设 args，需手动填参）

| 配置名 | 模块 | 功能 |
|---|---|---|
| `_process_root_api` | `gen_hanress` | 对单个 root API 生成 harness（LLM 调用） |
| `ccdb` | `ccdb` | 解析 compile_commands.json |
| `signature_extractor` | `signature_extractor` | 提取函数签名/参数类型 |
| `bitmask_extractor` | `bitmask_extractor` | 提取 bitmask/flags 参数 |
| `guard_extractor` | `guard_extractor` | 提取调用链中的 guard 条件 |
| `resource_extractor` | `resource_extractor` | 提取资源分配/释放操作 |
| `sourcecode_extractor` | `sourcecode_extractor` | 提取函数源码实现 |
| `aggregator` | `aggregator` | 聚合所有静态分析结果生成 harness plan |
| `start_fuzzing` | `fuzz_runner` | 启动 AFL fuzzer 进程 |
| `parase_fuzzer_stats_file` | `fuzz_feedback_parser` | 解析 AFL 的 fuzzer_stats 文件 |
| `harness_analysis.py` | `plugin` | 对生成的 harness 代码做结构分析 |

### 运行时/反馈模块

| 配置名 | 目标库 | 功能 |
|---|---|---|
| `filter_merged_compile_pass_metadata.py` | **libxml2** | 过滤 Pass 插桩后的 trace 元数据 |
| `schedule_controller.py` | **libxml2** | 完整调度器（coarse→fine 两阶段模糊测试） |
| `harness_upgrade.py` | **libxml2** | harness 迭代升级 |

### 辅助模块

| 配置名 | 目标库 | 功能 |
|---|---|---|
| `cve_helper.py` | **lua** | 从 CVE intel 生成 hints.json 供 LLM 使用 |
| `gen_distance_fast` | **libxml2** | 预计算 AFLGo 的基本块距离 |

### C/C++ 二进制调试（`cppdbg` 类型）

| 配置名 | 目标 | 功能 |
|---|---|---|
| `aflgo-pass.so` | **gpac** | 调试 AFLGo 的 LLVM Pass 加载过程 |
| `distance.bin (gdb)` | **lrzip** | GDB 调试 distance.bin 距离计算 |
| `aflgo-clang` | **lrzip** | GDB 调试 aflgo-clang 编译包装器 |

### 组合配置（Compound）

| 配置名 | 组合内容 |
|---|---|
| `multiple experiments` | harness_gen_main1 + harness_gen_main2（lua 两个目标并行） |
| `multiple experiments2` | harness_gen_main2 + harness_gen_main3（lua + libtiff） |

### 涉及的库

**lua、libtiff、libxml2、gpac、lrzip**

---

## 二、框架整体运行流程

所有端到端配置都是从 `src.main` 进入的（`"module": "src.main"`）。

### 入口参数（main.py 接收）

| 参数 | 简写 | 含义 |
|---|---|---|
| `--lib_name` | `-l` | 目标库名称（如 lua, libtiff） |
| `--function-name` | `-f` | 目标函数名（或包含目标函数名的文件路径） |
| `--project-path` | `-p` | 目标项目源码目录 |
| `--dot-file` | `-d` | 调用图 dot 文件（`.bc.callgraph.dot`） |
| `--compile-commands-path` | `-c` | compile_commands.json 路径 |
| `--seeds-path` | `-s` | 用户提供的种子输入目录（可选） |
| `--cve-hints-path` | `-ch` | CVE hints JSON 文件（可选） |

### 完整执行流程

```
main.py
  │
  ├─ 1. create_batch()
  │     │
  │     ├─ 1a. get_available_harness()            ← harness 生成
  │     │    │
  │     │    ├─ load_call_graph()                 从 .dot 文件加载调用图
  │     │    ├─ get_target_func_location()        定位目标函数在哪个源文件
  │     │    ├─ get_root_apis()                   从调用图找到所有能到达目标的入口 API
  │     │    ├─ LLM.entry_api_filter()            LLM 筛选候选入口 API
  │     │    ├─ extract_target_call_chain()       提取每个 root_api → target 的调用链
  │     │    │
  │     │    ├─ aggregate_for_chain() (并行)      ★ Phase A: 对每条链做静态分析
  │     │    │    ├─ SignatureExtractor           提取函数签名、参数类型
  │     │    │    ├─ BitmaskExtractor             识别 bitmask/flags 参数
  │     │    │    ├─ GuardExtractor               提取 if/switch 等 guard 条件
  │     │    │    ├─ ResourceExtractor            识别 malloc/free/open/close 等
  │     │    │    └─ ImplementationExtractor      提取函数源码片段
  │     │    │    → 汇总为 harness_plan (JSON)
  │     │    │
  │     │    └─ _process_root_api() (并行)        ★ Phase B: LLM 生成 harness
  │     │         ├─ build_phase_A_context()      将 plan + 调用链信息构建为 prompt
  │     │         ├─ LLM.generate_harness_skeleton()   LLM 生成 harness 骨架
  │     │         ├─ LLM.generate_code()          LLM 生成完整 C 代码
  │     │         ├─ harness.compile_test()       编译测试，失败则 LLM 修复
  │     │         ├─ LLM.generate_dict()          生成 AFL 字典
  │     │         └─ [可选] cve_helper 约束注入 + harness_analysis 结构分析
  │     │
  │     └─ 1b. Batch.save_metadata()              持久化 batch 元数据到 batch_metadata/
  │
  └─ 2. EpochScheduler.run()
        │
        ├─ start_fuzzing()                        对每个 harness 启动 afl-fuzz 进程
        │
        └─ 主循环 (每 poll_sec=3s):
             │
             ├─ _collect_analyze()                收集 fuzzer_stats 反馈
             │    ├─ parse_fuzzer_stats_file()    解析 execs_done, paths_total 等
             │    └─ analyze_fuzzer_feedback()    分析距离进度/覆盖率/崩溃
             │
             ├─ 崩溃检测 + 自动重启               fuzzer 进程挂了就重新拉起
             │
             └─ 两阶段自适应升级:
                  
                  Phase COARSE (2-5 min):
                    ├─ 检测 unstable_harness / very_low_coverage
                    └─ 不合格 → harness_upgrade_procedure()
                         ├─ filter_merged_compile_pass_metadata()   收集运行时 trace
                         ├─ get_aggregate_runtime_trace_information()  分析 trace
                         ├─ LLM 生成改进 prompt + 迭代 harness
                         └─ 改进后重新进入 COARSE 阶段
                  ↓
                  Phase FINE (10-30 min):
                    ├─ 检测 distance_plateau (距离不再缩小)
                    └─ 触发 harness_upgrade 或继续
```

---

## 三、关键设计理念

1. **调用图驱动**：从目标的 `.bc.callgraph.dot` 出发，找到所有能覆盖目标函数的外部 API 入口，而非人工指定的入口点。

2. **LLM 全程参与**：API 筛选、harness 骨架生成、代码生成、编译修复、字典生成、harness 升级全部依赖 LLM（默认模型 `gpt-5.4`，兼容 OpenAI API）。

3. **两阶段模糊测试**：
   - **Coarse（粗粒度）**：2-5 分钟，快速筛选合格的 harness，检测不稳定/低覆盖
   - **Fine（细粒度）**：10-30 分钟，深度模糊测试，监控距离收敛（distance plateau）

4. **反馈闭环**：AFL 运行时统计数据 → fuzzer_stats 分析 → harness 升级 → 重新模糊，持续迭代直到满足条件或超时。

5. **静态分析**：基于 libclang 的 C 代码静态分析，提取函数签名、guard 条件、资源操作、bitmask 参数等，构建结构化的 harness plan。

6. **AFLGo 集成**（`aflgo_components/`）：使用定向灰盒模糊测试的 distance 计算和 LLVM Pass 插桩，引导 fuzzer 向目标基本块逼近。

7. **CVE 辅助**（`cve_helper/`）：从 CVE 情报/用户规则生成 hints，注入到 LLM prompt 中，提供针对性约束。

8. **运行时 Trace 反馈**：通过 Pass 插桩收集运行时数据（哪些基本块被访问），分析 harness 是否能有效到达目标函数，指导后续升级。

---

## 四、项目目录结构

```
auto_harness/
├── .vscode/                    # VS Code 配置 (launch.json, settings.json)
├── src/
│   ├── main.py                 # 入口：harness 生成 + 调度
│   ├── batch/                  # Batch 管理（元数据持久化、反馈收集）
│   ├── harness_class/          # Harness 生成与升级
│   │   ├── gen_hanress.py      # LLM 驱动的 harness 生成
│   │   ├── harness_class.py    # Harness 数据结构
│   │   ├── harness_upgrade.py  # 反馈驱动的 harness 迭代升级
│   │   └── harness_structural_refine.py  # 结构分析后精炼
│   ├── static_analyze/         # 基于 libclang 的静态分析
│   │   ├── aggregator.py       # 聚合所有 extractors 输出
│   │   ├── ccdb.py             # compile_commands.json 解析
│   │   ├── extract_call_chain.py # 调用图分析
│   │   └── extractor/          # 各类提取器
│   ├── llm/                    # LLM 接口
│   │   ├── LLM_class.py        # OpenAI 兼容 API 封装
│   │   ├── LLM_prompt.py       # Prompt 模板
│   │   └── build_phase_A_context.py  # 构建 Phase A 上下文
│   ├── fuzz_components/        # 模糊测试组件
│   │   ├── fuzz_runner.py      # AFL fuzzer 启动器
│   │   ├── fuzz_feedback_parser.py  # AFL stats 解析
│   │   └── fuzzer_feed_back_analysis.py  # 反馈分析
│   ├── scheduler/              # 调度器
│   │   └── schedule_controller.py  # EpochScheduler 主循环
│   ├── runtime_components/     # 运行时 trace 分析
│   ├── cve_helper/             # CVE 情报辅助
│   ├── harness_analysis/       # Harness 结构分析
│   ├── seed_generation/        # 种子生成
│   ├── aflgo_dev/              # AFLGo 开发调试
│   └── utils/                  # 工具函数
├── aflgo_components/           # AFLGo distance 计算
├── aflgo/                      # AFLGo 源码 (LLVM Pass, clang wrapper)
├── batch_metadata/             # Batch 元数据存储
├── scripts/                    # 辅助脚本
└── temp/                       # 临时文件
```

---

## 五、运行方式

### 方式 1：VS Code Run and Debug

1. 确保已激活 `autoharness` conda 环境
2. 在 VS Code 中选择 Python 解释器：`/root/miniconda3/envs/autoharness/bin/python`
3. 按 `Ctrl+Shift+D` 打开 Run and Debug 面板
4. 从下拉菜单中选择一个配置（如 `harness_gen_main1`）
5. 点击绿色播放按钮或按 `F5`

### 方式 2：命令行

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
