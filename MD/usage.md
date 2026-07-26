# Usage

## 一、Fuzz 种子的提供方式

种子（seed）是 AFL 模糊测试的初始输入，框架通过三种渠道提供种子，按优先级排列：

### 1. 用户预置种子（通过 `-s` 参数传入）

在 `main.py` 入口处通过 `-s` / `--seeds-path` 参数指定一个目录，框架将该目录下所有文件拷贝到 harness 的 `in/` 目录。

```bash
python -m src.main \
  -l lua \
  -f /root/experiment/targets_for_lua/target3.txt \
  -p /root/experiment/magma_lua/repo \
  -d /root/experiment/magma_lua/repo/fuzz_temp/lua.bc.callgraph.dot \
  -c /root/experiment/magma_lua/repo/compile_commands.json \
  -s /root/experiment/seeds_for_experiment/LUA003/   # ← 用户提供的种子目录
```

**代码路径：**
- `main.py:78-79`：解析 `-s` 参数，传入 `EpochScheduler.run(batch_id, seeds_path=seeds_path)`
- `scheduler/schedule_controller.py:235`：`start_fuzzing(batch_id=batch_id, seeds_path=seeds_path)` 带种子路径启动
- `fuzz_components/fuzz_runner.py:20-28`：`_ensure_seed_dir(input_path, seeds_path)` 调用 `copy_seeds_provided_by_user()` 拷贝文件
- `utils/utils.py:181-194`：`copy_seeds_provided_by_user(src_dir, dest_dir)` 遍历源目录，通过 `shutil.copy2()` 拷贝文件（跳过子目录）

### 2. LLM 动态生成种子（harness 升级阶段）

在 harness 升级（harness_upgrade）阶段，如果模糊测试反馈显示当前种子无法有效到达目标代码，LLM 会根据运行时 trace 分析结果生成更优的种子。

**代码路径：**
- `harness_class/harness_upgrade.py:217-268`：调用 `build_seed_generation_prompt()` 构建 prompt，再由 LLM 生成 `seed_for_harness` 对象（包含 base64 编码的种子内容）
- `harness_class/harness_upgrade.py:37-59`：`_save_modified_seeds()` 解码 base64 内容并写入文件
- `utils/utils.py:196-199`：`build_unique_llm_seed_path()` 生成带时间戳+UUID 的唯一文件名

### 3. 默认种子（兜底）

当以上两种来源均无可用种子时，框架会创建一个最简单的默认种子文件：

**`fuzz_components/fuzz_runner.py:30-35`**
```python
has_files = any(Path(input_path).iterdir())
if not has_files:
    seed_path = os.path.join(input_path, "seed_default")
    with open(seed_path, "w", encoding="utf-8") as f:
        f.write("111\n")
```

---

## 二、AFL 字典的提供方式

字典（dictionary）帮助 AFL 识别输入中的关键 token（如 magic bytes、协议关键字、命令名），提升变异效率和覆盖率。框架通过 **LLM 自动生成** 字典。

### 生成流程

`llm/LLM_class.py:251-338` 的 `generate_dict()` 方法：

1. 将 harness plan（包含调用链中每个函数的签名、guard 条件、资源类型）和生成的 harness 代码打包进 prompt
2. LLM 输出一个 token 列表，每个 token 包含：
   - `value`：关键字节序列（如结构体字段名、枚举值、库特有的 magic 值）
   - `weight_hint`：权重，低权重 token 被过滤（默认阈值 `min_weight=3`）
3. 对 token 做去重、空值过滤
4. 将每个 token 转换为 AFL 字典行格式（`token_to_bytes()` → `bytes_to_afl_dict_line()`）
5. 写入 harness 文件夹下的 `harness_dict.dict`

```python
# llm/LLM_class.py:319-327
p = Path(h.code_file)
p = str(p.parent)
dict_save_file = os.path.join(p, "harness_dict.dict")
with open(dict_save_file, "w", encoding="utf-8") as f:
    for v in cleaned_tokens:
        token_bytes = token_to_bytes(v)
        afl_dict_line = bytes_to_afl_dict_line(token_bytes)
        f.write(afl_dict_line)
        f.write("\n")
```

### 字典在 fuzz 中的使用

字典文件生成后，AFL 启动时如果文件存在则自动挂载：

**`fuzz_components/fuzz_runner.py:43-48`**
```python
dict_path = os.path.join(harness_dir, "harness_dict.dict")
dict_arg = f"-x {dict_path}" if os.path.exists(dict_path) else ""

fuzz_command = (
    f"afl-fuzz -m none -z exp "
    f"-i {input_path} -o {output_path} {dict_arg} -- {harness_path} @@"
)
```

即实际执行的 AFL 命令形如：
```bash
afl-fuzz -m none -z exp \
  -i /root/auto_harness/src/harness/20260417_114927/in \
  -o /root/auto_harness/src/harness/20260417_114927/out \
  -x /root/auto_harness/src/harness/20260417_114927/harness_dict.dict \
  -- /root/auto_harness/src/harness/20260417_114927/20260417_114927_luaG_traceexec.out @@
```

---

## 三、种子与字典的数据流总结

```
┌─ 用户预置种子 (-s) ──────────────────────────┐
│  copy_seeds_provided_by_user()                │
│  src/utils/utils.py:181                       │
└───────────────────────────────────────────────┼──→ in/ 目录 ──→ afl-fuzz
                                                │
┌─ LLM 动态种子 ────────────────────────────────┤
│  harness_upgrade → build_seed_generation_prompt│
│  → LLM → seed_for_harness → base64 decode     │
└───────────────────────────────────────────────┘
                                                
┌─ 默认种子 ────────────────────────────────────┤
│  写入 "111\n" 到 seed_default                  │
└───────────────────────────────────────────────┘

┌─ LLM 字典 ────────────────────────────────────┐
│  generate_dict() → DICT_GENERATE_PROMPT        │
│  → LLM → tokens → token_to_bytes()            │
│  → bytes_to_afl_dict_line()                    │──→ harness_dict.dict ──→ afl-fuzz -x
└───────────────────────────────────────────────┘

---

## 四、AFLGo 预处理模式：`BBtargets.txt` 与 `Ftargets.txt` 生成

Step 2 中需要运行 `opt -load-pass-plugin=aflgo-pass.so -passes="aflgo-npm" -targets=<...> -outdir=<...>` 进入预处理模式，根据 `BBtargets.txt` 生成 `Ftargets.txt`、`Fnames.txt`、`BBnames.txt`、`BBcalls.txt` 等文件。

### `BBtargets.txt` 格式要求

**每行必须是 `文件名:行号`**，不是函数名。Pass 内部会跳过不含冒号的行（`aflgo-pass.so.cc:311-312`）：

```
# 正确格式
parser.c:11876
parser.c:11852
xmlstring.c:234
```

```bash
# 错误格式：缺少冒号，该行会被跳过
xmlParseChunk
xmlPatMatch
```

### 常见问题：`Ftargets.txt` 为空

原因只有一个：**`targets.txt` 中指定的 `filename:line` 不在当前 bitcode 文件的 debug info 里**。

例如你的 bitcode 是 `./.libs/libxml2.so.16.2.0.bc`（共享库），它包含的是 `parser.c`、`buf.c`、`tree.c` 等库源码，**不包含** `xmllint.c`（它是独立的可执行文件源码）。如果你在 `targets.txt` 里写：

```
xmllint.c:384
xmllint.c:385
```

Pass 遍历 bitcode 中所有指令的 debug location 时找不到任何匹配，`is_target_func` 始终为 `false`，`Ftargets.txt` 就不会被写入任何函数名。

**排查方法**：

1. 确认你的 bc 文件包含哪些源码——看 `Fnames.txt` 中函数的源文件归属（或 `opt -print-module` 查看函数元数据）
2. `targets.txt` 中指定的源文件名必须与 debug info 中的文件名一致（通常只取 basename，pass 内部会调用 `find_last_of("/\\")` 截取）
3. 如果目标代码在可执行文件而非共享库中，需要找到可执行文件对应的 `.bc` 文件，或编译时用 `-emit-llvm` 单独生成

**受影响的文件**：
- `aflgo_components/instrument/aflgo-pass.so.cc:280-480`：预处理模式主逻辑
- `aflgo_components/instrument/aflgo-pass.so.cc:306-319`：`targets.txt` 解析（`filename:line` 格式）
- `aflgo_components/instrument/aflgo-pass.so.cc:393-404`：目标命中检测（匹配 debug location）
- `aflgo_components/instrument/aflgo-pass.so.cc:462-474`：写入 `Ftargets.txt` 的条件（`is_target_func == true` 或其内联的原函数）
```




### debug 方法
调用 harness_upgrade.py 158-159中的 get_fileterd_metadata_for_specific_root_api(), get_aggregate_runtime_trace_information(), 可以观察到目标函数是否到达，可以用来解析somepath_to_fuzzout/trace_out/runtime_trace_information下的大量  seed trace information.


###  后台执行 afl-fuzz
1. 创建 tmux 会话
tmux new -s aflgo

进入 tmux 后，直接运行你的命令：

afl-fuzz \
  -m none \
  -z exp \
  -i /root/auto_harness/src/harness/20260714_103533/in \
  -o /root/auto_harness/src/harness/20260714_103533/out \
  -x /root/auto_harness/src/harness/20260714_103533/harness_dict.dict \
  -- \
  /root/auto_harness/src/harness/20260714_103533/20260714_103533_xmlSchematronRunTest.out @@
2. 退出但不停止 fuzzing

按：

Ctrl+b

松开后再按：

d

这叫 detach。AFLGo 会继续运行。

3. 重新进入
tmux attach -t aflgo

查看已有会话：

tmux ls