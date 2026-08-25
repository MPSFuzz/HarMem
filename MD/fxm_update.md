## 记录优化的功能

1. 首先 aflgo编译会带asan， 但是llm生成的harness.c文件的编译命令没有带 -fsanitize=address，导致链接libxml2.so报 undefined reference,  这会导致LLM消耗显著的token和修复次数来修复这个问题。  

solved: 在生成编译指令时，在提示词里建议llm加上 -fsanitize=address，或者直接对生成的compilation command进行正则匹配。没有就加上。
采用的第二种方案。 改动位置：  src/harness_class/harness_class.py  82-91, 95-96 行。

新增了llm model的选择功能，因为gpt-5有时候会不响应超时，默认改成了deepseek-v4-pro，可以接收变量指定。


2. 由于afl-fuzz在运行时需要 echo > /proc/sys/kernel/core_pattern等操作，这些在docker容器里可能不能直接实现。因为docker容器对宿主机的这些文件夹是read-only，除非在启动容器时就加上 --privileged.  但是可以通过设置以下3个环境变量，来bypass此类问题：
export AFL_NO_AFFINITY=1                           # 已有，跳过 CPU 绑定
export AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1     # 跳过 core_pattern 检查
export AFL_SKIP_CPUFREQ=1                          # 跳过 CPU 频率调节器检查

solved: 修改 src/fuzz_components/fuzz_runner.py   79-80行


3. 更新了llm生成种子的机制。当前方案：判断coarse, fine评分，确定要不要更新种子，还是种子harness都更新。但是更新种子的方案都是一样的，都是调大模型，但是把执行过程中的trace, distance等信息都给大模型。大模型生成  base64的二进制数据。 这样限制了种子的多样性。

solved: 将提示词中生成base64的部分修改，让大模型生成 _seed_generator.py （放在 in 文件夹中），保留了base64类型的兜底。 在调用此py，在in中生成种子。大模型生成的py 会生成10-30个种子。 
具体涉及四个文件变更：
   1. build_seed_generation_prompt.py:52-89 — 提示词新增两种 JSON 格式：
    {"type": "generator", "generator_code": "...", "expected_count": N} 优先
    {"type": "seeds", "seeds": {...}} 退化兜底
   2. LLM_class.py:477-567 — llm_seed_generation() 分三路处理：
    type == "generator" → 调 _execute_seed_generator() → 文件路径 → seed_for_harness(encoding="file")
    type == "seeds" → 解析 seeds 子字段 → base64 → seed_for_harness(encoding="base64")
    含 "seed1" 的旧格式仍兼容
   3. fuzz_runner.py:1-49 — 新增 _execute_seed_generator()：
    写入 _seed_gen.py → subprocess.run("python3", ..., timeout=30) 
    按前缀 seed_/input_/fuzz_/test_ 收集产物文件路径
    执行完自动删除脚本
   4. harness_upgrade.py:37-63 — _save_modified_seeds() 新增 encoding == "file" 分支：
    文件已由生成器落地，跳过解码/写入，直接校验文件存在

并且写了  src/harness_class/fxm_test_seed_generator.py 进行单元测试，更新了launch.json, 新建了 fxm_test_seed_generator 用于断点单步调试 fxm_test_seed_generator.py。调试了一个json, 没有问题。


4. 更新了重启fuzzing的检查机制。现有是触发了harness或seed更新后，删除fuzz out并重启。会导致如果有crashes出现也不保留。 更新为 触发更新时先检查fuzz_stats内容，如果有crashes或hangs，会复制out, harness.c , harness.binary，带上时间戳重命名。
   4++.  更新了一个update逻辑。目前的更新完全依赖距离，但是当出现crashes，但是距离不缩小，也会被更新。这样导致同一个点，已经触达，但是可以触发多种不同的漏洞情况被忽略。因此在更新前，加一个crashes数量盘点。
   逻辑：
    条件	               动作
    首次发现 crash	       当前 epoch 延长到 60 min（一次性）
    后续 crash 数增长	   跳过升级，重置 epoch（正常时长）
    crash 数不变	       正常走升级流程

    涉及的改动：
    schedule_controller.py 三处改动：
   1. __init__ 新增两个 dict — 记录上一次 crash 数和 crash 奖励期
   2. _epoch_due() — 加入 eff_max 逻辑：如果 _crash_bonus_until 仍然有效，max 被延长到 60 min，否则用默认值
   3. run() 的 upgrade 评估循环 — 在 COARSE/FINE 判断之前加入 crash 检测：
    stats 里有 unique_crashes > 上次记录？
    ├─ 是 → 更新记录
    │      ├─ 首次 crash → 设 _crash_bonus_until = now + 60min
    │      └─ 后续 crash → 跳过升级，重置 epoch，继续跑
    ─ 否 → 正常走 COARSE/FINE 升级流程


5. 更新harness 升级的判定方式。  现有方案，即使coverage, stability得分都很高，但是epoch里距离没有缩小，还是会更新harness，这个更新是直接丢弃旧的harness，换新的重跑。有些harness就是需要更多时间的，现有方案导致每个harenss只能跑1个epoch,也就是30-60分钟。 
   fxm update: FINE 阶段的升级逻辑现在（改动代码只有src/scheduler/schedule_controller.py）：
        distance_plateau 且 harness 高质量(cov≥1.0, stab≥1.0)?
        ├─ coverage 涨了（要超过0.03才算） → 跳过升级，计数器归零，继续跑
        ├─ coverage 没涨 → 容忍3次，第4次才升级
        └─ 3次耗尽 或 harness 质量不达标 → 正常升级流程

    现在判定升级，如果只升级种子也会清理进程。修改成不杀死进程，直接更新in/， afl-fuzz会定期扫描 in/，所以这么改几乎没有影响。


6. 现在让LLM判定是更新harness 还是seed，会给很多信息：
fuzzer_stats 原始数据（execs, coverage, distance, crashes）
analysis_result（issues, hints, scores, plateau_diag）
static plans（调用链、函数签名、lifecycle）
harness 源码
trace 聚合数据（reached_functions, markers）
这些其实在harness_memory里就有体现，把 fuzzer_stats + analysis_result + trace 三块换成一段 harness_memory JSON，token 量砍掉 60%+，LLM 响应更快、判断更准，不会被 raw stats 噪音干扰
    fxm: 具体改动如下：
    harness_upgrade.py：
      - 新增 _build_harness_memory_text() 函数，从 trace_summary 提取 expected_chain、actual_chain、gap、marker_hit，拼成带字段解释的文本块
      - build_llm_feedback_prompt / build_llm_micro_tune_prompt 调用时传入 harness_memory_text
    runtime_trace_feedback_analysis.py：
      - 两个 prompt 构建函数新增 harness_memory_text 参数，插入到 "High-level observations" 区域顶部
！！说明：就一次 LLM 调用。LLM 收到 prompt，同时做两件事：决定要不要改 harness + 生成新 harness 代码


7. 更新了一点aflgo的源码，对能够触达最后一跳的种子，能量*5. 具体操作是，当框架触发 only_modify_seed时，out/下保存一个seed_boost.txt 里面都是能到最后一跳的种子，然后框架发送一个SIGUSR信号给afl-fuzz， af-fuzz收到信号读这个txt，更新boost_map这个结构（这是一个长时间维护的数据结构），更新种子的能量。 由于是在/root/aflgo下更新的afl-fuzz，框架里默认用的是auto_harness/aflgo_component/下的，所以cp了一份过去

8. 现在harness_fusion中看jaccard距离用的 nm 查看二进制中符号，需要grep 关键字，已经改成了通过 -k 关键字 手动提供。


## 一些重要的提升，但是过于复杂，暂时不加



TODO1:  优化计算距离的代码。用AFLGO的代码有些老。 重点看get_distance_fast.py
TODO2:  目前是手工设置BBtarget.txt以及 Ftarget.txt， 做成LLM-based 自动生成
TODO3:  有些harness写的不对，能编译，但是一跑就报错，可能是harness里不当的free，对于这种秒级报错，应该警惕harness的质量
还有一些seed_generator产生的种子会导致 afl-fuzz 100轮的3秒检查都过不去，说明种子生成器或者harness有问题。 是修harness还是放弃harness（倾向于修）


