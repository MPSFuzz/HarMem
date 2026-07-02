## 记录优化的功能

1. 首先 aflgo编译会带asan， 但是llm生成的harness.c文件的编译命令没有带 -fsanitize=address，导致链接libxml2.so报 undefined reference,  这会导致LLM消耗显著的token和修复次数来修复这个问题。  

solver: 在生成编译指令时，在提示词里建议llm加上 -fsanitize=address，或者直接对生成的compilation command进行正则匹配。没有就加上。
采用的第二种方案。 改动位置：  src/harness_class/harness_class.py  82-91, 95-96 行。


2. 由于afl-fuzz在运行时需要 echo > /proc/sys/kernel/core_pattern等操作，这些在docker容器里可能不能直接实现。因为docker容器对宿主机的这些文件夹是read-only，除非在启动容器时就加上 --privileged.  但是可以通过设置以下3个环境变量，来bypass此类问题：
export AFL_NO_AFFINITY=1                           # 已有，跳过 CPU 绑定
export AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1     # 跳过 core_pattern 检查
export AFL_SKIP_CPUFREQ=1                          # 跳过 CPU 频率调节器检查

solver: 修改 src/fuzz_components/fuzz_runner.py   79-80行


