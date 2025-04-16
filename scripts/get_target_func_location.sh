#!/bin/bash

# 检查是否提供了两个参数
if [ "$#" -ne 2 ]; then
    echo "用法: $0 <libxml2_path> <function_name>"
    echo "示例: $0 /path/to/libxml2 XXX"
    exit 1
fi

# 获取参数
LIBXML2_DIR="$1"
FUNCTION_NAME="$2"

# 检查目录是否存在
if [ ! -d "$LIBXML2_DIR" ]; then
    echo "Error: diractory '$LIBXML2_DIR' does not exist。"
    exit 1
fi

# 使用 find 查找所有 .c 文件
# 使用 grep -l 搜索包含函数名的文件并只打印文件名
# 正则表达式解释:
# \b       - 匹配单词边界，确保 FUNCTION_NAME 是一个完整的单词
# ${FUNCTION_NAME} - 要搜索的函数名
# \b       - 再次匹配单词边界
# \s* - 匹配零个或多个空白字符 (空格, tab)
# \(       - 匹配一个字面的左括号 '('
# -E       - 使用扩展正则表达式 (支持 \b, \s*)
# -l       - 只列出包含匹配项的文件名 (List files with matches)
find "$LIBXML2_DIR" -type f -name '*.c' -exec grep -lE "\b${FUNCTION_NAME}\b\s*\(" {} +

exit 0