#!/bin/bash
if [ "$#" -ne 2 ]; then
    echo "Usage: $0 <old_commit> <new_commit>"
    exit 1
fi

OLD_COMMIT=$1
NEW_COMMIT=$2
tmp_diff_file=$(mktemp)
output_file="./fixedfunc.txt"

trap 'rm -f "$tmp_diff_file" "$output_file"' EXIT

git diff $OLD_COMMIT $NEW_COMMIT > "$tmp_diff_file"
flag=0
flag2=0
funcname=""
newline=""
filename=""
regex='[_a-zA-Z][_a-zA-Z0-9]*[[:space:]]*\([^)]*\)'
while IFS= read -r line; do
    if [[ $line == diff* ]]; then
        if [[ $line == *.c ]]; then
            flag=1
            filename=$(echo "$line" | awk -F'/' '{print $NF}')

        else
            flag=0
        fi
    fi

    if [[ "$flag" -eq 1 ]]; then
        if [[ "$flag2" -eq 1 ]]; then
            if [[ ${newline}${line} =~ $regex && "$line" != *"-"* && $line != *";"* && $line != *"="* && "$line" != *"<"* && "$line" != *">"* && "$line" != *"."* && "$line" != *"/*"* ]]; then
                funcname=${newline}${line}
                #echo ${filename}:${funcname} >>"$output_file"
                echo ${funcname} >>"$output_file"
            fi
            flag2=0
        fi

        if [[ $line == @@* ]]; then
            newline=$(echo "$line" | sed -E 's/^@@[^@]+@@ //')
            if [[ $newline =~ $regex ]]; then
                funcname="$newline"
                #echo ${filename}:${funcname} >>"$output_file"
                echo ${funcname} >>"$output_file"
            else
                flag2=1
            fi
        fi

        if [[ $line == +* && $line != *";"* && $line != *"="* && "$line" != *"<"* && "$line" != *">"* && "$line" != *"#"* && "$line" != "+++"* && "$line" != *"-"* && "$line" != *"."* && "$line" != *"/*"* ]]; then
            if [[ $line == +* ]]; then
                line=$(echo "$line" | sed 's/^+//') 
            fi    
            if [[ $line =~ $regex ]]; then
                funcname="$line"
                #echo ${filename}:${funcname} >>"$output_file"
                echo ${funcname} >>"$output_file"
            else
                flag2=1
                newline=$line
            fi
        fi
    fi
done < $tmp_diff_file  # 替换为你的输入文件

if [ -f "$output_file" ]; then
    cat "$output_file"
fi