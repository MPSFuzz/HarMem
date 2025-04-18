#!/bin/bash
# Usage: ./extract_modified_funcs.sh <source_dir> <old_commit> <new_commit>

if [ "$#" -ne 3 ]; then
    echo "Usage: $0 <source_dir> <old_commit> <new_commit>"
    exit 1
fi

TARGET_DIR=$1
OLD_COMMIT=$2
NEW_COMMIT=$3

tmp_diff_file=$(mktemp)
output_file="./fixedfunc.txt"

trap 'rm -f "$tmp_diff_file"' EXIT

cd "$TARGET_DIR" || {
    echo "Error: Could not change directory to $TARGET_DIR"
    exit 1
}

# Generate diff with zero context lines and include function name context
# -U0: no context, -p: show C function name in hunk headers
git diff -U0 -p "$OLD_COMMIT" "$NEW_COMMIT" > "$tmp_diff_file"

# Looser regex for hunk header extraction: name(params)
header_regex='[_a-zA-Z][_a-zA-Z0-9]*[[:space:]]*\([^)]*\)'

# Strict regex for detecting added function definitions: return_type name(params) [optional {]
sig_regex='^[[:space:]]*[_a-zA-Z][_a-zA-Z0-9[:space:]]+[[:space:]]+[_a-zA-Z][_a-zA-Z0-9]*[[:space:]]*\([^;]*\)[[:space:]]*(\{)?[[:space:]]*$'

# Clear output file
> "$output_file"

while IFS= read -r line; do
    # Extract from hunk header (captures both modified and entirely new functions)
    if [[ $line == @@*@@* ]]; then
        func=$(echo "$line" | sed -E 's/^@@[^@]+@@[[:space:]]*//')
        if [[ $func =~ $header_regex ]]; then
            echo "$func" >> "$output_file"
        fi
    fi

    # Scan added lines for strict function definitions
    if [[ $line == +* ]]; then
        candidate=${line#+}
        if [[ $candidate =~ $sig_regex ]]; then
            echo "$candidate" >> "$output_file"
        fi
    fi

done < "$tmp_diff_file"

# Output unique function signatures
if [[ -f "$output_file" ]]; then
    sort -u "$output_file"
fi
