#!/bin/bash

search_for_flag() {
    local path=$1
    for dir in "$path"/*; do
        if [ -d "$dir" ]; then
            search_for_flag "$dir"
        elif [ -f "$dir" ] && [ "$(basename "$dir")" == "flag.txt" ]; then
            echo "Flag found at: $dir"
            awk '1' "$dir"  
        fi
    done
}

base_path="longleat_maze"  # Adjust the path as needed
search_for_flag "$base_path"
