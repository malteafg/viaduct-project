#!/bin/bash

# The script takes one argument - the root folder to start searching from
root_folder=$1

# Verify root_folder is a directory
if [[ ! -d $root_folder ]]; then
    echo "$root_folder is not a valid directory"
    exit 1
fi

# Flag to indicate all folders are correct
all_folders_correct=true

# Use find to search for directories matching the pattern 19-xx-xx_28-05
while IFS= read -r -d '' dir; do
    # Check if 'classification.txt' file exists in the subfolder
    if [[ -f "$dir/classification.txt" ]]; then
        # Check if the file contains the expected content
        if ! grep -Fxq "MPC: True" "$dir/classification.txt"; then
            # If it doesn't, print the name of the subfolder and set the flag to false
            echo "Folder $dir has incorrect content"
            all_folders_correct=false
        fi
    else
        # If the file doesn't exist, also print the name of the subfolder and set the flag to false
        echo "Folder $dir does not contain classification.txt"
        all_folders_correct=false
    fi
done < <(find "$root_folder" -type d -regextype posix-extended -regex ".*/19-[^/]*-[^/]*/28-05" -print0)

# If all folders were correct, print the success message
if $all_folders_correct; then
    echo "All folders correct"
fi
