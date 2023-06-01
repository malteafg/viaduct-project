#!/bin/bash

# The script is running from the VIADUCT-PROJECT/ directory
root_folder="."

# Verify root_folder is a directory
if [[ ! -d $root_folder ]]; then
    echo "$root_folder is not a valid directory"
    exit 1
fi

# Verify benchmarks folder exists
benchmarks_folder="$root_folder/benchmarks"
if [[ ! -d $benchmarks_folder ]]; then
    echo "$benchmarks_folder is not a valid directory"
    exit 1
fi

# Verify input_alice.txt and input_bob.txt exist in the root_folder
if [[ ! -f "$root_folder/input_alice.txt" ]] || [[ ! -f "$root_folder/input_bob.txt" ]]; then
    echo "input_alice.txt and/or input_bob.txt files do not exist in $root_folder"
    exit 1
fi

# Iterate over all .via files in the benchmarks folder
for via_file in "$benchmarks_folder"/*.via; do
    # Extract the base filename without extension
    base_filename=$(basename -- "$via_file")
    base_filename="${base_filename%.*}"
    
    # Create a new directory in the root folder with the base filename
    new_folder="$root_folder/$base_filename"
    mkdir -p "$new_folder"
    
    # Copy the .via file into the new directory
    cp "$via_file" "$new_folder"
    
    # Create a captures folder in the new directory
    mkdir -p "$new_folder/captures"
    
    # Copy input_alice.txt and input_bob.txt files from the root folder into the new directory
    cp "$root_folder/input_alice.txt" "$new_folder"
    cp "$root_folder/input_bob.txt" "$new_folder"
done
