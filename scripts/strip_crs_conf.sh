#!/bin/bash

# Directory containing CRS .conf files (relative to GitHub workspace)
CRS_DIR="rules"
# Output directory for stripped files
OUTPUT_DIR="stripped_bash_files"

# Create output directory
mkdir -p "$OUTPUT_DIR"

# Check if CRS_DIR exists
if [ ! -d "$CRS_DIR" ]; then
    echo "Error: Directory $CRS_DIR not found"
    exit 1
fi

# Process each .conf file
for file in "$CRS_DIR"/*.conf; do
    if [[ -f "$file" ]]; then
        filename=$(basename "$file")
        # Append -strip_bash.conf to output filename
        output_filename="${filename%.conf}-strip_bash.conf"
        output_file="$OUTPUT_DIR/$output_filename"

        # Strip comments and empty lines
        awk '!/^[[:space:]]*(#.*)?$/' "$file" > "$output_file"

        echo "Processed $filename -> $output_filename"
    else
        echo "No .conf files found in $CRS_DIR"
    fi
done