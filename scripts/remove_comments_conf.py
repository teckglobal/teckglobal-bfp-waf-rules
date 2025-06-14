import os
import re

# Input and output directories
input_dir = "rules"
output_dir = "stripped_files"

# Create output directory if it doesn't exist
os.makedirs(output_dir, exist_ok=True)

# Get list of .conf files in the rules directory
conf_files = [f for f in os.listdir(input_dir) if f.endswith('.conf')]

for conf_file in conf_files:
    # Read the input file
    input_path = os.path.join(input_dir, conf_file)
    with open(input_path, 'r') as f:
        content = f.read()
    
    # Remove comments and empty lines
    lines = [line for line in content.splitlines() if line.strip() and not line.strip().startswith('#')]
    content = '\n'.join(lines)
    
    # Split content into individual SecRule/SecMarker directives
    # Match SecRule or SecMarker, capturing the entire rule including continuations
    rule_pattern = r'(SecRule|SecMarker)\s+[^\n]*(?:\n\s*\\[^\n]*)*?(?=\n(?:SecRule|SecMarker)|$|\n\s*[^\\])'
    rules = re.findall(rule_pattern, content, re.DOTALL)
    
    # Process each rule to collapse into a single line
    processed_rules = []
    for rule in rules:
        # Remove line continuations (\) and collapse newlines
        rule = re.sub(r'\\\n\s*', ' ', rule)
        # Replace multiple spaces with a single space, preserving quoted content
        rule = re.sub(r'\s+', ' ', rule.strip())
        processed_rules.append(rule)
    
    # Create output filename with -strip.conf suffix
    output_filename = os.path.splitext(conf_file)[0] + "-strip.conf"
    output_path = os.path.join(output_dir, output_filename)
    
    # Write the processed rules to the output file
    with open(output_path, 'w') as f:
        f.write('\n'.join(processed_rules) + '\n')
    
    print(f"Processed {conf_file} -> {output_path}")
