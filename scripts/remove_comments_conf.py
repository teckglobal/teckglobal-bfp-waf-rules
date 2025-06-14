import os

# Input and output directories
input_dir = "rules"
output_dir = "stripped_conf_files"

# Ensure input directory exists
if not os.path.isdir(input_dir):
    print(f"Error: Input directory '{input_dir}' does not exist")
    exit(1)

# Create output directory if it doesn't exist
os.makedirs(output_dir, exist_ok=True)

# Get list of .conf files in the rules directory
conf_files = [f for f in os.listdir(input_dir) if f.endswith('.conf')]

if not conf_files:
    print(f"No .conf files found in '{input_dir}'")
    exit(0)

for conf_file in conf_files:
    # Read the input file
    input_path = os.path.join(input_dir, conf_file)
    try:
        with open(input_path, 'r') as f:
            lines = f.readlines()
    except Exception as e:
        print(f"Error reading {conf_file}: {e}")
        continue
    
    # Initialize variables
    processed_rules = []
    current_rule = []
    in_rule = False

    # Process lines
    for line in lines:
        line = line.rstrip('\n')
        # Skip comments and empty lines
        if not line.strip() or line.strip().startswith('#'):
            continue
        
        # Check if line starts a new rule
        if line.strip().startswith(('SecRule ', 'SecMarker ')):
            # Save previous rule if exists
            if current_rule:
                # Collapse rule into single line
                rule_text = ' '.join(current_rule).strip()
                rule_text = ' '.join(rule_text.split())  # Normalize whitespace
                processed_rules.append(rule_text)
                current_rule = []
            in_rule = True
            current_rule.append(line.strip())
        elif in_rule and line.strip().startswith('\\'):
            # Continuation line, append content after '\'
            current_rule.append(line.strip()[1:].strip())
        elif in_rule:
            # Part of multi-line rule
            current_rule.append(line.strip())
    
    # Save the last rule if exists
    if current_rule:
        rule_text = ' '.join(current_rule).strip()
        rule_text = ' '.join(rule_text.split())  # Normalize whitespace
        processed_rules.append(rule_text)
    
    # Create output filename with -strip.conf suffix
    output_filename = os.path.splitext(conf_file)[0] + "-strip.conf"
    output_path = os.path.join(output_dir, output_filename)
    
    # Write the processed rules to the output file
    try:
        with open(output_path, 'w') as f:
            f.write('\n'.join(processed_rules) + '\n')
        print(f"Processed {conf_file} -> {output_path} ({len(processed_rules)} rules)")
    except Exception as e:
        print(f"Error writing {output_path}: {e}")
        continue
