import os

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
        lines = f.readlines()
    
    # Remove lines starting with '#' or empty lines
    cleaned_lines = [line for line in lines if line.strip() and not line.strip().startswith('#')]
    
    # Create output filename with -strip.conf suffix
    output_filename = os.path.splitext(conf_file)[0] + "-strip.conf"
    output_path = os.path.join(output_dir, output_filename)
    
    # Write the cleaned content to the output file
    with open(output_path, 'w') as f:
        f.write(''.join(cleaned_lines))
    
    print(f"Processed {conf_file} -> {output_path}")
