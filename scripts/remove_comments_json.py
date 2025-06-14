import os
import json
import re

# Input and output directories
input_dir = "rules"
output_dir = "stripped_files"

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
    
    rules = []
    current_rule = []
    in_rule = False

    # Process lines
    for line in lines:
        line = line.rstrip('\n')
        if not line.strip() or line.strip().startswith('#'):
            continue
        
        if line.strip().startswith(('SecRule ', 'SecMarker ')):
            if current_rule:
                rule_text = ' '.join(current_rule).strip()
                rule_text = ' '.join(rule_text.split())
                rules.append(parse_rule(rule_text, conf_file))
                current_rule = []
            in_rule = True
            current_rule.append(line.strip())
        elif in_rule and line.strip().startswith('\\'):
            current_rule.append(line.strip()[1:].strip())
        elif in_rule:
            current_rule.append(line.strip())
    
    if current_rule:
        rule_text = ' '.join(current_rule).strip()
        rule_text = ' '.join(rule_text.split())
        rules.append(parse_rule(rule_text, conf_file))
    
    # Create output filename with -strip.json suffix
    output_filename = os.path.splitext(conf_file)[0] + "-strip.json"
    output_path = os.path.join(output_dir, output_filename)
    
    # Write JSON to output file
    try:
        with open(output_path, 'w') as f:
            json.dump(rules, f, indent=2)
        print(f"Processed {conf_file} -> {output_path} ({len(rules)} rules)")
    except Exception as e:
        print(f"Error writing {output_path}: {e}")
        continue

def parse_rule(rule_text, conf_file):
    rule = {
        "file_name": os.path.splitext(conf_file)[0] + "-strip.conf"
    }
    
    # Match SecRule or SecMarker
    secrule_match = re.match(r'^SecRule\s+([^"]+)"([^"]+)"\s+"([^"]+)"$', rule_text)
    secmarker_match = re.match(r'^SecMarker\s+"([^"]+)"$', rule_text)
    
    if secmarker_match:
        rule["directive"] = "SecMarker"
        rule["rule_id"] = secmarker_match.group(1)
        return rule
    
    if secrule_match:
        rule["directive"] = "SecRule"
        rule["variables"] = [v.strip() for v in secrule_match.group(1).split('|') if v.strip()]
        rule["operator"] = secrule_match.group(2)
        actions_str = secrule_match.group(3)
        
        actions = {}
        tags = []
        transforms = []
        setvars = []
        
        # Parse actions
        action_parts = []
        current_part = ""
        in_quotes = False
        for char in actions_str:
            if char == '"' and (not current_part.endswith('\\')):
                in_quotes = not in_quotes
                current_part += char
            elif char == ',' and not in_quotes:
                action_parts.append(current_part.strip())
                current_part = ""
            else:
                current_part += char
        if current_part.strip():
            action_parts.append(current_part.strip())
        
        for part in action_parts:
            part = part.strip()
            if part.startswith('tag:'):
                tags.append(part[5:-1] if part.endswith('"') else part[5:])
            elif part.startswith('t:'):
                transforms.append(part[3:-1] if part.endswith('"') else part[3:])
            elif part.startswith('setvar:'):
                if ':' in part[7:]:
                    var, val = part[7:].split('=', 1)
                    setvars.append({"variable": var.strip('"'), "value": val.strip('"')})
            elif ':' in part:
                key, value = part.split(':', 1)
                actions[key.strip()] = value.strip('"')
            else:
                actions[part] = True
        
        actions['tags'] = tags
        actions['transforms'] = transforms
        actions['setvars'] = setvars
        rule["rule_id"] = actions.get('id', '')
        rule["actions"] = actions
        return rule
    
    return None
