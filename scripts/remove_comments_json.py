import os
import json
import re
import logging

# Set up logging
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')

# Define parse_rule function
def parse_rule(rule_text, conf_file):
    rule = {
        "file_name": os.path.splitext(conf_file)[0] + "-strip.conf"
    }
    
    # Match SecMarker
    secmarker_match = re.match(r'^SecMarker\s+"([^"]+)"$', rule_text)
    if secmarker_match:
        rule["directive"] = "SecMarker"
        rule["rule_id"] = secmarker_match.group(1)
        logging.debug(f"Parsed SecMarker: {rule['rule_id']}")
        return rule
    
    # Match SecRule with flexible parsing
    secrule_match = re.match(r'^SecRule\s+([^\s]+)(?:\s+("[^"]*"|[^\s]+))?(?:\s+(.+))?$', rule_text, re.DOTALL)
    if secrule_match:
        rule["directive"] = "SecRule"
        rule["variables"] = [v.strip() for v in secrule_match.group(1).split('|') if v.strip()]
        rule["operator"] = secrule_match.group(2).strip('"') if secrule_match.group(2) else ""
        actions_str = secrule_match.group(3).strip('"') if secrule_match.group(3) else ""
        
        actions = {}
        tags = []
        transforms = []
        setvars = []
        
        # Parse actions, handling commas outside quotes
        action_parts = []
        current_part = ""
        in_quotes = False
        i = 0
        while i < len(actions_str):
            char = actions_str[i]
            if char == '"' and (i == 0 or actions_str[i-1] != '\\'):
                in_quotes = not in_quotes
                current_part += char
            elif char == ',' and not in_quotes:
                if current_part.strip():
                    action_parts.append(current_part.strip())
                current_part = ""
            else:
                current_part += char
            i += 1
        if current_part.strip():
            action_parts.append(current_part.strip())
        
        for part in action_parts:
            part = part.strip()
            if not part:
                continue
            if part.startswith('tag:'):
                tag_value = part[4:].strip('"\'')
                tags.append(tag_value)
            elif part.startswith('t:'):
                transform_value = part[2:].strip('"\'')
                transforms.append(transform_value)
            elif part.startswith('setvar:'):
                if '=' in part[7:]:
                    var, val = part[7:].split('=', 1)
                    setvars.append({"variable": var.strip('"\''), "value": val.strip('"\'')})
            elif ':' in part and not part.startswith('ctl:'):
                key, value = part.split(':', 1)
                actions[key.strip()] = value.strip('"\'')
            else:
                actions[part] = True
        
        actions['tags'] = tags
        actions['transforms'] = transforms
        actions['setvars'] = setvars
        rule["rule_id"] = actions.get('id', '')
        rule["actions"] = actions
        
        logging.debug(f"Parsed SecRule: {rule['rule_id']} with {len(tags)} tags, {len(transforms)} transforms")
        return rule
    
    logging.warning(f"Failed to parse rule: {rule_text[:100]}...")
    return None

# Input and output directories
input_dir = "rules"
output_dir = "stripped_json_files"

# Ensure input directory exists
if not os.path.isdir(input_dir):
    logging.error(f"Input directory '{input_dir}' does not exist")
    exit(1)

# Create output directory if it doesn't exist
os.makedirs(output_dir, exist_ok=True)

# Get list of .conf files in the rules directory
conf_files = [f for f in os.listdir(input_dir) if f.endswith('.conf')]

if not conf_files:
    logging.info(f"No .conf files found in '{input_dir}'")
    exit(0)

for conf_file in conf_files:
    # Read the input file
    input_path = os.path.join(input_dir, conf_file)
    try:
        with open(input_path, 'r') as f:
            lines = f.readlines()
    except Exception as e:
        logging.error(f"Error reading {conf_file}: {e}")
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
                parsed_rule = parse_rule(rule_text, conf_file)
                if parsed_rule:
                    rules.append(parsed_rule)
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
        parsed_rule = parse_rule(rule_text, conf_file)
        if parsed_rule:
            rules.append(parsed_rule)
    
    # Create output filename with -strip.json suffix
    output_filename = os.path.splitext(conf_file)[0] + "-strip.json"
    output_path = os.path.join(output_dir, output_filename)
    
    # Write JSON to output file
    try:
        with open(output_path, 'w') as f:
            json.dump(rules, f, indent=2)
        logging.info(f"Processed {conf_file} -> {output_path} ({len(rules)} rules)")
    except Exception as e:
        logging.error(f"Error writing {output_path}: {e}")
        continue
