import os
import json
import re
import logging

# Set up logging
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')

# Precompile regex
SECRULE_RE = re.compile(r'^SecRule\s+([^\s]+)\s+("[^"]*"|[^\s"]*)?\s*(".*"|.*)$', re.DOTALL)
SECMARKER_RE = re.compile(r'^SecMarker\s+"([^"]+)"$')

# Define parse_rule function
def parse_rule(rule_text, conf_file, comments, rule_count, total_rules):
    rule = {
        "file_name": os.path.splitext(conf_file)[0] + "-strip.conf",
        "comments": comments,
        "parsing_status": "success",
        "raw_rule": rule_text.replace(' \\ ', ' ')
    }
    
    # Match SecMarker
    secmarker_match = SECMARKER_RE.match(rule_text)
    if secmarker_match:
        rule["directive"] = "SecMarker"
        rule["rule_id"] = secmarker_match.group(1)
        rule["chain_id"] = None
        rule["chain_order"] = 0
        rule["paranoia_level"] = None
        rule["rule_category"] = '-'.join(conf_file.split('-')[1:-1]) if '-' in conf_file else "Generic"
        rule["attack_vectors"] = []
        rule["confidence_level"] = None
        rule["rule_source"] = "OWASP_CRS/4.16.0-dev"
        rule["execution_phase"] = None
        logging.debug(f"Parsed SecMarker: {rule['rule_id']}")
        return rule
    
    # Match SecRule
    secrule_match = SECRULE_RE.match(rule_text)
    if secrule_match:
        rule["directive"] = "SecRule"
        rule["variables"] = [v.strip() for v in secrule_match.group(1).split('|') if v.strip()]
        rule["operator"] = secrule_match.group(2).strip('"') if secrule_match.group(2) else ""
        actions_str = secrule_match.group(3).strip('"') if secrule_match.group(3) else ""
        
        actions = {}
        tags = []
        transforms = []
        setvars = []
        ctl = []
        
        # Parse actions
        action_parts = []
        current_part = ""
        in_quotes = False
        i = 0
        while i < len(actions_str):
            char = actions_str[i]
            if char == '"' and (i == 0 or actions_str[i-1] != '\\'):
                in_quotes = not in_quotes
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
                tags.append(part[4:].strip('"\''))
            elif part.startswith('t:'):
                transforms.append(part[2:].strip('"\''))
            elif part.startswith('setvar:'):
                if '=' in part[7:]:
                    var, val = part[7:].split('=', 1)
                    score_type = "attack" if "score" in var.lower() and "anomaly" not in var.lower() else ("anomaly" if "anomaly" in var.lower() else "other")
                    setvars.append({"variable": var.strip('"\''), "value": val.strip('"\''), "score_type": score_type})
            elif part.startswith('ctl:'):
                ctl.append(part[4:].strip('"\''))
            elif ':' in part:
                key, value = part.split(':', 1)
                actions[key.strip()] = value.strip('"\'')
            else:
                actions[part] = True
        
        actions['tags'] = tags
        actions['transforms'] = transforms
        actions['setvars'] = setvars
        actions['ctl'] = ctl
        rule["rule_id"] = actions.get('id', f"unknown-{rule_count}")
        
        # Paranoia level
        rule["paranoia_level"] = next((t.split('/')[1] for t in tags if t.startswith('paranoia-level/')), None)
        if not rule["paranoia_level"] and rule["variables"] == ["TX:DETECTION_PARANOIA_LEVEL"]:
            pl_match = re.match(r'@lt (\d+)', rule["operator"])
            if pl_match:
                rule["paranoia_level"] = f"PL{pl_match.group(1)}"
        
        # Additional fields
        rule["rule_category"] = '-'.join(conf_file.split('-')[1:-1]) if '-' in conf_file else "Generic"
        rule["attack_vectors"] = [t.split('/')[-1] for t in tags if t.startswith('capec/')] + ([actions.get('msg', '').split(':')[-1].strip()] if actions.get('msg') and ':' in actions.get('msg') else [])
        rule["confidence_level"] = "high" if actions.get('severity') == "CRITICAL" else ("medium" if actions.get('severity') == "WARNING" else "low")
        rule["rule_source"] = actions.get('ver', "OWASP_CRS/4.16.0-dev")
        rule["execution_phase"] = {1: "request_headers", 2: "request_body", 3: "response_headers", 4: "response_body", 5: "logging"}.get(int(actions.get('phase', 0)), None)
        
        if not actions.get('id'):
            rule["parsing_status"] = "partial"
            logging.warning(f"Partial parse for rule {rule_count} in {conf_file}: missing id")
        
        logging.debug(f"Parsed SecRule: {rule['rule_id']} with {len(tags)} tags, {len(transforms)} transforms")
        return rule
    
    rule["parsing_status"] = "failed"
    logging.warning(f"Failed to parse rule {rule_count} in {conf_file}: {rule_text[:100]}...")
    return rule

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
    current_comments = []
    in_rule = False
    chain_id = None
    chain_order = 0
    rule_count = 0
    total_rules = sum(1 for line in lines if line.strip().startswith(('SecRule ', 'SecMarker ')))

    # Process lines
    for line in lines:
        line = line.rstrip('\n')
        if line.strip().startswith('#'):
            current_comments.append(line.strip('#').strip())
            continue
        if not line.strip():
            continue
        
        if line.strip().startswith(('SecRule ', 'SecMarker ')):
            if current_rule:
                rule_text = ' '.join(current_rule).strip()
                rule_text = ' '.join(rule_text.split())
                parsed_rule = parse_rule(rule_text, conf_file, current_comments, rule_count, total_rules)
                if parsed_rule:
                    if chain_id and parsed_rule.get("actions", {}).get("chain", False):
                        parsed_rule["chain_id"] = chain_id
                        parsed_rule["chain_order"] = chain_order
                        chain_order += 1
                    elif chain_id and not parsed_rule.get("actions", {}).get("chain", False):
                        parsed_rule["chain_id"] = chain_id
                        parsed_rule["chain_order"] = chain_order
                        chain_id = None
                        chain_order = 0
                    else:
                        chain_id = parsed_rule["rule_id"] if parsed_rule.get("actions", {}).get("chain", False) and not parsed_rule["rule_id"].startswith("unknown-") else None
                        chain_order = 1 if chain_id else 0
                    rules.append(parsed_rule)
                current_rule = []
                current_comments = []
                rule_count += 1
            in_rule = True
            current_rule.append(line.strip())
        elif in_rule and line.strip().startswith('\\'):
            current_rule.append(line.strip()[1:].strip())
        elif in_rule:
            current_rule.append(line.strip())
    
    if current_rule:
        rule_text = ' '.join(current_rule).strip()
        rule_text = ' '.join(rule_text.split())
        parsed_rule = parse_rule(rule_text, conf_file, current_comments, rule_count, total_rules)
        if parsed_rule:
            if chain_id:
                parsed_rule["chain_id"] = chain_id
                parsed_rule["chain_order"] = chain_order
            rules.append(parsed_rule)
        rule_count += 1
    
    # Validate rule count
    if rule_count != total_rules:
        logging.warning(f"Parsed {rule_count} of {total_rules} rules in {conf_file}; missing rules detected")
    
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
