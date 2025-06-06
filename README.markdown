# teckglobal-bfp-waf-rules

## Overview
This public repository stores validated JSON rules for the Teckglobal BFP WordPress WAF plugin, converted from the OWASP Core Rule Set (CRS). These rules are used to protect WordPress sites from attacks like SQL injection, XSS, and RFI.

## Source
- Rules are generated from CRS (version 4.16.0) using a private parsing repository (`teckglobal-bfp-msc-parser`).
- Converted from `.conf` to JSON using `msc_pyparser` and validated before public release.

## Usage
1. **Fetch Rules**:
   - Access JSON files (e.g., `REQUEST-942-APPLICATION-ATTACK-SQLI.json`) via raw URLs:
     ```bash
     https://raw.githubusercontent.com/teckglobal/teckglobal-bfp-waf-rules/main/rules/REQUEST-942-APPLICATION-ATTACK-SQLI.json
     ```
   - Or clone the repository:
     ```bash
     git clone https://github.com/teckglobal/teckglobal-bfp-waf-rules.git
     ```
2. **Integrate with WAF**:
   - Use the Teckglobal BFP plugin’s `update-waf-rules.php` to ingest rules into the WAF database.
   - Example PHP snippet:
     ```php
     $rule_files = [
         'https://raw.githubusercontent.com/teckglobal/teckglobal-bfp-waf-rules/main/rules/REQUEST-942-APPLICATION-ATTACK-SQLI.json',
         // Add other files
     ];
     foreach ($rule_files as $url) {
         $response = wp_remote_get($url);
         $json = wp_remote_retrieve_body($response);
         $rules = json_decode($json, true);
         // Insert into database
     }
     ```
3. **Test Rules**:
   - Deploy in a staging environment.
   - Test with ZAP Proxy or similar tools using attack payloads.
   - Monitor WAF logs for rule matches.

## Directory Structure
- `rules/`: Contains JSON rule files (e.g., `REQUEST-905-COMMON-EXCEPTIONS.json`).
- Total: 665 rules (CRS 4.16.0).

## Notes
- **Updates**: Rules are periodically updated from the private parsing repo after validation.
- **Compatibility**: Designed for the Teckglobal BFP WAF plugin.
- **Issues**: Report problems via GitHub issues or contact the Teckglobal team.