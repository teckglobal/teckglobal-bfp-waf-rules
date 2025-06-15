# teckglobal-bfp-waf-rules

## Overview
This public repository stores validated JSON rules for the Teckglobal BFP WordPress plugin (WAF), converted from the OWASP Core Rule Set (CRS). These rules protect WordPress sites from attacks like SQL injection, XSS, and RFI. The repository also includes scripts and GitHub Actions workflows to process CRS `.conf` files, generating stripped or reformatted outputs for integration with the WAF plugin.

## Source
- Rules are generated from CRS (version 4.16.0) using a private parsing repository (`teckglobal-bfp-crs-parser`).
- Converted from `.conf` to JSON using `python` and validated before public release.
- Original `.conf` files are stored in the `rules/` directory, sourced from CRS 4.16.0.

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
   - Use the Teckglobal BFP plugin’s `update-waf-rules.php` to ingest JSON rules into the WAF database.
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
3. **Use Stripped `.conf` Files**:
   - Access stripped `.conf` files from `stripped_bash_files/` or `stripped_conf_files/` for lightweight rule deployment.
   - Example: `REQUEST-905-COMMON-EXCEPTIONS-strip_bash.conf` or `REQUEST-905-COMMON-EXCEPTIONS-strip_conf.conf`.
4. **Test Rules**:
   - Deploy in a staging environment.
   - Test with ZAP Proxy or similar tools using attack payloads.
   - Monitor WAF logs for rule matches.

## Directory Structure
- `rules/`: Contains original CRS `.conf` files (e.g., `REQUEST-905-COMMON-EXCEPTIONS.conf`) and JSON rule files (e.g., `REQUEST-942-APPLICATION-ATTACK-SQLI.json`). Total: 665 rules (CRS 4.16.0).
- `scripts/`: Contains processing scripts:
  - `strip_crs_conf.sh`: Bash script to strip comments and empty lines from `.conf` files.
  - Python scripts (WIP): For reformatting `.conf` to one-line rules or converting to JSON.
- `stripped_bash_files/`: Output directory for Bash-stripped `.conf` files (e.g., `REQUEST-905-COMMON-EXCEPTIONS-strip_bash.conf`).
- `stripped_conf_files/`: Output directory for Python-stripped one-line `.conf` files (e.g., `REQUEST-905-COMMON-EXCEPTIONS-strip_conf.conf`).
- `.github/workflows/`: Contains GitHub Actions workflows for automated rule processing.

## GitHub Actions Workflows
The repository includes three workflows in `.github/workflows/` to process CRS rules:

1. **`clean-bash.yml`**:
   - **Task**: Strips comments and empty lines from all `.conf` files in `rules/`, preserving the original CRS rule structure (including multi-line formats with `\` continuation characters).
   - **Script**: Uses `scripts/strip_crs_conf.sh` (Bash).
   - **Input**: All `.conf` files in `rules/` (e.g., `REQUEST-905-COMMON-EXCEPTIONS.conf`).
   - **Output**: Stripped files in `stripped_bash_files/` with `-strip_bash.conf` suffix (e.g., `REQUEST-905-COMMON-EXCEPTIONS-strip_bash.conf`).
   - **Status**: Fully functional.
   - **Trigger**: Runs on push to `main` or manual dispatch.

2. **`clean-conf.yml`**:
   - **Task**: Strips all non-rule content (comments, empty lines) from `.conf` files and reformats rules into a single-line format, removing `\` continuation characters while preserving rule functionality (e.g., `\/` for threat detection).
   - **Script**: Uses a Python script in `scripts/` (not specified in repo, assumed functional).
   - **Input**: All `.conf` files in `rules/`.
   - **Output**: One-line rule files in `stripped_conf_files/` with `-strip_conf.conf` suffix (e.g., `REQUEST-905-COMMON-EXCEPTIONS-strip_conf.conf`).
   - **Status**: Fully functional.
   - **Trigger**: Runs on push to `main` or manual dispatch.

3. **`clean-json.yml`**:
   - **Task**: Converts all CRS `.conf` files in `rules/` to JSON format, preserving rule sections and structure for compatibility with the Teckglobal BFP WAF plugin.
   - **Script**: Uses a Python script in `scripts/` (not specified, under development).
   - **Input**: All `.conf` files in `rules/`.
   - **Output**: JSON files in `rules/` (e.g., `REQUEST-942-APPLICATION-ATTACK-SQLI.json`).
   - **Status**: Work in progress, not fully functional.
   - **Trigger**: Runs on push to `main` or manual dispatch.

## Notes
- **licensed: This project uses rules from the OWASP Core Rule Set (CRS), licensed under the Apache Software License version 2.0. See https://coreruleset.org for details.
- **Updates**: Rules and stripped files are periodically updated from the private parsing repo (`teckglobal-bfp-crs-parser`) after validation.
- **Compatibility**: JSON rules and stripped `.conf` files are designed for the Teckglobal BFP Wordpress plugin.
- **Workflow Outputs**: Stripped files in `stripped_bash_files/` and `stripped_conf_files/` are ready for deployment; JSON conversion in `clean-json.yml` is still being developed.
- **Issues**: Report problems via GitHub issues or contact the Teckglobal team.
