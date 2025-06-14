import requests
import os
from urllib.parse import urljoin

# GitHub repository details
repo_api_url = "https://api.github.com/repos/teckglobal/teckglobal-bfp-waf-rules/contents/rules"
raw_base_url = "https://raw.githubusercontent.com/teckglobal/teckglobal-bfp-waf-rules/main/rules/"
output_dir = "stripped_files"

# Create output directory
os.makedirs(output_dir, exist_ok=True)

# Fetch list of .conf files from the repository
headers = {"Accept": "application/vnd.github.v3+json"}
# If private repo, uncomment and use PAT
# headers["Authorization"] = f"token {os.getenv('GITHUB_TOKEN')}"
response = requests.get(repo_api_url, headers=headers)
if response.status_code == 200:
    files = response.json()
    conf_files = [f['name'] for f in files if f['name'].endswith('.conf')]
else:
    print(f"Failed to fetch file list: HTTP {response.status_code}")
    conf_files = []

for conf_file in conf_files:
    # Download the file
    file_url = urljoin(raw_base_url, conf_file)
    response = requests.get(file_url)
    
    if response.status_code == 200:
        # Remove lines starting with '#' or empty lines
        lines = response.text.splitlines()
        cleaned_lines = [line for line in lines if line.strip() and not line.strip().startswith('#')]
        
        # Create output filename with -strip.conf suffix
        output_filename = os.path.splitext(conf_file)[0] + "-strip.conf"
        output_path = os.path.join(output_dir, output_filename)
        
        # Write the cleaned content to the output file
        with open(output_path, 'w') as f:
            f.write('\n'.join(cleaned_lines) + '\n')
        
        print(f"Processed {conf_file} -> {output_path}")
    else:
        print(f"Failed to download {conf_file}: HTTP {response.status_code}")