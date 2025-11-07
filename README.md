
# LLM-Powered Automation for Cyber Security
# JetBrains Tast Aassignment

`Core Architecture:`

`Input: Git repository path, number of commits to scan, output file`
`Processing: Two-stage detection (regex/entropy, LLM analysis)`
`Output: JSON report with commit hash, file path, snippet, finding type, rationale, confidence lewel, ATT&CK, mitre_category, severity`
`*rationale - Based on type of finding, and part of diff it was found`
`*confidence lewel - arithmetic euristic`

## How setup
`python -m venv venv`  
`source venv/bin/activate`  
`pip install -r requirements.txt`  
`export ANTHROPIC_API_KEY="YOUR_ANTHROPIC_API_KEY"`  
## How to run
`python scan_git.py --repo "/path/to/the/repository/you/want/to/scan" --n 5 --out report.json`  
`--n`  stands for 5 last commits in the target repository.

Technical Report & Evaluation ipynb
https://colab.research.google.com/drive/1TR2dBqLM94JjyXJToJT7Jjyg0sI1xNJw?usp=sharing
