
# LLM-Powered Automation for Cyber Security
# JetBrains Test Assignment
A CLI tool that scans git repository for secrets exposure.


Core Architecture:


Input: Git repository path, number of commits to scan, output file  

Processing: Two-stage detection (regex/entropy, LLM analysis)  

Output: JSON report with commit hash, file path, snippet, finding type, rationale, confidence level, ATT&CK, mitre_category, severity

*rationale - Based on type of finding, and part of diff it was found -- message or diff

*confidence level - arithmetic heuristic  


## How setup
`python -m venv venv`  
`source venv/bin/activate`  
`pip install -r requirements.txt`  
`export ANTHROPIC_API_KEY="YOUR_ANTHROPIC_API_KEY"`  
## How to run
`python scan_git.py --repo "/path/to/the/repository/you/want/to/scan" --n 5 --out report.json`  
`--n`  stands for 5 last commits in the target repository.  

Programm was tested with Python 3.11.7  

## Technical Report & Evaluation ipynb


The extensive report on the calculations, data analysis, model evaluation, charts, as well as a description of the obstacles, and ideas for further development is at the link below. Repo holds also an archive with a synthetic tagged dataset of secrets, and model reports to check the calculations performed in the Python notebook.   

https://colab.research.google.com/drive/1TR2dBqLM94JjyXJToJT7Jjyg0sI1xNJw?usp=sharing

 

I've found a few interesting obstacles with couple of different kinds of language models also quantized running locally.  


most interested in Sonnet 4.5 API, Foundation-Sec-8B-Instruct-Q8_0-GGUF, Foundation-Sec Integration Issue, Foundation-Sec-8B-Q4_K_M-GGUF 

