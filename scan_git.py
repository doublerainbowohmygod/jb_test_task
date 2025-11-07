import re
import json
import math
from collections import Counter
from patterns import all_patterns, ignore_patterns, prompt_with_examples
import subprocess
import anthropic
import os
from tqdm import tqdm
import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed
import sys

API_KEY = os.getenv("ANTHROPIC_API_KEY")

try:
    compiled_patterns = [re.compile(p, re.IGNORECASE) for p in all_patterns]
    ignore_regex = re.compile('|'.join(ignore_patterns), re.IGNORECASE)
except re.error as e:
    print(f"Error compiling regex patterns: {e}")
    sys.exit(1)


def cal_from_comandline(repo_path, n):
    try:
        result = subprocess.run(
            ['git', 'log', f'-n{n}', '--all', '--date-order', '--pretty=format:%H%x09%s'],
            cwd=repo_path,
            capture_output=True,
            text=True,
            check=True
    )
    except (subprocess.CalledProcessError, FileNotFoundError) as e:
        print(f"Git error: {e}")
        return []

    lines = result.stdout.splitlines()
    commits = []
    for line in lines:
        if not line.strip():
            continue

        parts = line.split('\t', 1)
        if len(parts) == 2:
            commit_hash, message = parts
            try:
                diff_result = subprocess.run(
                    ['git', 'show', commit_hash],
                    cwd=repo_path,
                    capture_output=True,
                    text=True,
                    check=True
                )
                commits.append({
                    'commit_hash': commit_hash.strip(),
                    'message': message.strip(),
                    'diff': diff_result.stdout
                })
            except subprocess.CalledProcessError:
                commits.append({
                    'commit_hash': commit_hash.strip(),
                    'message': message.strip(),
                    'diff': ""
                })

    return commits


def calculate_entropy(text):
    if not text or not isinstance(text, str):
        return 0

    try:
        counter = Counter(text)
        length = len(text)
        entropy = -sum((count/length) * math.log2(count/length) for count in counter.values())
        return entropy
    except Exception:
        return 0
    

def secret_alike_in_line(line, use_entropy=True, min_entropy=4.5, min_length=8):
    if not line or not isinstance(line, str):
        return False
    for regex in compiled_patterns:
        try:
            match = regex.search(line)
            if match and not ignore_regex.search(match.group(0)):
                return True
        except Exception:
            continue

    if use_entropy:
        try:
            words = re.findall(r'["\']([^"\']{' + str(min_length) + r',})["\']', line)
            for word in words:
                if ignore_regex.search(word):
                    continue
                entropy = calculate_entropy(word)
                if entropy >= min_entropy:

                    return True
        except Exception:
            pass
    return False


def parse_json_response(text):
    if not text or not isinstance(text, str):
        return {"findings": [], "error": "Empty response"}
    try:
        if "```" in text:
            json_str = text.split("```")[1].replace("json", "").strip()
        else:
            json_str = text.strip()
        result = json.loads(json_str)
    
        if 'findings' not in result:
            result['findings'] = []
        if not isinstance(result['findings'], list):
            result['findings'] = []
        return result
    
    except json.JSONDecodeError:
        return {"findings": [], "error": "Parse failed", "raw": text}


def analyze_diff_with_claude(commit_message, diff_text, commit_hash):
    claude_client = anthropic.Anthropic(api_key=API_KEY)
    prompt = prompt_with_examples.format(diff_text=diff_text, 
                                         commit_hash=commit_hash,
                                         commit_message=commit_message
                                         )

    try:
        claude_response = claude_client.messages.create(
            model="claude-sonnet-4-20250514",
            max_tokens=2048,
            messages=[
                {"role": "user", "content": prompt}
            ]
        )
        result_text = claude_response.content[0].text
        return parse_json_response(result_text)
    except Exception as e:
        print(f"API Error: {e}")
        return {"findings": [], "error": str(e)}


def build_report(analysis_results):
    if not analysis_results:
        return []
    
    report = []
    for result in analysis_results:
        if not result:
            continue
        findings = result.get('findings', [])
        for finding in findings:
            if not finding:
                continue
            report_entry = {
                'commit_hash': finding.get('commit_hash'),
                'file_path': finding.get('file_path'),
                'snippet': finding.get('snippet'),
                'finding_type': finding.get('finding_type'),
                'rationale': finding.get('rationale'),
                'confidence': finding.get('confidence'),
                'ATT&CK': finding.get('ATT&CK'),
                'mitre_category': finding.get('mitre_category'),
                'severity': finding.get('severity'),
            }
            report.append(report_entry)

    return report


def analyze(list_commit_data, report_file_name):
    if not list_commit_data:
        with open(report_file_name, 'w') as f:
            json.dump({'diff_counter': {'checked': 0, 'found_in': 0}, 'results': []}, f)
        return
    secrets_in_both = list(filter(
        lambda c: secret_alike_in_line(c['diff']) or secret_alike_in_line(c['message']),
        list_commit_data
    ))

    if not secrets_in_both: 
        with open(report_file_name, 'w') as f:
            json.dump({'diff_counter': {'checked': 0, 'found_in': 0}, 'results': []}, f)
        return

    analysis_results = []
    with ThreadPoolExecutor(max_workers=min(5, len(secrets_in_both))) as executor:
        future_to_commit = {
            executor.submit(
                analyze_diff_with_claude,
                commit['message'],
                commit['diff'],
                commit['commit_hash']
            ): commit
            for commit in secrets_in_both
        }

        for future in tqdm(as_completed(future_to_commit), total=len(secrets_in_both),
                           desc="Analyzing commits"):
            commit = future_to_commit[future]
            try:
                result = future.result(timeout=60)
                analysis_results.append(result)
            except Exception as e:
                print(f"Error analyzing {commit['commit_hash'][:8]}: {e}")
                analysis_results.append({"findings": [], "error": str(e)})

    final_report = {
        'diff_counter': {
            'checked': len(analysis_results),
            'found_in':   sum(1 for found in analysis_results if found and found.get('findings'))
        },
        'results': build_report(analysis_results)
    }

    try:
        with open(report_file_name, 'w') as f:
            json.dump(final_report, f, indent=2)
    except Exception as e:
        print(f"Error saving report: {e}")


def main():
    if not API_KEY:
        print("Error: ANTHROPIC_API_KEY environment variable not set.")
        sys.exit(1)

    parser = argparse.ArgumentParser(description='Secret scanning tool')
    parser.add_argument('--repo', required=True, help='Repository path or URL')
    parser.add_argument('--n', type=int, default=10, help='Number of commits to scan (default: 10)')
    parser.add_argument('--out', default='report.json', help='Output file (default: report.json)')

    args = parser.parse_args()

    if args.n <= 0:
        print("Error: Number of commits must be positive")
        return

    enriched_commits = cal_from_comandline(args.repo, args.n)
    if not enriched_commits:
        print("No commits found or error accessing repository")
        return
    analyze(enriched_commits, args.out)
    print(f"Scan complete. Report saved to {args.out}")


if __name__ == "__main__":
    main()
