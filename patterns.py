patterns = [
    r'AKIA[0-9A-Z]{16}',  # AWS
    r'password\s*=\s*["\'][^"\']+["\']',
    r'api[_-]?key\s*=\s*["\'][^"\']+["\']',
    r'token\s*:?=\s*["\'][^"\']+["\']'
]

extra_patterns = [
    r'\b([A-Za-z0-9+/]{40})[ \r\n\'"`]',                  # AWS API Secret
    r'(?i)(%s).{0,20}([a-z0-9_.-~]{34})',                # Azure Client Secret
    r'\b(sl.[A-Za-z0-9-_]{130,140})\b',                  # Dropbox API Key
    r'EAACEdEose0cBA[0-9A-Za-z]+',                       # Facebook Access Token
    r'(?i)(?:pass|token|cred|secret|key)(?:.|[\n\r]){0,40}(\b[\x21-\x7e]{16,64}\b)',  # Generic
    r'\b((?:ghp|gho|ghu|ghs|ghr)_[a-zA-Z0-9]{36,255})\b',  # Github Token
    r'(xoxb|xoxp|xapp|xoxa|xoxr)-[0-9]{10,13}-[a-zA-Z0-9-]*',  # Slack Token
    r'[rs]k_live_[a-zA-Z0-9]{20,30}',                     # Stripe API Key
    r'(?i)(?:twitter)(?:.|[\n\r]){0,40}\b[1-9][0-9]+-[0-9a-zA-Z]{40}\b', # Twitter
    r'[0-9]+-[0-9A-Za-z_]{32}.apps.googleusercontent.com'  # Youtube/Google OAuth
]

all_patterns = patterns + extra_patterns

ignore_patterns = [
    r'^test',
    r'^example',
    r'placeholder',
    r'^mock',
    r'^dummy',
    r'^fake',
    r'YOUR_.*_HERE',
    r'^(?:123|1234|12345|123456|1234567|12345678).{0,10}$',
]


prompt_with_examples = """You are a security expert analyzing git diffs and commit messages for leaked secrets.
Classify it using cybersecurity standards such as MITRE ATT&CK, ENISA, and CWE. Return a valid JSON containing fields:
ATT&CK, mitre_category, enisa_category, severity, system_component, compliance.

EXAMPLES OF SECRETS:
- API keys: "api_key = 'sk_live_abc123xyz'"
- Passwords: "password = 'MySecretPass123'"
- SSH keys: "ssh-rsa AAAAB3NzaC1yc2EAAAABIwAAAQEArD1..."
- Tokens: "token = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...'"
- AWS keys: "AKIAIOSFODNN7EXAMPLE"
- GitHub tokens: "ghp_1234567890abcdef"
- Private keys: "-----BEGIN RSA PRIVATE KEY-----"
- OAuth tokens: "oauth_token = 'ya29.a0AfH6SM...'"
-   JWTs: "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJ..."


NOT SECRETS:
- Test data: "password = 'test123'"
- Dummy values: "secret = 'dummy_value'"
- Fake credentials: "username = 'fake_user', password = 'fake_pass'"
- Development placeholders: "const API_KEY = 'your-api-key-here';"
- Mock values: "api_key = 'mock_key_456'"
- Examples: "# Example: api_key = 'your-key-here'"
- Placeholders: "API_KEY = 'xxx'"
- Environment variables: "API_KEY = os.getenv('API_KEY')"

Analyze this text from commit {commit_hash}:

{diff_text} and commit message {commit_message}

Return output strictly in JSON format.

Output valid JSON:
{{
  "findings": [
    {{
  "commit_hash": "extract from diff header",
  "file_path": "extract from diff FILE PATH PATTERNS below",
  "snippet": "exact line containing secret",
  "finding_type": "api_key|password|token|aws_key|private_key|other",
  "rationale": "if it founded in commit message say In commit message. Then use RATIONALE PATTERNS below",
  "confidence": "HIGH|MEDIUM|LOW based on CONFIDENCE PATTERNS criteria below",
  "ATT&CK": "T1552...  appropriate subtechnique ID creteria below",
  "mitre_category": "Credential Access|Initial Access|etc",
  "severity": "critical|high|medium|low",

    }}
  ]
}}

ATT&CK PATTERNS ()
Subtechniques
T1552.007 - Container API
T1552.001 - Credentials In Files
T1552.002 - Credentials in Registry
T1552.003 - Bash History
T1552.004 - Private Keys
T1552.005 - Cloud Instance Metadata API
T1552.006 - Group Policy Preferences
T1552.008 - Chat Messages

RATIONALE PATTERNS (technical explanation):

API keys/tokens:
"Credential matches [service] authentication pattern with valid format [specifics]. High entropy string (X characters) located in [context]."

Passwords:
"Plaintext credential assigned to privileged account. No hashing/encryption applied. Found in [production/staging] environment configuration."

Private keys:
"Complete cryptographic key material including [RSA/ED25519] header/footer markers. Key grants [specific access]. Located in version-controlled [component]."

AWS credentials:
"Credential pair matching AWS IAM format (AKIA prefix + secret key). Grants programmatic access to cloud resources via [service]."

CONFIDENCE PATTERNS (assess likelihood):

- HIGH: Exact format match + high entropy (>4.5) + production context + no test/mock/placeholder indicators
- MEDIUM: Pattern match + moderate entropy (3.5-4.5) OR ambiguous context/path
- LOW: Weak pattern + low entropy (<3.5) OR test/example/dummy/placeholder indicators present

Examples:
- HIGH: "AKIA16CHARSTRING in backend/config/prod.py with AWS_SECRET_ACCESS_KEY pair"
- MEDIUM: "32-char hex string in api_key variable, path unclear"
- LOW: "password='test123' or API_KEY='your-key-here'"

DETECTION RULES:
- AWS: AKIA[A-Z0-9]{{16}}
- Private keys: -----BEGIN.*PRIVATE KEY-----
- SSH keys: -----BEGIN.*SSH PRIVATE KEY-----
- JWTs: eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJ...
- Generic secrets: High entropy (>4.5), suspicious variable names (api_key, password, secret, token)
- Ignore: test/mock/example/dummy/fake in path or value

FILE PATH PATTERNS
if line.startswith('diff --git'):
parts = line.strip().split()
    old_path, new_path = parts[2], parts[3]
    if old_path.startswith('a/') or new_path.startswith('b/'): 
      path[2:]
    if new_path == '/dev/null':
        return old_path
    return new_path

Return {{"findings": []}} if no secrets found.
Output ONLY JSON, nothing else."""
