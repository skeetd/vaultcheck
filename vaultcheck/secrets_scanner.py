import math
import os
import re
from dataclasses import dataclass
from pathlib import Path

SKIP_EXTENSIONS = {
    ".png", ".jpg", ".jpeg", ".gif", ".ico", ".svg", ".woff", ".woff2",
    ".ttf", ".eot", ".mp4", ".mp3", ".zip", ".gz", ".tar", ".pdf",
    ".pyc", ".pyo", ".so", ".dll", ".exe",
}
SKIP_DIRS = {
    ".git", "node_modules", "__pycache__", ".venv", "venv", "env",
    "dist", "build", ".pytest_cache", ".mypy_cache",
}
# Package lock files contain legitimate high-entropy hashes everywhere
SKIP_FILES = {
    "package-lock.json", "yarn.lock", "poetry.lock", "Pipfile.lock",
    "composer.lock", "Gemfile.lock", "go.sum", "Cargo.lock",
}

_ALLOWLIST = re.compile(
    r"(?i)os\.environ|os\.getenv|process\.env|getenv|"
    r"your[_-]|example[_-]|placeholder|<[a-z_]+>|"
    r"\$\{[A-Za-z_]+\}|\$[A-Z_]+|"
    r"xxx+|todo|changeme|replace.?me|insert.?here|"
    r"test.?key|dummy|fake|sample|demo"
)

PATTERNS = [
    # Private keys
    {"name": "RSA Private Key",      "pattern": r"-----BEGIN RSA PRIVATE KEY-----",    "severity": "CRITICAL", "category": "private_key"},
    {"name": "EC Private Key",       "pattern": r"-----BEGIN EC PRIVATE KEY-----",     "severity": "CRITICAL", "category": "private_key"},
    {"name": "OpenSSH Private Key",  "pattern": r"-----BEGIN OPENSSH PRIVATE KEY-----","severity": "CRITICAL", "category": "private_key"},
    {"name": "PEM Private Key",      "pattern": r"-----BEGIN PRIVATE KEY-----",        "severity": "CRITICAL", "category": "private_key"},
    # AWS
    {"name": "AWS Access Key ID",         "pattern": r"\bAKIA[0-9A-Z]{16}\b",                                                    "severity": "CRITICAL", "category": "cloud"},
    {"name": "AWS Secret Access Key",     "pattern": r"(?i)aws.{0,20}(?:secret|key).{0,30}['\"][0-9a-zA-Z/+]{40}['\"]",         "severity": "CRITICAL", "category": "cloud"},
    # GitHub
    {"name": "GitHub PAT (classic)",      "pattern": r"ghp_[0-9a-zA-Z]{36}",           "severity": "CRITICAL", "category": "vcs"},
    {"name": "GitHub OAuth Token",        "pattern": r"gho_[0-9a-zA-Z]{36}",           "severity": "CRITICAL", "category": "vcs"},
    {"name": "GitHub App Token",          "pattern": r"ghs_[0-9a-zA-Z]{36}",           "severity": "CRITICAL", "category": "vcs"},
    {"name": "GitHub Fine-grained PAT",   "pattern": r"github_pat_[0-9a-zA-Z_]{82}",  "severity": "CRITICAL", "category": "vcs"},
    # Stripe
    {"name": "Stripe Live Secret Key",      "pattern": r"sk_live_[0-9a-zA-Z]{24,}",       "severity": "CRITICAL", "category": "payment"},
    {"name": "Stripe Live Publishable Key", "pattern": r"pk_live_[0-9a-zA-Z]{24,}",       "severity": "HIGH",     "category": "payment"},
    {"name": "Stripe Test Key",             "pattern": r"(?:sk|pk)_test_[0-9a-zA-Z]{24,}","severity": "LOW",      "category": "payment"},
    # Twilio
    {"name": "Twilio Account SID",  "pattern": r"\bAC[0-9a-f]{32}\b",                             "severity": "HIGH",     "category": "communication"},
    {"name": "Twilio Auth Token",   "pattern": r"(?i)twilio.{0,20}['\"][0-9a-f]{32}['\"]",        "severity": "CRITICAL", "category": "communication"},
    # Google
    {"name": "Google API Key",      "pattern": r"AIza[0-9A-Za-z\-_]{35}",             "severity": "HIGH",     "category": "cloud"},
    # SendGrid
    {"name": "SendGrid API Key",    "pattern": r"SG\.[0-9A-Za-z\-_]{22}\.[0-9A-Za-z\-_]{43}", "severity": "HIGH", "category": "communication"},
    # Slack
    {"name": "Slack Bot Token",     "pattern": r"xoxb-[0-9]{11,13}-[0-9]{11,13}-[0-9a-zA-Z]{24}",                      "severity": "HIGH", "category": "communication"},
    {"name": "Slack User Token",    "pattern": r"xoxp-[0-9]{11,13}-[0-9]{11,13}-[0-9]{11,13}-[0-9a-f]{32}",            "severity": "HIGH", "category": "communication"},
    # Database connection strings
    {"name": "Database Connection String", "pattern": r"(?i)(?:postgres|postgresql|mysql|mongodb|redis|mssql):\/\/[^:]+:[^@\s'\"]{3,}@", "severity": "CRITICAL", "category": "database"},
    # JWT
    {"name": "JSON Web Token",      "pattern": r"eyJ[0-9a-zA-Z_-]{10,}\.[0-9a-zA-Z_-]{10,}\.[0-9a-zA-Z_-]{10,}", "severity": "MEDIUM", "category": "token"},
    # Generic credentials
    {"name": "Hardcoded Password",  "pattern": r"(?i)\b(?:password|passwd|pwd)\s*=\s*['\"][^'\"]{6,}['\"]",                                                "severity": "HIGH",   "category": "credential"},
    {"name": "Generic Secret",      "pattern": r"(?i)\b(?:secret_key|secret|api_key|apikey|auth_token|access_token)\s*=\s*['\"][0-9a-zA-Z_\-\.]{16,}['\"]","severity": "MEDIUM", "category": "credential"},
]

_COMPILED = [{**p, "_re": re.compile(p["pattern"])} for p in PATTERNS]


@dataclass
class SecretFinding:
    file: str
    line_number: int
    line_content: str
    secret_type: str
    category: str
    severity: str
    matched_value: str
    masked_context: str = ""   # the line with the secret masked — safe to display


def _mask(value: str) -> str:
    if len(value) <= 8:
        return "***"
    return value[:4] + "*" * (len(value) - 8) + value[-4:]


def _entropy(s: str) -> float:
    if not s:
        return 0.0
    freq: dict[str, int] = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    n = len(s)
    return -sum((f / n) * math.log2(f / n) for f in freq.values())


def scan_file(filepath: Path, root: Path) -> list[SecretFinding]:
    findings: list[SecretFinding] = []
    rel = str(filepath.relative_to(root))
    try:
        text = filepath.read_text(encoding="utf-8", errors="replace")
    except Exception:
        return []

    for lineno, line in enumerate(text.splitlines(), start=1):
        if _ALLOWLIST.search(line):
            continue
        for pat in _COMPILED:
            m = pat["_re"].search(line)
            if m:
                masked = _mask(m.group(0))
                findings.append(SecretFinding(
                    file=rel,
                    line_number=lineno,
                    line_content=line.strip()[:120],
                    secret_type=pat["name"],
                    category=pat["category"],
                    severity=pat["severity"],
                    matched_value=masked,
                    masked_context=line.strip().replace(m.group(0), masked)[:160],
                ))
                break  # one finding per line to avoid duplicates
    return findings


def scan_directory(root: Path) -> list[SecretFinding]:
    findings: list[SecretFinding] = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for filename in filenames:
            if filename in SKIP_FILES:
                continue
            p = Path(dirpath) / filename
            if p.suffix.lower() in SKIP_EXTENSIONS:
                continue
            findings.extend(scan_file(p, root))
    return findings
