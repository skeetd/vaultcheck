import math
import os
import re
import subprocess
from dataclasses import dataclass
from pathlib import Path

from .ignore import line_suppressed, load_ignore_rules

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
    r"xxx+|todo|changeme|replace.?(?:me|with)|insert.?here|redacted|"
    r"test.?key|dummy|fake|sample|demo"
)

# Entropy fallback: a high-entropy string assigned to a variable (= or :) that no
# named pattern caught is likely a secret. Threshold per spec: >4.5 bits/char, >20 chars.
_ENTROPY_RE = re.compile(r"""[=:]\s*['"]([A-Za-z0-9+/=_\-]{20,})['"]""")
_ENTROPY_MIN_LEN = 20
_ENTROPY_THRESHOLD = 4.5

# Files that should never be committed (flagged on presence, regardless of contents).
_SENSITIVE_FILENAMES = {
    ".env", ".env.local", ".env.production", ".env.staging",
    "id_rsa", "id_dsa", "id_ecdsa", "id_ed25519",
    "credentials.json", "service-account.json", "gcp-key.json",
    "secrets.yaml", "secrets.json",
}
_SENSITIVE_SUFFIXES = (".pem", ".key", ".p12", ".pfx")
_SENSITIVE_RELPATHS = {"config/secrets.yml"}
# Template/example variants are safe — don't flag these.
_SENSITIVE_SAFE_HINTS = ("example", "sample", "template", "dist")

PATTERNS = [
    # Private keys
    {"name": "RSA Private Key",      "pattern": r"-----BEGIN RSA PRIVATE KEY-----",    "severity": "CRITICAL", "category": "private_key"},  # nosec secret
    {"name": "EC Private Key",       "pattern": r"-----BEGIN EC PRIVATE KEY-----",     "severity": "CRITICAL", "category": "private_key"},  # nosec secret
    {"name": "OpenSSH Private Key",  "pattern": r"-----BEGIN OPENSSH PRIVATE KEY-----","severity": "CRITICAL", "category": "private_key"},  # nosec secret
    {"name": "PEM Private Key",      "pattern": r"-----BEGIN PRIVATE KEY-----",        "severity": "CRITICAL", "category": "private_key"},  # nosec secret
    {"name": "DSA/PGP Private Key",  "pattern": r"-----BEGIN (?:DSA |PGP )PRIVATE KEY(?: BLOCK)?-----", "severity": "CRITICAL", "category": "private_key"},  # nosec secret
    {"name": "Certificate",          "pattern": r"-----BEGIN CERTIFICATE-----",        "severity": "LOW",      "category": "private_key"},  # nosec secret
    # AWS
    {"name": "AWS Access Key ID",         "pattern": r"\bAKIA[0-9A-Z]{16}\b",                                                    "severity": "CRITICAL", "category": "cloud"},
    {"name": "AWS Secret Access Key",     "pattern": r"(?i)aws.{0,20}(?:secret|key).{0,30}['\"][0-9a-zA-Z/+]{40}['\"]",         "severity": "CRITICAL", "category": "cloud"},
    # GitHub
    {"name": "GitHub PAT (classic)",      "pattern": r"ghp_[0-9a-zA-Z]{36}",           "severity": "CRITICAL", "category": "vcs"},
    {"name": "GitHub OAuth Token",        "pattern": r"gho_[0-9a-zA-Z]{36}",           "severity": "CRITICAL", "category": "vcs"},
    {"name": "GitHub App Token",          "pattern": r"ghs_[0-9a-zA-Z]{36}",           "severity": "CRITICAL", "category": "vcs"},
    {"name": "GitHub Fine-grained PAT",   "pattern": r"github_pat_[0-9a-zA-Z_]{82}",  "severity": "CRITICAL", "category": "vcs"},
    {"name": "GitHub Token (u2s/refresh)","pattern": r"\bgh[ur]_[0-9a-zA-Z]{36,}\b",   "severity": "CRITICAL", "category": "vcs"},
    # Stripe
    {"name": "Stripe Live Secret Key",      "pattern": r"sk_live_[0-9a-zA-Z]{24,}",       "severity": "CRITICAL", "category": "payment"},
    {"name": "Stripe Live Publishable Key", "pattern": r"pk_live_[0-9a-zA-Z]{24,}",       "severity": "HIGH",     "category": "payment"},
    {"name": "Stripe Test Key",             "pattern": r"(?:sk|pk)_test_[0-9a-zA-Z]{24,}","severity": "LOW",      "category": "payment"},
    # Twilio
    {"name": "Twilio Account SID",  "pattern": r"\bAC[0-9a-f]{32}\b",                             "severity": "HIGH",     "category": "communication"},
    {"name": "Twilio Auth Token",   "pattern": r"(?i)twilio.{0,20}['\"][0-9a-f]{32}['\"]",        "severity": "CRITICAL", "category": "communication"},
    {"name": "Twilio API Key",      "pattern": r"\bSK[0-9a-f]{32}\b",                             "severity": "HIGH",     "category": "communication"},
    # Google
    {"name": "Google API Key",      "pattern": r"AIza[0-9A-Za-z\-_]{35}",             "severity": "HIGH",     "category": "cloud"},
    {"name": "Google OAuth Client ID", "pattern": r"\b[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com", "severity": "MEDIUM", "category": "cloud"},
    # SendGrid
    {"name": "SendGrid API Key",    "pattern": r"SG\.[0-9A-Za-z\-_]{22}\.[0-9A-Za-z\-_]{43}", "severity": "HIGH", "category": "communication"},
    # AI / LLM providers
    {"name": "Anthropic API Key",   "pattern": r"sk-ant-(?:api|admin)\d{2}-[A-Za-z0-9_-]{80,}", "severity": "CRITICAL", "category": "ai"},
    {"name": "OpenAI Project Key",  "pattern": r"\bsk-proj-[A-Za-z0-9_-]{20,}",                  "severity": "CRITICAL", "category": "ai"},
    {"name": "OpenAI Service Key",  "pattern": r"\bsk-(?:svcacct|admin)-[A-Za-z0-9_-]{20,}",     "severity": "CRITICAL", "category": "ai"},
    {"name": "OpenAI API Key (legacy)", "pattern": r"\bsk-[A-Za-z0-9]{48}\b",                    "severity": "CRITICAL", "category": "ai"},
    {"name": "Hugging Face Token",  "pattern": r"\bhf_[A-Za-z0-9]{34,}\b",                       "severity": "HIGH",     "category": "ai"},
    {"name": "Groq API Key",        "pattern": r"\bgsk_[A-Za-z0-9]{48,}\b",                      "severity": "HIGH",     "category": "ai"},
    {"name": "Replicate API Token", "pattern": r"\br8_[A-Za-z0-9]{37,}\b",                       "severity": "HIGH",     "category": "ai"},
    {"name": "Perplexity API Key",  "pattern": r"\bpplx-[A-Za-z0-9]{40,}\b",                     "severity": "HIGH",     "category": "ai"},
    {"name": "xAI (Grok) API Key",  "pattern": r"\bxai-[A-Za-z0-9]{70,}\b",                      "severity": "CRITICAL", "category": "ai"},
    {"name": "Cohere API Key",      "pattern": r"(?i)cohere[^\n]{0,20}['\"][A-Za-z0-9]{40}['\"]","severity": "HIGH",     "category": "ai"},
    # Slack
    {"name": "Slack Webhook URL",   "pattern": r"https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]{20,}", "severity": "HIGH", "category": "communication"},
    {"name": "Slack Bot Token",     "pattern": r"xoxb-[0-9]{11,13}-[0-9]{11,13}-[0-9a-zA-Z]{24}",                      "severity": "HIGH", "category": "communication"},
    {"name": "Slack User Token",    "pattern": r"xoxp-[0-9]{11,13}-[0-9]{11,13}-[0-9]{11,13}-[0-9a-f]{32}",            "severity": "HIGH", "category": "communication"},
    {"name": "Slack App Token",     "pattern": r"xapp-[0-9]+-[A-Z0-9]+-[0-9]+-[a-zA-Z0-9]+",                          "severity": "HIGH", "category": "communication"},
    # Discord / Telegram / email senders
    {"name": "Discord Bot Token",   "pattern": r"\b[MNO][A-Za-z\d_-]{23,25}\.[A-Za-z\d_-]{6}\.[A-Za-z\d_-]{27,}\b",   "severity": "HIGH",   "category": "communication"},
    {"name": "Discord Webhook URL", "pattern": r"https://(?:ptb\.|canary\.)?discord(?:app)?\.com/api/webhooks/\d{17,}/[A-Za-z0-9_-]{60,}", "severity": "MEDIUM", "category": "communication"},
    {"name": "Telegram Bot Token",  "pattern": r"\b\d{8,10}:[A-Za-z0-9_-]{35}\b",                                     "severity": "HIGH",   "category": "communication"},
    {"name": "Mailgun API Key",     "pattern": r"\bkey-[0-9a-zA-Z]{32}\b",                                            "severity": "HIGH",   "category": "communication"},
    {"name": "Mailchimp API Key",   "pattern": r"\b[0-9a-f]{32}-us\d{1,2}\b",                                         "severity": "HIGH",   "category": "communication"},
    # Cloud / infrastructure
    {"name": "DigitalOcean Token",  "pattern": r"\bdo[opr]_v1_[a-f0-9]{64}\b",                                        "severity": "CRITICAL", "category": "cloud"},
    {"name": "Azure Storage Key",   "pattern": r"(?i)AccountKey=[A-Za-z0-9+/]{86}==",                                 "severity": "CRITICAL", "category": "cloud"},
    {"name": "Firebase Cloud Messaging Key", "pattern": r"\bAAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{140}\b",               "severity": "HIGH",     "category": "cloud"},
    {"name": "Cloudflare API Token", "pattern": r"(?i)(?:cf|cloudflare)[_-]?api[_-]?token['\"]?\s*[=:]\s*['\"][A-Za-z0-9_-]{37}['\"]", "severity": "HIGH", "category": "cloud"},
    {"name": "Heroku API Key",       "pattern": r"(?i)heroku[^\n]{0,30}\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b", "severity": "HIGH", "category": "cloud"},
    # Payment processors
    {"name": "Stripe Restricted Key", "pattern": r"\brk_live_[0-9a-zA-Z]{24,}",                                       "severity": "CRITICAL", "category": "payment"},
    {"name": "Square Access Token",  "pattern": r"\bsq0[a-z]{3}-[0-9A-Za-z_-]{22,}\b",                                 "severity": "CRITICAL", "category": "payment"},
    {"name": "Shopify Access Token", "pattern": r"\bshp(?:at|ca|pa|ss)_[a-fA-F0-9]{32}\b",                            "severity": "CRITICAL", "category": "payment"},
    {"name": "Braintree Access Token", "pattern": r"access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}",             "severity": "CRITICAL", "category": "payment"},
    # Version control / package registries
    {"name": "GitLab Personal Access Token", "pattern": r"\bglpat-[0-9a-zA-Z_-]{20}\b",                               "severity": "CRITICAL", "category": "vcs"},
    {"name": "npm Access Token",     "pattern": r"\bnpm_[A-Za-z0-9]{36}\b",                                           "severity": "HIGH",     "category": "package"},
    {"name": "PyPI Upload Token",    "pattern": r"\bpypi-AgEI[A-Za-z0-9_-]{50,}",                                     "severity": "HIGH",     "category": "package"},
    # SaaS / developer tools
    {"name": "Atlassian API Token", "pattern": r"\bATATT3[A-Za-z0-9_\-=]{180,}",                                      "severity": "HIGH",     "category": "saas"},
    {"name": "Sentry Auth Token",   "pattern": r"\bsntrys_[A-Za-z0-9_=\-]{60,}",                                      "severity": "HIGH",     "category": "saas"},
    {"name": "Sentry DSN",          "pattern": r"https://[0-9a-f]{32}@[a-z0-9.-]*sentry\.io/\d+",                     "severity": "MEDIUM",   "category": "saas"},
    {"name": "New Relic API Key",   "pattern": r"\bNRAK-[A-Z0-9]{27}\b",                                              "severity": "HIGH",     "category": "saas"},
    {"name": "Linear API Key",      "pattern": r"\blin_api_[A-Za-z0-9]{40}\b",                                        "severity": "HIGH",     "category": "saas"},
    {"name": "Notion Integration Token", "pattern": r"\bntn_[A-Za-z0-9]{40,}\b",                                      "severity": "HIGH",     "category": "saas"},
    {"name": "Airtable Token",      "pattern": r"\bpat[A-Za-z0-9]{14}\.[A-Za-z0-9]{64}\b",                            "severity": "HIGH",     "category": "saas"},
    {"name": "Dropbox Access Token", "pattern": r"\bsl\.[A-Za-z0-9_-]{130,}\b",                                       "severity": "HIGH",     "category": "saas"},
    # Database connection strings
    {"name": "Database Connection String", "pattern": r"(?i)(?:postgres|postgresql|mysql|mssql|mongodb(?:\+srv)?|redis):\/\/[^:@\s'\"]*:[^@\s'\"]+@", "severity": "CRITICAL", "category": "database"},
    {"name": "Connection string with password", "pattern": r"(?i)(?:connection[_-]?string|connstr|db[_-]?url)[^\n]{0,40}password=", "severity": "HIGH", "category": "database"},  # nosec secret
    # JWT
    {"name": "JSON Web Token",      "pattern": r"eyJ[0-9a-zA-Z_-]{10,}\.[0-9a-zA-Z_-]{10,}\.[0-9a-zA-Z_-]{10,}", "severity": "MEDIUM", "category": "token"},
    # Generic credentials (key/value with a secret-suggesting variable name)
    {"name": "Hardcoded Password",  "pattern": r"(?i)\b(?:password|passwd|pwd)\s*[=:]\s*['\"][^'\"]{6,}['\"]",                                                       "severity": "HIGH",   "category": "credential"},
    {"name": "Generic Secret",      "pattern": r"(?i)\b(?:secret_key|secret|api[_-]?key|apikey|auth[_-]?token|access[_-]?token|private[_-]?key)\s*[=:]\s*['\"][^'\"]{8,}['\"]","severity": "MEDIUM", "category": "credential"},
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
    commit: str = ""           # short SHA when the finding comes from git history (else "")


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
        findings.extend(_scan_line(line, rel, lineno))
    return findings


def scan_directory(root: Path, ignore_rules=None) -> list[SecretFinding]:
    if ignore_rules is None:
        ignore_rules = load_ignore_rules(root)
    findings: list[SecretFinding] = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for filename in filenames:
            if filename in SKIP_FILES:
                continue
            p = Path(dirpath) / filename
            if p.suffix.lower() in SKIP_EXTENSIONS:
                continue
            if ignore_rules.match(str(p.relative_to(root))):
                continue
            findings.extend(scan_file(p, root))
    findings.extend(_scan_sensitive_files(root, ignore_rules))
    return findings


def _scan_line(line: str, file: str, lineno: int, commit: str = "") -> list[SecretFinding]:
    """Run every secret pattern against a single line. Shared by file and history scans."""
    if _ALLOWLIST.search(line):
        return []
    if line_suppressed(line, "secret"):  # inline `# nosec [secret]` opt-out
        return []
    out: list[SecretFinding] = []
    for pat in _COMPILED:
        m = pat["_re"].search(line)
        if m:
            masked = _mask(m.group(0))
            out.append(SecretFinding(
                file=file,
                line_number=lineno,
                line_content=line.strip()[:120],
                secret_type=pat["name"],
                category=pat["category"],
                severity=pat["severity"],
                matched_value=masked,
                masked_context=line.strip().replace(m.group(0), masked)[:160],
                commit=commit,
            ))
            break  # one finding per line to avoid duplicates
    if not out:  # entropy fallback — high-entropy value assigned to a variable
        em = _ENTROPY_RE.search(line)
        if em:
            val = em.group(1)
            if len(val) >= _ENTROPY_MIN_LEN and _entropy(val) > _ENTROPY_THRESHOLD:
                masked = _mask(val)
                out.append(SecretFinding(
                    file=file, line_number=lineno, line_content=line.strip()[:120],
                    secret_type="High-entropy secret", category="credential", severity="MEDIUM",
                    matched_value=masked,
                    masked_context=line.strip().replace(val, masked)[:160], commit=commit,
                ))
    return out


def _scan_sensitive_files(root: Path, ignore_rules) -> list[SecretFinding]:
    """Flag sensitive files that should never be committed (.env, *.pem, id_rsa, …)."""
    findings: list[SecretFinding] = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for filename in filenames:
            low = filename.lower()
            rel = str((Path(dirpath) / filename).relative_to(root)).replace("\\", "/")
            if any(h in low for h in _SENSITIVE_SAFE_HINTS):  # .env.example etc.
                continue
            is_sensitive = (
                low in _SENSITIVE_FILENAMES
                or low.startswith(".env.")
                or low.endswith(_SENSITIVE_SUFFIXES)
                or rel in _SENSITIVE_RELPATHS
            )
            if not is_sensitive or ignore_rules.match(rel):
                continue
            findings.append(SecretFinding(
                file=rel, line_number=0, line_content="",
                secret_type=f"Sensitive file committed: {filename}",
                category="hygiene", severity="HIGH",
                matched_value="(file present in repo)",
                masked_context="This file type commonly holds credentials — it should be git-ignored, never committed.",
            ))
    return findings


def scan_git_history(repo_root: Path, max_commits: int = 2000) -> list[SecretFinding]:
    """Scan added lines across the full git history for secrets.

    Finds credentials that were committed and later removed — invisible to a working-tree
    scan but still recoverable from history. Requires a full (non-shallow) clone; a shallow
    clone simply yields little history. Each distinct secret is reported once, attributed to
    the earliest commit in which it was added. The raw value is masked, same as file scans.
    """
    if not (repo_root / ".git").exists():
        return []
    # Printable marker, not NUL — process arguments can't carry embedded NUL bytes
    # (the OS truncates the argument there), which would silently drop commit markers.
    marker = "VAULTCHECK\x1fCOMMIT\x1f"
    try:
        proc = subprocess.run(
            ["git", "-C", str(repo_root), "log", "--all", "-p", "-U0", "--no-color",
             f"--max-count={max_commits}", f"--pretty=format:{marker}%H"],
            capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=300,
        )
    except Exception:
        return []
    if proc.returncode != 0:
        return []

    findings: list[SecretFinding] = []
    seen: set[tuple] = set()  # (file, secret_type, masked) — collapse a secret repeated across commits
    commit = ""
    cur_file = ""
    lineno = 0
    for raw in proc.stdout.splitlines():
        if raw.startswith(marker):
            commit = raw[len(marker):][:12]
        elif raw.startswith("+++ b/"):
            cur_file = raw[6:]
        elif raw.startswith("@@"):
            m = re.search(r"\+(\d+)", raw)
            lineno = int(m.group(1)) if m else 0
        elif raw.startswith("+") and not raw.startswith("+++"):
            for f in _scan_line(raw[1:], cur_file, lineno, commit):
                key = (f.file, f.secret_type, f.matched_value)
                if key not in seen:
                    seen.add(key)
                    findings.append(f)
            lineno += 1
    return findings
