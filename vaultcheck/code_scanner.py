import os
import re
from dataclasses import dataclass
from pathlib import Path

_SKIP_DIRS = {".git", "node_modules", "__pycache__", ".venv", "venv", "dist", "build"}
_CODE_EXTENSIONS = {".py", ".js", ".ts", ".jsx", ".tsx", ".php", ".rb", ".java", ".go"}

PATTERNS = [
    # SQL injection
    {"name": "SQL Injection — string concat",   "pattern": r"(?i)(?:execute|cursor\.execute)\s*\([^)]*\+",                                       "severity": "HIGH",     "category": "sqli",    "description": "SQL query built with string concatenation. Use parameterized queries instead."},
    {"name": "SQL Injection — f-string",        "pattern": r"(?i)cursor\.execute\s*\(\s*f['\"].*?(?:SELECT|INSERT|UPDATE|DELETE|DROP)",           "severity": "HIGH",     "category": "sqli",    "description": "SQL query built with f-string. Use parameterized queries instead."},
    {"name": "Raw SQL format string",           "pattern": r"(?i)(?:SELECT|INSERT|UPDATE|DELETE)\s+.{0,60}%[sd]|\.format\s*\(",                  "severity": "MEDIUM",   "category": "sqli",    "description": "SQL query with % or .format() formatting — potential injection risk."},
    # XSS
    {"name": "Unsafe innerHTML",                "pattern": r"\.innerHTML\s*=",                                                                     "severity": "HIGH",     "category": "xss",     "description": "Assigning to innerHTML with unsanitized content enables XSS."},
    {"name": "document.write()",                "pattern": r"document\.write\s*\(",                                                                "severity": "MEDIUM",   "category": "xss",     "description": "document.write() with user input enables XSS."},
    {"name": "Flask Markup() / mark_safe()",    "pattern": r"\b(?:Markup|mark_safe)\s*\(",                                                        "severity": "MEDIUM",   "category": "xss",     "description": "Marking content as safe — ensure it is properly sanitized first."},
    # Command injection
    {"name": "subprocess shell=True",           "pattern": r"subprocess\.(?:call|run|Popen|check_output)\s*\([^)]*shell\s*=\s*True",             "severity": "CRITICAL", "category": "cmdi",    "description": "shell=True with dynamic input enables OS command injection."},
    {"name": "os.system() call",                "pattern": r"\bos\.system\s*\(",                                                                   "severity": "HIGH",     "category": "cmdi",    "description": "os.system() is vulnerable to command injection. Prefer subprocess with a list."},
    {"name": "eval() usage",                    "pattern": r"\beval\s*\(",                                                                         "severity": "HIGH",     "category": "cmdi",    "description": "eval() with user-controlled input enables code injection."},
    # Weak crypto
    {"name": "MD5 hash",                        "pattern": r"hashlib\.md5\s*\(",                                                                   "severity": "MEDIUM",   "category": "crypto",  "description": "MD5 is cryptographically broken. Use SHA-256 or SHA-3."},
    {"name": "SHA-1 hash",                      "pattern": r"hashlib\.sha1\s*\(",                                                                  "severity": "MEDIUM",   "category": "crypto",  "description": "SHA-1 is deprecated for security. Use SHA-256 or SHA-3."},
    {"name": "Weak PRNG (random module)",       "pattern": r"\brandom\.(?:random|randint|choice|randrange)\s*\(",                                 "severity": "MEDIUM",   "category": "crypto",  "description": "random is not cryptographically secure. Use the secrets module for tokens."},
    # Insecure config
    {"name": "Flask debug=True",                "pattern": r"app\.run\s*\([^)]*debug\s*=\s*True",                                                 "severity": "HIGH",     "category": "config",  "description": "Flask debug mode must never be enabled in production."},
    {"name": "CORS wildcard origin",            "pattern": r"Access-Control-Allow-Origin['\"]?\s*[=:]\s*['\"]?\*",                                "severity": "MEDIUM",   "category": "config",  "description": "Wildcard CORS allows any origin — restrict to known domains."},
    {"name": "SSL verification disabled",       "pattern": r"verify\s*=\s*False",                                                                  "severity": "HIGH",     "category": "config",  "description": "Disabling SSL verification exposes the connection to MITM attacks."},
    {"name": "Hardcoded IP address",            "pattern": r"['\"](?:\d{1,3}\.){3}\d{1,3}['\"]",                                                  "severity": "LOW",      "category": "config",  "description": "Hardcoded IP address — use config or environment variables."},
]

_COMPILED = [{**p, "_re": re.compile(p["pattern"])} for p in PATTERNS]


@dataclass
class CodeFinding:
    file: str
    line_number: int
    line_content: str
    issue_type: str
    category: str
    severity: str
    description: str


def _scan_file(filepath: Path, root: Path) -> list[CodeFinding]:
    findings: list[CodeFinding] = []
    rel = str(filepath.relative_to(root))
    try:
        lines = filepath.read_text(encoding="utf-8", errors="replace").splitlines()
    except Exception:
        return []
    for lineno, line in enumerate(lines, start=1):
        for pat in _COMPILED:
            if pat["_re"].search(line):
                findings.append(CodeFinding(
                    file=rel,
                    line_number=lineno,
                    line_content=line.strip()[:120],
                    issue_type=pat["name"],
                    category=pat["category"],
                    severity=pat["severity"],
                    description=pat["description"],
                ))
                break
    return findings


def scan_directory(root: Path) -> list[CodeFinding]:
    findings: list[CodeFinding] = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in _SKIP_DIRS]
        for filename in filenames:
            p = Path(dirpath) / filename
            if p.suffix.lower() in _CODE_EXTENSIONS:
                findings.extend(_scan_file(p, root))
    return findings
