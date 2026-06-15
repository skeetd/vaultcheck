import os
import re
from dataclasses import dataclass
from pathlib import Path

from .ignore import line_suppressed, load_ignore_rules

_SKIP_DIRS = {".git", "node_modules", "__pycache__", ".venv", "venv", "dist", "build"}
_CODE_EXTENSIONS = {".py", ".js", ".ts", ".jsx", ".tsx", ".php", ".rb", ".java", ".go"}


@dataclass
class CodeFinding:
    file: str
    line_number: int
    issue_type: str
    category: str
    severity: str
    description: str
    line_content: str = ""

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
    # Remote code execution / unsafe deserialization
    {"name": "Pickle deserialization",          "pattern": r"\bpickle\.loads?\s*\(",                                                               "severity": "CRITICAL", "category": "deser",   "description": "Unpickling untrusted data executes arbitrary code (RCE). Use a safe format like JSON."},
    {"name": "Unsafe yaml.load()",              "pattern": r"(?i)yaml\.load\s*\((?![^)\n]*safe)",                                                  "severity": "CRITICAL", "category": "deser",   "description": "yaml.load() without SafeLoader can instantiate arbitrary objects (RCE). Use yaml.safe_load()."},
    {"name": "yaml.unsafe_load()",              "pattern": r"\byaml\.unsafe_load\s*\(",                                                            "severity": "CRITICAL", "category": "deser",   "description": "yaml.unsafe_load() can execute arbitrary code on load. Use yaml.safe_load()."},
    {"name": "marshal deserialization",         "pattern": r"\bmarshal\.loads?\s*\(",                                                              "severity": "CRITICAL", "category": "deser",   "description": "marshal on untrusted data is unsafe and can crash or execute code."},
    {"name": "Java Runtime.exec()",             "pattern": r"Runtime\.getRuntime\(\)\.exec\s*\(",                                                  "severity": "CRITICAL", "category": "cmdi",    "description": "Runtime.exec() with dynamic input enables OS command injection."},
    {"name": "Java deserialization (readObject)", "pattern": r"\.readObject\s*\(\s*\)",                                                            "severity": "CRITICAL", "category": "deser",   "description": "Deserializing untrusted input via ObjectInputStream.readObject() is a classic RCE."},
    {"name": "PHP unserialize()",               "pattern": r"\bunserialize\s*\(",                                                                  "severity": "CRITICAL", "category": "deser",   "description": "PHP unserialize() on untrusted data enables object-injection RCE. Use json_decode()."},
    {"name": "PHP shell execution",             "pattern": r"\b(?:shell_exec|passthru|proc_open|popen)\s*\(",                                       "severity": "CRITICAL", "category": "cmdi",    "description": "Shell-executing function with dynamic input enables command injection."},
    {"name": "Ruby Marshal.load",               "pattern": r"\bMarshal\.load\s*\(",                                                                "severity": "CRITICAL", "category": "deser",   "description": "Marshal.load on untrusted data executes arbitrary code (RCE)."},
    {"name": "Node child_process exec",         "pattern": r"child_process\.(?:exec|execSync)\s*\(",                                               "severity": "HIGH",     "category": "cmdi",    "description": "child_process.exec runs a shell — use execFile/spawn with an args array on untrusted input."},
    {"name": "JS Function constructor",         "pattern": r"\bnew\s+Function\s*\(",                                                               "severity": "HIGH",     "category": "cmdi",    "description": "The Function constructor evaluates strings as code, like eval()."},
    {"name": "exec() usage",                    "pattern": r"\bexec\s*\(",                                                                         "severity": "HIGH",     "category": "cmdi",    "description": "exec() runs arbitrary code — never call it on untrusted input."},
    {"name": "Server-side template injection",  "pattern": r"render_template_string\s*\(",                                                         "severity": "HIGH",     "category": "ssti",    "description": "render_template_string() with user input enables SSTI → RCE. Render a fixed template with context vars."},
    {"name": "JWT 'none' algorithm",            "pattern": r"(?i)(?:alg|algorithm)['\"]?\s*[:=]\s*['\"]none['\"]",                                  "severity": "CRITICAL", "category": "auth",    "description": "JWT 'none' algorithm disables signature verification — anyone can forge tokens."},
    # Weak crypto
    {"name": "MD5 hash",                        "pattern": r"hashlib\.md5\s*\(",                                                                   "severity": "MEDIUM",   "category": "crypto",  "description": "MD5 is cryptographically broken. Use SHA-256 or SHA-3."},
    {"name": "SHA-1 hash",                      "pattern": r"hashlib\.sha1\s*\(",                                                                  "severity": "MEDIUM",   "category": "crypto",  "description": "SHA-1 is deprecated for security. Use SHA-256 or SHA-3."},
    {"name": "Weak PRNG (random module)",       "pattern": r"\brandom\.(?:random|randint|choice|randrange)\s*\(",                                 "severity": "MEDIUM",   "category": "crypto",  "description": "random is not cryptographically secure. Use the secrets module for tokens."},
    # Insecure config
    {"name": "Flask debug=True",                "pattern": r"app\.run\s*\([^)]*debug\s*=\s*True",                                                 "severity": "HIGH",     "category": "config",  "description": "Flask debug mode must never be enabled in production."},
    {"name": "CORS wildcard origin",            "pattern": r"Access-Control-Allow-Origin['\"]?\s*[=:]\s*['\"]?\*",                                "severity": "MEDIUM",   "category": "config",  "description": "Wildcard CORS allows any origin — restrict to known domains."},
    {"name": "SSL verification disabled",       "pattern": r"verify\s*=\s*False",                                                                  "severity": "HIGH",     "category": "config",  "description": "Disabling SSL verification exposes the connection to MITM attacks."},
    {"name": "Node TLS verification disabled",  "pattern": r"(?i)rejectUnauthorized\s*:\s*false",                                                  "severity": "HIGH",     "category": "config",  "description": "rejectUnauthorized:false disables TLS certificate validation — exposes connections to MITM."},
    {"name": "Global TLS check disabled",       "pattern": r"NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*['\"]?0",                                           "severity": "HIGH",     "category": "config",  "description": "NODE_TLS_REJECT_UNAUTHORIZED=0 disables all TLS verification process-wide."},
    {"name": "Go InsecureSkipVerify",           "pattern": r"InsecureSkipVerify\s*:\s*true",                                                       "severity": "HIGH",     "category": "config",  "description": "InsecureSkipVerify:true disables TLS certificate validation — exposes connections to MITM."},
    {"name": "Unverified SSL context (Python)", "pattern": r"ssl\._create_unverified_context\s*\(",                                                "severity": "HIGH",     "category": "config",  "description": "Creating an unverified SSL context disables certificate validation."},
    {"name": "Hardcoded IP address",            "pattern": r"['\"](?:\d{1,3}\.){3}\d{1,3}['\"]",                                                  "severity": "LOW",      "category": "config",  "description": "Hardcoded IP address — use config or environment variables."},
]

DOCKERFILE_PATTERNS = [
    {"name": "Running as root",                "pattern": r"^(?!.*USER\s)",                                                        "severity": "MEDIUM",   "category": "docker", "description": "No USER instruction — container runs as root by default.", "whole_file": True},
    {"name": "Hardcoded secret in ENV/ARG",    "pattern": r"(?i)^\s*(?:ENV|ARG)\s+\w*(?:PASSWORD|SECRET|TOKEN|KEY|API_KEY)\w*\s*=?\s*\S+", "severity": "HIGH",     "category": "docker", "description": "Secret-like value baked into the image via ENV/ARG — pass at runtime instead."},
    {"name": "ADD with remote URL",            "pattern": r"(?i)^\s*ADD\s+https?://",                                              "severity": "MEDIUM",   "category": "docker", "description": "ADD fetching a remote URL — prefer COPY plus an explicit, verified download step."},
    {"name": "apt-get without --no-install-recommends", "pattern": r"(?i)apt-get install(?!.*--no-install-recommends)",            "severity": "LOW",      "category": "docker", "description": "apt-get install without --no-install-recommends increases image size and attack surface."},
    {"name": "Using 'latest' base image tag",  "pattern": r"(?im)^\s*FROM\s+[^\s:@]+(:latest)?\s*$",                               "severity": "LOW",      "category": "docker", "description": "Pin base images to a specific version/digest instead of 'latest' for reproducible builds."},
    {"name": "chmod 777",                      "pattern": r"chmod\s+(-R\s+)?777",                                                  "severity": "MEDIUM",   "category": "docker", "description": "chmod 777 grants world-writable permissions — scope permissions narrowly."},
    {"name": "curl|sh / wget|sh pipe-to-shell", "pattern": r"(?:curl|wget)[^|\n]*\|\s*(?:sudo\s+)?(?:ba)?sh",                       "severity": "HIGH",     "category": "docker", "description": "Piping a downloaded script directly into a shell is a supply-chain risk — verify checksums/signatures first."},
]
_DOCKERFILE_COMPILED = [{**p, "_re": re.compile(p["pattern"], re.MULTILINE)} for p in DOCKERFILE_PATTERNS]

# --- Infrastructure-as-Code (Terraform + docker-compose) -----------------
IAC_PATTERNS = [
    {"name": "Security group open to 0.0.0.0/0",   "pattern": r"0\.0\.0\.0/0",                                              "severity": "HIGH",     "category": "iac", "description": "Resource is reachable from the entire internet — restrict the CIDR range."},
    {"name": "Terraform/compose hardcoded secret",  "pattern": r"(?i)(password|secret|api[_-]?key|access[_-]?key|token)\s*[:=]\s*['\"][^'\"\$\{][^'\"]{6,}['\"]", "severity": "HIGH", "category": "iac", "description": "Secret-like value hardcoded in IaC — use a secrets manager or variables."},
    {"name": "Unencrypted storage",                 "pattern": r"(?i)encrypted\s*[:=]\s*false",                             "severity": "MEDIUM",   "category": "iac", "description": "Storage/volume explicitly set to unencrypted — enable encryption at rest."},
    {"name": "Public S3 ACL",                       "pattern": r"(?i)acl\s*[:=]\s*['\"]?public-read(-write)?['\"]?",         "severity": "HIGH",     "category": "iac", "description": "Public S3 ACL exposes bucket contents — use private ACLs and bucket policies."},
    {"name": "compose: privileged container",       "pattern": r"(?i)privileged\s*:\s*true",                                "severity": "HIGH",     "category": "iac", "description": "privileged: true grants near-host access — scope capabilities narrowly instead."},
    {"name": "compose: host network mode",          "pattern": r"(?i)network_mode\s*:\s*['\"]?host['\"]?",                   "severity": "MEDIUM",   "category": "iac", "description": "host network mode removes container network isolation."},
    {"name": "compose: Docker socket mounted",      "pattern": r"/var/run/docker\.sock",                                    "severity": "HIGH",     "category": "iac", "description": "Mounting the Docker socket gives the container root-equivalent control of the host."},
    {"name": "TLS verification disabled (IaC)",     "pattern": r"(?i)(skip_tls_verify|insecure_skip_verify)\s*[:=]\s*true", "severity": "HIGH",     "category": "iac", "description": "Disabling TLS verification in infrastructure exposes connections to MITM."},
]
_IAC_COMPILED = [{**p, "_re": re.compile(p["pattern"])} for p in IAC_PATTERNS]

# --- GitHub Actions workflow security ------------------------------------
ACTIONS_PATTERNS = [
    {"name": "pull_request_target trigger",         "pattern": r"(?i)pull_request_target",                                  "severity": "HIGH",     "category": "ci", "description": "pull_request_target runs with repo secrets in the context of untrusted PR code — easy to exfiltrate secrets."},
    {"name": "Unpinned third-party action (branch/tag)", "pattern": r"(?i)uses:\s*(?!actions/)[\w.-]+/[\w.-]+@(?:main|master|v?\d+(?:\.\d+)*)\s*$", "severity": "MEDIUM", "category": "ci", "description": "Third-party action pinned to a mutable ref — pin to a full commit SHA."},
    {"name": "curl|sh in workflow",                 "pattern": r"(?:curl|wget)[^|\n]*\|\s*(?:sudo\s+)?(?:ba)?sh",            "severity": "HIGH",     "category": "ci", "description": "Piping a downloaded script to a shell in CI is a supply-chain risk."},
    {"name": "Secret echoed to logs",               "pattern": r"(?i)echo\s+.*\$\{\{\s*secrets\.",                          "severity": "HIGH",     "category": "ci", "description": "A secret is echoed — it may end up in build logs."},
    {"name": "Broad workflow permissions: write-all","pattern": r"(?i)permissions:\s*write-all",                             "severity": "MEDIUM",   "category": "ci", "description": "write-all grants the GITHUB_TOKEN broad scopes — set least-privilege permissions."},
    {"name": "Expression injection via PR title/body","pattern": r"\$\{\{\s*github\.event\.(?:issue|pull_request)\.(?:title|body)\s*\}\}", "severity": "HIGH", "category": "ci", "description": "Interpolating attacker-controlled PR/issue text into a run step enables script injection — pass via env instead."},
    {"name": "Hardcoded secret in workflow env",      "pattern": r"(?i)\b\w*(?:KEY|TOKEN|SECRET|PASSWORD|PASSWD)\w*\s*:\s*['\"][^'\"$]{8,}['\"]", "severity": "HIGH", "category": "ci", "description": "Hardcoded secret-like value in a workflow — reference it as ${{ secrets.NAME }} instead of inlining it."},
]
_ACTIONS_COMPILED = [{**p, "_re": re.compile(p["pattern"])} for p in ACTIONS_PATTERNS]

_IAC_EXTENSIONS = {".tf", ".tfvars"}
_COMPOSE_NAMES = {"docker-compose.yml", "docker-compose.yaml", "compose.yml", "compose.yaml"}


def _is_iac_file(filename: str) -> bool:
    name = filename.lower()
    return Path(name).suffix in _IAC_EXTENSIONS or name in _COMPOSE_NAMES


def _is_github_workflow(p: Path, root: Path) -> bool:
    if p.suffix.lower() not in {".yml", ".yaml"}:
        return False
    try:
        rel_parts = p.relative_to(root).parts
    except ValueError:
        return False
    return len(rel_parts) >= 3 and rel_parts[0] == ".github" and rel_parts[1] == "workflows"


def _scan_line_patterns(filepath: Path, root: Path, compiled: list) -> list[CodeFinding]:
    findings: list[CodeFinding] = []
    rel = str(filepath.relative_to(root))
    try:
        lines = filepath.read_text(encoding="utf-8", errors="replace").splitlines()
    except Exception:
        return []
    for lineno, line in enumerate(lines, start=1):
        stripped = line.strip()
        if stripped.startswith("#"):
            continue
        if line_suppressed(line, "code"):
            continue
        for pat in compiled:
            if pat["_re"].search(line):
                findings.append(CodeFinding(
                    file=rel,
                    line_number=lineno,
                    line_content=stripped[:120],
                    issue_type=pat["name"],
                    category=pat["category"],
                    severity=pat["severity"],
                    description=pat["description"],
                ))
                break
    return findings


_GITIGNORE_SENSITIVE = [".env", "*.pem", "*.key", "id_rsa", "*.p12", "*.pfx", "credentials"]


def _scan_gitignore(root: Path) -> list[CodeFinding]:
    """Flag sensitive patterns that exist in the repo but are not git-ignored."""
    gitignore = root / ".gitignore"
    ignored_text = ""
    if gitignore.exists():
        try:
            ignored_text = gitignore.read_text(encoding="utf-8", errors="replace").lower()
        except Exception:
            ignored_text = ""
    ignored_lines = {l.strip() for l in ignored_text.splitlines() if l.strip() and not l.startswith("#")}

    # Which sensitive file types actually appear in the tree?
    present_kinds: set[str] = set()
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in _SKIP_DIRS]
        for fn in filenames:
            low = fn.lower()
            if low == ".env" or low.startswith(".env."):
                present_kinds.add(".env")
            elif low.endswith((".pem",)):
                present_kinds.add("*.pem")
            elif low.endswith((".key",)):
                present_kinds.add("*.key")
            elif low in ("id_rsa", "id_dsa", "id_ecdsa", "id_ed25519"):
                present_kinds.add("id_rsa")
            elif low.endswith((".p12", ".pfx")):
                present_kinds.add("*.p12")

    findings: list[CodeFinding] = []
    for kind in sorted(present_kinds):
        covered = any(kind == il or kind.lstrip("*") in il or il.lstrip("*") in kind
                      for il in ignored_lines)
        if not covered:
            findings.append(CodeFinding(
                file=".gitignore",
                line_number=0,
                issue_type=f"Sensitive file type not git-ignored: {kind}",
                category="hygiene",
                severity="MEDIUM",
                description=f"Files matching '{kind}' are present but not covered by .gitignore — "
                            "they risk being committed. Add an ignore rule.",
            ))
    return findings

_COMPILED = [{**p, "_re": re.compile(p["pattern"])} for p in PATTERNS]


def _scan_file(filepath: Path, root: Path) -> list[CodeFinding]:
    findings: list[CodeFinding] = []
    rel = str(filepath.relative_to(root))
    try:
        lines = filepath.read_text(encoding="utf-8", errors="replace").splitlines()
    except Exception:
        return []
    for lineno, line in enumerate(lines, start=1):
        if line_suppressed(line, "code"):
            continue
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


def _is_dockerfile(filename: str) -> bool:
    name = filename.lower()
    return name == "dockerfile" or name.startswith("dockerfile.") or name.endswith(".dockerfile")


def _scan_dockerfile(filepath: Path, root: Path) -> list[CodeFinding]:
    findings: list[CodeFinding] = []
    rel = str(filepath.relative_to(root))
    try:
        text = filepath.read_text(encoding="utf-8", errors="replace")
    except Exception:
        return []
    lines = text.splitlines()
    for pat in _DOCKERFILE_COMPILED:
        if pat.get("whole_file"):
            # "Running as root": flag once if no USER instruction anywhere in the file
            if not re.search(r"(?im)^\s*USER\s+\S+", text):
                findings.append(CodeFinding(
                    file=rel,
                    line_number=1,
                    line_content=lines[0].strip()[:120] if lines else "",
                    issue_type=pat["name"],
                    category=pat["category"],
                    severity=pat["severity"],
                    description=pat["description"],
                ))
            continue
        for lineno, line in enumerate(lines, start=1):
            if line_suppressed(line, "code"):
                continue
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
    return findings


def scan_directory(root: Path, ignore_rules=None) -> list[CodeFinding]:
    if ignore_rules is None:
        ignore_rules = load_ignore_rules(root)
    findings: list[CodeFinding] = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in _SKIP_DIRS]
        for filename in filenames:
            p = Path(dirpath) / filename
            if ignore_rules.match(str(p.relative_to(root))):
                continue
            if p.suffix.lower() in _CODE_EXTENSIONS:
                findings.extend(_scan_file(p, root))
            elif _is_dockerfile(filename):
                findings.extend(_scan_dockerfile(p, root))
            elif _is_iac_file(filename):
                findings.extend(_scan_line_patterns(p, root, _IAC_COMPILED))
            elif _is_github_workflow(p, root):
                findings.extend(_scan_line_patterns(p, root, _ACTIONS_COMPILED))
    # repo-wide hygiene checks (operate on the tree, not a single file)
    findings.extend(_scan_gitignore(root))
    return findings
