"""Send findings to a LOCAL fine-tuned LLM (the `vuln-explainer` Ollama model) for
remediation explanations — a free, offline drop-in for paid remediation calls.

It talks to Ollama's local API (default http://localhost:11434). If Ollama or the
model isn't reachable, every call returns None so callers fall back to the static
guidance in `explanations.py`. Results are cached on disk by content fingerprint so
repeated renders/scans don't re-run the model.

The prompt shape mirrors `vuln-explainer/prompts.py` — the single source of truth
the model was trained against. If that module is importable (sibling project) we
use it directly; otherwise we use a verbatim vendored copy.

SAFETY: raw secret values are never sent to the model. For secret findings we use
the masked context only (never `line_content`, which holds the original line).
"""
import hashlib
import html
import json
import os
import sys
import urllib.error
import urllib.request
from pathlib import Path
from typing import Optional

OLLAMA_HOST = os.environ.get("OLLAMA_HOST", "http://localhost:11434").rstrip("/")
MODEL = os.environ.get("VAULTCHECK_LLM_MODEL", "vuln-explainer")
TIMEOUT = float(os.environ.get("VAULTCHECK_LLM_TIMEOUT", "60"))
# Auto-use in the dashboard only when explicitly switched on; CLI/forced callers
# can call explain_* directly regardless of this.
AUTO_ENABLED = os.environ.get("VAULTCHECK_LLM", "").lower() in ("1", "true", "yes", "on")

_CACHE_PATH = Path(__file__).resolve().parent.parent / ".llm_explain_cache.json"
_VULN_EXPLAINER_DIR = Path(os.environ.get("VULN_EXPLAINER_DIR", r"C:\Users\str\vuln-explainer"))

# Verbatim fallback copy of vuln-explainer/prompts.py SYSTEM_PROMPT.
_VENDORED_SYSTEM_PROMPT = """You are a senior application-security engineer writing concise remediation guidance for vulnerability scanner findings.

For each finding you receive, write a fix guide that is:

1. Why it matters - one sentence on the real-world risk.
2. Quick fix - the smallest change that addresses the finding.
3. Better fix - the more robust long-term fix.
4. Verify - one specific test the user can run after fixing.

Constraints:
- Total length: 6-10 short lines. No fluff.
- Use plain text only (no markdown). Use line breaks for structure.
- Be specific to the finding - don't paste generic advice.
- If the finding is purely informational and no fix is needed, say so in one line.
- If you don't have enough info to give a real fix, say what extra info would help.
- Never invent CVE numbers, version numbers, or links you don't actually know."""


def _load_prompt_helpers():
    """Prefer the real single-source prompts.py; fall back to vendored copy."""
    try:
        if _VULN_EXPLAINER_DIR.exists() and str(_VULN_EXPLAINER_DIR) not in sys.path:
            sys.path.insert(0, str(_VULN_EXPLAINER_DIR))
        from prompts import SYSTEM_PROMPT, format_code_finding  # type: ignore
        return SYSTEM_PROMPT, format_code_finding
    except Exception:
        return _VENDORED_SYSTEM_PROMPT, _vendored_format_code_finding


def _vendored_format_code_finding(cf: dict) -> str:
    return "\n".join([
        f"Issue: {cf.get('issue_type', '?')}",
        f"Category: {cf.get('category', '?')}",
        f"Severity: {(cf.get('severity') or 'info').upper()}",
        f"File: {cf.get('file', '?')}:{cf.get('line_number', '?')}",
        f"Code: {cf.get('line_content', '')}",
        f"Description: {cf.get('description', '-')}",
    ])


SYSTEM_PROMPT, _format_code_finding = _load_prompt_helpers()


def _to_dict(f) -> dict:
    return f if isinstance(f, dict) else getattr(f, "__dict__", {})


def _normalize(finding) -> dict:
    """Map any finding (CodeFinding/SecretFinding/DepFinding/LicenseFinding/disclosure
    dict) into the code-finding shape prompts.py expects.

    SAFETY: for secrets we use the MASKED context only — never `line_content`,
    which contains the original (unmasked) source line.
    """
    d = _to_dict(finding)
    is_secret = bool(d.get("secret_type")) or d.get("kind") == "Secret"
    issue = d.get("issue_type") or d.get("type") or d.get("secret_type") or "Finding"

    # Code/context — masked sources first; raw line_content only for non-secrets.
    code = d.get("masked_context") or d.get("context")
    if not code and not is_secret:
        code = d.get("line_content", "")
    code = code or ""

    desc = d.get("description") or d.get("summary") or d.get("reason")
    if not desc and is_secret:
        desc = f"Hardcoded secret of type '{issue}' detected (value masked)."
    desc = desc or d.get("detail") or "-"

    return {
        "issue_type": issue,
        "category": d.get("category", "?"),
        "severity": d.get("severity", "info"),
        "file": d.get("file", "?"),
        "line_number": d.get("line_number", d.get("line", "?")),
        "line_content": code,   # the key format_code_finding reads — already safe
        "description": desc,
    }


def format_input(finding) -> str:
    """The exact user-message text the model was trained on, for one finding."""
    return _format_code_finding(_normalize(finding))


# --- cache ------------------------------------------------------------------

def _load_cache() -> dict:
    try:
        return json.loads(_CACHE_PATH.read_text(encoding="utf-8"))
    except Exception:
        return {}


def _save_cache(cache: dict) -> None:
    try:
        _CACHE_PATH.write_text(json.dumps(cache, indent=2), encoding="utf-8")
    except Exception:
        pass


def _key(user_text: str) -> str:
    return hashlib.sha1(f"{MODEL}\n{user_text}".encode("utf-8")).hexdigest()


# --- Ollama ----------------------------------------------------------------

def is_available() -> bool:
    """True if Ollama is reachable and the configured model is installed."""
    try:
        req = urllib.request.Request(f"{OLLAMA_HOST}/api/tags",
                                     headers={"Accept": "application/json"})
        with urllib.request.urlopen(req, timeout=5) as resp:
            data = json.loads(resp.read())
    except Exception:
        return False
    names = [m.get("name", "") for m in data.get("models", [])]
    base = MODEL.split(":")[0]
    return any(n == MODEL or n.split(":")[0] == base for n in names)


def _generate(user_text: str) -> Optional[str]:
    body = json.dumps({
        "model": MODEL,
        "stream": False,
        "messages": [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": user_text},
        ],
        "options": {"temperature": 0.3, "top_p": 0.9},
    }).encode("utf-8")
    req = urllib.request.Request(f"{OLLAMA_HOST}/api/chat", data=body,
                                 headers={"Content-Type": "application/json"}, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
            data = json.loads(resp.read())
    except Exception:
        return None
    text = (data.get("message") or {}).get("content", "").strip()
    return text or None


def explain_finding(finding, use_cache: bool = True) -> Optional[str]:
    """Return the local model's remediation text for one finding, or None if the
    model is unavailable. Cached on disk by content fingerprint."""
    user_text = format_input(finding)
    key = _key(user_text)
    if use_cache:
        cached = _load_cache().get(key)
        if cached:
            return cached
    text = _generate(user_text)
    if text and use_cache:
        cache = _load_cache()
        cache[key] = text
        _save_cache(cache)
    return text


def explain_findings(findings: list) -> dict:
    """Explain many findings. Returns {finding_index: text}. Skips silently if the
    model isn't available so callers can fall back to static guidance."""
    out: dict = {}
    if not findings or not is_available():
        return out
    for i, f in enumerate(findings):
        text = explain_finding(f)
        if text:
            out[i] = text
    return out


def explain_html(findings: list, heading: str = "AI remediation (local vuln-explainer model)") -> Optional[str]:
    """Build an HTML <section> of per-finding model explanations for the report.

    Returns None if the model is unavailable or produced nothing, so the caller
    can simply omit the section (the static per-category guidance still shows).
    """
    texts = explain_findings(findings)
    if not texts:
        return None
    rows = ""
    for i, f in enumerate(findings):
        if i not in texts:
            continue
        d = _to_dict(f)
        label = (d.get("issue_type") or d.get("type") or d.get("secret_type") or "Finding")
        loc = f"{d.get('file', '?')}:{d.get('line_number', d.get('line', '?'))}"
        rows += (
            '<div class="ai-item">'
            f'<div class="ai-head"><span class="ai-label">{html.escape(str(label))}</span>'
            f'<span class="ai-loc mono">{html.escape(loc)}</span></div>'
            f'<pre class="ai-text">{html.escape(texts[i])}</pre>'
            "</div>"
        )
    return (
        '<section class="ai-remediation">'
        f"<h2>{html.escape(heading)}</h2>"
        '<div class="section-sub">Generated locally and offline by your fine-tuned model — '
        'no data left this machine. Review before acting.</div>'
        f"{rows}</section>"
    )
