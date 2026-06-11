"""Responsible-disclosure helpers.

Find recently-created public repos, scan them for secrets (MASKED ONLY — the raw
secret is discarded at detection time and never retained), and produce a private
notice for the repo owner.

Hard rules baked in here:
- The raw secret value is never stored or returned (secrets_scanner masks it).
- We never use, validate, or log into anything with a found credential.
- Notices are meant for PRIVATE delivery to the owner, never a public issue.
"""
import hashlib
import json
import os
import urllib.parse
import urllib.request
from datetime import datetime, timedelta, timezone
from typing import Optional

from .scanner import run_scan

GITHUB_SEARCH = "https://api.github.com/search/repositories"


def _gh_headers() -> dict:
    headers = {
        "Accept": "application/vnd.github+json",
        "User-Agent": "vaultcheck-disclosure",
    }
    token = os.environ.get("GITHUB_TOKEN")
    if token:
        headers["Authorization"] = f"Bearer {token}"
    return headers


def fetch_recent_public_repos(limit: int = 50, since_minutes: int = 720, page: int = 1):
    """Return (repos, error). Supports pagination so a worker can keep pulling new repos.

    A GITHUB_TOKEN raises the rate limit substantially; without it GitHub search
    is limited to ~10 requests/minute.
    """
    since = (datetime.now(timezone.utc) - timedelta(minutes=since_minutes)).strftime(
        "%Y-%m-%dT%H:%M:%SZ"
    )
    query = urllib.parse.urlencode({
        "q": f"created:>{since}",
        "sort": "updated",
        "order": "desc",
        "per_page": min(max(limit, 1), 100),
        "page": max(page, 1),
    })
    req = urllib.request.Request(f"{GITHUB_SEARCH}?{query}", headers=_gh_headers())
    try:
        with urllib.request.urlopen(req, timeout=20) as resp:
            data = json.loads(resp.read())
    except Exception as exc:  # noqa: BLE001
        return [], str(exc)

    repos = [
        {
            "full_name": item["full_name"],
            "url": item["html_url"],
            "owner": item["owner"]["login"],
        }
        for item in data.get("items", [])[:limit]
    ]
    return repos, None


def fingerprint(repo_full_name: str, secret_type: str, file: str, line: int) -> str:
    """Stable dedupe key for a finding — derived from LOCATION, not the secret."""
    raw = f"{repo_full_name}|{secret_type}|{file}|{line}"
    return hashlib.sha256(raw.encode()).hexdigest()[:16]


def scan_repo(repo_url: str, token: Optional[str] = None):
    """Scan a repo for exposures and return (findings, errors).

    Covers secrets (masked at detection — the raw value is never retained) AND
    insecure code patterns, so it finds more than just API keys. Each finding:
    {kind, type, severity, file, line, detail}.
    """
    result = run_scan(repo_url, phases=("secrets", "code"),
                      github_token=token or os.environ.get("GITHUB_TOKEN"))
    findings = []
    for f in result.secrets:
        findings.append({"kind": "Secret", "type": f.secret_type, "severity": f.severity,
                         "file": f.file, "line": f.line_number, "detail": f.matched_value})
    for c in result.code:
        findings.append({"kind": "Code", "type": c.issue_type, "severity": c.severity,
                         "file": c.file, "line": c.line_number, "detail": c.description})
    return findings, result.errors


def build_notice(repo_full_name: str, owner: str, findings: list[dict]) -> str:
    """A private, polite, actionable disclosure message for the repo owner.

    Tolerant of both the new finding shape (kind/type/detail) and older stored
    cases (secret_type/masked_value).
    """
    def kind(f): return f.get("kind", "Secret")
    def typ(f):  return f.get("type") or f.get("secret_type") or "Issue"

    items = "\n".join(
        f"  - [{f.get('severity', '?')}] {kind(f)}: {typ(f)} in {f.get('file')}:{f.get('line')}"
        for f in findings
    )
    has_secret = any(kind(f) == "Secret" for f in findings)
    secret_line = (
        "\n\nThe items marked 'Secret' look like hardcoded credentials — please rotate "
        "them and remove them from the repository history (e.g. with `git filter-repo`)."
        if has_secret else ""
    )
    return (
        f"Hello @{owner},\n\n"
        f"An automated security scan flagged potential issues in your public repository "
        f"{repo_full_name}:\n\n{items}{secret_line}\n\n"
        "For your safety, any secret values were never stored or used — only their type "
        "and location.\n\n"
        "— Automated responsible-disclosure notice from VaultCheck"
    )
