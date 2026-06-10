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


def fetch_recent_public_repos(limit: int = 5, since_minutes: int = 180):
    """Return (repos, error). Throttled by design — caller passes a small limit.

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
        "per_page": min(max(limit, 1), 30),
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


def scan_repo_secrets(repo_url: str):
    """Scan a repo for secrets and return (masked_findings, errors).

    matched_value is already masked by the scanner — the raw secret never exists
    outside the regex match and is not returned here.
    """
    result = run_scan(repo_url, phases=("secrets",), github_token=os.environ.get("GITHUB_TOKEN"))
    findings = [
        {
            "secret_type": f.secret_type,
            "file": f.file,
            "line": f.line_number,
            "masked_value": f.matched_value,
            "severity": f.severity,
        }
        for f in result.secrets
    ]
    return findings, result.errors


def build_notice(repo_full_name: str, owner: str, findings: list[dict]) -> str:
    """A private, polite, actionable disclosure message for the repo owner."""
    items = "\n".join(
        f"  - {f['secret_type']} in {f['file']}:{f['line']} (value masked: {f['masked_value']})"
        for f in findings
    )
    return (
        f"Hello @{owner},\n\n"
        f"An automated security scan flagged what appear to be hardcoded credentials "
        f"committed to your public repository {repo_full_name}:\n\n"
        f"{items}\n\n"
        "If these are real, please rotate them right away and remove them from the "
        "repository history (e.g. with `git filter-repo`). For your safety the actual "
        "secret values were never stored or used — only their type and location.\n\n"
        "— Automated responsible-disclosure notice from VaultCheck"
    )
