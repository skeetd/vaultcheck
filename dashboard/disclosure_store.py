"""JSON store for responsible-disclosure cases.

A case = one repo with one or more MASKED secret findings, plus a review status.
Never stores a raw secret value.

Status flow:  pending -> approved -> disclosed   (or -> dismissed)
"""
import json
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

CASES_FILE = Path(__file__).parent / "disclosure_cases.json"

STATUSES = ("pending", "approved", "disclosed", "dismissed")


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _load() -> dict:
    if not CASES_FILE.exists():
        return {}
    return json.loads(CASES_FILE.read_text(encoding="utf-8"))


def _save(data: dict) -> None:
    CASES_FILE.write_text(json.dumps(data, indent=2), encoding="utf-8")


def list_cases(status: Optional[str] = None) -> list[dict]:
    cases = list(_load().values())
    if status:
        cases = [c for c in cases if c["status"] == status]
    return sorted(cases, key=lambda c: c["created_at"], reverse=True)


def counts() -> dict:
    data = _load().values()
    return {s: sum(1 for c in data if c["status"] == s) for s in STATUSES}


def repo_exists(repo_full_name: str) -> bool:
    return any(c["repo"] == repo_full_name for c in _load().values())


def add_case(repo_full_name: str, owner: str, findings: list[dict],
             repo_url: Optional[str] = None) -> Optional[dict]:
    """Add a new case unless this repo is already tracked (dedupe by repo)."""
    if repo_exists(repo_full_name):
        return None
    data = _load()
    cid = str(uuid.uuid4())
    case = {
        "id": cid,
        "repo": repo_full_name,
        "owner": owner,
        "repo_url": repo_url or f"https://github.com/{repo_full_name}",
        "findings": findings,  # masked only
        "status": "pending",
        "created_at": _now(),
        "updated_at": _now(),
    }
    data[cid] = case
    _save(data)
    return case


def set_status(case_id: str, status: str) -> bool:
    if status not in STATUSES:
        return False
    data = _load()
    if case_id not in data:
        return False
    data[case_id]["status"] = status
    data[case_id]["updated_at"] = _now()
    _save(data)
    return True
