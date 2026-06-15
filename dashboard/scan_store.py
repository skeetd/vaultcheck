"""Per-user scan history (JSON store).

A scan record belongs to exactly one user_id, so a user only ever sees their own
scans. The admin (dashboard) can see aggregate stats and recent activity.
"""
import json
import uuid
from datetime import datetime, timezone
from pathlib import Path

SCANS_FILE = Path(__file__).parent / "scans.json"


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _load() -> dict:
    if not SCANS_FILE.exists():
        return {}
    return json.loads(SCANS_FILE.read_text(encoding="utf-8"))


def _save(data: dict) -> None:
    SCANS_FILE.write_text(json.dumps(data, indent=2), encoding="utf-8")


def add_scan(user_id: str, kind: str, target: str, counts: dict, total: int,
             fingerprints: list = None) -> dict:
    data = _load()
    rec = {
        "id": str(uuid.uuid4()),
        "user_id": user_id,
        "kind": kind,                 # "repo" or "check:<check_id>"
        "target": target,
        "created_at": _now(),
        "counts": counts,             # {CRITICAL, HIGH, MEDIUM, LOW}
        "total": total,
        "fingerprints": fingerprints or [],  # stable IDs of findings, for diffing
    }
    data[rec["id"]] = rec
    _save(data)
    return rec


def latest_for_target(target: str, kind: str = "repo") -> dict:
    """Most recent scan record for a given target+kind, or None."""
    matches = [r for r in _load().values()
               if r.get("target") == target and r.get("kind") == kind]
    if not matches:
        return None
    return max(matches, key=lambda r: r["created_at"])


def list_for_user(user_id: str) -> list[dict]:
    return sorted((r for r in _load().values() if r["user_id"] == user_id),
                  key=lambda r: r["created_at"], reverse=True)


def recent(limit: int = 10) -> list[dict]:
    return sorted(_load().values(), key=lambda r: r["created_at"], reverse=True)[:limit]


def count_this_month(user_id: str) -> int:
    ym = datetime.now(timezone.utc).strftime("%Y-%m")
    return sum(1 for r in _load().values()
               if r["user_id"] == user_id and r["created_at"][:7] == ym)


def stats() -> dict:
    data = list(_load().values())
    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    by_kind: dict = {}
    for r in data:
        by_kind[r["kind"]] = by_kind.get(r["kind"], 0) + 1
    return {
        "total": len(data),
        "today": sum(1 for r in data if r["created_at"][:10] == today),
        "findings": sum(r.get("total", 0) for r in data),
        "by_kind": sorted(by_kind.items(), key=lambda x: -x[1])[:6],
    }
