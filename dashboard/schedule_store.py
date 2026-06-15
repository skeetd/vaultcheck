"""Scheduled scans (JSON store).

A schedule re-runs a repo scan or a registered check on an interval and records the
result. Owned by a user_id (or "admin"), so each owner manages only their own.
"""
import json
import threading
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Optional

SCHEDULES_FILE = Path(__file__).parent / "schedules.json"

INTERVALS = {
    "hourly": timedelta(hours=1),
    "daily":  timedelta(days=1),
    "weekly": timedelta(weeks=1),
}

_lock = threading.Lock()


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _iso(dt: datetime) -> str:
    return dt.isoformat()


def _load() -> dict:
    if not SCHEDULES_FILE.exists():
        return {}
    return json.loads(SCHEDULES_FILE.read_text(encoding="utf-8"))


def _save(data: dict) -> None:
    SCHEDULES_FILE.write_text(json.dumps(data, indent=2), encoding="utf-8")


def add_schedule(owner: str, kind: str, target: str, interval: str) -> Optional[dict]:
    if interval not in INTERVALS:
        return None
    with _lock:
        data = _load()
        sid = str(uuid.uuid4())
        sched = {
            "id": sid,
            "owner": owner,
            "kind": kind,            # "repo" or "check:<check_id>"
            "target": target,
            "interval": interval,
            "active": True,
            "created_at": _iso(_now()),
            "next_run": _iso(_now()),   # first run on the next scheduler tick
            "last_run": None,
            "last_result": None,        # {counts, total}
        }
        data[sid] = sched
        _save(data)
        return sched


def list_for_owner(owner: str) -> list[dict]:
    return sorted((s for s in _load().values() if s["owner"] == owner),
                  key=lambda s: s["created_at"], reverse=True)


def list_all() -> list[dict]:
    return sorted(_load().values(), key=lambda s: s["created_at"], reverse=True)


def delete(schedule_id: str, owner: Optional[str] = None) -> bool:
    with _lock:
        data = _load()
        s = data.get(schedule_id)
        if not s or (owner is not None and s["owner"] != owner):
            return False
        del data[schedule_id]
        _save(data)
        return True


def due(now: Optional[datetime] = None) -> list[dict]:
    """Active schedules whose next_run has passed."""
    now = now or _now()
    out = []
    for s in _load().values():
        if not s.get("active"):
            continue
        try:
            nxt = datetime.fromisoformat(s["next_run"])
        except (ValueError, KeyError):
            continue
        if nxt <= now:
            out.append(s)
    return out


def mark_run(schedule_id: str, counts: dict, total: int) -> None:
    """Record a run and advance next_run by the schedule's interval."""
    with _lock:
        data = _load()
        s = data.get(schedule_id)
        if not s:
            return
        now = _now()
        s["last_run"] = _iso(now)
        s["last_result"] = {"counts": counts, "total": total}
        s["next_run"] = _iso(now + INTERVALS.get(s["interval"], timedelta(days=1)))
        _save(data)
