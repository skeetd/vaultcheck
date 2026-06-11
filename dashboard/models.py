"""Simple JSON-file user store. No database required for MVP."""
import json
import secrets
import uuid
from datetime import datetime
from pathlib import Path
from typing import Optional

USERS_FILE = Path(__file__).parent / "users.json"


def _load() -> dict:
    if not USERS_FILE.exists():
        return {}
    return json.loads(USERS_FILE.read_text(encoding="utf-8"))


def _save(data: dict) -> None:
    USERS_FILE.write_text(json.dumps(data, indent=2), encoding="utf-8")


def list_users() -> list[dict]:
    return list(_load().values())


def get_user(user_id: str) -> Optional[dict]:
    return _load().get(user_id)


def get_user_by_email(email: str) -> Optional[dict]:
    for u in _load().values():
        if u["email"].lower() == email.lower():
            return u
    return None


def get_user_by_token(token: str) -> Optional[dict]:
    if not token:
        return None
    for u in _load().values():
        if u.get("api_token") == token:
            return u
    return None


def create_user(username: str, email: str, plan: str = "free") -> dict:
    data = _load()
    user = {
        "id":         str(uuid.uuid4()),
        "username":   username,
        "email":      email,
        "plan":       plan,
        "api_token":  secrets.token_urlsafe(24),
        "created_at": datetime.utcnow().isoformat(),
        "scan_count": 0,
    }
    data[user["id"]] = user
    _save(data)
    return user


def update_plan(user_id: str, plan: str) -> Optional[dict]:
    data = _load()
    if user_id not in data:
        return None
    data[user_id]["plan"] = plan
    if plan != "pro":
        data[user_id]["pro_until"] = None
    _save(data)
    return data[user_id]


def set_pro_until(user_id: str, until: Optional[str], amount: str = "") -> Optional[dict]:
    """Mark a user Pro, optionally until a date (YYYY-MM-DD). None = no expiry."""
    data = _load()
    if user_id not in data:
        return None
    data[user_id]["plan"] = "pro"
    data[user_id]["pro_until"] = until
    data[user_id]["paid_at"] = datetime.utcnow().isoformat()
    if amount:
        data[user_id]["paid_amount"] = amount
    _save(data)
    return data[user_id]


def effective_plan(user: dict) -> str:
    """Pro auto-downgrades to free once pro_until has passed."""
    plan = user.get("plan", "free")
    if plan == "pro":
        until = user.get("pro_until")
        if until and until[:10] < datetime.utcnow().strftime("%Y-%m-%d"):
            return "free"
    return plan


def delete_user(user_id: str) -> bool:
    data = _load()
    if user_id not in data:
        return False
    del data[user_id]
    _save(data)
    return True


def increment_scan_count(user_id: str) -> None:
    data = _load()
    if user_id in data:
        data[user_id]["scan_count"] = data[user_id].get("scan_count", 0) + 1
        _save(data)
