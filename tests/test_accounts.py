"""Self-serve account creation, validation and authentication."""
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from dashboard import models


def _fresh_store():
    tmp = tempfile.mkdtemp(prefix="vc_acct_")
    models.USERS_FILE = Path(tmp) / "users.json"


def test_create_and_authenticate():
    _fresh_store()
    user, err = models.create_account("alice", "alice@example.com", "longenough")
    assert err is None and user, err
    assert user["plan"] == "free"
    assert models.authenticate("alice@example.com", "longenough")
    assert models.authenticate("alice@example.com", "wrong") is None


def test_rejects_weak_password():
    _fresh_store()
    _, err = models.create_account("bob", "bob@example.com", "short")
    assert err and "8 characters" in err, err


def test_rejects_bad_email():
    _fresh_store()
    _, err = models.create_account("bob", "not-an-email", "longenough")
    assert err and "valid email" in err, err


def test_rejects_duplicate_email():
    _fresh_store()
    models.create_account("a", "dup@example.com", "longenough")
    _, err = models.create_account("b", "dup@example.com", "longenough")
    assert err and "already exists" in err, err


def test_password_hash_not_plaintext():
    _fresh_store()
    user, _ = models.create_account("carol", "carol@example.com", "longenough")
    assert user["password_hash"] and "longenough" not in user["password_hash"]


def test_admin_created_user_has_no_password():
    _fresh_store()
    u = models.create_user("dave", "dave@example.com", "free")
    assert u["password_hash"] is None
    assert models.authenticate("dave@example.com", "anything") is None


if __name__ == "__main__":
    passed = failed = 0
    for name, fn in list(globals().items()):
        if name.startswith("test_") and callable(fn):
            try:
                fn(); print(f"[+] {name}"); passed += 1
            except AssertionError as e:
                print(f"[!] {name}: {e}"); failed += 1
    print(f"\n{passed} passed, {failed} failed")
    sys.exit(1 if failed else 0)
