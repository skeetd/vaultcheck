"""Git-history secret scanning: finds removed secrets, attributes commit, stays masked."""
import subprocess
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from vaultcheck.secrets_scanner import scan_git_history

SECRET = "AKIA1234567890ABCDEF"  # matches the AWS pattern; avoids allowlist words


def _make_repo(root: Path):
    def git(*a):
        subprocess.run(["git", "-C", str(root), *a], check=True, capture_output=True)
    git("init", "-q")
    git("config", "user.email", "t@example.com")
    git("config", "user.name", "Test")
    (root / "conf.py").write_text(f'aws_key = "{SECRET}"\n', encoding="utf-8")
    git("add", "-A"); git("commit", "-q", "-m", "add config")
    (root / "conf.py").write_text('aws_key = os.environ["AWS_KEY"]\n', encoding="utf-8")
    git("add", "-A"); git("commit", "-q", "-m", "move to env var")


def test_finds_removed_secret_masked():
    with tempfile.TemporaryDirectory() as d:
        root = Path(d)
        _make_repo(root)
        hits = scan_git_history(root)
        assert any(h.secret_type == "AWS Access Key ID" for h in hits), "missed removed key"
        for h in hits:
            assert SECRET not in h.matched_value, f"raw secret leaked: {h.matched_value}"
            assert h.commit, "history finding should carry a commit sha"


def test_non_git_dir_returns_empty():
    with tempfile.TemporaryDirectory() as d:
        assert scan_git_history(Path(d)) == []


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
