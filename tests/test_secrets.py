import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from vaultcheck.secrets_scanner import scan_file

FIXTURE = Path(__file__).parent / "fixtures" / "sample_secrets.py"


def test_detects_aws_key():
    findings = scan_file(FIXTURE, FIXTURE.parent.parent)
    types = {f.secret_type for f in findings}
    assert "AWS Access Key ID" in types, f"Expected AWS key, got: {types}"


def test_detects_github_token():
    findings = scan_file(FIXTURE, FIXTURE.parent.parent)
    types = {f.secret_type for f in findings}
    assert "GitHub PAT (classic)" in types, f"Expected GitHub PAT, got: {types}"


def test_detects_stripe_key():
    findings = scan_file(FIXTURE, FIXTURE.parent.parent)
    types = {f.secret_type for f in findings}
    assert "Stripe Live Secret Key" in types, f"Expected Stripe key, got: {types}"


def test_detects_db_connection():
    findings = scan_file(FIXTURE, FIXTURE.parent.parent)
    types = {f.secret_type for f in findings}
    assert "Database Connection String" in types, f"Expected DB string, got: {types}"


def test_detects_hardcoded_password():
    findings = scan_file(FIXTURE, FIXTURE.parent.parent)
    types = {f.secret_type for f in findings}
    assert "Hardcoded Password" in types, f"Expected password, got: {types}"


def test_values_are_masked():
    findings = scan_file(FIXTURE, FIXTURE.parent.parent)
    for f in findings:
        assert "***" in f.matched_value or len(f.matched_value) < len("AKIAIOSFODNN7EXAMPLE"), \
            f"Value not masked: {f.matched_value}"


if __name__ == "__main__":
    passed = 0
    failed = 0
    for name, fn in list(globals().items()):
        if name.startswith("test_") and callable(fn):
            try:
                fn()
                print(f"[+] {name}")
                passed += 1
            except AssertionError as e:
                print(f"[!] {name}: {e}")
                failed += 1
    print(f"\n{passed} passed, {failed} failed")
