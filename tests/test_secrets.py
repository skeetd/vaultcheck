import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from vaultcheck.secrets_scanner import scan_directory, scan_file

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


def test_detects_anthropic_key():
    import secrets as _secrets
    import string
    import tempfile
    token = "".join(_secrets.choice(string.ascii_letters + string.digits) for _ in range(95))
    raw = "sk-ant-api03-" + token
    tmp = Path(tempfile.mkdtemp())
    f = tmp / "cfg.py"
    f.write_text(f'ANTHROPIC_API_KEY = "{raw}"\n', encoding="utf-8")
    findings = scan_file(f, tmp)
    types = {x.secret_type for x in findings}
    assert "Anthropic API Key" in types, f"Expected Anthropic key, got: {types}"
    for x in findings:  # raw key must never appear unmasked
        assert raw not in x.matched_value, f"Anthropic key not masked: {x.matched_value}"


def test_detects_more_provider_keys():
    import tempfile
    samples = {
        "OpenAI Project Key":           "sk-proj-" + "A" * 45,
        "Hugging Face Token":           "hf_" + "c" * 36,
        "Groq API Key":                 "gsk_" + "d" * 52,
        "Slack Webhook URL":            "https://hooks.slack.com/services/T00000000/B11111111/" + "h" * 24,
        "GitLab Personal Access Token": "glpat-" + "abcDEF1234567890wxyz",
        "Stripe Restricted Key":        "rk_live_" + "abcdEFGH1234ijklMNOP5678",
        "npm Access Token":             "npm_" + "a" * 36,
        "DigitalOcean Token":           "dop_v1_" + "a" * 64,
    }
    tmp = Path(tempfile.mkdtemp())
    for i, (label, val) in enumerate(samples.items()):
        (tmp / f"f{i}.py").write_text(f'k = "{val}"\n', encoding="utf-8")
    findings = scan_directory(tmp)
    found = {f.secret_type for f in findings}
    for label in samples:
        assert label in found, f"{label} not detected; got {sorted(found)}"
    for f in findings:  # nothing leaked unmasked
        assert f.matched_value not in samples.values(), f"leaked: {f.matched_value}"


def test_flags_sensitive_files():
    import tempfile
    d = Path(tempfile.mkdtemp())
    (d / ".env").write_text("X=1\n", encoding="utf-8")
    (d / "server.pem").write_text("x\n", encoding="utf-8")
    (d / ".env.example").write_text("X=1\n", encoding="utf-8")  # template — must NOT flag
    types = {f.secret_type for f in scan_directory(d)}
    assert "Sensitive file committed: .env" in types
    assert any("server.pem" in t for t in types)
    assert not any("example" in t for t in types)


def test_high_entropy_secret():
    import tempfile
    d = Path(tempfile.mkdtemp())
    (d / "a.py").write_text('token = "f8Kd0sLpQ2zXcV7bNm3RtY9wErT1uIoP"\n', encoding="utf-8")
    fs = scan_directory(d)
    assert any(f.secret_type == "High-entropy secret" and f.severity == "MEDIUM" for f in fs)


def test_safe_placeholders_not_flagged():
    import tempfile
    d = Path(tempfile.mkdtemp())
    (d / "s.py").write_text(
        'a = "your-api-key-here"\n'
        'b = os.environ.get("API_KEY")\n'
        'c = "${process.env.API_KEY}"\n'
        'd = "REPLACE_WITH_YOUR_KEY"\n', encoding="utf-8")
    assert scan_file(d / "s.py", d) == []


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
