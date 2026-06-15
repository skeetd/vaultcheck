import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from vaultcheck.scanner import ScanResult
from vaultcheck.secrets_scanner import SecretFinding
from vaultcheck.code_scanner import CodeFinding
from vaultcheck.reporter import generate_report
from vaultcheck.explanations import _GENERIC, explain


def _sample() -> ScanResult:
    r = ScanResult(target="t", phases=("secrets", "code"))
    r.secrets = [SecretFinding(file="a.py", line_number=1, line_content="", secret_type="AWS",
                               category="cloud", severity="CRITICAL", matched_value="AKIA****")]
    r.code = [
        CodeFinding(file="b.py", line_number=2, issue_type="Pickle deserialization", category="deser", severity="CRITICAL", description="x"),
        CodeFinding(file="c.js", line_number=3, issue_type="Unsafe innerHTML", category="xss", severity="HIGH", description="x"),
        CodeFinding(file="d.py", line_number=4, issue_type="MD5 hash", category="crypto", severity="MEDIUM", description="x"),
    ]
    return r


def test_only_severities_single():
    crit = _sample().only_severities(["critical"])
    assert crit.severity_counts == {"CRITICAL": 2, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    assert all(f.severity == "CRITICAL" for f in crit.all_findings)


def test_only_severities_multiple():
    hm = _sample().only_severities(["high", "medium"])
    assert {f.severity for f in hm.all_findings} == {"HIGH", "MEDIUM"}


def test_only_severities_returns_copy():
    r = _sample()
    r.only_severities(["low"])
    assert r.total == 4  # original is untouched


def test_explain_known_vs_generic():
    assert explain("deser") is not _GENERIC
    assert explain("cloud") is not _GENERIC
    assert explain("unknown-category-xyz") is _GENERIC
    impact, fix = explain("sqli")
    assert impact and fix and impact != fix


def test_report_has_guidance_and_filter_note():
    html = generate_report(_sample().only_severities(["critical"]), severity_filter=["critical"])
    assert "filtered to CRITICAL" in html
    assert "What these mean" in html
    assert "How to secure" in html and "Impact" in html


if __name__ == "__main__":
    passed = failed = 0
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
