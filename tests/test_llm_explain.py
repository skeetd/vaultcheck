import json
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

import vaultcheck.llm_explain as L
from vaultcheck.secrets_scanner import SecretFinding
from vaultcheck.code_scanner import CodeFinding


class _FakeResp:
    def __init__(self, payload):
        self._b = json.dumps(payload).encode()
    def read(self):
        return self._b
    def __enter__(self):
        return self
    def __exit__(self, *a):
        return False


def _mock_ollama(monkey_chat="Why it matters: x\nQuick fix: y\nBetter fix: z\nVerify: w",
                 model_present=True):
    def fake(req, timeout=0):
        url = getattr(req, "full_url", req)
        if url.endswith("/api/tags"):
            models = [{"name": "vuln-explainer:latest"}] if model_present else []
            return _FakeResp({"models": models})
        if url.endswith("/api/chat"):
            return _FakeResp({"message": {"content": monkey_chat}})
        raise RuntimeError("unexpected url " + url)
    L.urllib.request.urlopen = fake


def _down():
    def fake(*a, **k):
        raise RuntimeError("connection refused")
    L.urllib.request.urlopen = fake


def test_raw_secret_never_in_prompt():
    raw = "AKIAIOSFODNN7EXAMPLE"
    sf = SecretFinding(file="a.py", line_number=1, line_content=f'key = "{raw}"',
                       secret_type="AWS Access Key ID", category="cloud", severity="CRITICAL",
                       matched_value="AKIA****", masked_context='key = "AKIA****"')
    prompt = L.format_input(sf)
    assert raw not in prompt, f"raw secret leaked into prompt:\n{prompt}"
    assert "AKIA****" in prompt  # masked context is what gets sent


def test_format_code_finding_shape():
    cf = CodeFinding(file="b.py", line_number=2, issue_type="Pickle deserialization",
                     category="deser", severity="CRITICAL", description="RCE",
                     line_content="pickle.loads(blob)")
    prompt = L.format_input(cf)
    assert "Issue: Pickle deserialization" in prompt
    assert "Severity: CRITICAL" in prompt
    assert "pickle.loads(blob)" in prompt


def test_explain_finding_and_cache():
    L._CACHE_PATH = Path(tempfile.mkdtemp()) / "cache.json"
    _mock_ollama()
    cf = CodeFinding(file="b.py", line_number=2, issue_type="X", category="cmdi",
                     severity="HIGH", description="d", line_content="exec(x)")
    txt = L.explain_finding(cf)
    assert txt and "Quick fix" in txt
    _down()  # cache should serve the second call without the network
    assert L.explain_finding(cf) == txt


def test_is_available_reflects_model_presence():
    _mock_ollama(model_present=True)
    assert L.is_available() is True
    _mock_ollama(model_present=False)
    assert L.is_available() is False
    _down()
    assert L.is_available() is False


def test_explain_html_and_fallback():
    L._CACHE_PATH = Path(tempfile.mkdtemp()) / "cache.json"
    cf = CodeFinding(file="b.py", line_number=2, issue_type="X", category="cmdi",
                     severity="HIGH", description="d", line_content="exec(x)")
    _mock_ollama()
    html = L.explain_html([cf])
    assert html and "AI remediation" in html
    _down()  # model unreachable -> caller can omit the section
    L._CACHE_PATH = Path(tempfile.mkdtemp()) / "cache2.json"
    assert L.explain_html([cf]) is None


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
