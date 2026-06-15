import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from vaultcheck.code_scanner import scan_directory
from vaultcheck.sbom import generate_sbom
from vaultcheck.diff import diff_fingerprints


def _mkrepo(files: dict) -> Path:
    d = Path(tempfile.mkdtemp())
    for rel, content in files.items():
        p = d / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content, encoding="utf-8")
    return d


def test_dockerfile_findings():
    d = _mkrepo({"Dockerfile": "FROM ubuntu\nENV API_KEY=secret123\nRUN chmod -R 777 /app\n"})
    issues = {f.issue_type for f in scan_directory(d)}
    assert any("root" in i for i in issues)
    assert any("ENV/ARG" in i for i in issues)
    assert any("chmod 777" in i for i in issues)


def test_iac_findings():
    d = _mkrepo({"main.tf": 'ingress { cidr_blocks = ["0.0.0.0/0"] }\n',
                 "docker-compose.yml": "services:\n  a:\n    privileged: true\n"})
    issues = {f.issue_type for f in scan_directory(d)}
    assert any("0.0.0.0/0" in i for i in issues)
    assert any("privileged" in i for i in issues)


def test_github_actions_findings():
    d = _mkrepo({".github/workflows/ci.yml": "on: pull_request_target\npermissions: write-all\n"})
    cats = {f.category for f in scan_directory(d)}
    issues = {f.issue_type for f in scan_directory(d)}
    assert "ci" in cats
    assert any("pull_request_target" in i for i in issues)


def test_gitignore_hygiene():
    d = _mkrepo({"server.pem": "key", "README.md": "x"})  # no .gitignore covering *.pem
    issues = {f.issue_type for f in scan_directory(d)}
    assert any("not git-ignored" in i for i in issues)


def test_sbom_cyclonedx():
    d = _mkrepo({"requirements.txt": "flask==2.0.0\nrequests==2.28.0\n"})
    doc = generate_sbom(d, "cyclonedx")
    assert doc["bomFormat"] == "CycloneDX"
    names = {c["name"] for c in doc["components"]}
    assert {"flask", "requests"} <= names
    assert all(c["purl"].startswith("pkg:pypi/") for c in doc["components"])


def test_sbom_spdx():
    d = _mkrepo({"requirements.txt": "flask==2.0.0\n"})
    doc = generate_sbom(d, "spdx")
    assert doc["spdxVersion"] == "SPDX-2.3"
    assert any(p["name"] == "flask" for p in doc["packages"])


def test_diff():
    prev = [{"id": "a", "label": "A", "severity": "HIGH", "kind": "code"},
            {"id": "b", "label": "B", "severity": "LOW", "kind": "code"}]
    cur = [{"id": "b", "label": "B", "severity": "LOW", "kind": "code"},
           {"id": "c", "label": "C", "severity": "CRITICAL", "kind": "secret"}]
    d = diff_fingerprints(prev, cur)
    assert {x["id"] for x in d["new"]} == {"c"}
    assert {x["id"] for x in d["fixed"]} == {"a"}
    assert {x["id"] for x in d["unchanged"]} == {"b"}


# --- ignore / suppression -------------------------------------------------
from vaultcheck.ignore import IgnoreRules, line_suppressed, nosec_scopes, load_ignore_rules


def test_ignore_glob_patterns():
    r = IgnoreRules(["**/tests/fixtures/**", "examples/**", "**/*.min.js"])
    assert r.match("tests/fixtures/sample.py")
    assert r.match("a/b/tests/fixtures/x.py")
    assert r.match("examples/demo/config.py")
    assert r.match("static/app.min.js")
    assert not r.match("vaultcheck/scanner.py")


def test_ignore_directory_pattern():
    r = IgnoreRules(["build/"])
    assert r.match("build/out.js")
    assert r.match("build")
    assert not r.match("src/build_tool.py")


def test_nosec_scopes():
    assert nosec_scopes("x = 1") is None
    assert nosec_scopes("x = 1  # nosec") == set()          # all
    assert nosec_scopes("x = 1  # nosec code") == {"code"}
    assert nosec_scopes("x = 1  // nosec secret") == {"secret"}


def test_line_suppressed_scope():
    assert line_suppressed("k='AKIA...'  # nosec", "secret")
    assert line_suppressed("k='AKIA...'  # nosec secret", "secret")
    assert not line_suppressed("k='AKIA...'  # nosec code", "secret")
    assert line_suppressed("eval(x)  # nosec code", "code")


def test_default_ignores_filter_examples(tmp_path):
    (tmp_path / "examples").mkdir()
    (tmp_path / "examples" / "config.py").write_text('K = "AKIAIOSFODNN7EXAMPLE"\n')
    (tmp_path / "app.py").write_text('K = "AKIAIOSFODNN7EXAMPLE"\n')
    from vaultcheck.secrets_scanner import scan_directory
    rules = load_ignore_rules(tmp_path, use_defaults=True)
    files = {f.file for f in scan_directory(tmp_path, ignore_rules=rules)}
    assert "app.py" in files
    assert not any("examples" in f for f in files)
