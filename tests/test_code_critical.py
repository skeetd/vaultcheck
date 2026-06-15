import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from vaultcheck.code_scanner import scan_directory


def _scan_line(filename: str, line: str):
    tmp = Path(tempfile.mkdtemp())
    (tmp / filename).write_text(line + "\n", encoding="utf-8")
    return scan_directory(tmp)


def test_pickle_is_critical():
    fs = _scan_line("a.py", "data = pickle.loads(blob)")
    assert any(f.issue_type == "Pickle deserialization" and f.severity == "CRITICAL" for f in fs)


def test_unsafe_yaml_is_critical():
    fs = _scan_line("b.py", "cfg = yaml.load(stream)")
    assert any(f.severity == "CRITICAL" and "yaml" in f.issue_type.lower() for f in fs)


def test_safe_yaml_not_flagged():
    fs = _scan_line("c.py", "cfg = yaml.load(s, Loader=yaml.SafeLoader)")
    assert not any("yaml" in f.issue_type.lower() for f in fs)


def test_php_unserialize_is_critical():
    fs = _scan_line("d.php", "x = unserialize(d);")
    assert any(f.issue_type == "PHP unserialize()" and f.severity == "CRITICAL" for f in fs)


def test_java_runtime_exec_is_critical():
    fs = _scan_line("E.java", "Process p = Runtime.getRuntime().exec(cmd);")
    assert any(f.issue_type == "Java Runtime.exec()" and f.severity == "CRITICAL" for f in fs)


def test_jwt_none_is_critical():
    fs = _scan_line("f.js", 'const h = { alg: "none" }')
    assert any(f.issue_type == "JWT 'none' algorithm" and f.severity == "CRITICAL" for f in fs)


def test_tls_disabled_is_high():
    fs = _scan_line("g.js", "const o = { rejectUnauthorized: false }")
    assert any(f.issue_type == "Node TLS verification disabled" and f.severity == "HIGH" for f in fs)


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
