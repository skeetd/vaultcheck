"""OSV batch query: chunking, hit mapping, and DepFinding construction (network mocked)."""
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from vaultcheck import deps_scanner as ds


# Canned OSV vuln object for a known-bad package.
_VULN = {
    "id": "GHSA-xxxx-yyyy-zzzz",
    "summary": "Example advisory",
    "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}],
    "affected": [{"ranges": [{"events": [{"introduced": "0"}, {"fixed": "2.20.0"}]}]}],
}


def _patch(monkeypatch_pairs):
    saved = {name: getattr(ds, name) for name, _ in monkeypatch_pairs}
    for name, fn in monkeypatch_pairs:
        setattr(ds, name, fn)
    return saved


def _restore(saved):
    for name, fn in saved.items():
        setattr(ds, name, fn)


def test_batch_maps_hits_to_findings():
    calls = {"batch": 0}

    def fake_post(url, payload, timeout=30):
        calls["batch"] += 1
        # one query per package; return a vuln id only for "requests"
        results = []
        for q in payload["queries"]:
            if q["package"]["name"] == "requests":
                results.append({"vulns": [{"id": _VULN["id"]}]})
            else:
                results.append({})
        return {"results": results}

    saved = _patch([("_post_json", fake_post), ("_fetch_vuln", lambda vid: _VULN)])
    try:
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            (root / "requirements.txt").write_text("requests==2.19.1\nflask==2.0.0\n", encoding="utf-8")
            findings = ds.scan_directory(root)
    finally:
        _restore(saved)

    assert calls["batch"] == 1, "should batch all packages into a single call"
    assert len(findings) == 1, f"expected 1 finding, got {len(findings)}"
    f = findings[0]
    assert f.package == "requests" and f.severity == "CRITICAL" and f.fixed_version == "2.20.0", vars(f)


def test_batch_chunks_over_100():
    seen_sizes = []

    def fake_post(url, payload, timeout=30):
        seen_sizes.append(len(payload["queries"]))
        return {"results": [{} for _ in payload["queries"]]}

    saved = _patch([("_post_json", fake_post), ("_fetch_vuln", lambda vid: {})])
    try:
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            lines = "".join(f"pkg{i}==1.0.0\n" for i in range(230))
            (root / "requirements.txt").write_text(lines, encoding="utf-8")
            ds.scan_directory(root)
    finally:
        _restore(saved)

    assert seen_sizes == [100, 100, 30], seen_sizes


def test_no_packages_no_network():
    def boom(*a, **k):
        raise AssertionError("network should not be called for an empty tree")

    saved = _patch([("_post_json", boom)])
    try:
        with tempfile.TemporaryDirectory() as d:
            assert ds.scan_directory(Path(d)) == []
    finally:
        _restore(saved)


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
