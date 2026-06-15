"""Stable fingerprints for findings, and diffing between two scans.

A fingerprint is a short, deterministic hash of the identifying parts of a
finding (type + location), so the same issue produces the same ID across scans.
This lets scheduled re-scans report what is NEW, FIXED or unchanged since last time.
"""
import hashlib


def _fp(*parts) -> str:
    raw = "|".join(str(p) for p in parts)
    return hashlib.sha1(raw.encode("utf-8")).hexdigest()[:12]


def fingerprint_result(result) -> list[dict]:
    """Return a list of {id, severity, kind, label} for every finding in a ScanResult."""
    out: list[dict] = []
    for f in getattr(result, "secrets", []):
        out.append({"id": _fp("secret", f.secret_type, f.file, f.line_number),
                    "severity": f.severity, "kind": "secret",
                    "label": f"{f.secret_type} @ {f.file}:{f.line_number}"})
    for f in getattr(result, "deps", []):
        out.append({"id": _fp("dep", f.package, f.version, f.vuln_id),
                    "severity": f.severity, "kind": "dependency",
                    "label": f"{f.package}@{f.version} ({f.vuln_id})"})
    for f in getattr(result, "code", []):
        out.append({"id": _fp("code", f.issue_type, f.file, f.line_number),
                    "severity": f.severity, "kind": "code",
                    "label": f"{f.issue_type} @ {f.file}:{f.line_number}"})
    for f in getattr(result, "git_history", []):
        out.append({"id": _fp("git", f.secret_type, f.file),
                    "severity": f.severity, "kind": "git_history",
                    "label": f"{f.secret_type} ({f.file})"})
    for f in getattr(result, "licenses", []):
        out.append({"id": _fp("license", f.package, f.version, f.license),
                    "severity": f.severity, "kind": "license",
                    "label": f"{f.package}@{f.version}: {f.license}"})
    return out


def diff_fingerprints(previous: list, current: list) -> dict:
    """Compare two fingerprint lists (of dicts or bare id strings).

    Returns {"new": [...], "fixed": [...], "unchanged": [...]} with full dicts
    where available.
    """
    def as_map(items):
        m = {}
        for it in items:
            if isinstance(it, str):
                m[it] = {"id": it, "label": it, "severity": "?", "kind": "?"}
            else:
                m[it["id"]] = it
        return m

    prev = as_map(previous or [])
    cur = as_map(current or [])
    new_ids = cur.keys() - prev.keys()
    fixed_ids = prev.keys() - cur.keys()
    same_ids = cur.keys() & prev.keys()
    return {
        "new": [cur[i] for i in new_ids],
        "fixed": [prev[i] for i in fixed_ids],
        "unchanged": [cur[i] for i in same_ids],
    }
