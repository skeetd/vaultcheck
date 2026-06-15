import json
import math
import re
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from .ignore import load_ignore_rules

try:
    import tomllib  # Python 3.11+
except ModuleNotFoundError:  # pragma: no cover
    tomllib = None

OSV_API = "https://api.osv.dev/v1/query"
OSV_BATCH_API = "https://api.osv.dev/v1/querybatch"
OSV_VULN_API = "https://api.osv.dev/v1/vulns/"
OSV_BATCH_SIZE = 100  # OSV accepts up to 1000 queries per batch; stay conservative

_SKIP_PARTS = {"node_modules", ".venv", "venv", "env", "dist", "build"}


@dataclass
class DepFinding:
    file: str
    package: str
    version: str
    ecosystem: str
    severity: str
    vuln_id: str
    summary: str
    fixed_version: Optional[str]

    @property
    def remediation(self) -> str:
        if not self.fixed_version:
            return "No fixed version yet — assess exploitability or replace the package."
        tmpl = _FIX_CMD.get(self.ecosystem)
        cmd = tmpl.format(pkg=self.package, fix=self.fixed_version) if tmpl else ""
        return f"Upgrade to {self.fixed_version}" + (f"  ·  {cmd}" if cmd else "")


# Upgrade command per ecosystem, used by DepFinding.remediation
_FIX_CMD = {
    "PyPI":      "pip install '{pkg}>={fix}'",
    "npm":       "npm install {pkg}@{fix}",
    "Go":        "go get {pkg}@v{fix} && go mod tidy",
    "RubyGems":  "bundle update {pkg}",
    "crates.io": "cargo update -p {pkg} --precise {fix}",
    "Packagist": "composer require {pkg}:^{fix}",
}


@dataclass
class LicenseFinding:
    file: str
    package: str
    version: str
    ecosystem: str
    license: str
    severity: str
    reason: str


# Licenses that commonly cause compliance problems in proprietary/commercial products.
# Severity reflects typical risk for a closed-source business, not legal advice.
_COPYLEFT_STRONG = {"GPL-2.0", "GPL-2.0-only", "GPL-2.0-or-later", "GPL-3.0", "GPL-3.0-only",
                    "GPL-3.0-or-later", "AGPL-3.0", "AGPL-3.0-only", "AGPL-3.0-or-later"}
_COPYLEFT_WEAK = {"LGPL-2.1", "LGPL-2.1-only", "LGPL-2.1-or-later", "LGPL-3.0",
                  "LGPL-3.0-only", "LGPL-3.0-or-later", "MPL-2.0", "EPL-1.0", "EPL-2.0", "CDDL-1.0", "CDDL-1.1"}
_UNKNOWN_OR_NONE = {"", "UNKNOWN", "NOASSERTION", "NONE"}

_DEPSDEV_ECOSYSTEM = {
    "PyPI": "pypi", "npm": "npm", "Go": "go", "RubyGems": "rubygems",
    "Packagist": "packagist", "crates.io": "cargo",
}


def _query_license(package: str, version: str, ecosystem: str) -> Optional[str]:
    """Look up the SPDX license for a package@version via deps.dev (covers all our ecosystems)."""
    dd_eco = _DEPSDEV_ECOSYSTEM.get(ecosystem)
    if not dd_eco:
        return None
    url = (f"https://api.deps.dev/v3/systems/{dd_eco}/packages/"
           f"{urllib.parse.quote(package, safe='')}/versions/{urllib.parse.quote(version, safe='')}")
    try:
        req = urllib.request.Request(url, headers={"Accept": "application/json"})
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read())
    except Exception:
        return None
    licenses = data.get("licenses") or []
    return licenses[0] if licenses else "UNKNOWN"


def _classify_license(spdx: str) -> Optional[tuple[str, str]]:
    """Return (severity, reason) if a license warrants a finding, else None."""
    norm = spdx.strip()
    if norm in _UNKNOWN_OR_NONE:
        return ("LOW", "No license metadata found — verify usage rights manually.")
    if norm in _COPYLEFT_STRONG:
        return ("HIGH", f"{norm} is a strong copyleft license — may require releasing source "
                        "of derivative/linked works.")
    if norm in _COPYLEFT_WEAK:
        return ("MEDIUM", f"{norm} is a weak copyleft / reciprocal license — review obligations "
                          "for modifications and distribution.")
    return None


def _post_json(url: str, payload: dict, timeout: int = 30) -> dict:
    req = urllib.request.Request(
        url,
        data=json.dumps(payload).encode(),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read())


def _query_osv(package: str, version: str, ecosystem: str) -> list[dict]:
    """Single-package query (full vuln objects). Kept for the registry 'package' check."""
    try:
        return _post_json(
            OSV_API, {"package": {"name": package, "ecosystem": ecosystem}, "version": version}, timeout=15
        ).get("vulns", [])
    except Exception:
        return []


def _query_osv_batch(queries: list[tuple[str, str, str]]) -> list[list[str]]:
    """Batch-query OSV for many (name, version, ecosystem) tuples at once.

    The batch endpoint returns only vuln *ids* per query (not full objects), so the
    return value is, per input query, a list of vuln-id strings. A clean repo costs a
    single round-trip per OSV_BATCH_SIZE packages instead of one call per package.
    """
    out: list[list[str]] = [[] for _ in queries]
    for start in range(0, len(queries), OSV_BATCH_SIZE):
        chunk = queries[start:start + OSV_BATCH_SIZE]
        body = {"queries": [
            {"package": {"name": n, "ecosystem": e}, "version": v} for (n, v, e) in chunk
        ]}
        try:
            data = _post_json(OSV_BATCH_API, body)
        except Exception:
            continue
        for i, res in enumerate(data.get("results", [])):
            out[start + i] = [v["id"] for v in (res.get("vulns") or []) if v.get("id")]
    return out


_VULN_CACHE: dict[str, dict] = {}


def _fetch_vuln(vuln_id: str) -> dict:
    """Fetch a full vuln object by id (cached). Used after a batch query identifies hits."""
    if vuln_id in _VULN_CACHE:
        return _VULN_CACHE[vuln_id]
    try:
        req = urllib.request.Request(
            OSV_VULN_API + urllib.parse.quote(vuln_id),
            headers={"Accept": "application/json"},
        )
        with urllib.request.urlopen(req, timeout=20) as resp:
            data = json.loads(resp.read())
    except Exception:
        data = {}
    _VULN_CACHE[vuln_id] = data
    return data


def _label_from_score(score: float) -> str:
    if score >= 9.0:
        return "CRITICAL"
    if score >= 7.0:
        return "HIGH"
    if score >= 4.0:
        return "MEDIUM"
    return "LOW"


# CVSS v3.x base-score metric weights (spec section 7.1)
_CVSS3 = {
    "AV": {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2},
    "AC": {"L": 0.77, "H": 0.44},
    "UI": {"N": 0.85, "R": 0.62},
    "C":  {"H": 0.56, "L": 0.22, "N": 0.0},
    "I":  {"H": 0.56, "L": 0.22, "N": 0.0},
    "A":  {"H": 0.56, "L": 0.22, "N": 0.0},
}
_PR_UNCHANGED = {"N": 0.85, "L": 0.62, "H": 0.27}
_PR_CHANGED   = {"N": 0.85, "L": 0.68, "H": 0.5}


def _cvss3_base_score(vector: str) -> Optional[float]:
    """Compute a CVSS v3.x base score from a vector string."""
    try:
        parts = dict(p.split(":", 1) for p in vector.split("/") if ":" in p)
        scope_changed = parts.get("S") == "C"
        av = _CVSS3["AV"][parts["AV"]]
        ac = _CVSS3["AC"][parts["AC"]]
        ui = _CVSS3["UI"][parts["UI"]]
        pr = (_PR_CHANGED if scope_changed else _PR_UNCHANGED)[parts["PR"]]
        c, i, a = _CVSS3["C"][parts["C"]], _CVSS3["I"][parts["I"]], _CVSS3["A"][parts["A"]]
    except (KeyError, ValueError):
        return None

    iss = 1 - (1 - c) * (1 - i) * (1 - a)
    if scope_changed:
        impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15
    else:
        impact = 6.42 * iss
    if impact <= 0:
        return 0.0
    exploitability = 8.22 * av * ac * pr * ui
    raw = 1.08 * (impact + exploitability) if scope_changed else impact + exploitability
    return math.ceil(min(raw, 10.0) * 10) / 10  # round up to 1 decimal


def _severity_from_vuln(vuln: dict) -> str:
    best: Optional[float] = None
    for sev in vuln.get("severity", []):
        score_raw = str(sev.get("score", "")).strip()
        try:
            num = float(score_raw)
            best = num if best is None else max(best, num)
            continue
        except ValueError:
            pass
        if score_raw.upper().startswith("CVSS:"):
            computed = _cvss3_base_score(score_raw)
            if computed is not None:
                best = computed if best is None else max(best, computed)
    if best is not None:
        return _label_from_score(best)

    # Fallback: GHSA qualitative severity when no CVSS vector is present
    qual = str(vuln.get("database_specific", {}).get("severity", "")).upper()
    if qual == "MODERATE":
        return "MEDIUM"
    if qual in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
        return qual
    return "MEDIUM"


def _fixed_version(vuln: dict) -> Optional[str]:
    for affected in vuln.get("affected", []):
        for r in affected.get("ranges", []):
            for event in r.get("events", []):
                if "fixed" in event:
                    return event["fixed"]
    return None


def _parse_requirements_txt(filepath: Path) -> list[tuple[str, str]]:
    packages = []
    for line in filepath.read_text(encoding="utf-8", errors="replace").splitlines():
        line = line.strip()
        if not line or line.startswith(("#", "-", "git+", "http")):
            continue
        m = re.match(r"^([A-Za-z0-9_\-\.]+)\s*[=<>!~^]{1,2}\s*([0-9][^\s,;#]*)", line)
        if m:
            packages.append((m.group(1), m.group(2).strip()))
    return packages


def _parse_package_json(filepath: Path) -> list[tuple[str, str]]:
    try:
        data = json.loads(filepath.read_text(encoding="utf-8"))
    except Exception:
        return []
    packages = []
    for section in ("dependencies", "devDependencies"):
        for name, ver in data.get(section, {}).items():
            ver = re.sub(r"^[^0-9]*", "", str(ver))
            if ver:
                packages.append((name, ver))
    return packages


def _parse_go_mod(filepath: Path) -> list[tuple[str, str]]:
    packages = []
    in_block = False
    for raw in filepath.read_text(encoding="utf-8", errors="replace").splitlines():
        line = raw.split("//", 1)[0].strip()
        if not line:
            continue
        if line.startswith("require") and "(" in line:
            in_block = True
            continue
        if in_block and line == ")":
            in_block = False
            continue
        if line.startswith("require "):
            line = line[len("require "):].strip()
        elif not in_block:
            continue
        m = re.match(r"^(\S+)\s+v([0-9]\S*)", line)
        if m:
            packages.append((m.group(1), m.group(2)))  # OSV's Go ecosystem drops the leading 'v'
    return packages


def _parse_gemfile_lock(filepath: Path) -> list[tuple[str, str]]:
    packages = []
    for raw in filepath.read_text(encoding="utf-8", errors="replace").splitlines():
        m = re.match(r"^    (\S+) \(([0-9][^)]*)\)\s*$", raw)  # 4-space spec line, pinned version
        if m:
            packages.append((m.group(1), m.group(2)))
    return packages


def _parse_composer_lock(filepath: Path) -> list[tuple[str, str]]:
    try:
        data = json.loads(filepath.read_text(encoding="utf-8"))
    except Exception:
        return []
    packages = []
    for section in ("packages", "packages-dev"):
        for pkg in data.get(section, []):
            name = pkg.get("name", "")
            ver = str(pkg.get("version", "")).lstrip("v")
            if name and ver[:1].isdigit():
                packages.append((name, ver))
    return packages


def _parse_toml_lock(filepath: Path) -> list[tuple[str, str]]:
    """Cargo.lock and poetry.lock both list [[package]] tables with name + version."""
    if tomllib is None:
        return []
    try:
        data = tomllib.loads(filepath.read_text(encoding="utf-8"))
    except Exception:
        return []
    out = []
    for pkg in data.get("package", []):
        name, ver = pkg.get("name"), pkg.get("version")
        if name and ver:
            out.append((name, str(ver)))
    return out


_MANIFEST_PARSERS = {
    "requirements.txt": ("PyPI",      _parse_requirements_txt),
    "package.json":     ("npm",       _parse_package_json),
    "go.mod":           ("Go",        _parse_go_mod),
    "Gemfile.lock":     ("RubyGems",  _parse_gemfile_lock),
    "composer.lock":    ("Packagist", _parse_composer_lock),
    "Cargo.lock":       ("crates.io", _parse_toml_lock),
    "poetry.lock":      ("PyPI",      _parse_toml_lock),
}


def scan_directory(root: Path, ignore_rules=None) -> list[DepFinding]:
    if ignore_rules is None:
        ignore_rules = load_ignore_rules(root)
    # 1. Collect every declared package across all manifests first…
    collected: list[tuple[str, str, str, str]] = []  # (rel_file, pkg, version, ecosystem)
    for filename, (ecosystem, parser) in _MANIFEST_PARSERS.items():
        for dep_file in root.rglob(filename):
            if any(p in _SKIP_PARTS for p in dep_file.parts):
                continue
            rel = str(dep_file.relative_to(root))
            if ignore_rules.match(rel):
                continue
            for pkg, ver in parser(dep_file):
                collected.append((rel, pkg, ver, ecosystem))
    if not collected:
        return []

    # 2. …ask OSV about all of them in one batched round-trip (ids only)…
    id_lists = _query_osv_batch([(pkg, ver, eco) for (_rel, pkg, ver, eco) in collected])

    # 3. …then fetch full details only for the packages that actually have advisories.
    findings: list[DepFinding] = []
    for (rel, pkg, ver, eco), vuln_ids in zip(collected, id_lists):
        for vid in vuln_ids:
            vuln = _fetch_vuln(vid)
            if not vuln:
                continue
            findings.append(DepFinding(
                file=rel,
                package=pkg,
                version=ver,
                ecosystem=eco,
                severity=_severity_from_vuln(vuln),
                vuln_id=vuln.get("id", vid),
                summary=(vuln.get("summary") or "No summary available.")[:200],
                fixed_version=_fixed_version(vuln),
            ))
    return findings


def scan_licenses(root: Path) -> list[LicenseFinding]:
    """Check declared dependency licenses for copyleft/unknown licenses that may pose
    compliance risk in proprietary products. Uses the same manifest parsers as the
    vulnerability scan, with license data from deps.dev.
    """
    findings: list[LicenseFinding] = []
    ignore_rules = load_ignore_rules(root)
    for filename, (ecosystem, parser) in _MANIFEST_PARSERS.items():
        for dep_file in root.rglob(filename):
            if any(p in _SKIP_PARTS for p in dep_file.parts):
                continue
            rel = str(dep_file.relative_to(root))
            if ignore_rules.match(rel):
                continue
            for pkg, ver in parser(dep_file):
                spdx = _query_license(pkg, ver, ecosystem)
                if spdx is None:
                    continue  # lookup failed / unsupported ecosystem — skip rather than false-flag
                classification = _classify_license(spdx)
                if classification:
                    severity, reason = classification
                    findings.append(LicenseFinding(
                        file=rel,
                        package=pkg,
                        version=ver,
                        ecosystem=ecosystem,
                        license=spdx or "UNKNOWN",
                        severity=severity,
                        reason=reason,
                    ))
    return findings
