import json
import math
import re
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

try:
    import tomllib  # Python 3.11+
except ModuleNotFoundError:  # pragma: no cover
    tomllib = None

OSV_API = "https://api.osv.dev/v1/query"

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


def _query_osv(package: str, version: str, ecosystem: str) -> list[dict]:
    payload = json.dumps(
        {"package": {"name": package, "ecosystem": ecosystem}, "version": version}
    ).encode()
    req = urllib.request.Request(
        OSV_API,
        data=payload,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            return json.loads(resp.read()).get("vulns", [])
    except Exception:
        return []


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


def scan_directory(root: Path) -> list[DepFinding]:
    findings: list[DepFinding] = []
    for filename, (ecosystem, parser) in _MANIFEST_PARSERS.items():
        for dep_file in root.rglob(filename):
            if any(p in _SKIP_PARTS for p in dep_file.parts):
                continue
            rel = str(dep_file.relative_to(root))
            for pkg, ver in parser(dep_file):
                for vuln in _query_osv(pkg, ver, ecosystem):
                    findings.append(DepFinding(
                        file=rel,
                        package=pkg,
                        version=ver,
                        ecosystem=ecosystem,
                        severity=_severity_from_vuln(vuln),
                        vuln_id=vuln.get("id", "UNKNOWN"),
                        summary=vuln.get("summary", "No summary available.")[:200],
                        fixed_version=_fixed_version(vuln),
                    ))
    return findings
