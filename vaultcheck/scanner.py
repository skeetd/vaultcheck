import re
import shutil
import subprocess
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from .code_scanner import CodeFinding, scan_directory as _scan_code
from .deps_scanner import DepFinding, scan_directory as _scan_deps
from .secrets_scanner import SecretFinding, scan_directory as _scan_secrets

ALL_PHASES = ("secrets", "deps", "code")


@dataclass
class ScanResult:
    target: str
    secrets: list[SecretFinding] = field(default_factory=list)
    deps: list[DepFinding] = field(default_factory=list)
    code: list[CodeFinding] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    phases: tuple = ()  # which scan phases actually ran

    @property
    def all_findings(self):
        return self.secrets + self.deps + self.code

    @property
    def severity_counts(self) -> dict[str, int]:
        counts: dict[str, int] = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        for f in self.all_findings:
            counts[f.severity] = counts.get(f.severity, 0) + 1
        return counts

    @property
    def total(self) -> int:
        return len(self.all_findings)


def _is_github_url(target: str) -> bool:
    # GitHub or GitLab — both are cloneable over https
    return bool(re.match(r"https?://(?:github|gitlab)\.com/", target))


def _clone(url: str, dest: Path, token: Optional[str] = None) -> bool:
    if token:
        url = url.replace("https://", f"https://{token}@")
    result = subprocess.run(
        ["git", "clone", "--depth", "1", url, str(dest)],
        capture_output=True,
        timeout=120,
    )
    return result.returncode == 0


def run_scan(
    target: str,
    phases: tuple[str, ...] = ALL_PHASES,
    github_token: Optional[str] = None,
) -> ScanResult:
    result = ScanResult(target=target)
    result.phases = tuple(phases)
    tmpdir: Optional[Path] = None

    if _is_github_url(target):
        tmpdir = Path(tempfile.mkdtemp(prefix="vaultcheck_"))
        if not _clone(target, tmpdir, github_token):
            shutil.rmtree(tmpdir, ignore_errors=True)
            result.errors.append(f"Failed to clone: {target}")
            return result
        scan_path = tmpdir
    else:
        scan_path = Path(target).resolve()
        if not scan_path.exists():
            result.errors.append(f"Path not found: {scan_path}")
            return result

    try:
        if "secrets" in phases:
            result.secrets = _scan_secrets(scan_path)
        if "deps" in phases:
            result.deps = _scan_deps(scan_path)
        if "code" in phases:
            result.code = _scan_code(scan_path)
    finally:
        if tmpdir:
            shutil.rmtree(tmpdir, ignore_errors=True)

    return result
