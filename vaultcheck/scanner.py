import re
import shutil
import subprocess
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from .code_scanner import CodeFinding, scan_directory as _scan_code
from .deps_scanner import (
    DepFinding, LicenseFinding, scan_directory as _scan_deps, scan_licenses as _scan_licenses,
)
from .secrets_scanner import (
    SecretFinding, scan_directory as _scan_secrets, scan_git_history as _scan_history,
)

ALL_PHASES = ("secrets", "deps", "code")
# Opt-in phases — slower or network-heavy, so not run unless explicitly requested.
OPTIONAL_PHASES = ("git_history", "licenses")


@dataclass
class ScanResult:
    target: str
    secrets: list[SecretFinding] = field(default_factory=list)
    deps: list[DepFinding] = field(default_factory=list)
    code: list[CodeFinding] = field(default_factory=list)
    git_history: list[SecretFinding] = field(default_factory=list)  # secrets found only in git history
    licenses: list[LicenseFinding] = field(default_factory=list)    # risky dependency licenses
    errors: list[str] = field(default_factory=list)
    phases: tuple = ()  # which scan phases actually ran
    ignored_patterns: list = field(default_factory=list)  # effective .vaultcheckignore patterns

    @property
    def all_findings(self):
        return self.secrets + self.deps + self.code + self.git_history

    @property
    def severity_counts(self) -> dict[str, int]:
        counts: dict[str, int] = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        for f in self.all_findings:
            counts[f.severity] = counts.get(f.severity, 0) + 1
        for f in self.licenses:  # licenses aren't in all_findings (counted, not "findings")
            counts[f.severity] = counts.get(f.severity, 0) + 1
        return counts

    @property
    def total(self) -> int:
        return len(self.all_findings)

    def only_severities(self, severities) -> "ScanResult":
        """Return a copy keeping only findings at the given severity level(s).

        `severities` is any iterable of severity names (case-insensitive), e.g.
        ("critical",) or ("high", "medium"). Phases/errors/metadata are preserved,
        so the report still shows what was scanned — just filtered to these levels.
        """
        keep = {s.upper() for s in severities}

        def _f(items):
            return [x for x in items if x.severity.upper() in keep]

        return ScanResult(
            target=self.target,
            secrets=_f(self.secrets),
            deps=_f(self.deps),
            code=_f(self.code),
            git_history=_f(self.git_history),
            licenses=_f(self.licenses),
            errors=list(self.errors),
            phases=self.phases,
            ignored_patterns=list(self.ignored_patterns),
        )


def _is_github_url(target: str) -> bool:
    # GitHub or GitLab — both are cloneable over https
    return bool(re.match(r"https?://(?:github|gitlab)\.com/", target))


def _clone(url: str, dest: Path, token: Optional[str] = None, full: bool = False) -> bool:
    if token:
        url = url.replace("https://", f"https://{token}@")
    # Full history is needed to find secrets that were committed then removed; otherwise
    # a shallow clone is much faster and enough for a working-tree scan.
    depth = [] if full else ["--depth", "1"]
    result = subprocess.run(
        ["git", "clone", *depth, url, str(dest)],
        capture_output=True,
        timeout=300 if full else 120,
    )
    return result.returncode == 0


def run_scan(
    target: str,
    phases: tuple[str, ...] = ALL_PHASES,
    github_token: Optional[str] = None,
    use_default_ignores: bool = True,
) -> ScanResult:
    result = ScanResult(target=target)
    result.phases = tuple(phases)
    tmpdir: Optional[Path] = None
    need_history = "git_history" in phases  # full clone required to walk past commits

    if _is_github_url(target):
        tmpdir = Path(tempfile.mkdtemp(prefix="vaultcheck_"))
        if not _clone(target, tmpdir, github_token, full=need_history):
            shutil.rmtree(tmpdir, ignore_errors=True)
            result.errors.append(f"Failed to clone: {target}")
            return result
        scan_path = tmpdir
    else:
        scan_path = Path(target).resolve()
        if not scan_path.exists():
            result.errors.append(f"Path not found: {scan_path}")
            return result

    from .ignore import load_ignore_rules
    ignore_rules = load_ignore_rules(scan_path, use_defaults=use_default_ignores)
    result.ignored_patterns = list(ignore_rules.patterns)

    try:
        if "secrets" in phases:
            result.secrets = _scan_secrets(scan_path, ignore_rules=ignore_rules)
        if "deps" in phases:
            result.deps = _scan_deps(scan_path, ignore_rules=ignore_rules)
        if "code" in phases:
            result.code = _scan_code(scan_path, ignore_rules=ignore_rules)
        if need_history:
            if (scan_path / ".git").exists():
                # Don't re-report a secret already visible in the working tree.
                current = {(s.file, s.secret_type, s.matched_value) for s in result.secrets}
                result.git_history = [
                    h for h in _scan_history(scan_path)
                    if (h.file, h.secret_type, h.matched_value) not in current
                ]
            else:
                result.errors.append("git_history: no .git directory found — skipped.")
        if "licenses" in phases:
            result.licenses = _scan_licenses(scan_path)
    finally:
        if tmpdir:
            shutil.rmtree(tmpdir, ignore_errors=True)

    return result
