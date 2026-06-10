"""Unified check registry — the backbone for growing vaultcheck into a multi-check
platform.

Every capability (repo scan, website, DNS, breach, ...) is a Check with consistent
metadata. Adding a new feature = registering ONE entry here. The CLI and dashboard
can enumerate and run anything in the registry without special-casing.

`requires_auth=True` marks checks that must only target assets the user owns or is
authorized to test (active web scanning, cloud config, port scans, ...).
"""
from dataclasses import dataclass
from typing import Callable

from .checks import (
    CheckFinding,
    CheckResult,
    check_dns_health,
    check_email_breach,
    check_pwned_password,
    check_security_txt,
    check_typosquat,
    check_website,
)
from .scanner import ALL_PHASES, run_scan


@dataclass
class Check:
    id: str
    name: str
    category: str        # Repo | Web | Identity | Cloud | ...
    target_type: str     # repo | url | domain | email | password
    tier: str            # free | pro
    requires_auth: bool  # target must be owned/authorized
    run: Callable[[str], CheckResult]
    description: str = ""


def _repo_check(target: str) -> CheckResult:
    """Adapter: flatten the repo scanner's typed findings into the unified model."""
    res = run_scan(target, phases=ALL_PHASES)
    findings = []
    for s in res.secrets:
        findings.append(CheckFinding(s.severity, f"Secret: {s.secret_type}",
                                     f"{s.file}:{s.line_number} ({s.matched_value})"))
    for d in res.deps:
        findings.append(CheckFinding(d.severity, f"Vulnerable dependency: {d.package}@{d.version}",
                                     f"{d.vuln_id} · {d.remediation}"))
    for c in res.code:
        findings.append(CheckFinding(c.severity, f"Insecure code: {c.issue_type}",
                                     f"{c.file}:{c.line_number}"))
    return CheckResult("repo", target, findings, res.errors)


REGISTRY: list[Check] = [
    Check("repo", "Repository scan", "Repo", "repo", "free", False, _repo_check,
          "Secrets, vulnerable dependencies and insecure code."),
    Check("website", "Website posture", "Web", "url", "free", False, check_website,
          "HTTPS, security headers, cookies, TLS expiry (passive)."),
    Check("dns", "DNS & email auth", "Web", "domain", "free", False, check_dns_health,
          "SPF, DMARC, DNSSEC and MX hygiene."),
    Check("security-txt", "security.txt", "Web", "url", "free", False, check_security_txt,
          "Checks for an RFC 9116 /.well-known/security.txt."),
    Check("typosquat", "Typosquat domains", "Identity", "domain", "free", False, check_typosquat,
          "Finds registered look-alike domains of your brand."),
    Check("breach", "Email breach", "Identity", "email", "free", False, check_email_breach,
          "Have I Been Pwned lookup (needs HIBP_API_KEY)."),
    Check("pwned-password", "Pwned password", "Identity", "password", "free", False, check_pwned_password,
          "Check a password against the breach corpus (k-anonymity)."),
]


def list_checks() -> list[Check]:
    return REGISTRY


def get_check(check_id: str):
    return next((c for c in REGISTRY if c.id == check_id), None)
