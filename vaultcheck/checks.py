"""Non-repo security checks: websites (passive) and email-breach lookups.

Small registry so more check types are easy to add later ("etc.").

Website checks here are PASSIVE — a single normal request + a TLS handshake, safe
for any public URL (the way securityheaders.com / SSL Labs work). Active or
intrusive testing must be limited to sites you own or are authorized to test.
"""
import hashlib
import ipaddress
import json
import os
import socket
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field


@dataclass
class CheckFinding:
    severity: str
    title: str
    detail: str = ""


@dataclass
class CheckResult:
    check_type: str
    target: str
    findings: list = field(default_factory=list)
    errors: list = field(default_factory=list)
    summary: str = ""  # optional one-line headline for the check


_SECURITY_HEADERS = {
    "strict-transport-security": ("MEDIUM", "HSTS not set", "Add Strict-Transport-Security to enforce HTTPS."),
    "content-security-policy":   ("MEDIUM", "No Content-Security-Policy", "A CSP mitigates XSS and data injection."),
    "x-content-type-options":    ("LOW", "X-Content-Type-Options missing", "Set to 'nosniff' to stop MIME sniffing."),
    "x-frame-options":           ("LOW", "X-Frame-Options missing", "Prevent clickjacking (or use CSP frame-ancestors)."),
    "referrer-policy":           ("LOW", "Referrer-Policy missing", "Limit referrer leakage to other sites."),
    "permissions-policy":        ("LOW", "Permissions-Policy missing", "Restrict browser features (camera, geolocation, ...)."),
}


def _resolves_public(host: str) -> bool:
    """SSRF guard: True only if every resolved address is a public, routable IP."""
    try:
        infos = socket.getaddrinfo(host, None)
    except Exception:  # noqa: BLE001
        return False
    for info in infos:
        try:
            addr = ipaddress.ip_address(info[4][0])
        except ValueError:
            continue
        if (addr.is_private or addr.is_loopback or addr.is_link_local
                or addr.is_reserved or addr.is_multicast or addr.is_unspecified):
            return False
    return True


def check_website(url: str) -> CheckResult:
    """Passive web security posture: HTTPS, security headers, cookies, TLS expiry."""
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    findings: list = []
    errors: list = []
    host = urllib.parse.urlparse(url).hostname
    if not host:
        return CheckResult("website", url, [], ["Invalid URL — could not parse a host."])
    if not _resolves_public(host):
        return CheckResult("website", url, [], ["Refusing to scan a private, loopback, or link-local address."])

    try:
        req = urllib.request.Request(url, headers={"User-Agent": "vaultcheck"}, method="GET")
        with urllib.request.urlopen(req, timeout=15) as resp:
            headers = {k.lower(): v for k, v in resp.headers.items()}
            cookies = resp.headers.get_all("Set-Cookie") or []
            final_url = resp.geturl()
    except Exception as exc:  # noqa: BLE001
        return CheckResult("website", url, [], [f"Could not fetch {url}: {exc}"])

    if not final_url.startswith("https://"):
        findings.append(CheckFinding("HIGH", "Site not served over HTTPS",
                                     "Traffic is unencrypted — enable TLS and redirect HTTP to HTTPS."))

    for header, (sev, title, detail) in _SECURITY_HEADERS.items():
        if header not in headers:
            findings.append(CheckFinding(sev, title, detail))

    if headers.get("server") and any(ch.isdigit() for ch in headers["server"]):
        findings.append(CheckFinding("LOW", "Server version disclosed", f"Server: {headers['server']}"))
    if "x-powered-by" in headers:
        findings.append(CheckFinding("LOW", "Technology disclosed", f"X-Powered-By: {headers['x-powered-by']}"))

    if cookies and any("secure" not in c.lower() for c in cookies):
        findings.append(CheckFinding("MEDIUM", "Cookie without Secure flag", "A cookie may be sent over plain HTTP."))
    if cookies and any("httponly" not in c.lower() for c in cookies):
        findings.append(CheckFinding("LOW", "Cookie without HttpOnly flag", "A cookie is readable by JavaScript (XSS risk)."))

    if host and final_url.startswith("https://"):
        try:
            ctx = ssl.create_default_context()
            with socket.create_connection((host, 443), timeout=10) as sock:
                with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                    cert = ssock.getpeercert()
            days = int((ssl.cert_time_to_seconds(cert["notAfter"]) - time.time()) / 86400)
            if days < 0:
                findings.append(CheckFinding("CRITICAL", "TLS certificate expired", f"Expired {abs(days)} day(s) ago."))
            elif days < 15:
                findings.append(CheckFinding("HIGH", "TLS certificate expiring soon", f"{days} day(s) left."))
            elif days < 30:
                findings.append(CheckFinding("MEDIUM", "TLS certificate expiring soon", f"{days} day(s) left."))
        except ssl.SSLCertVerificationError as exc:
            findings.append(CheckFinding("HIGH", "TLS certificate invalid", str(exc)))
        except Exception as exc:  # noqa: BLE001
            errors.append(f"TLS check failed: {exc}")

    present = sum(1 for h in _SECURITY_HEADERS if h in headers)
    grade = "A" if present >= 6 else "B" if present >= 5 else "C" if present >= 4 else "D" if present >= 2 else "F"
    summary = f"Security header grade: {grade} ({present}/6 headers, {'HTTPS' if final_url.startswith('https') else 'no HTTPS'})"
    return CheckResult("website", final_url, findings, errors, summary=summary)


def check_email_breach(email: str) -> CheckResult:
    """Look up an email in Have I Been Pwned. Requires HIBP_API_KEY.

    Use for emails you are responsible for. A 404 from HIBP means 'not found in
    any known breach' (good news).
    """
    api_key = os.environ.get("HIBP_API_KEY")
    if not api_key:
        return CheckResult("breach", email, [], [
            "HIBP_API_KEY not set. Email breach lookup needs a Have I Been Pwned "
            "API key (https://haveibeenpwned.com/API/Key)."
        ])

    api = (
        "https://haveibeenpwned.com/api/v3/breachedaccount/"
        f"{urllib.parse.quote(email)}?truncateResponse=false"
    )
    req = urllib.request.Request(api, headers={"hibp-api-key": api_key, "User-Agent": "vaultcheck"})
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            breaches = json.loads(resp.read())
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            return CheckResult("breach", email, [], [])  # clean
        return CheckResult("breach", email, [], [f"HIBP error {exc.code}: {exc.reason}"])
    except Exception as exc:  # noqa: BLE001
        return CheckResult("breach", email, [], [str(exc)])

    findings = []
    for b in breaches:
        data_classes = b.get("DataClasses", [])
        sev = "HIGH" if "Passwords" in data_classes else "MEDIUM"
        detail = "Exposed data: " + ", ".join(data_classes) if data_classes else ""
        findings.append(CheckFinding(sev, f"Found in breach: {b.get('Title', b.get('Name'))} ({b.get('BreachDate', '?')})", detail))
    return CheckResult("breach", email, findings, [])


def check_pwned_password(password: str) -> CheckResult:
    """Check a password against the HIBP Pwned Passwords corpus via k-anonymity.

    Only the first 5 chars of the SHA-1 hash leave the machine — the password
    itself is never sent, logged, or shown. Free, no API key.
    """
    sha1 = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
    prefix, suffix = sha1[:5], sha1[5:]
    try:
        req = urllib.request.Request(
            f"https://api.pwnedpasswords.com/range/{prefix}",
            headers={"User-Agent": "vaultcheck", "Add-Padding": "true"},
        )
        with urllib.request.urlopen(req, timeout=15) as resp:
            body = resp.read().decode()
    except Exception as exc:  # noqa: BLE001
        return CheckResult("pwned-password", "(password not shown)", [], [str(exc)])

    count = 0
    for line in body.splitlines():
        h, _, c = line.partition(":")
        if h.strip() == suffix:
            count = int(c.strip() or "0")
            break
    if count > 0:
        sev = "HIGH" if count >= 1000 else "MEDIUM"
        return CheckResult("pwned-password", "(password not shown)", [
            CheckFinding(sev, "Password found in known breaches",
                         f"Seen {count:,} time(s) — choose a different password.")
        ], [])
    return CheckResult("pwned-password", "(password not shown)", [], [])


def _doh(name: str, rtype: str) -> dict:
    """Resolve a DNS record via DNS-over-HTTPS (no extra dependency)."""
    url = f"https://dns.google/resolve?name={urllib.parse.quote(name)}&type={rtype}"
    req = urllib.request.Request(url, headers={"User-Agent": "vaultcheck"})
    with urllib.request.urlopen(req, timeout=15) as resp:
        return json.loads(resp.read())


def check_dns_health(domain: str) -> CheckResult:
    """Email-auth & DNS hygiene: SPF, DMARC, DNSSEC, MX."""
    domain = domain.strip().lower().rstrip(".")
    if domain.startswith(("http://", "https://")):
        domain = urllib.parse.urlparse(domain).hostname or domain
    findings: list = []
    errors: list = []
    try:
        txt = [a.get("data", "").strip('"') for a in _doh(domain, "TXT").get("Answer", [])]
        spf = [t for t in txt if t.lower().startswith("v=spf1")]
        if not spf:
            findings.append(CheckFinding("MEDIUM", "No SPF record", "Add an SPF TXT record to curb email spoofing."))
        elif any("+all" in s.lower() for s in spf):
            findings.append(CheckFinding("HIGH", "SPF allows all senders (+all)", "Tighten the policy to ~all or -all."))

        dmarc = [a.get("data", "").strip('"') for a in _doh(f"_dmarc.{domain}", "TXT").get("Answer", [])
                 if "v=dmarc1" in a.get("data", "").lower()]
        if not dmarc:
            findings.append(CheckFinding("MEDIUM", "No DMARC record", "Add a _dmarc TXT record (start at p=none)."))
        elif any("p=none" in d.lower() for d in dmarc):
            findings.append(CheckFinding("LOW", "DMARC policy is p=none", "Move to p=quarantine or p=reject when ready."))

        if not _doh(domain, "A").get("AD"):
            findings.append(CheckFinding("LOW", "DNSSEC not validated", "Responses are not DNSSEC-signed/validated."))
        if not _doh(domain, "MX").get("Answer"):
            findings.append(CheckFinding("LOW", "No MX records", "No mail servers configured for this domain."))
    except Exception as exc:  # noqa: BLE001
        errors.append(f"DNS lookup failed: {exc}")
    return CheckResult("dns", domain, findings, errors)


def check_security_txt(target: str) -> CheckResult:
    """Check for an RFC 9116 /.well-known/security.txt (a place to report issues)."""
    host = urllib.parse.urlparse(target).hostname if target.startswith(("http://", "https://")) else target
    host = (host or "").strip().strip("/").lower()
    if not host or not _resolves_public(host):
        return CheckResult("security-txt", target, [], ["Refusing to check a private or unresolvable host."])

    for path in ("/.well-known/security.txt", "/security.txt"):
        try:
            req = urllib.request.Request(f"https://{host}{path}", headers={"User-Agent": "vaultcheck"})
            with urllib.request.urlopen(req, timeout=12) as resp:
                if resp.status == 200:
                    body = resp.read(4000).decode("utf-8", "replace")
                    if "contact:" in body.lower():
                        return CheckResult("security-txt", host, [], [], summary=f"security.txt found at {path}")
                    return CheckResult("security-txt", host, [
                        CheckFinding("LOW", "security.txt present but missing Contact field", "RFC 9116 requires a Contact field.")
                    ], [])
        except Exception:  # noqa: BLE001
            continue

    return CheckResult("security-txt", host, [
        CheckFinding("LOW", "No security.txt (RFC 9116)", "Add /.well-known/security.txt so researchers can reach you.")
    ], [], summary="No security.txt found")


def _typo_variants(name: str, tld: str) -> list:
    out = set()
    for i in range(len(name)):                       # character omission
        out.add(f"{name[:i]}{name[i + 1:]}.{tld}")
    for i in range(len(name) - 1):                   # adjacent transposition
        chars = list(name)
        chars[i], chars[i + 1] = chars[i + 1], chars[i]
        out.add(f"{''.join(chars)}.{tld}")
    for i in range(len(name)):                        # character doubling
        out.add(f"{name[:i + 1]}{name[i]}{name[i + 1:]}.{tld}")
    for t in ("com", "net", "org", "co", "io", "app", "dev", "xyz"):  # TLD swap
        if t != tld:
            out.add(f"{name}.{t}")
    out.discard(f"{name}.{tld}")
    return sorted(v for v in out if not v.startswith("."))


def check_typosquat(domain: str) -> CheckResult:
    """Find registered look-alike domains of a brand (omission/transposition/TLD swaps)."""
    if domain.startswith(("http://", "https://")):
        domain = urllib.parse.urlparse(domain).hostname or domain
    domain = domain.strip().lower().rstrip(".")
    if domain.startswith("www."):
        domain = domain[4:]
    if "." not in domain:
        return CheckResult("typosquat", domain, [], ["Enter a domain like example.com."])

    name, _, tld = domain.rpartition(".")
    variants = _typo_variants(name, tld)[:20]  # bounded — one DNS lookup each
    findings, errors, checked = [], [], 0
    for variant in variants:
        try:
            if _doh(variant, "NS").get("Answer"):
                findings.append(CheckFinding("MEDIUM", f"Look-alike domain registered: {variant}",
                                             "A typosquat of your domain is registered — possible phishing vector."))
            checked += 1
        except Exception as exc:  # noqa: BLE001
            errors.append(f"{variant}: {exc}")
    return CheckResult("typosquat", domain, findings, errors,
                       summary=f"Checked {checked} look-alikes; {len(findings)} registered.")
