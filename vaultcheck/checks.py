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
from datetime import datetime, timezone

from .deps_scanner import _fixed_version, _query_osv, _severity_from_vuln


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


def _hostname(target: str) -> str:
    if target.startswith(("http://", "https://")):
        target = urllib.parse.urlparse(target).hostname or target
    return target.strip().strip("/").lower().rstrip(".")


def check_subdomains(domain: str) -> CheckResult:
    """Discover subdomains from Certificate Transparency logs (crt.sh). Passive."""
    domain = _hostname(domain)
    if not domain:
        return CheckResult("subdomains", domain, [], ["Enter a domain like example.com."])
    try:
        req = urllib.request.Request(
            f"https://crt.sh/?q={urllib.parse.quote('%.' + domain)}&output=json",
            headers={"User-Agent": "vaultcheck"},
        )
        with urllib.request.urlopen(req, timeout=30) as resp:
            data = json.loads(resp.read() or "[]")
    except Exception as exc:  # noqa: BLE001
        return CheckResult("subdomains", domain, [], [f"crt.sh lookup failed: {exc}"])

    subs = set()
    for entry in data:
        for name in str(entry.get("name_value", "")).splitlines():
            name = name.strip().lower().lstrip("*.")
            if name.endswith(domain) and name != domain:
                subs.add(name)
    findings = [CheckFinding("LOW", s, "Subdomain found in certificate transparency logs.")
                for s in sorted(subs)[:100]]
    return CheckResult("subdomains", domain, findings, [],
                       summary=f"Found {len(subs)} unique subdomain(s) in CT logs.")


def _tls_supports(host: str, version) -> Optional[bool]:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        ctx.minimum_version = version
        ctx.maximum_version = version
    except (ValueError, OSError):
        return None  # local OpenSSL cannot negotiate this version
    try:
        with socket.create_connection((host, 443), timeout=8) as sock:
            with ctx.wrap_socket(sock, server_hostname=host):
                return True
    except (ssl.SSLError, OSError):
        return False


def check_tls(target: str) -> CheckResult:
    """Deep TLS check: deprecated protocols (TLS 1.0/1.1) and certificate detail."""
    host = _hostname(target)
    if not host:
        return CheckResult("tls", target, [], ["Enter a domain like example.com."])
    findings, errors = [], []

    for label, ver, sev in (("TLS 1.0", ssl.TLSVersion.TLSv1, "HIGH"),
                            ("TLS 1.1", ssl.TLSVersion.TLSv1_1, "MEDIUM")):
        if _tls_supports(host, ver):
            findings.append(CheckFinding(sev, f"{label} is supported (deprecated)",
                                         f"Disable {label}; serve TLS 1.2+ only."))

    summary = ""
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((host, 443), timeout=10) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
        issuer = dict(x[0] for x in cert.get("issuer", [])).get("organizationName", "?")
        days = int((ssl.cert_time_to_seconds(cert["notAfter"]) - time.time()) / 86400)
        if days < 0:
            findings.append(CheckFinding("CRITICAL", "TLS certificate expired", f"Expired {abs(days)} day(s) ago."))
        elif days < 30:
            findings.append(CheckFinding("HIGH" if days < 15 else "MEDIUM",
                                         "TLS certificate expiring soon", f"{days} day(s) left."))
        summary = f"Issuer: {issuer}; certificate valid for {days} more day(s)."
    except ssl.SSLCertVerificationError as exc:
        findings.append(CheckFinding("HIGH", "TLS certificate invalid", str(exc)))
    except Exception as exc:  # noqa: BLE001
        errors.append(f"TLS connection failed: {exc}")

    return CheckResult("tls", host, findings, errors, summary=summary)


def check_cors(url: str) -> CheckResult:
    """Probe for a reflected/permissive CORS policy. One request."""
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    host = urllib.parse.urlparse(url).hostname
    if not host or not _resolves_public(host):
        return CheckResult("cors", url, [], ["Refusing to probe a private or unresolvable host."])
    test_origin = "https://vaultcheck-cors-probe.example"
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "vaultcheck", "Origin": test_origin})
        with urllib.request.urlopen(req, timeout=15) as resp:
            acao = resp.headers.get("Access-Control-Allow-Origin")
            acac = (resp.headers.get("Access-Control-Allow-Credentials") or "").lower() == "true"
    except Exception as exc:  # noqa: BLE001
        return CheckResult("cors", url, [], [f"Request failed: {exc}"])

    findings = []
    if acao == test_origin and acac:
        findings.append(CheckFinding("HIGH", "CORS reflects any origin with credentials",
                                     "Access-Control-Allow-Origin echoes the request Origin AND allows credentials — any site can read authenticated responses."))
    elif acao == test_origin:
        findings.append(CheckFinding("MEDIUM", "CORS reflects any origin",
                                     "Access-Control-Allow-Origin echoes the request Origin — restrict it to known domains."))
    elif acao == "*":
        findings.append(CheckFinding("LOW", "CORS allows all origins (*)",
                                     "Fine for public data, risky for anything authenticated."))
    return CheckResult("cors", url, findings, [],
                       summary="No permissive CORS detected." if not findings else "")


_EXPOSED_PATHS = [
    ("/.git/HEAD", "ref:"),
    ("/.env", "="),
    ("/.svn/entries", ""),
    ("/.DS_Store", ""),
    ("/.aws/credentials", "aws_"),
    ("/server-status", "Apache"),
    ("/backup.zip", ""),
]


def check_exposed_files(url: str) -> CheckResult:
    """Probe for commonly-exposed sensitive files. Authorized targets only."""
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    parsed = urllib.parse.urlparse(url)
    host = parsed.hostname
    if not host or not _resolves_public(host):
        return CheckResult("exposed-files", url, [], ["Refusing to probe a private or unresolvable host."])
    base = f"{parsed.scheme}://{host}"
    findings = []
    for path, marker in _EXPOSED_PATHS:
        try:
            req = urllib.request.Request(base + path, headers={"User-Agent": "vaultcheck"})
            with urllib.request.urlopen(req, timeout=10) as resp:
                if resp.status == 200:
                    body = resp.read(2048).decode("utf-8", "replace")
                    if not marker or marker.lower() in body.lower():
                        findings.append(CheckFinding("HIGH", f"Exposed: {path}",
                                                     "Publicly accessible — block or remove it."))
        except Exception:  # noqa: BLE001
            continue
    return CheckResult("exposed-files", base, findings, [],
                       summary="None of the probed paths were exposed." if not findings else "")


def check_rdap(domain: str) -> CheckResult:
    """Domain registration info (age, registrar, expiry) via RDAP."""
    domain = _hostname(domain)
    if not domain:
        return CheckResult("rdap", domain, [], ["Enter a domain like example.com."])
    try:
        req = urllib.request.Request(f"https://rdap.org/domain/{urllib.parse.quote(domain)}",
                                     headers={"User-Agent": "vaultcheck", "Accept": "application/rdap+json"})
        with urllib.request.urlopen(req, timeout=15) as resp:
            data = json.loads(resp.read())
    except Exception as exc:  # noqa: BLE001
        return CheckResult("rdap", domain, [], [f"RDAP lookup failed: {exc}"])

    events = {e.get("eventAction"): e.get("eventDate") for e in data.get("events", [])}
    reg, exp = events.get("registration"), events.get("expiration")
    registrar = "?"
    try:
        for ent in data.get("entities", []):
            if "registrar" in ent.get("roles", []):
                for v in ent.get("vcardArray", [[], []])[1]:
                    if v[0] == "fn":
                        registrar = v[3]
    except Exception:  # noqa: BLE001
        pass

    def _days_since(iso):
        try:
            dt = datetime.fromisoformat(iso.replace("Z", "+00:00"))
            return (datetime.now(timezone.utc) - dt).days
        except Exception:  # noqa: BLE001
            return None

    findings = []
    age = _days_since(reg) if reg else None
    if age is not None and age < 90:
        findings.append(CheckFinding("MEDIUM", "Recently registered domain",
                                     f"Registered {age} day(s) ago — a common phishing indicator."))
    if exp:
        left = _days_since(exp)
        if left is not None and left > -30:  # within 30 days of (or past) expiry
            findings.append(CheckFinding("MEDIUM", "Domain expiring soon", f"{-left} day(s) until expiry."))
    return CheckResult("rdap", domain, findings, [],
                       summary=f"Registered {reg or '?'}, expires {exp or '?'}, registrar {registrar}.")


def check_caa(domain: str) -> CheckResult:
    """CAA records — which CAs may issue certificates for the domain."""
    domain = _hostname(domain)
    if not domain:
        return CheckResult("caa", domain, [], ["Enter a domain like example.com."])
    try:
        answers = _doh(domain, "CAA").get("Answer", [])
    except Exception as exc:  # noqa: BLE001
        return CheckResult("caa", domain, [], [f"DNS lookup failed: {exc}"])
    issuers = [a.get("data", "").strip() for a in answers if a.get("data")]
    if not issuers:
        return CheckResult("caa", domain, [
            CheckFinding("LOW", "No CAA record",
                         "Without CAA, any certificate authority can issue certs for this domain. Add a CAA record to restrict it.")
        ], [], summary="No CAA records found.")
    return CheckResult("caa", domain, [], [],
                       summary=f"{len(issuers)} CAA record(s): " + ("; ".join(issuers))[:200])


def check_package(target: str) -> CheckResult:
    """Look up a single package@version against OSV. Format: [ecosystem:]name@version."""
    spec = target.strip()
    eco = "PyPI"
    if ":" in spec and "@" in spec and spec.index(":") < spec.index("@"):
        eco, spec = spec.split(":", 1)
    if "@" not in spec:
        return CheckResult("package", target, [],
                           ["Use name@version, e.g. flask@0.12.2 (or npm:lodash@4.17.0)."])
    name, version = (p.strip() for p in spec.rsplit("@", 1))
    eco_map = {"pypi": "PyPI", "pip": "PyPI", "npm": "npm", "go": "Go", "rubygems": "RubyGems",
               "gem": "RubyGems", "crates": "crates.io", "cargo": "crates.io",
               "packagist": "Packagist", "composer": "Packagist"}
    eco = eco_map.get(eco.lower(), eco)
    try:
        vulns = _query_osv(name, version, eco)
    except Exception as exc:  # noqa: BLE001
        return CheckResult("package", target, [], [f"OSV query failed: {exc}"])
    findings = []
    for v in vulns:
        fix = _fixed_version(v)
        detail = (v.get("summary", "") or "")[:150] + (f" — fixed in {fix}" if fix else "")
        findings.append(CheckFinding(_severity_from_vuln(v), v.get("id", "UNKNOWN"), detail))
    return CheckResult("package", f"{eco}:{name}@{version}", findings, [],
                       summary=f"{len(findings)} known vulnerabilit{'y' if len(findings) == 1 else 'ies'} for {name} {version}.")


def check_cve(keyword: str) -> CheckResult:
    """Search NVD for recent CVEs matching a keyword (no API key; rate-limited)."""
    keyword = keyword.strip()
    if not keyword:
        return CheckResult("cve", keyword, [], ["Enter a product or keyword, e.g. openssl."])
    url = ("https://services.nvd.nist.gov/rest/json/cves/2.0?"
           + urllib.parse.urlencode({"keywordSearch": keyword, "resultsPerPage": 10}))
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "vaultcheck"})
        with urllib.request.urlopen(req, timeout=25) as resp:
            data = json.loads(resp.read())
    except Exception as exc:  # noqa: BLE001
        return CheckResult("cve", keyword, [], [f"NVD query failed (rate-limited without a key?): {exc}"])

    findings = []
    for item in data.get("vulnerabilities", [])[:10]:
        cve = item.get("cve", {})
        cid = cve.get("id", "CVE-?")
        desc = next((d["value"] for d in cve.get("descriptions", []) if d.get("lang") == "en"), "")
        sev = "MEDIUM"
        for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            metrics = cve.get("metrics", {}).get(key)
            if metrics:
                base = metrics[0].get("cvssData", {}).get("baseScore")
                if base is not None:
                    sev = "CRITICAL" if base >= 9 else "HIGH" if base >= 7 else "MEDIUM" if base >= 4 else "LOW"
                break
        findings.append(CheckFinding(sev, cid, desc[:200]))
    return CheckResult("cve", keyword, findings, [],
                       summary=f"{data.get('totalResults', len(findings))} total match(es); showing {len(findings)}.")
