"""Plain-language explanations for findings.

For each finding category we describe the **impact** (what an attacker can do / what
can go wrong) and **how to secure** it. This is static and fully offline — no API
calls at scan time — keyed by the `category` string the scanners already assign, so
any finding can be explained with a sensible generic fallback.
"""

# category -> (impact, how_to_fix)
EXPLANATIONS: dict[str, tuple[str, str]] = {
    # --- Insecure code ---------------------------------------------------
    "sqli": (
        "An attacker can inject SQL to read, change or delete any data in the database, "
        "bypass authentication, and in some setups run commands on the server.",
        "Use parameterized queries / prepared statements (bound parameters) or a vetted "
        "ORM. Never build SQL by concatenating or string-formatting user input.",
    ),
    "xss": (
        "Injected JavaScript runs in your users' browsers — it can steal sessions and "
        "cookies, log keystrokes, deface the page, or act as the victim.",
        "Encode output for its context and avoid innerHTML / document.write with "
        "untrusted data. Add a Content-Security-Policy and rely on framework auto-escaping.",
    ),
    "cmdi": (
        "Untrusted input reaches a shell or code evaluator, letting an attacker run "
        "arbitrary commands or code on the server — full remote code execution.",
        "Never pass user input to a shell or eval/exec. Use argument arrays "
        "(subprocess([...]) / execFile / spawn) and strict allow-lists for external calls.",
    ),
    "deser": (
        "Deserializing untrusted data can build arbitrary objects and execute code as it "
        "loads — a classic path to full remote code execution.",
        "Don't deserialize untrusted input with unsafe loaders. Use safe formats (JSON) "
        "or safe APIs (yaml.safe_load, signed / allow-listed deserialization).",
    ),
    "ssti": (
        "User input rendered as a template is evaluated on the server, which usually "
        "escalates to remote code execution and full server compromise.",
        "Render a fixed template and pass user data only as context variables — never "
        "build the template string itself from user input.",
    ),
    "auth": (
        "Broken authentication or token validation lets an attacker forge identities or "
        "tokens and reach other users' data or admin functions.",
        "Verify signatures against a fixed allow-list of algorithms (never 'none'), check "
        "exp/aud/iss claims, and keep signing keys secret and rotated.",
    ),
    "crypto": (
        "Weak or broken cryptography (MD5/SHA-1, predictable randomness) can be cracked "
        "or forged, exposing passwords, tokens, or integrity guarantees.",
        "Use modern algorithms: SHA-256/SHA-3, bcrypt or argon2 for passwords, and the "
        "secrets module / a CSPRNG for tokens and IDs.",
    ),
    "config": (
        "Insecure configuration — debug mode, disabled TLS verification, wildcard CORS — "
        "exposes internals or enables man-in-the-middle interception and data theft.",
        "Disable debug in production, always verify TLS certificates, restrict CORS to "
        "known origins, and keep environment-specific config out of the code.",
    ),
    "docker": (
        "Risky container settings (running as root, secrets baked into the image, mutable "
        "base tags) widen the blast radius if the container is compromised.",
        "Run as a non-root USER, pass secrets at runtime, pin base images by digest, and "
        "install only what you need.",
    ),
    "iac": (
        "Insecure infrastructure-as-code provisions real exposed resources — open "
        "security groups, public buckets, unencrypted or privileged workloads.",
        "Restrict CIDR ranges, make storage private and encrypted, drop privileged/host "
        "modes, and keep secrets in a secrets manager.",
    ),
    "ci": (
        "Insecure CI workflows can leak repository secrets or let a malicious pull "
        "request run code with your tokens — a supply-chain compromise.",
        "Avoid pull_request_target with untrusted code, pin actions to a commit SHA, use "
        "least-privilege permissions, and never echo secrets.",
    ),
    "hygiene": (
        "Sensitive files that aren't git-ignored are easily committed and pushed, leaking "
        "credentials into history where they are hard to fully remove.",
        "Add the patterns to .gitignore; if anything was already committed, rotate it and "
        "purge it from the git history.",
    ),
    # --- Dependencies / licenses ----------------------------------------
    "dep": (
        "This dependency has a known, published vulnerability (CVE/advisory) that an "
        "attacker can look up and exploit against your application.",
        "Upgrade to the fixed version (see the per-finding command). If none exists yet, "
        "assess exploitability or replace the package.",
    ),
    "license": (
        "Copyleft or unknown licenses can impose legal obligations (e.g. releasing your "
        "source) or create compliance risk for a proprietary product.",
        "Check whether the license fits your distribution model; replace the dependency "
        "or get legal sign-off where required.",
    ),
    # --- Secrets ---------------------------------------------------------
    "private_key": (
        "A leaked private key lets an attacker impersonate your server or identity, "
        "decrypt intercepted traffic, or sign artifacts as you.",
        "Treat it as compromised: revoke and reissue the key, then remove it from the "
        "repository and its history.",
    ),
    "cloud": (
        "Leaked cloud credentials can hand an attacker control of your infrastructure — "
        "running up large bills, reading data, or pivoting deeper.",
        "Revoke and rotate the key now, scope new keys to least privilege, and store them "
        "in a secrets manager or environment variables.",
    ),
    "vcs": (
        "A leaked source-control token can read or push code, alter CI, and reach other "
        "repos and secrets across your org — a supply-chain risk.",
        "Revoke and rotate the token, and switch to short-lived, least-privilege tokens.",
    ),
    "payment": (
        "Leaked payment-provider keys can move money, issue refunds, or read customer and "
        "transaction data.",
        "Roll the key in the provider dashboard immediately and restrict it to the needed "
        "operations and IPs.",
    ),
    "communication": (
        "Leaked messaging/email keys let attackers send messages or email as you "
        "(phishing and spam) and read communications.",
        "Revoke and rotate the key, and restrict its scopes and allowed senders.",
    ),
    "database": (
        "A database connection string exposes the credentials needed to read or modify "
        "all the data it can reach.",
        "Rotate the credentials, restrict network access, and load the connection string "
        "from the environment.",
    ),
    "token": (
        "A leaked token or JWT can be replayed to access whatever it authorizes until it "
        "expires or is revoked.",
        "Revoke and rotate it, shorten its lifetime, and keep it out of source and logs.",
    ),
    "credential": (
        "A hardcoded password or secret grants direct access to whatever it protects.",
        "Remove it from the code, rotate it, and load it from a secrets manager or "
        "environment variable.",
    ),
    "ai": (
        "A leaked AI/LLM provider key can be used to run up large API bills and to access "
        "your account's usage and data.",
        "Revoke and rotate the key, set spend limits, and store it as an environment "
        "secret.",
    ),
    "package": (
        "A leaked package-registry token can publish or yank packages under your name — a "
        "direct supply-chain attack on everyone who installs them.",
        "Revoke the token, enable 2FA / publish protections, and use short-lived CI tokens.",
    ),
    "saas": (
        "A leaked SaaS API token can read or modify data in that service and may expose "
        "any linked systems.",
        "Revoke and rotate the token and scope it to least privilege.",
    ),
}

_GENERIC = (
    "This finding is a security weakness an attacker could potentially abuse to reach "
    "data or systems they shouldn't.",
    "Review the affected code or configuration, remove or restrict the risky pattern, "
    "and rotate anything that may have been exposed.",
)


def explain(category: str) -> tuple[str, str]:
    """Return (impact, how_to_fix) for a finding category, with a generic fallback."""
    return EXPLANATIONS.get((category or "").lower(), _GENERIC)
