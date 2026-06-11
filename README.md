# VaultCheck

A developer-focused security scanner, packaged as a small freemium product.
Scan GitHub repositories for hardcoded secrets, vulnerable dependencies and
insecure code, run a library of network/domain checks, responsibly disclose
exposures in public repos, and open auto-fix pull requests — all from a clean
Flask dashboard or the CLI.

## Features

**Repository scan** (`/scan`, `run.py scan`)
- **Secrets** — 24+ patterns (AWS, GitHub, Stripe, Slack, DB strings, private keys, JWTs, passwords…), masked at detection
- **Vulnerable dependencies** — OSV lookup with real CVSS v3 scoring across 7 ecosystems (`requirements.txt`, `package.json`, `go.mod`, `Gemfile.lock`, `composer.lock`, `Cargo.lock`, `poetry.lock`), with a per-finding upgrade command
- **Insecure code** — SQLi, XSS, command injection, weak crypto, risky config
- Clean, light, self-contained HTML report

**Security checks** (`/check`, `run.py check run <id> <target>`) — 15 in a unified registry:
`repo`, `website`, `dns`, `security-txt`, `typosquat`, `breach`, `pwned-password`,
`subdomains` (crt.sh), `tls` (deprecated protocols + cert), `cors`, `exposed-files`,
`rdap` (domain age/registrar), `caa`, `package` (`name@version` → OSV), `cve` (NVD search).

**Responsible disclosure** (`/disclosure`, admin) — scans newly-created public repos
until N findings, in the background; you review each **masked** finding, then send a
**private** notice to the owner. Secrets are never stored, shown, or used.

**Auto-fix PR** (`run.py fix <repo>`) — opens a GitHub PR bumping vulnerable
dependencies on a new branch. Dry-run by default; `--apply` to open the PR.

**Admin dashboard** (`/`) — manage users + access tokens, plans (free/pro),
billing & plan expiry (auto-downgrade), per-user scan history, usage overview.

## Quick start

```bash
git clone https://github.com/skeetd/vaultcheck.git
cd vaultcheck
pip install -r requirements.txt

# create your .env (see Configuration below)
cp .env.example .env
python -c "import secrets; print(secrets.token_hex(32))"   # put in FLASK_SECRET_KEY

python run.py dashboard      # http://127.0.0.1:5050
```

On Windows PowerShell, use `Copy-Item .env.example .env`.

### CLI

```bash
python run.py scan https://github.com/owner/repo      # full repo scan -> report.html
python run.py scan ./local/path --phase secrets       # limit phases
python run.py check list                              # list all checks
python run.py check run package flask@0.12.2
python run.py check run tls example.com
python run.py fix https://github.com/you/repo         # dry-run; add --apply for a real PR
```

Exit codes: `2` on CRITICAL, `1` on HIGH — handy as a CI gate.

## Configuration (`.env`)

| Variable | Required | Purpose |
|---|---|---|
| `ADMIN_PASSWORD` | yes | Admin dashboard login |
| `FLASK_SECRET_KEY` | yes | Flask session signing |
| `GITHUB_TOKEN` | no | Higher GitHub rate limits + private repos (disclosure/fix need write scope) |
| `HIBP_API_KEY` | no | Enables the email-breach check |

`.env`, `users.json`, `disclosure_cases.json` and `scans.json` are git-ignored —
they hold secrets and local data and never leave your machine.

## Dashboard usage

1. Open `http://127.0.0.1:5050`, log in with `ADMIN_PASSWORD`.
2. **Create a user** → they get an **access token** (shown in the table / user page).
3. Hand the token to the user; they scan via `/scan` and `/check`, and see only
   their own history at `/history`.
4. Toggle **free/pro** or open a user to set **Pro until \<date\>** (auto-downgrades on expiry).

Free plan is limited to **20 scans/month**; pro is unlimited.

## Project structure

```
vaultcheck/
  secrets_scanner.py    deps_scanner.py    code_scanner.py
  scanner.py            reporter.py
  checks.py             registry.py        # 15-check registry (the extensibility backbone)
  disclosure.py         autofix.py
dashboard/
  app.py                models.py          scan_store.py   disclosure_store.py   auth.py
  templates/            # base.html (shared layout) + admin, scan, check, history, disclosure, user_detail, login
run.py                  # CLI entry point
examples/vulnerable-demo/   tests/
```

Adding a new check = one function in `checks.py` + one line in `registry.py`; it
shows up automatically in the CLI and the `/check` dropdown.

## Notes & roadmap

- **UI** is intentionally light and professional. Pages share `base.html`.
- **Responsible disclosure** is notify-only: detect → mask → privately notify the
  owner. Never log in with a found credential; never open a public issue.
- **Not yet built:** Stripe billing, scheduled/recurring scans, self-serve signup,
  git-history secret scanning, OSV batch queries, the live auto-fix PR path
  (the manifest-rewrite logic is unit-tested; opening a real PR needs a write token).

## Disclaimer

Run scans only against assets you own or are authorized to test. Findings are
indicative — verify before acting.
