# VaultCheck

A developer-focused security scanner, packaged as a small freemium product.
Scan GitHub repositories for hardcoded secrets, vulnerable dependencies and
insecure code, run a library of network/domain checks, responsibly disclose
exposures in public repos, and open auto-fix pull requests — all from a clean
Flask dashboard or the CLI.

## Features

**Repository scan** (`/scan`, `run.py scan`)
- **Secrets** — 55+ patterns (AWS, GitHub, GitLab, Stripe, Slack, Anthropic, OpenAI & other LLM providers, Discord/Telegram, npm/PyPI, cloud & SaaS tokens, DB strings, private keys, JWTs, passwords…), masked at detection
- **Vulnerable dependencies** — OSV lookup with real CVSS v3 scoring across 7 ecosystems (`requirements.txt`, `package.json`, `go.mod`, `Gemfile.lock`, `composer.lock`, `Cargo.lock`, `poetry.lock`), with a per-finding upgrade command
- **Insecure code** — SQLi, XSS, command injection, **RCE & unsafe deserialization** (pickle, `yaml.load`, `unserialize`, `readObject`, `Marshal.load`…), **disabled TLS verification** (across Python/Node/Go), **JWT `none` algorithm**, weak crypto, risky config, plus **Dockerfile**, **Terraform/docker-compose (IaC)**, **GitHub Actions workflow** checks and **.gitignore hygiene**
- **Git history** (opt-in `--phase git_history`) — scans past commits for secrets even after they were removed from HEAD
- **Dependency licenses** (opt-in `--phase licenses`) — flags copyleft (GPL/AGPL/LGPL/MPL) or unknown licenses via deps.dev
- Clean, light, self-contained HTML report — every finding comes with a plain-language **impact ("what can happen") and how-to-secure** explanation; add `--pdf` for a PDF, `--sbom cyclonedx|spdx` for an SBOM
- **Severity filter** — `--severity critical` (repeatable, e.g. `--severity high --severity medium`) reports only the levels you choose; also available as checkboxes on the dashboard `/scan` form
- **CI gating** — `--fail-on critical|high|medium|low|any|never` sets the exit code for pipelines

**Security checks** (`/check`, `run.py check run <id> <target>`) — 19 in a unified registry:
`repo`, `website`, `dns`, `security-txt`, `typosquat`, `breach`, `pwned-password`,
`subdomains` (crt.sh), `tls` (deprecated protocols + cert), `cors`, `https-redirect`
(HSTS/preload), `cookies` (Secure/HttpOnly/SameSite), `mixed-content`, `exposed-files`,
`open-redirect`, `rdap` (domain age/registrar), `caa`, `package` (`name@version` → OSV),
`cve` (NVD search).

**SBOM export** (`run.py sbom <path>`) — CycloneDX 1.5 or SPDX 2.3 JSON from the declared
dependencies (metadata-only, no network).

**Scheduled re-scan & change detection** (`run.py rescan <repo>`, `/rescan`) — re-scans a
repo, diffs against the last stored scan, and reports what is **new** or **fixed**. Pair
with cron / a CI cron job for continuous monitoring.

**Notifications** (`run.py notify-test`) — Slack incoming webhooks and generic JSON webhooks,
configured via `VAULTCHECK_SLACK_WEBHOOK` / `VAULTCHECK_WEBHOOK_URL`. `rescan` sends a change
report only when findings actually changed.

**Responsible disclosure** (`/disclosure`, admin) — monitors newly-created public repos
on **GitHub and GitLab**, scanning in the background until N findings. You review each
**masked** finding — every one deep-links to the exact line at the source and shows the
line with the secret masked, so you can rule out false positives without the raw secret
ever being stored — then send a **private** notice to the owner.

**Auto-fix PR** (`run.py fix <repo>`) — opens a GitHub PR bumping vulnerable
dependencies on a new branch. Dry-run by default; `--apply` to open the PR.

**Admin dashboard** (`/`) — log in once and scan from the session (no tokens to paste).
Manage users, plans (free/pro), billing & plan expiry (auto-downgrade), scan history and
a usage overview.

> **Network note:** the license check calls `api.deps.dev`. If you run VaultCheck behind an
> egress allowlist, add that domain (alongside `api.osv.dev`, `crt.sh`, `api.github.com`,
> the NVD and HIBP endpoints).


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

1. Open `http://127.0.0.1:5050` and log in with `ADMIN_PASSWORD`.
2. From the sidebar: **Scan** a repo, run a **Check**, browse **History**, or open
   **Public repos** to monitor GitHub/GitLab for leaked secrets and notify owners.
3. The **Dashboard** manages users and billing — toggle free/pro or open a user to set
   **Pro until \<date\>** (auto-downgrades when it lapses).

Everything runs from your admin session — no access tokens to hand around.

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
