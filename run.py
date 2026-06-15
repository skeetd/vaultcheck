#!/usr/bin/env python3
"""
vaultcheck — CLI entry point

Usage:
  python run.py scan <target> [--output report.html] [--phase secrets|deps|code]
  python run.py dashboard
"""
import sys
import os
import click
from pathlib import Path
from typing import Optional
from dotenv import load_dotenv

load_dotenv(Path(__file__).resolve().parent / ".env")


@click.group()
def cli():
    pass


@cli.command()
@click.argument("target")
@click.option("--output", "-o", default="report.html", show_default=True, help="Output HTML report path.")
@click.option(
    "--phase", "-p",
    multiple=True,
    type=click.Choice(["secrets", "deps", "code", "git_history", "licenses"], case_sensitive=False),
    help="Run only specific phases. Repeat to include multiple. Default: secrets, deps, code.",
)
@click.option("--history", "history", is_flag=True, default=False,
              help="Shortcut for --phase git_history (scan full git history for removed secrets; full clone).")
@click.option("--json", "as_json", is_flag=True, default=False, help="Print findings as JSON to stdout.")
@click.option(
    "--fail-on",
    type=click.Choice(["critical", "high", "medium", "low", "any", "never"], case_sensitive=False),
    default="high", show_default=True,
    help="Exit non-zero if a finding at or above this severity is found (for CI gating).",
)
@click.option("--sbom", type=click.Choice(["cyclonedx", "spdx"], case_sensitive=False), default=None,
              help="Also write an SBOM in the given format next to the report.")
@click.option("--pdf", "as_pdf", is_flag=True, default=False,
              help="Also write a PDF report next to the HTML report.")
@click.option("--no-default-ignores", is_flag=True, default=False,
              help="Disable built-in ignores (test fixtures, examples, vendored deps).")
@click.option("--severity", "severities", multiple=True,
              type=click.Choice(["critical", "high", "medium", "low"], case_sensitive=False),
              help="Only report findings at these severity level(s). Repeatable. Default: all.")
@click.option("--explain", "as_explain", is_flag=True, default=False,
              help="Add per-finding remediation from your local vuln-explainer model (Ollama, offline).")
def scan(target: str, output: str, phase: tuple[str, ...], history: bool, as_json: bool,
         fail_on: str, sbom: Optional[str], as_pdf: bool, no_default_ignores: bool,
         severities: tuple[str, ...], as_explain: bool):
    """Scan a local path or GitHub repo URL for security issues."""
    from vaultcheck.scanner import run_scan, ALL_PHASES
    from vaultcheck.reporter import generate_report

    phases = list(phase) if phase else list(ALL_PHASES)
    if history and "git_history" not in phases:
        phases.append("git_history")
    token = os.environ.get("GITHUB_TOKEN")

    click.echo(f"[*] Target  : {target}")
    click.echo(f"[*] Phases  : {', '.join(phases)}")
    if severities:
        click.echo(f"[*] Severity: only {', '.join(s.upper() for s in severities)}")
    if token:
        click.echo("[*] Auth    : GitHub token found")

    result = run_scan(target, phases=tuple(phases), github_token=token,
                      use_default_ignores=not no_default_ignores)
    if severities:
        result = result.only_severities(severities)

    if result.errors:
        for err in result.errors:
            click.echo(f"[!] {err}", err=True)

    if as_json:
        import json, dataclasses
        data = {
            "target": result.target,
            "secrets": [dataclasses.asdict(f) for f in result.secrets],
            "deps":    [dataclasses.asdict(f) for f in result.deps],
            "code":    [dataclasses.asdict(f) for f in result.code],
            "git_history": [dataclasses.asdict(f) for f in result.git_history],
            "licenses":    [dataclasses.asdict(f) for f in result.licenses],
            "severity_counts": result.severity_counts,
            "errors":  result.errors,
        }
        click.echo(json.dumps(data, indent=2))
        _gate_exit(result, fail_on)
        return

    ai_section = None
    if as_explain:
        from vaultcheck.llm_explain import explain_html
        ai_section = explain_html(result.all_findings + result.licenses)
        if ai_section:
            click.echo("[*] LLM     : added local-model remediation to the report.")
        else:
            click.echo("[!] LLM     : local vuln-explainer model not reachable — "
                       "skipped AI remediation (static guidance still included).", err=True)

    out_path = Path(output)
    generate_report(result, output_path=out_path, severity_filter=list(severities) or None,
                    ai_section=ai_section)

    if as_pdf:
        from vaultcheck.pdf_report import generate_pdf_report
        pdf_path = out_path.with_suffix(".pdf")
        generate_pdf_report(result, pdf_path)
        click.echo(f"[+] PDF     : {pdf_path.resolve()}")

    if sbom:
        from vaultcheck.sbom import generate_sbom
        import json as _json
        scan_path = target if not target.startswith(("http://", "https://")) else None
        # For remote repos the temp clone is already gone; SBOM uses local path only.
        if scan_path and Path(scan_path).exists():
            sbom_doc = generate_sbom(Path(scan_path), sbom)
            ext = "cdx.json" if sbom.lower() == "cyclonedx" else "spdx.json"
            sbom_path = out_path.with_suffix("").with_suffix(f".{ext}")
            sbom_path.write_text(_json.dumps(sbom_doc, indent=2), encoding="utf-8")
            click.echo(f"[+] SBOM    : {sbom_path.resolve()}")
        else:
            click.echo("[!] SBOM    : skipped (only supported for local paths)", err=True)

    counts = result.severity_counts
    click.echo()
    click.echo(f"  CRITICAL : {counts['CRITICAL']}")
    click.echo(f"  HIGH     : {counts['HIGH']}")
    click.echo(f"  MEDIUM   : {counts['MEDIUM']}")
    click.echo(f"  LOW      : {counts['LOW']}")
    click.echo(f"  TOTAL    : {result.total + len(result.licenses)}")
    if "git_history" in phases:
        click.echo(f"  (history : {len(result.git_history)} secret(s) found only in past commits)")
    click.echo()
    click.echo(f"[+] Report  : {out_path.resolve()}")

    _gate_exit(result, fail_on)


_SEVERITY_RANK = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}


def _gate_exit(result, fail_on: str) -> None:
    """Exit non-zero if any finding meets the configured severity threshold."""
    fail_on = fail_on.lower()
    if fail_on == "never":
        return
    counts = result.severity_counts
    if fail_on == "any":
        if sum(counts.values()) > 0:
            click.echo("[!] Gate    : findings present — failing.", err=True)
            sys.exit(1)
        return
    threshold = _SEVERITY_RANK[fail_on.upper()]
    triggered = {s: n for s, n in counts.items() if n > 0 and _SEVERITY_RANK[s] >= threshold}
    if triggered:
        summary = ", ".join(f"{n} {s}" for s, n in sorted(
            triggered.items(), key=lambda kv: -_SEVERITY_RANK[kv[0]]))
        click.echo(f"[!] Gate    : {summary} at/above {fail_on.upper()} — failing.", err=True)
        sys.exit(1)


@cli.command()
@click.argument("target")
@click.option("--format", "fmt", type=click.Choice(["cyclonedx", "spdx"], case_sensitive=False),
              default="cyclonedx", show_default=True, help="SBOM output format.")
@click.option("--output", "-o", default=None, help="Output path (defaults to sbom.<fmt>.json).")
@click.option("--name", "project_name", default=None, help="Project name for the SBOM metadata.")
def sbom(target: str, fmt: str, output: Optional[str], project_name: Optional[str]):
    """Generate a Software Bill of Materials (SBOM) for a local repo path."""
    import json as _json
    from vaultcheck.sbom import generate_sbom

    path = Path(target)
    if not path.exists():
        click.echo(f"[!] Path not found: {path}", err=True)
        sys.exit(1)

    doc = generate_sbom(path, fmt, project_name)
    n = len(doc.get("components", doc.get("packages", [])))
    if output:
        out_path = Path(output)
    else:
        ext = "cdx.json" if fmt.lower() == "cyclonedx" else "spdx.json"
        out_path = Path(f"sbom.{ext}")
    out_path.write_text(_json.dumps(doc, indent=2), encoding="utf-8")
    click.echo(f"[+] {fmt} SBOM written: {out_path.resolve()} ({n} components)")


@cli.command()
@click.argument("target")
@click.option("--no-notify", is_flag=True, default=False, help="Do not send notifications.")
@click.option("--slack", "slack_url", default=None, help="Slack webhook URL (overrides env).")
@click.option("--webhook", "webhook_url", default=None, help="Generic webhook URL (overrides env).")
@click.option(
    "--phase", "-p", multiple=True,
    type=click.Choice(["secrets", "deps", "code", "git_history", "licenses"], case_sensitive=False),
    help="Run only specific phases. Default: secrets, deps, code.",
)
def rescan(target: str, no_notify: bool, slack_url: Optional[str],
           webhook_url: Optional[str], phase: tuple[str, ...]):
    """Re-scan a repo, diff against the last scan, and notify on changes.

    Intended to be run on a schedule (cron / CI). Compares to the previous stored
    scan of the same target and reports what is NEW or FIXED.
    """
    from vaultcheck.schedule import run_scheduled_scan
    from vaultcheck.scanner import ALL_PHASES

    phases = phase if phase else ALL_PHASES
    token = os.environ.get("GITHUB_TOKEN")
    summary = run_scheduled_scan(target, phases=phases, github_token=token,
                                 notify=not no_notify, slack_url=slack_url,
                                 webhook_url=webhook_url)

    for err in summary["errors"]:
        click.echo(f"[!] {err}", err=True)

    d = summary["diff"]
    click.echo(f"[*] Target  : {target}")
    if not summary["baseline_existed"]:
        click.echo("[*] Baseline: none found — this scan is the new baseline.")
    click.echo(f"[*] Changes : {d['new']} new, {d['fixed']} fixed, {d['unchanged']} unchanged")
    for n in sorted(d["new_items"], key=lambda x: x.get("severity", "")):
        click.echo(f"    + {n.get('severity','?'):8} {n.get('label','')}")
    for fx in d["fixed_items"][:20]:
        click.echo(f"    - fixed   {fx.get('label','')}")
    if not no_notify and summary["notified"]:
        for r in summary["notified"]:
            status = "ok" if r["ok"] else f"FAILED ({r['detail']})"
            click.echo(f"[*] Notify  : {r['sink']} — {status}")


@cli.command(name="notify-test")
@click.option("--slack", "slack_url", default=None, help="Slack webhook URL (overrides env).")
@click.option("--webhook", "webhook_url", default=None, help="Generic webhook URL (overrides env).")
def notify_test(slack_url: Optional[str], webhook_url: Optional[str]):
    """Send a test notification to verify Slack/webhook configuration."""
    from vaultcheck.notify import notify_scan
    results = notify_scan("vaultcheck/test", {"CRITICAL": 1, "HIGH": 2, "MEDIUM": 0, "LOW": 3}, 6,
                          slack_url=slack_url, webhook_url=webhook_url,
                          title="VaultCheck test notification")
    if not results:
        click.echo("[!] No sinks configured. Set VAULTCHECK_SLACK_WEBHOOK or "
                   "VAULTCHECK_WEBHOOK_URL, or pass --slack/--webhook.", err=True)
        sys.exit(1)
    for r in results:
        status = "ok" if r["ok"] else f"FAILED ({r['detail']})"
        click.echo(f"[*] {r['sink']}: {status}")


@cli.command(name="llm-test")
def llm_test():
    """Check the local vuln-explainer model (Ollama) and explain one sample finding."""
    from vaultcheck.llm_explain import MODEL, OLLAMA_HOST, explain_finding, is_available
    click.echo(f"[*] Ollama  : {OLLAMA_HOST}   model: {MODEL}")
    if not is_available():
        click.echo("[!] Not reachable. Start Ollama and run "
                   "`ollama create vuln-explainer -f Modelfile` in the vuln-explainer repo.", err=True)
        sys.exit(1)
    sample = {
        "issue_type": "SQL Injection — string concat", "category": "sqli", "severity": "HIGH",
        "file": "app.py", "line_number": 42,
        "line_content": "cursor.execute('SELECT * FROM users WHERE id=' + user_id)",  # nosec code
        "description": "SQL query built with string concatenation.",
    }
    click.echo("[*] Sending a sample finding to the model…\n")
    text = explain_finding(sample, use_cache=False)
    if not text:
        click.echo("[!] Model reachable but returned nothing.", err=True)
        sys.exit(1)
    click.echo(text)


@cli.command()
@click.option("--host", default="127.0.0.1", show_default=True)
@click.option("--port", default=5050, show_default=True)
def dashboard(host: str, port: int):
    """Start the admin dashboard."""
    from dashboard.app import create_app
    app = create_app()
    click.echo(f"[*] Dashboard : http://{host}:{port}")
    app.run(host=host, port=port, debug=False)


_SEV_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}


def _print_check(res):
    click.echo(f"[*] {res.check_type} : {res.target}")
    if getattr(res, "summary", ""):
        click.echo(f"    {res.summary}")
    for err in res.errors:
        click.echo(f"[!] {err}", err=True)
    if not res.findings:
        if not res.errors:
            click.echo("[+] No issues found.")
        return
    for f in sorted(res.findings, key=lambda x: _SEV_ORDER.get(x.severity, 9)):
        click.echo(f"  [{f.severity}] {f.title}")
        if f.detail:
            click.echo(f"        {f.detail}")
    if any(f.severity == "CRITICAL" for f in res.findings):
        sys.exit(2)
    if any(f.severity == "HIGH" for f in res.findings):
        sys.exit(1)


@cli.group()
def check():
    """Run non-repo checks (website, email breach)."""


@check.command("website")
@click.argument("url")
def check_website_cmd(url: str):
    """Passive security check of a website (headers, TLS, cookies)."""
    from vaultcheck.checks import check_website
    _print_check(check_website(url))


@check.command("breach")
@click.argument("email")
def check_breach_cmd(email: str):
    """Check if an email appears in known public breaches (needs HIBP_API_KEY)."""
    from vaultcheck.checks import check_email_breach
    _print_check(check_email_breach(email))


@check.command("list")
def check_list_cmd():
    """List every registered check."""
    from vaultcheck.registry import list_checks
    click.echo(f"{'ID':17} {'CATEGORY':10} {'TYPE':9} {'TIER':6} DESCRIPTION")
    for c in list_checks():
        auth = "  [authorized targets only]" if c.requires_auth else ""
        click.echo(f"{c.id:17} {c.category:10} {c.target_type:9} {c.tier:6} {c.description}{auth}")


@check.command("run")
@click.argument("check_id")
@click.argument("target")
def check_run_cmd(check_id: str, target: str):
    """Run any registered check by id, e.g. 'check run dns example.com'."""
    from vaultcheck.registry import get_check
    chk = get_check(check_id)
    if chk is None:
        click.echo(f"[!] Unknown check '{check_id}'. Run 'check list'.", err=True)
        sys.exit(1)
    _print_check(chk.run(target))


@cli.command()
@click.argument("repo_url")
@click.option("--apply", "do_apply", is_flag=True, default=False,
              help="Actually open the PR. Without this flag it is a dry run.")
def fix(repo_url: str, do_apply: bool):
    """Open a PR bumping vulnerable deps in a GitHub repo (needs GITHUB_TOKEN with write access)."""
    from vaultcheck.scanner import run_scan
    from vaultcheck.autofix import parse_repo, plan_bumps, create_fix_pr

    token = os.environ.get("GITHUB_TOKEN")
    if not token:
        click.echo("[!] GITHUB_TOKEN with write access is required.", err=True)
        sys.exit(1)
    parsed = parse_repo(repo_url)
    if not parsed:
        click.echo("[!] Provide a GitHub repo URL: https://github.com/owner/repo", err=True)
        sys.exit(1)
    owner, repo = parsed

    click.echo(f"[*] Scanning {owner}/{repo} for vulnerable dependencies...")
    result = run_scan(repo_url, phases=("deps",), github_token=token)
    bumps = plan_bumps(result.deps)
    if not bumps:
        click.echo("[+] No auto-fixable vulnerable dependencies (requirements.txt / package.json).")
        return

    click.echo(f"[*] Planned fixes ({len(bumps)}):")
    for b in bumps:
        click.echo(f"      {b.file}: {b.package} {b.old_version} -> {b.new_version}  ({b.advisory}, {b.severity})")

    out = create_fix_pr(owner, repo, bumps, token, dry_run=not do_apply)
    if out.get("dry_run"):
        click.echo(f"\n[*] DRY RUN — would update {len(out['files'])} file(s) on branch '{out['branch']}'.")
        click.echo("[*] Re-run with --apply to open the pull request.")
    elif out.get("pr_url"):
        click.echo(f"\n[+] Pull request opened: {out['pr_url']}")
    else:
        click.echo(f"\n[!] {out.get('note', 'No changes were made.')}")


if __name__ == "__main__":
    cli()
