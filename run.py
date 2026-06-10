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
    type=click.Choice(["secrets", "deps", "code"], case_sensitive=False),
    help="Run only specific phases. Repeat to include multiple. Default: all.",
)
@click.option("--json", "as_json", is_flag=True, default=False, help="Print findings as JSON to stdout.")
def scan(target: str, output: str, phase: tuple[str, ...], as_json: bool):
    """Scan a local path or GitHub repo URL for security issues."""
    from vaultcheck.scanner import run_scan, ALL_PHASES
    from vaultcheck.reporter import generate_report

    phases = phase if phase else ALL_PHASES
    token = os.environ.get("GITHUB_TOKEN")

    click.echo(f"[*] Target  : {target}")
    click.echo(f"[*] Phases  : {', '.join(phases)}")
    if token:
        click.echo("[*] Auth    : GitHub token found")

    result = run_scan(target, phases=phases, github_token=token)

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
            "errors":  result.errors,
        }
        click.echo(json.dumps(data, indent=2))
        return

    out_path = Path(output)
    generate_report(result, output_path=out_path)

    counts = result.severity_counts
    click.echo()
    click.echo(f"  CRITICAL : {counts['CRITICAL']}")
    click.echo(f"  HIGH     : {counts['HIGH']}")
    click.echo(f"  MEDIUM   : {counts['MEDIUM']}")
    click.echo(f"  LOW      : {counts['LOW']}")
    click.echo(f"  TOTAL    : {result.total}")
    click.echo()
    click.echo(f"[+] Report  : {out_path.resolve()}")

    if counts["CRITICAL"] > 0:
        sys.exit(2)
    if counts["HIGH"] > 0:
        sys.exit(1)


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
