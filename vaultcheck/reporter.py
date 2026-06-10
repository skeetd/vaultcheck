import html
from datetime import datetime
from pathlib import Path
from typing import Optional

from . import __version__
from .scanner import ALL_PHASES, ScanResult

_SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]


def _esc(s) -> str:
    return html.escape(str(s))


def _sev_badge(severity: str) -> str:
    return f'<span class="sev sev-{severity.lower()}">{_esc(severity)}</span>'


def _table(findings: list, columns: list[tuple]) -> str:
    """columns: list of (header, accessor_fn, kind) where kind in {sev, mono, text}."""
    if not findings:
        return '<p class="empty">No findings in this category.</p>'
    head = "".join(f"<th>{_esc(h)}</th>" for h, _, _ in columns)
    rows = []
    for f in sorted(findings, key=lambda x: _SEVERITY_ORDER.index(x.severity)):
        cells = []
        for _, fn, kind in columns:
            val = fn(f)
            if kind == "sev":
                cells.append(f"<td>{_sev_badge(val)}</td>")
            elif kind == "mono":
                cells.append(f'<td class="mono">{_esc(val)}</td>')
            else:
                cells.append(f"<td>{_esc(val)}</td>")
        rows.append("<tr>" + "".join(cells) + "</tr>")
    return (
        '<div class="table-wrap"><table>'
        f"<thead><tr>{head}</tr></thead>"
        f'<tbody>{"".join(rows)}</tbody>'
        "</table></div>"
    )


def generate_report(result: ScanResult, output_path: Optional[Path] = None,
                    upgrade_hint: Optional[str] = None) -> str:
    ts = datetime.now().strftime("%Y-%m-%d %H:%M")
    counts = result.severity_counts
    total = result.total

    # Severity stat cards
    cards = ""
    for sev in _SEVERITY_ORDER:
        cards += (
            f'<div class="stat stat-{sev.lower()}">'
            f'<div class="stat-num">{counts[sev]}</div>'
            f'<div class="stat-label">{sev.title()}</div>'
            f"</div>"
        )

    # Proportion bar
    denom = total or 1
    segs = ""
    for sev in _SEVERITY_ORDER:
        pct = counts[sev] / denom * 100
        if pct > 0:
            segs += (
                f'<div class="seg seg-{sev.lower()}" style="width:{pct:.1f}%" '
                f'title="{sev}: {counts[sev]}"></div>'
            )
    sevbar = f'<div class="sevbar">{segs}</div>' if total else ""

    ran = set(result.phases) if result.phases else set(ALL_PHASES)

    def _skipped() -> str:
        extra = f" {_esc(upgrade_hint)}" if upgrade_hint else ""
        return f'<div class="table-wrap"><p class="skipped">Not included in this scan.{extra}</p></div>'

    def _count(label: str, n: int, phase: str) -> str:
        return f"{n} {label}" if phase in ran else f"{label}: not scanned"

    breakdown = (
        f"{_count('secrets', len(result.secrets), 'secrets')} &nbsp;·&nbsp; "
        f"{_count('dependencies', len(result.deps), 'deps')} &nbsp;·&nbsp; "
        f"{_count('code issues', len(result.code), 'code')}"
    )

    secrets_html = _table(result.secrets, [
        ("Severity", lambda f: f.severity, "sev"),
        ("Type",     lambda f: f.secret_type, "text"),
        ("File",     lambda f: f.file, "mono"),
        ("Line",     lambda f: str(f.line_number), "mono"),
        ("Value",    lambda f: f.matched_value, "mono"),
    ]) if "secrets" in ran else _skipped()
    deps_html = _table(result.deps, [
        ("Severity", lambda f: f.severity, "sev"),
        ("Package",  lambda f: f"{f.package}@{f.version}", "mono"),
        ("Advisory", lambda f: f.vuln_id, "mono"),
        ("Summary",  lambda f: f.summary, "text"),
        ("Remediation", lambda f: f.remediation, "mono"),
    ]) if "deps" in ran else _skipped()
    code_html = _table(result.code, [
        ("Severity", lambda f: f.severity, "sev"),
        ("Issue",    lambda f: f.issue_type, "text"),
        ("File",     lambda f: f.file, "mono"),
        ("Line",     lambda f: str(f.line_number), "mono"),
        ("Detail",   lambda f: f.description, "text"),
    ]) if "code" in ran else _skipped()

    errors_html = ""
    if result.errors:
        items = "".join(f"<li>{_esc(e)}</li>" for e in result.errors)
        errors_html = f'<div class="errors"><strong>Scan warnings</strong><ul>{items}</ul></div>'

    doc = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>VaultCheck Report — {_esc(result.target)}</title>
<style>
  :root {{
    --bg:        #eef1f4;
    --card:      #ffffff;
    --border:    #dce1e7;
    --text:      #1f2933;
    --text-soft: #67727e;
    --crit:      #b3261e;
    --crit-bg:   #fdeae8;
    --high:      #b35309;
    --high-bg:   #fcefe0;
    --med:       #846a00;
    --med-bg:    #fbf4d6;
    --low:       #5a6772;
    --low-bg:    #eceff2;
    --sans: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
    --mono: "SF Mono", "Cascadia Code", "JetBrains Mono", Consolas, "Liberation Mono", monospace;
  }}
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{
    background: var(--bg);
    color: var(--text);
    font-family: var(--sans);
    font-size: 14px;
    line-height: 1.55;
    -webkit-font-smoothing: antialiased;
  }}
  .wrap {{ max-width: 1080px; margin: 0 auto; padding: 32px 20px 64px; }}

  /* Header */
  header {{ margin-bottom: 28px; }}
  .title {{ font-size: 22px; font-weight: 700; letter-spacing: -0.3px; }}
  .title .vc {{ color: var(--text); }}
  .subtitle {{ color: var(--text-soft); font-size: 13px; margin-top: 4px; }}
  .subtitle code {{ font-family: var(--mono); color: var(--text); }}

  /* Summary card */
  .summary {{
    background: var(--card);
    border: 1px solid var(--border);
    border-radius: 10px;
    padding: 22px 24px;
    margin-bottom: 32px;
    box-shadow: 0 1px 2px rgba(16,24,40,0.04);
  }}
  .summary-top {{ display: flex; align-items: baseline; justify-content: space-between; flex-wrap: wrap; gap: 8px; }}
  .total {{ font-size: 15px; }}
  .total b {{ font-size: 28px; }}
  .breakdown {{ color: var(--text-soft); font-size: 13px; }}
  .sevbar {{ display: flex; height: 8px; border-radius: 4px; overflow: hidden; margin: 16px 0 20px; background: var(--low-bg); }}
  .seg-critical {{ background: var(--crit); }}
  .seg-high     {{ background: var(--high); }}
  .seg-medium   {{ background: var(--med); }}
  .seg-low      {{ background: var(--low); }}

  .stats {{ display: grid; grid-template-columns: repeat(4, 1fr); gap: 12px; }}
  @media (max-width: 560px) {{ .stats {{ grid-template-columns: repeat(2, 1fr); }} }}
  .stat {{ border: 1px solid var(--border); border-top-width: 3px; border-radius: 8px; padding: 12px 14px; }}
  .stat-num {{ font-size: 26px; font-weight: 700; line-height: 1; }}
  .stat-label {{ font-size: 12px; color: var(--text-soft); margin-top: 4px; text-transform: uppercase; letter-spacing: 0.4px; }}
  .stat-critical {{ border-top-color: var(--crit); }} .stat-critical .stat-num {{ color: var(--crit); }}
  .stat-high     {{ border-top-color: var(--high); }} .stat-high .stat-num     {{ color: var(--high); }}
  .stat-medium   {{ border-top-color: var(--med); }}  .stat-medium .stat-num   {{ color: var(--med); }}
  .stat-low      {{ border-top-color: var(--low); }}  .stat-low .stat-num      {{ color: var(--low); }}

  /* Sections */
  section {{ margin-bottom: 36px; }}
  h2 {{ font-size: 15px; font-weight: 600; margin-bottom: 4px; }}
  .section-sub {{ color: var(--text-soft); font-size: 12.5px; margin-bottom: 12px; }}

  /* Tables */
  .table-wrap {{
    background: var(--card);
    border: 1px solid var(--border);
    border-radius: 10px;
    overflow: hidden;
  }}
  table {{ width: 100%; border-collapse: collapse; }}
  thead th {{
    text-align: left;
    font-size: 11.5px;
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: 0.4px;
    color: var(--text-soft);
    background: #f7f8fa;
    padding: 10px 14px;
    border-bottom: 1px solid var(--border);
    white-space: nowrap;
  }}
  tbody td {{ padding: 11px 14px; border-bottom: 1px solid #eef0f3; vertical-align: top; }}
  tbody tr:last-child td {{ border-bottom: none; }}
  tbody tr:hover {{ background: #fafbfc; }}
  td.mono {{ font-family: var(--mono); font-size: 12.5px; overflow-wrap: anywhere; }}

  /* Severity badges */
  .sev {{
    display: inline-block;
    font-size: 11px;
    font-weight: 700;
    letter-spacing: 0.3px;
    padding: 2px 8px;
    border-radius: 4px;
    white-space: nowrap;
  }}
  .sev-critical {{ color: var(--crit); background: var(--crit-bg); }}
  .sev-high     {{ color: var(--high); background: var(--high-bg); }}
  .sev-medium   {{ color: var(--med);  background: var(--med-bg); }}
  .sev-low      {{ color: var(--low);  background: var(--low-bg); }}

  .empty {{ padding: 20px; color: var(--text-soft); font-style: italic; }}
  .skipped {{ padding: 18px 20px; color: var(--text-soft); background: #f7f8fa; font-size: 13px; }}

  .errors {{ background: var(--high-bg); border: 1px solid #f0d3b3; border-radius: 8px; padding: 12px 16px; margin-bottom: 24px; }}
  .errors ul {{ margin: 6px 0 0 18px; }}

  footer {{ margin-top: 40px; padding-top: 16px; border-top: 1px solid var(--border); color: var(--text-soft); font-size: 12px; }}
  footer a {{ color: var(--text-soft); }}
</style>
</head>
<body>
<div class="wrap">

  <header>
    <div class="title"><span class="vc">VaultCheck</span> Security Report</div>
    <div class="subtitle">
      Target <code>{_esc(result.target)}</code> &nbsp;·&nbsp; scanned {ts} &nbsp;·&nbsp; v{_esc(__version__)}
    </div>
  </header>

  {errors_html}

  <div class="summary">
    <div class="summary-top">
      <div class="total"><b>{total}</b> findings</div>
      <div class="breakdown">{breakdown}</div>
    </div>
    {sevbar}
    <div class="stats">{cards}</div>
  </div>

  <section>
    <h2>Secrets</h2>
    <div class="section-sub">Hardcoded credentials and keys detected in source files.</div>
    {secrets_html}
  </section>

  <section>
    <h2>Vulnerable dependencies</h2>
    <div class="section-sub">Declared packages with known advisories (source: OSV).</div>
    {deps_html}
  </section>

  <section>
    <h2>Insecure code</h2>
    <div class="section-sub">Risky patterns detected by static analysis.</div>
    {code_html}
  </section>

  <footer>
    Generated by VaultCheck v{_esc(__version__)} on {ts}. Findings are indicative — review before acting.
    Dependency data from <a href="https://osv.dev">osv.dev</a>.
  </footer>

</div>
</body>
</html>"""
    if output_path:
        output_path.write_text(doc, encoding="utf-8")
    return doc
