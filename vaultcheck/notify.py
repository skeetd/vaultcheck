"""Outbound notifications for scan results / diffs.

Supports two sink types, both over plain stdlib HTTP:
  - Slack incoming webhooks (https://hooks.slack.com/services/...)
  - Generic JSON webhooks (any URL; receives the raw payload)

Sinks are configured via environment variables so no secrets live in code:
  VAULTCHECK_SLACK_WEBHOOK   - Slack incoming webhook URL
  VAULTCHECK_WEBHOOK_URL     - generic JSON webhook URL

notify_scan() sends a summary; notify_diff() sends only when something changed,
which is what the scheduler uses to avoid noise.
"""
import json
import os
import urllib.request
from typing import Optional

_SEV_EMOJI = {"CRITICAL": ":red_circle:", "HIGH": ":large_orange_circle:",
              "MEDIUM": ":large_yellow_circle:", "LOW": ":large_blue_circle:"}


def _post_json(url: str, payload: dict, timeout: int = 10) -> tuple[bool, str]:
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(url, data=data,
                                 headers={"Content-Type": "application/json"}, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return (200 <= resp.status < 300, f"HTTP {resp.status}")
    except Exception as exc:  # noqa: BLE001
        return (False, str(exc))


def _slack_summary_blocks(target: str, counts: dict, total: int,
                          title: str = "VaultCheck scan complete") -> dict:
    line = "  ".join(f"{_SEV_EMOJI.get(s,'')} {s.title()}: *{counts.get(s,0)}*"
                     for s in ("CRITICAL", "HIGH", "MEDIUM", "LOW"))
    return {
        "text": f"{title}: {target} — {total} findings",
        "blocks": [
            {"type": "header", "text": {"type": "plain_text", "text": title}},
            {"type": "section", "text": {"type": "mrkdwn",
                "text": f"*Target:* `{target}`\n*Total findings:* *{total}*"}},
            {"type": "section", "text": {"type": "mrkdwn", "text": line}},
        ],
    }


def _slack_diff_blocks(target: str, diff: dict) -> dict:
    new, fixed = diff.get("new", []), diff.get("fixed", [])
    lines = [f"*Target:* `{target}`",
             f":warning: *{len(new)} new*   :white_check_mark: *{len(fixed)} fixed*   "
             f"({len(diff.get('unchanged', []))} unchanged)"]
    for n in sorted(new, key=lambda x: x.get("severity", "")):
        lines.append(f"  • _new_ {_SEV_EMOJI.get(n.get('severity',''),'')} "
                     f"*{n.get('severity','?')}* — {n.get('label','')}")
    for fx in fixed[:10]:
        lines.append(f"  • _fixed_ :white_check_mark: {fx.get('label','')}")
    return {
        "text": f"VaultCheck: {len(new)} new / {len(fixed)} fixed on {target}",
        "blocks": [
            {"type": "header", "text": {"type": "plain_text", "text": "VaultCheck change report"}},
            {"type": "section", "text": {"type": "mrkdwn", "text": "\n".join(lines)[:2900]}},
        ],
    }


def _sinks(slack_url: Optional[str], webhook_url: Optional[str]) -> list[tuple[str, str]]:
    sinks = []
    slack = slack_url or os.environ.get("VAULTCHECK_SLACK_WEBHOOK")
    generic = webhook_url or os.environ.get("VAULTCHECK_WEBHOOK_URL")
    if slack:
        sinks.append(("slack", slack))
    if generic:
        sinks.append(("webhook", generic))
    return sinks


def notify_scan(target: str, counts: dict, total: int,
                slack_url: Optional[str] = None, webhook_url: Optional[str] = None,
                title: str = "VaultCheck scan complete") -> list[dict]:
    """Send a scan summary to all configured sinks. Returns per-sink results."""
    results = []
    for kind, url in _sinks(slack_url, webhook_url):
        if kind == "slack":
            ok, msg = _post_json(url, _slack_summary_blocks(target, counts, total, title))
        else:
            ok, msg = _post_json(url, {"event": "scan_complete", "target": target,
                                       "counts": counts, "total": total})
        results.append({"sink": kind, "ok": ok, "detail": msg})
    return results


def notify_diff(target: str, diff: dict,
                slack_url: Optional[str] = None, webhook_url: Optional[str] = None,
                only_if_changed: bool = True) -> list[dict]:
    """Send a change report. By default sends only when there are new/fixed findings."""
    changed = bool(diff.get("new") or diff.get("fixed"))
    if only_if_changed and not changed:
        return [{"sink": "-", "ok": True, "detail": "no change — not sent"}]
    results = []
    for kind, url in _sinks(slack_url, webhook_url):
        if kind == "slack":
            ok, msg = _post_json(url, _slack_diff_blocks(target, diff))
        else:
            ok, msg = _post_json(url, {"event": "scan_diff", "target": target,
                                       "new": diff.get("new", []),
                                       "fixed": diff.get("fixed", []),
                                       "unchanged_count": len(diff.get("unchanged", []))})
        results.append({"sink": kind, "ok": ok, "detail": msg})
    return results
