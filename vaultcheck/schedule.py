"""Scheduled / repeatable scans with change detection.

This module orchestrates a re-scan of a target, diffs it against the most recent
stored scan, persists the new result, and optionally notifies on changes. It does
NOT run its own timer loop — scheduling (cron, systemd timer, GitHub Actions cron,
APScheduler, etc.) is left to the deployment, which simply calls run_scheduled_scan().

This keeps the module testable and avoids a long-lived background process inside
the web app. The dashboard exposes a "scan now / re-scan" button that calls the
same function synchronously.
"""
import os
from pathlib import Path
from typing import Optional

from .diff import diff_fingerprints, fingerprint_result
from .scanner import ALL_PHASES, run_scan


def run_scheduled_scan(
    target: str,
    phases: tuple = ALL_PHASES,
    github_token: Optional[str] = None,
    user_id: str = "scheduler",
    notify: bool = True,
    slack_url: Optional[str] = None,
    webhook_url: Optional[str] = None,
    store=None,
) -> dict:
    """Run a scan, diff against the previous stored scan for this target, persist, notify.

    `store` is the scan_store module (injected so this stays importable without the
    dashboard package on the path). If None, it is imported lazily.

    Returns a summary dict: {target, counts, total, diff, notified}.
    """
    if store is None:
        from dashboard import scan_store as store  # lazy import

    github_token = github_token or os.environ.get("GITHUB_TOKEN")
    result = run_scan(target, phases=phases, github_token=github_token)

    current_fps = fingerprint_result(result)

    previous = store.latest_for_target(target, kind="repo")
    prev_fps = previous.get("fingerprints", []) if previous else []
    diff = diff_fingerprints(prev_fps, current_fps)

    counts = result.severity_counts
    total = result.total + len(result.licenses)
    store.add_scan(user_id, "repo", target, counts, total, fingerprints=current_fps)

    notified = []
    if notify and previous is not None:
        # Only notify on diffs once we have a baseline to compare against.
        from .notify import notify_diff
        notified = notify_diff(target, diff, slack_url=slack_url,
                               webhook_url=webhook_url, only_if_changed=True)

    return {
        "target": target,
        "counts": counts,
        "total": total,
        "errors": result.errors,
        "diff": {"new": len(diff["new"]), "fixed": len(diff["fixed"]),
                 "unchanged": len(diff["unchanged"]),
                 "new_items": diff["new"], "fixed_items": diff["fixed"]},
        "baseline_existed": previous is not None,
        "notified": notified,
    }
