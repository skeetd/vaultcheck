import os
import re
import threading
import time
from pathlib import Path
from typing import Optional
from urllib.parse import urlparse
from flask import (
    Blueprint, Flask, flash, redirect, render_template,
    request, session, url_for
)
from dotenv import load_dotenv
from .auth import (
    auth_required, current_owner, current_user, get_admin_password, is_admin, login_required,
)
from . import models
from . import billing
from . import disclosure_store
from . import scan_store
from . import schedule_store
from vaultcheck.checks import CheckResult
from vaultcheck.disclosure import SOURCES, build_notice, scan_repo
from vaultcheck.explanations import explain
from vaultcheck.registry import get_check, list_checks
from vaultcheck.reporter import generate_report
from vaultcheck.scanner import run_scan

load_dotenv(Path(__file__).resolve().parent.parent / ".env")

bp = Blueprint("main", __name__)


@bp.app_context_processor
def inject_identity():
    """Make the current identity available to every template (nav, account links)."""
    return {
        "is_admin": is_admin(),
        "current_user": current_user(),
    }

# Which scan phases each plan may run (free tier = limited functionality)
PLAN_PHASES = {
    "free": ("secrets", "code"),
    "pro":  ("secrets", "deps", "code"),
}
# Web form only scans public GitHub repos — never local paths (avoids scanning the server)
_GITHUB_URL_RE = re.compile(r"^https://github\.com/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+/?$")


def _safe_next(default_endpoint: str) -> str:
    """Only honour same-site relative redirect targets (avoid open redirects)."""
    nxt = request.args.get("next") or request.form.get("next") or ""
    if nxt.startswith("/") and not nxt.startswith("//"):
        return nxt
    return url_for(default_endpoint)


@bp.route("/signup", methods=["GET", "POST"])
def signup():
    if is_admin() or session.get("user_id"):
        return redirect(url_for("main.scan"))
    if request.method == "POST":
        user, error = models.create_account(
            request.form.get("username", ""),
            request.form.get("email", ""),
            request.form.get("password", ""),
        )
        if error:
            return render_template("signup.html", error=error,
                                   username=request.form.get("username", ""),
                                   email=request.form.get("email", "")), 400
        session["user_id"] = user["id"]
        flash(f"Welcome to VaultCheck, {user['username']}! You're on the Free plan.", "ok")
        return redirect(url_for("main.scan"))
    return render_template("signup.html")


@bp.route("/login", methods=["GET", "POST"])
def login():
    """Customer login (email + password)."""
    if request.method == "POST":
        user = models.authenticate(
            request.form.get("email", "").strip(),
            request.form.get("password", ""),
        )
        if user:
            session["user_id"] = user["id"]
            return redirect(_safe_next("main.scan"))
        return render_template("login.html", error="Invalid email or password.",
                               email=request.form.get("email", "")), 401
    return render_template("login.html")


@bp.route("/admin/login", methods=["GET", "POST"])
def admin_login():
    """Operator login (single admin password)."""
    error = None
    if request.method == "POST":
        if request.form.get("password", "") == get_admin_password():
            session["admin_logged_in"] = True
            return redirect(_safe_next("main.index"))
        error = "Invalid password."
    return render_template("admin_login.html", error=error)


@bp.route("/logout")
def logout():
    session.pop("admin_logged_in", None)
    session.pop("user_id", None)
    return redirect(url_for("main.login"))


@bp.route("/")
def index():
    """Public landing for visitors; dashboard for the admin; app for signed-in users."""
    if is_admin():
        users = models.list_users()
        return render_template("admin.html", users=users,
                               stats=scan_store.stats(), recent=scan_store.recent(8))
    if session.get("user_id"):
        return redirect(url_for("main.scan"))
    return render_template("landing.html", stripe_ready=billing.is_configured(),
                           price_label=PRO_PRICE_LABEL)


@bp.route("/healthz")
def healthz():
    return {"status": "ok"}, 200


@bp.route("/users/create", methods=["POST"])
@login_required
def create_user():
    username = request.form.get("username", "").strip()
    email    = request.form.get("email", "").strip()
    plan     = request.form.get("plan", "free")

    if not username or not email:
        flash("Username and email are required.", "error")
        return redirect(url_for("main.index"))
    if models.get_user_by_email(email):
        flash(f"Email already exists: {email}", "error")
        return redirect(url_for("main.index"))

    models.create_user(username, email, plan)
    flash(f"User '{username}' created.", "ok")
    return redirect(url_for("main.index"))


@bp.route("/users/<user_id>/plan", methods=["POST"])
@login_required
def set_plan(user_id: str):
    plan = request.form.get("plan", "free")
    user = models.update_plan(user_id, plan)
    if user:
        flash(f"Plan updated to [{plan.upper()}] for {user['username']}.", "ok")
    else:
        flash("User not found.", "error")
    return redirect(url_for("main.index"))


@bp.route("/users/<user_id>/delete", methods=["POST"])
@login_required
def delete_user(user_id: str):
    if models.delete_user(user_id):
        flash("User deleted.", "ok")
    else:
        flash("User not found.", "error")
    return redirect(url_for("main.index"))


@bp.route("/users/<user_id>")
@login_required
def user_detail(user_id: str):
    user = models.get_user(user_id)
    if not user:
        flash("User not found.", "error")
        return redirect(url_for("main.index"))
    return render_template("user_detail.html", user=user,
                           effective=models.effective_plan(user),
                           scans=scan_store.list_for_user(user_id),
                           used=scan_store.count_this_month(user_id),
                           quota=FREE_MONTHLY_QUOTA)


@bp.route("/users/<user_id>/pro", methods=["POST"])
@login_required
def set_pro(user_id: str):
    until = (request.form.get("until") or "").strip() or None
    amount = (request.form.get("amount") or "").strip()
    if models.set_pro_until(user_id, until, amount):
        flash(f"Marked Pro{(' until ' + until) if until else ' (no expiry)'}.", "ok")
    else:
        flash("User not found.", "error")
    return redirect(url_for("main.user_detail", user_id=user_id))


# repo -> richer /scan flow ; password -> CLI only (don't POST plaintext to the server)
_WEB_CHECK_EXCLUDE = ("repo", "password")

FREE_MONTHLY_QUOTA = 20  # free plan: scans per calendar month (pro = unlimited)


def _quota_remaining() -> Optional[int]:
    """Scans left this month for the current identity. None = unlimited (admin/pro)."""
    if is_admin():
        return None
    user = current_user()
    if not user or models.effective_plan(user) == "pro":
        return None
    return max(0, FREE_MONTHLY_QUOTA - scan_store.count_this_month(user["id"]))


@bp.route("/scan", methods=["GET", "POST"])
@auth_required
def scan():
    """Scan a public repo for secrets, vulnerable dependencies and insecure code."""
    remaining = _quota_remaining()
    if request.method == "GET":
        return render_template("scan.html", remaining=remaining)

    if remaining == 0:
        return render_template("scan.html", remaining=0,
            error=f"Free plan limit reached ({FREE_MONTHLY_QUOTA} scans/month). Upgrade to Pro for unlimited scans."), 429

    repo_url = request.form.get("repo_url", "").strip()
    if not _GITHUB_URL_RE.match(repo_url):
        return render_template("scan.html", remaining=remaining,
            error="Enter a valid public GitHub repo URL, e.g. https://github.com/owner/repo"), 400

    severities = [s for s in request.form.getlist("severity")
                  if s in ("CRITICAL", "HIGH", "MEDIUM", "LOW")]
    explain = request.form.get("explain") == "1"

    result = run_scan(repo_url, github_token=os.environ.get("GITHUB_TOKEN"))
    if result.errors:
        return render_template("scan.html", remaining=remaining, error="; ".join(result.errors)), 502

    from vaultcheck.diff import fingerprint_result
    # Record the full (unfiltered) result so history and quotas reflect everything…
    scan_store.add_scan(current_owner(), "repo", repo_url, result.severity_counts, result.total,
                        fingerprints=fingerprint_result(result))
    # …but show the report filtered to the chosen severities, if any.
    if severities:
        result = result.only_severities(severities)
    ai_section = None
    if explain:
        from vaultcheck.llm_explain import explain_html
        ai_section = explain_html(result.all_findings + result.licenses)
    return generate_report(result, severity_filter=severities or None, ai_section=ai_section)


@bp.route("/rescan", methods=["POST"])
@auth_required
def rescan():
    """Re-scan a repo and show what changed since the last stored scan of the same repo."""
    remaining = _quota_remaining()
    if remaining == 0:
        return render_template("scan.html", remaining=0,
            error=f"Free plan limit reached ({FREE_MONTHLY_QUOTA} scans/month). Upgrade to Pro for unlimited scans."), 429

    repo_url = request.form.get("repo_url", "").strip()
    if not _GITHUB_URL_RE.match(repo_url):
        return render_template("scan.html", remaining=remaining,
            error="Enter a valid public GitHub repo URL to re-scan, e.g. https://github.com/owner/repo"), 400

    from vaultcheck.schedule import run_scheduled_scan
    summary = run_scheduled_scan(
        repo_url, github_token=os.environ.get("GITHUB_TOKEN"),
        user_id=current_owner(), notify=True, store=scan_store,
    )
    if summary["errors"]:
        return render_template("scan.html", remaining=remaining, error="; ".join(summary["errors"])), 502

    return render_template("rescan.html", summary=summary, repo_url=repo_url)


_SEV_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
# Rank for sorting whole-check cards worst-first; clean & errored checks sink to the bottom.
_RESULT_RANK = {**_SEV_ORDER, "CLEAN": 4, "ERROR": 5}
# Which check target_types make sense for a given kind of entered target.
_TARGET_COMPAT = {
    "url":     {"url", "domain"},
    "domain":  {"domain", "url"},
    "email":   {"email"},
    "package": {"package"},
    "keyword": {"keyword"},
}


def _classify_target(t: str) -> str:
    t = t.strip()
    if t.lower().startswith(("http://", "https://")):
        return "url"
    if "@" in t:
        local, _, rest = t.partition("@")
        if rest[:1].isdigit() or ":" in local:
            return "package"          # flask@0.12.2  /  npm:left-pad@1.0.0
        if "." in rest:
            return "email"            # you@example.com
        return "keyword"
    if re.match(r"^[a-z0-9.-]+\.[a-z]{2,}$", t, re.I):
        return "domain"               # example.com
    return "keyword"


def _arg_for_check(chk, target: str, kind: str) -> str:
    """Adapt the entered target to what each check expects (URL vs bare hostname)."""
    if chk.target_type == "url" and kind == "domain":
        return "https://" + target
    if chk.target_type == "domain" and kind == "url":
        return urlparse(target).hostname or target
    return target


def _summarize_result(res) -> tuple[str, dict]:
    counts = {s: 0 for s in _SEV_ORDER}
    for f in res.findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1
    present = [s for s in _SEV_ORDER if counts[s]]
    worst = present[0] if present else ("ERROR" if res.errors else "CLEAN")
    return worst, counts


def _run_all_checks(target: str):
    """Run every passive check that fits the target, as tidy per-check cards (worst-first)."""
    kind = _classify_target(target)
    compat = _TARGET_COMPAT.get(kind, set())
    # Passive only: never auto-run authorized-target-only (active) checks in bulk.
    bundle = [c for c in list_checks()
              if c.target_type in compat and not c.requires_auth and c.id not in _WEB_CHECK_EXCLUDE]
    cards, agg = [], {s: 0 for s in _SEV_ORDER}
    for chk in bundle:
        arg = _arg_for_check(chk, target, kind)
        try:
            res = chk.run(arg)
        except Exception as exc:  # one failing check must not sink the whole run
            res = CheckResult(chk.id, arg, [], [str(exc)])
        worst, counts = _summarize_result(res)
        for s in _SEV_ORDER:
            agg[s] += counts[s]
        cards.append({
            "check": chk, "result": res, "worst": worst, "counts": counts,
            "findings": sorted(res.findings, key=lambda f: _SEV_ORDER.get(f.severity, 9)),
        })
    cards.sort(key=lambda c: _RESULT_RANK.get(c["worst"], 9))
    return kind, cards, agg, sum(agg.values())


@bp.route("/check", methods=["GET", "POST"])
@auth_required
def check_page():
    checks = [c for c in list_checks() if c.target_type not in _WEB_CHECK_EXCLUDE]
    remaining = _quota_remaining()
    if request.method == "GET":
        return render_template("check.html", checks=checks, remaining=remaining)

    action = request.form.get("action", "one")
    check_id = request.form.get("check_id", "").strip()
    target = request.form.get("target", "").strip()

    def back(msg, code):
        return render_template("check.html", checks=checks, error=msg, remaining=remaining,
                               selected=check_id, target=target), code

    if remaining == 0:
        return back(f"Free plan limit reached ({FREE_MONTHLY_QUOTA} scans/month). Upgrade to Pro for unlimited.", 429)
    if not target:
        return back("Enter a target to check.", 400)

    if action == "all":
        kind, cards, agg, total = _run_all_checks(target)
        if not cards:
            return back("No passive checks apply to that target — try a domain or URL.", 400)
        buckets = {s: sum(1 for c in cards if c["worst"] == s) for s in _SEV_ORDER}
        buckets["CLEAN"] = sum(1 for c in cards if c["worst"] == "CLEAN")
        buckets["ERROR"] = sum(1 for c in cards if c["worst"] == "ERROR")
        scan_store.add_scan(current_owner(), "check:all", target, agg, total)
        return render_template("check.html", checks=checks, remaining=remaining, target=target,
                               all_cards=cards, agg=agg, total=total, buckets=buckets, kind=kind)

    chk = get_check(check_id)
    if chk is None or chk.target_type in _WEB_CHECK_EXCLUDE:
        return back("Pick a valid check type.", 400)

    result = chk.run(target)
    findings = sorted(result.findings, key=lambda f: _SEV_ORDER.get(f.severity, 9))
    counts = {s: sum(1 for f in result.findings if f.severity == s) for s in _SEV_ORDER}
    scan_store.add_scan(current_owner(), f"check:{check_id}", target, counts, len(result.findings))

    return render_template("check.html", checks=checks, result=result, findings=findings,
                           counts=counts, selected=check_id, target=target, check_name=chk.name,
                           remaining=remaining)


@bp.route("/history")
@auth_required
def history():
    """Scan history. Admin sees everything; a user sees only their own scans."""
    if is_admin():
        scans = scan_store.recent(200)
    else:
        scans = scan_store.list_for_user(current_owner())
    return render_template("history.html", scans=scans)


@bp.route("/account")
@auth_required
def account():
    """Self-serve user account: plan, usage, recent scans."""
    user = current_user()
    if not user:  # an admin has the full dashboard instead
        return redirect(url_for("main.index"))
    plan = models.effective_plan(user)
    used = scan_store.count_this_month(user["id"])
    return render_template("account.html", user=user, plan=plan, used=used,
                           quota=FREE_MONTHLY_QUOTA,
                           remaining=(None if plan == "pro" else max(0, FREE_MONTHLY_QUOTA - used)),
                           scans=scan_store.list_for_user(user["id"])[:10])


PRO_PRICE_LABEL = os.environ.get("PRO_PRICE_LABEL", "$12 / month")


@bp.route("/billing")
@auth_required
def billing_page():
    user = current_user()
    if not user:
        return redirect(url_for("main.index"))
    return render_template("billing.html", user=user, plan=models.effective_plan(user),
                           stripe_ready=billing.is_configured(), price_label=PRO_PRICE_LABEL)


@bp.route("/billing/checkout", methods=["POST"])
@auth_required
def billing_checkout():
    user = current_user()
    if not user:
        return redirect(url_for("main.index"))
    if not billing.is_configured():
        flash("Online payment isn't configured yet — see the manual upgrade instructions below.", "error")
        return redirect(url_for("main.billing_page"))
    url = billing.create_checkout_session(
        user,
        success_url=url_for("main.billing_success", _external=True),
        cancel_url=url_for("main.billing_page", _external=True),
    )
    if not url:
        flash("Couldn't start checkout. Please try again.", "error")
        return redirect(url_for("main.billing_page"))
    return redirect(url, code=303)


@bp.route("/billing/success")
@auth_required
def billing_success():
    flash("Payment received — your Pro plan will activate shortly. Thank you!", "ok")
    return redirect(url_for("main.account"))


@bp.route("/stripe/webhook", methods=["POST"])
def stripe_webhook():
    """Stripe calls this after a successful payment; we grant Pro here (no auth — verified by signature)."""
    etype, user_id, amount = billing.parse_webhook(request.get_data(), request.headers.get("Stripe-Signature", ""))
    if etype in ("checkout.session.completed", "invoice.paid") and user_id:
        models.set_pro_until(user_id, billing.pro_until_from_now(), amount)
    return ("", 200)


# How many new public repos to pull and scan per fetch. Human-gated and bounded:
# Background "scan until N findings" worker — scanning many repos is slow, so it runs
# in a thread and the page polls job state. Bounded by DISCLOSURE_MAX_REPOS for safety.
DISCLOSURE_DEFAULT_TARGET = 10
DISCLOSURE_MAX_TARGET = 50
DISCLOSURE_MAX_REPOS = 120

_job = {"status": "idle", "source": "github", "scanned": 0, "found": 0, "queued": 0,
        "target": 0, "severities": [], "explain": False, "error": None}
_job_lock = threading.Lock()


def _run_disclosure_job(target, token, source="github", severities=None, explain=False):
    page = 1
    sev_keep = {s.upper() for s in (severities or [])}  # empty = all severities
    ai_on = False
    explain_finding = None
    if explain:  # only enable AI remediation if the local model is actually reachable
        try:
            from vaultcheck.llm_explain import explain_finding, is_available
            ai_on = is_available()
        except Exception:
            ai_on = False
    try:
        while True:
            with _job_lock:
                if _job["found"] >= target or _job["scanned"] >= DISCLOSURE_MAX_REPOS:
                    break
            repos, error = (SOURCES.get(source) or SOURCES["github"])(limit=50, page=page)
            if error:
                with _job_lock:
                    _job["error"] = error
                break
            if not repos:
                break
            for repo in repos:
                with _job_lock:
                    if _job["found"] >= target or _job["scanned"] >= DISCLOSURE_MAX_REPOS:
                        break
                if disclosure_store.repo_exists(repo["full_name"]):
                    continue
                findings, _errs = scan_repo(repo["url"], token)
                if sev_keep:  # only keep findings at the requested severity level(s)
                    findings = [f for f in findings if (f.get("severity") or "").upper() in sev_keep]
                if ai_on and findings:  # attach local-model remediation to each finding
                    for f in findings:
                        try:
                            txt = explain_finding(f)
                        except Exception:
                            txt = None
                        if txt:
                            f["ai"] = txt
                with _job_lock:
                    _job["scanned"] += 1
                if findings:
                    disclosure_store.add_case(repo["full_name"], repo["owner"], findings, repo["url"])
                    with _job_lock:
                        _job["queued"] += 1
                        _job["found"] += len(findings)
            page += 1
            if page > 10:  # GitHub search caps at 1000 results
                break
    finally:
        with _job_lock:
            _job["status"] = "done"


_SEV_RANK = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}


def _annotate_and_rank(cases: list[dict]) -> list[dict]:
    """Tag each case with its worst severity + per-severity counts, then sort worst-first.

    'Criticality' of a repo = its most severe finding; ties broken by newest first.
    """
    for case in cases:
        counts = {s: 0 for s in _SEV_RANK}
        for f in case["findings"]:
            sev = (f.get("severity") or "LOW").upper()
            counts[sev] = counts.get(sev, 0) + 1
        present = [s for s in _SEV_RANK if counts.get(s)]  # _SEV_RANK is worst-first
        case["counts_by_sev"] = counts
        case["worst"] = present[0] if present else "LOW"
        case["finding_count"] = len(case["findings"])
    cases.sort(key=lambda c: c["created_at"], reverse=True)        # newest first…
    cases.sort(key=lambda c: _SEV_RANK.get(c["worst"], 3))         # …then worst severity first (stable)
    return cases


def _case_guidance(findings: list[dict]) -> list[dict]:
    """Distinct impact / how-to-secure explanations for the categories in a case."""
    seen: set = set()
    out: list[dict] = []
    for f in findings:
        cat = (f.get("category") or "").lower()
        key = cat or "general"
        if key in seen:
            continue
        seen.add(key)
        impact, fix = explain(cat)
        out.append({"cat": cat or (f.get("kind") or "general").lower(),
                    "impact": impact, "fix": fix})
    return out


@bp.route("/disclosure")
@login_required
def disclosure():
    pending = disclosure_store.list_cases("pending")
    approved = disclosure_store.list_cases("approved")
    for case in pending + approved:
        case["notice"] = build_notice(case["repo"], case["owner"], case["findings"])
        case["guidance"] = _case_guidance(case["findings"])
    _annotate_and_rank(pending)
    _annotate_and_rank(approved)
    buckets = {s: sum(1 for c in pending if c["worst"] == s) for s in _SEV_RANK}
    with _job_lock:
        job = dict(_job)
    return render_template(
        "disclosure.html",
        pending=pending,
        approved=approved,
        buckets=buckets,
        counts=disclosure_store.counts(),
        job=job,
    )


@bp.route("/disclosure/fetch", methods=["POST"])
@login_required
def disclosure_fetch():
    with _job_lock:
        if _job["status"] == "running":
            flash("A scan is already running.", "error")
            return redirect(url_for("main.disclosure"))
        try:
            target = int(request.form.get("target", DISCLOSURE_DEFAULT_TARGET))
        except (TypeError, ValueError):
            target = DISCLOSURE_DEFAULT_TARGET
        target = max(1, min(target, DISCLOSURE_MAX_TARGET))
        source = request.form.get("source", "github")
        if source not in SOURCES:
            source = "github"
        severities = [s for s in request.form.getlist("severity")
                      if s in ("CRITICAL", "HIGH", "MEDIUM", "LOW")]
        explain = request.form.get("explain") == "1"
        _job.update({"status": "running", "source": source, "scanned": 0, "found": 0,
                     "queued": 0, "target": target, "severities": severities,
                     "explain": explain, "error": None})

    token = os.environ.get("GITHUB_TOKEN")
    threading.Thread(target=_run_disclosure_job, args=(target, token, source, severities, explain),
                     daemon=True).start()
    sev_note = f" ({', '.join(severities)} only)" if severities else ""
    flash(f"Scanning new public repos on {source} until {target} findings{sev_note}…", "ok")
    return redirect(url_for("main.disclosure"))


@bp.route("/disclosure/<case_id>/<action>", methods=["POST"])
@login_required
def disclosure_action(case_id: str, action: str):
    mapping = {"approve": "approved", "dismiss": "dismissed", "disclosed": "disclosed"}
    if action in mapping and disclosure_store.set_status(case_id, mapping[action]):
        flash(f"Case marked {mapping[action]}.", "ok")
    else:
        flash("Unknown action or case.", "error")
    return redirect(url_for("main.disclosure"))


# ── Scheduled scans ───────────────────────────────────────────────────────────
SCHEDULER_TICK = 60  # seconds between checks for due schedules
_scheduler_started = False


def _can_schedule() -> bool:
    if is_admin():
        return True
    user = current_user()
    return bool(user and models.effective_plan(user) == "pro")


def _run_one_schedule(sched: dict) -> None:
    kind, target = sched["kind"], sched["target"]
    try:
        if kind == "repo":
            result = run_scan(target, github_token=os.environ.get("GITHUB_TOKEN"))
            counts, total = result.severity_counts, result.total
        elif kind.startswith("check:"):
            chk = get_check(kind.split(":", 1)[1])
            if chk is None:
                return
            res = chk.run(target)
            counts = {s: sum(1 for f in res.findings if f.severity == s)
                      for s in ("CRITICAL", "HIGH", "MEDIUM", "LOW")}
            total = len(res.findings)
        else:
            return
    except Exception:
        return
    scan_store.add_scan(sched["owner"], kind, target, counts, total)
    schedule_store.mark_run(sched["id"], counts, total)


def _scheduler_loop() -> None:
    while True:
        try:
            for sched in schedule_store.due():
                _run_one_schedule(sched)
        except Exception:
            pass
        time.sleep(SCHEDULER_TICK)


def _start_scheduler() -> None:
    global _scheduler_started
    if _scheduler_started:
        return
    _scheduler_started = True
    threading.Thread(target=_scheduler_loop, daemon=True).start()


@bp.route("/schedules")
@auth_required
def schedules():
    items = schedule_store.list_all() if is_admin() else schedule_store.list_for_owner(current_owner())
    checks = [c for c in list_checks() if c.target_type not in _WEB_CHECK_EXCLUDE]
    return render_template("schedules.html", schedules=items, checks=checks,
                           can_schedule=_can_schedule(),
                           intervals=list(schedule_store.INTERVALS.keys()))


@bp.route("/schedules/add", methods=["POST"])
@auth_required
def schedules_add():
    if not _can_schedule():
        flash("Scheduled scans are a Pro feature. Upgrade to enable them.", "error")
        return redirect(url_for("main.schedules"))
    kind = request.form.get("kind", "").strip()
    target = request.form.get("target", "").strip()
    interval = request.form.get("interval", "daily").strip()

    if interval not in schedule_store.INTERVALS:
        flash("Pick a valid interval.", "error")
        return redirect(url_for("main.schedules"))
    if kind == "repo":
        if not _GITHUB_URL_RE.match(target):
            flash("Enter a valid GitHub repo URL for a repository scan.", "error")
            return redirect(url_for("main.schedules"))
    elif kind.startswith("check:"):
        if get_check(kind.split(":", 1)[1]) is None:
            flash("Pick a valid check type.", "error")
            return redirect(url_for("main.schedules"))
    else:
        flash("Pick a valid scan type.", "error")
        return redirect(url_for("main.schedules"))
    if not target:
        flash("Enter a target.", "error")
        return redirect(url_for("main.schedules"))

    schedule_store.add_schedule(current_owner(), kind, target, interval)
    flash("Schedule created — it will run on the next cycle.", "ok")
    return redirect(url_for("main.schedules"))


@bp.route("/schedules/<schedule_id>/delete", methods=["POST"])
@auth_required
def schedules_delete(schedule_id: str):
    owner = None if is_admin() else current_owner()
    if schedule_store.delete(schedule_id, owner):
        flash("Schedule removed.", "ok")
    else:
        flash("Schedule not found.", "error")
    return redirect(url_for("main.schedules"))


@bp.app_errorhandler(404)
def not_found(_e):
    return render_template("error.html", code=404,
                           message="That page doesn't exist."), 404


@bp.app_errorhandler(500)
def server_error(_e):
    return render_template("error.html", code=500,
                           message="Something went wrong on our end."), 500


def create_app() -> Flask:
    app = Flask(__name__, template_folder="templates")
    app.secret_key = os.environ.get("FLASK_SECRET_KEY", os.urandom(32))
    app.register_blueprint(bp)
    _start_scheduler()
    return app
