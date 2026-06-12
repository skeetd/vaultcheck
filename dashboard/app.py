import os
import re
import threading
from pathlib import Path
from flask import (
    Blueprint, Flask, flash, redirect, render_template,
    request, session, url_for
)
from dotenv import load_dotenv
from .auth import get_admin_password, login_required
from . import models
from . import disclosure_store
from . import scan_store
from vaultcheck.disclosure import SOURCES, build_notice, scan_repo
from vaultcheck.registry import get_check, list_checks
from vaultcheck.reporter import generate_report
from vaultcheck.scanner import run_scan

load_dotenv(Path(__file__).resolve().parent.parent / ".env")

bp = Blueprint("main", __name__)

# Which scan phases each plan may run (free tier = limited functionality)
PLAN_PHASES = {
    "free": ("secrets", "code"),
    "pro":  ("secrets", "deps", "code"),
}
# Web form only scans public GitHub repos — never local paths (avoids scanning the server)
_GITHUB_URL_RE = re.compile(r"^https://github\.com/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+/?$")


@bp.route("/login", methods=["GET", "POST"])
def login():
    error = None
    if request.method == "POST":
        pw = request.form.get("password", "")
        if pw == get_admin_password():
            session["admin_logged_in"] = True
            return redirect(request.args.get("next") or url_for("main.index"))
        error = "Invalid password."
    return render_template("login.html", error=error)


@bp.route("/logout")
def logout():
    session.pop("admin_logged_in", None)
    return redirect(url_for("main.login"))


@bp.route("/")
@login_required
def index():
    users = models.list_users()
    return render_template("admin.html", users=users,
                           stats=scan_store.stats(), recent=scan_store.recent(8))


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


@bp.route("/scan", methods=["GET", "POST"])
@login_required
def scan():
    """Scan a public repo for secrets, vulnerable dependencies and insecure code."""
    if request.method == "GET":
        return render_template("scan.html")

    repo_url = request.form.get("repo_url", "").strip()
    if not _GITHUB_URL_RE.match(repo_url):
        return render_template("scan.html",
            error="Enter a valid public GitHub repo URL, e.g. https://github.com/owner/repo"), 400

    result = run_scan(repo_url, github_token=os.environ.get("GITHUB_TOKEN"))
    if result.errors:
        return render_template("scan.html", error="; ".join(result.errors)), 502

    scan_store.add_scan("admin", "repo", repo_url, result.severity_counts, result.total)
    return generate_report(result)


# repo -> richer /scan flow ; password -> CLI only (don't POST plaintext to the server)
_WEB_CHECK_EXCLUDE = ("repo", "password")

FREE_MONTHLY_QUOTA = 20  # free plan: scans per calendar month (pro = unlimited)


@bp.route("/check", methods=["GET", "POST"])
@login_required
def check_page():
    checks = [c for c in list_checks() if c.target_type not in _WEB_CHECK_EXCLUDE]
    if request.method == "GET":
        return render_template("check.html", checks=checks)

    check_id = request.form.get("check_id", "").strip()
    target = request.form.get("target", "").strip()

    def back(msg, code):
        return render_template("check.html", checks=checks, error=msg,
                               selected=check_id, target=target), code

    chk = get_check(check_id)
    if chk is None or chk.target_type in _WEB_CHECK_EXCLUDE:
        return back("Pick a valid check type.", 400)
    if not target:
        return back("Enter a target to check.", 400)

    result = chk.run(target)
    order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    findings = sorted(result.findings, key=lambda f: order.get(f.severity, 9))
    counts = {s: sum(1 for f in result.findings if f.severity == s) for s in order}
    scan_store.add_scan("admin", f"check:{check_id}", target, counts, len(result.findings))

    return render_template("check.html", checks=checks, result=result, findings=findings,
                           counts=counts, selected=check_id, target=target, check_name=chk.name)


@bp.route("/history")
@login_required
def history():
    """Scan history (every repo scan and check that has been run)."""
    return render_template("history.html", scans=scan_store.recent(200))


# How many new public repos to pull and scan per fetch. Human-gated and bounded:
# Background "scan until N findings" worker — scanning many repos is slow, so it runs
# in a thread and the page polls job state. Bounded by DISCLOSURE_MAX_REPOS for safety.
DISCLOSURE_DEFAULT_TARGET = 10
DISCLOSURE_MAX_TARGET = 50
DISCLOSURE_MAX_REPOS = 120

_job = {"status": "idle", "source": "github", "scanned": 0, "found": 0, "queued": 0, "target": 0, "error": None}
_job_lock = threading.Lock()


def _run_disclosure_job(target, token, source="github"):
    page = 1
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


@bp.route("/disclosure")
@login_required
def disclosure():
    pending = disclosure_store.list_cases("pending")
    approved = disclosure_store.list_cases("approved")
    for case in pending + approved:
        case["notice"] = build_notice(case["repo"], case["owner"], case["findings"])
    with _job_lock:
        job = dict(_job)
    return render_template(
        "disclosure.html",
        pending=pending,
        approved=approved,
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
        _job.update({"status": "running", "source": source, "scanned": 0, "found": 0,
                     "queued": 0, "target": target, "error": None})

    token = os.environ.get("GITHUB_TOKEN")
    threading.Thread(target=_run_disclosure_job, args=(target, token, source), daemon=True).start()
    flash(f"Scanning new public repos on {source} until {target} findings…", "ok")
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


def create_app() -> Flask:
    app = Flask(__name__, template_folder="templates")
    app.secret_key = os.environ.get("FLASK_SECRET_KEY", os.urandom(32))
    app.register_blueprint(bp)
    return app
