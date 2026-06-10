import os
import re
from pathlib import Path
from flask import (
    Blueprint, Flask, flash, redirect, render_template,
    request, session, url_for
)
from dotenv import load_dotenv
from .auth import get_admin_password, login_required
from . import models
from . import disclosure_store
from vaultcheck.disclosure import build_notice, fetch_recent_public_repos, scan_repo_secrets
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
    return render_template("admin.html", users=users)


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


@bp.route("/scan", methods=["GET", "POST"])
def scan():
    """Public self-serve scan: a user submits their own repo with their access token."""
    if request.method == "GET":
        return render_template("scan.html")

    token = request.form.get("token", "").strip()
    repo_url = request.form.get("repo_url", "").strip()

    user = models.get_user_by_token(token)
    if not user:
        return render_template("scan.html", error="Invalid access token.", token=token), 403
    if not _GITHUB_URL_RE.match(repo_url):
        return render_template(
            "scan.html",
            error="Enter a valid public GitHub repo URL, e.g. https://github.com/owner/repo",
            token=token,
        ), 400

    phases = PLAN_PHASES.get(user["plan"], PLAN_PHASES["free"])
    result = run_scan(repo_url, phases=phases, github_token=os.environ.get("GITHUB_TOKEN"))
    models.increment_scan_count(user["id"])

    if result.errors:
        return render_template("scan.html", error="; ".join(result.errors), token=token), 502

    upgrade_hint = "Upgrade to Pro to enable dependency scanning." if user["plan"] == "free" else None
    return generate_report(result, upgrade_hint=upgrade_hint)


# repo -> richer /scan flow ; password -> CLI only (don't POST plaintext to the server)
_WEB_CHECK_EXCLUDE = ("repo", "password")


@bp.route("/check", methods=["GET", "POST"])
def check_page():
    checks = [c for c in list_checks() if c.target_type not in _WEB_CHECK_EXCLUDE]
    if request.method == "GET":
        return render_template("check.html", checks=checks)

    token = request.form.get("token", "").strip()
    check_id = request.form.get("check_id", "").strip()
    target = request.form.get("target", "").strip()

    def back(msg, code):
        return render_template("check.html", checks=checks, error=msg,
                               token=token, selected=check_id, target=target), code

    user = models.get_user_by_token(token)
    if not user:
        return back("Invalid access token.", 403)
    chk = get_check(check_id)
    if chk is None or chk.target_type in _WEB_CHECK_EXCLUDE:
        return back("Pick a valid check type.", 400)
    if chk.tier == "pro" and user["plan"] != "pro":
        return back(f"The '{chk.name}' check requires a Pro plan.", 403)
    if not target:
        return back("Enter a target to check.", 400)

    result = chk.run(target)
    models.increment_scan_count(user["id"])

    order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    findings = sorted(result.findings, key=lambda f: order.get(f.severity, 9))
    counts = {s: sum(1 for f in result.findings if f.severity == s) for s in order}

    return render_template("check.html", checks=checks, result=result, findings=findings,
                           counts=counts, selected=check_id, target=target, token=token,
                           check_name=chk.name)


# How many new public repos to pull and scan per fetch. Human-gated and bounded:
# the scan runs synchronously in the request, so a large batch would hang the page.
# Real volume needs a background worker (see roadmap), not a bigger number here.
DISCLOSURE_BATCH = 5
DISCLOSURE_MAX = 15


@bp.route("/disclosure")
@login_required
def disclosure():
    pending = disclosure_store.list_cases("pending")
    approved = disclosure_store.list_cases("approved")
    for case in pending + approved:
        case["notice"] = build_notice(case["repo"], case["owner"], case["findings"])
    return render_template(
        "disclosure.html",
        pending=pending,
        approved=approved,
        counts=disclosure_store.counts(),
    )


@bp.route("/disclosure/fetch", methods=["POST"])
@login_required
def disclosure_fetch():
    try:
        count = int(request.form.get("count", DISCLOSURE_BATCH))
    except (TypeError, ValueError):
        count = DISCLOSURE_BATCH
    count = max(1, min(count, DISCLOSURE_MAX))

    repos, error = fetch_recent_public_repos(limit=count, since_minutes=180)
    if error:
        flash(f"GitHub fetch failed: {error}", "error")
        return redirect(url_for("main.disclosure"))

    scanned = 0
    queued = 0
    for repo in repos:
        if disclosure_store.repo_exists(repo["full_name"]):
            continue
        findings, _errs = scan_repo_secrets(repo["url"])
        scanned += 1
        if findings:
            disclosure_store.add_case(repo["full_name"], repo["owner"], findings)
            queued += 1

    flash(f"Scanned {scanned} new public repo(s); {queued} with potential secrets queued for review.", "ok")
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
