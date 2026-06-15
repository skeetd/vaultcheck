"""Authentication: a single operator admin (password) plus self-serve user accounts.

Two independent sessions can coexist:
- ``admin_logged_in``  — the operator, signs in with ADMIN_PASSWORD, runs the dashboard.
- ``user_id``          — a self-serve customer account, signs in with email + password.

Scan/check/history pages accept EITHER identity; the admin dashboard requires admin.
"""
import functools
import os

from flask import redirect, request, session, url_for

from . import models


def get_admin_password() -> str:
    pw = os.environ.get("ADMIN_PASSWORD")
    if not pw:
        raise RuntimeError("ADMIN_PASSWORD environment variable is not set.")
    return pw


def is_admin() -> bool:
    return bool(session.get("admin_logged_in"))


def current_user() -> dict | None:
    """The logged-in self-serve user, or None."""
    uid = session.get("user_id")
    return models.get_user(uid) if uid else None


def current_owner() -> str:
    """Owner id for storing scans: the admin's scans live under 'admin'."""
    if is_admin():
        return "admin"
    user = current_user()
    return user["id"] if user else "anonymous"


def login_required(f):
    """Admin-only routes (dashboard, user management, disclosure, schedules admin)."""
    @functools.wraps(f)
    def wrapper(*args, **kwargs):
        if not is_admin():
            return redirect(url_for("main.admin_login", next=request.path))
        return f(*args, **kwargs)
    return wrapper


def auth_required(f):
    """Routes usable by an admin OR a signed-in user (scan, check, history, account)."""
    @functools.wraps(f)
    def wrapper(*args, **kwargs):
        if not is_admin() and not session.get("user_id"):
            return redirect(url_for("main.login", next=request.path))
        return f(*args, **kwargs)
    return wrapper
