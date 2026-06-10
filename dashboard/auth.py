"""Single-admin password auth via Flask session."""
import functools
import os

from flask import redirect, request, session, url_for


def get_admin_password() -> str:
    pw = os.environ.get("ADMIN_PASSWORD")
    if not pw:
        raise RuntimeError("ADMIN_PASSWORD environment variable is not set.")
    return pw


def login_required(f):
    @functools.wraps(f)
    def wrapper(*args, **kwargs):
        if not session.get("admin_logged_in"):
            return redirect(url_for("main.login", next=request.path))
        return f(*args, **kwargs)
    return wrapper
