"""Stripe Checkout integration for the Pro plan.

Designed to degrade gracefully:
- With STRIPE_SECRET_KEY + STRIPE_PRICE_ID set (and the `stripe` package installed),
  the billing page offers a real hosted Checkout and a webhook grants Pro.
- Without them, the billing page shows manual-payment instructions and nothing breaks.

No card data ever touches this app — Stripe-hosted Checkout handles it.
"""
import os
from datetime import datetime, timedelta, timezone
from typing import Optional

try:
    import stripe  # type: ignore
except ModuleNotFoundError:  # pragma: no cover
    stripe = None

# Days of Pro granted per successful monthly payment.
PRO_PERIOD_DAYS = 31


def _secret_key() -> str:
    return os.environ.get("STRIPE_SECRET_KEY", "")


def price_id() -> str:
    return os.environ.get("STRIPE_PRICE_ID", "")


def webhook_secret() -> str:
    return os.environ.get("STRIPE_WEBHOOK_SECRET", "")


def is_configured() -> bool:
    """True when a real Stripe Checkout can be created."""
    return bool(stripe and _secret_key() and price_id())


def _client():
    stripe.api_key = _secret_key()
    return stripe


def create_checkout_session(user: dict, success_url: str, cancel_url: str) -> Optional[str]:
    """Create a hosted Checkout session and return its URL, or None on failure."""
    if not is_configured():
        return None
    try:
        session = _client().checkout.Session.create(
            mode="subscription",
            line_items=[{"price": price_id(), "quantity": 1}],
            client_reference_id=user["id"],
            customer_email=user.get("email"),
            metadata={"user_id": user["id"], "username": user.get("username", "")},
            success_url=success_url,
            cancel_url=cancel_url,
        )
        return session.url
    except Exception:
        return None


def pro_until_from_now() -> str:
    return (datetime.now(timezone.utc) + timedelta(days=PRO_PERIOD_DAYS)).strftime("%Y-%m-%d")


def parse_webhook(payload: bytes, sig_header: str):
    """Verify and parse a Stripe webhook. Returns (event_type, user_id, amount) or (None, None, None).

    When STRIPE_WEBHOOK_SECRET is set the signature is verified; otherwise the JSON is
    parsed best-effort (useful for local Stripe CLI forwarding in test mode).
    """
    if not stripe:
        return None, None, None
    try:
        if webhook_secret():
            event = stripe.Webhook.construct_event(payload, sig_header, webhook_secret())
        else:
            import json
            event = json.loads(payload.decode("utf-8"))
    except Exception:
        return None, None, None

    etype = event.get("type")
    obj = (event.get("data") or {}).get("object") or {}
    user_id = obj.get("client_reference_id") or (obj.get("metadata") or {}).get("user_id")
    amount = obj.get("amount_total")
    amount_str = f"{amount / 100:.2f} {(obj.get('currency') or '').upper()}".strip() if amount else ""
    return etype, user_id, amount_str
