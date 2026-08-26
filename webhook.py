"""Turn an Orca webhook POST into a list of alert ids to remediate.

Orca ships two payload shapes and lets you edit the body template, so nothing
about the incoming JSON is guaranteed except that the alert id is in there
somewhere. Rather than pin one path, this walks the known ones:

    {"version": "1.0", "data": {...}}   the current wrapper format
    {"state": {"alert_id": "orca-1"}}   the legacy flat format
    {"alert_id": "orca-1"}              a hand-trimmed body template
    [ {...}, {...} ]                    a batch

Everything here is stdlib only and side-effect free, so it can be unit tested
without the Functions Framework or a network.
"""

from __future__ import annotations

import hmac
import os
import re

# Orca alert ids look like orca-1596292. Validating the shape keeps an arbitrary
# string from the request body ever reaching a URL path or an API query.
ALERT_ID_RE = re.compile(r"^orca-[A-Za-z0-9]+$")

# Where the alert id has been observed, most specific first. Each entry is a
# dotted path walked against the (possibly unwrapped) payload.
ALERT_ID_PATHS = (
    "state.alert_id",
    "alert_id",
    "alertId",
    "data.state.alert_id",
    "data.alert_id",
    "alert.state.alert_id",
    "alert.alert_id",
    "AlertId",
    "alert_state.alert_id",
    "data.AlertId",
    "Alert.AlertId",
)

# Keys whose value is a list of alerts when Orca batches them.
BATCH_KEYS = ("alerts", "data", "items", "results")

# Fields checked against ALERT_TYPE_ALLOWLIST, when that filter is configured.
TYPE_FIELDS = (
    "type_key",
    "type",
    "type_string",
    "category",
    "subject_type",
    "asset_type",
    # Serving-layer / capitalised equivalents.
    "AlertType",
    "AppsecScanType",
    "Category",
    "Title",
    "SecurityDomains",
)


class WebhookError(Exception):
    """The request itself is wrong: bad auth, bad JSON, no alert id."""

    def __init__(self, message: str, status: int = 400):
        super().__init__(message)
        self.status = status


def env_flag(name: str, default: bool = False) -> bool:
    raw = os.environ.get(name)
    if raw is None or raw.strip() == "":
        return default
    return raw.strip().lower() in ("1", "true", "yes", "on")


def _dig(obj: object, path: str) -> object:
    """Walk a dotted path, returning None the moment it stops matching."""
    for part in path.split("."):
        if not isinstance(obj, dict):
            return None
        obj = obj.get(part)
    return obj


def unwrap(payload: dict) -> dict:
    """Strip the {"version": ..., "data": {...}} envelope if that's what this is.

    Only unwraps when `data` is a dict, so a batch under `data` is left for
    extract_alert_ids to fan out.
    """
    if set(payload) <= {"version", "data", "schema_version"} and isinstance(
        payload.get("data"), dict
    ):
        return payload["data"]
    return payload


def verify_secret(headers) -> None:
    """Reject the request unless it carries the shared secret.

    Orca's webhook template can send any custom header, and its built-in API Key
    field lands in `Authorization`, so both are accepted. Fails closed: with no
    WEBHOOK_SECRET configured the endpoint refuses everything, because an open
    endpoint here spends AI metering units and writes to customer repos.
    """
    if env_flag("ALLOW_UNAUTHENTICATED"):
        return

    expected = os.environ.get("WEBHOOK_SECRET", "").strip()
    if not expected:
        raise WebhookError(
            "WEBHOOK_SECRET is not configured; refusing to accept unauthenticated "
            "webhooks (set ALLOW_UNAUTHENTICATED=true only for local testing)",
            status=500,
        )

    header_name = os.environ.get("WEBHOOK_SECRET_HEADER", "X-Orca-Webhook-Token")
    presented = (headers.get(header_name) or "").strip()
    if not presented:
        auth = (headers.get("Authorization") or "").strip()
        # Orca's API Key field may or may not be prefixed depending on template.
        for prefix in ("Bearer ", "Token "):
            if auth.startswith(prefix):
                auth = auth[len(prefix) :].strip()
                break
        presented = auth

    if not presented or not hmac.compare_digest(presented, expected):
        raise WebhookError("invalid or missing webhook secret", status=401)


def matches_type_filter(alert: dict) -> bool:
    """True unless ALERT_TYPE_ALLOWLIST is set and none of its terms appear.

    Terms are matched case-insensitively as substrings against the alert's type
    and category fields, so `sast` catches `sast_finding` and `SAST Finding`.
    """
    raw = os.environ.get("ALERT_TYPE_ALLOWLIST", "").strip()
    if not raw:
        return True
    terms = [t.strip().lower() for t in raw.split(",") if t.strip()]
    if not terms:
        return True

    def haystack_of(obj: dict) -> str:
        parts = []
        for field in TYPE_FIELDS:
            value = _unwrap_value(obj.get(field))
            if value is not None:
                parts.append(str(value))
        return " ".join(parts).lower()

    haystack = haystack_of(alert)
    # The legacy format nests some of these under `state`.
    state = _unwrap_value(alert.get("state"))
    if isinstance(state, dict):
        haystack += " " + haystack_of(state)
    return any(term in haystack for term in terms)


def _unwrap_value(value: object) -> object:
    """Serving-layer fields arrive as {"value": ...}; take the inner value.

    Orca's newer integration payloads are built from the serving layer, where
    every field is wrapped this way — "AlertId": {"value": "orca-1590385"} — while
    the legacy webhook format uses a bare string. Accept both.
    """
    if isinstance(value, dict) and "value" in value:
        return value["value"]
    return value


def _alert_id_of(alert: dict) -> str | None:
    for path in ALERT_ID_PATHS:
        value = _unwrap_value(_dig(alert, path))
        if isinstance(value, str) and ALERT_ID_RE.match(value.strip()):
            return value.strip()
    return None


def extract_alerts(payload: object) -> list[dict]:
    """Flatten whatever arrived into a list of individual alert objects."""
    if isinstance(payload, list):
        return [a for item in payload for a in extract_alerts(item)]
    if not isinstance(payload, dict):
        return []

    alert = unwrap(payload)
    if _alert_id_of(alert) is not None:
        return [alert]

    # No id at this level: the alerts must be in a list one level down.
    for key in BATCH_KEYS:
        value = alert.get(key)
        if isinstance(value, list):
            nested = [a for item in value for a in extract_alerts(item)]
            if nested:
                return nested
    return []


def extract_alert_ids(payload: object) -> list[str]:
    """Alert ids from the payload, de-duplicated, order preserved, filter applied.

    Raises WebhookError if the payload carried no recognisable alert id at all —
    that's a misconfigured webhook template, worth surfacing as a 400.
    """
    alerts = extract_alerts(payload)
    if not alerts:
        raise WebhookError(
            "no Orca alert id found in the payload; check the webhook body "
            'template includes the alert id (or use "All alert fields in JSON")'
        )

    ids: list[str] = []
    for alert in alerts:
        alert_id = _alert_id_of(alert)
        if alert_id is None or alert_id in ids:
            continue
        if not matches_type_filter(alert):
            continue
        ids.append(alert_id)
    return ids
