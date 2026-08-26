"""Cloud Functions v2 entrypoint: Orca alert webhook -> AI code fix -> pull request.

Deploy with deploy.sh, point an Orca webhook integration at the resulting URL, and
every alert Orca sends gets a fix generated and (with CREATE_PR=true) a pull request
opened by Orca's own GitHub App.

Environment (see .env.example for the full list):
    ORCA_API_TOKEN    required   Orca API token; needs ai-core remediation + shiftleft write
    WEBHOOK_SECRET    required   shared secret Orca must present, or the endpoint 401s
    CREATE_PR         default false   false generates the fix without writing to the repo

Processing is synchronous because Orca's fix generation is: step 2 takes 13-24s and
has no polling API. A single alert therefore takes roughly 15-40s end to end, which
is why the function is deployed with a 300s timeout. If Orca times out and retries,
DEDUPE_WINDOW guards against opening the same pull request twice.
"""

from __future__ import annotations

import json
import logging
import os
import time
from collections import OrderedDict

import functions_framework

import orca_codefix
import webhook

logging.basicConfig(level=os.environ.get("LOG_LEVEL", "INFO"))
log = logging.getLogger("orca-codefix")

# Alert ids already handled by this instance, newest last. Orca retries a webhook
# it considers failed, and generating a fix is both billable and repo-writing, so
# a replay must not run twice. This is per-instance and therefore best-effort: it
# catches the common case where a retry lands on the warm instance that just ran.
_DEDUPE_WINDOW = int(os.environ.get("DEDUPE_WINDOW", "512"))
_seen: OrderedDict[str, dict] = OrderedDict()


def _remember(alert_id: str, result: dict) -> None:
    _seen[alert_id] = result
    _seen.move_to_end(alert_id)
    while len(_seen) > _DEDUPE_WINDOW:
        _seen.popitem(last=False)


def _json(body: dict, status: int = 200):
    return (json.dumps(body, default=str), status, {"Content-Type": "application/json"})


def process_alert(alert_id: str, create_pr: bool) -> dict:
    """Remediate one alert, returning a result dict that never raises."""
    started = time.monotonic()

    if _DEDUPE_WINDOW > 0 and alert_id in _seen:
        log.info("%s already processed by this instance, skipping", alert_id)
        # Report this call's own (near-zero) duration, not the cached run's.
        return {**_seen[alert_id], "deduplicated": True, "duration_seconds": 0.0}

    try:
        result = orca_codefix.remediate(alert_id, create_pr=create_pr)
    except orca_codefix.OrcaError as exc:
        result = {
            "alert_id": alert_id,
            "status": "error",
            "error": str(exc),
            "retryable": exc.retryable,
        }
        log.error("%s failed: %s", alert_id, exc)
    else:
        # The generated patch can be tens of KB. It belongs in the pull request,
        # not in a webhook response Orca discards, so report it by size only.
        fix = result.pop("fix", None)
        if fix:
            result["fixed_code_bytes"] = len(fix.get("fixed_code") or "")
        log.info("%s -> %s", alert_id, result.get("status"))

    result["duration_seconds"] = round(time.monotonic() - started, 1)
    if _DEDUPE_WINDOW > 0 and result.get("status") != "error":
        _remember(alert_id, result)
    return result


@functions_framework.http
def orca_webhook(request):
    """HTTP entrypoint. GET is a health check; POST is the Orca webhook."""
    if request.method == "GET":
        return _json(
            {
                "status": "ok",
                "service": "orca-codefix-webhook",
                "create_pr": webhook.env_flag("CREATE_PR"),
                "auth_required": not webhook.env_flag("ALLOW_UNAUTHENTICATED"),
            }
        )

    if request.method != "POST":
        return _json({"error": f"{request.method} not allowed; use POST"}, 405)

    try:
        webhook.verify_secret(request.headers)
        payload = request.get_json(silent=True, force=True)
        if payload is None:
            raise webhook.WebhookError("request body is not valid JSON")
        alert_ids = webhook.extract_alert_ids(payload)
    except webhook.WebhookError as exc:
        log.warning("rejected request: %s", exc)
        return _json({"error": str(exc)}, exc.status)

    if not alert_ids:
        # Parsed fine, but ALERT_TYPE_ALLOWLIST filtered everything out. This is a
        # success: Orca did its job and we deliberately did nothing.
        log.info("no alerts matched ALERT_TYPE_ALLOWLIST")
        return _json({"status": "ignored", "reason": "no alerts matched type filter"})

    limit = int(os.environ.get("MAX_ALERTS_PER_REQUEST", "10"))
    skipped = alert_ids[limit:]
    if skipped:
        log.warning("%d alerts over MAX_ALERTS_PER_REQUEST=%d, not processed", len(skipped), limit)

    create_pr = webhook.env_flag("CREATE_PR")
    results = [process_alert(alert_id, create_pr) for alert_id in alert_ids[:limit]]

    body = {
        "status": "processed",
        "create_pr": create_pr,
        "processed": len(results),
        "results": results,
    }
    if skipped:
        body["not_processed"] = skipped

    # Ask Orca to retry only when every failure was transient, so a permanent
    # failure (no code fix, missing permission) doesn't loop forever.
    errors = [r for r in results if r.get("status") == "error"]
    if errors and len(errors) == len(results) and all(r.get("retryable") for r in errors):
        return _json(body, 503)
    return _json(body)
