"""The Orca "AI code fix -> pull request" flow, in three API calls.

  1. POST /api/serving-layer/query                  alert id -> repository, and
                                                    which remediation skill fits
  2. POST /api/ai-core/skills/code_remediation/...  generate the fix (~20s)
  3. POST .../repository_contexts/{id}/pull_requests/  open the PR

Step 3's body is step 2's response remapped, with the code base64'd. Orca drives
its own GitHub App server-side, so no GitHub credential is involved here.

Reads one environment variable, ORCA_API_TOKEN, which needs two separately
granted permissions: the ai-core remediation skill for step 2, and shiftleft
write for step 3. Missing either is a 403, and the shape says which:
{"detail": ...} from ai-core, {"error_code": "permission_denied"} from shiftleft.
A third form, error_code "1012", means the token was fine but Orca's GitHub App
lacks `Contents write` on that repository.

Raises OrcaError rather than exiting, so main.py decides what a failure means.
"""

from __future__ import annotations

import base64
import json
import os
import re
import urllib.error
import urllib.parse
import urllib.request

# Overridable only so the test suite can point at a local stand-in for the API.
BASE = os.environ.get("ORCA_API_BASE", "https://api.orcasecurity.io")
APP = "https://app.orcasecurity.io"

# Step 2 re-runs the model server-side and takes 13-24s in practice.
TIMEOUT = 180


# Anything interpolated into a URL path must not be able to leave its segment.
# UUIDs and the test fixtures both satisfy this; a value containing / . : or %
# does not.
PATH_SEGMENT_RE = re.compile(r"^[A-Za-z0-9_-]{1,128}$")


class OrcaError(Exception):
    """An Orca API call failed, or the alert can't be remediated.

    `status` is the HTTP status when the failure came from the API, else None.
    `retryable` tells a webhook caller whether asking again could ever help.
    """

    def __init__(self, message: str, status: int | None = None, retryable: bool = False):
        super().__init__(message)
        self.status = status
        self.retryable = retryable


def auth_header() -> str:
    """The Authorization header value to send to Orca."""
    token = os.environ.get("ORCA_API_TOKEN", "").strip()
    if not token:
        raise OrcaError("ORCA_API_TOKEN is not set")
    return f"Token {token}"


def resolve_url(path: str) -> str:
    """Join BASE and path, refusing anything that isn't HTTPS.

    BASE comes from the environment, and urllib honours schemes like file:// and
    ftp://, so without this a stray ORCA_API_BASE would turn every API call into
    a local file read. http is permitted against loopback only, so the test suite
    can point at a local stand-in for the Orca API.
    """
    url = BASE.rstrip("/") + path
    parts = urllib.parse.urlsplit(url)
    if parts.scheme == "https":
        return url
    if parts.scheme == "http" and parts.hostname in ("127.0.0.1", "localhost", "::1"):
        return url
    raise OrcaError(
        f"refusing to call a non-HTTPS URL ({parts.scheme or 'no'} scheme): check ORCA_API_BASE"
    )


def call(path: str, body: dict | None = None, expect: int = 200, auth: str | None = None) -> dict:
    """POST if a body is given, else GET. Raises OrcaError on any other status."""
    req = urllib.request.Request(
        resolve_url(path),
        data=json.dumps(body).encode() if body is not None else None,
        method="POST" if body is not None else "GET",
        headers={
            "Authorization": auth or auth_header(),
            "Content-Type": "application/json",
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
            status, raw = resp.status, resp.read()
    except urllib.error.HTTPError as exc:
        status, raw = exc.code, exc.read()
    except (urllib.error.URLError, TimeoutError) as exc:
        # Network-level: no response at all, so worth another attempt later.
        raise OrcaError(f"{path} -> unreachable: {exc}", retryable=True) from exc
    if status != expect:
        detail = raw.decode(errors="replace")[:300]
        # 429 and 5xx are the only statuses where the same request may later work.
        raise OrcaError(
            f"{path} -> {status}: {detail}",
            status=status,
            retryable=status == 429 or status >= 500,
        )
    return json.loads(raw or b"null")


class NoCodeOrigin(OrcaError):
    """The alert doesn't map to any code, so there is nothing to fix.

    A normal outcome, not a fault: most CSPM alerts describe resources that were
    never provisioned from IaC Orca can see. Distinct from OrcaError so the
    webhook can report it as a skip rather than an error.
    """


def resolve_target(alert_id: str, auth: str | None = None) -> tuple[str, str]:
    """Find the repository to patch, and which remediation skill applies.

    Returns (repository_context_id, skill) where skill is "sast" or "c2d".

    Two shapes of alert reach code by different routes, and the alert's own asset
    type is what distinguishes them — not its category, of which CSPM alone has
    hundreds:

      asset IS a CodeRepository   the finding is in the repo Orca scanned, so the
                                  repo is the asset itself             -> sast
      asset is a cloud resource   the finding is in the IaC that deployed it, so
                                  the repo comes from its code origin  -> c2d

    Anything the second route can't resolve has no code origin and is skipped
    before step 2, so it costs no AI metering unit.
    """
    body = call(
        "/api/serving-layer/query",
        {
            "query": {
                "models": ["Alert"],
                "type": "object_set",
                "with": {"key": "AlertId", "values": [alert_id], "type": "str", "operator": "eq"},
            },
            "additional_models[]": ["Inventory"],
            "full_graph_fetch": {"enabled": True},
        },
        auth=auth,
    )
    try:
        inventory = body["data"][0]["data"]["Inventory"]
    except (KeyError, IndexError, TypeError):
        raise NoCodeOrigin(f"{alert_id} has no asset attached") from None

    # A CodeRepository asset carries the repository context id directly, as its
    # Id field. Cloud resources have no such field, which is the tell.
    if inventory.get("type") == "CodeRepository":
        try:
            return inventory["data"]["Id"]["value"], "sast"
        except (KeyError, TypeError):
            raise NoCodeOrigin(f"{alert_id}: code repository asset has no Id") from None

    asset_id = inventory.get("id")
    if not asset_id:
        raise NoCodeOrigin(f"{alert_id}: asset has no id to trace to code")
    return lookup_code_origin(alert_id, asset_id, auth), "c2d"


def lookup_code_origin(alert_id: str, asset_id: str, auth: str | None = None) -> str:
    """Trace a cloud asset back to the repository whose IaC deployed it.

    Asks for the CodeOrigin objects whose Inventories include this asset, and
    takes the CodeRepository hanging off the first one.
    """
    body = call(
        "/api/serving-layer/query",
        {
            "query": {
                "models": ["CodeOrigin"],
                "type": "object_set",
                "with": {
                    "models": ["Inventory"],
                    "type": "object_set",
                    "keys": ["Inventories"],
                    "operator": "has",
                    "with": {
                        "keys": ["base"],
                        "models": ["base"],
                        "type": "object",
                        "operator": "has",
                        "with": {
                            "key": "id",
                            "values": [asset_id],
                            "type": "uuid",
                            "operator": "in",
                        },
                    },
                },
            },
            "additional_models[]": ["CodeRepository"],
            "get_results_and_count": False,
            "full_graph_fetch": {"enabled": True},
        },
        auth=auth,
    )
    try:
        return body["data"][0]["data"]["CodeRepository"]["data"]["Id"]["value"]
    except (KeyError, IndexError, TypeError):
        raise NoCodeOrigin(
            f"{alert_id}: asset has no code origin Orca can trace, so there is no "
            f"IaC to patch"
        ) from None


def generate_fix(
    alert_id: str, repo_context_id: str, auth: str | None = None, skill: str = "sast"
) -> dict:
    """Step 2. Synchronous, 13-24s, non-deterministic, costs one AI metering unit.

    `skill` picks the endpoint: "sast" for a finding in scanned source, "c2d"
    (code-to-cloud) for a cloud misconfiguration traced back to its IaC. The two
    take the same request and return the same response shape.
    """
    if skill not in ("sast", "c2d"):
        raise OrcaError(f"unknown remediation skill {skill!r}")
    if not PATH_SEGMENT_RE.match(repo_context_id):
        raise OrcaError(f"repository_context_id has an unexpected form: {repo_context_id!r}")
    return call(
        f"/api/ai-core/skills/code_remediation/{skill}",
        {
            "target_schema": "serving-layer",
            "alert_id": alert_id,
            "repository_context_id": repo_context_id,
        },
        auth=auth,
    )


def open_pull_request(
    alert_id: str, repo_context_id: str, fix: dict, auth: str | None = None
) -> dict:
    """Step 3. A pure remap of step 2's response; Orca's GitHub App does the rest."""
    # This one lands in the URL path rather than the body, so bound its shape.
    if not PATH_SEGMENT_RE.match(repo_context_id):
        raise OrcaError(f"repository_context_id has an unexpected form: {repo_context_id!r}")
    return call(
        f"/api/shiftleft/repository_contexts/{repo_context_id}/pull_requests/",
        {
            "title": fix["pr_title"],
            "description": fix["pr_description"],
            "alert_id": alert_id,
            "alert_url": f"{APP}/alerts/{alert_id}",
            "file_path": fix["file_path"],
            "fixed_content": base64.b64encode(fix["fixed_code"].encode()).decode(),
        },
        expect=201,
        auth=auth,
    )


def remediate(alert_id: str, create_pr: bool = False, auth: str | None = None) -> dict:
    """Run the whole flow for one alert and describe what happened.

    Returns a dict with `status` in: skipped_false_positive, skipped_no_code_fix,
    generated (fix produced, PR not requested), pr_opened. A NoCodeOrigin is left
    to the caller, which knows whether to treat it as a skip or an error.
    """
    auth = auth or auth_header()
    ctx, skill = resolve_target(alert_id, auth)
    fix = generate_fix(alert_id, ctx, auth, skill=skill)

    result = {
        "alert_id": alert_id,
        "repository_context_id": ctx,
        "skill": skill,
        "file_path": fix.get("file_path"),
        "remediation_type": fix.get("remediation_type"),
        "is_false_positive": bool(fix.get("is_false_positive")),
        "pr_title": fix.get("pr_title"),
    }

    # Non-code remediations (action steps only) and false positives have no patch.
    if fix.get("is_false_positive"):
        return {**result, "status": "skipped_false_positive"}
    if fix.get("remediation_type") != "code_fix":
        return {**result, "status": "skipped_no_code_fix"}
    if not create_pr:
        return {**result, "status": "generated", "fix": fix}

    pr = open_pull_request(alert_id, ctx, fix, auth)
    return {**result, "status": "pr_opened", "pull_request_url": pr.get("url")}
