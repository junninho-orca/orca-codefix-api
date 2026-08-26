#!/usr/bin/env python3
"""Open an Orca AI code fix as a pull request, without the UI.

Three calls, one Orca API token:

  1. POST /api/serving-layer/query                    alert id -> repository_context_id
  2. POST /api/ai-core/skills/code_remediation/sast   generate the fix (~20s, synchronous)
  3. POST .../repository_contexts/{id}/pull_requests/ open the PR

Step 3's body is just step 2's response remapped, with the code base64'd. Orca
drives its own GitHub App server-side, so no GitHub credential is involved.

    export ORCA_API_TOKEN="..."
    ./orca_codefix.py orca-1596292 --create-pr

The token needs two separately-granted permissions: the ai-core remediation skill
for step 2, and shiftleft write for step 3. Missing either is a 403, and the shape
says which: {"detail": ...} from ai-core, {"error_code": "permission_denied"} from
shiftleft. A third form, error_code "1012", means the token was fine but Orca's
GitHub App lacks `Contents write` on that repo.

Behind a TLS-intercepting proxy, point Python at the system roots first:
    security find-certificate -a -p /Library/Keychains/System.keychain > ca.pem
    export SSL_CERT_FILE="$PWD/ca.pem"

This module is also the engine behind the Cloud Function in main.py, so the
library half raises OrcaError instead of exiting; only the CLI half exits.
"""

from __future__ import annotations

import argparse
import base64
import json
import os
import pathlib
import sys
import urllib.error
import urllib.request

BASE = os.environ.get("ORCA_API_BASE", "https://api.orcasecurity.io")
APP = os.environ.get("ORCA_APP_BASE", "https://app.orcasecurity.io")

# Step 2 re-runs the model server-side and takes 13-24s in practice.
TIMEOUT = int(os.environ.get("ORCA_HTTP_TIMEOUT", "180"))


class OrcaError(Exception):
    """An Orca API call failed, or the alert can't be remediated.

    `status` is the HTTP status when the failure came from the API, else None.
    `retryable` tells a webhook caller whether asking again could ever help.
    """

    def __init__(self, message: str, status: int | None = None, retryable: bool = False):
        super().__init__(message)
        self.status = status
        self.retryable = retryable


def load_dotenv() -> None:
    """Load a .env sitting next to this script. Real env vars win over the file."""
    path = pathlib.Path(__file__).resolve().with_name(".env")
    if not path.exists():
        return
    for line in path.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        os.environ.setdefault(key.strip(), value.strip().strip("\"'"))


def auth_header() -> str:
    """The Authorization header value to send to Orca.

    ORCA_AUTH is the full header value and wins. ORCA_API_TOKEN is the bare token,
    which is the friendlier thing to put in Secret Manager.
    """
    auth = os.environ.get("ORCA_AUTH", "").strip()
    if auth:
        return auth
    token = os.environ.get("ORCA_API_TOKEN", "").strip()
    if token:
        return f"Token {token}"
    raise OrcaError(
        "no Orca credential: set ORCA_API_TOKEN (bare token) or ORCA_AUTH "
        '(full header value, e.g. "Token abc123")'
    )


def call(path: str, body: dict | None = None, expect: int = 200, auth: str | None = None) -> dict:
    """POST if a body is given, else GET. Raises OrcaError on any other status."""
    req = urllib.request.Request(
        BASE + path,
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


def lookup_repo_context(alert_id: str, auth: str | None = None) -> str:
    """The repository_context_id is just the alert's CodeRepository asset Id."""
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
        return body["data"][0]["data"]["Inventory"]["data"]["Id"]["value"]
    except (KeyError, IndexError, TypeError):
        raise OrcaError(f"{alert_id} has no code repository attached") from None


def generate_fix(alert_id: str, repo_context_id: str, auth: str | None = None) -> dict:
    """Step 2. Synchronous, 13-24s, non-deterministic, costs one AI metering unit."""
    return call(
        "/api/ai-core/skills/code_remediation/sast",
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


def remediate(
    alert_id: str,
    create_pr: bool = False,
    repo_context_id: str | None = None,
    auth: str | None = None,
) -> dict:
    """Run the whole flow for one alert and describe what happened.

    Returns a dict with `status` in: skipped_false_positive, skipped_no_code_fix,
    generated (fix produced, PR not requested), pr_opened.
    """
    auth = auth or auth_header()
    ctx = repo_context_id or lookup_repo_context(alert_id, auth)
    fix = generate_fix(alert_id, ctx, auth)

    result = {
        "alert_id": alert_id,
        "repository_context_id": ctx,
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


def main() -> None:
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    ap.add_argument("alert_id", help="e.g. orca-1596292")
    ap.add_argument("--repo-context-id", help="skip the step 1 lookup")
    ap.add_argument("--create-pr", action="store_true", help="open the PR (writes to the repo)")
    args = ap.parse_args()

    load_dotenv()
    try:
        auth = auth_header()
        ctx = args.repo_context_id or lookup_repo_context(args.alert_id, auth)
        print(f"repository_context_id: {ctx}", file=sys.stderr)

        fix = generate_fix(args.alert_id, ctx, auth)
        json.dump(fix, sys.stdout, indent=2)

        if fix.get("is_false_positive") or fix.get("remediation_type") != "code_fix":
            sys.exit("\nno code fix to submit")
        if not args.create_pr:
            print("\n(dry run — pass --create-pr to open the PR)", file=sys.stderr)
            return

        pr = open_pull_request(args.alert_id, ctx, fix, auth)
        print(f"\nopened {pr['url']}", file=sys.stderr)
    except OrcaError as exc:
        sys.exit(str(exc))


if __name__ == "__main__":
    main()
