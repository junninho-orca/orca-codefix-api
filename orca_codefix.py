#!/usr/bin/env python3
"""Open an Orca AI code fix as a pull request, without the UI.

Three calls, one Orca API token:

  1. POST /api/serving-layer/query                    alert id -> repository_context_id
  2. POST /api/ai-core/skills/code_remediation/sast   generate the fix (~20s, synchronous)
  3. POST .../repository_contexts/{id}/pull_requests/ open the PR

Step 3's body is just step 2's response remapped, with the code base64'd. Orca
drives its own GitHub App server-side, so no GitHub credential is involved.

    export ORCA_AUTH="Token $ORCA_API_TOKEN"
    ./orca_codefix_replay.py orca-1596292 --create-pr

The token needs two separately-granted permissions: the ai-core remediation skill
for step 2, and shiftleft write for step 3. Missing either is a 403, and the shape
says which: {"detail": ...} from ai-core, {"error_code": "permission_denied"} from
shiftleft. A third form, error_code "1012", means the token was fine but Orca's
GitHub App lacks `Contents write` on that repo.

Behind a TLS-intercepting proxy, point Python at the system roots first:
    security find-certificate -a -p /Library/Keychains/System.keychain > ca.pem
    export SSL_CERT_FILE="$PWD/ca.pem"
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

BASE = "https://api.orcasecurity.io"
APP = "https://app.orcasecurity.io"


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


def call(path: str, body: dict | None = None, expect: int = 200) -> dict:
    """POST if a body is given, else GET. Exits with the server's message on failure."""
    req = urllib.request.Request(
        BASE + path,
        data=json.dumps(body).encode() if body is not None else None,
        method="POST" if body is not None else "GET",
        headers={"Authorization": os.environ["ORCA_AUTH"], "Content-Type": "application/json"},
    )
    try:
        with urllib.request.urlopen(req, timeout=180) as resp:
            status, raw = resp.status, resp.read()
    except urllib.error.HTTPError as exc:
        status, raw = exc.code, exc.read()
    if status != expect:
        sys.exit(f"{path} -> {status}: {raw.decode(errors='replace')[:300]}")
    return json.loads(raw or b"null")


def lookup_repo_context(alert_id: str) -> str:
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
    )
    try:
        return body["data"][0]["data"]["Inventory"]["data"]["Id"]["value"]
    except (KeyError, IndexError, TypeError):
        sys.exit(f"{alert_id} has no code repository attached")


def main() -> None:
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    ap.add_argument("alert_id", help="e.g. orca-1596292")
    ap.add_argument("--repo-context-id", help="skip the step 1 lookup")
    ap.add_argument("--create-pr", action="store_true", help="open the PR (writes to the repo)")
    args = ap.parse_args()

    load_dotenv()
    if not os.environ.get("ORCA_AUTH"):
        sys.exit('ORCA_AUTH is unset — e.g. export ORCA_AUTH="Token $ORCA_API_TOKEN"')

    ctx = args.repo_context_id or lookup_repo_context(args.alert_id)
    print(f"repository_context_id: {ctx}", file=sys.stderr)

    fix = call(
        "/api/ai-core/skills/code_remediation/sast",
        {
            "target_schema": "serving-layer",
            "alert_id": args.alert_id,
            "repository_context_id": ctx,
        },
    )
    json.dump(fix, sys.stdout, indent=2)

    # Non-code remediations (action steps only) and false positives have no patch.
    if fix.get("is_false_positive") or fix.get("remediation_type") != "code_fix":
        sys.exit("\nno code fix to submit")

    if not args.create_pr:
        print("\n(dry run — pass --create-pr to open the PR)", file=sys.stderr)
        return

    pr = call(
        f"/api/shiftleft/repository_contexts/{ctx}/pull_requests/",
        {
            "title": fix["pr_title"],
            "description": fix["pr_description"],
            "alert_id": args.alert_id,
            "alert_url": f"{APP}/alerts/{args.alert_id}",
            "file_path": fix["file_path"],
            "fixed_content": base64.b64encode(fix["fixed_code"].encode()).decode(),
        },
        expect=201,
    )
    print(f"\nopened {pr['url']}", file=sys.stderr)


if __name__ == "__main__":
    main()
