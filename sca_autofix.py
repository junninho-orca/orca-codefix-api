#!/usr/bin/env python3
"""Scheduled SCA autofix: pick recent shiftleft alerts and run orca-patch on each.

Orca's AI code fix API (main.py) covers SAST, IaC and CSPM, but not SCA. For those
this script, run from .github/workflows/orca-sca-autofix.yml, lists the open
vulnerability alerts on CodeRepository assets, drops any that already have an
open pull request, and runs Claude Code headless with the vendored orca-patch
skill against each one, which clones the owning repository, bumps the package,
and opens the pull request.

    python3 sca_autofix.py                       # alerts created in the last 26h
    python3 sca_autofix.py --alert-id orca-1234  # one alert, on demand
    python3 sca_autofix.py --dry-run             # list and dedupe, run nothing

The listing and filtering helpers (build_query, select_alerts and what they call)
are stdlib only and side-effect free so test_sca_autofix.py can cover them
without a network. Everything that talks to Orca, GitHub or Claude lives in
main() and the fetch_/run_ functions below it.

Environment: ORCA_API_TOKEN (Orca REST and, via .mcp.json, the Orca MCP server),
ANTHROPIC_API_KEY (Claude Code), GH_TOKEN (gh and git for every repo in the org),
GITHUB_REPOSITORY_OWNER (the org whose pull requests are searched).
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile

import orca_codefix

# Same shape webhook.py enforces before an id reaches a URL or a query.
ALERT_ID_RE = re.compile(r"^orca-[A-Za-z0-9]+$")

# Hard cap on alerts per run. Each one is a full Claude Code session that clones
# a repository and opens a pull request, so the bound is on cost and on review
# load, not on API quota.
MAX_ALERTS = 5

# How far back the scheduled run looks. The workflow runs every 2h; 26h means a
# day of missed runs (runner outage, workflow disabled) is caught up on the next
# one, and an alert still open after that is also still there the day after.
LOOKBACK_HOURS = 26

# Page size for the alert query. The CreatedAt filter keeps the scheduled result
# far below this; main() warns when a page comes back full, since alerts past
# the first page would be silently missed.
QUERY_LIMIT = 500

# Branch the skill is told to use, so a second run can find the first run's PR.
BRANCH_PREFIX = "orca-patch/"

# Where the alert's creation time has been observed in serving-layer records.
# Walked in order; the first parseable value wins.
CREATED_AT_PATHS = (
    "CreatedAt",
    "CreationTime",
    "AlertCreatedAt",
    "FirstSeen",
    "Timestamp",
    "created_at",
    "creation_time",
    "state.created_at",
)

# Per-alert wall clock for the headless Claude run. A clone, a manifest bump, a
# dependency resolve and a PR fit well inside this; a stuck run does not get to
# eat the whole job.
CLAUDE_TIMEOUT_SECONDS = 30 * 60

PR_URL_RE = re.compile(r"https://github\.com/[\w.-]+/[\w.-]+/pull/\d+")


def _unwrap(value: object) -> object:
    """Serving-layer fields arrive as {"value": ...}; take the inner value."""
    if isinstance(value, dict) and "value" in value:
        return value["value"]
    return value


def _dig(obj: object, path: str) -> object:
    """Walk a dotted path through value-wrapped dicts, None when it stops matching."""
    for part in path.split("."):
        obj = _unwrap(obj)
        if not isinstance(obj, dict):
            return None
        obj = obj.get(part)
    return _unwrap(obj)


def build_query(alert_id: str | None = None, since: dt.datetime | None = None) -> dict:
    """The serving-layer body that lists candidate alerts.

    With an alert id, it is the same by-id lookup main.py's flow uses. Without
    one, it asks for open vulnerability alerts created since `since`, and leaves
    the asset-type filtering to select_alerts: the serving layer rejects filters
    on AssetData.asset_type and Labels ("Unknown field"), while Status, Category
    and CreatedAt are accepted, so those three bound the result server-side and
    the rest is decided from the returned records.
    """
    if alert_id is not None:
        if not ALERT_ID_RE.match(alert_id):
            raise ValueError(f"not an Orca alert id: {alert_id!r}")
        where = {"key": "AlertId", "values": [alert_id], "type": "str", "operator": "eq"}
    else:
        clauses = [
            {"key": "Status", "values": ["open"], "type": "str", "operator": "in"},
            {"key": "Category", "values": ["Vulnerabilities"], "type": "str", "operator": "in"},
        ]
        if since is not None:
            stamp = since.astimezone(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S+00:00")
            clauses.append({"key": "CreatedAt", "values": [stamp], "type": "datetime", "operator": "gte"})
        where = {"type": "operation", "operator": "and", "values": clauses}
    return {
        "query": {"models": ["Alert"], "type": "object_set", "with": where},
        "additional_models[]": ["Inventory"],
        "full_graph_fetch": {"enabled": True},
        "limit": QUERY_LIMIT,
    }


def alert_id_of(record: dict) -> str | None:
    value = _dig(record, "data.AlertId")
    if value is None:
        value = _dig(record, "AlertId")
    if isinstance(value, str) and ALERT_ID_RE.match(value.strip()):
        return value.strip()
    return None


def created_at(record: dict) -> dt.datetime | None:
    """The alert's creation time as an aware UTC datetime, or None if not found.

    Accepts ISO 8601 strings (with Z or an offset) and epoch seconds or
    milliseconds, since both have been seen from Orca's APIs.
    """
    data = _unwrap(record.get("data")) if "data" in record else record
    for path in CREATED_AT_PATHS:
        value = _dig(data, path)
        parsed = _parse_time(value)
        if parsed is not None:
            return parsed
    return None


def _parse_time(value: object) -> dt.datetime | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        seconds = value / 1000 if value > 1e11 else value
        try:
            return dt.datetime.fromtimestamp(seconds, tz=dt.timezone.utc)
        except (OverflowError, OSError, ValueError):
            return None
    if isinstance(value, str) and value.strip():
        text = value.strip()
        if text.endswith("Z"):
            text = text[:-1] + "+00:00"
        try:
            parsed = dt.datetime.fromisoformat(text)
        except ValueError:
            return None
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=dt.timezone.utc)
        return parsed.astimezone(dt.timezone.utc)
    return None


def is_sca_alert(record: dict) -> bool:
    """True for an open vulnerability finding on a scanned code repository.

    The asset type is the tell, exactly as in orca_codefix.resolve_target: the
    attached Inventory is a CodeRepository. AssetData.asset_type and the
    source:shiftleft label are accepted as equivalents, since records fetched
    without the Inventory model still carry those.
    """
    data = _unwrap(record.get("data")) if "data" in record else record
    if not isinstance(data, dict):
        return False

    status = _dig(data, "Status")
    if isinstance(status, str) and status.lower() != "open":
        return False

    category = _dig(data, "Category")
    if isinstance(category, str) and category.lower() != "vulnerabilities":
        return False

    inventory = _unwrap(data.get("Inventory"))
    inventory_type = inventory.get("type") if isinstance(inventory, dict) else None
    asset_type = _dig(data, "AssetData.asset_type")
    labels = _dig(data, "Labels")
    labels = [str(x).lower() for x in labels] if isinstance(labels, list) else []
    return (
        inventory_type == "CodeRepository"
        or asset_type == "CodeRepository"
        or "source:shiftleft" in labels
    )


def select_alerts(
    records: list,
    now: dt.datetime,
    lookback_hours: int = LOOKBACK_HOURS,
    limit: int = MAX_ALERTS,
    alert_id: str | None = None,
) -> list[str]:
    """Alert ids worth running, newest first, de-duplicated, capped at `limit`.

    Scheduled mode keeps SCA alerts created within the lookback window; a record
    with no readable creation time is kept too, since dropping it would hide a
    field rename as an empty run. On-demand mode (`alert_id`) returns just that
    id if it is present and is an SCA alert, regardless of age.
    """
    if alert_id is not None and not ALERT_ID_RE.match(alert_id):
        raise ValueError(f"not an Orca alert id: {alert_id!r}")

    cutoff = now - dt.timedelta(hours=lookback_hours)
    kept: list[tuple[dt.datetime, str]] = []
    seen: set[str] = set()
    for record in records:
        if not isinstance(record, dict):
            continue
        found = alert_id_of(record)
        if found is None or found in seen or not is_sca_alert(record):
            continue
        when = created_at(record)
        if alert_id is not None:
            if found != alert_id:
                continue
        elif when is not None and when < cutoff:
            continue
        seen.add(found)
        kept.append((when or now, found))

    kept.sort(key=lambda pair: pair[0], reverse=True)
    return [found for _, found in kept[:limit]]


def branch_for(alert_id: str) -> str:
    return BRANCH_PREFIX + alert_id


def build_prompt(alert_id: str, workspace: str) -> str:
    """What the headless Claude run is asked to do.

    The skill's own flow presents the diff and waits for the engineer before
    pushing; there is no engineer in a scheduled job, so the prompt grants that
    step up front and pins the branch name the dedupe check looks for. Every
    other rule in the skill (no default branch, no force, no merge, stop
    conditions) stays in force.
    """
    return (
        f"Use the orca-patch skill to patch {alert_id} and open the PR. "
        "This is an unattended run with no engineer to consult: the pull request "
        "step is approved in advance, so after verifying the patch, commit it, "
        f"push it, and open the PR in this same run. Name the branch {branch_for(alert_id)} "
        f"(instead of the fix/ prefix). Clone the owning repository under {workspace}. "
        "Never push to the default branch, never force-push, never merge. Before "
        "opening the PR, check the target repository for an open pull request on "
        "another orca-patch/* branch that touches the same file (gh pr list --repo "
        "<owner/repo> --state open --json url,headRefName,files); if one exists, do "
        "not open a second PR: comment on that one with this alert id and its ui_url, "
        f"and end your report with the line 'PR: attached to <url>'. If any "
        "stop condition applies, do not commit or push; finish with the skill's "
        "report block explaining why, and nothing else needs doing."
    )


def outcome_row(alert_id: str, outcome: str, detail: str) -> str:
    """One line of the run summary table. Pipes in `detail` would break the row."""
    return f"| {alert_id} | {outcome} | {detail.replace('|', '/').replace(chr(10), ' ')} |"


def extract_report(text: str, alert_id: str, limit: int = 600) -> str:
    """The skill's `## <alert-id>: ...` report block from Claude's final message.

    Falls back to the tail of the message when the block is missing, so a run
    that ended some other way still leaves a readable trace in the summary.
    """
    start = text.find(f"## {alert_id}")
    if start >= 0:
        snippet = text[start:].strip()
        if len(snippet) > limit:
            snippet = snippet[: limit - 3] + "..."
        return snippet
    snippet = text.strip()
    if len(snippet) > limit:
        snippet = "..." + snippet[-(limit - 3) :]
    return snippet


def repos_mentioned(text: str, owner: str) -> list[str]:
    """`owner/repo` names in Claude's final message, in order of first mention.

    The skill's report names the origin repository (as a github.com URL or a bare
    owner/repo), which is where any PR it opened lives. Only repositories under
    `owner` count, since the PAT and the dedupe are scoped to that org.
    """
    found: list[str] = []
    pattern = re.compile(
        r"(?:https?://github\.com/|(?<![\w./@-]))(" + re.escape(owner) + r"/[\w.-]+?)(?=[\s)\]>,:;'\"`]|\.git\b|/|$)",
        re.IGNORECASE,
    )
    for match in pattern.finditer(text):
        repo = match.group(1).rstrip(".")
        if repo.lower() not in (r.lower() for r in found):
            found.append(repo)
    return found


def attached_pr(text: str) -> str | None:
    """URL from the report's `PR: attached to <url>` line, when the skill chose to
    comment on an existing PR for the same fix surface instead of opening one."""
    match = re.search(r"PR:\s*attached to\s*(" + PR_URL_RE.pattern + ")", text, re.IGNORECASE)
    return match.group(1) if match else None


# --- Everything below has side effects: Orca, GitHub, Claude. ---------------


def fetch_alerts(alert_id: str | None, since: dt.datetime | None) -> list:
    body = orca_codefix.call("/api/serving-layer/query", build_query(alert_id, since))
    data = body.get("data") if isinstance(body, dict) else None
    return data if isinstance(data, list) else []


def _gh_json(args: list[str]) -> list:
    result = subprocess.run(["gh", *args], capture_output=True, text=True, check=True)
    hits = json.loads(result.stdout or "[]")
    return hits if isinstance(hits, list) else []


def find_open_pr(owner: str, alert_id: str) -> str | None:
    """URL of an open PR anywhere in `owner` whose head is this alert's branch.

    Uses the search API, which can lag a fresh PR by a minute or two; fine for
    the pre-run check, where anything that new was opened by this same run.
    """
    hits = _gh_json([
        "search", "prs", "--owner", owner, "--state", "open",
        "--head", branch_for(alert_id), "--json", "url", "--limit", "5",
    ])
    return hits[0]["url"] if hits else None


def find_pr_mentioning(owner: str, alert_id: str) -> str | None:
    """URL of an open PR in `owner` whose body or comments name this alert.

    Two alerts can share one fix surface (the same Dockerfile deployed to two
    environments). The first run opens the PR; the second attaches its alert id
    as a comment instead of opening another. This is what keeps the second alert
    from being re-attached every two hours until Orca closes it.
    """
    hits = _gh_json([
        "search", "prs", "--owner", owner, "--state", "open",
        "--match", "body,comments", alert_id, "--json", "url", "--limit", "5",
    ])
    return hits[0]["url"] if hits else None


def find_pr_in_repos(repos: list[str], alert_id: str) -> str | None:
    """URL of the open PR on this alert's branch in any of `repos`.

    `gh pr list --head` reads the repository directly, so unlike the search API
    it sees a PR the moment it exists.
    """
    for repo in repos:
        hits = _gh_json([
            "pr", "list", "--repo", repo, "--state", "open",
            "--head", branch_for(alert_id), "--json", "url", "--limit", "1",
        ])
        if hits:
            return hits[0]["url"]
    return None


def run_claude(alert_id: str, workspace: str, repo_root: str) -> tuple[str, dict]:
    """Run Claude Code headless from the repo root so .claude/skills is picked up.

    Returns the final assistant text and the parsed result envelope. Permissions
    are bypassed because nobody is there to approve them; the blast radius is
    bounded by the PAT's scopes and by the skill's own contract.
    """
    cmd = [
        "claude", "-p", build_prompt(alert_id, workspace),
        "--output-format", "json",
        "--mcp-config", os.path.join(repo_root, ".mcp.json"),
        "--strict-mcp-config",
        "--add-dir", workspace,
        "--dangerously-skip-permissions",
    ]
    proc = subprocess.run(
        cmd,
        cwd=repo_root,
        capture_output=True,
        text=True,
        timeout=CLAUDE_TIMEOUT_SECONDS,
    )
    try:
        envelope = json.loads(proc.stdout or "{}")
    except json.JSONDecodeError:
        envelope = {}
    text = envelope.get("result") if isinstance(envelope, dict) else None
    if not isinstance(text, str) or not text.strip():
        text = (proc.stdout or "") + ("\n" + proc.stderr if proc.stderr else "")
    if proc.returncode != 0 and not envelope:
        raise RuntimeError(f"claude exited {proc.returncode}: {proc.stderr.strip()[:400]}")
    return text, envelope


def process(alert_id: str, owner: str, repo_root: str, dry_run: bool) -> tuple[str, str]:
    """Handle one alert end to end and return (outcome, detail) for the summary.

    Never raises: a failure on one alert is reported as its own row and the run
    moves on to the next.
    """
    try:
        existing = find_open_pr(owner, alert_id)
        covering = None if existing else find_pr_mentioning(owner, alert_id)
    except (subprocess.CalledProcessError, json.JSONDecodeError, KeyError) as exc:
        return "error", f"PR lookup failed: {exc}"
    if existing:
        return "skipped", f"open PR exists: {existing}"
    if covering:
        return "skipped", f"already covered by an open PR: {covering}"
    if dry_run:
        return "dry-run", "would run orca-patch"

    workspace = tempfile.mkdtemp(prefix=f"{alert_id}-", dir=os.environ.get("RUNNER_TEMP"))
    try:
        text, envelope = run_claude(alert_id, workspace, repo_root)
    except subprocess.TimeoutExpired:
        return "error", f"claude timed out after {CLAUDE_TIMEOUT_SECONDS // 60} min"
    except (RuntimeError, OSError) as exc:
        return "error", str(exc)
    finally:
        shutil.rmtree(workspace, ignore_errors=True)

    cost = envelope.get("total_cost_usd") if isinstance(envelope, dict) else None
    cost_note = f" (${cost:.2f})" if isinstance(cost, (int, float)) else ""

    # GitHub is the ground truth. Read the repository the report names first,
    # since that is exact and instant; the search index can lag a fresh PR.
    try:
        opened = find_pr_in_repos(repos_mentioned(text, owner), alert_id) or find_open_pr(owner, alert_id)
    except (subprocess.CalledProcessError, json.JSONDecodeError, KeyError):
        opened = None
    if opened:
        return "pr_opened", f"{opened}{cost_note}"

    attached = attached_pr(text)
    if attached:
        return "attached", f"commented on the existing PR for the same fix surface: {attached}{cost_note}"

    match = PR_URL_RE.search(text)
    if match:
        return "pr_opened", f"{match.group(0)}{cost_note}"
    return "no_pr", extract_report(text, alert_id) + cost_note


def write_summary(rows: list[str], header: str) -> None:
    table = "\n".join(
        [f"## {header}", "", "| Alert | Outcome | Detail |", "|---|---|---|", *rows, ""]
    )
    print(table)
    path = os.environ.get("GITHUB_STEP_SUMMARY")
    if path:
        with open(path, "a", encoding="utf-8") as handle:
            handle.write(table + "\n")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--alert-id", default=None, help="run this one alert instead of the window")
    parser.add_argument("--dry-run", action="store_true", help="list and dedupe, run nothing")
    parser.add_argument("--limit", type=int, default=MAX_ALERTS)
    parser.add_argument("--lookback-hours", type=int, default=LOOKBACK_HOURS)
    args = parser.parse_args(argv)

    alert_id = args.alert_id.strip() or None if args.alert_id else None
    if alert_id and not ALERT_ID_RE.match(alert_id):
        print(f"::error::not an Orca alert id: {alert_id!r}", file=sys.stderr)
        return 2

    owner = os.environ.get("GITHUB_REPOSITORY_OWNER", "").strip()
    if not owner:
        print("::error::GITHUB_REPOSITORY_OWNER is not set", file=sys.stderr)
        return 2
    repo_root = os.path.dirname(os.path.abspath(__file__))

    now = dt.datetime.now(tz=dt.timezone.utc)
    since = None if alert_id else now - dt.timedelta(hours=args.lookback_hours)
    try:
        records = fetch_alerts(alert_id, since)
    except orca_codefix.OrcaError as exc:
        # No candidates is not a failure of the run, but not being able to ask is.
        print(f"::error::Orca query failed: {exc}", file=sys.stderr)
        return 1
    if len(records) >= QUERY_LIMIT:
        print(f"::warning::Orca returned a full page of {QUERY_LIMIT} alerts; some may be missed", file=sys.stderr)

    chosen = select_alerts(
        records, now, lookback_hours=args.lookback_hours, limit=args.limit, alert_id=alert_id
    )
    header = (
        f"Orca SCA autofix: {alert_id}" if alert_id
        else f"Orca SCA autofix: {len(chosen)} of {len(records)} alerts in the last {args.lookback_hours}h"
    )
    if alert_id and not chosen:
        write_summary([outcome_row(alert_id, "skipped", "not an open SCA alert on a CodeRepository")], header)
        return 0
    if not chosen:
        write_summary([outcome_row("(none)", "nothing to do", "")], header)
        return 0

    rows = []
    for found in chosen:
        print(f"::group::{found}")
        outcome, detail = process(found, owner, repo_root, args.dry_run)
        print(f"{found}: {outcome}: {detail}")
        print("::endgroup::")
        rows.append(outcome_row(found, outcome, detail))
    write_summary(rows, header)
    return 0


if __name__ == "__main__":
    sys.exit(main())
