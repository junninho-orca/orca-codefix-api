# Orca AI code fix webhook

A Cloud Function that receives Orca Security alerts, generates the AI code fix,
and opens a pull request, the flow Orca's Code Security UI performs, running
unattended. Needs one Orca API token; no GitHub credential.

## Deploy

```bash
gcloud config set project YOUR_PROJECT
./deploy.sh
```

Re-run it any time to update. It enables the required APIs, stores the
credentials in Secret Manager, creates the service account, deploys the function,
and prints the trigger URL and webhook secret. It prompts for the Orca token if
`ORCA_API_TOKEN` isn't already in your environment.

The Google Cloud account running `deploy.sh` needs the GCP IAM roles
`roles/editor` and `roles/secretmanager.admin`, or `roles/owner`. This is
separate from the Orca role below.

### Create the Orca API token

In Orca, under **Settings → Users & Permissions → API → Create API Token**:

| Field | Value |
|---|---|
| Name | anything, e.g. `codefix-webhook` |
| Service Token | tick; not tied to a person who may later be deprovisioned |
| Role | **AI Code Fix (Custom)** |

Copy the token value before closing the window: Orca shows it once and it can't
be retrieved afterwards. That value is what `deploy.sh` asks for.

Then in Orca, under **Settings → Connections → Integrations → Webhook → Create**:

| Field | Value |
|---|---|
| Trigger URL | the URL `deploy.sh` printed |
| Header | `X-Orca-Webhook-Token` = the webhook secret |
| Body | tick **All alert fields in JSON** |

Leave **API Key** empty. Then add an automation rule and send its alerts to the
webhook. Scope it narrowly, since every alert costs an AI metering unit.

Confirm it's live with `curl https://YOUR-FUNCTION-URL`.

## Configuration

Set on the function, so it changes without a redeploy:

```bash
gcloud functions deploy orca-codefix-webhook --region=us-central1 \
  --update-env-vars CREATE_PR=false
```

| Variable | Default | Purpose |
|---|---|---|
| `CREATE_PR` | `true` | `false` generates the fix without writing to the repository |
| `ALERT_TYPE_ALLOWLIST` | *(empty)* | substring filter on alert type/category; leave empty and scope in Orca instead |
| `WEBHOOK_SECRET_HEADER` | `X-Orca-Webhook-Token` | header carrying the shared secret |
| `MAX_ALERTS_PER_REQUEST` | `10` | bound on work from one request |
| `DEDUPE_WINDOW` | `512` | recent alert ids remembered per instance; `0` disables |
| `LOG_LEVEL` | `INFO` | |

`ORCA_API_TOKEN` and `WEBHOOK_SECRET` come from Secret Manager.

Read the webhook secret back:

```bash
gcloud secrets versions access latest --secret=orca-webhook-secret
```

To rotate the Orca token, create a new one as above, then add it as a version and
redeploy, since the function resolves `:latest` at deploy time:

```bash
printf '%s' "NEW_TOKEN" | gcloud secrets versions add orca-api-token --data-file=-
./deploy.sh
```

## What it can fix

| Alert | Result |
|---|---|
| SAST or IaC finding in a scanned repository | fix + PR |
| CSPM misconfiguration **with** IaC code origin | fix + PR |
| CSPM misconfiguration **without** code origin | skipped, nothing to patch |
| Orca returns no code fix | skipped, action steps only |

**A CSPM fix patches the IaC, not the live resource.** The pull request corrects
the source of the drift; the resource stays misconfigured until someone applies
the change, and the alert will not close on merge.

One alert takes 15-40s, and each run costs an AI metering unit. Orca sends one
alert per request and waits for the response, so alerts are handled serially.

## SCA autofix (Claude)

The AI code fix API does not fix SCA findings, so vulnerable dependencies in a
scanned repository take a second path: a GitHub Actions workflow runs the
[orca-patch](.claude/skills/orca-patch/SKILL.md) Claude Code skill against each
new alert, and the skill clones the owning repository, bumps the package to the
smallest patched version in its track, and opens a pull request. The Cloud
Function is untouched; the two paths split on alert category.

| Alert | Path | Result |
|---|---|---|
| SAST, IaC, CSPM with code origin | Cloud Function | Orca AI code fix + PR |
| SCA vulnerability on a CodeRepository asset (source shiftleft) | this workflow | orca-patch diff + PR on branch `orca-patch/<alert-id>` |
| SCA alert whose only fix is a major version jump, or that has drifted at HEAD | this workflow | no PR; the skill's stop-condition report lands in the run summary |

**Pull requests are never merged automatically.** The skill never pushes to a
default branch, never force-pushes, and never merges; every PR waits for a human
review, and the alert closes on Orca's next scan after the merge.

### Secrets

Set these as Actions secrets on this repository:

| Secret | Purpose | How to create |
|---|---|---|
| `ANTHROPIC_API_KEY` | Claude Code, which runs the skill | [console.anthropic.com](https://console.anthropic.com/) |
| `ORCA_API_TOKEN` | lists alerts over the REST API and backs the Orca MCP server in `.mcp.json` | as above, with the built-in **Viewer** role or a custom role that can read alerts |
| `AUTOFIX_GH_PAT` | `git clone`, `git push` and `gh pr create` against any repository in the org | fine-grained PAT, resource owner = the org, all repositories, **Contents: read and write** and **Pull requests: read and write** |

The Cloud Function's Orca token is not reused here: that one carries write
permissions this workflow does not need. `.mcp.json` reads the token from the
`ORCA_API_TOKEN` environment variable, so nothing is hardcoded.

### Schedule and manual runs

The workflow runs every 2 hours and picks up open SCA alerts created in the last
26 hours, newest first, capped at 5 per run. Before running an alert it searches
the org for an open PR on `orca-patch/<alert-id>`, or an open PR whose body or
comments name the alert, and skips the alert when one exists, so a still-open
alert is not patched twice. Two alerts can share one fix surface (the same
Dockerfile deployed to prod and UAT); when the skill finds an open `orca-patch/*`
PR already touching the file, it comments the second alert id on that PR instead
of opening another. Alerts run serially, and one failing does not fail the run:
the job summary lists every alert with its outcome (PR URL, attached to an
existing PR, skipped, or the skill's report).

For one alert on demand, use **Actions -> Orca SCA autofix -> Run workflow** and
fill in `alert_id`; the 26 hour window does not apply, only the open-PR check.
Tick `dry_run` to see what a run would do without spending anything.

Locally, the same driver runs with the three variables exported:

```bash
GITHUB_REPOSITORY_OWNER=your-org python3 sca_autofix.py --dry-run
```

Each alert costs one Claude Code session, typically a few minutes and a few
dollars, plus 1 to 2 Orca MCP calls. `MAX_ALERTS` and `LOOKBACK_HOURS` at the top
of `sca_autofix.py` are the knobs.

### Tests

```bash
python3 test_sca_autofix.py
```

Standard library only; covers the alert listing and filtering. Nothing touches
Orca, GitHub or Claude.

## Logs

```bash
gcloud logging read 'jsonPayload.status="pr_opened"' --limit=20 \
  --format='value(jsonPayload.alert_id, jsonPayload.pull_request_url)'
```

Responses: `200` processed or skipped; `400` unparseable body or no alert id;
`401` bad secret; `503` transient failure.

## Troubleshooting a 403

The token needs two separately granted permissions, so one that generates fixes
may still fail to open the pull request. The response shape says which:

| Response | Cause |
|---|---|
| `{"detail": "Insufficient permissions"}` | ai-core remediation skill not granted |
| `{"error_code": "permission_denied"}` | shiftleft write not granted |
| `{"error_code": "1012"}` | token is fine; Orca's GitHub App lacks `Contents write` on that repository |
