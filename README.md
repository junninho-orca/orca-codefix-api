# Orca AI code fix webhook

A Cloud Function that receives Orca Security alerts, generates the AI code fix,
and opens a pull request — the flow Orca's Code Security UI performs, running
unattended.

One Orca API token does all of it. No GitHub credential is involved, because Orca
opens the pull request through its own GitHub App.

## Deploy

```bash
gcloud config set project YOUR_PROJECT
./deploy.sh
```

That's the whole install. The script enables the required APIs, stores your Orca
token and a generated webhook secret in Secret Manager, creates a service account
whose only privilege is reading those two secrets, deploys the function, and
prints the trigger URL plus the webhook secret. It prompts for the Orca token if
`ORCA_API_TOKEN` isn't already in your environment.

Re-run it any time to update the function; it's idempotent.

Then in Orca — **Settings → Connections → Integrations → Webhook → Create**:

| Field | Value |
|---|---|
| Trigger URL | the URL `deploy.sh` printed |
| Header | `X-Orca-Webhook-Token` = the webhook secret |
| Body | tick **All alert fields in JSON** |

Leave **API Key** empty — the custom header carries the secret.

Finally add an automation rule and send its alerts to the webhook. Scope it in
Orca: every alert that reaches the function costs an AI metering unit, and the
rule is what controls volume.

Check it answers:

```bash
curl https://YOUR-FUNCTION-URL
```

## Configuration

Everything lives on the function, so it can be changed without redeploying and
without touching code:

```bash
gcloud functions deploy orca-codefix-webhook --region=us-central1 \
  --update-env-vars CREATE_PR=false
```

| Variable | Default | Purpose |
|---|---|---|
| `CREATE_PR` | `true` | `false` generates the fix and reports it without writing to the repository |
| `ALERT_TYPE_ALLOWLIST` | *(empty)* | temporary narrowing, e.g. `sast`; see below |
| `WEBHOOK_SECRET_HEADER` | `X-Orca-Webhook-Token` | header carrying the shared secret |
| `MAX_ALERTS_PER_REQUEST` | `10` | bound on work from a single request |
| `DEDUPE_WINDOW` | `512` | recent alert ids remembered per instance; `0` disables |
| `LOG_LEVEL` | `INFO` | |

`ORCA_API_TOKEN` and `WEBHOOK_SECRET` are injected from Secret Manager. To rotate
either, add a new secret version — the function picks up `latest` on next deploy:

```bash
printf '%s' "NEW_TOKEN" | gcloud secrets versions add orca-api-token --data-file=-
```

Read the webhook secret back at any time:

```bash
gcloud secrets versions access latest --secret=orca-webhook-secret
```

### Why there is no category filter

`ALERT_TYPE_ALLOWLIST` is off by default and best left off. The function already
filters structurally: an alert is processed only if it resolves to code, decided
before anything billable happens. That needs no list of alert categories — CSPM
alone has hundreds, so a name-based list would miss new ones and silently drop
valid ones. Scope alerts in the Orca automation rule instead.

When the allowlist does drop an alert, it's logged at WARNING with the fields it
actually matched against, so a field-name mismatch can't look like normal
operation.

## What it can fix

| Alert | Supported | How |
|---|---|---|
| SAST finding in scanned source | yes | `sast` skill |
| IaC finding in a scanned repository | yes | `sast` skill |
| CSPM misconfiguration **with** IaC code origin | yes | `c2d` skill |
| CSPM misconfiguration **without** code origin | no — `skipped_no_code_origin` | there is no code to patch |
| Anything Orca returns no `code_fix` for | no — `skipped_no_code_fix` | action steps only |

Verified against `AwsS3Bucket`, `AwsEc2Elbv2`, `AwsRdsDbInstance`,
`AwsEc2VpcEndpoint`, `AzureStorageAccount` and `CodeRepository` assets. Routing is
driven by asset type, so a cloud resource type not listed here needs no change.

**A CSPM fix patches the IaC, not the live resource.** The pull request corrects
the source of the drift; the resource stays misconfigured until someone applies
the change, and the alert will not close on merge.

## How it works

| # | Call | Purpose |
|---|---|---|
| 1 | `POST /api/serving-layer/query` | alert → repository, and which skill applies |
| 1b | `POST /api/serving-layer/query` | for a cloud asset: → the repository whose IaC deployed it |
| 2 | `POST /api/ai-core/skills/code_remediation/{sast\|c2d}` | generate the fix |
| 3 | `POST /api/shiftleft/repository_contexts/{id}/pull_requests/` | open the PR |

**Step 1** routes on the alert's asset type. A `CodeRepository` asset *is* the
repository, and carries the context id as `Inventory.data.Id.value` → `sast`. A
cloud resource has no such field; its repository comes from the `CodeOrigin`
objects whose `Inventories` include that asset → `c2d`. An alert that resolves to
neither has no code origin and is skipped here, before step 2, so it costs
nothing.

**Step 2** is synchronous, 13–24s, with no polling API — which is why the function
has a 300s timeout and one alert takes roughly 15–40s end to end. It re-runs the
model per call, so output is **non-deterministic** and each call costs an AI
metering unit. Both skills take the same request and return the same shape.

**Step 3** is a pure remap of step 2's response:

```
title          <- pr_title
description    <- pr_description
file_path      <- file_path
alert_url      <- https://app.orcasecurity.io/alerts/{alert_id}
fixed_content  <- base64(fixed_code)
```

Orca's backend does the branching, diffing and commit. Returns
`201 {"url": "https://github.com/…/pull/N"}`.

These are internal app endpoints, not documented public API, so they can change
without notice.

## Behaviour

**Payload shapes.** Orca sends either `{"version": "1.0", "data": {…}}` with
serving-layer fields wrapped as `{"value": …}`, or a legacy flat format with the
id at `state.alert_id` — and the body template is editable. The parser walks the
known paths in either shape, fans out batches, and validates every alert id
against `orca-[A-Za-z0-9]+` before it reaches an API call.

**Duplicate deliveries.** Generating a fix is billable and opens a pull request,
so the same alert arriving twice must not run twice. Each instance remembers the
last `DEDUPE_WINDOW` alert ids and short-circuits repeats.

This guard is per-instance and therefore partial: it catches a duplicate landing
on the instance that just ran, and misses one arriving after a cold start or a
redeploy, or on a second instance. Whether Orca re-delivers a webhook, and under
what conditions, is not documented and was not verified — treat this as a safety
net, not a guarantee. The durable version would ask Orca whether the alert already
has a pull request before opening one.

**Response codes.**

| Code | Meaning |
|---|---|
| `200` | processed, ignored by the type filter, or failed permanently |
| `400` | body isn't JSON, or carries no recognisable alert id |
| `401` | missing or wrong shared secret |
| `405` | not `GET` or `POST` |
| `503` | every alert failed transiently — re-delivery worth attempting |

Logs are one JSON object per line, so `alert_id`, `status` and
`pull_request_url` are queryable:

```bash
gcloud logging read 'jsonPayload.status="pr_opened"' --limit=20 \
  --format='value(jsonPayload.alert_id, jsonPayload.pull_request_url)'
```

## Security

The endpoint is deployed `--allow-unauthenticated` at the IAM layer because Orca's
webhook can only send custom headers, not a signed GCP identity token. The
`WEBHOOK_SECRET` check inside the function is therefore the real gate: compared in
constant time, and **failing closed** — with no secret configured it rejects every
request rather than accepting all of them.

`ALLOW_UNAUTHENTICATED=true` disables that check and exists only for local
testing. Never set it on a deployed function.

The function's service account can read its two secrets and nothing else. Calls to
Orca are refused unless the resolved URL is HTTPS.

## Token permissions

The token needs **two separately granted permissions**, not one write bit, so a
token that generates fixes may still fail to open the pull request. The 403 shape
says which:

| Response | Meaning | Fix |
|---|---|---|
| `{"detail": "Insufficient permissions"}` | ai-core remediation skill not granted | grant it (blocks step 2) |
| `{"error_code": "permission_denied"}` | shiftleft write not granted | grant it (blocks step 3) |
| `{"error_code": "1012"}` | token is fine; Orca's **GitHub App** lacks `Contents write` on that repository | grant the App access to that repository |

## Tests

```bash
python3 test_webhook.py                    # payload parsing and auth, stdlib only

python3 -m pip install -r requirements.txt
python3 test_integration.py                # the function against a fake Orca API
```

94 tests. Nothing touches the real Orca API, spends a metering unit, or opens a
pull request — a local server stands in for `api.orcasecurity.io`. Coverage
includes both routing paths, the payload shapes, auth, the base64 remap, duplicate
suppression, the skip paths, retryable-vs-permanent error handling, and URL
safety. Sample payloads are in [samples/](samples/).

## Note

`CREATE_PR=true` opens real pull requests. It is the deployed default, so the
scope of the Orca automation rule governs both spend and pull request volume.
