# Orca AI code fix webhook

A Cloud Function that receives Orca Security alerts, generates the AI code fix,
and opens a pull request — the flow Orca's Code Security UI performs, running
unattended. One Orca API token does all of it; no GitHub credential is needed,
because Orca opens the pull request through its own GitHub App.

## Deploy

```bash
gcloud config set project YOUR_PROJECT
./deploy.sh
```

That's the whole install, and it's idempotent — re-run it to update. It enables
the required APIs, stores your Orca token and a generated webhook secret in
Secret Manager, creates a service account that can read only those two secrets,
deploys the function, and prints the trigger URL and webhook secret. It prompts
for the Orca token if `ORCA_API_TOKEN` isn't already in your environment.

Create that token with the **AI Code Fix (Custom)** role.

The deploying account needs to enable APIs, create secrets, create a service
account, and set IAM bindings — Editor plus Secret Manager Admin, or Owner.

Then in Orca — **Settings → Connections → Integrations → Webhook → Create**:

| Field | Value |
|---|---|
| Trigger URL | the URL `deploy.sh` printed |
| Header | `X-Orca-Webhook-Token` = the webhook secret |
| Body | tick **All alert fields in JSON** |

Leave **API Key** empty; the custom header carries the secret. Then add an
automation rule and send its alerts to the webhook — scope it in Orca, since
every alert reaching the function costs an AI metering unit.

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

`ORCA_API_TOKEN` and `WEBHOOK_SECRET` come from Secret Manager. To rotate, add a
version and redeploy — the function resolves `:latest` at deploy time:

```bash
printf '%s' "NEW_TOKEN" | gcloud secrets versions add orca-api-token --data-file=-
gcloud secrets versions access latest --secret=orca-webhook-secret   # read it back
```

## What it can fix

Routing is decided by the alert's asset type, so no list of alert categories is
involved:

| Alert | Result |
|---|---|
| SAST or IaC finding in a scanned repository | fix + PR |
| CSPM misconfiguration **with** IaC code origin | fix + PR |
| CSPM misconfiguration **without** code origin | `skipped_no_code_origin` — no code to patch |
| Orca returns no code fix | `skipped_no_code_fix` — action steps only |

Verified against `AwsS3Bucket`, `AwsEc2Elbv2`, `AwsRdsDbInstance`,
`AwsEc2VpcEndpoint`, `AzureStorageAccount` and `CodeRepository` assets.

**A CSPM fix patches the IaC, not the live resource.** The pull request corrects
the source of the drift; the resource stays misconfigured until someone applies
the change, and the alert will not close on merge.

**Duplicate deliveries** are suppressed per instance, so a repeat landing on a
cold start, after a redeploy, or on a second instance can still open a second
pull request. Treat it as a safety net, not a guarantee.

## Operating

One alert takes 15–40s: Orca's fix generation is synchronous and has no polling
API, hence the 300s function timeout. Output is non-deterministic — the same
alert produces different prose each run, and each run costs a metering unit.

Logs are one JSON object per line:

```bash
gcloud logging read 'jsonPayload.status="pr_opened"' --limit=20 \
  --format='value(jsonPayload.alert_id, jsonPayload.pull_request_url)'
```

Responses: `200` processed, ignored or permanently failed; `400` unparseable
body or no alert id; `401` bad secret; `503` all failures transient.

The endpoint is IAM-unauthenticated because Orca can only send headers, not a
signed GCP token. `WEBHOOK_SECRET` is therefore the real gate — compared in
constant time, and failing closed, so an unset secret rejects everything.
`ALLOW_UNAUTHENTICATED=true` disables that check and is for local testing only.

## Troubleshooting a 403

The token needs **two separately granted permissions**, so one that generates
fixes may still fail to open the pull request. The response shape says which:

| Response | Cause |
|---|---|
| `{"detail": "Insufficient permissions"}` | ai-core remediation skill not granted |
| `{"error_code": "permission_denied"}` | shiftleft write not granted |
| `{"error_code": "1012"}` | token is fine; Orca's GitHub App lacks `Contents write` on that repository |

These are internal Orca app endpoints, not documented public API, so they can
change without notice.
