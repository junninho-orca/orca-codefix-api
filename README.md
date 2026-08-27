# Orca AI code fix webhook

A Cloud Function that receives Orca Security alerts, generates the AI code fix,
and opens a pull request — the flow Orca's Code Security UI performs, running
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

In Orca — **Settings → Users & Permissions → API → Create API Token**:

| Field | Value |
|---|---|
| Name | anything, e.g. `codefix-webhook` |
| Service Token | tick — not tied to a person who may later be deprovisioned |
| Role | **AI Code Fix (Custom)** |
| Scope | optionally limit to specific Shift Left Projects |

Copy the token value before closing the window — Orca shows it once and it can't
be retrieved afterwards. That value is what `deploy.sh` asks for.

Then in Orca — **Settings → Connections → Integrations → Webhook → Create**:

| Field | Value |
|---|---|
| Trigger URL | the URL `deploy.sh` printed |
| Header | `X-Orca-Webhook-Token` = the webhook secret |
| Body | tick **All alert fields in JSON** |

Leave **API Key** empty. Then add an automation rule and send its alerts to the
webhook — scope it narrowly, since every alert costs an AI metering unit.

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

Rotate the Orca token — create a new one as above, then add it as a version and
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
