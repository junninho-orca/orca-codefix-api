# orca-codefix-api

Drive Orca Security's "AI code fix → open pull request" flow without the UI, either
as a one-off CLI run or as a Cloud Function that Orca calls on every matching alert.

Orca's Code Security UI can generate a fix for a SAST alert and open a PR with it.
That flow is three API calls, and this reproduces it headlessly with a single Orca
API token — no browser session, and no GitHub credential, because Orca opens the PR
through its own GitHub App.

Reverse-engineered from a HAR capture of the UI, then verified end to end against
the live API.

| | |
|---|---|
| `orca_codefix.py` | CLI, and the engine both entrypoints share. Standard library only. |
| `main.py` | Cloud Functions v2 entrypoint: Orca webhook → fix → pull request. |
| `webhook.py` | Parses and authenticates the incoming Orca webhook. |
| `deploy.sh` | One-command deploy: APIs, Secret Manager, service account, function. |

## Deploy the webhook

```bash
gcloud config set project YOUR_PROJECT
./deploy.sh
```

`deploy.sh` is idempotent — re-run it to update the function. It enables the
required APIs, stores your Orca token and a generated webhook secret in Secret
Manager, creates a least-privilege service account that can read only those two
secrets, deploys the function, and prints the trigger URL plus the exact Orca
settings to paste. Defaults are overridable by environment variable:

```bash
REGION=europe-west1 CREATE_PR=false ALERT_TYPE_ALLOWLIST=sast ./deploy.sh
```

Then, in Orca — **Settings → Connections → Integrations → Webhook → Create**:

| Field | Value |
|---|---|
| Trigger URL | the URL `deploy.sh` printed |
| Header | `X-Orca-Webhook-Token` = the webhook secret |
| Body | tick **All alert fields in JSON** |

Finally add an automation rule scoped to your SAST / code security alerts and send
them to that webhook. Scope it narrowly — every alert that reaches the function
spends an AI metering unit.

Verify the deployment answers at all:

```bash
curl https://YOUR-FUNCTION-URL
```

That's a health check reporting whether `CREATE_PR` is on and auth is required. To
replay a real alert through it without waiting for Orca:

```bash
curl -X POST https://YOUR-FUNCTION-URL \
  -H 'Content-Type: application/json' \
  -H "X-Orca-Webhook-Token: $WEBHOOK_SECRET" \
  -d '{"version":"1.0","data":{"alert_id":"orca-1596292"}}'
```

## Use the CLI

```bash
cp .env.example .env      # then fill in ORCA_API_TOKEN

# generate a fix and print it, without touching the repo
./orca_codefix.py orca-1596292

# generate and open the pull request
./orca_codefix.py orca-1596292 --create-pr
```

Python 3.9+, standard library only. Credentials come from a `.env` beside the
script; real environment variables take precedence, so
`ORCA_API_TOKEN=... ./orca_codefix.py ...` overrides the file for one run.
`--repo-context-id` skips the step 1 lookup, saving a round trip.

## Configuration

Set on the function via `deploy.sh`, or in `.env` for local runs. Full annotated
list in [.env.example](.env.example).

| Variable | Default | Purpose |
|---|---|---|
| `ORCA_API_TOKEN` | — | required; needs both permissions below |
| `WEBHOOK_SECRET` | — | required; shared secret Orca must present |
| `CREATE_PR` | `false` | `false` generates the fix without writing to the repo |
| `ALERT_TYPE_ALLOWLIST` | *(empty)* | substring filter on alert type/category |
| `WEBHOOK_SECRET_HEADER` | `X-Orca-Webhook-Token` | header carrying the secret |
| `MAX_ALERTS_PER_REQUEST` | `10` | bound on work from one request |
| `DEDUPE_WINDOW` | `512` | alert ids remembered per instance; `0` disables |

## Testing

```bash
python3 test_webhook.py                       # parsing and auth, stdlib only

python3 -m pip install -r requirements.txt
python3 test_integration.py                   # whole function vs a fake Orca API
```

`test_integration.py` runs the real handler against a local stand-in for
`api.orcasecurity.io`, so it spends no AI metering units and opens no pull
requests. It covers the payload shapes, auth, the base64 remap, retry dedupe, the
false-positive and no-code-fix paths, and the retryable-vs-permanent error split.

To run the function locally against the **real** Orca API:

```bash
./run_local.sh    # :8080, CREATE_PR=false unless you set it
```

Sample payloads in [samples/](samples/) cover the wrapper, legacy, minimal, and
batch shapes.

## How it works

| # | Call | Purpose |
|---|---|---|
| 1 | `POST /api/serving-layer/query` | alert id → `repository_context_id` |
| 2 | `POST /api/ai-core/skills/code_remediation/sast` | generate the fix |
| 3 | `POST /api/shiftleft/repository_contexts/{id}/pull_requests/` | open the PR |

**Step 1.** `repository_context_id` isn't a special identifier — it's the alert's
CodeRepository asset `Id`, at `data[0].data.Inventory.data.Id.value`. This step
also acts as the filter for non-code alerts: they fail here, before step 2, so
they cost nothing.

**Step 2.** Synchronous, no polling, 13–24s. Returns the whole result in one shot:
`fixed_code`, `original_code`, `pr_title`, `pr_description`, `file_path`,
`considerations`, plus `is_false_positive` and `remediation_type` gates. It re-runs
the model per call, so output is **non-deterministic** and each call costs an AI
metering unit — two runs on the same alert produce different prose.

**Step 3.** The body is a pure remap of step 2's response, with exactly one
transform:

```
title          <- pr_title
description    <- pr_description
file_path      <- file_path
alert_url      <- https://app.orcasecurity.io/alerts/{alert_id}
fixed_content  <- base64(fixed_code)
```

No client-side diffing, branch naming, or commit logic — Orca's backend does all of
it. Returns `201 {"url": "https://github.com/…/pull/N"}`.

## Webhook behaviour

**Payload shapes.** Orca sends either `{"version": "1.0", "data": {…}}` or the
legacy flat format with the id at `state.alert_id`, and the body template is
editable, so the parser walks the known paths rather than pinning one. Batches
(a list, or a list under `data` / `alerts`) fan out. Alert ids are validated
against `orca-[A-Za-z0-9]+` before reaching any API call.

**Latency.** Processing is synchronous because Orca's fix generation is — step 2
has no polling API. One alert takes roughly 15–40s, which is why the function is
deployed with a 300s timeout.

**Retries.** Orca retries a webhook it considers failed, and each replay would
otherwise spend another metering unit and open another PR. Each instance remembers
the last `DEDUPE_WINDOW` alert ids and short-circuits repeats. This is
per-instance, so it catches the common case — a retry landing on the instance that
just ran — not every possible duplicate. The function also returns `503` (asking
Orca to retry) only when every failure in the request was transient; permanent
outcomes return `200` so they don't loop.

**Response codes.**

| Code | Meaning |
|---|---|
| `200` | processed, ignored by the type filter, or failed permanently |
| `400` | body isn't JSON, or carries no recognisable alert id |
| `401` | missing or wrong shared secret |
| `405` | not `GET` or `POST` |
| `503` | every alert failed transiently — Orca should retry |

## Security model

The endpoint is deployed `--allow-unauthenticated` at the IAM layer because Orca's
webhook can only send custom headers, not a signed GCP identity token. The
`WEBHOOK_SECRET` check inside the function is therefore the real gate, compared in
constant time, and the function **fails closed**: with no secret configured it
rejects every request rather than accepting all of them. `ALLOW_UNAUTHENTICATED=true`
disables that check and exists only for local testing — never set it on a deployed
function.

The function's service account is granted exactly one privilege: reading its two
secrets. It has no other access to the project.

## Token permissions

Steps 2 and 3 need **two separately-granted permissions**, not one write bit. A
token can carry either without the other, so a token that generates fixes fine may
still fail to open the PR.

The 403 shape tells you which grant is missing:

| Response | Meaning | Fix |
|---|---|---|
| `{"detail": "Insufficient permissions"}` | ai-core remediation skill not granted | grant it (blocks step 2) |
| `{"error_code": "permission_denied"}` | shiftleft write not granted | grant it (blocks step 3) |
| `{"error_code": "1012"}` | token is fine; Orca's **GitHub App** lacks `Contents write` on that repo | grant the App access to the repo |

That last one is per-repo and unrelated to the token — it fires even for a
fully-authorized browser session.

These are internal app endpoints, not documented public API, so they can change
without notice.

## TLS-intercepting proxies

Affects local CLI runs, not the deployed function. On a corporate network that
terminates TLS, Python's bundled CA store won't have the proxy root and every call
fails with `CERTIFICATE_VERIFY_FAILED` (while `curl` works, since it uses the macOS
keychain). Point Python at the system roots:

```bash
security find-certificate -a -p /System/Library/Keychains/SystemRootCertificates.keychain >  ca.pem
security find-certificate -a -p /Library/Keychains/System.keychain                        >> ca.pem
export SSL_CERT_FILE="$PWD/ca.pem"
```

## Note

`CREATE_PR=true` and the CLI's `--create-pr` open real pull requests in the target
repository. Both default to off; those are the only things that write.
