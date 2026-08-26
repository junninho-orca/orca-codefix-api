#!/usr/bin/env bash
#
# Deploy the Orca codefix webhook to Cloud Functions v2, from scratch, idempotently.
#
#   ./deploy.sh
#
# Everything is overridable by environment variable; the defaults are fine for a
# first deploy. Re-running is safe — APIs, secrets, and IAM bindings are only
# created when missing, and the function is updated in place.
#
#   PROJECT_ID       defaults to the active gcloud project
#   REGION           default us-central1
#   FUNCTION_NAME    default orca-codefix-webhook
#   CREATE_PR        default true   — set false to generate fixes without opening PRs
#   ORCA_API_TOKEN   read from the environment or .env, else prompted for
#   WEBHOOK_SECRET   read from the environment or .env, else generated
#
set -euo pipefail

PROJECT_ID="${PROJECT_ID:-$(gcloud config get-value project 2>/dev/null)}"
REGION="${REGION:-us-central1}"
FUNCTION_NAME="${FUNCTION_NAME:-orca-codefix-webhook}"
RUNTIME="${RUNTIME:-python312}"
SERVICE_ACCOUNT_ID="${SERVICE_ACCOUNT_ID:-orca-codefix-fn}"
TOKEN_SECRET="${TOKEN_SECRET:-orca-api-token}"
WEBHOOK_SECRET_NAME="${WEBHOOK_SECRET_NAME:-orca-webhook-secret}"
CREATE_PR="${CREATE_PR:-true}"
ALERT_TYPE_ALLOWLIST="${ALERT_TYPE_ALLOWLIST:-}"
TIMEOUT="${TIMEOUT:-300s}"
MEMORY="${MEMORY:-512Mi}"
MAX_INSTANCES="${MAX_INSTANCES:-3}"

if [[ -z "$PROJECT_ID" ]]; then
  echo "No GCP project set. Run: gcloud config set project YOUR_PROJECT" >&2
  exit 1
fi

# Pick up credentials from a local .env the same way the CLI does.
if [[ -f .env ]]; then
  set -a; . ./.env; set +a
fi

SERVICE_ACCOUNT="${SERVICE_ACCOUNT_ID}@${PROJECT_ID}.iam.gserviceaccount.com"

say() { printf '\n\033[1m==> %s\033[0m\n' "$*"; }

say "Project ${PROJECT_ID}, region ${REGION}, function ${FUNCTION_NAME}"

say "Enabling required APIs"
gcloud services enable \
  cloudfunctions.googleapis.com \
  run.googleapis.com \
  cloudbuild.googleapis.com \
  artifactregistry.googleapis.com \
  secretmanager.googleapis.com \
  eventarc.googleapis.com \
  --project "$PROJECT_ID"

# --- credentials -------------------------------------------------------------

# create_secret NAME VALUE — creates the secret, or adds a version if it exists.
create_secret() {
  local name="$1" value="$2"
  if gcloud secrets describe "$name" --project "$PROJECT_ID" >/dev/null 2>&1; then
    echo "  secret ${name} already exists, leaving its current version in place"
  else
    printf '%s' "$value" | gcloud secrets create "$name" \
      --data-file=- --replication-policy=automatic --project "$PROJECT_ID"
    echo "  created secret ${name}"
  fi
}

say "Storing credentials in Secret Manager"

if ! gcloud secrets describe "$TOKEN_SECRET" --project "$PROJECT_ID" >/dev/null 2>&1; then
  if [[ -z "${ORCA_API_TOKEN:-}" ]]; then
    # -s so the token never lands in the terminal scrollback or shell history.
    read -rsp "  Orca API token (needs ai-core remediation + shiftleft write): " ORCA_API_TOKEN
    echo
  fi
  if [[ -z "${ORCA_API_TOKEN:-}" ]]; then
    echo "An Orca API token is required." >&2
    exit 1
  fi
fi
create_secret "$TOKEN_SECRET" "${ORCA_API_TOKEN:-}"

GENERATED_SECRET=""
if ! gcloud secrets describe "$WEBHOOK_SECRET_NAME" --project "$PROJECT_ID" >/dev/null 2>&1; then
  if [[ -z "${WEBHOOK_SECRET:-}" ]]; then
    WEBHOOK_SECRET="$(openssl rand -hex 32)"
    GENERATED_SECRET="$WEBHOOK_SECRET"
  fi
fi
create_secret "$WEBHOOK_SECRET_NAME" "${WEBHOOK_SECRET:-}"

# --- identity ----------------------------------------------------------------

say "Setting up the function's service account"
if ! gcloud iam service-accounts describe "$SERVICE_ACCOUNT" --project "$PROJECT_ID" >/dev/null 2>&1; then
  gcloud iam service-accounts create "$SERVICE_ACCOUNT_ID" \
    --display-name "Orca codefix webhook function" --project "$PROJECT_ID"
fi

# The only privilege the function needs: read its two secrets. Bound per-secret
# rather than project-wide so it cannot read anything else in the project.
for secret in "$TOKEN_SECRET" "$WEBHOOK_SECRET_NAME"; do
  gcloud secrets add-iam-policy-binding "$secret" \
    --member "serviceAccount:${SERVICE_ACCOUNT}" \
    --role roles/secretmanager.secretAccessor \
    --project "$PROJECT_ID" --condition=None >/dev/null
done
echo "  ${SERVICE_ACCOUNT} can read ${TOKEN_SECRET} and ${WEBHOOK_SECRET_NAME}"

# --- deploy ------------------------------------------------------------------

# Orca's webhook can only send custom headers, not a signed GCP identity token,
# so the endpoint must accept unauthenticated requests at the IAM layer. The
# WEBHOOK_SECRET check inside the function is what actually guards it, and the
# function fails closed if that secret is missing.
say "Deploying the function"
gcloud functions deploy "$FUNCTION_NAME" \
  --gen2 \
  --runtime "$RUNTIME" \
  --region "$REGION" \
  --source . \
  --entry-point orca_webhook \
  --trigger-http \
  --allow-unauthenticated \
  --service-account "$SERVICE_ACCOUNT" \
  --timeout "$TIMEOUT" \
  --memory "$MEMORY" \
  --max-instances "$MAX_INSTANCES" \
  --set-env-vars "CREATE_PR=${CREATE_PR},ALERT_TYPE_ALLOWLIST=${ALERT_TYPE_ALLOWLIST}" \
  --set-secrets "ORCA_API_TOKEN=${TOKEN_SECRET}:latest,WEBHOOK_SECRET=${WEBHOOK_SECRET_NAME}:latest" \
  --project "$PROJECT_ID"

URL="$(gcloud functions describe "$FUNCTION_NAME" --region "$REGION" \
  --project "$PROJECT_ID" --format='value(serviceConfig.uri)')"

say "Deployed"
cat <<SUMMARY
  Trigger URL : ${URL}
  CREATE_PR   : ${CREATE_PR}$([[ "$CREATE_PR" == "true" ]] && echo "   (opens real pull requests)")

Configure Orca — Settings > Connections > Integrations > Webhook > Create:
  Trigger URL : ${URL}
  Header      : X-Orca-Webhook-Token = <the webhook secret>
  Body        : tick "All alert fields in JSON"

Then add an automation rule scoped to your SAST / code security alerts and send
them to this webhook.

Health check:
  curl ${URL}

Read the webhook secret back at any time:
  gcloud secrets versions access latest --secret=${WEBHOOK_SECRET_NAME} --project=${PROJECT_ID}

Logs:
  gcloud functions logs read ${FUNCTION_NAME} --region=${REGION} --project=${PROJECT_ID}
SUMMARY

if [[ -n "$GENERATED_SECRET" ]]; then
  printf '\n  Generated webhook secret (shown once, also in Secret Manager):\n    %s\n' \
    "$GENERATED_SECRET"
fi
