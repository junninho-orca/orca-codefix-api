#!/usr/bin/env bash
#
# Run the function locally on :8080 for testing, then in another shell:
#
#   curl localhost:8080                                     # health check
#   curl -X POST localhost:8080 \
#        -H 'Content-Type: application/json' \
#        -H "X-Orca-Webhook-Token: $WEBHOOK_SECRET" \
#        -d @samples/wrapper.json
#
# Credentials come from .env. CREATE_PR stays false unless you set it, so a local
# run generates a fix and prints it without writing to any repository.
#
set -euo pipefail

if [[ -f .env ]]; then
  set -a; . ./.env; set +a
fi

export CREATE_PR="${CREATE_PR:-false}"
export WEBHOOK_SECRET="${WEBHOOK_SECRET:-local-dev-secret}"
export LOG_LEVEL="${LOG_LEVEL:-DEBUG}"

python3 -m pip install --quiet --disable-pip-version-check -r requirements.txt

echo "CREATE_PR=${CREATE_PR}  WEBHOOK_SECRET=${WEBHOOK_SECRET}"
exec python3 -m functions_framework --target orca_webhook --debug --port "${PORT:-8080}"
