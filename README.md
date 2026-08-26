# orca-codefix-api

Drive Orca Security's "AI code fix → open pull request" flow from a script instead
of the web UI.

Orca's Code Security UI can generate a fix for a SAST alert and open a PR with it.
That flow is three API calls, and this reproduces it headlessly with a single Orca
API token — no browser session, and no GitHub credential, because Orca opens the PR
through its own GitHub App server-side.

Reverse-engineered from a HAR capture of the UI, then verified end to end against
the live API.

## Usage

```bash
export ORCA_AUTH="Token $ORCA_API_TOKEN"

# generate a fix and print it, without touching the repo
./orca_codefix.py orca-1596292

# generate and open the pull request
./orca_codefix.py orca-1596292 --create-pr
```

Python 3.9+, standard library only.

`--repo-context-id` skips the step 1 lookup if you already know the repository
context, saving a round trip.

## How it works

| # | Call | Purpose |
|---|---|---|
| 1 | `POST /api/serving-layer/query` | alert id → `repository_context_id` |
| 2 | `POST /api/ai-core/skills/code_remediation/sast` | generate the fix |
| 3 | `POST /api/shiftleft/repository_contexts/{id}/pull_requests/` | open the PR |

**Step 1.** `repository_context_id` isn't a special identifier — it's the alert's
CodeRepository asset `Id`, at `data[0].data.Inventory.data.Id.value`.

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

On a corporate network that terminates TLS, Python's bundled CA store won't have
the proxy root and every call fails with `CERTIFICATE_VERIFY_FAILED` (while `curl`
works, since it uses the macOS keychain). Point Python at the system roots:

```bash
security find-certificate -a -p /System/Library/Keychains/SystemRootCertificates.keychain >  ca.pem
security find-certificate -a -p /Library/Keychains/System.keychain                        >> ca.pem
export SSL_CERT_FILE="$PWD/ca.pem"
```

## Note

`--create-pr` opens a real pull request in the target repository. The script is
dry-run by default; the flag is the only thing that writes.
