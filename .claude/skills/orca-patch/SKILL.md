---
name: orca-patch
description: >-
  Patch cloud and SCA vulnerabilities found by Orca Security, producing a local
  diff the engineer reviews and commits. Use this skill whenever the user gives
  an Orca alert ID (orca-XXXXX) or an asset name and wants to fix, patch,
  remediate, resolve, or burn down a CVE, vulnerable package, or outdated base
  image, even if they just say "fix this alert", "patch this", "what do I do
  about orca-1234", or "clean up the vulns on my service". Vulnerability
  findings only, not misconfiguration, compliance, or IAM findings. Covers GCP
  Cloud Run, GKE containers, Cloud Functions, container images, code
  repositories (shiftleft/SCA), and images pinned in IaC. Can commit the fix to a new branch and open a pull request when
  the engineer approves. Requires the Orca Security MCP server and git access
  to clone the owning repository (an existing local checkout is used when
  present).
---

# Orca Patch

Turn an Orca Security alert (or an asset's alert backlog) into a minimal,
reviewable local diff that fixes the finding at its code origin: the
dependency manifest, Dockerfile, Terraform, or Helm values that produced the
vulnerable resource. You find the code origin through Orca, make the smallest
safe edit in the engineer's local checkout, verify it, and hand the diff to
the engineer. The engineer reviews it, and on request you commit it to a
branch and open a pull request for them to merge. Orca's next scan confirms
closure.

## Scope

Vulnerability findings only: `Category: Vulnerabilities`. That covers app
dependencies (SCA, including shiftleft findings on code repositories), OS
packages, unpatched systems, and outdated or neglected base images.

Misconfiguration, compliance, secrets, and IAM findings are out of scope.
When handed one, say so, surface the alert's own `Recommendation` and
`ui_url`, and stop. Do not edit Terraform, Helm, or cloud config to satisfy a
posture finding. Terraform and Helm are in scope only as the place a
vulnerable image or package version is pinned.

## Safety contract (read first, applies to every phase)

These rules exist because this skill touches production-adjacent code and a
security system of record. Breaking them destroys the trust that lets
engineers use the skill at all.

- The diff is the deliverable. You may commit it, push it to a new branch,
  and open a pull request, but only after the engineer has seen the diff and
  explicitly asked for that step (Phase 6). Never bundle the push into the
  same turn as the patch, and never merge the PR.
- Never push to the default branch and never force-push. Every push goes to a
  new branch created for this fix.
- Never run `gcloud`, `kubectl`, `terraform apply`, `helm upgrade`, or any
  command that mutates cloud state. A pull request is the only outward-facing
  action this skill takes.
- Orca stays read-only, with one exception: after the engineer confirms the
  fix is merged, you may (with their explicit go-ahead) add an alert comment
  linking the commit and set the alert status to `in_progress`. Never set
  `closed`, `dismissed`, or `snoozed`. Closure belongs to the next Orca scan.
- Never delete files.
- Smallest change that fixes the finding: smallest patched version in the
  installed major/minor track, same distro track for base images, one fix
  surface per diff, no edits outside the finding.
- Never reproduce masked snippet values, environment variable contents, or
  anything from a `SecretEnvVarsDetected` block into a diff, comment, commit
  message, PR title or body, or report. Treat those as sensitive context: mention
  that secret findings exist, never what they contain.
- When a fix requires a major version jump, an EOL base image migration, or a
  guess you could not confirm, stop and report instead of patching. A precise
  report of why no safe patch exists is a valid, useful outcome.

## Credit discipline

Orca MCP calls cost the customer credits. The data you need is almost always
in the first response.

- Never call `discovery_search`. Never call `get_alert_attack_path_data` or
  other attack path tools. They are expensive and add nothing to a patch.
- Skip `get_asset_by_alert_id`: the `get_alert` response already embeds the
  asset record under `Inventory` (UUID, type, state, exposure).
- Expected budget: 1 to 2 calls for most alerts, up to 6 for the deepest GKE
  fallback chain, plus 2 opt-in writeback calls. If you find yourself past
  8 calls on one alert, stop and reconsider the route.

## Workflow

### Phase 1: Resolve scope

**Alert mode** (user gives `orca-XXXXX`): call `get_alert(alert_id)`. One
call yields everything routing needs: `AlertType`, `RuleType`, `Category`,
`Labels`, `RiskFindings`, `AssetData` (asset type, image name, tags), and the
embedded `Inventory` (asset UUID, type, state).

**Asset mode** (user gives an asset name or ID): call `get_asset_by_name` or
`get_asset_by_id`, then `get_asset_related_alerts_summary(asset_uuid)`.
Filter to `Category: Vulnerabilities` with
the `fix_available` label, sort by OrcaScore, then group by what the eventual
fix surface will be, so one diff can retire several alerts. Present the
grouped list and let the engineer pick before patching anything.

Sanity checks before going further: if the alert `Status` is not `open`, or
the asset `State` is `pending_deletion` (the workload may already be
rotating out), or the asset's latest revision differs from the alerted one,
tell the engineer and confirm the patch is still wanted.

### Phase 2: Classify and find the code origin

Route on the `get_alert` response. Full decision detail, hop chains, field
maps, and observed response schemas live in
[references/orca-navigation.md](references/orca-navigation.md); read it
before your first navigation in a session.

| Signal in the alert | Route | Origin source |
|---|---|---|
| `asset_type: CodeRepository`, label `source:shiftleft` | SCA on code | Embedded in the alert (`RiskFindings.package`), no further calls |
| Runtime asset (CloudRun, Container, GcpCloudFunction, VM) | Runtime | `get_alert_code_origin(alert_id)` |
| Code origin empty | Fallback | Walk the deployment hierarchy upward (revision to service, container to spec to cluster), `get_code_origin` at each ancestor |
| Still nothing | Search, then heuristics | Org-wide code search (`gh search code`) on image, service, and project names; then the heuristic classes: see the navigation reference |

Origin records come back as one of three types, each carrying the repo URL,
default branch, file path, line range, blame, contributors, and often
CodeOwners: `Dockerfile`, `TerraformResource`, or `TerraformModuleCall`.

### Phase 3: Locate the patch site in the local checkout

The origin points at code; the engineer's checkout is the ground truth.

1. Get into the origin repo. If the working directory's git remote already
   matches the origin's `CodeRepository.Url`, use it. Otherwise clone it:
   `git clone --depth 50 <CodeRepository.Url>` into a nearby workspace
   directory (the default branch is in the origin record), tell the engineer
   where the clone landed, and work there. A shallow clone is enough because
   only HEAD matters for the patch. Only if the clone fails (no credentials,
   no network, repo access denied) do you stop: report the exact clone
   command for the engineer to run, and continue from their checkout.
   Cloning is read-only toward the remote. Any commit or push from the clone
   happens only in Phase 6, with the engineer's explicit go-ahead.
2. Navigate to the origin `Path` (or `RiskFindings.package.target` for SCA
   alerts).
3. Drift check, always: origin data is pinned to a historical commit. Verify
   the finding still holds at HEAD (the `installed_version` still appears in
   the manifest, the flagged config line still exists). If the file moved or
   the version already changed, report instead of patching.
4. The origin file is not always the patch site. A Dockerfile origin with an
   app-package CVE means the fix lives in the dependency manifest near that
   Dockerfile. A Terraform origin with a package CVE means the fix lives in
   the app source or Dockerfile in the same repo, and the Terraform file
   likely needs no change. The origin file is the patch site only when the
   vulnerable artifact is pinned there: a base image tag in a Dockerfile, or
   an image reference in Terraform or Helm values.

### Phase 4: Patch

Follow the fix archetype for the finding class, from
[references/patch-playbooks.md](references/patch-playbooks.md): manifest
bump, base image bump, or third-party image bump. That file also
carries the version selection rules, the transitive dependency ladder,
lockfile handling, and the `for_each` trap for Terraform module calls. Read
the relevant playbook before editing.

### Phase 5: Verify and present

- Run the cheapest verification the repo supports: dependency resolution or
  a build for manifests, `docker build` if available for Dockerfiles,
  `terraform validate` for IaC, the repo's own tests when fast.
- For dependency fixes, assert the outcome mechanically: the dependency tree
  must now resolve the vulnerable package at or above the patched version.
- Present the diff with: what was vulnerable and why this edit fixes it, the
  target version and its source (Orca field, registry metadata, or advisory
  link), the blast radius (every asset and alert this surface covers, from
  the origin's `Inventories` array), suggested reviewers (CodeOwners first,
  else the last commit author), and the Orca alert links (`ui_url`).

### Phase 6: Optional commit, push, and pull request

Only after the engineer has seen the diff and asked for a PR. Present the
diff first, then ask. Never volunteer the push in the same turn as the patch.

Preflight, and stop if any of these fails:

- `git status --porcelain` shows only the files you edited. Unrelated staged
  or modified files mean the engineer's in-progress work would land in your
  commit. Stop and name what else is dirty.
- HEAD is on a branch, not detached, and you are branching off the origin
  record's default branch rather than committing onto it.
- A push remote exists (`git remote -v`), and `gh auth status` succeeds if you
  intend to open the PR with `gh`.

Then:

1. Branch: `git checkout -b fix/<alert-id>-<short-slug>`.
2. Stage only the files you edited, by explicit path. Never `git add -A`.
3. Commit with a message the reviewer can act on: a subject line naming the
   package or image and the target version, and a body naming the alert ID,
   the asset, the CVEs closed, and the `ui_url`. No secret values, ever.
4. `git push -u origin <branch>`. Never `--force`.
5. `gh pr create` using the Phase 5 presentation as the body: what was
   vulnerable, the target version and its source, blast radius, the
   verification you ran, and the Orca alert links. Request the origin
   record's CodeOwners as reviewers when it names them. Open it as a draft if
   the engineer asked for a draft.
6. If `gh` is missing or unauthenticated, push the branch anyway and hand the
   engineer the compare URL to open the PR themselves.

Never merge the PR, never delete the branch, and never push again to a branch
the engineer has taken over.

### Phase 7: Optional Orca writeback

Only after the engineer confirms the fix is merged, and only if they want it:
`add_alert_comment` with the commit or PR link, then
`update_alert_status(alert_id, "in_progress")`, on every alert the fix
surface covers. Remind them Orca auto-verifies on the next scan.

## Stop conditions

Stop and produce a report (findings, route taken, why no patch) instead of
editing when any of these hold: the alert's `Category` is not
`Vulnerabilities`; the origin repo cannot be cloned and no
matching checkout exists; the finding has drifted at HEAD; the only fix is a major version jump;
the base image track is EOL; a transitive dependency cannot be fixed within
the safety rules; a `for_each` block's concrete instance cannot be located;
or the code origin is a heuristic guess the engineer has not confirmed.

Stop before committing or pushing, keeping the patch itself on the table,
when: the working tree carries unrelated changes; HEAD is detached; the
branch you would commit to is the default branch; the remote rejects the
push; or the repo's contribution guide requires something you cannot satisfy,
such as a signed CLA or a linked issue.

## Report structure

When you finish (patch or no patch), summarize in this shape:

```
## <alert-id>: <title>
Asset: <name> (<type>, <account>, exposure) | Orca: <ui_url>
Origin: <repo> @ <path>:<lines> (<origin type>) | Owners: <CodeOwners or last author>
Fix: <one line: what changed and to what version> | Also closes: <sibling alerts/assets>
Verification: <what was run and the result>
PR: <url, or "not opened: diff only">
Next: engineer reviews and merges; Orca confirms on next scan
```
