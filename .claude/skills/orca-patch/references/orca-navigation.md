# Orca MCP navigation for patching

Validated tool sequences for getting from an alert to its code origin with
the fewest possible calls. Every chain here was verified against live tenant
data; trust these routes over improvisation.

## ID cheat sheet

| Identifier | Example | Where it comes from |
|---|---|---|
| Alert ID | `orca-87716` | User input, alert lists |
| Asset UUID | `c1f09a89-312c-91ad-...` | `data[0].Inventory.id` in `get_alert` |
| Asset unique ID | `serverlesscontainer_<project>_<name>` | `Inventory.asset_unique_id` |
| Inventory type | `CloudRun`, `Group`, `GcpCloudFunction` | `data[0].Inventory.type` |

Important distinction: `AssetData.asset_type` (display type, e.g.
`Container`) and `Inventory.type` (model type, e.g. `Group`) can differ.
Grouped containers alert on a `Group` model whose display type is Container.
Tool calls that take a `model_name` need the `Inventory.type` value; passing
the display type returns a 404.

## Key fields to extract from get_alert

```
data[0].data:
  AlertType, RuleType, Category, Labels   -> routing
  Status, IsLive                          -> sanity checks
  Recommendation, RemediationCli          -> fix guidance text
  CveIds, MaxCvssScore, CveFixAvailable   -> report context
  RiskFindings                            -> the finding itself (shape varies, see below)
  AssetData.asset_image_name              -> image heuristics for fallbacks
  AssetData.asset_tags_info_list          -> team|X, managed-by|terraform, helm chart hints
data[0].Inventory:
  id (UUID), type, data.State, data.Exposure, data.RiskLevel
data[0].ui_url                            -> link for the report
```

`RiskFindings` shapes observed:

- Single-CVE runtime alerts (`RuleType: trending_cve`):
  `RiskFindings.cve.packages[]` with `package_name`, `installed_version`,
  `patched_version`, and sometimes `non_os_package_paths` (paths inside the
  image; presence means an app dependency, not an OS package).
- Multi-CVE software alerts (`RuleType: vulnerability` on runtime assets,
  titled "Vulnerabilities detected on <pkg>"): only `top_cves` and counts.
  No per-package `patched_version`; resolve the target version locally (see
  patch playbooks).
- Shiftleft SCA alerts (label `source:shiftleft`, asset is CodeRepository):
  `RiskFindings.package` with `target` (file path in the repo), `origin_url`
  (GitHub blame link with exact lines), `package_name`,
  `installed_version`; `top_cves[].patched_version` lists fixed versions.
- Unpatched OS (`RuleType: unpatched_system`): distro name and version,
  fixable CVE counts. Whole-image finding, not per-package.

## Routing and chains

### SCA on a code repository (cheapest: 1 call)

Detect: `AssetData.asset_type == "CodeRepository"` or label
`source:shiftleft`. Everything is in the alert. Do NOT call
`get_alert_code_origin`; it returns empty for these because the alert is
already on code. Patch site is `RiskFindings.package.target` in the repo
named by `AssetData.asset_name`.

### Runtime asset, direct origin (2 calls)

`get_alert` then `get_alert_code_origin(alert_id)`. Non-empty means done.
Observed for Cloud Run services built from Dockerfiles (origin type
`Dockerfile`) and Cloud Functions (origin type `TerraformModuleCall`).

### Cloud Run revision with no origin: hop to the service (4 calls)

Cloud Run alerts attach to the revision/container asset; the Terraform origin
often lives on the parent `GcpCloudRunService`. Chain:

1. `get_alert_code_origin` returns empty.
2. `get_linked_entities_data(container_uuid, {related_model:
   "GcpCloudRunService", relation_key: "Service", reversed_relation_key:
   "CloudRun", count: 1})` returns the parent service asset. (If this
   errors, fetch the shape first with
   `get_linked_entities_mapping(container_uuid, "CloudRun")`.)
3. Integrity check: the service's `LatestReadyRevisionName` should equal the
   alerted revision name. If it does not, the alert may describe a
   superseded deploy; flag it.
4. `get_code_origin(service_uuid)` returns the Terraform origin.

### GKE container with no origin: climb to the cluster (up to 6 calls)

GKE container alerts attach to a `Group` model. The Terraform origin lives on
the `GcpGkeCluster` asset, reached through the container spec. Chain, using
hardcoded relation shapes (fall back to `get_linked_entities_mapping` with
the correct `model_name` if a data call errors):

1. `get_alert_code_origin` returns empty.
2. Group to real container: `get_linked_entities_data(group_uuid,
   {related_model: "Inventory", relation_key: "RepresentativeAsset",
   reversed_relation_key: "RepresentsGroup", count: 1})`.
3. Container to spec: `get_linked_entities_data(container_uuid,
   {related_model: "K8sContainerSpec", relation_key: "K8sContainerSpec",
   reversed_relation_key: "Containers", count: 1})`. The spec also gives
   ports, privilege flags, and image ref for the report.
4. Spec to cluster: `get_linked_entities_data(spec_uuid, {related_model:
   "Cluster", relation_key: "K8sCluster", reversed_relation_key:
   "ContainerSpecs", count: 1})`. This yields the `GcpGkeCluster` asset.
5. `get_code_origin(cluster_uuid)` returns the Terraform origin (observed:
   `TerraformModuleCall` for the cluster module).

Dead end to avoid: the alert's `cluster_unique_id` (`gke_...`) resolves via
`get_asset_by_id` to the GKE *Group* asset, which carries no code origin.
Only the `GcpGkeCluster` asset reached through the spec does.

Also avoid `get_asset_by_name` for pivoting: it substring-matches images,
revisions, and unrelated assets. The linked-entity hops are deterministic.

The container's own `Tags` are worth reading on the way past: `helm.sh/chart`
names the Helm release that deploys the image, `team|` names the owner,
`managed-by|terraform` confirms the IaC path.

### Still no origin: search the org before falling back to heuristics

When the direct call and the hierarchy hops both come up empty, search the
customer's source org for the declaring code before resorting to guesswork.
The `gh` CLI (or the GitHub MCP when available) makes this one or two cheap
commands, and it turns most would-be dead ends into a confirmable origin.

Build search terms from the signals the alert already gave you, most
specific first:

1. Image path segments: the repository and service names inside the
   Artifact Registry path (`.../docker/<repo>/<service>:<tag>`), and the
   final image name itself.
2. The asset or service name, with revision suffixes stripped
   (`internal-apps-dso-00105-wsx` becomes `internal-apps-dso`).
3. The GCP project ID and its display name (`cloud_vendor_id`,
   `account_name`, and the `name|` account tag). Projects and repos often
   share naming: project `internal-apps-ffa3` (named `internal-apps`) is
   deployed from the repo `internal-apps-dso`. A project name is a strong
   substring hint for `gh search repos`.
4. Kubernetes namespace, `app|` and `team|` tags, and the Helm chart name.

Run, in order, stopping at the first confident hit:

```
gh search code "<image or service name>" --owner <org> --limit 10
gh search repos "<project or service name>" --owner <org> --limit 10
```

A hit in a Dockerfile, Helm values file, Terraform file, or CI workflow
usually IS the declaration site. Present the match (repo, file, line) to the
engineer as a proposed origin, get confirmation, then continue with the
normal playbooks. Log in the report that Orca had no origin for this asset
and which search found it, plus the recommendation to connect that repo to
Orca AppSec.

If search is unavailable (no `gh`, no org access) or finds nothing
convincing, fall through to the heuristic classes below.

### Heuristic classes when search cannot settle it

1. **Third-party vendor image** (registry the customer does not own:
   `quay.io/argoproj/argocd`, `docker.io/grafana/grafana`). No Dockerfile
   will ever exist. The fix is a version bump where the deployment is
   declared. Find the declaration by grepping the IaC/GitOps repo (often
   identified by the cluster-origin chain above) for the image string or the
   chart name from the `helm.sh/chart` tag.
2. **Buildpack / source deploy** (image in `gcf-artifacts` or a
   `cloud-run-source-deploy` repository, e.g.
   `<project>__<region>__<service>:version_N`). Built by Cloud Buildpacks
   from source; no Dockerfile. Deliverable is guidance: redeploy from source
   with an updated runtime, or point the skill at the source repo.
3. **First-party image from a repo not connected to Orca.** The Artifact
   Registry path usually encodes the repo:
   `.../docker/<repo-name>/<service>:<tag>` maps to the GitHub repo of the
   same name. State the guess explicitly, require the engineer to confirm
   before touching anything, and recommend connecting the repo to Orca
   AppSec so future alerts carry origins.

## Origin record schemas (observed)

All three types share: `ReferenceUrl` (blame link pinned to a commit),
`Path`/`FileName`, `Contributors`, `LastCommitInfo` or per-line blame,
`CodeRepository` (with `Url` and `DefaultBranch`), `Inventories` (every
runtime asset produced by this origin; your dedupe list), and `CodeOwners`
(sometimes empty; when present, these are the reviewers to suggest).

- `Dockerfile`: adds `BaseImage` (e.g. `python:3.8-slim-bullseye`).
- `TerraformResource`: adds `ResourceType` (e.g.
  `google_cloud_run_v2_service`), `Name`, `StartLine`, `EndLine`,
  `CodeSnippet` with per-line blame, `Module`.
- `TerraformModuleCall`: same as TerraformResource but for a `module` block.
  Check the snippet for `for_each`/`count` before treating the lines as the
  patch site (see the playbooks).

Masking: snippets redact secrets and some URLs with asterisks. Treat the
snippet as a locator (file, lines, owners), never as content to copy into a
patch. The engineer's checkout is the source of truth for file content.

## Dedupe before patching

The origin's `Inventories` array lists every asset built from the same
origin, across accounts and environments (observed: one Dockerfile backing
both prod and UAT Cloud Run services). Optionally,
`get_alerts_with_similar_alert_type(alert_id, alert_type)` (one call) finds
sibling alerts on other assets. Patch the surface once and list everything it
closes in the report.
