# Patch playbooks

How to make the actual edit, by finding class. Every playbook ends in a local
diff for engineer review, or a stop-condition report. Nothing here commits,
pushes, or deploys: that is Phase 6 of the skill, and only on request.

## Classify the finding first

The finding class, not the origin type, decides what kind of edit is correct.

| Signal in RiskFindings | Class | Playbook |
|---|---|---|
| Ecosystem-form package (`org.springframework:spring-beans`, `next`, `protobufjs`, `Pillow`) or `non_os_package_paths` present | App dependency | Manifest bump |
| Distro-versioned package (`libssl3 3.0.11-1~deb12u2`, `openssl 3.3.3-r0`) | OS package | Base image bump |
| `RuleType: unpatched_system`, hundreds of matched CVEs | Neglected image | Base image refresh |
| Image from a vendor registry the customer does not own | Third-party image | Image version bump |
| Category is not `Vulnerabilities` (misconfiguration, compliance, secrets, IAM) | Out of scope | Report the alert's `Recommendation` and stop |

## Choosing the target version

Precedence, and why: Orca's own data is authoritative when present; local
tooling resolves against live registry metadata when it is not; and staying
inside the installed major keeps the change reviewable as a security patch
rather than an upgrade project.

1. `patched_version` from the alert (present on single-CVE trending alerts
   and shiftleft alerts). When several versions are listed, e.g.
   `13.5.9, 14.2.25, 15.2.3, 12.3.5` for an installed `14.2.3`, pick the one
   sharing the installed major.minor track: `14.2.25`.
2. When absent (multi-CVE "Vulnerabilities detected on <pkg>" alerts):
   resolve locally with ecosystem tooling (`npm audit`, OSV lookup,
   `pip index versions`, `mvn versions:display-dependency-updates`), still
   choosing the minimal fixed version in the installed track. Web search for
   the advisory is fine when tooling is ambiguous; cite the advisory in the
   diff description.
3. Never jump a major on your own. A major-only fix is a stop condition:
   report it as a separate, human-owned upgrade task.

## Playbook: manifest bump (app dependencies)

1. Locate the manifest. Shiftleft alerts name it (`RiskFindings.package.target`).
   For Dockerfile-origin alerts, search the Dockerfile's directory (and what
   it COPYs) for the ecosystem manifest: `pom.xml`, `package.json`,
   `requirements.txt`, `go.mod`, `pyproject.toml`. `non_os_package_paths`
   (e.g. `/app.jar/BOOT-INF/lib/spring-beans-5.3.15.jar`) confirms the
   ecosystem.
2. Drift check: the `installed_version` must still appear at HEAD.
3. Direct dependency: edit the manifest to the target version. Never
   hand-edit a lockfile; regenerate it with the package manager
   (`npm install --package-lock-only`, `mvn versions:set`, `poetry lock`).
4. Transitive dependency: follow the ladder below.
5. Verify: dependency resolution or build succeeds, and the tree now
   resolves the vulnerable package at or above the target
   (`npm ls <pkg>`, `mvn dependency:tree -Dincludes=<pkg>`).

### Transitive dependency ladder

Work down; take the first rung that succeeds. Find the parent chain
deterministically first: `npm why <pkg>` / `npm ls <pkg>`,
`mvn dependency:tree -Dincludes=<groupId>:<artifactId>`,
`pipdeptree --reverse --packages <pkg>`, `gradle dependencyInsight`.

1. **Lockfile refresh.** If the declared range already admits the fixed
   version, the lock is just stale: `npm update <pkg>`, `yarn up -R <pkg>`.
   Smallest possible diff; check this before anything else.
2. **Parent bump.** Find the smallest parent release in its current major
   that pulls the fixed transitive. Sources in order: registry metadata
   (`npm view <parent>@'<range>' dependencies.<pkg>`, parent POMs), then web
   search ("<parent> <CVE-id> fixed version"; prefer the parent's own
   release notes and cite them). Bump the parent, regenerate the lock,
   assert the resolved version.
3. **Override**, only when no fixed parent release exists yet. npm
   `overrides` / yarn `resolutions` / pnpm overrides / Maven
   `dependencyManagement` / Gradle constraints / pip constraints. Maven and
   Gradle versions of this are fully idiomatic; treat them routinely. For
   npm-family overrides: same-major forcing only, add a comment naming the
   CVE and the parent's tracking issue, and frame it in the diff description
   as interim until the parent ships. Go modules need no override at all:
   `go get <pkg>@<version>` bumps a transitive directly.
4. **Stop** if even the override conflicts with peer constraints, or the fix
   requires crossing a major anywhere. If a parent major jump is the only
   real fix, the override (rung 3) is the interim patch and the major
   upgrade goes in the report as follow-up work.

## Playbook: base image bump (OS packages, unpatched OS)

The `patched_version` format tells you what is needed:
`3.0.18-1~deb12u2` means a newer Debian 12 snapshot; a `-rN` suffix means an
Alpine point release; `-0ubuntu3.7` means a newer Ubuntu package snapshot.
Rebuilding on a current base almost always picks these up.

1. Read `BaseImage` from the Dockerfile origin, confirm at HEAD.
2. Floating tag (`node:20`): a rebuild picks up the fix. The diff may be
   empty; the deliverable is a rebuild instruction, optionally with a
   pin-by-digest bump so the change is visible and reproducible.
3. Pinned tag (`python:3.8-slim-bullseye`): bump to the latest patch tag on
   the same track, after checking the track is not EOL.
4. EOL track (check the alert's `OsEndOfSupport`, or the distro's release
   page): stop condition. Report "base image migration required" as a
   human-owned task; do not silently cross distro majors or language
   minors.
5. Last resort when the base cannot move: an explicit package upgrade line
   in the Dockerfile (`apt-get install --only-upgrade <pkg>=<version>`),
   commented as temporary.
6. Verify with `docker build` when available; otherwise confirm the target
   tag or package version exists upstream.

For `unpatched_system` alerts, the Orca `RemediationCli` text already
describes the rebuild flow; the diff is the base image line, and the report
should set the expectation that hundreds of CVEs close together on rescan.

## Playbook: third-party image bump

The customer does not build this image (Grafana, Argo CD, and similar), so
there is nothing to patch in a Dockerfile. The fix is running a fixed
release.

1. Map the fixed library version to the vendor release that ships it, via
   the vendor's release notes or security advisories (web search). Link the
   changelog in the diff description.
2. Find the declaration site: grep the IaC/GitOps repo (identified by the
   cluster or service origin chain) for the image string, or for the chart
   named in the container's `helm.sh/chart` tag. Declarations live in
   Terraform `helm_release` blocks, Helm values files, or Argo CD app
   manifests.
3. Bump the tag or chart version. Same-major only; a vendor major jump is a
   stop condition with the upgrade reported as follow-up work.
4. Verify: the target tag exists in the registry; `helm template` or
   `terraform validate` passes when available.

## The for_each trap (Terraform and Helm origins)

Applies whenever the version you need to bump is pinned in IaC rather than in
a Dockerfile or manifest.

A `TerraformModuleCall` with `for_each` or `count` deploys many instances from
one block. Editing the shared block bumps the image for all of them, which is
almost never the intended blast radius. Locate the per-instance definition
instead (grep the repo, usually tfvars or a locals map, for the alerted
asset's name) and patch that entry. If you cannot find the concrete instance,
stop and report.

Verify with `terraform validate`, and tell the engineer what `terraform plan`
should show for the one instance you changed.

## Verification quick reference

| Surface | Check |
|---|---|
| pom.xml | `mvn -q verify` or `mvn dependency:tree -Dincludes=<pkg>` |
| package.json | lock regen succeeds, `npm ls <pkg>` shows target version |
| requirements/pyproject | resolver succeeds, `pip index versions` confirms target exists |
| Dockerfile | `docker build` if available; else upstream tag/package exists |
| Terraform | `terraform validate`; describe expected `plan` output |
| Any repo with fast tests | run them |

## The diff handoff

Present every patch with: the vulnerable state and why this edit fixes it;
the target version and its source (Orca field, registry metadata, or cited
advisory); the blast radius from the origin's `Inventories` plus any sibling
alerts found; suggested reviewers (CodeOwners, else last commit author); the
Orca `ui_url` links; and any adjacent facts the engineer should know
(outdated runtime flagged, secrets-in-env findings exist, asset pending
deletion) without reproducing sensitive values. Then stop and let the
engineer read it. If they ask for a pull request, follow Phase 6 of the
skill. Merging is always theirs.
