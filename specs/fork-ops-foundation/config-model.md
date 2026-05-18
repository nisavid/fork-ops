# Fork Ops Config Model

Status: Draft

`Fork Ops Config` lives at `.agents/fork-ops.toml` in a Maintained Fork.

## Model

The config contains two classes of data:

- Descriptive fork facts: repository facts that tools should verify against live state when possible.
- Prescriptive fork policies: operating rules that agents should follow unless the user explicitly changes them.

Config validation is capability-based. A Maintained Fork can be valid at a lower Fork Ops Capability Level without carrying every section needed for heavier operations.

The first fully operational implementation target is `track-aware`. `sync-ready` should be represented in the schema design so existing fork policy can be migrated cleanly, but sync mutation workflows can be implemented after the config and upstream-track surface is reliable.

Migration support should start with read-only Migration Assessment and non-mutating proposed config patches. Full migration should later progress through Migration Plan, Migration Dry Run, and Migration Execution after target functionality exists.

## Capability Levels

| Level | Required shape | Enables |
| --- | --- | --- |
| `identified` | Repository, fork remote, upstream identity, default change target. | Basic fork recognition and authority discovery. |
| `scoutable` | Identified shape plus source routes and authority order. | Upstream/fork research with source-quality guidance. |
| `track-aware` | Scoutable shape plus release channels and upstream tracks. | Baseline comparison, upstream freshness reports, and shared upstream-ref maintenance. |
| `sync-ready` | Track-aware shape plus default sync baseline, merge policy, ancestry checks, and divergence policy. | Ancestry-preserving upstream sync planning and validation. |
| `review-ready` | Sync-ready shape plus PR, review, checks, merge, and cleanup policy. | End-to-end PR review/publication closeout. |
| `provenance-ready` | Relevant lower levels plus package, artifact, runtime, or install-state verification surfaces. | Source/artifact/runtime provenance diagnosis. |

## Descriptive Sections

- `repository`: repository identity, host, default branch, and verified protected branches.
- `fork_remotes`: fork-owned remotes and push targets.
- `upstreams`: upstream projects, remotes, and disabled push expectations.
- `release_channels`: live upstream release selectors such as latest stable or latest preview. Release-channel results are resolved live by default and recorded as operation evidence only when needed.
- `upstream_tracks`: named ref roles, owners, sources, update rules, local branch rules, non-fast-forward handling, evidence checks, and sync eligibility.
- `local_surfaces`: paths for fork-local authority, docs, skills, scripts, hooks, migration inputs, non-normative domain tags, and partial Repo Ops portability hints.

## Prescriptive Sections

- `authority`: source order, upstream canon rules, required context paths, pre-change requirements, durable discovery destinations, and inference labeling.
- `change_targets`: fork-local defaults and upstream contribution exceptions.
- `sync_policy`: fork sync methods, track update methods, commit-identity rules, default sync baseline, sync start refs, ancestry checks, and forbidden history rewrites.
- `divergence_policy`: contract inventory, preservation checks, and uncertainty destination.
- `review_policy`: draft PR requirements, review readiness gates, review-thread handling, and merge ownership.
- `publication_policy`: branch push, PR creation, merge, branch deletion, and cleanup rules.
- `local_gates`: required local verification before pushing, marking ready, or merging.
- `portability`: non-normative portability hints for domains and components.

## Validation Behavior

- Parse and schema errors fail closed.
- Missing optional sections produce capability-specific unavailable status.
- Capability-level checks explain the missing facts or policies needed for the requested operation.
- Descriptive fact mismatches produce diagnostics before dependent operations run.
- Prescriptive policy conflicts require escalation unless a deterministic precedence rule exists.
- Portability hints never block current Fork Ops behavior.
- Release-channel resolution does not mutate config. Baseline-changing operations update Upstream Tracks or produce evidence artifacts according to policy.
- Migration Assessment and proposed config patch generation are read-only. Migration Execution is unavailable until the corresponding plan, dry-run, and validation surfaces exist.
- Config writes should use semantic operations by default. Advanced raw writes must validate parse and schema results and expose the proposed diff before mutation.
