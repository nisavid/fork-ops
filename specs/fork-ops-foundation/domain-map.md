# Fork Ops Domain Map

Status: Draft

This map names the domains currently in scope for Fork Ops and marks non-normative portability hints for future Repo Ops migration.

| Domain | Purpose | Portability hint |
| --- | --- | --- |
| `identity` | Define the Maintained Fork, upstreams, fork remotes, default change target, and ownership facts. | fork-specific |
| `authority` | Define source-order rules, upstream canon, fork-local policy, escalation boundaries, and decision ownership. | fork-specific |
| `upstream_intelligence` | Track upstream remotes, release channels, upstream tracks, sync baselines, and freshness checks. | fork-specific |
| `divergence` | Record local contracts, intentional deltas, preservation checks, and uncertainty routing. | fork-specific |
| `change_targeting` | Distinguish fork-local work, upstream contribution exceptions, selective upstreaming, and replacement PRs. | fork-specific |
| `sync` | Preserve upstream commit identity and operate ancestry-preserving update workflows. | fork-specific |
| `review_publication` | Manage branches, draft PRs, review bots, checks, merge readiness, and cleanup. | repo-ops-candidate |
| `contributor_prs` | Repair external PRs while preserving authorship, review evidence, and fork-specific branch/security constraints. | shared-with-fork-policy |
| `dependency_ops` | Discover dependency update surfaces, maintain update automation, and report blocked lanes. | repo-ops-candidate |
| `provenance_validation` | Prove which source, package, artifact, runtime, or installed build is active. | repo-ops-candidate |
| `agent_equipment` | Inventory and migrate fork-related skills, docs, scripts, hooks, config, and instructions into reusable equipment. | repo-ops-candidate |

Portability hints are not authoritative migration decisions. Future Repo Ops migration design owns the final boundary.
