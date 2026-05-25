# Fork Ops #32 Equipment Migration Case Study

This case study records a read-only run against the local Lemonade fork using
the equipment migration preflight added for #32.

## Inputs

- Repository: `/home/nisavid/src/nisavid/lemonade`
- Additional equipment roots:
  - `/home/nisavid/.agents/skills/onboarding-forks-for-agent-maintenance`
  - `/home/nisavid/.agents/skills/syncing-forks-with-upstream`
  - `/home/nisavid/.agents/skills/getting-prs-merged`
  - `/home/nisavid/.agents/skills/pr-review-orchestration`

## Commands

```bash
UV_CACHE_DIR=/tmp/fork-ops-uv-cache uv run --package fork-ops fork-ops migration preflight --repo /home/nisavid/src/nisavid/lemonade --source-root /home/nisavid/.agents/skills/onboarding-forks-for-agent-maintenance --source-root /home/nisavid/.agents/skills/syncing-forks-with-upstream --source-root /home/nisavid/.agents/skills/getting-prs-merged --source-root /home/nisavid/.agents/skills/pr-review-orchestration
UV_CACHE_DIR=/tmp/fork-ops-uv-cache uv run --package fork-ops fork-ops migration plan --repo /home/nisavid/src/nisavid/lemonade > /tmp/fork-ops-32-lemonade-migration-plan.json
UV_CACHE_DIR=/tmp/fork-ops-uv-cache uv run --package fork-ops fork-ops migration dry-run --plan /tmp/fork-ops-32-lemonade-migration-plan.json
```

## Results

Equipment preflight reported:

- operation: `equipment-migration-preflight`
- default onboarding intent: `migrate_toward_fork_ops`
- discovery scopes: 5
- equipment groups: 30
- equipment evidence entries: 30
- unassessed equipment areas: 2
- proposed record target: `docs/agents/fork-ops-equipment-review.toml`

The initial migration dry run reported:

- `can_execute`: `false`
- activation readiness: `blocked`
- blocker: `semantic_coverage.incomplete`
- replayable wet run: unavailable
- drift policy: `fail_closed_by_default`

After marking the two semantic-coverage paths as reviewed
`retain_authoritative_owner` equipment decisions in the proposed equipment
review record, the reviewed-equipment dry run reported:

- `can_execute`: `true`
- activation readiness: `ready_for_guarded_config_creation_with_limits`
- blocked steps: none
- replayable wet run: available
- drift policy: `fail_closed_by_default`

The reviewed-equipment plan produced a different replay fingerprint from the
blocked plan, so reviewed equipment decisions are part of replay identity.

## Interpretation

This demonstrates the concrete #32 behavior that Agent Armory can generalize:

- existing equipment is grouped before detailed migration decisions;
- unassessed areas limit activation and replacement claims;
- reviewed equipment dispositions can unblock guarded config creation without
  authorizing source-material replacement or removal;
- replay metadata reflects the reviewed equipment decisions that changed the
  dry-run outcome.
