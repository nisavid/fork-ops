# Fork Ops Operation Guide

Start configured-fork operations by locating fork-local authority.

```bash
uv run --package fork-ops fork-ops plugin health
uv run --package fork-ops fork-ops workflow catalog
uv run --package fork-ops fork-ops capability report --repo /path/to/configured-fork
```

For an unconfigured fork, start with migration assessment instead.

```bash
uv run --package fork-ops fork-ops migration assess --repo /path/to/fork
uv run --package fork-ops fork-ops migration preflight --repo /path/to/fork --source-root /path/to/global-skills
uv run --package fork-ops fork-ops migration preflight --repo /path/to/fork --scan-profile full-breadth
uv run --package fork-ops fork-ops migration plan --repo /path/to/fork
uv run --package fork-ops fork-ops migration dry-run --repo /path/to/fork
uv run --package fork-ops fork-ops migration execute --repo /path/to/fork
uv run --package fork-ops fork-ops migration propose-config --repo /path/to/fork --format toml
```

## Config Access

Use the CLI or MCP tools instead of ad hoc TOML parsing when an operation depends on fork ops config.

```bash
uv run --package fork-ops fork-ops config show --repo /path/to/configured-fork --format json
uv run --package fork-ops fork-ops config validate --repo /path/to/configured-fork --required-level track-aware
```

Create a starter config when fork-local authority already identifies the fork
and upstream repository:

```bash
uv run --package fork-ops fork-ops config init --repo /path/to/fork --repository-owner OWNER --repository-name REPO --upstream-owner UPSTREAM_OWNER --upstream-name UPSTREAM_REPO --write
```

MCP tools expose the same surface for agents:

- `fork_ops_plugin_health`
- `fork_ops_config_read`
- `fork_ops_config_validate`
- `fork_ops_capability_report`
- `fork_ops_workflow_catalog`
- `fork_ops_workflow_migration_inventory`
- `fork_ops_migration_assessment`
- `fork_ops_equipment_migration_preflight`
- `fork_ops_migration_plan`
- `fork_ops_migration_dry_run`
- `fork_ops_migration_execute`
- `fork_ops_migration_blocker_resolution`
- `fork_ops_migration_config_patch`
- `fork_ops_schema`

## Plugin Health

Use plugin health when first bringing Fork Ops online or when one control
surface works while another is missing. The report checks plugin registration,
skill discovery, CLI execution, MCP config, MCP startup, MCP tool listing, and
UI visibility when inspectable.

```bash
uv run --package fork-ops fork-ops plugin health
```

Each readiness path reports one status: `ready`, `failed`, `unavailable`, or
`uninspectable`. MCP failures include next paths, and the report provides CLI
fallback guidance when CLI execution is ready.

## Workflow Migration Inventory

Use workflow inventory for product-surface workflow migration, not for replacing
a maintained fork's authority. It scans operator-provided roots or the
full-breadth profile and reports source kind, source scope, material scope,
candidate operator intent, likely workflow catalog target, coverage status,
accounting records, follow-up candidates, and evidence references.

```bash
uv run --package fork-ops fork-ops workflow inventory --source-root /path/to/global-skills --source-root /path/to/fork
uv run --package fork-ops fork-ops workflow inventory --scan-profile full-breadth
```

Backlog candidates in this report are evidence for future catalog work. They do
not mean the workflow is available.

The `full-breadth` profile scans known user-global roots, the maintained-fork
repository set, and adjacent roots. It records the visited roots in
`source_root_records`, preserves each root's scope, and accounts for each
discovered workflow entry exactly once. Planned workflows, reusable Repo Ops
candidates, and unassessed roots receive follow-up candidates. Repository roots
are included only when `FORK_OPS_FULL_BREADTH_REPO_BASE` is set. Use
`FORK_OPS_FULL_BREADTH_MAINTAINED_REPOS` and
`FORK_OPS_FULL_BREADTH_ADJACENT_REPOS` to run the same profile against another
layout.

## Equipment Migration Preflight

Use equipment preflight before treating existing skills, configs, docs, hooks,
or other equipment as replaced. The preflight is read-only. It reports assessed
discovery scopes, proposed onboarding intent, equipment groups, proposed
dispositions, unassessed areas, compatibility entries when detected, activation
impact, and a proposed TOML equipment review record.

```bash
uv run --package fork-ops fork-ops migration preflight --repo /path/to/fork --source-root /path/to/global-skills
uv run --package fork-ops fork-ops migration preflight --repo /path/to/fork --scan-profile full-breadth
```

When no extra source root is supplied, preflight scans repo-local material and
names user-global equipment as unassessed. Unassessed areas limit activation
readiness and replacement coverage for overlapping behavior. Reviewed
`retain_authoritative_owner` entries in the equipment review record can support
guarded config creation while source-material replacement and removal remain
unavailable.

Use `--scan-profile full-breadth` when full-breadth accounting is required. The
full-breadth preflight adds accounting records and follow-up candidates from the
known user-global, maintained-fork, and adjacent-root surfaces to the repo-local
equipment review record. Replacement coverage remains false until equivalent
Fork Ops-owned behavior exists, validates, and is reported as covered behavior.

## Schema Artifacts

The documented schema copy and packaged runtime schema copy should stay aligned
with the runtime schema printer.

```bash
uv run --package fork-ops fork-ops schema check --plugin-root plugins/fork-ops
```

## Capability Routing

Use `identified` for basic fork recognition and authority discovery.

Use `scoutable` for upstream and fork research where source order matters.

Use `track-aware` for release-channel and upstream track reasoning, freshness reports, and baseline comparison.

Use `sync-ready` only for sync planning and validation when sync policy and divergence policy are present.

Use `review-ready` only when PR, review, publication, and local gate policy are present.

Use `provenance-ready` only when source, artifact, package, runtime, or install-state verification surfaces are configured.

Capability reports include a summary of
`docs/agents/fork-ops-equipment-review.toml` when that record exists. The
summary identifies whether the record is valid, how many equipment decisions
are pending or reviewed, which reviewed paths remain retained authority, and
whether unassessed equipment areas still limit activation readiness. When the
record contains accounting records, the capability summary reports accounting
record counts, status counts, and follow-up candidate counts. The summary does
not by itself authorize equipment edits, disabling, redirects, replacement
coverage claims, or source-material removal.

## Mutation Policy

The foundation implementation supports guarded migration execution for
plans whose dry-run blockers are resolved for config creation. It creates
`.agents/fork-ops.toml`, preserves retained source materials, reports migration
map dispositions, equipment preflight findings, review artifact decisions,
activation-readiness limits, replayable wet-run evidence, operator-readable
narratives, migration blockers, and resulting capability verification. A
`semantic_coverage.incomplete` path only stops blocking guarded config creation
when the migration review artifact records a reviewed `retain` decision or the
equipment review record records a reviewed `retain_authoritative_owner`
disposition for that path. Retained authority remains checked-in source
material and still blocks source-material replacement or removal. The
implementation does not run broad sync mutations, PR publication closeout,
arbitrary migration edits, equipment edits, equipment disabling, or
source-material removal. Agents should report missing capabilities and provide
the smallest safe next step.

When mutation surfaces exist, they should share core mutation gate logic:

- Validate config before acting.
- Verify descriptive fork facts against live state when possible.
- Respect prescriptive fork policies.
- Produce structured evidence.
- Fail closed when mutation gates fail.

Semantic tools should call mutation gates before side effects because they know the typed operation intent. Hooks should enforce harness boundaries for lifecycle events and manual mutation paths.
