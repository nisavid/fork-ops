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
- `fork_ops_migration_plan`
- `fork_ops_migration_dry_run`
- `fork_ops_migration_execute`
- `fork_ops_migration_config_patch`
- `fork_ops_schema`

## Plugin Health

Use plugin health when first bringing Fork Ops online or when one control
surface works while another is missing. The report checks plugin registration,
skill discovery, CLI execution, MCP config resolution, MCP process startup, MCP
tool listing, and UI visibility when a UI inspection result is supplied.

```bash
uv run --package fork-ops fork-ops plugin health
```

Each readiness path reports one status: `ready`, `failed`, `unavailable`, or
`uninspectable`. MCP failures include next paths, and the report keeps CLI
fallback guidance available when CLI execution is ready.

## Workflow Migration Inventory

Use workflow inventory for product-surface workflow migration, not for replacing
a maintained fork's authority. It scans operator-provided roots and reports
source kind, material scope, candidate operator intent, likely workflow catalog
target, coverage status, and evidence references.

```bash
uv run --package fork-ops fork-ops workflow inventory --source-root /path/to/global-skills --source-root /path/to/fork
```

Backlog candidates in this report are evidence for future catalog work. They do
not mean the workflow is available.

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

## Mutation Policy

The foundation implementation supports guarded migration execution for
blocker-free plans that create `.agents/fork-ops.toml`, preserve retained source
materials, and verify the resulting capability level. It does not run broad
sync mutations, PR publication closeout, arbitrary migration edits, or
source-material removal. Agents should report missing capabilities and provide
the smallest safe next step.

When mutation surfaces exist, they should share core mutation gate logic:

- Validate config before acting.
- Verify descriptive fork facts against live state when possible.
- Respect prescriptive fork policies.
- Produce structured evidence.
- Fail closed when mutation gates fail.

Semantic tools should call mutation gates before side effects because they know the typed operation intent. Hooks should enforce harness boundaries for lifecycle events and manual mutation paths.
