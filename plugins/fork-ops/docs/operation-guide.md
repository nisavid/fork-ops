# Fork Ops Operation Guide

Start every fork operation by locating fork-local authority.

```bash
uv run --package fork-ops fork-ops capability report --repo /path/to/fork
```

## Config Access

Use the CLI or MCP tools instead of ad hoc TOML parsing when an operation depends on Fork Ops Config.

```bash
uv run --package fork-ops fork-ops config show --repo /path/to/fork --format json
uv run --package fork-ops fork-ops config validate --repo /path/to/fork --required-level track-aware
```

MCP tools expose the same surface for agents:

- `fork_ops_config_read`
- `fork_ops_config_validate`
- `fork_ops_capability_report`
- `fork_ops_migration_assessment`
- `fork_ops_migration_config_patch`
- `fork_ops_schema`

## Capability Routing

Use `identified` for basic fork recognition and authority discovery.

Use `scoutable` for upstream and fork research where source order matters.

Use `track-aware` for release-channel and Upstream Track reasoning, freshness reports, and baseline comparison.

Use `sync-ready` only for sync planning and validation when sync policy and divergence policy are present.

Use `review-ready` only when PR, review, publication, and local gate policy are present.

Use `provenance-ready` only when source, artifact, package, runtime, or install-state verification surfaces are configured.

## Mutation Policy

The foundation implementation does not run broad sync mutations, PR publication closeout, or migration execution. Agents should report the missing capability and provide the smallest safe next step.

When mutation surfaces exist, they should share core Mutation Gate logic:

- Validate config before acting.
- Verify Descriptive Fork Facts against live state when possible.
- Respect Prescriptive Fork Policies.
- Produce structured evidence.
- Fail closed when mutation gates fail.

Semantic tools should call Mutation Gates before side effects because they know the typed operation intent. Hooks should enforce harness boundaries for lifecycle events and manual mutation paths.
