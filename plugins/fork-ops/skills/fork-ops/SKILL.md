---
name: fork-ops
description: Use when operating a maintained repository fork, validating .agents/fork-ops.toml, assessing fork-ops readiness, inspecting upstream tracks, or migrating fork-related agent materials into Fork Ops.
---

# Fork Ops

Use this skill when the task concerns a maintained fork: a repository operated with an explicit upstream, local contracts, checked-in fork ops config, and repo-owned agent guidance.

## Authority Order

1. Read `.agents/fork-ops.toml` when it exists.
2. Read fork-local docs and agent instructions named by `local_surfaces`.
3. Read upstream source and docs when fork-local authority points there.
4. Use live Git and GitHub state to verify Descriptive Fork Facts.
5. Label inferred conclusions when direct evidence is unavailable.

Fork-local authority is the source of truth for the specific fork. The plugin supplies reusable operations and does not replace checked-in fork policy.

## Tool Surfaces

- CLI: `uv run --project ${PLUGIN_ROOT} fork-ops ...`
- Plugin health: `uv run --project ${PLUGIN_ROOT} fork-ops plugin health`
- Workflow catalog: `uv run --project ${PLUGIN_ROOT} fork-ops workflow catalog`
- MCP: `fork_ops_plugin_health`, `fork_ops_workflow_catalog`, `fork_ops_config_read`, `fork_ops_config_validate`, `fork_ops_capability_report`, `fork_ops_migration_assessment`, `fork_ops_migration_plan`, `fork_ops_migration_dry_run`, `fork_ops_migration_execute`, `fork_ops_migration_config_patch`, `fork_ops_schema`
- Schema: `${PLUGIN_ROOT}/schema/fork-ops.schema.json`
- Operation docs: `${PLUGIN_ROOT}/docs/operation-guide.md`

## Default Workflow

1. Run a capability report before choosing an operation:

   ```bash
   uv run --project ${PLUGIN_ROOT} fork-ops plugin health
   uv run --project ${PLUGIN_ROOT} fork-ops workflow catalog
   uv run --project ${PLUGIN_ROOT} fork-ops capability report --repo /path/to/fork
   ```

2. For config questions, validate the config before trusting dependent policy:

   ```bash
   uv run --project ${PLUGIN_ROOT} fork-ops config validate --repo /path/to/fork --required-level track-aware
   ```

3. For existing fork materials, start with read-only migration assessment:

   ```bash
   uv run --project ${PLUGIN_ROOT} fork-ops migration assess --repo /path/to/fork
   ```

4. For a reviewed migration path, generate a non-mutating migration plan:

   ```bash
   uv run --project ${PLUGIN_ROOT} fork-ops migration plan --repo /path/to/fork
   ```

5. For a migration preview, run a non-mutating dry run:

   ```bash
   uv run --project ${PLUGIN_ROOT} fork-ops migration dry-run --repo /path/to/fork
   ```

6. For a reviewed, blocker-free config migration, run guarded migration execution:

   ```bash
   uv run --project ${PLUGIN_ROOT} fork-ops migration execute --repo /path/to/fork
   ```

7. For a first config draft, generate a non-mutating proposed config patch and review it against the source materials before applying it:

   ```bash
   uv run --project ${PLUGIN_ROOT} fork-ops migration propose-config --repo /path/to/fork --format toml
   ```

8. Treat sync, publication, source-material removal, and arbitrary migration mutations as unavailable unless the config capability level and tool surface explicitly support them.

## Escalation Boundaries

Escalate when fork-local authority is missing, contradictory, or insufficient for a stakeholder decision. Escalate when an operation requires a control surface the agent does not have. Make the return contract concrete: requested decision, command output, URL, or artifact path.

## Current Capability

This foundation version targets `track-aware`. It can discover, parse, validate, normalize, and report config state. It can inspect local Git remotes and configured upstream track refs. It can assess migration inputs, generate reviewed non-mutating migration plans, dry runs, and config proposals, and execute guarded config creation for blocker-free plans. It does not execute broad upstream sync, PR publication closeout, source-material removal, or arbitrary migration edits.
