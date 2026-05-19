# Fork Ops Plugin

This directory contains the Codex plugin package for Fork Ops.

For project orientation, start with the repository [README](../../README.md). This
page is the package-level reference for the plugin's implemented surfaces and
local development checks.

> [!NOTE]
> The foundation version targets `track-aware`. It supports config discovery,
> schema validation, upstream release-channel and upstream track modeling, live
> Git ref checks, CLI access, MCP access, workflow migration inventory,
> read-only migration assessment, migration plans with disposition maps and
> proposed review artifacts, dry-run, guarded execution, config proposal
> generation, operator-readable migration narratives, and blocker explanations.
> Broad sync mutations, publication closeout, arbitrary migration edits, and
> source-material removal are designed but not enabled yet.

## Surfaces

- Skill: `skills/fork-ops/SKILL.md`
- CLI: `uv run --package fork-ops fork-ops ...`
- Plugin health: `uv run --package fork-ops fork-ops plugin health`
- MCP: `fork_ops_plugin_health`, `fork_ops_workflow_catalog`, `fork_ops_workflow_migration_inventory`, `fork_ops_migration_plan`, `fork_ops_migration_dry_run`, `fork_ops_migration_execute`, `fork_ops_migration_blocker_resolution`, `fork_ops_migration_config_patch`, and related tools exposed through `.mcp.json`
- Schema: `schema/fork-ops.schema.json` and packaged runtime copy `src/fork_ops/fork-ops.schema.json`
- Docs: `docs/config-schema.md`, `docs/operation-guide.md`, `docs/migration.md`

## Common Commands

Inspect a configured fork's current Fork Ops capability:

```bash
uv run --package fork-ops fork-ops plugin health
uv run --package fork-ops fork-ops workflow catalog
uv run --package fork-ops fork-ops capability report --repo /path/to/configured-fork
```

Inventory reusable workflow materials without editing source roots:

```bash
uv run --package fork-ops fork-ops workflow inventory --source-root /path/to/source-root
```

Validate the config before relying on track-aware operations:

```bash
uv run --package fork-ops fork-ops config validate --repo /path/to/configured-fork --required-level track-aware
```

Assess existing fork-related materials without editing the fork:

```bash
uv run --package fork-ops fork-ops migration assess --repo /path/to/fork
uv run --package fork-ops fork-ops migration plan --repo /path/to/fork
uv run --package fork-ops fork-ops migration dry-run --repo /path/to/fork
uv run --package fork-ops fork-ops migration propose-config --repo /path/to/fork --format toml
uv run --package fork-ops fork-ops migration explain-blocker --input /path/to/migration-output.json --blocker-code semantic_coverage.incomplete
```

Apply a reviewed migration plan through guarded config creation when the dry-run
preview has no blockers:

```bash
uv run --package fork-ops fork-ops migration execute --repo /path/to/fork
```

## Quick Checks

```bash
export UV_CACHE_DIR=/tmp/fork-ops-uv-cache
uv run --package fork-ops fork-ops plugin health
uv run --package fork-ops fork-ops schema print
uv run --package fork-ops fork-ops workflow catalog
uv run --package fork-ops fork-ops workflow inventory --source-root /path/to/source-root
uv run --package fork-ops fork-ops schema check --plugin-root plugins/fork-ops
uv run --package fork-ops fork-ops migration assess --repo /path/to/fork
uv run --package fork-ops fork-ops migration assess --repo /path/to/fork --with-proposed-config
uv run --package fork-ops fork-ops migration plan --repo /path/to/fork
uv run --package fork-ops fork-ops migration dry-run --repo /path/to/fork
uv run --package fork-ops fork-ops migration execute --repo /path/to/fork
uv run --package fork-ops fork-ops migration propose-config --repo /path/to/fork --format toml
uv run --package fork-ops fork-ops migration explain-blocker --input /path/to/migration-output.json --blocker-code semantic_coverage.incomplete
uv run --package fork-ops fork-ops capability report --repo /path/to/configured-fork
uv run --package fork-ops ruff check --cache-dir .ruff_cache
uv run --package fork-ops pytest plugins/fork-ops/tests -q
uv run --package fork-ops mypy --cache-dir .mypy_cache
```
