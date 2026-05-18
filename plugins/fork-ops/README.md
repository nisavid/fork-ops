# Fork Ops Plugin

This directory contains the Codex plugin package for Fork Ops.

For project orientation, start with the repository [README](../../README.md). This
page is the package-level reference for the plugin's implemented surfaces and
local development checks.

> [!NOTE]
> The foundation version targets `track-aware`. It supports config discovery,
> schema validation, upstream release-channel and upstream track modeling, live
> Git ref checks, CLI access, MCP access, read-only migration assessment, and
> non-mutating migration plan and config proposal generation. Broad sync
> mutations, publication closeout, migration dry run, and migration execution
> are designed but not enabled yet.

## Surfaces

- Skill: `skills/fork-ops/SKILL.md`
- CLI: `uv run --package fork-ops fork-ops ...`
- MCP: `fork_ops_migration_plan`, `fork_ops_migration_config_patch`, and related tools exposed through `.mcp.json`
- Schema: `schema/fork-ops.schema.json` and packaged runtime copy `src/fork_ops/fork-ops.schema.json`
- Docs: `docs/config-schema.md`, `docs/operation-guide.md`, `docs/migration.md`

## Common Commands

Inspect a configured fork's current Fork Ops capability:

```bash
uv run --package fork-ops fork-ops capability report --repo /path/to/configured-fork
```

Validate the config before relying on track-aware operations:

```bash
uv run --package fork-ops fork-ops config validate --repo /path/to/configured-fork --required-level track-aware
```

Assess existing fork-related materials without editing the fork:

```bash
uv run --package fork-ops fork-ops migration assess --repo /path/to/fork
uv run --package fork-ops fork-ops migration plan --repo /path/to/fork
uv run --package fork-ops fork-ops migration propose-config --repo /path/to/fork --format toml
```

## Quick Checks

```bash
export UV_CACHE_DIR=/tmp/fork-ops-uv-cache
uv run --package fork-ops fork-ops schema print
uv run --package fork-ops fork-ops migration assess --repo /path/to/fork
uv run --package fork-ops fork-ops migration assess --repo /path/to/fork --with-proposed-config
uv run --package fork-ops fork-ops migration plan --repo /path/to/fork
uv run --package fork-ops fork-ops migration propose-config --repo /path/to/fork --format toml
uv run --package fork-ops fork-ops capability report --repo /path/to/configured-fork
uv run --package fork-ops ruff check --cache-dir .ruff_cache
uv run --package fork-ops pytest plugins/fork-ops/tests -q
uv run --package fork-ops mypy --cache-dir .mypy_cache
```
