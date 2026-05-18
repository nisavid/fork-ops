# Fork Ops Plugin

Fork Ops is a Codex plugin for agentic operations on Maintained Forks.

The plugin reads fork-local authority from `.agents/fork-ops.toml`, validates that config against the Fork Ops schema, reports the fork's capability level, and provides read-only Migration Assessment plus non-mutating config proposal generation for existing fork-related docs, skills, scripts, configs, and instructions.

The first implementation target is `track-aware`. It supports config discovery, schema validation, upstream release-channel and Upstream Track modeling, live Git ref checks, CLI access, and MCP access. Broad sync mutations, publication closeout, and migration execution are designed but not enabled in this foundation version.

## Surfaces

- Skill: `skills/fork-ops/SKILL.md`
- CLI: `uv run --package fork-ops fork-ops ...`
- MCP: `fork_ops_migration_config_patch` and related tools exposed through `.mcp.json`
- Schema: `src/fork_ops/fork-ops.schema.json`
- Docs: `docs/config-schema.md`, `docs/operation-guide.md`, `docs/migration.md`

## Quick Checks

```bash
export UV_CACHE_DIR=/tmp/fork-ops-uv-cache
uv run --package fork-ops fork-ops schema print
uv run --package fork-ops fork-ops capability report --repo /path/to/fork
uv run --package fork-ops fork-ops migration assess --repo /path/to/fork
uv run --package fork-ops fork-ops migration assess --repo /path/to/fork --with-proposed-config
uv run --package fork-ops fork-ops migration propose-config --repo /path/to/fork --format toml
uv run --package fork-ops ruff check --cache-dir .ruff_cache
uv run --package fork-ops pytest plugins/fork-ops/tests -q
uv run --package fork-ops mypy --cache-dir .mypy_cache
```
