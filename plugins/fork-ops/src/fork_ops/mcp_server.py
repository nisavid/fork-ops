"""MCP adapter for Fork Ops.

This module requires the optional ``mcp`` dependency.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any, cast

from .core import (
    CONFIG_RELATIVE_PATH,
    ForkOpsError,
    assess_migration,
    build_status_report,
    dry_run_migration,
    execute_migration,
    find_config_path,
    generate_migration_plan,
    load_raw_config,
    propose_migration_config_patch,
    schema_json,
)

_MCP_IMPORT_ERROR: ModuleNotFoundError | None = None
_FAST_MCP_CLASS: Any = None

try:
    from mcp.server.fastmcp import FastMCP  # type: ignore[import-not-found]
except ModuleNotFoundError as exc:  # pragma: no cover - exercised only without optional dependency.
    _MCP_IMPORT_ERROR = exc
else:
    _FAST_MCP_CLASS = FastMCP


ToolFunc = Callable[..., Any]
mcp = _FAST_MCP_CLASS("Fork Ops") if _FAST_MCP_CLASS is not None else None


def _tool(func: ToolFunc) -> ToolFunc:
    if mcp is None:
        return func
    return cast(ToolFunc, mcp.tool()(func))


@_tool
def fork_ops_config_read(repo_path: str = ".", normalized: bool = True) -> dict[str, Any]:
    """Read the Fork Ops config for a repository."""
    if normalized:
        return build_status_report(repo_path, include_config=True)
    path = find_config_path(repo_path)
    try:
        raw = load_raw_config(repo_path)
    except ForkOpsError as exc:
        return {
            "path": str(path),
            "raw": "",
            "diagnostics": [
                {
                    "severity": "error",
                    "code": "config.read_failed",
                    "message": str(exc),
                    "path": str(CONFIG_RELATIVE_PATH),
                }
            ],
        }
    return {
        "path": str(path),
        "raw": raw,
        "diagnostics": [],
    }


@_tool
def fork_ops_config_validate(repo_path: str = ".", required_level: str = "") -> dict[str, Any]:
    """Validate Fork Ops config and optionally check a required capability level."""
    report = build_status_report(repo_path, include_config=False)
    if required_level:
        levels = report["capability"]["levels"]
        report["required_level"] = {
            "level": required_level,
            "available": bool(levels.get(required_level, {}).get("available")),
        }
    return report


@_tool
def fork_ops_capability_report(repo_path: str = ".") -> dict[str, Any]:
    """Report Fork Ops capability levels for a repository."""
    return cast(dict[str, Any], build_status_report(repo_path, include_config=False)["capability"])


@_tool
def fork_ops_migration_assessment(
    repo_path: str = ".",
    include_proposed_config_patch: bool = False,
) -> dict[str, Any]:
    """Run a read-only migration assessment for fork-related materials."""
    return assess_migration(repo_path, include_proposed_config_patch=include_proposed_config_patch)


@_tool
def fork_ops_migration_plan(repo_path: str = ".") -> dict[str, Any]:
    """Generate a non-mutating migration plan from fork-related materials."""
    return generate_migration_plan(repo_path)


@_tool
def fork_ops_migration_dry_run(
    repo_path: str = ".",
    migration_plan: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Preview a migration plan without mutating the repository."""
    return dry_run_migration(repo_path, plan=migration_plan)


@_tool
def fork_ops_migration_execute(
    repo_path: str = "",
    migration_plan: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Apply a validated migration plan through guarded operations."""
    return execute_migration(repo_path, plan=migration_plan)


@_tool
def fork_ops_migration_config_patch(repo_path: str = ".") -> dict[str, Any]:
    """Generate a non-mutating Fork Ops config proposal for migration planning."""
    return propose_migration_config_patch(repo_path)


@_tool
def fork_ops_schema() -> str:
    """Return the Fork Ops config JSON Schema."""
    return schema_json()


def main() -> None:
    if mcp is None:
        raise SystemExit(
            "The Fork Ops MCP server requires the optional dependency: pip install 'fork-ops[mcp]'"
        ) from _MCP_IMPORT_ERROR
    mcp.run()


if __name__ == "__main__":
    main()
