"""MCP adapter for Fork Ops.

This module requires the optional ``mcp`` dependency.
"""

from __future__ import annotations

from typing import Any, cast

from .core import (
    assess_migration,
    build_status_report,
    load_raw_config,
    propose_migration_config_patch,
    schema_json,
)

try:
    from mcp.server.fastmcp import FastMCP
except ModuleNotFoundError as exc:  # pragma: no cover - exercised only without optional dependency.
    raise SystemExit(
        "The Fork Ops MCP server requires the optional dependency: pip install 'fork-ops[mcp]'"
    ) from exc


mcp = FastMCP("Fork Ops")


@mcp.tool()
def fork_ops_config_read(repo_path: str = ".", normalized: bool = True) -> dict[str, Any] | str:
    """Read the Fork Ops config for a repository."""
    if normalized:
        return build_status_report(repo_path, include_config=True)
    return load_raw_config(repo_path)


@mcp.tool()
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


@mcp.tool()
def fork_ops_capability_report(repo_path: str = ".") -> dict[str, Any]:
    """Report Fork Ops capability levels for a repository."""
    return cast(dict[str, Any], build_status_report(repo_path, include_config=False)["capability"])


@mcp.tool()
def fork_ops_migration_assessment(repo_path: str = ".") -> dict[str, Any]:
    """Run a read-only Migration Assessment for fork-related materials."""
    return assess_migration(repo_path)


@mcp.tool()
def fork_ops_migration_config_patch(repo_path: str = ".") -> dict[str, Any]:
    """Generate a non-mutating Fork Ops config proposal for migration planning."""
    return propose_migration_config_patch(repo_path)


@mcp.tool()
def fork_ops_schema() -> str:
    """Return the Fork Ops config JSON Schema."""
    return schema_json()


def main() -> None:
    mcp.run()


if __name__ == "__main__":
    main()
