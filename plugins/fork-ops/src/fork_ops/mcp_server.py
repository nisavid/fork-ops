"""MCP adapter for Fork Ops.

This module requires the optional ``mcp`` dependency.
"""

from __future__ import annotations

import json
import sys
from collections.abc import Callable
from typing import Any, cast

from ._contracts import ArtifactKind, operation_artifact
from .core import (
    ForkOpsError,
    _validate_bounded_object,
    assess_migration,
    build_equipment_migration_preflight,
    build_plugin_health_report,
    build_status_report,
    build_workflow_migration_inventory,
    dry_run_migration,
    execute_migration,
    explain_migration_blocker,
    generate_migration_plan,
    propose_migration_config_patch,
    read_config_result,
    schema_json,
)
from .workflow_catalog import workflow_catalog

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
_REGISTERED_TOOL_IDS: list[str] = []


def _tool(func: ToolFunc) -> ToolFunc:
    _REGISTERED_TOOL_IDS.append(func.__name__)
    if mcp is None:
        return func
    return cast(ToolFunc, mcp.tool()(func))


@_tool
def fork_ops_plugin_health(
    plugin_root: str = "",
    repo_root: str = "",
    ui_visible: bool | None = None,
) -> dict[str, Any]:
    """Report Fork Ops plugin health diagnostics."""
    return build_plugin_health_report(
        plugin_root or None,
        repo_root=repo_root or None,
        ui_visible=ui_visible,
    )


@_tool
def fork_ops_config_read(repo_path: str = ".", normalized: bool = True) -> dict[str, Any]:
    """Read the Fork Ops config for a repository."""
    return read_config_result(repo_path, normalized=normalized)


@_tool
def fork_ops_config_validate(repo_path: str = ".", required_level: str = "") -> dict[str, Any]:
    """Validate Fork Ops config and optionally check a required capability level."""
    return build_status_report(
        repo_path,
        include_config=True,
        required_level=required_level,
    )


@_tool
def fork_ops_capability_report(repo_path: str = ".") -> dict[str, Any]:
    """Report Fork Ops capability levels for a repository."""
    return cast(dict[str, Any], build_status_report(repo_path, include_config=True)["capability"])


@_tool
def fork_ops_migration_assessment(
    repo_path: str = ".",
    include_proposed_config_patch: bool = False,
) -> dict[str, Any]:
    """Run a read-only migration assessment for fork-related materials."""
    return assess_migration(repo_path, include_proposed_config_patch=include_proposed_config_patch)


@_tool
def fork_ops_equipment_migration_preflight(
    repo_path: str = ".",
    source_roots: list[str] | None = None,
    scan_profile: str = "custom",
) -> dict[str, Any]:
    """Build a read-only equipment migration preflight for onboarding."""
    _validate_bounded_object(source_roots or [], label="MCP source roots")
    return build_equipment_migration_preflight(
        repo_path,
        source_roots,
        scan_profile=scan_profile,
    )


@_tool
def fork_ops_migration_plan(repo_path: str = ".", scan_profile: str = "custom") -> dict[str, Any]:
    """Generate a non-mutating migration plan from fork-related materials."""
    return generate_migration_plan(repo_path, scan_profile=scan_profile)


@_tool
def fork_ops_migration_dry_run(
    repo_path: str | None = None,
    migration_plan: dict[str, Any] | None = None,
    scan_profile: str = "custom",
) -> dict[str, Any]:
    """Preview a migration plan without mutating the repository."""
    if migration_plan is not None and scan_profile != "custom":
        raise ForkOpsError("scan_profile cannot be used with migration_plan.")
    if migration_plan is not None:
        _validate_bounded_object(migration_plan, label="MCP migration plan")
    return dry_run_migration(repo_path, plan=migration_plan, scan_profile=scan_profile)


@_tool
def fork_ops_migration_execute(
    repo_path: str | None = None,
    migration_plan: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Apply a validated migration plan through guarded operations."""
    if repo_path is None or not repo_path.strip():
        raise ForkOpsError("Mutation requires an explicit non-empty repository path.")
    if migration_plan is not None:
        _validate_bounded_object(migration_plan, label="MCP migration plan")
    return execute_migration(repo_path, plan=migration_plan)


@_tool
def fork_ops_migration_blocker_resolution(
    workflow_output: dict[str, Any],
    blocker_code: str | None = None,
) -> dict[str, Any]:
    """Explain a migration blocker from structured workflow output."""
    _validate_bounded_object(workflow_output, label="MCP workflow output")
    return explain_migration_blocker(workflow_output, blocker_code)


@_tool
def fork_ops_migration_config_patch(repo_path: str = ".") -> dict[str, Any]:
    """Generate a non-mutating Fork Ops config proposal for migration planning."""
    return propose_migration_config_patch(repo_path)


@_tool
def fork_ops_schema() -> str:
    """Return the Fork Ops config JSON Schema."""
    return schema_json()


@_tool
def fork_ops_workflow_catalog() -> dict[str, Any]:
    """Return the Fork Ops intent-level workflow catalog."""
    return workflow_catalog()


@_tool
def fork_ops_workflow_migration_inventory(
    source_roots: list[str] | None = None,
    scan_profile: str = "custom",
) -> dict[str, Any]:
    """Build a read-only workflow migration inventory from source roots."""
    _validate_bounded_object(source_roots or [], label="MCP source roots")
    return build_workflow_migration_inventory(source_roots, scan_profile=scan_profile)


def mcp_healthcheck() -> dict[str, Any]:
    """Return lightweight startup evidence without opening the stdio MCP server."""
    return cast(
        dict[str, Any],
        operation_artifact(
            ArtifactKind.MCP_HEALTHCHECK,
            "mcp-healthcheck",
            {
                "mcp_dependency_available": mcp is not None,
                "missing_dependency": str(_MCP_IMPORT_ERROR) if _MCP_IMPORT_ERROR else None,
                "server": "Fork Ops",
                "tools": list(_REGISTERED_TOOL_IDS),
            },
        ),
    )


def main(argv: list[str] | None = None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    if argv == ["--health-check"]:
        print(json.dumps(mcp_healthcheck(), indent=2, sort_keys=True))
        return 0
    if mcp is None:
        raise SystemExit(
            "The Fork Ops MCP server requires the optional dependency: pip install 'fork-ops[mcp]'"
        ) from _MCP_IMPORT_ERROR
    mcp.run()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
