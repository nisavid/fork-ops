"""Fork Ops config loading, validation, reporting, and migration assessment."""

from __future__ import annotations

import copy
import hashlib
import json
import os
import re
import shlex
import subprocess
import sys
import tomllib
import uuid
from collections.abc import Callable, Iterable
from datetime import date, datetime, time
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from .schema import CAPABILITY_LEVELS, CONFIG_SCHEMA, Diagnostic, schema_diagnostics
from .workflow_catalog import WorkflowContract, workflow_contracts

CONFIG_RELATIVE_PATH = Path(".agents/fork-ops.toml")
SCHEMA_ARTIFACT_RELATIVE_PATHS = (
    Path("schema/fork-ops.schema.json"),
    Path("src/fork_ops/fork-ops.schema.json"),
)
MCP_TOOL_IDS = (
    "fork_ops_plugin_health",
    "fork_ops_config_read",
    "fork_ops_config_validate",
    "fork_ops_capability_report",
    "fork_ops_migration_assessment",
    "fork_ops_migration_plan",
    "fork_ops_migration_dry_run",
    "fork_ops_migration_execute",
    "fork_ops_migration_config_patch",
    "fork_ops_schema",
    "fork_ops_workflow_catalog",
    "fork_ops_workflow_migration_inventory",
)
PLUGIN_HEALTH_STATUS_VALUES = {
    "ready": "The readiness path was inspected and is usable.",
    "partial": "Some readiness paths are usable while others are unavailable or uninspectable.",
    "failed": "The readiness path was inspected and returned a blocking failure.",
    "unavailable": "The readiness path has no usable local control surface in this context.",
    "uninspectable": (
        "The readiness path needs an external or UI control surface that was not provided."
    ),
}
PLUGIN_HEALTH_CHECK_STATUSES = {"ready", "failed", "unavailable", "uninspectable"}
CommandRunner = Callable[[list[str], Path, float], subprocess.CompletedProcess[str]]
_CANDIDATE_FILE_SUFFIXES = {".json", ".md", ".toml", ".yaml", ".yml"}
_CANDIDATE_SCAN_SKIP_DIRS = {
    ".git",
    ".mypy_cache",
    ".ruff_cache",
    ".tox",
    ".venv",
    "__pycache__",
    "node_modules",
}
_FORK_SIGNAL_NEEDLES = (
    "baseline",
    "disabled",
    "fork",
    "force-push",
    "github releases",
    "merge-base",
    "release channel",
    "release tag",
    "review automation",
    "review bot",
    "stable release",
    "sync",
    "issue tracker",
    "prs",
    "pull request",
    "pull requests",
    "upstream",
    "upstream issue",
    "upstream issues",
    "upstream-main",
    "upstream-stable",
    "upstream track",
    "divergence",
    "code scanning",
    "review thread",
)
_WORKFLOW_INVENTORY_SIGNAL_NEEDLES = (
    ("workflow-catalog", ("workflow catalog", "fork ops workflow")),
    ("operator-intent", ("operator intent", "use when", "trigger phrases")),
    ("fork-local-authority", ("fork-local authority", "maintained fork")),
    (
        "upstream-sync",
        (
            "upstream sync",
            "sync policy",
            "sync baseline",
            "default baseline",
            "stable baseline",
            "origin/upstream",
        ),
    ),
    ("upstream-evidence", ("merge-base --is-ancestor", "upstream refs", "upstream track")),
    ("review-publication", ("pull request", "publication", "review preparation")),
    ("review-automation", ("review bot", "review thread", "code scanning")),
    ("mutation-gate", ("mutation gate", "local gate", "required checks")),
    ("procedure", ("procedure", "runbook")),
    ("policy", ("fork policy", "review policy", "publication policy", "sync policy")),
    ("handoff", ("handoff", "return contract")),
    ("blocker", ("blocker", "blocked")),
)
_WORKFLOW_SIGNAL_NEEDLE_MAP = dict(_WORKFLOW_INVENTORY_SIGNAL_NEEDLES)
_WORKFLOW_POLICY_PATH_QUALIFIERS = {
    "baseline",
    "branch",
    "closeout",
    "divergence",
    "fork",
    "merge",
    "publication",
    "pull",
    "release",
    "request",
    "review",
    "sync",
    "upstream",
}
SOURCE_MATERIAL_DISPOSITION_TYPES = (
    "extracted_into_config",
    "retained_as_fork_local_authority",
    "mapped_to_workflow_backlog",
    "irrelevant_to_fork_ops",
    "unsupported_extractor_shape",
    "needs_human_decision",
    "deferred_with_rationale",
)
MIGRATION_REVIEW_ARTIFACT_RELATIVE_PATH = "docs/agents/fork-ops-migration-review.md"


class ForkOpsError(RuntimeError):
    """Base error for expected Fork Ops failures."""


def find_config_path(repo_path: str | Path = ".") -> Path:
    return Path(repo_path).expanduser().resolve() / CONFIG_RELATIVE_PATH


def load_raw_config(repo_path: str | Path = ".", config_path: str | Path | None = None) -> str:
    path = Path(config_path).expanduser().resolve() if config_path else find_config_path(repo_path)
    try:
        return path.read_text()
    except FileNotFoundError as exc:
        raise ForkOpsError(f"Fork Ops config not found: {path}") from exc
    except OSError as exc:
        raise ForkOpsError(f"Fork Ops config read failed: {path}: {exc}") from exc


def parse_config_text(raw: str) -> dict[str, Any]:
    try:
        parsed = tomllib.loads(raw)
    except tomllib.TOMLDecodeError as exc:
        raise ForkOpsError(f"Fork Ops config TOML parse failed: {exc}") from exc
    if not isinstance(parsed, dict):
        raise ForkOpsError("Fork Ops config must parse to a TOML table.")
    return parsed


def load_config(
    repo_path: str | Path = ".",
    config_path: str | Path | None = None,
) -> dict[str, Any]:
    return parse_config_text(load_raw_config(repo_path, config_path))


def normalize_config(config: dict[str, Any]) -> dict[str, Any]:
    normalized = copy.deepcopy(config)
    repository = normalized.setdefault("repository", {})
    if isinstance(repository, dict) and repository.get("owner") and repository.get("name"):
        repository.setdefault("slug", f"{repository['owner']}/{repository['name']}")
    for key in (
        "fork_remotes",
        "upstreams",
        "release_channels",
        "upstream_tracks",
        "local_surfaces",
    ):
        normalized.setdefault(key, [])
    for key in (
        "authority",
        "change_targets",
        "sync_policy",
        "divergence_policy",
        "review_policy",
        "publication_policy",
        "local_gates",
        "portability",
    ):
        normalized.setdefault(key, {})
    return normalized


def _json_safe(value: Any) -> Any:
    if isinstance(value, dict):
        return {key: _json_safe(item) for key, item in value.items()}
    if isinstance(value, list | tuple):
        return [_json_safe(item) for item in value]
    if isinstance(value, datetime | date | time):
        return value.isoformat()
    return value


def build_plugin_health_report(
    plugin_root: str | Path | None = None,
    *,
    repo_root: str | Path | None = None,
    command_runner: CommandRunner | None = None,
    ui_visible: bool | None = None,
    timeout: float = 5.0,
) -> dict[str, Any]:
    root = _plugin_root(plugin_root)
    repo = _plugin_repo_root(root, repo_root)
    runner = command_runner or _default_command_runner

    checks: list[dict[str, Any]] = []

    checks.append(_plugin_registration_check(root, repo))
    checks.append(_skill_discovery_check(root))

    cli_check = _cli_execution_check(root, runner, timeout)
    checks.append(cli_check)
    cli_ready = cli_check["status"] == "ready"

    mcp_config_check, mcp_server = _mcp_config_resolution_check(root)
    checks.append(mcp_config_check)

    mcp_startup_check, mcp_startup_payload = _mcp_process_startup_check(
        root,
        mcp_config_check,
        mcp_server,
        runner,
        timeout,
        cli_ready=cli_ready,
    )
    checks.append(mcp_startup_check)
    checks.append(_mcp_tool_listing_check(mcp_startup_check, mcp_startup_payload, cli_ready))
    checks.append(_ui_visibility_check(ui_visible))

    summary = _plugin_health_summary(checks)
    return {
        "operation": "plugin-health",
        "model": "independent-readiness-paths",
        "plugin_root": str(root),
        "repo_root": str(repo),
        "status_values": dict(PLUGIN_HEALTH_STATUS_VALUES),
        "summary": summary,
        "checks": checks,
        "cli_fallback": _cli_fallback(cli_ready, root, repo),
        "mutation_policy": "read-only diagnostics; no repository mutation is performed",
    }


def _plugin_root(plugin_root: str | Path | None) -> Path:
    if plugin_root is not None:
        return Path(plugin_root).expanduser().resolve()
    return Path(__file__).resolve().parents[2]


def _plugin_repo_root(plugin_root: Path, repo_root: str | Path | None) -> Path:
    if repo_root is not None:
        return Path(repo_root).expanduser().resolve()
    if plugin_root.parent.name == "plugins":
        return plugin_root.parent.parent.resolve()
    return plugin_root.parent.resolve()


def _health_check(
    check_id: str,
    label: str,
    status: str,
    summary: str,
    *,
    evidence: dict[str, Any] | None = None,
    next_steps: tuple[str, ...] = (),
) -> dict[str, Any]:
    if status not in PLUGIN_HEALTH_CHECK_STATUSES:
        raise ValueError(f"Unknown plugin health status: {status}")
    return {
        "id": check_id,
        "label": label,
        "status": status,
        "summary": summary,
        "evidence": _json_safe(evidence or {}),
        "next_steps": list(next_steps),
    }


def _plugin_registration_check(plugin_root: Path, repo_root: Path) -> dict[str, Any]:
    marketplace_path = repo_root / ".agents/plugins/marketplace.json"
    if not marketplace_path.exists():
        return _health_check(
            "plugin_registration",
            "Plugin registration",
            "unavailable",
            "Plugin marketplace metadata was not found.",
            evidence={"path": str(marketplace_path)},
            next_steps=(
                "Install or register the Fork Ops plugin in the Codex plugin marketplace.",
                "Pass --repo-root if the plugin marketplace metadata lives outside this checkout.",
            ),
        )
    try:
        marketplace = json.loads(marketplace_path.read_text())
    except UnicodeDecodeError as exc:
        return _health_check(
            "plugin_registration",
            "Plugin registration",
            "failed",
            "Plugin marketplace metadata is not valid UTF-8 text.",
            evidence={"path": str(marketplace_path), "error": str(exc)},
            next_steps=("Repair .agents/plugins/marketplace.json text encoding.",),
        )
    except OSError as exc:
        return _health_check(
            "plugin_registration",
            "Plugin registration",
            "uninspectable",
            "Plugin marketplace metadata could not be read.",
            evidence={"path": str(marketplace_path), "error": str(exc)},
            next_steps=("Check file permissions for .agents/plugins/marketplace.json.",),
        )
    except json.JSONDecodeError as exc:
        return _health_check(
            "plugin_registration",
            "Plugin registration",
            "failed",
            "Plugin marketplace metadata is not valid JSON.",
            evidence={"path": str(marketplace_path), "error": str(exc)},
            next_steps=("Repair .agents/plugins/marketplace.json before trusting plugin state.",),
        )
    if not isinstance(marketplace, dict):
        return _health_check(
            "plugin_registration",
            "Plugin registration",
            "failed",
            "Plugin marketplace metadata must be a JSON object.",
            evidence={"path": str(marketplace_path), "json_type": type(marketplace).__name__},
            next_steps=("Repair .agents/plugins/marketplace.json plugin registration metadata.",),
        )

    plugins = marketplace.get("plugins")
    if not isinstance(plugins, list):
        return _health_check(
            "plugin_registration",
            "Plugin registration",
            "failed",
            "Plugin marketplace metadata does not contain a plugins list.",
            evidence={"path": str(marketplace_path)},
            next_steps=("Repair .agents/plugins/marketplace.json plugin registration metadata.",),
        )

    matching_plugins = [
        item for item in plugins if isinstance(item, dict) and item.get("name") == "fork-ops"
    ]
    if not matching_plugins:
        return _health_check(
            "plugin_registration",
            "Plugin registration",
            "failed",
            "Fork Ops is not registered in the plugin marketplace metadata.",
            evidence={"path": str(marketplace_path), "registered_plugin_count": len(plugins)},
            next_steps=("Register the local Fork Ops plugin before relying on Codex discovery.",),
        )

    matching_registrations: list[tuple[dict[str, Any], Path]] = []
    for plugin in matching_plugins:
        source = plugin.get("source")
        source_path = source.get("path") if isinstance(source, dict) else None
        if isinstance(source_path, str):
            matching_registrations.append((plugin, _resolve_health_path(repo_root, source_path)))

    if not matching_registrations:
        return _health_check(
            "plugin_registration",
            "Plugin registration",
            "failed",
            "Fork Ops plugin registration does not include a local source path.",
            evidence={"path": str(marketplace_path), "plugins": matching_plugins},
            next_steps=("Record a local source path for the Fork Ops plugin registration.",),
        )
    matched_registration = next(
        (
            (plugin, registered_path)
            for plugin, registered_path in matching_registrations
            if registered_path == plugin_root
        ),
        None,
    )
    if matched_registration is None:
        return _health_check(
            "plugin_registration",
            "Plugin registration",
            "failed",
            "Fork Ops plugin registration points at a different plugin root.",
            evidence={
                "path": str(marketplace_path),
                "registered_paths": [
                    str(registered_path) for _, registered_path in matching_registrations
                ],
                "plugin_root": str(plugin_root),
            },
            next_steps=("Update plugin marketplace metadata or pass the matching --plugin-root.",),
        )
    plugin, registered_path = matched_registration
    return _health_check(
        "plugin_registration",
        "Plugin registration",
        "ready",
        "Fork Ops is registered in the plugin marketplace metadata.",
        evidence={
            "path": str(marketplace_path),
            "registered_path": str(registered_path),
            "policy": plugin.get("policy", {}),
        },
    )


def _skill_discovery_check(plugin_root: Path) -> dict[str, Any]:
    skill_path = plugin_root / "skills/fork-ops/SKILL.md"
    if not skill_path.exists():
        return _health_check(
            "skill_discovery",
            "Skill discovery",
            "failed",
            "Fork Ops skill file is missing from the plugin package.",
            evidence={"path": str(skill_path)},
            next_steps=("Restore plugins/fork-ops/skills/fork-ops/SKILL.md.",),
        )
    try:
        skill_text = skill_path.read_text()
    except UnicodeDecodeError as exc:
        return _health_check(
            "skill_discovery",
            "Skill discovery",
            "failed",
            "Fork Ops skill file is not valid UTF-8 text.",
            evidence={"path": str(skill_path), "error": str(exc)},
            next_steps=("Repair plugins/fork-ops/skills/fork-ops/SKILL.md text encoding.",),
        )
    except OSError as exc:
        return _health_check(
            "skill_discovery",
            "Skill discovery",
            "uninspectable",
            "Fork Ops skill file could not be read.",
            evidence={"path": str(skill_path), "error": str(exc)},
            next_steps=("Check file permissions for the Fork Ops skill.",),
        )
    if not re.search(r"(?m)^name:\s*fork-ops\s*$", skill_text):
        return _health_check(
            "skill_discovery",
            "Skill discovery",
            "failed",
            "Fork Ops skill metadata does not declare name: fork-ops.",
            evidence={"path": str(skill_path)},
            next_steps=("Repair the Fork Ops skill frontmatter.",),
        )
    return _health_check(
        "skill_discovery",
        "Skill discovery",
        "ready",
        "Fork Ops skill metadata is present and names the skill.",
        evidence={"path": str(skill_path)},
    )


def _cli_execution_check(
    plugin_root: Path,
    command_runner: CommandRunner,
    timeout: float,
) -> dict[str, Any]:
    cli_script = plugin_root / "scripts/fork_ops_cli.py"
    command = [sys.executable, str(cli_script), "workflow", "catalog"]
    if not cli_script.exists():
        return _health_check(
            "cli_execution",
            "CLI execution",
            "unavailable",
            "Fork Ops CLI wrapper is not present in the plugin package.",
            evidence={"command": command, "path": str(cli_script)},
            next_steps=("Restore plugins/fork-ops/scripts/fork_ops_cli.py.",),
        )
    completed = command_runner(command, plugin_root, timeout)
    evidence = _command_evidence(command, completed)
    if completed.returncode != 0:
        return _health_check(
            "cli_execution",
            "CLI execution",
            "failed",
            "Fork Ops CLI workflow catalog probe failed.",
            evidence=evidence,
            next_steps=("Run fork-ops workflow catalog directly and inspect stderr.",),
        )
    try:
        payload = json.loads(completed.stdout)
    except json.JSONDecodeError as exc:
        evidence["error"] = str(exc)
        return _health_check(
            "cli_execution",
            "CLI execution",
            "failed",
            "Fork Ops CLI workflow catalog probe did not return JSON.",
            evidence=evidence,
            next_steps=("Run fork-ops workflow catalog directly and inspect stdout.",),
        )
    if not isinstance(payload, dict):
        evidence["json_type"] = type(payload).__name__
        return _health_check(
            "cli_execution",
            "CLI execution",
            "failed",
            "Fork Ops CLI workflow catalog probe did not return a JSON object.",
            evidence=evidence,
            next_steps=("Run fork-ops workflow catalog directly and inspect stdout.",),
        )
    if payload.get("operation") != "workflow-catalog":
        evidence["operation"] = payload.get("operation")
        return _health_check(
            "cli_execution",
            "CLI execution",
            "failed",
            "Fork Ops CLI probe did not return the workflow catalog operation.",
            evidence=evidence,
            next_steps=("Verify the fork-ops command resolves to this plugin checkout.",),
        )
    workflows = payload.get("workflows", [])
    if not isinstance(workflows, list):
        evidence["workflows_type"] = type(workflows).__name__
        return _health_check(
            "cli_execution",
            "CLI execution",
            "failed",
            "Fork Ops CLI workflow catalog probe returned malformed workflows metadata.",
            evidence=evidence,
            next_steps=("Run fork-ops workflow catalog directly and inspect stdout.",),
        )
    evidence["workflow_count"] = len(workflows)
    evidence.pop("stdout", None)
    evidence.pop("stderr", None)
    return _health_check(
        "cli_execution",
        "CLI execution",
        "ready",
        "Fork Ops CLI can return the workflow catalog.",
        evidence=evidence,
    )


def _mcp_config_resolution_check(
    plugin_root: Path,
) -> tuple[dict[str, Any], dict[str, Any] | None]:
    mcp_config_path = plugin_root / ".mcp.json"
    if not mcp_config_path.exists():
        return (
            _health_check(
                "mcp_config_resolution",
                "MCP config resolution",
                "unavailable",
                "Fork Ops MCP config was not found in the plugin package.",
                evidence={"path": str(mcp_config_path)},
                next_steps=("Restore plugins/fork-ops/.mcp.json or configure the MCP server.",),
            ),
            None,
        )
    try:
        mcp_config = json.loads(mcp_config_path.read_text())
    except UnicodeDecodeError as exc:
        return (
            _health_check(
                "mcp_config_resolution",
                "MCP config resolution",
                "failed",
                "Fork Ops MCP config is not valid UTF-8 text.",
                evidence={"path": str(mcp_config_path), "error": str(exc)},
                next_steps=("Repair plugins/fork-ops/.mcp.json text encoding.",),
            ),
            None,
        )
    except OSError as exc:
        return (
            _health_check(
                "mcp_config_resolution",
                "MCP config resolution",
                "uninspectable",
                "Fork Ops MCP config could not be read.",
                evidence={"path": str(mcp_config_path), "error": str(exc)},
                next_steps=("Check file permissions for plugins/fork-ops/.mcp.json.",),
            ),
            None,
        )
    except json.JSONDecodeError as exc:
        return (
            _health_check(
                "mcp_config_resolution",
                "MCP config resolution",
                "failed",
                "Fork Ops MCP config is not valid JSON.",
                evidence={"path": str(mcp_config_path), "error": str(exc)},
                next_steps=("Repair plugins/fork-ops/.mcp.json before starting MCP.",),
            ),
            None,
        )
    if not isinstance(mcp_config, dict):
        return (
            _health_check(
                "mcp_config_resolution",
                "MCP config resolution",
                "failed",
                "Fork Ops MCP config must be a JSON object.",
                evidence={"path": str(mcp_config_path), "json_type": type(mcp_config).__name__},
                next_steps=("Repair plugins/fork-ops/.mcp.json before starting MCP.",),
            ),
            None,
        )
    servers = mcp_config.get("mcpServers")
    server = servers.get("fork-ops") if isinstance(servers, dict) else None
    if not isinstance(server, dict):
        return (
            _health_check(
                "mcp_config_resolution",
                "MCP config resolution",
                "failed",
                "Fork Ops MCP config does not define mcpServers.fork-ops.",
                evidence={"path": str(mcp_config_path)},
                next_steps=("Add an mcpServers.fork-ops entry to plugins/fork-ops/.mcp.json.",),
            ),
            None,
        )
    return (
        _health_check(
            "mcp_config_resolution",
            "MCP config resolution",
            "ready",
            "Fork Ops MCP config resolves the fork-ops server entry.",
            evidence={
                "path": str(mcp_config_path),
                "command": server.get("command"),
                "args": server.get("args", []),
                "cwd": server.get("cwd", "."),
            },
        ),
        server,
    )


def _mcp_process_startup_check(
    plugin_root: Path,
    config_check: dict[str, Any],
    server: dict[str, Any] | None,
    command_runner: CommandRunner,
    timeout: float,
    *,
    cli_ready: bool,
) -> tuple[dict[str, Any], dict[str, Any] | None]:
    if config_check["status"] != "ready" or server is None:
        return (
            _health_check(
                "mcp_process_startup",
                "MCP process startup",
                "unavailable",
                "MCP startup was not probed because MCP config is not ready.",
                evidence={"blocked_by": "mcp_config_resolution"},
                next_steps=_mcp_failure_next_steps(cli_ready),
            ),
            None,
        )

    command_value = server.get("command")
    args_value = server.get("args", [])
    if not isinstance(command_value, str) or not isinstance(args_value, (list, tuple)) or not all(
        isinstance(item, str) for item in args_value
    ):
        return (
            _health_check(
                "mcp_process_startup",
                "MCP process startup",
                "failed",
                "MCP server command is not a string command with string args.",
                evidence={"command": command_value, "args": args_value},
                next_steps=_mcp_failure_next_steps(cli_ready),
            ),
            None,
        )
    cwd_value = server.get("cwd", ".")
    if not isinstance(cwd_value, str):
        cwd_value = "."
    cwd = _resolve_health_path(plugin_root, cwd_value)
    command = [command_value, *args_value, "--health-check"]
    completed = command_runner(command, cwd, timeout)
    evidence = _command_evidence(command, completed)
    evidence["cwd"] = str(cwd)
    if completed.returncode != 0:
        return (
            _health_check(
                "mcp_process_startup",
                "MCP process startup",
                "failed",
                "Fork Ops MCP health-check process failed.",
                evidence=evidence,
                next_steps=_mcp_failure_next_steps(cli_ready),
            ),
            None,
        )
    try:
        payload = json.loads(completed.stdout)
    except json.JSONDecodeError as exc:
        evidence["error"] = str(exc)
        return (
            _health_check(
                "mcp_process_startup",
                "MCP process startup",
                "failed",
                "Fork Ops MCP health-check process did not return JSON.",
                evidence=evidence,
                next_steps=_mcp_failure_next_steps(cli_ready),
            ),
            None,
        )
    if not isinstance(payload, dict):
        evidence["json_type"] = type(payload).__name__
        return (
            _health_check(
                "mcp_process_startup",
                "MCP process startup",
                "failed",
                "Fork Ops MCP health-check process did not return a JSON object.",
                evidence=evidence,
                next_steps=_mcp_failure_next_steps(cli_ready),
            ),
            None,
        )
    if payload.get("server") != "Fork Ops":
        evidence["server"] = payload.get("server")
        return (
            _health_check(
                "mcp_process_startup",
                "MCP process startup",
                "failed",
                "Fork Ops MCP health-check process returned an unexpected server name.",
                evidence=evidence,
                next_steps=_mcp_failure_next_steps(cli_ready),
            ),
            None,
        )
    mcp_dependency_available = payload.get("mcp_dependency_available")
    evidence["mcp_dependency_available"] = mcp_dependency_available
    if not isinstance(mcp_dependency_available, bool):
        evidence["missing_dependency"] = payload.get("missing_dependency")
        return (
            _health_check(
                "mcp_process_startup",
                "MCP process startup",
                "failed",
                "Fork Ops MCP health-check process returned malformed dependency metadata.",
                evidence=evidence,
                next_steps=_mcp_failure_next_steps(cli_ready),
            ),
            None,
        )
    if not mcp_dependency_available:
        evidence["missing_dependency"] = payload.get("missing_dependency")
        return (
            _health_check(
                "mcp_process_startup",
                "MCP process startup",
                "failed",
                "Fork Ops MCP optional dependency is not installed.",
                evidence=evidence,
                next_steps=_mcp_failure_next_steps(cli_ready),
            ),
            None,
        )
    evidence["server"] = payload["server"]
    evidence.pop("stdout", None)
    evidence.pop("stderr", None)
    return (
        _health_check(
            "mcp_process_startup",
            "MCP process startup",
            "ready",
            "Fork Ops MCP health-check process starts successfully.",
            evidence=evidence,
        ),
        payload,
    )


def _mcp_tool_listing_check(
    startup_check: dict[str, Any],
    startup_payload: dict[str, Any] | None,
    cli_ready: bool,
) -> dict[str, Any]:
    if startup_check["status"] != "ready" or startup_payload is None:
        return _health_check(
            "mcp_tool_listing",
            "MCP tool listing",
            "unavailable",
            "MCP tool listing was not inspected because MCP startup is not ready.",
            evidence={"blocked_by": "mcp_process_startup"},
            next_steps=_mcp_failure_next_steps(cli_ready),
        )
    tools = startup_payload.get("tools")
    if not isinstance(tools, list) or not all(isinstance(item, str) for item in tools):
        return _health_check(
            "mcp_tool_listing",
            "MCP tool listing",
            "failed",
            "MCP health-check output does not include a string tool list.",
            evidence={"tools": tools},
            next_steps=_mcp_failure_next_steps(cli_ready),
        )
    missing_tools = [tool for tool in MCP_TOOL_IDS if tool not in tools]
    if missing_tools:
        return _health_check(
            "mcp_tool_listing",
            "MCP tool listing",
            "failed",
            "MCP health-check output is missing expected Fork Ops tools.",
            evidence={"tools": tools, "missing_tools": missing_tools},
            next_steps=_mcp_failure_next_steps(cli_ready),
        )
    return _health_check(
        "mcp_tool_listing",
        "MCP tool listing",
        "ready",
        "Fork Ops MCP health-check output lists the expected tools.",
        evidence={"tools": tools},
    )


def _ui_visibility_check(ui_visible: bool | None) -> dict[str, Any]:
    if ui_visible is None:
        return _health_check(
            "ui_visibility",
            "UI visibility",
            "uninspectable",
            "No Codex UI visibility control surface was provided.",
            next_steps=(
                "Inspect the Codex plugin UI when a UI automation or screenshot "
                "surface is available.",
            ),
        )
    if ui_visible:
        return _health_check(
            "ui_visibility",
            "UI visibility",
            "ready",
            "The provided UI control surface reports Fork Ops as visible.",
        )
    return _health_check(
        "ui_visibility",
        "UI visibility",
        "failed",
        "The provided UI control surface reports Fork Ops as not visible.",
        next_steps=("Open the Codex plugin UI and verify the Fork Ops plugin registration.",),
    )


def _plugin_health_summary(checks: list[dict[str, Any]]) -> dict[str, Any]:
    counts = {status: 0 for status in PLUGIN_HEALTH_STATUS_VALUES}
    for check in checks:
        counts[check["status"]] += 1
    if counts["failed"]:
        status = "failed"
    elif counts["ready"] == len(checks):
        status = "ready"
    elif counts["ready"] == 0 and counts["uninspectable"] and not (
        counts["failed"] or counts["unavailable"]
    ):
        status = "uninspectable"
    else:
        status = "partial"
    return {
        "status": status,
        "ready_count": counts["ready"],
        "failed_count": counts["failed"],
        "unavailable_count": counts["unavailable"],
        "uninspectable_count": counts["uninspectable"],
        "check_count": len(checks),
    }


def _cli_fallback(cli_ready: bool, plugin_root: Path, repo_root: Path) -> dict[str, Any]:
    return {
        "usable": cli_ready,
        "command": "uv run --package fork-ops fork-ops workflow catalog",
        "plugin_health_command": (
            "uv run --package fork-ops fork-ops plugin health "
            f"--plugin-root {shlex.quote(str(plugin_root))} "
            f"--repo-root {shlex.quote(str(repo_root))}"
        ),
        "note": (
            "Use CLI commands while MCP or UI surfaces are unavailable."
            if cli_ready
            else "CLI fallback is not usable until the CLI execution path is ready."
        ),
    }


def _mcp_failure_next_steps(cli_ready: bool) -> tuple[str, ...]:
    steps = [
        "Inspect plugins/fork-ops/.mcp.json and the fork-ops-mcp health-check command.",
        "Run uv run --package fork-ops fork-ops plugin health for the full diagnostic report.",
    ]
    if cli_ready:
        steps.append("Use uv run --package fork-ops fork-ops workflow catalog as a CLI fallback.")
    return tuple(steps)


def _command_evidence(
    command: list[str],
    completed: subprocess.CompletedProcess[str],
) -> dict[str, Any]:
    return {
        "command": command,
        "exit_code": completed.returncode,
        "stdout": _short_output(completed.stdout),
        "stderr": _short_output(completed.stderr),
    }


def _short_output(value: str | bytes | None, limit: int = 4000) -> str:
    if value is None:
        return ""
    if isinstance(value, bytes):
        value = value.decode(errors="replace")
    if len(value) <= limit:
        return value
    return value[:limit] + "...<truncated>"


def _resolve_health_path(root: Path, value: str) -> Path:
    path = Path(value).expanduser()
    if not path.is_absolute():
        path = root / path
    return path.resolve()


def _default_command_runner(
    command: list[str],
    cwd: Path,
    timeout: float,
) -> subprocess.CompletedProcess[str]:
    try:
        return subprocess.run(
            command,
            cwd=cwd,
            text=True,
            encoding="utf-8",
            errors="replace",
            capture_output=True,
            timeout=timeout,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        return subprocess.CompletedProcess(
            command,
            124,
            _short_output(exc.stdout),
            _short_output(exc.stderr) or str(exc),
        )
    except OSError as exc:
        return subprocess.CompletedProcess(command, 127, "", str(exc))


def build_status_report(
    repo_path: str | Path = ".",
    config_path: str | Path | None = None,
    include_config: bool = True,
) -> dict[str, Any]:
    repo = Path(repo_path).expanduser().resolve()
    config_file = (
        Path(config_path).expanduser().resolve() if config_path else find_config_path(repo)
    )
    diagnostics: list[Diagnostic] = []

    if not config_file.exists():
        diagnostics.append(
            Diagnostic(
                severity="error",
                code="config.missing",
                message=f"Fork Ops config not found at {config_file}",
                path=str(CONFIG_RELATIVE_PATH),
            )
        )
        return {
            "repo_path": str(repo),
            "config_path": str(config_file),
            "config_exists": False,
            "capability": capability_report({}, diagnostics),
            "diagnostics": [item.to_dict() for item in diagnostics],
        }

    try:
        config = parse_config_text(load_raw_config(repo, config_file))
    except ForkOpsError as exc:
        diagnostics.append(
            Diagnostic(
                severity="error",
                code="config.parse_failed",
                message=str(exc),
                path=str(CONFIG_RELATIVE_PATH),
            )
        )
        return {
            "repo_path": str(repo),
            "config_path": str(config_file),
            "config_exists": True,
            "capability": capability_report({}, diagnostics),
            "diagnostics": [item.to_dict() for item in diagnostics],
        }

    normalized = normalize_config(config)
    diagnostics.extend(schema_diagnostics(normalized))
    diagnostics.extend(reference_diagnostics(normalized))
    diagnostics.extend(git_diagnostics(repo, normalized))

    payload: dict[str, Any] = {
        "repo_path": str(repo),
        "config_path": str(config_file),
        "config_exists": True,
        "schema_version": normalized.get("schema_version"),
        "capability": capability_report(normalized, diagnostics),
        "diagnostics": [item.to_dict() for item in diagnostics],
    }
    if include_config:
        payload["config"] = _json_safe(normalized)
    return payload


def capability_report(
    config: dict[str, Any],
    diagnostics: Iterable[Diagnostic] | None = None,
) -> dict[str, Any]:
    diagnostics = list(diagnostics or [])
    blocking_errors = [item for item in diagnostics if item.severity == "error"]
    levels: dict[str, Any] = {}
    highest: str | None = None

    for level in CAPABILITY_LEVELS:
        missing = list(_missing_requirements(config, level))
        if blocking_errors:
            available = False
        else:
            available = not missing
        levels[level] = {
            "available": available,
            "missing": missing,
            "enables": _level_enables(level),
        }
        if available:
            highest = level

    return {
        "highest_available": highest,
        "levels": levels,
    }


def reference_diagnostics(config: dict[str, Any]) -> list[Diagnostic]:
    diagnostics: list[Diagnostic] = []
    upstreams = _section_items(config, "upstreams")
    release_channels = _section_items(config, "release_channels")
    upstream_tracks = _section_items(config, "upstream_tracks")
    upstream_ids = _ids(upstreams)
    release_channel_ids = _ids(release_channels)
    track_ids = _ids(upstream_tracks)

    diagnostics.extend(_duplicate_id_diagnostics("upstreams", upstreams))
    diagnostics.extend(_duplicate_id_diagnostics("release_channels", release_channels))
    diagnostics.extend(_duplicate_id_diagnostics("upstream_tracks", upstream_tracks))

    for index, channel in enumerate(release_channels):
        if not isinstance(channel, dict):
            continue
        upstream = channel.get("upstream")
        if upstream and upstream not in upstream_ids:
            diagnostics.append(
                Diagnostic(
                    severity="error",
                    code="reference.unknown_upstream",
                    message=(
                        f"Release channel '{channel.get('id')}' references unknown "
                        f"upstream '{upstream}'."
                    ),
                    path=f"release_channels.{index}.upstream",
                )
            )

    for index, track in enumerate(upstream_tracks):
        if not isinstance(track, dict):
            continue
        upstream = track.get("upstream")
        if upstream and upstream not in upstream_ids:
            diagnostics.append(
                Diagnostic(
                    severity="error",
                    code="reference.unknown_upstream",
                    message=(
                        f"Upstream Track '{track.get('id')}' references unknown "
                        f"upstream '{upstream}'."
                    ),
                    path=f"upstream_tracks.{index}.upstream",
                )
            )
        if (
            track.get("source_type") == "release_channel"
            and track.get("source") not in release_channel_ids
        ):
            diagnostics.append(
                Diagnostic(
                    severity="error",
                    code="reference.unknown_release_channel",
                    message=(
                        f"Upstream Track '{track.get('id')}' references unknown release channel "
                        f"'{track.get('source')}'."
                    ),
                    path=f"upstream_tracks.{index}.source",
                )
            )

    sync_policy = _mapping_section(config, "sync_policy")
    default_baseline = sync_policy.get("default_sync_baseline")
    if default_baseline and default_baseline not in track_ids:
        diagnostics.append(
            Diagnostic(
                severity="error",
                code="reference.unknown_upstream_track",
                message=(
                    "sync_policy.default_sync_baseline references unknown "
                    f"Upstream Track '{default_baseline}'."
                ),
                path="sync_policy.default_sync_baseline",
            )
        )

    return diagnostics


def git_diagnostics(repo: Path, config: dict[str, Any]) -> list[Diagnostic]:
    diagnostics: list[Diagnostic] = []
    if not _git_ok(repo, "rev-parse", "--is-inside-work-tree"):
        diagnostics.append(
            Diagnostic(
                severity="warning",
                code="git.unavailable",
                message=f"{repo} is not available as a Git worktree for live checks.",
            )
        )
        return diagnostics

    for index, remote in enumerate(_section_items(config, "fork_remotes")):
        if not isinstance(remote, dict):
            continue
        _check_remote_url(repo, remote, f"fork_remotes.{index}", diagnostics)
    for index, upstream in enumerate(_section_items(config, "upstreams")):
        if not isinstance(upstream, dict):
            continue
        _check_remote_url(repo, upstream, f"upstreams.{index}", diagnostics)
    for index, track in enumerate(_section_items(config, "upstream_tracks")):
        if not isinstance(track, dict):
            continue
        ref = track.get("ref")
        if (
            isinstance(ref, str)
            and ref.startswith("refs/")
            and not _git_ok(repo, "show-ref", "--verify", ref)
        ):
            diagnostics.append(
                Diagnostic(
                    severity="warning",
                    code="git.ref_missing",
                    message=f"Configured Upstream Track ref does not exist locally: {ref}",
                    path=f"upstream_tracks.{index}.ref",
                )
            )

    return diagnostics


def assess_migration(
    repo_path: str | Path = ".",
    include_proposed_config_patch: bool = False,
) -> dict[str, Any]:
    repo = Path(repo_path).expanduser().resolve()
    candidates = _migration_candidates(repo)
    assessment: dict[str, Any] = {
        "repo_path": str(repo),
        "mode": "read-only",
        "summary": {
            "candidate_count": len(candidates),
            "has_fork_ops_config": (repo / CONFIG_RELATIVE_PATH).exists(),
        },
        "candidates": candidates,
        "next_actions": [
            "Review candidates before creating a migration plan.",
            "Generate a proposed config patch only when the migration plan needs one.",
            "Prefer semantic config writes over raw TOML edits.",
            "Run a migration dry run before migration execution once those surfaces exist.",
        ],
    }
    if include_proposed_config_patch:
        assessment["proposed_config_patch"] = propose_migration_config_patch(repo, candidates)
    return assessment


def propose_migration_config_patch(
    repo_path: str | Path = ".",
    candidates: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    repo = Path(repo_path).expanduser().resolve()
    migration_candidates = candidates if candidates is not None else _migration_candidates(repo)
    proposed_config = _build_proposed_config(repo, migration_candidates)
    toml = _toml_dumps(proposed_config)
    parsed = parse_config_text(toml)
    diagnostics = (
        _migration_proposal_diagnostics(_flatten_facts(migration_candidates))
        + schema_diagnostics(parsed)
        + reference_diagnostics(normalize_config(parsed))
    )
    return {
        "mode": "non-mutating",
        "purpose": "migration plan input",
        "target_path": str(CONFIG_RELATIVE_PATH),
        "operation": "create" if not find_config_path(repo).exists() else "review-and-merge",
        "requires_review": True,
        "config": proposed_config,
        "toml": toml,
        "contract_tags": ["toml_renderer.flat_config_contract"],
        "diagnostics": [item.to_dict() for item in diagnostics],
        "evidence": _proposal_evidence(migration_candidates),
        "limitations": [
            "This deterministic proposal is not a migration execution.",
            "Review against source materials before applying.",
            (
                "Config proposal TOML is limited to top-level scalar fields, "
                "top-level tables, and arrays of flat tables."
            ),
            (
                "Escalate to an LLM-based migration planner if important source "
                "semantics are not represented."
            ),
        ],
    }


def generate_migration_plan(
    repo_path: str | Path = ".",
    candidates: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    repo = Path(repo_path).expanduser().resolve()
    migration_candidates = candidates if candidates is not None else _migration_candidates(repo)
    proposed_config_patch = propose_migration_config_patch(repo, migration_candidates)
    evidence = _migration_plan_evidence(migration_candidates)
    retained_source_materials = _retained_source_materials(migration_candidates)
    migration_map = _migration_map(migration_candidates, proposed_config_patch)
    migration_review_artifact = _migration_review_artifact(migration_map)
    blockers = _migration_plan_blockers(migration_candidates, proposed_config_patch)
    return {
        "repo_path": str(repo),
        "mode": "non-mutating",
        "operation": "migration-plan",
        "requires_review": True,
        "source_material_disposition_types": list(SOURCE_MATERIAL_DISPOSITION_TYPES),
        "summary": {
            "candidate_count": len(migration_candidates),
            "evidence_source_count": len(evidence),
            "migration_map_entry_count": len(migration_map),
            "review_artifact_entry_count": len(migration_review_artifact["entries"]),
            "retained_source_material_count": len(retained_source_materials),
            "blocker_count": len(blockers),
            "semantic_coverage": _semantic_coverage_status(blockers),
        },
        "evidence": evidence,
        "migration_map": migration_map,
        "migration_review_artifact": migration_review_artifact,
        "proposed_config_patch": proposed_config_patch,
        "retained_source_materials": retained_source_materials,
        "deferred_removals": _deferred_removals(retained_source_materials),
        "blockers": blockers,
        "required_review": _migration_plan_required_review(blockers),
        "validation_requirements": _migration_plan_validation_requirements(),
        "limitations": [
            "This migration plan is non-mutating and does not apply config or edit source files.",
            "Source-material removal is not implemented; source materials remain preserved.",
            "Review semantic coverage before replacing or deleting fork-local authority.",
        ],
        "next_actions": [
            "Review proposed_config_patch against evidence.",
            "Review migration_review_artifact for durable decisions outside fork ops config.",
            "Resolve blockers before migration dry run.",
            "Run validation requirements after any manual application of the proposed config.",
        ],
    }


def build_workflow_migration_inventory(
    source_roots: Iterable[str | Path] | str | Path | None = None,
) -> dict[str, Any]:
    roots = _workflow_inventory_roots(source_roots)
    contracts = {item.id: item for item in workflow_contracts()}
    unresolvable_roots = [str(root) for root in roots if not root.exists()]
    entries: list[dict[str, Any]] = []
    seen_paths: set[Path] = set()
    for root in roots:
        for path in _iter_workflow_inventory_paths(root):
            resolved_path = path.resolve()
            if resolved_path in seen_paths:
                continue
            seen_paths.add(resolved_path)
            entry = _workflow_inventory_entry(root, path, contracts)
            if entry:
                entries.append(entry)
    entries.sort(key=lambda item: (item["source_root"], item["source_path"]))
    catalog_evidence = _workflow_catalog_evidence(entries, contracts)
    backlog_candidates = _workflow_backlog_candidates(entries)
    return {
        "operation": "workflow-migration-inventory",
        "mode": "read-only",
        "source_roots": [str(root) for root in roots],
        "summary": {
            "source_root_count": len(roots),
            "entry_count": len(entries),
            "catalog_evidence_group_count": len(catalog_evidence),
            "backlog_candidate_count": len(backlog_candidates),
            "unresolvable_source_root_count": len(unresolvable_roots),
        },
        "entries": entries,
        "catalog_evidence": catalog_evidence,
        "backlog_candidates": backlog_candidates,
        "unresolvable_source_roots": unresolvable_roots,
        "mutation_policy": "no source roots are modified",
        "limitations": [
            "This inventory classifies source material for workflow migration only.",
            "Backlog candidates are not implemented workflow promises.",
            "Fork-local authority remains owned by the maintained fork that contains it.",
        ],
    }


def dry_run_migration(
    repo_path: str | Path = ".",
    plan: dict[str, Any] | None = None,
) -> dict[str, Any]:
    migration_plan = plan if plan is not None else generate_migration_plan(repo_path)
    return dry_run_migration_plan(migration_plan)


def dry_run_migration_plan(
    plan: dict[str, Any],
    repo_path: str | Path | None = None,
) -> dict[str, Any]:
    if not isinstance(plan, dict):
        raise ForkOpsError("Migration dry run requires a migration plan object.")
    if plan.get("operation") != "migration-plan":
        raise ForkOpsError("Migration dry run input must have operation='migration-plan'.")

    proposed_config_patch = plan.get("proposed_config_patch", {})
    if not isinstance(proposed_config_patch, dict):
        raise ForkOpsError("Migration dry run input has malformed proposed_config_patch.")

    normalized_repo_path = _dry_run_repo_path(plan, repo_path)
    file_edits = _dry_run_file_edits(proposed_config_patch)
    config_changes = _dry_run_config_changes(proposed_config_patch)
    migration_map = _require_plan_list(plan, "migration_map")
    migration_review_artifact = _require_migration_review_artifact(plan)
    retained_materials = _require_plan_list(plan, "retained_source_materials")
    deferred_removals = _require_plan_list(plan, "deferred_removals")
    blocked_steps = _dry_run_blocked_steps(plan)
    blocked_steps.extend(_proposed_config_patch_consistency_blockers(proposed_config_patch))
    blocked_steps.extend(
        _migration_execution_blockers(
            Path(normalized_repo_path),
            {"file_edits": file_edits},
        )
    )
    blocked_steps.extend(
        _retained_source_material_blockers(Path(normalized_repo_path), retained_materials)
    )
    expected_verification_commands = _require_plan_list(plan, "validation_requirements")
    if not expected_verification_commands:
        blocked_steps.append(
            {
                "code": "migration_execution.validation_requirements_missing",
                "step": "verify_migration_execution",
                "source": "migration_plan",
                "message": "Migration execution requires at least one validation requirement.",
            }
        )
    else:
        blocked_steps.extend(_validation_requirement_blockers(expected_verification_commands))
    return {
        "repo_path": normalized_repo_path,
        "mode": "non-mutating",
        "operation": "migration-dry-run",
        "plan_operation": plan.get("operation"),
        "can_execute": not blocked_steps,
        "summary": {
            "file_edit_count": len(file_edits),
            "config_change_count": len(config_changes),
            "migration_map_entry_count": len(migration_map),
            "review_artifact_entry_count": len(
                _review_artifact_entries(migration_review_artifact)
            ),
            "retained_material_count": len(retained_materials),
            "blocked_step_count": len(blocked_steps),
            "verification_command_count": len(expected_verification_commands),
        },
        "file_edits": file_edits,
        "config_changes": config_changes,
        "migration_map": migration_map,
        "migration_review_artifact": migration_review_artifact,
        "retained_materials": retained_materials,
        "deferred_removals": deferred_removals,
        "blocked_steps": blocked_steps,
        "expected_verification_commands": expected_verification_commands,
        "limitations": [
            "This migration dry run is non-mutating and does not apply config or edit files.",
            "Source-material removal is not implemented; source materials remain preserved.",
        ],
        "next_actions": [
            "Review file_edits and config_changes against the migration plan evidence.",
            "Review migration_review_artifact before treating retained authority as covered.",
            "Resolve or explicitly waive blocked_steps before migration execution.",
            (
                "Run expected_verification_commands after migration execution applies changes."
            ),
        ],
    }


def execute_migration(
    repo_path: str | Path = ".",
    plan: dict[str, Any] | None = None,
) -> dict[str, Any]:
    migration_plan = plan if plan is not None else generate_migration_plan(repo_path)
    if plan is None:
        return execute_migration_plan(migration_plan)
    mismatch_result = _repo_path_mismatch_result(migration_plan, repo_path)
    if mismatch_result is not None:
        return mismatch_result
    return execute_migration_plan(migration_plan)


def execute_migration_plan(
    plan: dict[str, Any],
    repo_path: str | Path | None = None,
) -> dict[str, Any]:
    mismatch_result = _repo_path_mismatch_result(plan, repo_path)
    if mismatch_result is not None:
        return mismatch_result
    preview = dry_run_migration_plan(plan, repo_path)
    repo = Path(preview["repo_path"]).expanduser().resolve()
    preview_blockers = _require_preview_list(preview, "blocked_steps")
    if preview_blockers:
        return _migration_execution_result(
            repo=repo,
            preview=preview,
            status="blocked",
            applied_edits=[],
            skipped_edits=_skipped_preview_edits(preview, "blocked_steps_present"),
            blockers=preview_blockers,
            verification_results=[],
        )

    applied_edits, apply_blockers = _apply_migration_file_edits(
        repo,
        _require_preview_list(preview, "file_edits"),
    )
    if apply_blockers:
        return _migration_execution_result(
            repo=repo,
            preview=preview,
            status="blocked",
            applied_edits=applied_edits,
            skipped_edits=_skipped_preview_edits(preview, "write_guard_blocked"),
            blockers=apply_blockers,
            verification_results=[],
        )
    skipped_edits = _preserved_source_materials(preview)
    verification_results, verification_blockers = _verify_migration_execution(repo, preview)
    status = "applied" if not verification_blockers else "verification_failed"
    return _migration_execution_result(
        repo=repo,
        preview=preview,
        status=status,
        applied_edits=applied_edits,
        skipped_edits=skipped_edits,
        blockers=verification_blockers,
        verification_results=verification_results,
    )


def _repo_path_mismatch_result(
    migration_plan: dict[str, Any],
    repo_path: str | Path | None,
) -> dict[str, Any] | None:
    if migration_plan.get("operation") != "migration-plan":
        return None
    if repo_path is None or str(repo_path) == "":
        return None
    plan_repo_path = _dry_run_repo_path(migration_plan, None)
    requested_repo_path = str(Path(repo_path).expanduser().resolve())
    if requested_repo_path == plan_repo_path:
        return None
    return _migration_execution_result(
        repo=Path(requested_repo_path),
        preview={"plan_operation": migration_plan.get("operation")},
        status="blocked",
        applied_edits=[],
        skipped_edits=[],
        blockers=[
            {
                "code": "migration_execution.repo_path_mismatch",
                "message": (
                    "Supplied migration plan repo_path does not match the requested "
                    "execution repo_path."
                ),
                "plan_repo_path": plan_repo_path,
                "requested_repo_path": requested_repo_path,
            }
        ],
        verification_results=[],
    )


def _dry_run_repo_path(plan: dict[str, Any], repo_path: str | Path | None) -> str:
    raw_path = repo_path if repo_path is not None else plan.get("repo_path")
    if not isinstance(raw_path, str | Path) or not str(raw_path):
        raise ForkOpsError("Migration dry run input has malformed repo_path.")
    return str(Path(raw_path).expanduser().resolve())


def _dry_run_file_edits(proposed_config_patch: dict[str, Any]) -> list[dict[str, Any]]:
    target_path = proposed_config_patch.get("target_path")
    if not isinstance(target_path, str) or not target_path:
        raise ForkOpsError(
            "Migration dry run input has malformed proposed_config_patch.target_path."
        )
    target_path = _normalize_migration_relative_path(target_path)
    operation = proposed_config_patch.get("operation", "review-and-merge")
    if not isinstance(operation, str):
        raise ForkOpsError("Migration dry run input has malformed proposed_config_patch.operation.")
    content = proposed_config_patch.get("toml", "")
    if not isinstance(content, str):
        raise ForkOpsError("Migration dry run input has malformed proposed_config_patch.toml.")
    return [
        {
            "path": target_path,
            "action": operation,
            "status": "preview-only",
            "content_kind": "fork-ops-config",
            "content": content,
            "diagnostics": _require_patch_list(proposed_config_patch, "diagnostics"),
        }
    ]


def _dry_run_config_changes(proposed_config_patch: dict[str, Any]) -> list[dict[str, Any]]:
    target_path = proposed_config_patch.get("target_path")
    if not isinstance(target_path, str) or not target_path:
        raise ForkOpsError(
            "Migration dry run input has malformed proposed_config_patch.target_path."
        )
    target_path = _normalize_migration_relative_path(target_path)
    operation = proposed_config_patch.get("operation", "review-and-merge")
    if not isinstance(operation, str):
        raise ForkOpsError("Migration dry run input has malformed proposed_config_patch.operation.")
    config = proposed_config_patch.get("config", {})
    if not isinstance(config, dict):
        raise ForkOpsError("Migration dry run input has malformed proposed_config_patch.config.")
    return [
        {
            "target_path": target_path,
            "action": operation,
            "requires_review": bool(proposed_config_patch.get("requires_review", True)),
            "config": copy.deepcopy(config),
            "diagnostics": _require_patch_list(proposed_config_patch, "diagnostics"),
        }
    ]


def _proposed_config_patch_consistency_blockers(
    proposed_config_patch: dict[str, Any],
) -> list[dict[str, Any]]:
    toml = proposed_config_patch.get("toml", "")
    config = proposed_config_patch.get("config", {})
    if not isinstance(toml, str) or not isinstance(config, dict):
        return []
    try:
        parsed_config = parse_config_text(toml)
    except ForkOpsError as exc:
        return [
            {
                "code": "migration_execution.proposed_config_patch_invalid_toml",
                "step": "apply_migration_file_edits",
                "source": "migration_plan",
                "message": f"Proposed config patch TOML cannot be parsed: {exc}",
            }
        ]
    if parsed_config == config:
        return []
    return [
        {
            "code": "migration_execution.proposed_config_patch_mismatch",
            "step": "apply_migration_file_edits",
            "source": "migration_plan",
            "message": (
                "Proposed config patch TOML must match proposed_config_patch.config "
                "before migration execution."
            ),
        }
    ]


def _dry_run_blocked_steps(plan: dict[str, Any]) -> list[dict[str, Any]]:
    blocked_steps: list[dict[str, Any]] = []
    for blocker in _require_plan_list(plan, "blockers"):
        blocker.setdefault("step", "review_migration_plan")
        blocker.setdefault("source", "migration_plan")
        blocked_steps.append(blocker)
    return blocked_steps


def _require_plan_list(plan: dict[str, Any], key: str) -> list[dict[str, Any]]:
    if key not in plan:
        raise ForkOpsError(f"Migration dry run input is missing {key}.")
    value = plan[key]
    if not isinstance(value, list) or any(not isinstance(item, dict) for item in value):
        raise ForkOpsError(f"Migration dry run input has malformed {key}.")
    return [copy.deepcopy(item) for item in value]


def _require_plan_dict(plan: dict[str, Any], key: str) -> dict[str, Any]:
    if key not in plan:
        raise ForkOpsError(f"Migration dry run input is missing {key}.")
    value = plan[key]
    if not isinstance(value, dict):
        raise ForkOpsError(f"Migration dry run input has malformed {key}.")
    return copy.deepcopy(value)


def _require_migration_review_artifact(plan: dict[str, Any]) -> dict[str, Any]:
    artifact = _require_plan_dict(plan, "migration_review_artifact")
    entries = artifact.get("entries")
    if not isinstance(entries, list) or any(not isinstance(item, dict) for item in entries):
        raise ForkOpsError(
            "Migration dry run input has malformed migration_review_artifact.entries."
        )
    return artifact


def _require_patch_list(patch: dict[str, Any], key: str) -> list[dict[str, Any]]:
    value = patch.get(key, [])
    if not isinstance(value, list) or any(not isinstance(item, dict) for item in value):
        raise ForkOpsError(f"Migration dry run input has malformed proposed_config_patch.{key}.")
    return [copy.deepcopy(item) for item in value]


def _require_preview_list(preview: dict[str, Any], key: str) -> list[dict[str, Any]]:
    value = preview.get(key)
    if not isinstance(value, list) or any(not isinstance(item, dict) for item in value):
        raise ForkOpsError(f"Migration execution preview has malformed {key}.")
    return [copy.deepcopy(item) for item in value]


def _optional_preview_list(preview: dict[str, Any], key: str) -> list[dict[str, Any]]:
    value = preview.get(key, [])
    if not isinstance(value, list) or any(not isinstance(item, dict) for item in value):
        return []
    return [copy.deepcopy(item) for item in value]


def _optional_preview_dict(preview: dict[str, Any], key: str) -> dict[str, Any]:
    value = preview.get(key, {})
    return copy.deepcopy(value) if isinstance(value, dict) else {}


def _migration_execution_result(
    *,
    repo: Path,
    preview: dict[str, Any],
    status: str,
    applied_edits: list[dict[str, Any]],
    skipped_edits: list[dict[str, Any]],
    blockers: list[dict[str, Any]],
    verification_results: list[dict[str, Any]],
) -> dict[str, Any]:
    return {
        "repo_path": str(repo),
        "mode": "mutating",
        "operation": "migration-execution",
        "plan_operation": preview.get("plan_operation"),
        "status": status,
        "summary": {
            "applied_edit_count": len(applied_edits),
            "skipped_edit_count": len(skipped_edits),
            "migration_map_entry_count": len(_optional_preview_list(preview, "migration_map")),
            "review_artifact_entry_count": len(
                _review_artifact_entries(
                    _optional_preview_dict(preview, "migration_review_artifact")
                )
            ),
            "blocker_count": len(blockers),
            "verification_result_count": len(verification_results),
        },
        "applied_edits": applied_edits,
        "skipped_edits": skipped_edits,
        "migration_map": _optional_preview_list(preview, "migration_map"),
        "migration_review_artifact": _optional_preview_dict(
            preview,
            "migration_review_artifact",
        ),
        "blockers": blockers,
        "verification_results": verification_results,
    }


def _skipped_preview_edits(preview: dict[str, Any], reason: str) -> list[dict[str, Any]]:
    skipped = []
    for edit in _require_preview_list(preview, "file_edits"):
        skipped.append(
            {
                "path": edit.get("path"),
                "action": edit.get("action"),
                "status": "skipped",
                "reason": reason,
            }
        )
    skipped.extend(_preserved_source_materials(preview))
    return skipped


def _preserved_source_materials(preview: dict[str, Any]) -> list[dict[str, Any]]:
    return [
        {
            "path": material.get("path"),
            "action": "preserve",
            "status": "skipped",
            "reason": "source_material_retained_until_replacement_validates",
        }
        for material in _require_preview_list(preview, "retained_materials")
    ]


def _migration_execution_blockers(repo: Path, preview: dict[str, Any]) -> list[dict[str, Any]]:
    blockers: list[dict[str, Any]] = []
    file_edits = _require_preview_list(preview, "file_edits")
    if len(file_edits) != 1:
        blockers.append(
            {
                "code": "migration_execution.unsupported_edit_count",
                "message": "Migration execution currently supports exactly one config file edit.",
            }
        )
    for edit in file_edits:
        blockers.extend(_migration_file_edit_blockers(repo, edit))
    return blockers


def _migration_file_edit_blockers(repo: Path, edit: dict[str, Any]) -> list[dict[str, Any]]:
    blockers: list[dict[str, Any]] = []
    path, path_blocker = _migration_edit_target(repo, edit.get("path"))
    if path_blocker:
        blockers.append(path_blocker)
        return blockers

    action = edit.get("action")
    if action != "create":
        blockers.append(
            {
                "code": "migration_execution.unsupported_action",
                "path": edit.get("path"),
                "message": "Migration execution currently supports guarded config creation only.",
            }
        )
    if edit.get("content_kind") != "fork-ops-config":
        blockers.append(
            {
                "code": "migration_execution.unsupported_content_kind",
                "path": edit.get("path"),
                "message": "Migration execution currently writes Fork Ops config content only.",
            }
        )
    if edit.get("path") != CONFIG_RELATIVE_PATH.as_posix():
        blockers.append(
            {
                "code": "migration_execution.unsupported_target_path",
                "path": edit.get("path"),
                "message": "Migration execution currently writes only .agents/fork-ops.toml.",
            }
        )
    if (path.exists() or path.is_symlink()) and action == "create":
        blockers.append(
            {
                "code": "migration_execution.target_exists",
                "path": edit.get("path"),
                "message": "Refusing to overwrite an existing target during config creation.",
            }
        )

    content = edit.get("content")
    if not isinstance(content, str):
        blockers.append(
            {
                "code": "migration_execution.malformed_content",
                "path": edit.get("path"),
                "message": "Migration execution requires string content for guarded config writes.",
            }
        )
        return blockers
    try:
        parsed = parse_config_text(content)
    except ForkOpsError as exc:
        blockers.append(
            {
                "code": "migration_execution.config_parse_failed",
                "path": edit.get("path"),
                "message": str(exc),
            }
        )
        return blockers

    diagnostics = schema_diagnostics(parsed) + reference_diagnostics(normalize_config(parsed))
    error_diagnostics = [item.to_dict() for item in diagnostics if item.severity == "error"]
    if error_diagnostics:
        blockers.append(
            {
                "code": "migration_execution.config_diagnostics_failed",
                "path": edit.get("path"),
                "message": "Refusing to apply config content with validation errors.",
                "diagnostics": error_diagnostics,
            }
        )
    capability = capability_report(normalize_config(parsed), diagnostics)
    if not capability["levels"]["track-aware"]["available"]:
        blockers.append(
            {
                "code": "migration_execution.required_capability_unavailable",
                "path": edit.get("path"),
                "message": (
                    "Migration execution requires the proposed config to satisfy track-aware."
                ),
                "required_level": "track-aware",
                "missing": capability["levels"]["track-aware"]["missing"],
            }
        )
    return blockers


def _normalize_migration_relative_path(raw_path: str) -> str:
    return raw_path.replace("\\", "/")


def _migration_edit_target(
    repo: Path,
    raw_path: Any,
) -> tuple[Path, dict[str, Any] | None]:
    if not isinstance(raw_path, str) or not raw_path:
        return repo, {
            "code": "migration_execution.malformed_target_path",
            "message": "Migration execution requires a non-empty relative target path.",
        }
    normalized_path = _normalize_migration_relative_path(raw_path)
    target = Path(normalized_path)
    if target.is_absolute() or ".." in target.parts:
        return repo, {
            "code": "migration_execution.unsafe_target_path",
            "path": raw_path,
            "message": "Migration execution refuses absolute paths and parent traversal.",
        }
    repo_root = repo.resolve()
    resolved_parent = (repo / target).parent.resolve(strict=False)
    if not resolved_parent.is_relative_to(repo_root):
        return repo, {
            "code": "migration_execution.unsafe_target_path",
            "path": raw_path,
            "message": "Migration execution refuses target paths outside the repository.",
        }
    if resolved_parent.exists() and not resolved_parent.is_dir():
        return repo, {
            "code": "migration_execution.target_parent_not_directory",
            "path": raw_path,
            "message": "Migration execution target parent is not a directory.",
        }
    return repo / target, None


def _retained_source_material_blockers(
    repo: Path,
    retained_materials: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    blockers = []
    for material in retained_materials:
        raw_path = material.get("path")
        if not isinstance(raw_path, str) or not raw_path:
            blockers.append(
                {
                    "code": "migration_execution.malformed_retained_source",
                    "message": "Retained source material requires a non-empty relative path.",
                }
            )
            continue
        retained_path = Path(raw_path)
        if retained_path.is_absolute() or ".." in retained_path.parts:
            blockers.append(
                {
                    "code": "migration_execution.unsafe_retained_source_path",
                    "path": raw_path,
                    "message": "Retained source material must stay inside the repository.",
                }
            )
            continue
        path = repo / raw_path
        if not path.resolve(strict=False).is_relative_to(repo.resolve()):
            blockers.append(
                {
                    "code": "migration_execution.unsafe_retained_source_path",
                    "path": raw_path,
                    "message": "Retained source material must stay inside the repository.",
                }
            )
            continue
        if not path.exists():
            blockers.append(
                {
                    "code": "migration_execution.retained_source_missing",
                    "path": raw_path,
                    "message": "Retained source material is missing before migration execution.",
                }
            )
            continue
        expected_sha256 = material.get("content_sha256")
        if not isinstance(expected_sha256, str) or not expected_sha256:
            blockers.append(
                {
                    "code": "migration_execution.retained_source_hash_missing",
                    "path": raw_path,
                    "message": "Retained source material requires a planned content hash.",
                }
            )
            continue
        if _file_sha256(path) != expected_sha256:
            blockers.append(
                {
                    "code": "migration_execution.retained_source_changed",
                    "path": raw_path,
                    "message": "Retained source material changed after migration planning.",
                }
            )
    return blockers


def _apply_migration_file_edits(
    repo: Path,
    file_edits: list[dict[str, Any]],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    applied = []
    blockers = []
    repo_root = repo.resolve()
    for edit in file_edits:
        path, blocker = _migration_edit_target(repo, edit.get("path"))
        if blocker:
            blockers.append(blocker)
            continue
        content = edit["content"]
        parent_existed = path.parent.exists()
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
        except OSError as exc:
            blockers.append(
                {
                    "code": "migration_execution.target_parent_unavailable",
                    "path": edit.get("path"),
                    "message": f"Migration execution target parent is unavailable: {exc}",
                }
            )
            continue
        parent_blocker = _migration_target_parent_blocker(repo_root, path.parent, edit.get("path"))
        if parent_blocker:
            _remove_created_parent(path.parent, parent_existed)
            blockers.append(parent_blocker)
            continue
        try:
            _write_new_file_atomically(path, content)
        except FileExistsError:
            _remove_created_parent(path.parent, parent_existed)
            blockers.append(
                {
                    "code": "migration_execution.target_exists",
                    "path": edit.get("path"),
                    "message": "Refusing to overwrite a target created before config write.",
                }
            )
            continue
        except OSError as exc:
            _remove_created_parent(path.parent, parent_existed)
            blockers.append(
                {
                    "code": "migration_execution.write_failed",
                    "path": edit.get("path"),
                    "message": f"Migration execution config write failed: {exc}",
                }
            )
            continue
        applied.append(
            {
                "path": edit["path"],
                "action": edit["action"],
                "status": "applied",
                "content_kind": edit.get("content_kind"),
                "bytes": len(_config_content_bytes(content)),
                "content_sha256": hashlib.sha256(_config_content_bytes(content)).hexdigest(),
            }
        )
    return applied, blockers


def _migration_target_parent_blocker(
    repo_root: Path,
    parent: Path,
    raw_path: Any,
) -> dict[str, Any] | None:
    resolved_parent = parent.resolve(strict=False)
    if not resolved_parent.is_relative_to(repo_root):
        return {
            "code": "migration_execution.unsafe_target_path",
            "path": raw_path,
            "message": "Migration execution refuses target paths outside the repository.",
        }
    if not resolved_parent.is_dir():
        return {
            "code": "migration_execution.target_parent_not_directory",
            "path": raw_path,
            "message": "Migration execution target parent is not a directory.",
        }
    return None


def _write_new_file_atomically(path: Path, content: str) -> None:
    temp_path = path.with_name(f".{path.name}.tmp-{uuid.uuid4().hex}")
    content_bytes = _config_content_bytes(content)
    try:
        with temp_path.open("xb") as handle:
            handle.write(content_bytes)
            handle.flush()
            os.fsync(handle.fileno())
        os.link(temp_path, path)
    finally:
        temp_path.unlink(missing_ok=True)


def _config_content_bytes(content: str) -> bytes:
    return content.encode()


def _remove_created_parent(parent: Path, parent_existed: bool) -> None:
    if parent_existed:
        return
    try:
        parent.rmdir()
    except OSError:
        return


def _verify_migration_execution(
    repo: Path,
    preview: dict[str, Any],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    report = build_status_report(repo, include_config=False)
    required_level = "track-aware"
    required_available = bool(report["capability"]["levels"][required_level]["available"])
    status = "passed" if required_available else "failed"
    results = []
    for requirement in _require_preview_list(preview, "expected_verification_commands"):
        results.append(
            {
                "code": requirement.get("code"),
                "command": requirement.get("command"),
                "status": status,
                "highest_available": report["capability"]["highest_available"],
                "required_level": required_level,
                "required_level_available": required_available,
                "diagnostics": report.get("diagnostics", []),
                "note": (
                    "Status reflects Fork Ops capability verification; listed commands "
                    "are not executed."
                ),
            }
        )
    blockers = []
    if status != "passed":
        blockers.append(
            {
                "code": "migration_execution.verification_failed",
                "message": "Fork Ops config verification failed after migration execution.",
                "diagnostics": report.get("diagnostics", []),
            }
        )
    return results, blockers


def _migration_candidates(repo: Path) -> list[dict[str, Any]]:
    candidates: list[dict[str, Any]] = []
    for path in _iter_candidate_paths(repo):
        rel = path.relative_to(repo).as_posix()
        raw_bytes = _read_bytes(path)
        raw_text = raw_bytes.decode(errors="ignore")
        lowered_text = raw_text.lower()
        signals = _fork_signals(lowered_text)
        if not signals:
            continue
        urls = _extract_urls(raw_text)
        candidates.append(
            {
                "path": rel,
                "kind": _candidate_kind(rel),
                "content_sha256": hashlib.sha256(raw_bytes).hexdigest(),
                "signals": signals,
                "domains": _candidate_domains(signals),
                "extracted_facts": _extracted_facts(raw_text),
                "urls": urls,
                "proposed_destination": _proposed_destination(rel, signals),
                "portability_hint": _portability_hint(rel, signals),
            }
        )
    return sorted(candidates, key=lambda item: item["path"])


def _migration_plan_evidence(candidates: list[dict[str, Any]]) -> list[dict[str, Any]]:
    evidence = []
    for candidate in candidates:
        facts = candidate["extracted_facts"]
        if not facts:
            continue
        evidence.append(
            {
                "source_path": candidate["path"],
                "kind": candidate["kind"],
                "domains": candidate["domains"],
                "facts": facts,
                "urls": candidate["urls"],
                "proposed_destination": candidate["proposed_destination"],
                "portability_hint": candidate["portability_hint"],
            }
        )
    return evidence


def _migration_map(
    candidates: list[dict[str, Any]],
    proposed_config_patch: dict[str, Any],
) -> list[dict[str, Any]]:
    return [
        _migration_map_entry(candidate, proposed_config_patch)
        for candidate in sorted(candidates, key=lambda item: item["path"])
    ]


def _migration_map_entry(
    candidate: dict[str, Any],
    proposed_config_patch: dict[str, Any],
) -> dict[str, Any]:
    disposition_type = _source_material_disposition(candidate, proposed_config_patch)
    source_path = candidate["path"]
    entry_id = _migration_map_entry_id(source_path)
    return {
        "id": entry_id,
        "source_path": source_path,
        "source_kind": candidate["kind"],
        "content_sha256": candidate["content_sha256"],
        "domains": list(candidate["domains"]),
        "signals": list(candidate["signals"]),
        "disposition": {
            "type": disposition_type,
            "requires_review": True,
        },
        "target_surface": _migration_map_target_surface(disposition_type, candidate),
        "retained_source_material": True,
        "review_artifact_entry_id": f"{entry_id}:review",
    }


def _migration_map_entry_id(source_path: str) -> str:
    digest = hashlib.sha256(source_path.encode()).hexdigest()
    return f"migration-map:{digest[:16]}"


def _source_material_disposition(
    candidate: dict[str, Any],
    proposed_config_patch: dict[str, Any],
) -> str:
    facts = candidate["extracted_facts"]
    if _candidate_needs_human_decision(candidate, proposed_config_patch):
        return "needs_human_decision"
    if not facts and _candidate_is_retained_authority(candidate):
        return "retained_as_fork_local_authority"
    if not facts and _candidate_maps_to_workflow_backlog(candidate):
        return "mapped_to_workflow_backlog"
    if not facts and _candidate_is_irrelevant(candidate):
        return "irrelevant_to_fork_ops"
    if not facts:
        return "unsupported_extractor_shape"
    if proposed_config_patch.get("operation") != "create":
        return "deferred_with_rationale"
    return "extracted_into_config"


def _candidate_needs_human_decision(
    candidate: dict[str, Any],
    proposed_config_patch: dict[str, Any],
) -> bool:
    default_baseline_refs = {
        fact["value"]
        for fact in candidate["extracted_facts"]
        if fact["kind"] == "default_sync_baseline"
    }
    if not default_baseline_refs:
        return False
    for diagnostic in proposed_config_patch.get("diagnostics", []):
        if (
            isinstance(diagnostic, dict)
            and diagnostic.get("code") == "migration.default_sync_baseline_ambiguous"
        ):
            return True
    return False


def _candidate_maps_to_workflow_backlog(candidate: dict[str, Any]) -> bool:
    return _has_review_publication_signal(set(candidate["signals"]))


def _candidate_is_retained_authority(candidate: dict[str, Any]) -> bool:
    return candidate["kind"] in {"agent_instruction", "config"}


def _candidate_is_irrelevant(candidate: dict[str, Any]) -> bool:
    return not candidate["domains"] and not candidate["extracted_facts"]


def _migration_map_target_surface(
    disposition_type: str,
    candidate: dict[str, Any],
) -> dict[str, Any]:
    if disposition_type == "extracted_into_config":
        return {
            "type": "fork_ops_config",
            "path": CONFIG_RELATIVE_PATH.as_posix(),
            "sections": _candidate_config_sections(candidate),
        }
    if disposition_type == "retained_as_fork_local_authority":
        return {
            "type": "fork_local_authority",
            "path": candidate["path"],
        }
    if disposition_type == "mapped_to_workflow_backlog":
        return {
            "type": "workflow_catalog_backlog",
            "workflow_id": _candidate_workflow_backlog_target(candidate),
        }
    if disposition_type == "irrelevant_to_fork_ops":
        return {
            "type": "none",
        }
    return {
        "type": "migration_review_artifact",
        "path": MIGRATION_REVIEW_ARTIFACT_RELATIVE_PATH,
        "section": _migration_review_artifact_section(disposition_type),
    }


def _candidate_config_sections(candidate: dict[str, Any]) -> list[str]:
    return sorted({fact["suggested_config"] for fact in candidate["extracted_facts"]})


def _candidate_workflow_backlog_target(candidate: dict[str, Any]) -> str:
    if _has_review_publication_signal(set(candidate["signals"])):
        return "publication-closeout"
    return "fork-authority-migration"


def _migration_review_artifact_section(disposition_type: str) -> str:
    return {
        "unsupported_extractor_shape": "unsupported extractor shapes",
        "needs_human_decision": "human decisions",
        "deferred_with_rationale": "deferred mappings",
    }.get(disposition_type, "migration decisions")


def _migration_review_artifact(migration_map: list[dict[str, Any]]) -> dict[str, Any]:
    entries = [
        {
            "id": entry["review_artifact_entry_id"],
            "source_path": entry["source_path"],
            "disposition": copy.deepcopy(entry["disposition"]),
            "target_surface": copy.deepcopy(entry["target_surface"]),
            "retained_source_material": entry["retained_source_material"],
            "rationale": _migration_review_rationale(entry),
        }
        for entry in migration_map
    ]
    artifact = {
        "status": "proposed",
        "target_path": MIGRATION_REVIEW_ARTIFACT_RELATIVE_PATH,
        "content_kind": "migration-review-artifact",
        "entries": entries,
    }
    artifact["markdown"] = _migration_review_artifact_markdown(entries)
    return artifact


def _migration_review_rationale(entry: dict[str, Any]) -> str:
    disposition_type = entry["disposition"]["type"]
    if disposition_type == "extracted_into_config":
        return (
            "Machine-actionable facts are represented in the proposed fork ops config; "
            "the source material remains preserved until replacement coverage is reviewed."
        )
    if disposition_type == "retained_as_fork_local_authority":
        return (
            "This source remains fork-local authority because the migration does not "
            "replace always-loaded or checked-in authority surfaces."
        )
    if disposition_type == "mapped_to_workflow_backlog":
        return (
            "This source describes workflow behavior that belongs in workflow catalog "
            "follow-up work, not in machine-actionable fork ops config."
        )
    if disposition_type == "irrelevant_to_fork_ops":
        return "This source matched a broad scan signal but does not describe fork ops authority."
    if disposition_type == "unsupported_extractor_shape":
        return (
            "This source appears relevant, but the deterministic extractor did not produce "
            "structured facts for the current config proposal."
        )
    if disposition_type == "needs_human_decision":
        return (
            "The source contributes a migration choice that cannot be resolved "
            "deterministically and needs an operator decision."
        )
    if disposition_type == "deferred_with_rationale":
        return (
            "The source has extractable facts, but the current guarded execution slice "
            "does not merge arbitrary edits into existing fork ops config."
        )
    raise ForkOpsError(f"Unknown source material disposition: {disposition_type}")


def _migration_review_artifact_markdown(entries: list[dict[str, Any]]) -> str:
    lines = [
        "# Fork Ops Migration Review",
        "",
        "Status: proposed",
        "",
        "This artifact records migration review decisions that do not belong in fork ops config.",
    ]
    for entry in entries:
        lines.extend(
            [
                "",
                f"## {entry['source_path']}",
                "",
                f"- Disposition: {entry['disposition']['type']}",
                f"- Target surface: {entry['target_surface']['type']}",
                *_target_surface_markdown_lines(entry["target_surface"]),
                f"- Rationale: {entry['rationale']}",
            ]
        )
    return "\n".join(lines).rstrip() + "\n"


def _target_surface_markdown_lines(target_surface: dict[str, Any]) -> list[str]:
    lines = []
    for key in ("path", "workflow_id", "section"):
        value = target_surface.get(key)
        if isinstance(value, str) and value:
            lines.append(f"- Target {key.replace('_', ' ')}: {value}")
    sections = target_surface.get("sections")
    if isinstance(sections, list) and all(isinstance(item, str) for item in sections):
        lines.append(f"- Target sections: {', '.join(sections)}")
    return lines


def _review_artifact_entries(artifact: dict[str, Any]) -> list[dict[str, Any]]:
    entries = artifact.get("entries", [])
    if not isinstance(entries, list) or any(not isinstance(item, dict) for item in entries):
        return []
    return entries


def _retained_source_materials(candidates: list[dict[str, Any]]) -> list[dict[str, Any]]:
    retained = []
    for candidate in candidates:
        retained.append(
            {
                "path": candidate["path"],
                "kind": candidate["kind"],
                "domains": candidate["domains"],
                "proposed_destination": candidate["proposed_destination"],
                "portability_hint": candidate["portability_hint"],
                "content_sha256": candidate["content_sha256"],
                "replacement_status": "deferred",
                "retention_policy": (
                    "Keep this source material until a reviewed migration dry run proves "
                    "the fork ops replacement preserves the relevant authority."
                ),
            }
        )
    return retained


def _deferred_removals(retained_source_materials: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [
        {
            "path": material["path"],
            "status": "deferred",
            "reason": (
                "Removal is deferred because source material remains fork-local authority "
                "until replacement validation succeeds."
            ),
        }
        for material in retained_source_materials
    ]


def _migration_plan_blockers(
    candidates: list[dict[str, Any]],
    proposed_config_patch: dict[str, Any],
) -> list[dict[str, Any]]:
    blockers: list[dict[str, Any]] = []
    diagnostics = proposed_config_patch.get("diagnostics", [])
    error_diagnostics = [
        item for item in diagnostics if isinstance(item, dict) and item.get("severity") == "error"
    ]
    if error_diagnostics:
        blockers.append(
            {
                "code": "proposed_config_patch.diagnostics_failed",
                "message": "Resolve proposed config patch errors before migration dry run.",
                "diagnostics": error_diagnostics,
            }
        )
    uncovered_paths = [
        candidate["path"]
        for candidate in candidates
        if _source_material_disposition(candidate, proposed_config_patch)
        == "unsupported_extractor_shape"
    ]
    if uncovered_paths:
        blockers.append(
            {
                "code": "semantic_coverage.incomplete",
                "message": (
                    "Some candidate source materials were detected but did not produce "
                    "structured facts. Review them before replacing or removing source material."
                ),
                "paths": uncovered_paths,
            }
        )
    # No source material and source material without extracted facts are distinct
    # blockers; keep their signals separate for plan consumers.
    if not candidates:
        blockers.append(
            {
                "code": "source_material.none_found",
                "message": (
                    "No fork-related source materials were detected. Review scan scope before "
                    "treating the plan as complete."
                ),
            }
        )
    return blockers


def _semantic_coverage_status(blockers: list[dict[str, Any]]) -> str:
    if any(blocker.get("code") == "semantic_coverage.incomplete" for blocker in blockers):
        return "incomplete"
    return "complete"


def _migration_plan_required_review(blockers: list[dict[str, Any]]) -> list[dict[str, Any]]:
    required_review = [
        {
            "code": "review.proposed_config_patch",
            "status": "required",
            "subject": "proposed_config_patch",
            "reason": (
                "Config proposals are deterministic drafts and require human or agent review."
            ),
        },
        {
            "code": "review.retained_source_materials",
            "status": "required",
            "subject": "retained_source_materials",
            "reason": "Fork-local authority must remain until replacement coverage is verified.",
        },
        {
            "code": "review.migration_review_artifact",
            "status": "required",
            "subject": "migration_review_artifact",
            "reason": (
                "Durable migration decisions that are not machine-actionable config "
                "belong in the proposed review artifact."
            ),
        },
    ]
    if blockers:
        required_review.append(
            {
                "code": "review.blockers",
                "status": "required",
                "subject": "blockers",
                "reason": "Blockers must be resolved or explicitly waived before dry run.",
            }
        )
    return required_review


def _migration_plan_validation_requirements() -> list[dict[str, Any]]:
    return [
        {
            "code": "validation.config_validate",
            "command": (
                "uv run --package fork-ops fork-ops config validate "
                "--repo <repo> --required-level track-aware"
            ),
            "when": "after applying the proposed fork ops config",
        },
        {
            "code": "validation.capability_report",
            "command": "uv run --package fork-ops fork-ops capability report --repo <repo>",
            "when": "after applying the proposed fork ops config",
        },
    ]


def _validation_requirement_blockers(
    requirements: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    blockers = []
    expected_by_code = {
        requirement["code"]: requirement
        for requirement in _migration_plan_validation_requirements()
    }
    for requirement in requirements:
        code = requirement.get("code")
        command = requirement.get("command")
        expected = expected_by_code.get(code)
        if expected is None or command != expected["command"]:
            blockers.append(
                {
                    "code": "migration_execution.validation_requirement_unsupported",
                    "step": "verify_migration_execution",
                    "source": "migration_plan",
                    "validation_code": code,
                    "message": (
                        "Migration execution only reports supported Fork Ops "
                        "validation requirements."
                    ),
                }
            )
    supplied_codes = {requirement.get("code") for requirement in requirements}
    for code in expected_by_code:
        if code in supplied_codes:
            continue
        blockers.append(
            {
                "code": "migration_execution.validation_requirement_missing",
                "step": "verify_migration_execution",
                "source": "migration_plan",
                "validation_code": code,
                "message": (
                    "Migration execution requires the full Fork Ops validation "
                    "requirement set."
                ),
            }
        )
    return blockers


def _build_proposed_config(repo: Path, candidates: list[dict[str, Any]]) -> dict[str, Any]:
    origin_url = _git_output(repo, "remote", "get-url", "origin") or _find_remote_url(
        candidates, "origin"
    )
    upstream_url = _git_output(repo, "remote", "get-url", "upstream") or _find_remote_url(
        candidates, "upstream"
    )
    origin_slug = _github_slug_from_url(origin_url) or ("OWNER", "REPO")
    upstream_slug = _github_slug_from_url(upstream_url) or ("UPSTREAM_OWNER", "UPSTREAM_REPO")
    default_branch = _default_branch(repo)
    upstream_default_branch = _upstream_default_branch(repo) or "main"
    upstream_id = _slug_id(upstream_slug[1])
    facts = _flatten_facts(candidates)
    urls = _candidate_urls(repo, candidates)
    docs_url = _infer_docs_url(urls)
    product_site = _infer_product_site_url(urls, docs_url)
    context_paths = _required_context_paths(repo)

    fork_remote: dict[str, Any] = {
        "name": "origin",
        "push": True,
        "owner": origin_slug[0],
        "purpose": "fork-origin",
    }
    if origin_url:
        fork_remote["url"] = origin_url

    upstream_remote: dict[str, Any] = {
        "id": upstream_id,
        "name": upstream_slug[1],
        "owner": upstream_slug[0],
        "remote": "upstream",
        "push": False,
        "default_branch": upstream_default_branch,
    }
    if upstream_url:
        upstream_remote["url"] = upstream_url
    upstream_push_url = _git_output(repo, "remote", "get-url", "--push", "upstream")
    if upstream_push_url:
        upstream_remote["push_url"] = upstream_push_url
    elif upstream_url:
        upstream_remote["push_url"] = "DISABLED"

    config: dict[str, Any] = {
        "schema_version": "0.1",
        "repository": {
            "host": "github",
            "owner": origin_slug[0],
            "name": origin_slug[1],
            "default_branch": default_branch,
        },
        "authority": {
            "source_order": [
                "explicit-user-direction",
                "current-upstream-source-website-docs-release-notes-maintainer-guidance",
                "fork-local-agents-context-docs-agents",
                "source-structure-and-tests-inference",
                "prior-agent-notes-after-current-state-check",
            ],
            "upstream_canon": (
                "Upstream source, website, docs, release notes, and maintainer guidance "
                "are product-truth sources unless fork-local authority defines a divergence."
            ),
            "inference_labeling": "Label important inferences when direct evidence is unavailable.",
        },
        "change_targets": {
            "default": "fork",
            "upstream_contribution": "explicit-only",
            "upstream_issues": "explicit-only",
            "selective_upstreaming": "explicit-only",
        },
        "fork_remotes": [fork_remote],
        "upstreams": [upstream_remote],
        "release_channels": [],
        "upstream_tracks": [],
        "sync_policy": {},
        "local_surfaces": _proposed_local_surfaces(candidates),
    }
    if context_paths:
        config["authority"]["required_context_paths"] = context_paths
        config["authority"]["pre_change_requirements"] = [
            (
                "For non-trivial changes, read required_context_paths before specs, "
                "plans, or implementation."
            ),
            "Identify relevant upstream docs and source paths.",
            "Verify current upstream state when drift could affect the task.",
            "Record durable discoveries in the narrowest useful place.",
        ]
        durable_destinations = _durable_discovery_destinations(repo)
        if durable_destinations:
            config["authority"]["durable_discovery_destinations"] = durable_destinations
    if product_site:
        config["repository"]["product_site"] = product_site
        config["upstreams"][0]["site_url"] = product_site
    if docs_url:
        config["upstreams"][0]["docs_url"] = docs_url

    fact_values = {(fact["kind"], fact["value"]) for fact in facts}
    has_stable_release_channel = ("release_channel", "stable") in fact_values or (
        "release_channel_source",
        "github-releases",
    ) in fact_values
    if has_stable_release_channel:
        config["release_channels"].append(
            {
                "id": "stable",
                "upstream": upstream_id,
                "kind": "github_latest_release",
                "selection_source": "github-releases",
                "include_drafts": False,
                "include_prereleases": False,
                "notes": "Choose from live GitHub Releases, not tag sorting.",
            }
        )

    if _has_any_fact(fact_values, "ref_role", {"origin/upstream-main", "upstream-main"}):
        config["upstream_tracks"].append(
            {
                "id": "upstream-main",
                "upstream": upstream_id,
                "ref": "refs/remotes/origin/upstream-main",
                "role": "shared upstream main scouting baseline",
                "source_type": "upstream_ref",
                "source": "refs/remotes/upstream/main",
                "source_ref": "refs/remotes/upstream/main",
                "owner_remote": "origin",
                "local_branch": "upstream-main",
                "tracking_ref": "refs/remotes/upstream/main",
                "update_policy": (
                    "Update and push when a task depends on a shared current view "
                    "of upstream main, including upstream commit investigations, "
                    "proactive sync estimates, handoffs, issues, or PR descriptions."
                ),
                "evidence_checks": [
                    "git rev-parse upstream/main upstream-main origin/upstream-main",
                ],
                "sync_eligible": False,
                "notes": (
                    "Use for unreleased changes and scouting unless explicitly "
                    "syncing upstream main."
                ),
            }
        )

    if _has_any_fact(fact_values, "ref_role", {"origin/upstream-stable", "upstream-stable"}):
        stable_track_source = (
            {
                "source_type": "release_channel",
                "source": "stable",
                "notes": (
                    "Published stable upstream baseline for sync and fork release "
                    "versioning. Do not advance just because a new tag exists."
                ),
            }
            if has_stable_release_channel
            else {
                "source_type": "upstream_ref",
                "source": "refs/remotes/origin/upstream-stable",
                "source_ref": "refs/remotes/origin/upstream-stable",
                "notes": (
                    "Published stable upstream baseline was detected, but no release-channel "
                    "selection source was found. Review source material before treating this "
                    "track as release-channel backed."
                ),
            }
        )
        config["upstream_tracks"].append(
            {
                "id": "upstream-stable",
                "upstream": upstream_id,
                "ref": "refs/remotes/origin/upstream-stable",
                "role": "stable upstream release baseline",
                "owner_remote": "origin",
                "local_branch": "upstream-stable",
                "tracking_ref": "refs/remotes/origin/upstream-stable",
                "local_branch_policy": (
                    "Use local upstream-stable only when maintaining the published stable baseline."
                ),
                "update_policy": (
                    "Advance only for fork sync or fork versioning work that chooses "
                    "a new stable upstream release baseline."
                ),
                "non_fast_forward_policy": (
                    "If the selected release tag is not a fast-forward from the "
                    "published baseline, stop and ask whether to move the baseline."
                ),
                "evidence_checks": [
                    "git rev-parse <release-tag> upstream-stable origin/upstream-stable",
                ],
                "sync_eligible": True,
                **stable_track_source,
            }
        )

    default_sync_ref = _default_sync_baseline_ref(fact_values)
    for ref in _generic_origin_upstream_refs(fact_values, default_sync_ref):
        track_id = _origin_upstream_track_id(ref)
        if any(track.get("id") == track_id for track in config["upstream_tracks"]):
            continue
        source_ref = _origin_remote_tracking_ref(ref)
        config["upstream_tracks"].append(
            {
                "id": track_id,
                "upstream": upstream_id,
                "ref": source_ref,
                "role": "detected upstream baseline",
                "source_type": "upstream_ref",
                "source": source_ref,
                "source_ref": source_ref,
                "owner_remote": "origin",
                "tracking_ref": source_ref,
                "sync_eligible": ref == default_sync_ref,
                "notes": (
                    "Detected upstream baseline; review source material before treating "
                    "this track as release-channel backed."
                ),
            }
        )

    if default_sync_ref:
        default_sync_track = _origin_upstream_track_id(default_sync_ref)
        config["sync_policy"] = {
            "default_sync_baseline": default_sync_track,
            "default_sync_ref": default_sync_ref,
            "fork_sync_start_ref": f"origin/{default_branch}",
            "preserve_commit_identity": True,
            "forbid_history_rewrites": True,
            "allowed_merge_methods": ["merge", "ff-only"],
            "fork_sync_methods": ["merge"],
            "track_update_methods": ["ff-only"],
            "ancestry_checks": [
                f"git merge-base --is-ancestor {default_sync_ref} HEAD",
            ],
            "conditional_ancestry_checks": [
                (
                    "user-requested upstream main sync: "
                    "git merge-base --is-ancestor upstream/main HEAD"
                ),
            ],
            "pre_sync_fetches": [
                "git fetch origin",
                "git fetch upstream --prune --tags",
            ],
            "forbidden_flows": [
                "rebase upstream commits",
                "force-push routine baseline updates",
                "gh repo sync --force",
                "patch-equivalent sync without upstream ancestry",
            ],
            "unreleased_upstream_main": "explicit-user-request-only",
        }
        config["divergence_policy"] = {
            "uncertainty_destination": "ask-human-operator",
        }

    return config


def _proposal_evidence(candidates: list[dict[str, Any]]) -> list[dict[str, Any]]:
    evidence = []
    for candidate in candidates:
        if not candidate["extracted_facts"]:
            continue
        evidence.append(
            {
                "path": candidate["path"],
                "domains": candidate["domains"],
                "facts": candidate["extracted_facts"],
            }
        )
    return evidence


def _proposed_local_surfaces(candidates: list[dict[str, Any]]) -> list[dict[str, Any]]:
    surfaces = []
    for candidate in candidates:
        if _candidate_is_irrelevant(candidate):
            continue
        domains = candidate["domains"]
        surface = {
            "kind": candidate["kind"],
            "path": candidate["path"],
            "domain": _primary_domain(candidate),
            "domains": domains,
            "portability_hint": candidate["portability_hint"],
            "portability_hints": _portability_hints(candidate),
            "notes": "Discovered by fork authority migration assessment.",
        }
        scope = _repo_ops_candidate_scope(candidate)
        if scope:
            surface["repo_ops_candidate_scope"] = scope
        surfaces.append(surface)
    return surfaces


def _primary_domain(candidate: dict[str, Any]) -> str:
    domains = [str(domain) for domain in candidate["domains"]]
    if not domains:
        return "authority"
    for domain in (
        "review_publication",
        "upstream_intelligence",
        "sync",
        "divergence",
        "authority",
    ):
        if domain in domains:
            return domain
    return domains[0]


def _portability_hints(candidate: dict[str, Any]) -> list[str]:
    hints = [str(candidate["portability_hint"])]
    signals = set(candidate["signals"])
    if _has_review_publication_signal(signals) and "repo-ops-candidate" not in hints:
        hints.append("repo-ops-candidate")
    if _has_fork_specific_signal(signals) and "fork-specific" not in hints:
        hints.append("fork-specific")
    return hints


def _repo_ops_candidate_scope(candidate: dict[str, Any]) -> str:
    signals = set(candidate["signals"])
    if not _has_review_publication_signal(signals):
        return ""
    if _has_fork_specific_signal(signals):
        return "partial review/publication workflow; preserve fork-specific policy here."
    return "review/publication workflow."


def _flatten_facts(candidates: list[dict[str, Any]]) -> list[dict[str, str]]:
    facts: list[dict[str, str]] = []
    for candidate in candidates:
        facts.extend(candidate["extracted_facts"])
    return _unique_facts(facts)


def _has_any_fact(
    fact_values: set[tuple[str, str]],
    kind: str,
    values: set[str],
) -> bool:
    return any((kind, value) in fact_values for value in values)


def _default_sync_baseline_ref(fact_values: set[tuple[str, str]]) -> str:
    refs = _default_sync_baseline_fact_refs(fact_values)
    return refs[0] if len(refs) == 1 else ""


def _generic_origin_upstream_refs(
    fact_values: set[tuple[str, str]],
    default_sync_ref: str,
) -> list[str]:
    refs = {
        value
        for kind, value in fact_values
        if kind == "ref_role" and value.startswith("origin/upstream-")
    }
    refs.update(_default_sync_baseline_fact_refs(fact_values))
    if default_sync_ref:
        refs.add(default_sync_ref)
    return sorted(refs)


def _default_sync_baseline_fact_refs(fact_values: set[tuple[str, str]]) -> list[str]:
    return sorted(value for kind, value in fact_values if kind == "default_sync_baseline")


def _origin_upstream_track_id(ref: str) -> str:
    return _slug_id(ref.removeprefix("origin/"))


def _origin_remote_tracking_ref(ref: str) -> str:
    return f"refs/remotes/{ref}"


def _required_context_paths(repo: Path) -> list[str]:
    candidates = [
        "AGENTS.md",
        "CONTEXT.md",
        "docs/agents/domain.md",
        "docs/agents/research-map.md",
    ]
    return [path for path in candidates if (repo / path).exists()]


def _durable_discovery_destinations(repo: Path) -> list[str]:
    candidates = {
        "CONTEXT.md": "stable vocabulary and relationships",
        "docs/agents/research-map.md": "source maps and scout routes",
        "docs/agents/fork-stewardship.md": "fork operating policy",
        "AGENTS.md": "always-loaded high-impact rules",
    }
    return [f"{path}: {purpose}" for path, purpose in candidates.items() if (repo / path).exists()]


def _default_branch(repo: Path) -> str:
    origin_head = _git_output(repo, "symbolic-ref", "--short", "refs/remotes/origin/HEAD")
    if origin_head and "/" in origin_head:
        return origin_head.split("/", 1)[1]
    if _git_ok(repo, "show-ref", "--verify", "refs/remotes/origin/main"):
        return "main"
    current = _git_output(repo, "branch", "--show-current")
    return current or "main"


def _upstream_default_branch(repo: Path) -> str:
    upstream_head = _git_output(repo, "symbolic-ref", "--short", "refs/remotes/upstream/HEAD")
    if upstream_head and "/" in upstream_head:
        return upstream_head.split("/", 1)[1]
    return ""


def _candidate_urls(repo: Path, candidates: list[dict[str, Any]]) -> list[str]:
    urls: list[str] = []
    for candidate in candidates:
        urls.extend(str(url) for url in candidate.get("urls", []))
    return _dedupe_strings(urls)


def _find_remote_url(candidates: list[dict[str, Any]], remote_name: str) -> str:
    marker = f"{remote_name}:"
    for candidate in candidates:
        for fact in candidate["extracted_facts"]:
            if fact["kind"] == "remote_url" and fact["value"].startswith(marker):
                return str(fact["value"][len(marker) :])
    return ""


def _github_slug_from_url(url: str) -> tuple[str, str] | None:
    if not url:
        return None
    normalized = url.removesuffix(".git")
    if normalized.startswith("git@github.com:"):
        path = normalized.split(":", 1)[1]
    elif "github.com/" in normalized:
        path = normalized.split("github.com/", 1)[1]
    else:
        return None
    parts = path.strip("/").split("/")
    if len(parts) < 2:
        return None
    return parts[0], parts[1]


def _github_repo_root_slug_from_url(url: str) -> tuple[str, str] | None:
    if not url:
        return None
    normalized = url.strip().rstrip("/").removesuffix(".git")
    if normalized.startswith("git@github.com:"):
        path = normalized.split(":", 1)[1]
    elif "github.com/" in normalized:
        path = normalized.split("github.com/", 1)[1]
    else:
        return None
    parts = path.strip("/").split("/")
    if len(parts) != 2:
        return None
    return parts[0], parts[1]


def _infer_docs_url(urls: list[str]) -> str:
    for url in urls:
        if _is_public_web_url(url) and _looks_like_docs_url(url):
            return url
    return ""


def _infer_product_site_url(urls: list[str], docs_url: str = "") -> str:
    for url in urls:
        if not _is_public_web_url(url):
            continue
        if url == docs_url or _looks_like_docs_url(url):
            continue
        return _site_root(url)
    if docs_url:
        return _site_root(docs_url)
    return ""


def _is_public_web_url(url: str) -> bool:
    parsed = urlparse(url)
    return (
        parsed.scheme in {"http", "https"} and parsed.netloc != "" and parsed.netloc != "github.com"
    )


def _looks_like_docs_url(url: str) -> bool:
    parsed = urlparse(url)
    host_parts = parsed.netloc.lower().split(".")
    path_parts = [part for part in parsed.path.lower().split("/") if part]
    return "docs" in host_parts or (bool(path_parts) and path_parts[0] == "docs")


def _site_root(url: str) -> str:
    parsed = urlparse(url)
    if not parsed.scheme or not parsed.netloc:
        return url
    return f"{parsed.scheme}://{parsed.netloc}/"


def _extract_urls(text: str) -> list[str]:
    return [url.rstrip(".,)>`;'\"") for url in re.findall(r"https?://[^\s<)]+", text)]


def _dedupe_strings(values: list[str]) -> list[str]:
    seen: set[str] = set()
    deduped: list[str] = []
    for value in values:
        if value in seen:
            continue
        seen.add(value)
        deduped.append(value)
    return deduped


def _toml_dumps(data: dict[str, Any]) -> str:
    lines: list[str] = []
    for key, value in data.items():
        if isinstance(value, dict) or _is_array_of_tables(value):
            continue
        lines.append(f"{key} = {_toml_value(value)}")
    if lines:
        lines.append("")

    for key, value in data.items():
        if isinstance(value, dict):
            _emit_toml_table(lines, key, value)
        elif _is_array_of_tables(value):
            for item in value:
                lines.append(f"[[{key}]]")
                _emit_toml_body(lines, item)
                lines.append("")

    return "\n".join(lines).rstrip() + "\n"


def _emit_toml_table(lines: list[str], name: str, table: dict[str, Any]) -> None:
    if not table:
        return
    lines.append(f"[{name}]")
    _emit_toml_body(lines, table)
    lines.append("")


def _emit_toml_body(lines: list[str], table: dict[str, Any]) -> None:
    for key, value in table.items():
        if isinstance(value, dict):
            raise ForkOpsError(f"Nested TOML table rendering is unsupported for key: {key}")
        lines.append(f"{key} = {_toml_value(value)}")


def _toml_value(value: Any) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, int | float):
        return str(value)
    if isinstance(value, list):
        return "[" + ", ".join(_toml_value(item) for item in value) + "]"
    if isinstance(value, str):
        return _toml_string(value)
    raise ForkOpsError(f"Unsupported TOML value type: {type(value).__name__}")


def _toml_string(value: str) -> str:
    escaped: list[str] = []
    for char in value:
        if char == "\b":
            escaped.append("\\b")
        elif char == "\t":
            escaped.append("\\t")
        elif char == "\n":
            escaped.append("\\n")
        elif char == "\f":
            escaped.append("\\f")
        elif char == "\r":
            escaped.append("\\r")
        elif char == '"':
            escaped.append('\\"')
        elif char == "\\":
            escaped.append("\\\\")
        elif ord(char) <= 0x1F or ord(char) == 0x7F:
            escaped.append(f"\\u{ord(char):04X}")
        else:
            escaped.append(char)
    return '"' + "".join(escaped) + '"'


def _is_array_of_tables(value: Any) -> bool:
    return bool(value) and isinstance(value, list) and all(isinstance(item, dict) for item in value)


def create_initial_config_text(
    repo_path: str | Path = ".",
    repository_owner: str = "OWNER",
    repository_name: str = "REPO",
    upstream_owner: str = "UPSTREAM_OWNER",
    upstream_name: str = "UPSTREAM_REPO",
    default_branch: str = "main",
) -> str:
    repo = Path(repo_path).expanduser().resolve()
    origin_url = _git_output(repo, "remote", "get-url", "origin") or ""
    upstream_url = _git_output(repo, "remote", "get-url", "upstream") or ""
    upstream_id = _slug_id(upstream_name)
    fork_remote: dict[str, Any] = {
        "name": "origin",
        "push": True,
    }
    if origin_url:
        fork_remote["url"] = origin_url
    upstream: dict[str, Any] = {
        "id": upstream_id,
        "name": upstream_name,
        "owner": upstream_owner,
        "remote": "upstream",
        "default_branch": default_branch,
        "push": False,
    }
    if upstream_url:
        upstream["url"] = upstream_url
    return _toml_dumps(
        {
            "schema_version": "0.1",
            "repository": {
                "host": "github",
                "owner": repository_owner,
                "name": repository_name,
                "default_branch": default_branch,
                "protected_branches": [default_branch],
            },
            "authority": {
                "source_order": ["fork-ops-config", "repo-docs", "upstream-docs", "live-state"],
                "upstream_canon": (
                    "Upstream source and docs are canonical unless fork-local authority "
                    "defines a divergence."
                ),
                "inference_labeling": (
                    "Label inferred conclusions when direct evidence is unavailable."
                ),
            },
            "change_targets": {
                "default": "fork",
                "upstream_contribution": "explicit-only",
            },
            "fork_remotes": [fork_remote],
            "upstreams": [upstream],
            "release_channels": [
                {
                    "id": "stable",
                    "upstream": upstream_id,
                    "kind": "github_latest_release",
                    "include_prereleases": False,
                }
            ],
            "upstream_tracks": [
                {
                    "id": "upstream-stable",
                    "upstream": upstream_id,
                    "ref": "refs/remotes/origin/upstream-stable",
                    "source_type": "release_channel",
                    "source": "stable",
                    "owner_remote": "origin",
                    "update_policy": "manual",
                    "sync_eligible": True,
                }
            ],
            "local_surfaces": [
                {
                    "kind": "config",
                    "path": ".agents/fork-ops.toml",
                    "domain": "identity",
                    "portability_hint": "fork-specific",
                }
            ],
        }
    )


def schema_json() -> str:
    return json.dumps(CONFIG_SCHEMA, indent=2, sort_keys=True) + "\n"


def _migration_proposal_diagnostics(facts: list[dict[str, str]]) -> list[Diagnostic]:
    fact_values = {(fact["kind"], fact["value"]) for fact in facts}
    default_sync_refs = _default_sync_baseline_fact_refs(fact_values)
    if len(default_sync_refs) <= 1:
        return []
    return [
        Diagnostic(
            severity="error",
            code="migration.default_sync_baseline_ambiguous",
            message=(
                "Multiple default sync baseline refs were detected; review source "
                "materials before selecting one."
            ),
            path="sync_policy.default_sync_baseline",
            detail={"refs": default_sync_refs},
        )
    ]


def schema_artifact_report(plugin_root: str | Path = ".") -> dict[str, Any]:
    root = Path(plugin_root).expanduser().resolve()
    runtime_schema = schema_json().encode("utf-8")
    artifacts = []
    for relative_path in SCHEMA_ARTIFACT_RELATIVE_PATHS:
        path = root / relative_path
        try:
            content = path.read_bytes()
        except OSError as exc:
            artifacts.append(
                {
                    "path": relative_path.as_posix(),
                    "absolute_path": str(path),
                    "exists": path.exists(),
                    "matches_runtime_schema": False,
                    "error": str(exc),
                }
            )
            continue
        artifacts.append(
            {
                "path": relative_path.as_posix(),
                "absolute_path": str(path),
                "exists": True,
                "matches_runtime_schema": content == runtime_schema,
                "content_sha256": hashlib.sha256(content).hexdigest(),
            }
        )
    return {
        "plugin_root": str(root),
        "runtime_schema_sha256": hashlib.sha256(runtime_schema).hexdigest(),
        "ok": all(artifact["matches_runtime_schema"] for artifact in artifacts),
        "artifacts": artifacts,
    }


def _workflow_inventory_roots(
    source_roots: Iterable[str | Path] | str | Path | None,
) -> list[Path]:
    if source_roots is None:
        raw_roots: list[str | Path] = ["."]
    elif isinstance(source_roots, (str, Path)):
        raw_roots = [source_roots]
    else:
        raw_roots = list(source_roots)
    if not raw_roots:
        raw_roots = ["."]
    return [Path(root).expanduser().resolve() for root in raw_roots]


def _iter_workflow_inventory_paths(root: Path) -> Iterable[Path]:
    if root.is_file():
        if root.suffix.lower() in _CANDIDATE_FILE_SUFFIXES:
            yield root
        return
    if not root.is_dir():
        return
    for path in root.rglob("*"):
        if not path.is_file():
            continue
        relative_parts = path.relative_to(root).parts
        if any(part in _CANDIDATE_SCAN_SKIP_DIRS for part in relative_parts[:-1]):
            continue
        if path.suffix.lower() in _CANDIDATE_FILE_SUFFIXES:
            yield path


def _workflow_inventory_entry(
    root: Path,
    path: Path,
    contracts: dict[str, WorkflowContract],
) -> dict[str, Any] | None:
    raw_bytes = _read_bytes(path)
    raw_text = raw_bytes.decode(errors="ignore")
    source_path = path.relative_to(root).as_posix() if path != root else path.name
    source_kind = _workflow_source_kind(root, path, raw_text)
    signals = _workflow_inventory_signals(source_path, raw_text, source_kind)
    if not signals:
        return None
    entry_id = _workflow_inventory_entry_id(root, path)
    target = _workflow_catalog_target(signals, source_kind, raw_text)
    coverage_status = _workflow_coverage_status(target, contracts)
    return {
        "id": entry_id,
        "source_root": str(root),
        "source_path": source_path,
        "source_kind": source_kind,
        "material_scope": _workflow_material_scope(source_kind, source_path, path, raw_text),
        "content_sha256": hashlib.sha256(raw_bytes).hexdigest(),
        "candidate_operator_intent": _workflow_operator_intent(target, signals, source_kind),
        "likely_workflow_catalog_target": target,
        "coverage_status": coverage_status,
        "evidence": _workflow_inventory_evidence(entry_id, raw_text, signals),
    }


def _workflow_inventory_entry_id(root: Path, path: Path) -> str:
    digest = hashlib.sha256(f"{root}\0{path}".encode()).hexdigest()
    return f"workflow-inventory:{digest[:16]}"


def _workflow_source_kind(root: Path, path: Path, raw_text: str) -> str:
    rel_parts = path.relative_to(root).parts if path != root else path.parts[-1:]
    lowered_text = raw_text.lower()
    if path.name in {"AGENTS.md", "CLAUDE.md"}:
        return "agent-instruction"
    if path.name == "SKILL.md":
        return "global-skill" if _is_user_global_agents_path(path) else "repo-local-skill"
    if _workflow_path_has_token(rel_parts, {"handoff", "handoffs"}) or (
        "handoff contract" in lowered_text
    ):
        return "handoff"
    if _workflow_path_has_token(rel_parts, {"gate", "gates"}) or (
        "mutation gate" in lowered_text or "local gate" in lowered_text
    ):
        return "gate"
    if _workflow_path_has_token(rel_parts, {"procedure", "procedures", "runbook", "runbooks"}) or (
        "procedure:" in lowered_text or "runbook" in lowered_text
    ):
        return "procedure"
    if _workflow_path_has_policy_marker(rel_parts) or "policy:" in lowered_text:
        return "policy"
    if path.suffix.lower() in {".toml", ".yaml", ".yml", ".json"}:
        return "config"
    return "doc"


def _workflow_path_has_token(rel_parts: tuple[str, ...], tokens: set[str]) -> bool:
    return any(token in tokens for part in rel_parts for token in _workflow_path_tokens(part))


def _workflow_path_has_policy_marker(rel_parts: tuple[str, ...]) -> bool:
    for part in rel_parts:
        tokens = _workflow_path_tokens(part)
        if tokens in {("policy",), ("policies",)}:
            return True
        if tokens and tokens[-1] in {"policy", "policies"}:
            return bool(set(tokens[:-1]) & _WORKFLOW_POLICY_PATH_QUALIFIERS)
    return False


def _workflow_path_tokens(part: str) -> tuple[str, ...]:
    return tuple(token for token in re.split(r"[^a-z0-9]+", Path(part).stem.lower()) if token)


def _is_user_global_agents_path(path: Path) -> bool:
    return path.resolve().is_relative_to((Path.home() / ".agents").resolve())


def _workflow_inventory_signals(
    source_path: str,
    raw_text: str,
    source_kind: str,
) -> list[str]:
    haystack = f"{source_path}\n{raw_text}".lower()
    signals: list[str] = []
    for signal, needles in _WORKFLOW_INVENTORY_SIGNAL_NEEDLES:
        if any(_contains_signal(haystack, needle) for needle in needles):
            signals.append(signal)
    if source_kind in {
        "global-skill",
        "repo-local-skill",
        "agent-instruction",
        "policy",
        "gate",
        "procedure",
        "handoff",
    }:
        signals.append(source_kind)
    return _dedupe_strings(signals)


def _workflow_material_scope(
    source_kind: str,
    source_path: str,
    path: Path,
    raw_text: str,
) -> str:
    lowered_text = raw_text.lower()
    if source_kind == "global-skill":
        return "reusable-workflow-material"
    if source_kind in {"repo-local-skill", "agent-instruction", "config"}:
        return "fork-local-authority-material"
    if source_kind in {"policy", "gate"}:
        if _workflow_path_or_content_is_fork_local_authority(source_path, path, lowered_text):
            return "fork-local-authority-material"
        return "reusable-workflow-material"
    if _workflow_path_or_content_is_fork_local_authority(source_path, path, lowered_text):
        return "fork-local-authority-material"
    return "reusable-workflow-material"


def _workflow_path_or_content_is_fork_local_authority(
    source_path: str,
    path: Path,
    lowered_text: str,
) -> bool:
    lowered_path = source_path.lower()
    path_parts = tuple(part.lower() for part in path.parts)
    user_global_agents_path = _is_user_global_agents_path(path)
    return (
        (lowered_path in {"agents.md", "claude.md"} and not user_global_agents_path)
        or (
            not user_global_agents_path
            and (
                lowered_path.startswith(".agents/")
                or lowered_path.startswith("docs/agents/")
                or ".agents" in path_parts
                or any(
                    left == "docs" and right == "agents"
                    for left, right in zip(path_parts, path_parts[1:], strict=False)
                )
            )
        )
        or "fork-local authority" in lowered_text
        or "maintained fork" in lowered_text
    )


def _workflow_catalog_target(signals: list[str], source_kind: str, raw_text: str) -> str:
    signal_set = set(signals)
    lowered_text = raw_text.lower()
    if source_kind == "handoff":
        return "human-handoff-contracts"
    if "operator-onboarding" in lowered_text or "plugin health" in lowered_text:
        return "operator-onboarding"
    if "fork authority migration" in lowered_text or "source material" in lowered_text:
        return "fork-authority-migration"
    if "blocker" in signal_set and "handoff" not in signal_set:
        return "blocker-resolution"
    if "review-publication" in signal_set or "review-automation" in signal_set:
        if source_kind == "gate" or "review preparation" in lowered_text:
            return "review-preparation"
        return "publication-closeout"
    if "upstream-sync" in signal_set or "upstream-evidence" in signal_set:
        if "execute" in lowered_text or "execution" in lowered_text:
            return "guarded-sync-execution"
        if source_kind in {"agent-instruction", "gate"} and "mutation gate" in lowered_text:
            return "guarded-sync-execution"
        return "upstream-sync-planning"
    if "workflow-catalog" in signal_set:
        return "operator-onboarding"
    return f"{source_kind}-workflow-candidate"


def _workflow_operator_intent(target: str, signals: list[str], source_kind: str) -> str:
    intents = {
        "operator-onboarding": (
            "Verify Fork Ops plugin health and workflow catalog visibility before work begins."
        ),
        "fork-authority-migration": (
            "Map existing fork-local guidance into Fork Ops-readable authority."
        ),
        "upstream-sync-planning": "Plan a safe upstream sync without mutating repository refs.",
        "guarded-sync-execution": "Execute upstream sync work after mutation gates pass.",
        "review-preparation": "Prepare a fork-local change for configured review gates.",
        "publication-closeout": "Close out fork-local review and publication after gates pass.",
        "blocker-resolution": "Explain a Fork Ops blocker and route the next safe action.",
        "human-handoff-contracts": (
            "Preserve workflow state and return expectations across an operator or agent handoff."
        ),
    }
    if target in intents:
        return intents[target]
    if "operator-intent" in signals:
        return "Capture a reusable operator intent for future workflow catalog review."
    return f"Classify {source_kind} material for workflow catalog backlog review."


def _workflow_coverage_status(
    target: str,
    contracts: dict[str, WorkflowContract],
) -> str:
    contract = contracts.get(target)
    if contract is None:
        return "backlog-candidate"
    if contract.available and contract.implementation_status == "current":
        return "covered-current"
    if contract.available and contract.implementation_status == "diagnostic-only":
        return "covered-diagnostic-only"
    return "cataloged-not-implemented"


def _workflow_inventory_evidence(
    entry_id: str,
    raw_text: str,
    signals: list[str],
) -> list[dict[str, Any]]:
    evidence: list[dict[str, Any]] = []
    for index, signal in enumerate(signals, start=1):
        line = _workflow_signal_line(raw_text, signal)
        evidence.append(
            {
                "id": f"{entry_id}:e{index}",
                "signal": signal,
                "line": line,
                "basis": _workflow_signal_basis(signal),
            }
        )
    return evidence


def _workflow_signal_line(raw_text: str, signal: str) -> int | None:
    needles = _WORKFLOW_SIGNAL_NEEDLE_MAP.get(signal)
    if needles is None:
        return None
    lowered_needles = tuple(needle.lower() for needle in needles)
    for index, line in enumerate(raw_text.splitlines(), start=1):
        lowered_line = line.lower()
        if any(needle in lowered_line for needle in lowered_needles):
            return index
    return None


def _workflow_signal_basis(signal: str) -> str:
    return {
        "workflow-catalog": "workflow catalog language",
        "operator-intent": "operator intent or trigger language",
        "fork-local-authority": "fork-local authority language",
        "upstream-sync": "upstream sync language",
        "upstream-evidence": "upstream evidence command language",
        "review-publication": "review or publication workflow language",
        "review-automation": "review automation language",
        "mutation-gate": "mutation or gate language",
        "procedure": "procedure or runbook language",
        "policy": "policy language",
        "handoff": "handoff or return contract language",
        "blocker": "blocker language",
    }.get(signal, "source path or source kind")


def _workflow_catalog_evidence(
    entries: list[dict[str, Any]],
    contracts: dict[str, WorkflowContract],
) -> list[dict[str, Any]]:
    groups: dict[str, dict[str, Any]] = {}
    for entry in entries:
        workflow_id = entry["likely_workflow_catalog_target"]
        contract = contracts.get(workflow_id)
        if contract is None:
            continue
        group = groups.setdefault(
            workflow_id,
            {
                "workflow_id": workflow_id,
                "workflow_title": contract.title,
                "implementation_status": contract.implementation_status,
                "available": contract.available,
                "coverage_status": entry["coverage_status"],
                "entry_refs": [],
            },
        )
        group["entry_refs"].append(
            {
                "entry_id": entry["id"],
                "source_path": entry["source_path"],
                "evidence_ids": [item["id"] for item in entry["evidence"]],
            }
        )
    return [groups[key] for key in sorted(groups)]


def _workflow_backlog_candidates(entries: list[dict[str, Any]]) -> list[dict[str, Any]]:
    candidates = []
    for entry in entries:
        if entry["coverage_status"] != "backlog-candidate":
            continue
        candidates.append(
            {
                "entry_id": entry["id"],
                "source_path": entry["source_path"],
                "source_kind": entry["source_kind"],
                "material_scope": entry["material_scope"],
                "candidate_operator_intent": entry["candidate_operator_intent"],
                "candidate_target": entry["likely_workflow_catalog_target"],
                "coverage_status": entry["coverage_status"],
                "evidence_ids": [item["id"] for item in entry["evidence"]],
            }
        )
    return sorted(candidates, key=lambda item: (item["candidate_target"], item["source_path"]))


def _missing_requirements(config: dict[str, Any], level: str) -> Iterable[str]:
    requirements = {
        "identified": [
            "schema_version",
            "repository.host",
            "repository.owner",
            "repository.name",
            "repository.default_branch",
            "fork_remotes",
            "upstreams",
            "change_targets.default",
        ],
        "scoutable": [
            "authority.source_order",
            "local_surfaces",
        ],
        "track-aware": [
            "release_channels",
            "upstream_tracks",
        ],
        "sync-ready": [
            "sync_policy.default_sync_baseline",
            "sync_policy.preserve_commit_identity",
            "sync_policy.forbid_history_rewrites",
            "sync_policy.allowed_merge_methods",
            "divergence_policy.uncertainty_destination",
        ],
        "review-ready": [
            "review_policy",
            "publication_policy",
            "local_gates",
        ],
        "provenance-ready": [
            "local_gates.provenance",
        ],
    }
    cumulative: list[str] = []
    for candidate in CAPABILITY_LEVELS:
        cumulative.extend(requirements[candidate])
        if candidate == level:
            break
    for path in cumulative:
        if not _requirement_satisfied(config, path):
            yield path


def _level_enables(level: str) -> str:
    return {
        "identified": "Basic fork recognition and authority discovery.",
        "scoutable": "Upstream and fork research with source-quality guidance.",
        "track-aware": (
            "Baseline comparison, upstream freshness reports, and upstream-ref "
            "maintenance planning."
        ),
        "sync-ready": "Ancestry-preserving upstream sync planning and validation.",
        "review-ready": "End-to-end PR review and publication closeout.",
        "provenance-ready": "Source, artifact, runtime, or install-state provenance diagnosis.",
    }[level]


def _requirement_satisfied(config: dict[str, Any], dotted_path: str) -> bool:
    exists, current = _path_value(config, dotted_path)
    if not exists or current is None:
        return False
    if dotted_path in {
        "sync_policy.preserve_commit_identity",
        "sync_policy.forbid_history_rewrites",
    }:
        return current is True
    if isinstance(current, str | list | dict) and not current:
        return False
    return True


def _path_value(config: dict[str, Any], dotted_path: str) -> tuple[bool, Any]:
    current: Any = config
    for part in dotted_path.split("."):
        if not isinstance(current, dict) or part not in current:
            return False, None
        current = current[part]
    return True, current


def _section_items(config: dict[str, Any], key: str) -> list[Any]:
    items = config.get(key, [])
    return items if isinstance(items, list) else []


def _mapping_section(config: dict[str, Any], key: str) -> dict[str, Any]:
    section = config.get(key, {})
    return section if isinstance(section, dict) else {}


def _ids(items: Iterable[Any]) -> set[str]:
    return {
        item["id"] for item in items if isinstance(item, dict) and isinstance(item.get("id"), str)
    }


def _duplicate_id_diagnostics(section: str, items: Iterable[Any]) -> list[Diagnostic]:
    diagnostics: list[Diagnostic] = []
    seen: set[str] = set()
    for index, item in enumerate(items):
        item_id = item.get("id") if isinstance(item, dict) else None
        if not isinstance(item_id, str):
            continue
        if item_id in seen:
            diagnostics.append(
                Diagnostic(
                    severity="error",
                    code="reference.duplicate_id",
                    message=f"Duplicate id '{item_id}' in {section}.",
                    path=f"{section}.{index}.id",
                )
            )
        seen.add(item_id)
    return diagnostics


def _check_remote_url(
    repo: Path,
    item: dict[str, Any],
    path: str,
    diagnostics: list[Diagnostic],
) -> None:
    name_field = "remote" if isinstance(item.get("remote"), str) else "name"
    name = item.get(name_field)
    expected_url = item.get("url")
    if not isinstance(name, str):
        return
    actual_url = _git_output(repo, "remote", "get-url", name)
    if actual_url is None:
        diagnostics.append(
            Diagnostic(
                severity="warning",
                code="git.remote_missing",
                message=f"Configured remote does not exist locally: {name}",
                path=f"{path}.{name_field}",
            )
        )
        return
    if expected_url and actual_url != expected_url:
        diagnostics.append(
            Diagnostic(
                severity="warning",
                code="git.remote_url_mismatch",
                message=f"Configured URL for remote '{name}' differs from local Git.",
                path=f"{path}.url",
                detail={"configured": expected_url, "actual": actual_url},
            )
        )


def _git_ok(repo: Path, *args: str) -> bool:
    return _run_git(repo, *args).returncode == 0


def _git_output(repo: Path, *args: str) -> str | None:
    result = _run_git(repo, *args)
    if result.returncode != 0:
        return None
    return result.stdout.strip()


def _run_git(repo: Path, *args: str) -> subprocess.CompletedProcess[str]:
    command = ["git", "-C", str(repo), *args]
    try:
        return subprocess.run(
            command,
            check=False,
            text=True,
            capture_output=True,
            encoding="utf-8",
            errors="replace",
            timeout=10,
        )
    except subprocess.TimeoutExpired as exc:
        return subprocess.CompletedProcess(command, 124, "", str(exc))
    except FileNotFoundError as exc:
        return subprocess.CompletedProcess(command, 127, "", str(exc))


def _iter_candidate_paths(repo: Path) -> Iterable[Path]:
    roots = [
        repo / "AGENTS.md",
        repo / "CLAUDE.md",
        repo / "docs" / "agents",
        repo / "docs" / "adr",
        repo / "docs" / "maintainers",
        repo / ".agents",
        repo / ".codex",
    ]
    for root in roots:
        if root.is_file():
            yield root
        elif root.is_dir():
            for path in root.rglob("*"):
                if not path.is_file():
                    continue
                relative_parts = path.relative_to(root).parts
                if any(part in _CANDIDATE_SCAN_SKIP_DIRS for part in relative_parts[:-1]):
                    continue
                if path.suffix.lower() in _CANDIDATE_FILE_SUFFIXES:
                    yield path


def _read_text(path: Path) -> str:
    try:
        return path.read_text(errors="ignore")
    except OSError:
        return ""


def _read_bytes(path: Path) -> bytes:
    try:
        return path.read_bytes()
    except OSError:
        return b""


def _file_sha256(path: Path) -> str:
    try:
        return hashlib.sha256(path.read_bytes()).hexdigest()
    except OSError:
        return ""


def _fork_signals(text: str) -> list[str]:
    signals = []
    for needle in _FORK_SIGNAL_NEEDLES:
        if _contains_signal(text, needle):
            signals.append(needle)
    return signals


def _candidate_domains(signals: list[str]) -> list[str]:
    domains = []
    if any(
        signal in signals
        for signal in (
            "github releases",
            "release tag",
            "stable release",
            "upstream",
            "upstream-main",
            "upstream-stable",
            "upstream track",
        )
    ):
        domains.append("upstream_intelligence")
    if any(signal in signals for signal in ("sync", "baseline", "merge-base")):
        domains.append("sync")
    if "divergence" in signals:
        domains.append("divergence")
    if any(signal in signals for signal in ("force-push", "disabled")):
        domains.append("authority")
    if "upstream issue" in signals or "upstream issues" in signals:
        domains.append("authority")
    if any(
        signal in signals
        for signal in (
            "code scanning",
            "issue tracker",
            "prs",
            "pull request",
            "pull requests",
            "review automation",
            "review bot",
            "review thread",
        )
    ):
        domains.append("review_publication")
    return sorted(set(domains))


def _extracted_facts(text: str) -> list[dict[str, str]]:
    lowered_text = text.lower()
    facts: list[dict[str, str]] = []
    refs = sorted(
        set(re.findall(r"`([^`]*(?:upstream|origin/upstream)[^`]*)`", text, re.IGNORECASE))
    )
    for ref in refs:
        if _looks_like_ref_role(ref):
            facts.append(
                {
                    "kind": "ref_role",
                    "value": ref,
                    "suggested_config": "upstream_tracks",
                }
            )

    if "github releases" in lowered_text or "gh release list" in lowered_text:
        facts.append(
            {
                "kind": "release_channel_source",
                "value": "github-releases",
                "suggested_config": "release_channels",
            }
        )

    if (
        "stable release" in lowered_text
        or "latest stable" in lowered_text
        or "exclude-pre-releases" in lowered_text
    ):
        facts.append(
            {
                "kind": "release_channel",
                "value": "stable",
                "suggested_config": "release_channels",
            }
        )

    for ref in _default_sync_baseline_refs(text):
        facts.append(
            {
                "kind": "default_sync_baseline",
                "value": ref,
                "suggested_config": "sync_policy.default_sync_baseline",
            }
        )

    if (
        "push url `disabled`" in lowered_text
        or "push url is disabled" in lowered_text
        or "push url disabled" in lowered_text
    ):
        facts.append(
            {
                "kind": "disabled_upstream_push",
                "value": "upstream",
                "suggested_config": "upstreams.push",
            }
        )

    if "force-push" in lowered_text:
        facts.append(
            {
                "kind": "forbidden_history_rewrite",
                "value": "force-push",
                "suggested_config": "sync_policy.forbid_history_rewrites",
            }
        )

    if "merge-base --is-ancestor" in lowered_text:
        facts.append(
            {
                "kind": "ancestry_check",
                "value": "merge-base --is-ancestor",
                "suggested_config": "sync_policy.ancestry_checks",
            }
        )

    facts.extend(_extract_remote_url_facts(text))

    return _unique_facts(facts)


def _looks_like_ref_role(ref: str) -> bool:
    normalized = ref.lower()
    return (
        normalized.startswith("upstream/")
        or normalized.startswith("origin/upstream-")
        or normalized in {"upstream-main", "upstream-stable"}
    )


def _default_sync_baseline_refs(text: str) -> list[str]:
    ref_pattern = re.compile(
        r"(?<![a-zA-Z0-9_/-])"
        r"(origin/upstream-[A-Za-z0-9._/-]*[A-Za-z0-9_-])"
        r"(?![a-zA-Z0-9_/-])"
    )
    refs: set[str] = set()
    lowered_text = text.lower()
    for match in ref_pattern.finditer(text):
        window = lowered_text[max(0, match.start() - 160) : match.end() + 160]
        if "default" not in window or "baseline" not in window:
            continue
        refs.add(match.group(1))
    return sorted(refs)


def _contains_signal(text: str, needle: str) -> bool:
    pattern = rf"(?<![a-z0-9_/-]){re.escape(needle)}(?![a-z0-9_/-])"
    return re.search(pattern, text) is not None


def _extract_remote_url_facts(text: str) -> list[dict[str, str]]:
    facts: list[dict[str, str]] = []
    for line in text.splitlines():
        remote_name = _remote_name_for_line(line)
        if not remote_name:
            continue
        for url in _extract_urls(line):
            if not _github_repo_root_slug_from_url(url):
                continue
            suggested_config = "fork_remotes.url" if remote_name == "origin" else "upstreams.url"
            facts.append(
                {
                    "kind": "remote_url",
                    "value": f"{remote_name}:{url}",
                    "suggested_config": suggested_config,
                }
            )
    return facts


def _remote_name_for_line(line: str) -> str:
    lowered = line.lower()
    if "upstream" in lowered:
        return "upstream"
    if "origin" in lowered or "fork" in lowered:
        return "origin"
    return ""


def _unique_facts(facts: list[dict[str, str]]) -> list[dict[str, str]]:
    seen: set[tuple[str, str, str]] = set()
    unique: list[dict[str, str]] = []
    for fact in facts:
        key = (fact["kind"], fact["value"], fact["suggested_config"])
        if key in seen:
            continue
        seen.add(key)
        unique.append(fact)
    return unique


def _candidate_kind(rel_path: str) -> str:
    if rel_path.endswith("AGENTS.md") or rel_path.endswith("CLAUDE.md"):
        return "agent_instruction"
    if "/skills/" in rel_path:
        return "skill"
    if rel_path.endswith(".toml"):
        return "config"
    if rel_path.endswith(".md"):
        return "doc"
    return "other"


def _proposed_destination(rel_path: str, signals: list[str]) -> str:
    if any(
        signal in signals
        for signal in (
            "upstream track",
            "release channel",
            "release tag",
            "stable release",
            "upstream-main",
            "upstream-stable",
        )
    ):
        return "fork ops config release_channels/upstream_tracks plus operation guide"
    if "merge-base" in signals or "sync" in signals:
        return "fork ops config sync_policy/divergence_policy plus sync runbook"
    if any(
        signal in signals
        for signal in (
            "code scanning",
            "issue tracker",
            "prs",
            "pull request",
            "pull requests",
            "review automation",
            "review bot",
            "review thread",
        )
    ):
        return "review_policy/publication_policy or future Repo Ops equipment"
    if "/skills/" in rel_path:
        return "Fork Ops skill or migration note"
    return "Fork-local authority or migration assessment evidence"


def _portability_hint(rel_path: str, signals: list[str]) -> str:
    signal_set = set(signals)
    if "issue-tracker" in rel_path or "triage-labels" in rel_path:
        return "repo-ops-candidate"
    if _has_fork_specific_signal(signal_set):
        return "fork-specific"
    if _has_review_publication_signal(signal_set):
        return "repo-ops-candidate"
    return "shared-with-fork-policy"


def _has_review_publication_signal(signals: set[str]) -> bool:
    return any(
        signal in signals
        for signal in (
            "code scanning",
            "issue tracker",
            "prs",
            "pull request",
            "pull requests",
            "review automation",
            "review bot",
            "review thread",
        )
    )


def _has_fork_specific_signal(signals: set[str]) -> bool:
    return any(
        signal in signals
        for signal in (
            "divergence",
            "merge-base",
            "release channel",
            "release tag",
            "stable release",
            "sync",
            "upstream",
            "upstream issue",
            "upstream issues",
            "upstream-main",
            "upstream-stable",
            "upstream track",
        )
    )


def _slug_id(value: str) -> str:
    return value.lower().replace("_", "-").replace(" ", "-").replace("/", "-")
