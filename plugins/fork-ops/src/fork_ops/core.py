"""Fork Ops config loading, validation, reporting, and migration assessment."""

from __future__ import annotations

import copy
import hashlib
import json
import os
import re
import subprocess
import tomllib
import uuid
from collections.abc import Iterable
from datetime import date, datetime, time
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from .schema import CAPABILITY_LEVELS, CONFIG_SCHEMA, Diagnostic, schema_diagnostics

CONFIG_RELATIVE_PATH = Path(".agents/fork-ops.toml")
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
    diagnostics = schema_diagnostics(parsed) + reference_diagnostics(normalize_config(parsed))
    return {
        "mode": "non-mutating",
        "purpose": "migration plan input",
        "target_path": str(CONFIG_RELATIVE_PATH),
        "operation": "create" if not find_config_path(repo).exists() else "review-and-merge",
        "requires_review": True,
        "config": proposed_config,
        "toml": toml,
        "diagnostics": [item.to_dict() for item in diagnostics],
        "evidence": _proposal_evidence(migration_candidates),
        "limitations": [
            "This deterministic proposal is not a migration execution.",
            "Review against source materials before applying.",
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
    blockers = _migration_plan_blockers(migration_candidates, proposed_config_patch)
    return {
        "repo_path": str(repo),
        "mode": "non-mutating",
        "operation": "migration-plan",
        "requires_review": True,
        "summary": {
            "candidate_count": len(migration_candidates),
            "evidence_source_count": len(evidence),
            "retained_source_material_count": len(retained_source_materials),
            "blocker_count": len(blockers),
            "semantic_coverage": _semantic_coverage_status(blockers),
        },
        "evidence": evidence,
        "proposed_config_patch": proposed_config_patch,
        "retained_source_materials": retained_source_materials,
        "deferred_removals": _deferred_removals(retained_source_materials),
        "blockers": blockers,
        "required_review": _migration_plan_required_review(blockers),
        "validation_requirements": _migration_plan_validation_requirements(),
        "limitations": [
            "This migration plan is non-mutating and does not apply config or edit source files.",
            "Retain source materials until migration dry run and migration execution exist.",
            "Review semantic coverage before replacing or deleting fork-local authority.",
        ],
        "next_actions": [
            "Review proposed_config_patch against evidence.",
            "Resolve blockers before migration dry run.",
            "Run validation requirements after any manual application of the proposed config.",
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
            "retained_material_count": len(retained_materials),
            "blocked_step_count": len(blocked_steps),
            "verification_command_count": len(expected_verification_commands),
        },
        "file_edits": file_edits,
        "config_changes": config_changes,
        "retained_materials": retained_materials,
        "deferred_removals": deferred_removals,
        "blocked_steps": blocked_steps,
        "expected_verification_commands": expected_verification_commands,
        "limitations": [
            "This migration dry run is non-mutating and does not apply config or edit files.",
            (
                "Retain source materials until migration execution validates the replacement."
            ),
        ],
        "next_actions": [
            "Review file_edits and config_changes against the migration plan evidence.",
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
            "blocker_count": len(blockers),
            "verification_result_count": len(verification_results),
        },
        "applied_edits": applied_edits,
        "skipped_edits": skipped_edits,
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
        candidate["path"] for candidate in candidates if not candidate["extracted_facts"]
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

    if ("default_sync_baseline", "origin/upstream-stable") in fact_values:
        config["sync_policy"] = {
            "default_sync_baseline": "upstream-stable",
            "default_sync_ref": "origin/upstream-stable",
            "fork_sync_start_ref": f"origin/{default_branch}",
            "preserve_commit_identity": True,
            "forbid_history_rewrites": True,
            "allowed_merge_methods": ["merge", "ff-only"],
            "fork_sync_methods": ["merge"],
            "track_update_methods": ["ff-only"],
            "ancestry_checks": [
                "git merge-base --is-ancestor origin/upstream-stable HEAD",
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
        domains = candidate["domains"]
        surface = {
            "kind": candidate["kind"],
            "path": candidate["path"],
            "domain": _primary_domain(candidate),
            "domains": domains,
            "portability_hint": candidate["portability_hint"],
            "portability_hints": _portability_hints(candidate),
            "notes": "Migration assessment candidate; review before replacing source material.",
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

    if (
        "origin/upstream-stable" in lowered_text
        and "default" in lowered_text
        and "baseline" in lowered_text
    ):
        facts.append(
            {
                "kind": "default_sync_baseline",
                "value": "origin/upstream-stable",
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
    return value.lower().replace("_", "-").replace(" ", "-")
