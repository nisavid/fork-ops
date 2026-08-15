"""Fork Ops config loading, validation, reporting, and migration assessment."""

from __future__ import annotations

import copy
import errno
import hashlib
import json
import os
import re
import selectors
import shlex
import signal as process_signal
import stat
import subprocess
import sys
import tomllib
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from datetime import date, datetime, time
from pathlib import Path
from time import monotonic
from typing import IO, Any, cast
from urllib.parse import SplitResult, urlparse, urlsplit, urlunsplit

from ._contracts import (
    ActivationReadinessValue,
    ArtifactKind,
    Evidence,
    MutationStateValue,
    OperationalContinuityValue,
    OutcomeValue,
    PlanExecutabilityValue,
    ReplacementCoverageValue,
    State,
    StateDimension,
    artifact_contract,
    current_artifact_version,
    operation_artifact,
    versioned_artifact,
)
from ._contracts import (
    artifact_identity_diagnostic as _registered_artifact_identity_diagnostic,
)
from .schema import CAPABILITY_LEVELS, CONFIG_SCHEMA, Diagnostic, schema_diagnostics
from .workflow_catalog import WorkflowContract, workflow_contracts

CONFIG_RELATIVE_PATH = Path(".agents/fork-ops.toml")
_EQUIPMENT_REVIEW_CONTRACT = artifact_contract(ArtifactKind.EQUIPMENT_REVIEW)
_EQUIPMENT_REVIEW_VERSION = str(
    current_artifact_version(ArtifactKind.EQUIPMENT_REVIEW)
)
SUPPORTED_CONFIG_SCHEMA_VERSION = "0.1"
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
    "fork_ops_equipment_migration_preflight",
    "fork_ops_migration_plan",
    "fork_ops_migration_dry_run",
    "fork_ops_migration_execute",
    "fork_ops_migration_blocker_resolution",
    "fork_ops_migration_config_patch",
    "fork_ops_schema",
    "fork_ops_workflow_catalog",
    "fork_ops_workflow_migration_inventory",
)
_MIGRATION_OPERATION_BY_ARTIFACT_KIND = {
    ArtifactKind.MIGRATION_ASSESSMENT: "migration-assessment",
    ArtifactKind.MIGRATION_PLAN: "migration-plan",
    ArtifactKind.MIGRATION_DRY_RUN: "migration-dry-run",
    ArtifactKind.MIGRATION_EXECUTION_RESULT: "migration-execution",
    ArtifactKind.MIGRATION_BLOCKER_EXPLANATION: "migration-blocker-explanation",
}
_MIGRATION_ARTIFACT_KIND_BY_VALUE = {
    kind.value: kind for kind in _MIGRATION_OPERATION_BY_ARTIFACT_KIND
}
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

# All limits are part of the public operation contract. Equality is allowed; the
# first byte, item, level, or instant beyond a limit fails or marks a scan incomplete.
MAX_SCAN_ROOTS = 32
MAX_SCAN_ENTRIES = 20_000
MAX_SCAN_FILES = 4_000
MAX_SCAN_DEPTH = 32
MAX_FILE_BYTES = 1_048_576
MAX_TOTAL_READ_BYTES = 16_777_216
MAX_RESULT_ITEMS = 4_000
MAX_OBJECT_NODES = 50_000
MAX_OBJECT_DEPTH = 64
MAX_CONTAINER_ITEMS = 10_000
MAX_STRING_BYTES = 1_048_576
MAX_OBJECT_BYTES = 4_194_304
MAX_PATH_BYTES = 4_096
MAX_SUBPROCESS_STREAM_BYTES = 1_048_576
MAX_SUBPROCESS_OUTPUT_BYTES = 2_097_152
MAX_OPERATION_SECONDS = 30.0
_READ_CHUNK_BYTES = 64 * 1024


@dataclass
class _OperationBudget:
    started_at: float = field(default_factory=monotonic)
    root_count: int = 0
    entry_count: int = 0
    file_count: int = 0
    byte_count: int = 0
    result_count: int = 0
    incomplete_reasons: list[dict[str, str]] = field(default_factory=list)

    def mark_incomplete(self, code: str, subject: str = "") -> None:
        reason = {"code": code}
        if subject:
            reason["subject"] = subject
        if reason not in self.incomplete_reasons:
            self.incomplete_reasons.append(reason)

    def check_time(self) -> bool:
        if monotonic() - self.started_at <= MAX_OPERATION_SECONDS:
            return True
        self.mark_incomplete("limit.elapsed_time")
        return False

    def accounting(self) -> dict[str, Any]:
        return {
            "complete": not self.incomplete_reasons,
            "limit_reached": bool(self.incomplete_reasons),
            "limits": {
                "roots": MAX_SCAN_ROOTS,
                "entries": MAX_SCAN_ENTRIES,
                "files": MAX_SCAN_FILES,
                "depth": MAX_SCAN_DEPTH,
                "file_bytes": MAX_FILE_BYTES,
                "aggregate_bytes": MAX_TOTAL_READ_BYTES,
                "results": MAX_RESULT_ITEMS,
                "object_nodes": MAX_OBJECT_NODES,
                "object_depth": MAX_OBJECT_DEPTH,
                "container_items": MAX_CONTAINER_ITEMS,
                "string_bytes": MAX_STRING_BYTES,
                "object_bytes": MAX_OBJECT_BYTES,
                "path_bytes": MAX_PATH_BYTES,
                "subprocess_stream_bytes": MAX_SUBPROCESS_STREAM_BYTES,
                "subprocess_output_bytes": MAX_SUBPROCESS_OUTPUT_BYTES,
                "elapsed_seconds": MAX_OPERATION_SECONDS,
            },
            "observed": {
                "roots": self.root_count,
                "entries": self.entry_count,
                "files": self.file_count,
                "bytes": self.byte_count,
                "results": self.result_count,
            },
            "incomplete_reasons": list(self.incomplete_reasons),
        }


@dataclass(frozen=True)
class _CreatedFileIdentity:
    device: int
    inode: int
    size: int
    content_sha256: str
    modified_time_ns: int
    change_time_ns: int
    parent_device: int
    parent_inode: int
    root_device: int
    root_inode: int


@dataclass
class _BoundRepository:
    path: Path
    canonical_path: Path
    descriptor: int
    device: int
    inode: int

    def close(self) -> None:
        os.close(self.descriptor)


class _IndeterminateCreatedFileError(OSError):
    """A target may exist, but its exact post-create state cannot be proven."""


class _TargetAlreadyExistsError(FileExistsError):
    """The descriptor-relative final target existed before this mutation."""


class _CreatedParentUnavailableError(OSError):
    """The parent was created, but its exact post-create state cannot be proven."""


_EXPECTED_MCP_REGISTRATION: dict[str, Any] = {
    "mcpServers": {
        "fork-ops": {
            "command": "uv",
            "args": ["run", "--project", ".", "--extra", "mcp", "fork-ops-mcp"],
            "cwd": ".",
        }
    }
}
_JSON_SEQUENCE_TYPES: tuple[type[list[object]], type[tuple[object, ...]]] = (list, tuple)
_EMPTY_REQUIREMENT_TYPES: tuple[
    type[str],
    type[list[object]],
    type[dict[object, object]],
] = (str, list, dict)
_CANDIDATE_FILE_SUFFIXES = {".json", ".md", ".toml", ".yaml", ".yml"}
_CANDIDATE_SCAN_SKIP_DIRS = {
    ".git",
    ".mypy_cache",
    ".ruff_cache",
    ".tox",
    ".venv",
    "__pycache__",
    "build",
    "dist",
    "node_modules",
    "target",
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
SOURCE_MATERIAL_REVIEW_DECISION_TYPES = (
    "retain",
    "exclude",
    "defer",
    "needs-human-decision",
    "unsupported-extractor",
)
MIGRATION_REVIEW_ARTIFACT_RELATIVE_PATH = "docs/agents/fork-ops-migration-review.md"
EQUIPMENT_REVIEW_RECORD_RELATIVE_PATH = "docs/agents/fork-ops-equipment-review.toml"
MIGRATION_DISCOVERY_EXCLUDED_PATHS = frozenset(
    {
        CONFIG_RELATIVE_PATH.as_posix(),
        EQUIPMENT_REVIEW_RECORD_RELATIVE_PATH,
    }
)
EQUIPMENT_DISPOSITION_TYPES = (
    "migrate_to_fork_ops",
    "retain_authoritative_owner",
    "defer_to_follow_up",
    "ignore",
    "decide_item_by_item",
)
EQUIPMENT_DECISION_STATUS_TYPES = (
    "proposed",
    "pending_operator_decision",
    "reviewed",
    "superseded",
)
EQUIPMENT_DISCOVERY_SCOPE_KINDS = (
    "repo-local",
    "operator-source-root",
    "user-global",
    "maintained-fork",
    "adjacent-root",
)
EQUIPMENT_DISCOVERY_SCOPE_STATUSES = ("scanned", "unresolvable", "rejected")
SCAN_PROFILES = ("custom", "full-breadth")
ACCOUNTING_STATUS_TYPES = (
    "implemented_workflow",
    "partial_workflow",
    "planned_workflow",
    "fork_local_config",
    "retained_fork_local_authority",
    "repo_ops_candidate",
    "out_of_scope",
    "unassessed",
)
FULL_BREADTH_USER_ROOTS = (
    ".agents/skills",
    ".agents/spec",
    ".agents/plan",
    ".codex/skills",
    ".codex/plugins/cache/fork-ops",
)
FULL_BREADTH_MAINTAINED_REPOS = (
    "fork-ops",
    "lemonade",
    "codex-app-linux",
    "warp",
    "utilyze",
    "arch-pkgs",
    "arch-strix-halo-pkgs",
)
FULL_BREADTH_ADJACENT_REPOS = (
    "agent-armory",
    "tuned-limine",
)
FULL_BREADTH_REPO_BASE_ENV = "FORK_OPS_FULL_BREADTH_REPO_BASE"
FULL_BREADTH_MAINTAINED_REPOS_ENV = "FORK_OPS_FULL_BREADTH_MAINTAINED_REPOS"
FULL_BREADTH_ADJACENT_REPOS_ENV = "FORK_OPS_FULL_BREADTH_ADJACENT_REPOS"
UNAVAILABLE_MIGRATION_WORK = (
    "source-material replacement/removal",
    "arbitrary migration edits",
    "broad upstream sync mutation",
    "PR publication closeout",
)


class ForkOpsError(RuntimeError):
    """Base error for expected Fork Ops failures."""


class _BoundedReadError(ForkOpsError):
    """A root-bound file read could not be completed safely."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


def _require_explicit_repository_path(repo_path: str | Path | None) -> str | Path:
    if not isinstance(repo_path, str | Path) or not str(repo_path).strip():
        raise ForkOpsError("Mutation requires an explicit non-empty repository path.")
    return repo_path


def _validate_bounded_object(value: Any, *, label: str) -> None:
    """Reject structures that cannot be safely copied, validated, or serialized."""
    pending: list[tuple[Any, int]] = [(value, 0)]
    seen_containers: set[int] = set()
    node_count = 0
    object_bytes = 0
    while pending:
        item, depth = pending.pop()
        node_count += 1
        if node_count > MAX_OBJECT_NODES:
            raise ForkOpsError(f"{label} exceeds the object node limit.")
        if depth > MAX_OBJECT_DEPTH:
            raise ForkOpsError(f"{label} exceeds the object nesting limit.")
        if isinstance(item, str):
            encoded_bytes = len(item.encode("utf-8"))
            if encoded_bytes > MAX_STRING_BYTES:
                raise ForkOpsError(f"{label} contains a string larger than the limit.")
            object_bytes += encoded_bytes
            if object_bytes > MAX_OBJECT_BYTES:
                raise ForkOpsError(f"{label} exceeds the aggregate object byte limit.")
            continue
        if item is None or isinstance(item, bool | float):
            continue
        if isinstance(item, datetime | date | time):
            continue
        if isinstance(item, int):
            if item.bit_length() > MAX_STRING_BYTES * 8:
                raise ForkOpsError(f"{label} contains an integer larger than the limit.")
            continue
        if isinstance(item, dict):
            identity = id(item)
            if identity in seen_containers:
                raise ForkOpsError(f"{label} contains a cyclic or aliased container.")
            seen_containers.add(identity)
            if len(item) > MAX_CONTAINER_ITEMS:
                raise ForkOpsError(f"{label} exceeds the container item limit.")
            for key, child in item.items():
                if not isinstance(key, str):
                    raise ForkOpsError(f"{label} object keys must be strings.")
                pending.append((child, depth + 1))
                pending.append((key, depth + 1))
            continue
        if isinstance(item, _JSON_SEQUENCE_TYPES):
            identity = id(item)
            if identity in seen_containers:
                raise ForkOpsError(f"{label} contains a cyclic or aliased container.")
            seen_containers.add(identity)
            if len(item) > MAX_CONTAINER_ITEMS:
                raise ForkOpsError(f"{label} exceeds the container item limit.")
            pending.extend((child, depth + 1) for child in item)
            continue
        raise ForkOpsError(f"{label} contains unsupported value type {type(item).__name__}.")


def _relative_path_parts(relative_path: str | Path) -> tuple[str, ...]:
    path = Path(relative_path)
    if path.is_absolute() or not path.parts:
        raise _BoundedReadError("path.invalid", "Read path must be non-empty and relative.")
    if any(part in {"", ".", ".."} for part in path.parts):
        raise _BoundedReadError("path.invalid", "Read path contains an unsafe component.")
    if len(path.parts) > MAX_SCAN_DEPTH:
        raise _BoundedReadError("limit.depth", "Read path exceeds the traversal depth limit.")
    if len(os.fsencode(path.as_posix())) > MAX_PATH_BYTES:
        raise _BoundedReadError("limit.path_bytes", "Read path exceeds the byte limit.")
    return path.parts


def _read_regular_at(
    parent_descriptor: int,
    name: str,
    *,
    budget: _OperationBudget | None = None,
) -> bytes:
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    if hasattr(os, "O_NONBLOCK"):
        flags |= os.O_NONBLOCK
    try:
        descriptor = os.open(name, flags, dir_fd=parent_descriptor)
    except OSError as exc:
        raise _BoundedReadError("read.open_failed", "Regular file could not be opened.") from exc
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode):
            raise _BoundedReadError("read.special_file", "Read target is not a regular file.")
        if budget is not None:
            budget.file_count += 1
            if budget.file_count > MAX_SCAN_FILES:
                raise _BoundedReadError("limit.files", "File count exceeds the scan limit.")
        content = bytearray()
        while True:
            if budget is not None and not budget.check_time():
                raise _BoundedReadError("limit.elapsed_time", "Read elapsed-time limit reached.")
            chunk = os.read(descriptor, _READ_CHUNK_BYTES)
            if not chunk:
                break
            content.extend(chunk)
            if budget is not None:
                budget.byte_count += len(chunk)
            if len(content) > MAX_FILE_BYTES:
                raise _BoundedReadError("limit.file_bytes", "File exceeds the byte limit.")
            if budget is not None and budget.byte_count > MAX_TOTAL_READ_BYTES:
                raise _BoundedReadError(
                    "limit.aggregate_bytes",
                    "Aggregate read bytes exceed the scan limit.",
                )
        after = os.fstat(descriptor)
        identity_fields = (
            "st_dev",
            "st_ino",
            "st_size",
            "st_mtime_ns",
            "st_ctime_ns",
        )
        if any(getattr(before, field) != getattr(after, field) for field in identity_fields):
            raise _BoundedReadError("read.changed", "File changed while it was being read.")
        if after.st_size != len(content):
            raise _BoundedReadError("read.changed", "File size changed while it was being read.")
        return bytes(content)
    finally:
        os.close(descriptor)


def _read_bound_regular_file(
    root: _BoundRepository,
    relative_path: str | Path,
    *,
    budget: _OperationBudget | None = None,
) -> bytes:
    parts = _relative_path_parts(relative_path)
    parent_descriptor = os.dup(root.descriptor)
    try:
        for component in parts[:-1]:
            flags = os.O_RDONLY
            if hasattr(os, "O_DIRECTORY"):
                flags |= os.O_DIRECTORY
            if hasattr(os, "O_NOFOLLOW"):
                flags |= os.O_NOFOLLOW
            if hasattr(os, "O_NONBLOCK"):
                flags |= os.O_NONBLOCK
            try:
                next_descriptor = os.open(component, flags, dir_fd=parent_descriptor)
            except OSError as exc:
                raise _BoundedReadError(
                    "read.parent_open_failed",
                    "A read parent directory could not be opened.",
                ) from exc
            os.close(parent_descriptor)
            parent_descriptor = next_descriptor
            parent_stat = os.fstat(parent_descriptor)
            if not stat.S_ISDIR(parent_stat.st_mode):
                raise _BoundedReadError(
                    "read.parent_not_directory",
                    "A read parent is not a directory.",
                )
        return _read_regular_at(parent_descriptor, parts[-1], budget=budget)
    finally:
        os.close(parent_descriptor)


def _bound_lstat(root: _BoundRepository, relative_path: str | Path) -> os.stat_result:
    parts = _relative_path_parts(relative_path)
    parent_descriptor = os.dup(root.descriptor)
    try:
        for component in parts[:-1]:
            flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
            next_descriptor = os.open(component, flags, dir_fd=parent_descriptor)
            os.close(parent_descriptor)
            parent_descriptor = next_descriptor
        return os.stat(parts[-1], dir_fd=parent_descriptor, follow_symlinks=False)
    finally:
        os.close(parent_descriptor)


def _bound_path_kind(root_path: str | Path, relative_path: str | Path) -> str:
    """Return lexical, descriptor-bound metadata without following repository links."""
    lexical_root = Path(os.path.abspath(os.path.expanduser(str(root_path))))
    try:
        bound_root = _bind_repository(lexical_root)
    except OSError:
        return "uninspectable"
    kind = "uninspectable"
    try:
        try:
            path_stat = (
                os.fstat(bound_root.descriptor)
                if Path(relative_path) == Path(".")
                else _bound_lstat(bound_root, relative_path)
            )
        except FileNotFoundError:
            kind = "missing"
        except OSError:
            kind = "uninspectable"
        else:
            mode = path_stat.st_mode
            if stat.S_ISREG(mode):
                kind = "regular"
            elif stat.S_ISDIR(mode):
                kind = "directory"
            elif stat.S_ISLNK(mode):
                kind = "symlink"
            else:
                kind = "special"
        if not _repository_path_has_identity(bound_root):
            kind = "uninspectable"
    finally:
        try:
            bound_root.close()
        except OSError:
            kind = "uninspectable"
    return kind


def _lexical_path_kind(path: str | Path) -> str:
    lexical_path = Path(os.path.abspath(os.path.expanduser(str(path))))
    try:
        path_stat = os.stat(lexical_path, follow_symlinks=False)
    except FileNotFoundError:
        return "missing"
    except OSError:
        return "uninspectable"
    mode = path_stat.st_mode
    if stat.S_ISREG(mode):
        return "regular"
    if stat.S_ISDIR(mode):
        return "directory"
    if stat.S_ISLNK(mode):
        return "symlink"
    return "special"


def _open_bound_directory(
    root: _BoundRepository,
    relative_path: str | Path,
) -> int:
    if Path(relative_path) == Path("."):
        return os.dup(root.descriptor)
    parts = _relative_path_parts(relative_path)
    descriptor = os.dup(root.descriptor)
    try:
        for component in parts:
            flags = (
                os.O_RDONLY
                | getattr(os, "O_DIRECTORY", 0)
                | getattr(os, "O_NOFOLLOW", 0)
                | getattr(os, "O_NONBLOCK", 0)
            )
            next_descriptor = os.open(component, flags, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = next_descriptor
        return descriptor
    except Exception:
        os.close(descriptor)
        raise


def _scan_bound_directory(
    root: _BoundRepository,
    relative_directory: Path,
    *,
    budget: _OperationBudget,
    suffixes: set[str],
    skip_dirs: set[str],
    depth: int,
    seen_directories: set[tuple[int, int]],
) -> Iterable[Path]:
    if depth > MAX_SCAN_DEPTH:
        budget.mark_incomplete("limit.depth", relative_directory.as_posix())
        return
    try:
        descriptor = _open_bound_directory(root, relative_directory)
    except OSError:
        budget.mark_incomplete("scan.directory_open_failed", relative_directory.as_posix())
        return
    try:
        directory_stat = os.fstat(descriptor)
        identity = (directory_stat.st_dev, directory_stat.st_ino)
        if identity in seen_directories:
            return
        seen_directories.add(identity)
        try:
            iterator = os.scandir(descriptor)
        except OSError:
            budget.mark_incomplete("scan.directory_read_failed", relative_directory.as_posix())
            return
        with iterator:
            for entry in iterator:
                budget.entry_count += 1
                subject = (relative_directory / entry.name).as_posix()
                if budget.entry_count > MAX_SCAN_ENTRIES:
                    budget.mark_incomplete("limit.entries", subject)
                    return
                if not budget.check_time():
                    return
                if len(os.fsencode(entry.name)) > MAX_PATH_BYTES or len(
                    os.fsencode(subject)
                ) > MAX_PATH_BYTES:
                    budget.mark_incomplete("limit.path_bytes", subject)
                    continue
                try:
                    entry_stat = entry.stat(follow_symlinks=False)
                except OSError:
                    budget.mark_incomplete("scan.entry_stat_failed", subject)
                    continue
                mode = entry_stat.st_mode
                if stat.S_ISLNK(mode):
                    budget.mark_incomplete("scan.symlink_rejected", subject)
                    continue
                if stat.S_ISDIR(mode):
                    if entry.name in skip_dirs:
                        continue
                    if entry.name in {"pkg", "src"}:
                        try:
                            package_marker = os.stat(
                                "PKGBUILD",
                                dir_fd=descriptor,
                                follow_symlinks=False,
                            )
                        except OSError:
                            package_marker = None
                        if package_marker is not None and stat.S_ISREG(package_marker.st_mode):
                            continue
                    yield from _scan_bound_directory(
                        root,
                        relative_directory / entry.name,
                        budget=budget,
                        suffixes=suffixes,
                        skip_dirs=skip_dirs,
                        depth=depth + 1,
                        seen_directories=seen_directories,
                    )
                    if budget.incomplete_reasons and any(
                        reason["code"].startswith("limit.")
                        for reason in budget.incomplete_reasons
                    ):
                        return
                    continue
                if stat.S_ISREG(mode):
                    if Path(entry.name).suffix.lower() in suffixes:
                        yield relative_directory / entry.name
                    continue
                budget.mark_incomplete("scan.special_file_rejected", subject)
    finally:
        os.close(descriptor)


def _read_file_within_root(
    root_path: str | Path,
    relative_path: str | Path,
    *,
    budget: _OperationBudget | None = None,
) -> bytes:
    lexical_root = Path(os.path.abspath(os.path.expanduser(str(root_path))))
    try:
        bound_root = _bind_repository(lexical_root)
    except OSError as exc:
        raise _BoundedReadError("read.root_open_failed", "Read root could not be bound.") from exc
    try:
        content = _read_bound_regular_file(bound_root, relative_path, budget=budget)
        if not _repository_path_has_identity(bound_root):
            raise _BoundedReadError("read.root_changed", "Read root changed during the read.")
        return content
    finally:
        bound_root.close()


def _read_absolute_regular_file(path: str | Path) -> bytes:
    absolute_path = Path(os.path.abspath(os.path.expanduser(str(path))))
    anchor = Path(absolute_path.anchor)
    return _read_file_within_root(anchor, absolute_path.relative_to(anchor))


def find_config_path(repo_path: str | Path = ".") -> Path:
    return Path(os.path.abspath(os.path.expanduser(str(repo_path)))) / CONFIG_RELATIVE_PATH


def load_raw_config(repo_path: str | Path = ".", config_path: str | Path | None = None) -> str:
    repo = Path(os.path.abspath(os.path.expanduser(str(repo_path))))
    path = (
        Path(os.path.abspath(os.path.expanduser(str(config_path))))
        if config_path
        else repo / CONFIG_RELATIVE_PATH
    )
    try:
        relative_path = path.relative_to(repo)
    except ValueError as exc:
        raise ForkOpsError(
            "Fork Ops config path must stay inside the selected repository."
        ) from exc
    try:
        raw = _read_file_within_root(repo, relative_path)
        return raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ForkOpsError("Fork Ops config is not valid UTF-8 text.") from exc
    except _BoundedReadError as exc:
        raise ForkOpsError(f"Fork Ops config read failed ({exc.code}).") from exc


def parse_config_text(raw: str) -> dict[str, Any]:
    if len(raw.encode("utf-8")) > MAX_FILE_BYTES:
        raise ForkOpsError("Fork Ops config exceeds the file byte limit.")
    try:
        parsed = tomllib.loads(raw)
    except tomllib.TOMLDecodeError as exc:
        raise ForkOpsError(f"Fork Ops config TOML parse failed: {exc}") from exc
    if not isinstance(parsed, dict):
        raise ForkOpsError("Fork Ops config must parse to a TOML table.")
    _validate_bounded_object(parsed, label="Fork Ops config")
    return parsed


def load_config(
    repo_path: str | Path = ".",
    config_path: str | Path | None = None,
) -> dict[str, Any]:
    config = parse_config_text(load_raw_config(repo_path, config_path))
    schema_version = config.get("schema_version")
    if schema_version != SUPPORTED_CONFIG_SCHEMA_VERSION:
        raise ForkOpsError(_unsupported_config_schema_diagnostic(schema_version).message)
    return config


def normalize_config(config: dict[str, Any]) -> dict[str, Any]:
    _validate_bounded_object(config, label="Fork Ops config")
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
    if isinstance(value, _JSON_SEQUENCE_TYPES):
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
    mcp_config_check = _mcp_config_resolution_check(root)

    checks.append(_skill_discovery_check(root))
    cli_check = _cli_execution_check(runner, timeout)
    checks.append(cli_check)
    cli_ready = cli_check["status"] == "ready"

    checks.append(mcp_config_check)

    mcp_startup_check, mcp_startup_payload = _mcp_process_startup_check(
        mcp_config_check,
        runner,
        timeout,
        cli_ready=cli_ready,
    )
    checks.append(mcp_startup_check)
    checks.append(_mcp_tool_listing_check(mcp_startup_check, mcp_startup_payload, cli_ready))
    checks.append(_ui_visibility_check(ui_visible))

    summary = _plugin_health_summary(checks)
    return _canonical_operation_result(
        ArtifactKind.PLUGIN_HEALTH_REPORT,
        {
        "operation": "plugin-health",
        "model": "independent-readiness-paths",
        "plugin_root": str(root),
        "repo_root": str(repo),
        "status_values": dict(PLUGIN_HEALTH_STATUS_VALUES),
        "summary": summary,
        "checks": checks,
        "cli_fallback": _cli_fallback(cli_ready, root, repo),
        "mutation_policy": "read-only diagnostics; no repository mutation is performed",
        },
        operation="plugin-health",
        outcome=(
            OutcomeValue.FAILED
            if summary["status"] == "failed"
            else OutcomeValue.COMPLETED
        ),
    )


def _plugin_root(plugin_root: str | Path | None) -> Path:
    if plugin_root is not None:
        return Path(os.path.abspath(os.path.expanduser(str(plugin_root))))
    return Path(__file__).resolve().parents[2]


def _plugin_repo_root(plugin_root: Path, repo_root: str | Path | None) -> Path:
    if repo_root is not None:
        return Path(os.path.abspath(os.path.expanduser(str(repo_root))))
    if plugin_root.parent.name == "plugins":
        return plugin_root.parent.parent
    return plugin_root.parent


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
    marketplace_kind = _bound_path_kind(repo_root, Path(".agents/plugins/marketplace.json"))
    if marketplace_kind == "missing":
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
    if marketplace_kind != "regular":
        return _health_check(
            "plugin_registration",
            "Plugin registration",
            "uninspectable",
            "Plugin marketplace metadata could not be inspected safely.",
            evidence={"path": str(marketplace_path), "path_kind": marketplace_kind},
            next_steps=("Check the selected repository root and marketplace file type.",),
        )
    try:
        marketplace = json.loads(
            _read_file_within_root(
                repo_root,
                Path(".agents/plugins/marketplace.json"),
            ).decode("utf-8")
        )
    except UnicodeDecodeError as exc:
        return _health_check(
            "plugin_registration",
            "Plugin registration",
            "failed",
            "Plugin marketplace metadata is not valid UTF-8 text.",
            evidence={"path": str(marketplace_path), "error": str(exc)},
            next_steps=("Repair .agents/plugins/marketplace.json text encoding.",),
        )
    except (OSError, _BoundedReadError) as exc:
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
    skill_kind = _bound_path_kind(plugin_root, Path("skills/fork-ops/SKILL.md"))
    if skill_kind == "missing":
        return _health_check(
            "skill_discovery",
            "Skill discovery",
            "failed",
            "Fork Ops skill file is missing from the plugin package.",
            evidence={"path": str(skill_path)},
            next_steps=("Restore plugins/fork-ops/skills/fork-ops/SKILL.md.",),
        )
    if skill_kind != "regular":
        return _health_check(
            "skill_discovery",
            "Skill discovery",
            "uninspectable",
            "Fork Ops skill file could not be inspected safely.",
            evidence={"path": str(skill_path), "path_kind": skill_kind},
            next_steps=("Check the selected plugin root and skill file type.",),
        )
    try:
        skill_text = _read_file_within_root(
            plugin_root,
            Path("skills/fork-ops/SKILL.md"),
        ).decode("utf-8")
    except UnicodeDecodeError as exc:
        return _health_check(
            "skill_discovery",
            "Skill discovery",
            "failed",
            "Fork Ops skill file is not valid UTF-8 text.",
            evidence={"path": str(skill_path), "error": str(exc)},
            next_steps=("Repair plugins/fork-ops/skills/fork-ops/SKILL.md text encoding.",),
        )
    except (OSError, _BoundedReadError) as exc:
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
    command_runner: CommandRunner,
    timeout: float,
) -> dict[str, Any]:
    command = [sys.executable, "-I", "-m", "fork_ops.cli", "workflow", "catalog"]
    completed = command_runner(command, _trusted_package_directory(), timeout)
    evidence = _command_evidence(command, completed)
    evidence["launch_provenance"] = "current-interpreter-isolated-package-module"
    evidence["repository_controlled_executable_used"] = False
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
    identity_diagnostic = _artifact_identity_diagnostic(
        payload,
        expected_kind=ArtifactKind.WORKFLOW_CATALOG,
        path="workflow_catalog",
        label="Workflow catalog",
    )
    if identity_diagnostic is not None:
        evidence["artifact_identity"] = identity_diagnostic.to_dict()
        return _health_check(
            "cli_execution",
            "CLI execution",
            "failed",
            "Fork Ops CLI probe returned an unsupported workflow catalog contract.",
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
) -> dict[str, Any]:
    mcp_config_path = plugin_root / ".mcp.json"
    mcp_config_kind = _bound_path_kind(plugin_root, Path(".mcp.json"))
    if mcp_config_kind == "missing":
        return _health_check(
            "mcp_config_resolution",
            "MCP config resolution",
            "unavailable",
            "Fork Ops MCP config was not found in the plugin package.",
            evidence={"path": str(mcp_config_path)},
            next_steps=("Restore plugins/fork-ops/.mcp.json or configure the MCP server.",),
        )
    if mcp_config_kind != "regular":
        return _health_check(
            "mcp_config_resolution",
            "MCP config resolution",
            "uninspectable",
            "Fork Ops MCP config could not be inspected safely.",
            evidence={"path": str(mcp_config_path), "path_kind": mcp_config_kind},
            next_steps=("Check the selected plugin root and MCP config file type.",),
        )
    try:
        mcp_config = json.loads(
            _read_file_within_root(plugin_root, Path(".mcp.json")).decode("utf-8")
        )
    except UnicodeDecodeError as exc:
        return _health_check(
            "mcp_config_resolution",
            "MCP config resolution",
            "failed",
            "Fork Ops MCP config is not valid UTF-8 text.",
            evidence={"path": str(mcp_config_path), "error": str(exc)},
            next_steps=("Repair plugins/fork-ops/.mcp.json text encoding.",),
        )
    except (OSError, _BoundedReadError) as exc:
        return _health_check(
            "mcp_config_resolution",
            "MCP config resolution",
            "uninspectable",
            "Fork Ops MCP config could not be read.",
            evidence={"path": str(mcp_config_path), "error": str(exc)},
            next_steps=("Check file permissions for plugins/fork-ops/.mcp.json.",),
        )
    except json.JSONDecodeError as exc:
        return _health_check(
            "mcp_config_resolution",
            "MCP config resolution",
            "failed",
            "Fork Ops MCP config is not valid JSON.",
            evidence={"path": str(mcp_config_path), "error": str(exc)},
            next_steps=("Repair plugins/fork-ops/.mcp.json before starting MCP.",),
        )
    if not isinstance(mcp_config, dict):
        return _health_check(
            "mcp_config_resolution",
            "MCP config resolution",
            "failed",
            "Fork Ops MCP config must be a JSON object.",
            evidence={"path": str(mcp_config_path), "json_type": type(mcp_config).__name__},
            next_steps=("Repair plugins/fork-ops/.mcp.json before starting MCP.",),
        )
    if mcp_config != _EXPECTED_MCP_REGISTRATION:
        return _health_check(
            "mcp_config_resolution",
            "MCP config resolution",
            "failed",
            "Fork Ops MCP config does not match the reviewed registration shape.",
            evidence={
                "path": str(mcp_config_path),
                "registration_matches_reviewed_shape": False,
            },
            next_steps=("Restore the reviewed plugins/fork-ops/.mcp.json registration.",),
        )
    server = _EXPECTED_MCP_REGISTRATION["mcpServers"]["fork-ops"]
    return _health_check(
        "mcp_config_resolution",
        "MCP config resolution",
        "ready",
        "Fork Ops MCP config exactly matches the reviewed registration shape.",
        evidence={
            "path": str(mcp_config_path),
            "registration_matches_reviewed_shape": True,
            "command": server["command"],
            "args": server["args"],
            "cwd": server["cwd"],
            "registration_effect": "observational-only",
        },
    )


def _mcp_process_startup_check(
    config_check: dict[str, Any],
    command_runner: CommandRunner,
    timeout: float,
    *,
    cli_ready: bool,
) -> tuple[dict[str, Any], dict[str, Any] | None]:
    if config_check["status"] != "ready":
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

    cwd = _trusted_package_directory()
    command = [sys.executable, "-I", "-m", "fork_ops.mcp_server", "--health-check"]
    completed = command_runner(command, cwd, timeout)
    evidence = _command_evidence(command, completed)
    evidence["cwd"] = str(cwd)
    evidence["launch_provenance"] = "current-interpreter-isolated-package-module"
    evidence["repository_controlled_executable_used"] = False
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
    identity_diagnostic = _artifact_identity_diagnostic(
        payload,
        expected_kind=ArtifactKind.MCP_HEALTHCHECK,
        path="mcp_healthcheck",
        label="MCP health check",
    )
    if identity_diagnostic is not None:
        evidence["artifact_identity"] = identity_diagnostic.to_dict()
        return (
            _health_check(
                "mcp_process_startup",
                "MCP process startup",
                "failed",
                "Fork Ops MCP health-check process returned an unsupported contract.",
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


def _trusted_package_directory() -> Path:
    return Path(__file__).resolve().parent


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
        process = subprocess.Popen(
            command,
            cwd=cwd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            start_new_session=True,
        )
    except OSError as exc:
        return subprocess.CompletedProcess(command, 127, "", str(exc))
    streams = {process.stdout: bytearray(), process.stderr: bytearray()}
    selector = selectors.DefaultSelector()
    for stream in streams:
        if stream is not None:
            os.set_blocking(stream.fileno(), False)
            selector.register(stream, selectors.EVENT_READ)
    deadline = monotonic() + min(max(timeout, 0.0), MAX_OPERATION_SECONDS)
    failure = ""
    try:
        while process.poll() is None or selector.get_map():
            remaining = deadline - monotonic()
            if remaining <= 0:
                failure = "subprocess wall-time limit reached"
                break
            events = selector.select(min(remaining, 0.1)) if selector.get_map() else []
            for key, _ in events:
                stream = cast(IO[Any], key.fileobj)
                try:
                    chunk = os.read(stream.fileno(), _READ_CHUNK_BYTES)
                except BlockingIOError:
                    continue
                if not chunk:
                    selector.unregister(stream)
                    continue
                streams[stream].extend(chunk)
                stdout_size = len(streams[process.stdout]) if process.stdout is not None else 0
                stderr_size = len(streams[process.stderr]) if process.stderr is not None else 0
                if (
                    len(streams[stream]) > MAX_SUBPROCESS_STREAM_BYTES
                    or stdout_size + stderr_size > MAX_SUBPROCESS_OUTPUT_BYTES
                ):
                    failure = "subprocess output limit reached"
                    break
            if failure:
                break
        if failure:
            try:
                os.killpg(process.pid, process_signal.SIGKILL)
            except ProcessLookupError:
                pass
            process.wait()
            return subprocess.CompletedProcess(command, 124, "", failure)
        return_code = process.wait()
        stdout = bytes(streams[process.stdout]).decode("utf-8", errors="replace")
        stderr = bytes(streams[process.stderr]).decode("utf-8", errors="replace")
        return subprocess.CompletedProcess(command, return_code, stdout, stderr)
    finally:
        selector.close()
        for stream in streams:
            if stream is not None:
                stream.close()


def read_config_result(
    repo_path: str | Path = ".",
    *,
    normalized: bool,
) -> dict[str, Any]:
    repo = Path(os.path.abspath(os.path.expanduser(str(repo_path))))
    try:
        raw = load_raw_config(repo)
    except ForkOpsError as exc:
        return cast(
            dict[str, Any],
            operation_artifact(
                ArtifactKind.CONFIG_READ_RESULT,
                "config-read",
                {
                    "path": CONFIG_RELATIVE_PATH.as_posix(),
                    "format": "normalized" if normalized else "raw",
                    "config_identity": {"schema_version": None},
                    "diagnostics": [
                        Diagnostic(
                            severity="error",
                            code="config.read_failed",
                            message=str(exc),
                            path=str(CONFIG_RELATIVE_PATH),
                        ).to_dict()
                    ],
                },
                outcome=OutcomeValue.FAILED,
            ),
        )
    try:
        parsed = parse_config_text(raw)
    except ForkOpsError as exc:
        diagnostic = Diagnostic(
            severity="error",
            code="config.parse_failed",
            message=str(exc),
            path=str(CONFIG_RELATIVE_PATH),
        )
        fields: dict[str, Any] = {
            "path": CONFIG_RELATIVE_PATH.as_posix(),
            "format": "normalized" if normalized else "raw",
            "config_identity": {"schema_version": None},
            "diagnostics": [diagnostic.to_dict()],
        }
        if not normalized:
            fields["raw"] = raw
        return cast(
            dict[str, Any],
            operation_artifact(
                ArtifactKind.CONFIG_READ_RESULT,
                "config-read",
                fields,
                outcome=(OutcomeValue.REFUSED if normalized else OutcomeValue.COMPLETED),
            ),
        )

    config_schema_version = parsed.get("schema_version")
    diagnostics: list[Diagnostic] = []
    if config_schema_version != SUPPORTED_CONFIG_SCHEMA_VERSION:
        diagnostics.append(_unsupported_config_schema_diagnostic(config_schema_version))
    if not normalized:
        return cast(
            dict[str, Any],
            operation_artifact(
                ArtifactKind.CONFIG_READ_RESULT,
                "config-read",
                {
                    "path": CONFIG_RELATIVE_PATH.as_posix(),
                    "format": "raw",
                    "config_identity": {"schema_version": config_schema_version},
                    "raw": raw,
                    "diagnostics": [item.to_dict() for item in diagnostics],
                },
            ),
        )
    if diagnostics:
        return cast(
            dict[str, Any],
            operation_artifact(
                ArtifactKind.CONFIG_READ_RESULT,
                "config-read",
                {
                    "path": CONFIG_RELATIVE_PATH.as_posix(),
                    "format": "normalized",
                    "config_identity": {"schema_version": config_schema_version},
                    "diagnostics": [item.to_dict() for item in diagnostics],
                },
                outcome=OutcomeValue.REFUSED,
            ),
        )
    normalized_config = normalize_config(parsed)
    diagnostics.extend(schema_diagnostics(normalized_config))
    diagnostics.extend(reference_diagnostics(normalized_config))
    if any(item.severity == "error" for item in diagnostics):
        return cast(
            dict[str, Any],
            operation_artifact(
                ArtifactKind.CONFIG_READ_RESULT,
                "config-read",
                {
                    "path": CONFIG_RELATIVE_PATH.as_posix(),
                    "format": "normalized",
                    "config_identity": {"schema_version": config_schema_version},
                    "diagnostics": [item.to_dict() for item in diagnostics],
                },
                outcome=OutcomeValue.REFUSED,
            ),
        )
    return cast(
        dict[str, Any],
        operation_artifact(
            ArtifactKind.CONFIG_READ_RESULT,
            "config-read",
            {
                "path": CONFIG_RELATIVE_PATH.as_posix(),
                "format": "normalized",
                "config_identity": {"schema_version": config_schema_version},
                "config": _json_safe(normalized_config),
                "diagnostics": [],
            },
        ),
    )


def build_status_report(
    repo_path: str | Path = ".",
    config_path: str | Path | None = None,
    include_config: bool = True,
    required_level: str = "",
) -> dict[str, Any]:
    if required_level and required_level not in CAPABILITY_LEVELS:
        raise ForkOpsError(f"Unknown required capability level: {required_level}")
    repo = Path(os.path.abspath(os.path.expanduser(str(repo_path))))
    config_file = (
        Path(os.path.abspath(os.path.expanduser(str(config_path))))
        if config_path
        else find_config_path(repo)
    )
    diagnostics: list[Diagnostic] = []

    try:
        config_relative_path = config_file.relative_to(repo)
    except ValueError:
        config_kind = "uninspectable"
    else:
        config_kind = _bound_path_kind(repo, config_relative_path)
    if config_kind == "missing":
        diagnostics.append(
            Diagnostic(
                severity="error",
                code="config.missing",
                message=f"Fork Ops config not found at {config_file}",
                path=str(CONFIG_RELATIVE_PATH),
            )
        )
        capability = capability_report({}, diagnostics)
        _require_current_artifact(
            capability, ArtifactKind.CAPABILITY_REPORT, "Capability report"
        )
        equipment_review = _equipment_review_record_report(repo)
        _attach_equipment_review(capability, equipment_review)
        return _status_report_result(
            {
                "repo_path": str(repo),
                "config_path": str(config_file),
                "config_exists": False,
                "config_identity": {"schema_version": None},
                "capability": capability,
                "diagnostics": [item.to_dict() for item in diagnostics],
            },
            required_level=required_level,
        )
    if config_kind != "regular":
        diagnostics.append(
            Diagnostic(
                severity="error",
                code="config.uninspectable",
                message="Fork Ops config could not be inspected safely.",
                path=str(CONFIG_RELATIVE_PATH),
            )
        )
        capability = capability_report({}, diagnostics)
        _require_current_artifact(
            capability, ArtifactKind.CAPABILITY_REPORT, "Capability report"
        )
        equipment_review = _equipment_review_record_report(repo)
        _attach_equipment_review(capability, equipment_review)
        return _status_report_result(
            {
                "repo_path": str(repo),
                "config_path": str(config_file),
                "config_exists": False,
                "config_identity": {"schema_version": None},
                "capability": capability,
                "diagnostics": [item.to_dict() for item in diagnostics],
            },
            required_level=required_level,
        )

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
        capability = capability_report({}, diagnostics)
        _require_current_artifact(
            capability, ArtifactKind.CAPABILITY_REPORT, "Capability report"
        )
        equipment_review = _equipment_review_record_report(repo)
        _attach_equipment_review(capability, equipment_review)
        return _status_report_result(
            {
                "repo_path": str(repo),
                "config_path": str(config_file),
                "config_exists": True,
                "config_identity": {"schema_version": None},
                "capability": capability,
                "diagnostics": [item.to_dict() for item in diagnostics],
            },
            required_level=required_level,
        )

    config_schema_version = config.get("schema_version")
    if config_schema_version != SUPPORTED_CONFIG_SCHEMA_VERSION:
        diagnostics.append(_unsupported_config_schema_diagnostic(config_schema_version))
        capability = capability_report(config, diagnostics)
        _require_current_artifact(
            capability, ArtifactKind.CAPABILITY_REPORT, "Capability report"
        )
        equipment_review = _equipment_review_record_report(repo)
        _attach_equipment_review(capability, equipment_review)
        return _status_report_result(
            {
                "repo_path": str(repo),
                "config_path": str(config_file),
                "config_exists": True,
                "config_identity": {"schema_version": config_schema_version},
                "capability": capability,
                "diagnostics": [item.to_dict() for item in diagnostics],
            },
            outcome=OutcomeValue.REFUSED,
            required_level=required_level,
        )

    normalized = normalize_config(config)
    diagnostics.extend(schema_diagnostics(normalized))
    diagnostics.extend(reference_diagnostics(normalized))
    diagnostics.extend(git_diagnostics(repo, normalized))
    equipment_review = _equipment_review_record_report(repo)

    capability = capability_report(normalized, diagnostics)
    _require_current_artifact(
        capability, ArtifactKind.CAPABILITY_REPORT, "Capability report"
    )
    payload: dict[str, Any] = {
        "repo_path": str(repo),
        "config_path": str(config_file),
        "config_exists": True,
        "config_identity": {"schema_version": normalized.get("schema_version")},
        "capability": capability,
        "diagnostics": [item.to_dict() for item in diagnostics],
    }
    _attach_equipment_review(payload["capability"], equipment_review)
    if include_config:
        payload["config"] = _json_safe(normalized)
    return _status_report_result(payload, required_level=required_level)


def _status_report_result(
    fields: dict[str, Any],
    *,
    outcome: OutcomeValue | None = None,
    required_level: str = "",
) -> dict[str, Any]:
    selected_fields = copy.deepcopy(fields)
    capability = selected_fields.get("capability")
    if isinstance(capability, dict):
        evidence = _optional_preview_list(capability, "evidence")
        equipment_review = capability.get("equipment_review")
        if (
            isinstance(equipment_review, dict)
            and "activation_readiness" in equipment_review
            and not any(item.get("id") == "equipment.review" for item in evidence)
        ):
            evidence.append(
                Evidence(
                    id="equipment.review",
                    source="equipment_review",
                    detail={
                        "artifact_kind": _EQUIPMENT_REVIEW_CONTRACT.emitted_artifact_kind,
                        "schema_version": equipment_review.get("schema_version"),
                        "valid": equipment_review.get("valid"),
                    },
                ).to_dict()
            )
        capability["evidence"] = copy.deepcopy(evidence)
        selected_fields["evidence"] = copy.deepcopy(evidence)
    diagnostics = selected_fields.get("diagnostics", [])
    selected_outcome = outcome or (
        OutcomeValue.BLOCKED
        if isinstance(diagnostics, list)
        and any(
            isinstance(item, dict) and item.get("severity") == "error"
            for item in diagnostics
        )
        else OutcomeValue.COMPLETED
    )
    if required_level:
        level = selected_fields["capability"]["authority_readiness"]["levels"][
            required_level
        ]
        authority_ready = level["ready"]
        selected_fields["required_level"] = {
            "level": required_level,
            "authority_ready": authority_ready,
            "missing": (
                copy.deepcopy(level["missing"])
                if authority_ready is not None
                else None
            ),
        }
        if authority_ready is False and selected_outcome is OutcomeValue.COMPLETED:
            selected_outcome = OutcomeValue.BLOCKED
    return cast(
        dict[str, Any],
        operation_artifact(
            ArtifactKind.STATUS_REPORT,
            "config-status",
            selected_fields,
            outcome=selected_outcome,
        ),
    )


def capability_report(
    config: dict[str, Any],
    diagnostics: Iterable[Diagnostic] | None = None,
    *,
    extension_dependencies: Iterable[str] = (),
) -> dict[str, Any]:
    diagnostics = list(diagnostics or [])
    if isinstance(extension_dependencies, str):
        raise ValueError("extension dependencies must be a sequence of paths")
    raw_extension_paths = tuple(extension_dependencies)
    if any(
        not isinstance(path, str) or not path for path in raw_extension_paths
    ):
        raise ValueError("extension dependency paths must be non-empty strings")
    extension_paths = sorted(set(raw_extension_paths))
    config_schema_version = config.get("schema_version")
    unsupported_version = config_schema_version is not None and (
        not isinstance(config_schema_version, str)
        or config_schema_version != SUPPORTED_CONFIG_SCHEMA_VERSION
    )
    if unsupported_version and not any(
        item.code == "unsupported_schema_version" for item in diagnostics
    ):
        diagnostics.append(_unsupported_config_schema_diagnostic(config_schema_version))
    if extension_paths:
        diagnostics.append(
            Diagnostic(
                severity="error",
                code="unsupported_extension_semantics",
                message=(
                    "This operation depends on config extension semantics that Fork Ops "
                    "does not understand."
                ),
                path="config",
                detail={"extension_paths": extension_paths},
            )
        )
    semantic_refusal = (
        unsupported_version
        or bool(extension_paths)
        or any(item.code == "unsupported_schema_version" for item in diagnostics)
    )
    blocking_errors = [item for item in diagnostics if item.severity == "error"]
    levels: dict[str, Any] = {}
    highest: str | None = None

    for level in CAPABILITY_LEVELS:
        missing: list[str] = (
            [] if semantic_refusal else list(_missing_requirements(config, level))
        )
        if semantic_refusal:
            ready: bool | None = None
        elif blocking_errors:
            ready = False
        else:
            ready = not missing
        levels[level] = {
            "ready": ready,
            "missing": missing,
            "authority_enables": _level_enables(level),
        }
        if ready is True:
            highest = level

    repository_slug: str | None = None
    if not semantic_refusal:
        repository = _mapping_section(config, "repository")
        candidate_slug = repository.get("slug")
        if isinstance(candidate_slug, str):
            repository_slug = candidate_slug
        else:
            owner = repository.get("owner")
            name = repository.get("name")
            repository_slug = (
                f"{owner}/{name}"
                if isinstance(owner, str) and isinstance(name, str)
                else ""
            )
    config_evidence = Evidence(
        id="config.identity" if semantic_refusal else "config.authority",
        source="fork_ops_config",
        detail={
            "schema_version": (
                config_schema_version if isinstance(config_schema_version, str) else None
            ),
            **({} if semantic_refusal else {"repository_slug": repository_slug}),
        },
    )
    workflow_evidence = Evidence(
        id="workflow.catalog",
        source="workflow_catalog",
        detail={
            "artifact_kind": ArtifactKind.WORKFLOW_CATALOG.value,
            "schema_version": str(
                current_artifact_version(ArtifactKind.WORKFLOW_CATALOG)
            ),
        },
    )
    workflow_availability = [
        {
            "workflow_id": workflow.id,
            "implementation_extent": workflow.implementation_extent,
            "available_operations": [
                operation.id for operation in workflow.operations if operation.available
            ],
        }
        for workflow in workflow_contracts()
    ]
    common_state = {
        "subject": "reported_workflows",
        "evidence_ids": (config_evidence.id, workflow_evidence.id),
    }
    activation = State(
        dimension=StateDimension.ACTIVATION_READINESS,
        value=ActivationReadinessValue.UNASSESSED,
        derivation_rule=(
            "activation.requires_named_operation_authority_and_equipment_evidence"
        ),
        **common_state,
    )
    coverage = State(
        dimension=StateDimension.REPLACEMENT_COVERAGE,
        value=ReplacementCoverageValue.UNASSESSED,
        derivation_rule=(
            "coverage.requires_active_operation_authority_activation_and_behavior_evidence"
        ),
        **common_state,
    )
    continuity = State(
        dimension=StateDimension.OPERATIONAL_CONTINUITY,
        value=OperationalContinuityValue.UNASSESSED,
        derivation_rule=(
            "continuity.requires_active_fork_ops_or_verified_retained_owner_or_redirect"
        ),
        **common_state,
    )
    return cast(
        dict[str, Any],
        operation_artifact(
            ArtifactKind.CAPABILITY_REPORT,
            "capability-report",
            {
                "repository_identity": {"slug": repository_slug},
                "config_identity": {
                    "schema_version": (
                        config_schema_version
                        if isinstance(config_schema_version, str)
                        else None
                    )
                },
                "authority_readiness": {
                    "highest_authority_ready": highest,
                    "levels": levels,
                    "evidence_ids": [config_evidence.id],
                    "derivation_rule": (
                        "authority.required_fields_and_blocking_diagnostics"
                    ),
                },
                "workflow_availability": workflow_availability,
                "activation_readiness": activation.to_dict(),
                "replacement_coverage": coverage.to_dict(),
                "operational_continuity": continuity.to_dict(),
                "baseline_assurance": "unvalidated",
                "diagnostics": [item.to_dict() for item in diagnostics],
                "evidence": [config_evidence.to_dict(), workflow_evidence.to_dict()],
            },
            outcome=(
                OutcomeValue.REFUSED
                if semantic_refusal
                else OutcomeValue.BLOCKED
                if blocking_errors
                else OutcomeValue.COMPLETED
            ),
        ),
    )


def _unsupported_config_schema_diagnostic(value: object) -> Diagnostic:
    rendered = value if isinstance(value, str) else type(value).__name__
    return Diagnostic(
        severity="error",
        code="unsupported_schema_version",
        message=(
            "Fork Ops supports config schema version "
            f"{SUPPORTED_CONFIG_SCHEMA_VERSION}; found {rendered}."
        ),
        path="schema_version",
        detail={
            "supported_schema_versions": [SUPPORTED_CONFIG_SCHEMA_VERSION],
            "observed_schema_version": value,
            "regeneration": "Regenerate the config with `fork-ops config init`.",
        },
    )


def _canonical_operation_result(
    kind: ArtifactKind,
    payload: dict[str, Any],
    *,
    operation: str | None = None,
    outcome: OutcomeValue = OutcomeValue.COMPLETED,
    plan_executability: PlanExecutabilityValue = PlanExecutabilityValue.NOT_APPLICABLE,
    mutation_state: MutationStateValue = MutationStateValue.NOT_REQUESTED,
) -> dict[str, Any]:
    fields = copy.deepcopy(payload)
    payload_operation = fields.pop("operation", None)
    if operation is not None and payload_operation not in (None, operation):
        raise ValueError("payload operation conflicts with the canonical operation")
    selected_operation = operation or payload_operation
    if not isinstance(selected_operation, str) or not selected_operation:
        raise ValueError("canonical operation results require an operation")
    reserved_collisions = {
        key
        for key in (
            "artifact_kind",
            "schema_version",
            "outcome",
            "plan_executability",
            "mutation_state",
        )
        if key in fields
    }
    if reserved_collisions:
        raise ValueError("payload contains reserved canonical fields")
    return cast(
        dict[str, Any],
        operation_artifact(
            kind,
            selected_operation,
            fields,
            outcome=outcome,
            plan_executability=plan_executability,
            mutation_state=mutation_state,
        ),
    )


def _canonical_nested_artifact(
    kind: ArtifactKind,
    payload: dict[str, Any],
) -> dict[str, Any]:
    return cast(dict[str, Any], versioned_artifact(kind, copy.deepcopy(payload)))


def _artifact_identity_diagnostic(
    payload: dict[str, Any],
    *,
    expected_kind: ArtifactKind,
    path: str,
    label: str,
) -> Diagnostic | None:
    return _registered_artifact_identity_diagnostic(
        payload,
        expected_kind=expected_kind,
        path=path,
        label=label,
    )


def _require_current_artifact(
    payload: dict[str, Any],
    expected_kind: ArtifactKind,
    label: str,
) -> None:
    diagnostic = _artifact_identity_diagnostic(
        payload,
        expected_kind=expected_kind,
        path=expected_kind.value,
        label=label,
    )
    if diagnostic is not None:
        raise ForkOpsError(diagnostic.message)


def _migration_workflow_identity_diagnostic(
    payload: dict[str, Any],
    *,
    allow_explanation: bool,
) -> Diagnostic | None:
    observed_kind = payload.get("artifact_kind")
    kind = (
        _MIGRATION_ARTIFACT_KIND_BY_VALUE.get(observed_kind)
        if isinstance(observed_kind, str)
        else None
    )
    if kind is None or (
        not allow_explanation and kind is ArtifactKind.MIGRATION_BLOCKER_EXPLANATION
    ):
        return Diagnostic(
            severity="error",
            code="unsupported_artifact_version",
            message="Workflow output uses an unsupported artifact identity or version.",
            path="workflow_output",
            detail={
                "observed_artifact_kind": observed_kind,
                "observed_schema_version": payload.get("schema_version"),
                "regeneration": "Regenerate the workflow output with Fork Ops 1.0.",
            },
        )
    diagnostic = _artifact_identity_diagnostic(
        payload,
        expected_kind=kind,
        path="workflow_output",
        label="Workflow output",
    )
    if diagnostic is not None:
        return diagnostic
    expected_operation = _MIGRATION_OPERATION_BY_ARTIFACT_KIND[kind]
    if payload.get("operation") != expected_operation:
        return Diagnostic(
            severity="error",
            code="unsupported_artifact_version",
            message="Workflow output uses an unsupported artifact identity or version.",
            path="workflow_output.operation",
            detail={
                "expected_operation": expected_operation,
                "observed_operation": payload.get("operation"),
                "regeneration": "Regenerate the workflow output with Fork Ops 1.0.",
            },
        )
    return None


def _migration_plan_identity_diagnostic(plan: dict[str, Any]) -> Diagnostic | None:
    plan_diagnostic = _artifact_identity_diagnostic(
        plan,
        expected_kind=ArtifactKind.MIGRATION_PLAN,
        path="migration_plan",
        label="Migration plan",
    )
    if plan_diagnostic is not None:
        return plan_diagnostic
    if plan.get("scan_profile") not in SCAN_PROFILES:
        return _migration_plan_semantic_diagnostic(
            "scan_profile must use a current contract value",
            path="migration_plan.scan_profile",
        )
    if plan.get("workflow_run_mode") != _migration_workflow_run_mode():
        return _migration_plan_semantic_diagnostic(
            "workflow_run_mode must match the current guarded replay policy",
            path="migration_plan.workflow_run_mode",
        )
    nested_artifacts = (
        (
            "proposed_config_patch",
            ArtifactKind.MIGRATION_CONFIG_PATCH,
            "Migration config patch",
        ),
        (
            "migration_review_artifact",
            ArtifactKind.MIGRATION_REVIEW_ARTIFACT,
            "Migration review artifact",
        ),
        ("equipment_review_record", ArtifactKind.EQUIPMENT_REVIEW, "Equipment review"),
        (
            "equipment_migration_preflight",
            ArtifactKind.EMBEDDED_EQUIPMENT_MIGRATION_PREFLIGHT,
            "Embedded equipment migration preflight",
        ),
    )
    for key, expected_kind, label in nested_artifacts:
        nested = plan.get(key)
        nested_payload = nested if isinstance(nested, dict) else {}
        nested_diagnostic = _artifact_identity_diagnostic(
            nested_payload,
            expected_kind=expected_kind,
            path=f"migration_plan.{key}",
            label=label,
        )
        if nested_diagnostic is not None:
            return nested_diagnostic
    equipment_review = plan.get("equipment_review_record")
    if isinstance(equipment_review, dict):
        full_breadth = plan.get("scan_profile") == "full-breadth"
        trusted_workflow_inventory = (
            build_workflow_migration_inventory(scan_profile="full-breadth")
            if full_breadth
            else None
        )
        semantic_error = _equipment_review_semantic_error(
            equipment_review,
            require_toml=True,
            trusted_workflow_inventory=trusted_workflow_inventory,
            require_trusted_workflow_inventory=True,
        )
        if semantic_error is None and not full_breadth:
            if any(
                scope.get("kind") != "repo-local"
                for scope in _record_table_list(
                    equipment_review.get("discovery_scopes")
                )
            ):
                semantic_error = (
                    "custom migration plans cannot authorize external discovery scopes"
                )
        if semantic_error is None and trusted_workflow_inventory is not None:
            semantic_error = _migration_plan_workflow_inventory_error(
                plan,
                trusted_workflow_inventory,
            )
        if semantic_error is not None:
            return Diagnostic(
                severity="error",
                code="invalid_artifact_semantics",
                message="Equipment review has invalid canonical semantics.",
                path="migration_plan.equipment_review_record",
                detail={
                    "error": semantic_error,
                    "regeneration": "Regenerate the migration plan with Fork Ops 1.0.",
                },
            )
    return None


def _migration_plan_semantic_diagnostic(
    error: str,
    *,
    path: str,
) -> Diagnostic:
    return Diagnostic(
        severity="error",
        code="invalid_artifact_semantics",
        message="Migration plan has invalid canonical semantics.",
        path=path,
        detail={
            "error": error,
            "regeneration": "Regenerate the migration plan with Fork Ops 1.0.",
        },
    )


def _migration_plan_workflow_inventory_error(
    plan: dict[str, Any],
    trusted_workflow_inventory: dict[str, Any],
) -> str | None:
    expected_accounting = trusted_workflow_inventory.get("scan_accounting")
    plan_scan_accounting = plan.get("scan_accounting")
    if (
        not isinstance(plan_scan_accounting, dict)
        or not isinstance(expected_accounting, dict)
        or not isinstance(plan_scan_accounting.get("workflow_inventory"), dict)
        or _workflow_inventory_replay_accounting(
            plan_scan_accounting["workflow_inventory"]
        )
        != _workflow_inventory_replay_accounting(expected_accounting)
    ):
        return "migration plan workflow scan accounting is stale"
    repository_accounting = plan_scan_accounting.get("repository")
    expected_complete = bool(
        isinstance(repository_accounting, dict)
        and repository_accounting.get("complete") is True
        and expected_accounting.get("complete") is True
    )
    if (
        plan_scan_accounting.get("complete") is not expected_complete
        or plan.get("complete") is not expected_complete
    ):
        return "migration plan completeness does not match current scan accounting"
    return None


def _workflow_inventory_replay_accounting(
    accounting: dict[str, Any],
) -> dict[str, Any]:
    return {
        field_name: copy.deepcopy(accounting.get(field_name))
        for field_name in (
            "complete",
            "limit_reached",
            "limits",
            "incomplete_reasons",
        )
    }


def _migration_plan_repository_diagnostic(
    plan: dict[str, Any],
    repo: Path,
    *,
    bound_repo: _BoundRepository | None = None,
) -> Diagnostic | None:
    equipment_review = plan.get("equipment_review_record")
    if not isinstance(equipment_review, dict):
        return None
    error, _ = _equipment_review_repo_scope_state(
        repo,
        equipment_review,
        bound_repo=bound_repo,
    )
    if error is None:
        return None
    return Diagnostic(
        severity="error",
        code="invalid_artifact_semantics",
        message="Migration plan equipment evidence no longer matches the repository.",
        path="equipment_review_record",
        detail={
            "error": error,
            "regeneration": "Regenerate the migration plan from the selected repository.",
        },
    )


def _equipment_scope_drift_blocker(diagnostic: Diagnostic) -> dict[str, Any]:
    return {
        "code": "migration_execution.equipment_scope_stale",
        "step": "verify_migration_plan",
        "source": "equipment_review_record",
        "message": diagnostic.message,
        "detail": copy.deepcopy(diagnostic.detail),
    }


def _refused_operation_result(
    kind: ArtifactKind,
    operation: str,
    diagnostic: Diagnostic,
    *,
    mutation_requested: bool,
) -> dict[str, Any]:
    return cast(
        dict[str, Any],
        operation_artifact(
            kind,
            operation,
            {"diagnostics": [diagnostic.to_dict()]},
            outcome=OutcomeValue.REFUSED,
            mutation_state=(
                MutationStateValue.NOT_STARTED
                if mutation_requested
                else MutationStateValue.NOT_REQUESTED
            ),
        ),
    )


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
    repo = Path(os.path.abspath(os.path.expanduser(str(repo_path))))
    budget = _OperationBudget()
    candidates = _migration_candidates(repo, budget)
    scan_accounting = budget.accounting()
    config_kind = _bound_path_kind(repo, CONFIG_RELATIVE_PATH)
    assessment: dict[str, Any] = {
        "repo_path": str(repo),
        "mode": "read-only",
        "operation": "migration-assessment",
        "summary": {
            "candidate_count": len(candidates),
            "has_fork_ops_config": config_kind == "regular",
            "fork_ops_config_path_kind": config_kind,
        },
        "candidates": candidates,
        "scan_accounting": scan_accounting,
        "complete": scan_accounting["complete"],
        "next_actions": [
            "Review candidates before creating a migration plan.",
            "Generate a proposed config patch only when the migration plan needs one.",
            "Prefer semantic config writes over raw TOML edits.",
            "Run a migration dry run before migration execution once those surfaces exist.",
        ],
    }
    if include_proposed_config_patch:
        proposed_config_patch = propose_migration_config_patch(repo, candidates)
        _require_current_artifact(
            proposed_config_patch,
            ArtifactKind.MIGRATION_CONFIG_PATCH,
            "Migration config patch",
        )
        assessment["proposed_config_patch"] = proposed_config_patch
    return _with_migration_narrative(
        _canonical_operation_result(
            ArtifactKind.MIGRATION_ASSESSMENT,
            assessment,
            operation="migration-assessment",
        )
    )


def propose_migration_config_patch(
    repo_path: str | Path = ".",
    candidates: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    repo = Path(os.path.abspath(os.path.expanduser(str(repo_path))))
    budget = _OperationBudget()
    migration_candidates = (
        candidates if candidates is not None else _migration_candidates(repo, budget)
    )
    proposed_config = _build_proposed_config(repo, migration_candidates)
    toml = _toml_dumps(proposed_config)
    parsed = parse_config_text(toml)
    diagnostics = (
        _migration_proposal_diagnostics(_flatten_facts(migration_candidates))
        + schema_diagnostics(parsed)
        + reference_diagnostics(normalize_config(parsed))
    )
    config_kind = _bound_path_kind(repo, CONFIG_RELATIVE_PATH)
    proposal = {
        "mode": "non-mutating",
        "purpose": "migration plan input",
        "target_path": str(CONFIG_RELATIVE_PATH),
        "action": "create" if config_kind == "missing" else "review-and-merge",
        "target_path_kind": config_kind,
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
    if candidates is None:
        proposal["scan_accounting"] = budget.accounting()
        proposal["complete"] = not budget.incomplete_reasons
    return _canonical_operation_result(
        ArtifactKind.MIGRATION_CONFIG_PATCH,
        proposal,
        operation="migration-config-patch",
        outcome=(
            OutcomeValue.BLOCKED
            if any(
                isinstance(item, dict) and item.get("severity") == "error"
                for item in proposal["diagnostics"]
            )
            else OutcomeValue.COMPLETED
        ),
    )


def generate_migration_plan(
    repo_path: str | Path = ".",
    candidates: list[dict[str, Any]] | None = None,
    scan_profile: str = "custom",
) -> dict[str, Any]:
    repo = Path(os.path.abspath(os.path.expanduser(str(repo_path))))
    scan_profile = _normalize_scan_profile(scan_profile)
    budget = _OperationBudget()
    migration_candidates = (
        candidates if candidates is not None else _migration_candidates(repo, budget)
    )
    proposed_config_patch = propose_migration_config_patch(repo, migration_candidates)
    _require_current_artifact(
        proposed_config_patch,
        ArtifactKind.MIGRATION_CONFIG_PATCH,
        "Migration config patch",
    )
    evidence = _migration_plan_evidence(migration_candidates)
    retained_source_materials = _retained_source_materials(migration_candidates)
    migration_map = _migration_map(migration_candidates, proposed_config_patch)
    migration_review_artifact = _migration_review_artifact(migration_map)
    blockers = _migration_plan_blockers(migration_candidates, proposed_config_patch)
    if budget.incomplete_reasons:
        blockers.append(
            {
                "code": "migration.scan_incomplete",
                "message": "Migration discovery stopped before complete coverage was proven.",
                "scan_accounting": budget.accounting(),
            }
        )
    workflow_inventory = (
        build_workflow_migration_inventory(scan_profile=scan_profile)
        if scan_profile == "full-breadth"
        else None
    )
    if workflow_inventory is not None:
        _require_current_artifact(
            workflow_inventory,
            ArtifactKind.WORKFLOW_MIGRATION_INVENTORY,
            "Workflow migration inventory",
        )
    if workflow_inventory is not None and not workflow_inventory.get("complete", False):
        blockers.append(
            {
                "code": "migration.workflow_inventory_incomplete",
                "message": "Workflow inventory stopped before complete coverage was proven.",
                "scan_accounting": workflow_inventory.get("scan_accounting", {}),
            }
        )
    equipment_preflight_payload = _equipment_migration_preflight(
        repo,
        migration_candidates,
        migration_map,
        blockers,
        source_roots=None,
        workflow_inventory=workflow_inventory,
        scan_profile=scan_profile,
    )
    equipment_review_record = _equipment_review_record(equipment_preflight_payload)
    state_report = _activation_readiness_report(
        migration_map,
        blockers,
        equipment_preflight_payload,
    )
    equipment_preflight = _canonical_operation_result(
        ArtifactKind.EMBEDDED_EQUIPMENT_MIGRATION_PREFLIGHT,
        equipment_preflight_payload,
        operation="equipment-migration-preflight",
    )
    _require_current_artifact(
        equipment_preflight,
        ArtifactKind.EMBEDDED_EQUIPMENT_MIGRATION_PREFLIGHT,
        "Embedded equipment migration preflight",
    )
    accounting_records = copy.deepcopy(equipment_preflight_payload["accounting_records"])
    follow_up_candidates = copy.deepcopy(equipment_preflight_payload["follow_up_candidates"])
    evidence = _refreshed_migration_state_evidence(
        evidence,
        blockers,
        equipment_preflight_payload,
    )
    plan = {
        "repo_path": str(repo),
        "mode": "non-mutating",
        "operation": "migration-plan",
        "scan_profile": scan_profile,
        "requires_review": True,
        "workflow_run_mode": _migration_workflow_run_mode(),
        "source_material_disposition_types": list(SOURCE_MATERIAL_DISPOSITION_TYPES),
        "equipment_disposition_types": list(EQUIPMENT_DISPOSITION_TYPES),
        "accounting_status_types": list(ACCOUNTING_STATUS_TYPES),
        "summary": {
            "candidate_count": len(migration_candidates),
            "evidence_source_count": len(evidence),
            "migration_map_entry_count": len(migration_map),
            "review_artifact_entry_count": len(migration_review_artifact["entries"]),
            "equipment_group_count": len(equipment_preflight["equipment_groups"]),
            "unassessed_equipment_area_count": len(
                equipment_preflight["unassessed_equipment_areas"]
            ),
            "retained_source_material_count": len(retained_source_materials),
            "blocker_count": len(blockers),
            "semantic_coverage": _semantic_coverage_status(blockers),
            "accounting_record_count": len(accounting_records),
            "follow_up_candidate_count": len(follow_up_candidates),
        },
        "equipment_migration_preflight": equipment_preflight,
        "equipment_review_record": equipment_review_record,
        **state_report,
        "evidence": evidence,
        "migration_map": migration_map,
        "accounting_records": accounting_records,
        "follow_up_candidates": follow_up_candidates,
        "migration_review_artifact": migration_review_artifact,
        "proposed_config_patch": proposed_config_patch,
        "retained_source_materials": retained_source_materials,
        "deferred_removals": _deferred_removals(retained_source_materials),
        "blockers": blockers,
        "scan_accounting": {
            "complete": not budget.incomplete_reasons
            and (
                workflow_inventory is None
                or bool(workflow_inventory.get("complete", False))
            ),
            "repository": budget.accounting(),
            "workflow_inventory": (
                workflow_inventory.get("scan_accounting", {})
                if workflow_inventory is not None
                else None
            ),
        },
        "complete": not budget.incomplete_reasons
        and (
            workflow_inventory is None
            or bool(workflow_inventory.get("complete", False))
        ),
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
    canonical_plan = _canonical_operation_result(
        ArtifactKind.MIGRATION_PLAN,
        plan,
        plan_executability=(
            PlanExecutabilityValue.BLOCKED
            if blockers
            else PlanExecutabilityValue.EXECUTABLE
        ),
    )
    result = _with_migration_narrative(canonical_plan)
    # Public plans are JSON values. Materializing that boundary removes Python
    # object aliases so a later caller can be validated before deepcopy safely.
    return json.loads(json.dumps(result))


def build_equipment_migration_preflight(
    repo_path: str | Path = ".",
    source_roots: Iterable[str | Path] | str | Path | None = None,
    scan_profile: str = "custom",
) -> dict[str, Any]:
    repo = Path(os.path.abspath(os.path.expanduser(str(repo_path))))
    scan_profile = _normalize_scan_profile(scan_profile)
    budget = _OperationBudget()
    migration_candidates = _migration_candidates(repo, budget)
    proposed_config_patch = propose_migration_config_patch(repo, migration_candidates)
    _require_current_artifact(
        proposed_config_patch,
        ArtifactKind.MIGRATION_CONFIG_PATCH,
        "Migration config patch",
    )
    migration_map = _migration_map(migration_candidates, proposed_config_patch)
    blockers = _migration_plan_blockers(migration_candidates, proposed_config_patch)
    roots = _normalize_equipment_source_roots(source_roots)
    workflow_inventory = (
        build_workflow_migration_inventory(roots, scan_profile=scan_profile)
        if roots or scan_profile == "full-breadth"
        else None
    )
    if workflow_inventory is not None:
        _require_current_artifact(
            workflow_inventory,
            ArtifactKind.WORKFLOW_MIGRATION_INVENTORY,
            "Workflow migration inventory",
        )
    if budget.incomplete_reasons:
        blockers.append(
            {
                "code": "migration.scan_incomplete",
                "message": "Migration discovery stopped before complete coverage was proven.",
                "scan_accounting": budget.accounting(),
            }
        )
    if workflow_inventory is not None and not workflow_inventory.get("complete", False):
        blockers.append(
            {
                "code": "migration.workflow_inventory_incomplete",
                "message": "Workflow inventory stopped before complete coverage was proven.",
                "scan_accounting": workflow_inventory.get("scan_accounting", {}),
            }
        )
    preflight = _equipment_migration_preflight(
        repo,
        migration_candidates,
        migration_map,
        blockers,
        source_roots=roots,
        workflow_inventory=workflow_inventory,
        scan_profile=scan_profile,
    )
    preflight["equipment_review_record"] = _equipment_review_record(preflight)
    state_report = _activation_readiness_report(
        migration_map,
        blockers,
        preflight,
    )
    preflight.update(state_report)
    preflight["evidence"] = _refreshed_migration_state_evidence(
        _record_table_list(preflight.get("evidence")),
        blockers,
        preflight,
    )
    preflight["complete"] = not budget.incomplete_reasons and (
        workflow_inventory is None or bool(workflow_inventory.get("complete", False))
    )
    preflight["scan_accounting"] = {
        "complete": preflight["complete"],
        "repository": budget.accounting(),
        "workflow_inventory": (
            workflow_inventory.get("scan_accounting", {})
            if workflow_inventory is not None
            else None
        ),
    }
    return _canonical_operation_result(
        ArtifactKind.EQUIPMENT_MIGRATION_PREFLIGHT,
        preflight,
        operation="equipment-migration-preflight",
        plan_executability=(
            PlanExecutabilityValue.BLOCKED
            if blockers
            else PlanExecutabilityValue.EXECUTABLE
        ),
    )


def build_workflow_migration_inventory(
    source_roots: Iterable[str | Path] | str | Path | None = None,
    scan_profile: str = "custom",
) -> dict[str, Any]:
    scan_profile = _normalize_scan_profile(scan_profile)
    budget = _OperationBudget()
    roots = _workflow_inventory_roots(source_roots, scan_profile, budget)
    source_root_records = _workflow_source_root_records(roots, scan_profile)
    scopes_by_root = {record["path"]: record["source_scope"] for record in source_root_records}
    contracts = {item.id: item for item in workflow_contracts()}
    unresolvable_roots = [
        record["path"] for record in source_root_records if record["status"] == "unresolvable"
    ]
    entries: list[dict[str, Any]] = []
    seen_files: set[tuple[int, int]] = set()
    for root in roots:
        for path, raw_bytes in _workflow_root_files(root, budget, seen_files):
            entry = _workflow_inventory_entry(
                root,
                path,
                contracts,
                source_scope=scopes_by_root.get(str(root), "operator-source-root"),
                raw_bytes=raw_bytes,
            )
            if entry:
                entries.append(entry)
                budget.result_count += 1
                if budget.result_count > MAX_RESULT_ITEMS:
                    entries.pop()
                    budget.mark_incomplete("limit.results", str(path))
                    break
    entries.sort(key=_source_root_and_path_sort_key)
    catalog_evidence = _workflow_catalog_evidence(entries, contracts)
    backlog_candidates = _workflow_backlog_candidates(entries)
    accounting_records = _workflow_inventory_accounting_records(
        entries,
        source_root_records,
    )
    follow_up_candidates = _accounting_follow_up_candidates(accounting_records)
    _validate_workflow_accounting(
        entries,
        source_root_records,
        accounting_records,
        follow_up_candidates,
    )
    accounting = budget.accounting()
    return _canonical_operation_result(
        ArtifactKind.WORKFLOW_MIGRATION_INVENTORY,
        {
        "operation": "workflow-migration-inventory",
        "mode": "read-only",
        "scan_profile": scan_profile,
        "profile_notes": _scan_profile_notes(scan_profile, source_root_records),
        "source_roots": [str(root) for root in roots],
        "source_root_records": source_root_records,
        "summary": {
            "source_root_count": len(roots),
            "entry_count": len(entries),
            "catalog_evidence_group_count": len(catalog_evidence),
            "backlog_candidate_count": len(backlog_candidates),
            "unresolvable_source_root_count": len(unresolvable_roots),
            "accounting_record_count": len(accounting_records),
            "follow_up_candidate_count": len(follow_up_candidates),
        },
        "entries": entries,
        "catalog_evidence": catalog_evidence,
        "backlog_candidates": backlog_candidates,
        "accounting_records": accounting_records,
        "follow_up_candidates": follow_up_candidates,
        "unresolvable_source_roots": unresolvable_roots,
        "complete": accounting["complete"],
        "limit_reached": accounting["limit_reached"],
        "scan_accounting": accounting,
        "mutation_policy": "no source roots are modified",
        "limitations": [
            "This inventory classifies source material for workflow migration only.",
            "Backlog candidates are not implemented workflow promises.",
            "Fork-local authority remains owned by the maintained fork that contains it.",
        ],
        },
        operation="workflow-migration-inventory",
    )


def dry_run_migration(
    repo_path: str | Path | None = None,
    plan: dict[str, Any] | None = None,
    scan_profile: str = "custom",
) -> dict[str, Any]:
    migration_plan = (
        plan
        if plan is not None
        else generate_migration_plan(repo_path or ".", scan_profile=scan_profile)
    )
    return dry_run_migration_plan(migration_plan, repo_path)


def dry_run_migration_plan(
    plan: dict[str, Any],
    repo_path: str | Path | None = None,
) -> dict[str, Any]:
    return _dry_run_migration_plan(plan, repo_path)


def _dry_run_migration_plan(
    plan: dict[str, Any],
    repo_path: str | Path | None = None,
    *,
    bound_repo: _BoundRepository | None = None,
) -> dict[str, Any]:
    if not isinstance(plan, dict):
        raise ForkOpsError("Migration dry run requires a migration plan object.")
    _validate_bounded_object(plan, label="Migration plan")
    identity_diagnostic = _migration_plan_identity_diagnostic(plan)
    if identity_diagnostic is not None:
        return _refused_operation_result(
            ArtifactKind.MIGRATION_DRY_RUN,
            "migration-dry-run",
            identity_diagnostic,
            mutation_requested=False,
        )
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
    equipment_review_record = _optional_plan_dict(plan, "equipment_review_record")
    repository_diagnostic = _migration_plan_repository_diagnostic(
        plan,
        Path(normalized_repo_path),
        bound_repo=bound_repo,
    )
    equipment_preflight = _optional_plan_dict(plan, "equipment_migration_preflight")
    for field_name in (
        "discovery_scopes",
        "unassessed_equipment_areas",
        "evidence",
        "accounting_records",
        "follow_up_candidates",
    ):
        equipment_preflight[field_name] = copy.deepcopy(
            equipment_review_record.get(field_name, [])
        )
    equipment_preflight["equipment_groups"] = _authoritative_equipment_groups(
        equipment_review_record,
        migration_map,
    )
    equipment_preflight["operator_prompts"] = _equipment_operator_prompts(
        equipment_preflight["equipment_groups"],
        equipment_preflight["unassessed_equipment_areas"],
    )
    equipment_summary: dict[str, Any] = {
        count_name: len(equipment_preflight[section_name])
        for count_name, section_name in (
            ("discovery_scope_count", "discovery_scopes"),
            ("equipment_group_count", "equipment_groups"),
            ("evidence_entry_count", "evidence"),
            ("unassessed_equipment_area_count", "unassessed_equipment_areas"),
            ("accounting_record_count", "accounting_records"),
            ("follow_up_candidate_count", "follow_up_candidates"),
        )
    }
    equipment_preflight["default_onboarding_intent"] = str(
        equipment_review_record.get(
            "default_onboarding_intent",
            "migrate_toward_fork_ops",
        )
    )
    equipment_summary["default_onboarding_intent"] = equipment_preflight[
        "default_onboarding_intent"
    ]
    equipment_preflight["summary"] = equipment_summary
    accounting_records = copy.deepcopy(
        equipment_review_record.get("accounting_records", [])
    )
    follow_up_candidates = copy.deepcopy(
        equipment_review_record.get("follow_up_candidates", [])
    )
    retained_materials = _require_plan_list(plan, "retained_source_materials")
    deferred_removals = _require_plan_list(plan, "deferred_removals")
    retained_authority = _retained_authority(
        retained_materials,
        migration_review_artifact,
        equipment_review_record,
    )
    blocked_steps = _dry_run_blocked_steps(
        plan,
        migration_review_artifact,
        equipment_review_record,
    )
    if repository_diagnostic is not None:
        blocked_steps.append(_equipment_scope_drift_blocker(repository_diagnostic))
    scan_accounting = plan.get("scan_accounting")
    if (
        plan.get("complete") is not True
        or not isinstance(scan_accounting, dict)
        or scan_accounting.get("complete") is not True
    ):
        blocked_steps.append(
            {
                "code": "migration_execution.scan_accounting_incomplete",
                "step": "verify_migration_plan",
                "source": "migration_plan",
                "message": "Migration execution requires complete trusted scan accounting.",
            }
        )
    blocked_steps.extend(_proposed_config_patch_consistency_blockers(proposed_config_patch))
    blocked_steps.extend(
        _migration_execution_blockers(
            Path(normalized_repo_path),
            {"file_edits": file_edits},
            bound_repo=bound_repo,
        )
    )
    blocked_steps.extend(
        _retained_source_material_blockers(
            Path(normalized_repo_path),
            retained_materials,
            bound_repo=bound_repo,
        )
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
    state_report = _activation_readiness_report(
        migration_map,
        blocked_steps,
        equipment_preflight,
    )
    for field_name, value in state_report.items():
        equipment_preflight[field_name] = copy.deepcopy(value)
    refreshed_evidence = _refreshed_migration_state_evidence(
        _require_plan_list(plan, "evidence"),
        blocked_steps,
        equipment_preflight,
    )
    equipment_preflight_evidence = _refreshed_migration_state_evidence(
        _record_table_list(equipment_preflight.get("evidence")),
        blocked_steps,
        equipment_preflight,
    )
    equipment_preflight["summary"]["evidence_entry_count"] = len(
        equipment_preflight_evidence
    )
    equipment_preflight = _canonical_operation_result(
        ArtifactKind.EMBEDDED_EQUIPMENT_MIGRATION_PREFLIGHT,
        {
            "repo_path": normalized_repo_path,
            "mode": "read-only",
            "scan_profile": str(plan.get("scan_profile", "custom")),
            "default_onboarding_intent": equipment_preflight[
                "default_onboarding_intent"
            ],
            "discovery_scopes": equipment_preflight["discovery_scopes"],
            "unassessed_equipment_areas": equipment_preflight[
                "unassessed_equipment_areas"
            ],
            "summary": equipment_preflight["summary"],
            "equipment_groups": equipment_preflight["equipment_groups"],
            "evidence": equipment_preflight_evidence,
            "accounting_records": equipment_preflight["accounting_records"],
            "follow_up_candidates": equipment_preflight["follow_up_candidates"],
            "operator_prompts": equipment_preflight["operator_prompts"],
            **state_report,
            "limitations": _equipment_preflight_limitations(),
        },
        operation="equipment-migration-preflight",
    )
    dry_run = {
        "repo_path": normalized_repo_path,
        "mode": "non-mutating",
        "operation": "migration-dry-run",
        "plan_operation": plan.get("operation"),
        "workflow_run_mode": copy.deepcopy(
            plan.get("workflow_run_mode", _migration_workflow_run_mode())
        ),
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
            "accounting_record_count": len(accounting_records),
            "follow_up_candidate_count": len(follow_up_candidates),
        },
        "file_edits": file_edits,
        "config_changes": config_changes,
        "migration_map": migration_map,
        "accounting_records": accounting_records,
        "follow_up_candidates": follow_up_candidates,
        "equipment_migration_preflight": equipment_preflight,
        "equipment_review_record": equipment_review_record,
        **state_report,
        "evidence": refreshed_evidence,
        "replayable_wet_run": _replayable_wet_run(plan, blocked_steps),
        "migration_review_artifact": migration_review_artifact,
        "retained_materials": retained_materials,
        "retained_authority": retained_authority,
        "deferred_removals": deferred_removals,
        "blocked_steps": blocked_steps,
        "expected_verification_commands": expected_verification_commands,
        "unavailable_work": list(UNAVAILABLE_MIGRATION_WORK),
        "limitations": [
            "This migration dry run is non-mutating and does not apply config or edit files.",
            "Source-material removal is not implemented; source materials remain preserved.",
        ],
        "next_actions": [
            "Review file_edits and config_changes against the migration plan evidence.",
            "Review migration_review_artifact before treating retained authority as covered.",
            (
                "Resolve reported dry-run blockers with durable review evidence before "
                "migration execution."
            ),
            (
                "Run expected_verification_commands after migration execution applies changes."
            ),
        ],
    }
    canonical_dry_run = _canonical_operation_result(
        ArtifactKind.MIGRATION_DRY_RUN,
        dry_run,
        plan_executability=(
            PlanExecutabilityValue.BLOCKED
            if blocked_steps
            else PlanExecutabilityValue.EXECUTABLE
        ),
    )
    return _with_migration_narrative(canonical_dry_run)


def _authoritative_equipment_groups(
    review_record: dict[str, Any],
    migration_map: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    evidence_by_id = {
        str(item["id"]): item
        for item in _record_table_list(review_record.get("evidence"))
        if isinstance(item.get("id"), str) and item["id"]
    }
    migration_by_path = {
        str(item["source_path"]): item
        for item in migration_map
        if isinstance(item.get("source_path"), str) and item["source_path"]
    }
    groups: list[dict[str, Any]] = []
    for decision in _record_table_list(review_record.get("equipment")):
        if decision.get("decision_status") == "superseded":
            continue
        equipment_id = decision.get("equipment_id")
        if not isinstance(equipment_id, str) or not equipment_id:
            continue
        disposition = str(decision.get("disposition", ""))
        facets, compatibility_entries = _authoritative_equipment_group_projections(
            decision,
            disposition,
            evidence_by_id,
            migration_by_path,
        )
        group = {
            "id": equipment_id,
            "identifier": str(decision.get("identifier", "")),
            "source_scope": str(decision.get("source_scope", "")),
            "source_root": str(decision.get("source_root", "")),
            "source_path": str(decision.get("source_path", "")),
            "source_kind": str(decision.get("source_kind", "")),
            "content_sha256": str(decision.get("content_sha256", "")),
            "equipment_classification": str(
                decision.get("equipment_classification", "")
            ),
            "classification_confidence": str(
                decision.get("classification_confidence", "")
            ),
            "disposition": disposition,
            "decision_status": str(decision.get("decision_status", "")),
            "activation_impact": _equipment_activation_impact(disposition),
            "evidence_ids": list(decision.get("evidence_ids", [])),
            "facets": facets,
            "compatibility_entries": compatibility_entries,
        }
        groups.append(group)
    groups.sort(key=_equipment_group_sort_key)
    return groups


def _authoritative_equipment_group_projections(
    decision: dict[str, Any],
    disposition: str,
    evidence_by_id: dict[str, dict[str, Any]],
    migration_by_path: dict[str, dict[str, Any]],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    equipment_id = str(decision.get("equipment_id", ""))
    source_path = str(decision.get("source_path", ""))
    if decision.get("source_scope") == "repo-local":
        migration_entry = migration_by_path.get(source_path)
        if migration_entry is None:
            return [], []
        raw_disposition = migration_entry.get("disposition")
        migration_disposition = (
            raw_disposition if isinstance(raw_disposition, dict) else {}
        )
        source_disposition = str(migration_disposition.get("type", ""))
        return [
            _source_material_equipment_facet(
                equipment_id,
                migration_entry.get("domains", []),
                migration_entry.get("signals", []),
                source_disposition,
                disposition,
            )
        ], []

    workflow_evidence = [
        evidence_by_id[evidence_id]
        for evidence_id in decision.get("evidence_ids", [])
        if evidence_id in evidence_by_id
        and "workflow_source_entry_id" in evidence_by_id[evidence_id]
    ]
    if len(workflow_evidence) != 1:
        return [], []
    [projection] = workflow_evidence
    source_entry_id = str(projection.get("workflow_source_entry_id", ""))
    coverage_status = str(projection.get("workflow_coverage_status", ""))
    target = str(projection.get("workflow_catalog_target", ""))
    workflow_entry = {
        "id": source_entry_id,
        "source_kind": str(decision.get("source_kind", "")),
        "material_scope": str(projection.get("workflow_material_scope", "")),
        "coverage_status": coverage_status,
        "likely_workflow_catalog_target": target,
    }
    return _workflow_material_equipment_projections(
        equipment_id,
        workflow_entry,
        disposition,
    )


def execute_migration(
    repo_path: str | Path | None = None,
    plan: dict[str, Any] | None = None,
) -> dict[str, Any]:
    selected_repo_path = _require_explicit_repository_path(repo_path)
    migration_plan = (
        plan if plan is not None else generate_migration_plan(selected_repo_path)
    )
    return execute_migration_plan(migration_plan, selected_repo_path)


def execute_migration_plan(
    plan: dict[str, Any],
    repo_path: str | Path | None = None,
) -> dict[str, Any]:
    if not isinstance(plan, dict):
        raise ForkOpsError("Migration execution requires a migration plan object.")
    _validate_bounded_object(plan, label="Migration plan")
    identity_diagnostic = _migration_plan_identity_diagnostic(plan)
    if identity_diagnostic is not None:
        return _refused_operation_result(
            ArtifactKind.MIGRATION_EXECUTION_RESULT,
            "migration-execution",
            identity_diagnostic,
            mutation_requested=True,
        )
    raw_repo = _require_explicit_repository_path(repo_path)
    repo = Path(os.path.abspath(os.path.expanduser(str(raw_repo))))
    try:
        bound_repo = _bind_repository(repo)
    except OSError as exc:
        return _migration_execution_result(
            repo=repo,
            preview={"repo_path": str(repo), "plan_operation": plan.get("operation")},
            status="blocked",
            applied_edits=[],
            skipped_edits=[],
            blockers=[_repository_identity_blocker(exc)],
            verification_results=[],
        )
    result: dict[str, Any] | None = None

    def finish(value: dict[str, Any]) -> dict[str, Any]:
        nonlocal result
        result = value
        return value

    try:
        mismatch_result = _bound_repo_path_mismatch_result(plan, repo_path, bound_repo)
        if mismatch_result is not None:
            return finish(mismatch_result)
        preview = _dry_run_migration_plan(plan, repo_path, bound_repo=bound_repo)
        if preview.get("repo_path") != str(bound_repo.path) or not _repository_path_has_identity(
            bound_repo
        ):
            return finish(_migration_execution_result(
                repo=repo,
                preview=preview,
                status="blocked",
                applied_edits=[],
                skipped_edits=_skipped_preview_edits(preview, "repository_identity_changed"),
                blockers=[
                    _repository_identity_blocker(
                        OSError("repository root path changed during migration preflight")
                    )
                ],
                verification_results=[],
            ))
        preview_blockers = _require_preview_list(preview, "blocked_steps")
        if preview_blockers:
            return finish(_migration_execution_result(
                repo=repo,
                preview=preview,
                status="blocked",
                applied_edits=[],
                skipped_edits=_skipped_preview_edits(preview, "blocked_steps_present"),
                blockers=preview_blockers,
                verification_results=[],
            ))

        repository_diagnostic = _migration_plan_repository_diagnostic(
            plan,
            bound_repo.path,
            bound_repo=bound_repo,
        )
        if repository_diagnostic is not None:
            blocker = _equipment_scope_drift_blocker(repository_diagnostic)
            return finish(_migration_execution_result(
                repo=repo,
                preview=preview,
                status="blocked",
                applied_edits=[],
                skipped_edits=_skipped_preview_edits(
                    preview,
                    "equipment_scope_stale",
                ),
                blockers=[blocker],
                verification_results=[],
            ))

        prewrite_identity_diagnostic = _migration_plan_identity_diagnostic(plan)
        if prewrite_identity_diagnostic is not None:
            return finish(
                _refused_operation_result(
                    ArtifactKind.MIGRATION_EXECUTION_RESULT,
                    "migration-execution",
                    prewrite_identity_diagnostic,
                    mutation_requested=True,
                )
            )

        applied_edits, apply_blockers, created_targets = _apply_migration_file_edits(
            bound_repo,
            _require_preview_list(preview, "file_edits"),
        )
        if apply_blockers:
            if applied_edits:
                _mark_edits_applied_unverified(applied_edits)
            try:
                return finish(_migration_execution_result(
                    repo=repo,
                    preview=preview,
                    status="applied_unverified" if applied_edits else "blocked",
                    applied_edits=applied_edits,
                    skipped_edits=_skipped_preview_edits(preview, "write_guard_blocked"),
                    blockers=apply_blockers,
                    verification_results=[],
                ))
            except Exception as exc:
                if applied_edits:
                    _mark_edits_applied_unverified(applied_edits)
                    return finish(
                        _minimal_applied_unverified_migration_result(repo, applied_edits, exc)
                    )
                raise
        skipped_edits = _preserved_source_materials(preview)
        try:
            verification_results, verification_blockers = _verify_migration_execution(
                bound_repo,
                preview,
                created_targets,
            )
            postwrite_identity_diagnostic = _migration_plan_identity_diagnostic(plan)
            if postwrite_identity_diagnostic is not None:
                verification_blockers.append(
                    _equipment_scope_drift_blocker(postwrite_identity_diagnostic)
                )
        except Exception as exc:
            _mark_edits_applied_unverified(applied_edits)
            try:
                return finish(_migration_execution_result(
                    repo=repo,
                    preview=preview,
                    status="applied_unverified",
                    applied_edits=applied_edits,
                    skipped_edits=skipped_edits,
                    blockers=[
                        {
                            "code": "migration_execution.post_write_error",
                            "message": (
                                "Migration changed the repository but verification did not "
                                "complete."
                            ),
                            "error_type": type(exc).__name__,
                        }
                    ],
                    verification_results=[],
                ))
            except Exception as result_exc:
                return finish(
                    _minimal_applied_unverified_migration_result(
                        repo,
                        applied_edits,
                        result_exc,
                    )
                )
        status = "applied" if not verification_blockers else "applied_unverified"
        if verification_blockers:
            _mark_edits_applied_unverified(applied_edits)
        try:
            return finish(_migration_execution_result(
                repo=repo,
                preview=preview,
                status=status,
                applied_edits=applied_edits,
                skipped_edits=skipped_edits,
                blockers=verification_blockers,
                verification_results=verification_results,
            ))
        except Exception as exc:
            _mark_edits_applied_unverified(applied_edits)
            return finish(_minimal_applied_unverified_migration_result(repo, applied_edits, exc))
    finally:
        try:
            bound_repo.close()
        except OSError as exc:
            completed_result = result
            if completed_result is None:
                raise
            completed_result = cast(dict[str, Any], completed_result)
            applied = completed_result.get("applied_edits")
            if isinstance(applied, list) and applied:
                typed_applied = [edit for edit in applied if isinstance(edit, dict)]
                _mark_edits_applied_unverified(typed_applied)
                fallback = _minimal_applied_unverified_migration_result(repo, typed_applied, exc)
                completed_result.clear()
                completed_result.update(fallback)
            else:
                completed_result["outcome"] = OutcomeValue.BLOCKED
                completed_result["plan_executability"] = PlanExecutabilityValue.BLOCKED
                completed_result["mutation_state"] = MutationStateValue.NOT_STARTED
                blockers = completed_result.setdefault("blockers", [])
                if isinstance(blockers, list):
                    blockers.append(
                        {
                            "code": "migration_execution.repository_close_failed",
                            "message": "The selected repository descriptor could not be closed.",
                            "error_type": type(exc).__name__,
                        }
                    )


def _mark_edits_applied_unverified(applied_edits: list[dict[str, Any]]) -> None:
    for edit in applied_edits:
        edit["status"] = "applied_unverified"


def _minimal_applied_unverified_migration_result(
    repo: Path,
    applied_edits: list[dict[str, Any]],
    error: Exception,
) -> dict[str, Any]:
    return _canonical_operation_result(
        ArtifactKind.MIGRATION_EXECUTION_RESULT,
        {
        "repo_path": str(repo),
        "mode": "mutating",
        "operation": "migration-execution",
        "applied_edits": applied_edits,
        "skipped_edits": [],
        "blockers": [
            {
                "code": "migration_execution.post_write_error",
                "message": (
                    "Migration changed the repository but the result could not be completed."
                ),
                "error_type": type(error).__name__,
            }
        ],
        "verification_results": [],
        "mutation": {"occurred": True, "target_state": "unverified"},
        },
        operation="migration-execution",
        outcome=OutcomeValue.FAILED,
        plan_executability=PlanExecutabilityValue.BLOCKED,
        mutation_state=MutationStateValue.APPLIED_UNVERIFIED,
    )


def explain_migration_blocker(
    workflow_output: dict[str, Any],
    blocker_code: str | None = None,
) -> dict[str, Any]:
    if not isinstance(workflow_output, dict):
        raise ForkOpsError("Blocker explanation requires a workflow output object.")
    identity_diagnostic = _migration_workflow_identity_diagnostic(
        workflow_output,
        allow_explanation=False,
    )
    if identity_diagnostic is not None:
        return _refused_operation_result(
            ArtifactKind.MIGRATION_BLOCKER_EXPLANATION,
            "migration-blocker-explanation",
            identity_diagnostic,
            mutation_requested=False,
        )
    operation = workflow_output.get("operation")
    if (
        not isinstance(operation, str)
        or not operation.startswith("migration-")
        or operation == "migration-blocker-explanation"
    ):
        raise ForkOpsError("Blocker explanation requires migration workflow output.")
    blocker = _select_blocker(workflow_output, blocker_code)
    evidence = _blocker_evidence(workflow_output, blocker)
    result = {
        "operation": "migration-blocker-explanation",
        "mode": "read-only",
        "source_operation": workflow_output.get("operation"),
        "originating_workflow": _workflow_contract_dict(_originating_migration_workflow_id()),
        "resolution_workflow": _workflow_contract_dict("migration-blocker-explanation"),
        "blocker": copy.deepcopy(blocker),
        "blocker_evidence": evidence,
        "safe_continuations": _safe_continuations_for_blocker(blocker, evidence),
        "unavailable_work": list(UNAVAILABLE_MIGRATION_WORK),
    }
    return _with_migration_narrative(
        _canonical_operation_result(
            ArtifactKind.MIGRATION_BLOCKER_EXPLANATION,
            result,
            operation="migration-blocker-explanation",
        )
    )


def render_migration_narrative(workflow_output: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(workflow_output, dict):
        raise ForkOpsError("Migration narrative requires a workflow output object.")
    identity_diagnostic = _migration_workflow_identity_diagnostic(
        workflow_output,
        allow_explanation=True,
    )
    if identity_diagnostic is not None:
        raise ForkOpsError(identity_diagnostic.message)
    operation = workflow_output.get("operation")
    workflow_id = _narrative_workflow_id(operation)
    title = _narrative_title(operation)
    summary = _narrative_summary(workflow_output)
    blocker_explanations = _blocker_explanations(workflow_output)
    sections = _narrative_sections(workflow_output, blocker_explanations)
    safe_continuations = _safe_continuations(workflow_output, blocker_explanations)
    unavailable_work = _narrative_unavailable_work(workflow_output)
    refusal = _narrative_refusal(workflow_output, blocker_explanations)
    narrative = {
        "kind": "operator-readable-narrative",
        "workflow_id": workflow_id,
        "title": title,
        "summary": summary,
        "sections": sections,
        "blocker_explanations": blocker_explanations,
        "safe_continuations": safe_continuations,
        "unavailable_work": unavailable_work,
        "refusal": refusal,
    }
    narrative["text"] = _render_narrative_text(
        title,
        summary,
        sections,
        safe_continuations,
        unavailable_work,
        refusal,
    )
    return _canonical_nested_artifact(ArtifactKind.MIGRATION_NARRATIVE, narrative)


def _with_migration_narrative(workflow_output: dict[str, Any]) -> dict[str, Any]:
    output = copy.deepcopy(workflow_output)
    output["narrative"] = render_migration_narrative(output)
    return output


def _narrative_workflow_id(operation: Any) -> str:
    if operation == "migration-blocker-explanation":
        return "migration-blocker-explanation"
    return _originating_migration_workflow_id()


def _originating_migration_workflow_id() -> str:
    return "fork-authority-migration"


def _narrative_title(operation: Any) -> str:
    titles = {
        "migration-assessment": "Migration assessment narrative",
        "migration-plan": "Migration plan narrative",
        "migration-dry-run": "Migration dry run narrative",
        "migration-execution": "Migration execution narrative",
        "migration-blocker-explanation": "Migration blocker explanation narrative",
    }
    return titles.get(str(operation), "Migration narrative")


def _narrative_summary(workflow_output: dict[str, Any]) -> str:
    operation = workflow_output.get("operation")
    summary = workflow_output.get("summary")
    if operation == "migration-assessment" and isinstance(summary, dict):
        return (
            "This read-only migration assessment found "
            f"{summary.get('candidate_count', 0)} candidate source material items."
        )
    if operation == "migration-plan" and isinstance(summary, dict):
        return (
            "This non-mutating migration plan maps "
            f"{summary.get('migration_map_entry_count', 0)} source material items and "
            f"reports {summary.get('blocker_count', 0)} blockers."
        )
    if operation == "migration-dry-run" and isinstance(summary, dict):
        if workflow_output.get("can_execute"):
            return "This non-mutating migration dry run shows guarded config creation can proceed."
        return "This non-mutating migration dry run shows config creation is blocked."
    if operation == "migration-execution":
        outcome = workflow_output.get("outcome")
        mutation_state = workflow_output.get("mutation_state")
        if outcome == OutcomeValue.BLOCKED:
            return "Migration execution refused mutation because blockers are present."
        if mutation_state == MutationStateValue.APPLIED:
            return (
                "Migration execution applied guarded config creation and preserved "
                "retained authority."
            )
        if mutation_state == MutationStateValue.APPLIED_UNVERIFIED:
            return "Migration execution applied edits but verification reported blockers."
        return f"Migration execution outcome is {outcome}."
    if operation == "migration-blocker-explanation":
        blocker = workflow_output.get("blocker", {})
        code = blocker.get("code") if isinstance(blocker, dict) else None
        return f"Migration blocker explanation covers {code or 'the requested blocker'}."
    return "This migration output includes an operator-readable narrative."


def _narrative_sections(
    workflow_output: dict[str, Any],
    blocker_explanations: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    operation = workflow_output.get("operation")
    if operation == "migration-assessment":
        return _assessment_narrative_sections(workflow_output)
    if operation == "migration-plan":
        return _plan_narrative_sections(workflow_output, blocker_explanations)
    if operation == "migration-dry-run":
        return _dry_run_narrative_sections(workflow_output, blocker_explanations)
    if operation == "migration-execution":
        return _execution_narrative_sections(workflow_output, blocker_explanations)
    if operation == "migration-blocker-explanation":
        return _blocker_resolution_narrative_sections(workflow_output)
    return []


def _assessment_narrative_sections(workflow_output: dict[str, Any]) -> list[dict[str, Any]]:
    items = []
    for candidate in _optional_dict_list(workflow_output, "candidates"):
        facts = _optional_dict_list(candidate, "extracted_facts")
        domains = _string_list(candidate.get("domains"))
        fact_label = f"{len(facts)} structured facts"
        domain_label = f"; domains: {', '.join(domains)}" if domains else ""
        items.append(f"{candidate.get('path')}: {fact_label}{domain_label}")
    if not items:
        items.append("No candidate source material was detected in the scan scope.")
    return [
        {
            "heading": "source materials",
            "items": items,
        }
    ]


def _plan_narrative_sections(
    workflow_output: dict[str, Any],
    blocker_explanations: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    sections = [
        {"heading": "migration map", "items": _migration_map_narrative_items(workflow_output)},
        {
            "heading": "retained authority",
            "items": _retained_material_narrative_items(workflow_output),
        },
        {"heading": "blockers", "items": _blocker_narrative_items(blocker_explanations)},
    ]
    sections.append(
        {
            "heading": "safe config creation",
            "items": [_safe_config_creation_line(workflow_output)],
        }
    )
    return sections


def _dry_run_narrative_sections(
    workflow_output: dict[str, Any],
    blocker_explanations: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    edit_items = []
    for edit in _optional_dict_list(workflow_output, "file_edits"):
        edit_items.append(
            f"{edit.get('action')} {edit.get('path')} ({edit.get('status')})"
        )
    if not edit_items:
        edit_items.append("No file edits were previewed.")
    return [
        {"heading": "safe config creation", "items": [_safe_config_creation_line(workflow_output)]},
        {"heading": "file edits", "items": edit_items},
        {
            "heading": "retained authority",
            "items": _retained_material_narrative_items(workflow_output),
        },
        {"heading": "blockers", "items": _blocker_narrative_items(blocker_explanations)},
    ]


def _execution_narrative_sections(
    workflow_output: dict[str, Any],
    blocker_explanations: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    applied = [
        f"{edit.get('action')} {edit.get('path')} ({edit.get('status')})"
        for edit in _optional_dict_list(workflow_output, "applied_edits")
    ]
    skipped = [
        f"{edit.get('action')} {edit.get('path')} ({edit.get('reason')})"
        for edit in _optional_dict_list(workflow_output, "skipped_edits")
    ]
    return [
        {"heading": "safe config creation", "items": [_safe_config_creation_line(workflow_output)]},
        {
            "heading": "retained authority",
            "items": _retained_material_narrative_items(workflow_output),
        },
        {"heading": "applied edits", "items": applied or ["No edits were applied."]},
        {"heading": "skipped edits", "items": skipped or ["No edits were skipped."]},
        {"heading": "blockers", "items": _blocker_narrative_items(blocker_explanations)},
    ]


def _blocker_resolution_narrative_sections(workflow_output: dict[str, Any]) -> list[dict[str, Any]]:
    blocker = workflow_output.get("blocker", {})
    evidence = workflow_output.get("blocker_evidence", {})
    path_items: list[str] = (
        _string_list(evidence.get("paths")) if isinstance(evidence, dict) else []
    )
    map_entries = (
        _optional_dict_list(evidence, "migration_map_entries")
        if isinstance(evidence, dict)
        else []
    )
    evidence_items = [f"Source path: {path}" for path in path_items]
    for entry in map_entries:
        disposition = entry.get("disposition", {})
        disposition_type = (
            disposition.get("type") if isinstance(disposition, dict) else "unknown"
        )
        evidence_items.append(
            f"{entry.get('source_path')}: {disposition_type} -> "
            f"{_target_surface_type(entry.get('target_surface'))}"
        )
    if not evidence_items:
        evidence_items.append("No matching blocker evidence was present in the workflow output.")
    code = blocker.get("code") if isinstance(blocker, dict) else "unknown"
    return [
        {
            "heading": "blocker",
            "items": [f"{code}: {_blocker_summary(blocker, evidence)}"],
        },
        {"heading": "evidence", "items": evidence_items},
    ]


def _migration_map_narrative_items(workflow_output: dict[str, Any]) -> list[str]:
    items = []
    for entry in _optional_dict_list(workflow_output, "migration_map"):
        disposition = entry.get("disposition", {})
        disposition_type = disposition.get("type") if isinstance(disposition, dict) else "unknown"
        target_surface = entry.get("target_surface")
        items.append(
            f"{entry.get('source_path')}: {disposition_type} -> "
            f"{_target_surface_label(target_surface)}; retained source material: "
            f"{bool(entry.get('retained_source_material'))}"
        )
    if not items:
        items.append("No migration map entries are present.")
    return items


def _retained_material_narrative_items(workflow_output: dict[str, Any]) -> list[str]:
    materials = _optional_dict_list(workflow_output, "retained_source_materials")
    if not materials:
        materials = _optional_dict_list(workflow_output, "retained_materials")
    items = [
        f"retained source material {material.get('path')}: "
        f"{material.get('replacement_status', 'deferred')}"
        for material in materials
    ]
    if not items:
        items.append("No retained source material is listed.")
    return items


def _blocker_narrative_items(blocker_explanations: list[dict[str, Any]]) -> list[str]:
    if not blocker_explanations:
        return ["No blockers are reported."]
    items = []
    for explanation in blocker_explanations:
        paths = explanation.get("paths", [])
        path_text = f" Paths: {', '.join(paths)}." if paths else ""
        continuations = explanation.get("safe_continuations", [])
        continuation_text = (
            f" safe continuations: {'; '.join(continuations)}." if continuations else ""
        )
        items.append(
            f"{explanation.get('code')}: {explanation.get('summary')}.{path_text}"
            f"{continuation_text}"
        )
    return items


def _safe_config_creation_line(workflow_output: dict[str, Any]) -> str:
    operation = workflow_output.get("operation")
    if operation == "migration-plan":
        if _blockers_from_output(workflow_output):
            return "Guarded config creation is blocked until blockers resolve."
        return "Guarded config creation can proceed after required review and validation."
    if operation == "migration-dry-run":
        if workflow_output.get("can_execute"):
            return "guarded config creation can proceed for .agents/fork-ops.toml."
        return "config creation is blocked by the reported dry-run blockers."
    if operation == "migration-execution":
        outcome = workflow_output.get("outcome")
        mutation_state = workflow_output.get("mutation_state")
        if mutation_state == MutationStateValue.APPLIED:
            return "guarded config creation was applied for .agents/fork-ops.toml."
        if outcome == OutcomeValue.BLOCKED:
            return "config creation is blocked by the reported blockers."
        return "guarded config creation requires verification review."
    return "Guarded config creation remains subject to migration review."


def _blocker_explanations(workflow_output: dict[str, Any]) -> list[dict[str, Any]]:
    explanations = []
    for blocker in _blockers_from_output(workflow_output):
        evidence = _blocker_evidence(workflow_output, blocker)
        explanations.append(
            {
                "code": blocker.get("code"),
                "message": blocker.get("message"),
                "summary": _blocker_summary(blocker, evidence),
                "paths": _string_list(evidence.get("paths")),
                "migration_map_entries": evidence.get("migration_map_entries", []),
                "safe_continuations": _safe_continuations_for_blocker(blocker, evidence),
            }
        )
    return explanations


def _blockers_from_output(workflow_output: dict[str, Any]) -> list[dict[str, Any]]:
    for key in ("blockers", "blocked_steps"):
        value = workflow_output.get(key)
        if isinstance(value, list):
            return [copy.deepcopy(item) for item in value if isinstance(item, dict)]
    return []


def _select_blocker(
    workflow_output: dict[str, Any],
    blocker_code: str | None,
) -> dict[str, Any]:
    blockers = _blockers_from_output(workflow_output)
    if blocker_code:
        for blocker in blockers:
            if blocker.get("code") == blocker_code:
                return copy.deepcopy(blocker)
        raise ForkOpsError(
            f"Requested blocker code was not present in the workflow output: {blocker_code}"
        )
    if blockers:
        return copy.deepcopy(blockers[0])
    return {
        "code": "blocker.none_found",
        "message": "No blocker evidence was present in the workflow output.",
    }


def _blocker_evidence(
    workflow_output: dict[str, Any],
    blocker: dict[str, Any],
) -> dict[str, Any]:
    paths = _string_list(blocker.get("paths"))
    if not paths:
        path = blocker.get("path")
        paths: list[str] = [path] if isinstance(path, str) and path else []
    migration_map_entries = []
    for entry in _optional_dict_list(workflow_output, "migration_map"):
        source_path = entry.get("source_path")
        if paths and source_path in paths:
            migration_map_entries.append(copy.deepcopy(entry))
    return {
        "paths": paths,
        "migration_map_entries": migration_map_entries,
        "blocker_message": blocker.get("message"),
    }


def _blocker_summary(blocker: dict[str, Any], evidence: dict[str, Any]) -> str:
    code = blocker.get("code")
    if code == "semantic_coverage.incomplete":
        return (
            "semantic_coverage.incomplete means the deterministic extractor did not "
            "produce structured facts for the listed source material paths"
        )
    if code == "proposed_config_patch.diagnostics_failed":
        return "the proposed config patch has diagnostics that must be resolved before dry run"
    if isinstance(blocker.get("message"), str):
        return str(blocker["message"])
    if evidence.get("paths"):
        return "the listed source material paths need review before continuation"
    return "the requested blocker needs review against the workflow output"


def _safe_continuations_for_blocker(
    blocker: dict[str, Any],
    evidence: dict[str, Any],
) -> list[str]:
    code = blocker.get("code")
    if code == "semantic_coverage.incomplete":
        return [
            "Review the listed source material paths before replacing or removing them",
            "Keep the listed source material as fork-local authority",
            "Add structured migration evidence or improve extraction coverage",
            "Re-run migration plan and dry run after coverage changes",
        ]
    if code == "source_material.none_found":
        return [
            "Confirm the migration scan scope",
            "Add or point Fork Ops at fork-local authority source material",
        ]
    if code == "proposed_config_patch.diagnostics_failed":
        return [
            "Review proposed_config_patch.diagnostics",
            "Update source material or config proposal inputs before dry run",
        ]
    if str(code).startswith("migration_execution."):
        return [
            "Keep source material unchanged",
            "Resolve the execution blocker before retrying migration execution",
        ]
    if evidence.get("paths"):
        return ["Review the listed source material paths before continuing"]
    return ["Review the workflow output and select a safe next path"]


def _safe_continuations(
    workflow_output: dict[str, Any],
    blocker_explanations: list[dict[str, Any]],
) -> list[str]:
    continuations: list[str] = []
    for explanation in blocker_explanations:
        for item in explanation.get("safe_continuations", []):
            if isinstance(item, str) and item not in continuations:
                continuations.append(item)
    for action in _string_list(workflow_output.get("safe_continuations")):
        if action not in continuations:
            continuations.append(action)
    for action in _string_list(workflow_output.get("next_actions")):
        if action not in continuations:
            continuations.append(action)
    return continuations


def _narrative_unavailable_work(workflow_output: dict[str, Any]) -> list[str]:
    operation = workflow_output.get("operation")
    if operation in {
        "migration-plan",
        "migration-dry-run",
        "migration-execution",
        "migration-blocker-explanation",
    }:
        return list(UNAVAILABLE_MIGRATION_WORK)
    return []


def _narrative_refusal(
    workflow_output: dict[str, Any],
    blocker_explanations: list[dict[str, Any]],
) -> dict[str, Any]:
    active = (
        workflow_output.get("operation") == "migration-execution"
        and workflow_output.get("outcome") == OutcomeValue.BLOCKED
    )
    reason = ""
    if active:
        codes = [str(item.get("code")) for item in blocker_explanations if item.get("code")]
        subject = ", ".join(codes) if codes else "blockers"
        verb = "is" if len(codes) == 1 else "are"
        reason = (
            "Migration execution refused mutation because "
            f"{subject} {verb} present."
        )
    return {"active": active, "reason": reason}


def _render_narrative_text(
    title: str,
    summary: str,
    sections: list[dict[str, Any]],
    safe_continuations: list[str],
    unavailable_work: list[str],
    refusal: dict[str, Any],
) -> str:
    lines = [title, "", summary]
    if refusal.get("active") and refusal.get("reason"):
        lines.extend(["", f"refusal: {refusal['reason']}"])
    for section in sections:
        heading = section.get("heading")
        items = section.get("items", [])
        if not isinstance(heading, str) or not isinstance(items, list):
            continue
        lines.extend(["", f"{heading}:"])
        for item in items:
            if isinstance(item, str):
                lines.append(f"- {item}")
    if safe_continuations:
        lines.extend(["", "safe continuations:"])
        lines.extend(f"- {item}" for item in safe_continuations)
    if unavailable_work:
        lines.extend(["", "unavailable work:"])
        for item in unavailable_work:
            if item == "source-material replacement/removal":
                lines.append("- source-material replacement/removal is unavailable.")
            elif item.endswith("s"):
                lines.append(f"- {item} are unavailable.")
            else:
                lines.append(f"- {item} is unavailable.")
    return "\n".join(lines).rstrip()


def _workflow_contract_dict(workflow_id: str) -> dict[str, Any]:
    for contract in workflow_contracts():
        if contract.id == workflow_id:
            return contract.to_dict()
    return {
        "id": workflow_id,
        "title": workflow_id,
        "implementation_extent": "planned",
        "operations": [],
    }


def _target_surface_label(target_surface: Any) -> str:
    if not isinstance(target_surface, dict):
        return "unknown"
    surface_type = _target_surface_type(target_surface)
    path = target_surface.get("path")
    workflow_id = target_surface.get("workflow_id")
    section = target_surface.get("section")
    details = []
    if isinstance(path, str) and path:
        details.append(path)
    if isinstance(workflow_id, str) and workflow_id:
        details.append(workflow_id)
    if isinstance(section, str) and section:
        details.append(section)
    if details:
        return f"{surface_type} ({', '.join(details)})"
    return surface_type


def _target_surface_type(target_surface: Any) -> str:
    if isinstance(target_surface, dict) and isinstance(target_surface.get("type"), str):
        return str(target_surface["type"])
    return "unknown"


def _optional_dict_list(source: dict[str, Any], key: str) -> list[dict[str, Any]]:
    value = source.get(key)
    if not isinstance(value, list):
        return []
    return [item for item in value if isinstance(item, dict)]


def _string_list(value: Any) -> list[str]:
    if not isinstance(value, list):
        return []
    return [item for item in value if isinstance(item, str)]


def _bound_repo_path_mismatch_result(
    migration_plan: dict[str, Any],
    repo_path: str | Path | None,
    bound_repo: _BoundRepository,
) -> dict[str, Any] | None:
    if migration_plan.get("operation") != "migration-plan":
        return None
    if repo_path is None or str(repo_path) == "":
        return None
    raw_plan_path = migration_plan.get("repo_path")
    if not isinstance(raw_plan_path, str | Path) or not str(raw_plan_path):
        raise ForkOpsError("Migration execution plan has malformed repo_path.")
    plan_repo_path = os.path.abspath(os.path.expanduser(str(raw_plan_path)))
    requested_repo_path = os.path.abspath(os.path.expanduser(str(repo_path)))
    if requested_repo_path == plan_repo_path:
        return None
    return _migration_execution_result(
        repo=bound_repo.path,
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
    return os.path.abspath(os.path.expanduser(str(raw_path)))


def _dry_run_file_edits(proposed_config_patch: dict[str, Any]) -> list[dict[str, Any]]:
    target_path = proposed_config_patch.get("target_path")
    if not isinstance(target_path, str) or not target_path:
        raise ForkOpsError(
            "Migration dry run input has malformed proposed_config_patch.target_path."
        )
    target_path = _normalize_migration_relative_path(target_path)
    action = proposed_config_patch.get("action", "review-and-merge")
    if not isinstance(action, str):
        raise ForkOpsError("Migration dry run input has malformed proposed_config_patch.action.")
    content = proposed_config_patch.get("toml", "")
    if not isinstance(content, str):
        raise ForkOpsError("Migration dry run input has malformed proposed_config_patch.toml.")
    return [
        {
            "path": target_path,
            "action": action,
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
    action = proposed_config_patch.get("action", "review-and-merge")
    if not isinstance(action, str):
        raise ForkOpsError("Migration dry run input has malformed proposed_config_patch.action.")
    config = proposed_config_patch.get("config", {})
    if not isinstance(config, dict):
        raise ForkOpsError("Migration dry run input has malformed proposed_config_patch.config.")
    return [
        {
            "target_path": target_path,
            "action": action,
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


def _dry_run_blocked_steps(
    plan: dict[str, Any],
    migration_review_artifact: dict[str, Any],
    equipment_review_record: dict[str, Any],
) -> list[dict[str, Any]]:
    blocked_steps: list[dict[str, Any]] = []
    reviewed_retained_paths = _reviewed_retained_source_paths(
        migration_review_artifact,
        equipment_review_record,
    )
    for blocker in _require_plan_list(plan, "blockers"):
        if _blocker_resolved_by_reviewed_retain(blocker, reviewed_retained_paths):
            continue
        blocker.setdefault("step", "review_migration_plan")
        blocker.setdefault("source", "migration_plan")
        blocked_steps.append(blocker)
    return blocked_steps


def _blocker_resolved_by_reviewed_retain(
    blocker: dict[str, Any],
    reviewed_retained_paths: set[str],
) -> bool:
    if blocker.get("code") != "semantic_coverage.incomplete":
        return False
    paths = _string_list(blocker.get("paths"))
    if not paths:
        return False
    return all(path in reviewed_retained_paths for path in paths)


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


def _optional_plan_dict(plan: dict[str, Any], key: str) -> dict[str, Any]:
    value = plan.get(key, {})
    if value is None:
        return {}
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
    result = {
        "repo_path": str(repo),
        "mode": "mutating",
        "operation": "migration-execution",
        "plan_operation": preview.get("plan_operation"),
        "summary": {
            "applied_edit_count": len(applied_edits),
            "skipped_edit_count": len(skipped_edits),
            "migration_map_entry_count": len(_optional_preview_list(preview, "migration_map")),
            "retained_material_count": len(_optional_preview_list(preview, "retained_materials")),
            "retained_authority_count": len(
                _optional_preview_list(preview, "retained_authority")
            ),
            "review_artifact_entry_count": len(
                _review_artifact_entries(
                    _optional_preview_dict(preview, "migration_review_artifact")
                )
            ),
            "equipment_group_count": len(
                _optional_preview_list(
                    _optional_preview_dict(preview, "equipment_migration_preflight"),
                    "equipment_groups",
                )
            ),
            "blocker_count": len(blockers),
            "verification_result_count": len(verification_results),
        },
        "applied_edits": applied_edits,
        "skipped_edits": skipped_edits,
        "migration_map": _optional_preview_list(preview, "migration_map"),
        "equipment_migration_preflight": _optional_preview_dict(
            preview,
            "equipment_migration_preflight",
        ),
        "equipment_review_record": _optional_preview_dict(
            preview,
            "equipment_review_record",
        ),
        "activation_readiness": _optional_preview_dict(preview, "activation_readiness"),
        "replacement_coverage": _optional_preview_list(preview, "replacement_coverage"),
        "operational_continuity": _optional_preview_list(preview, "operational_continuity"),
        "evidence": _optional_preview_list(preview, "evidence"),
        "workflow_run_mode": _optional_preview_dict(preview, "workflow_run_mode"),
        "replayable_wet_run": _optional_preview_dict(preview, "replayable_wet_run"),
        "retained_materials": _optional_preview_list(preview, "retained_materials"),
        "retained_authority": _optional_preview_list(preview, "retained_authority"),
        "deferred_removals": _optional_preview_list(preview, "deferred_removals"),
        "migration_review_artifact": _optional_preview_dict(
            preview,
            "migration_review_artifact",
        ),
        "blockers": blockers,
        "verification_results": verification_results,
        "unavailable_work": list(UNAVAILABLE_MIGRATION_WORK),
    }
    outcome = {
        "applied": OutcomeValue.COMPLETED,
        "blocked": OutcomeValue.BLOCKED,
        "applied_unverified": OutcomeValue.FAILED,
        "verification_failed": OutcomeValue.FAILED,
    }.get(status, OutcomeValue.FAILED)
    mutation_state = (
        MutationStateValue.APPLIED
        if status == "applied"
        else (
            MutationStateValue.APPLIED_UNVERIFIED
            if applied_edits
            else MutationStateValue.NOT_STARTED
        )
    )
    canonical_result = _canonical_operation_result(
        ArtifactKind.MIGRATION_EXECUTION_RESULT,
        result,
        operation="migration-execution",
        outcome=outcome,
        plan_executability=(
            PlanExecutabilityValue.EXECUTABLE
            if status == "applied"
            else PlanExecutabilityValue.BLOCKED
        ),
        mutation_state=mutation_state,
    )
    return _with_migration_narrative(canonical_result)


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


def _migration_execution_blockers(
    repo: Path,
    preview: dict[str, Any],
    *,
    bound_repo: _BoundRepository | None = None,
    check_target: bool = True,
) -> list[dict[str, Any]]:
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
        blockers.extend(
            _migration_file_edit_blockers(
                repo,
                edit,
                bound_repo=bound_repo,
                check_target=check_target,
            )
        )
    return blockers


def _migration_file_edit_blockers(
    repo: Path,
    edit: dict[str, Any],
    *,
    bound_repo: _BoundRepository | None,
    check_target: bool,
) -> list[dict[str, Any]]:
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
    target_relative_path = Path(_normalize_migration_relative_path(str(edit.get("path", ""))))
    parent_kind, target_kind = _migration_target_path_kinds(
        repo,
        target_relative_path,
        bound_repo=bound_repo,
        check_target=check_target,
    )
    if parent_kind == "symlink":
        blockers.append(
            {
                "code": "migration_execution.unsafe_target_path",
                "path": edit.get("path"),
                "message": "Migration execution refuses target paths outside the repository.",
                "path_kind": parent_kind,
            }
        )
    elif parent_kind not in {"missing", "directory"}:
        blockers.append(
            {
                "code": "migration_execution.target_parent_not_directory",
                "path": edit.get("path"),
                "message": (
                    "Migration execution target parent is not safely inspectable as a directory."
                ),
                "path_kind": parent_kind,
            }
        )
    elif check_target and target_kind != "missing" and action == "create":
        blockers.append(
            {
                "code": "migration_execution.target_exists",
                "path": edit.get("path"),
                "message": (
                    "Refusing to overwrite or inspect an unsafe target during config creation."
                ),
                "path_kind": target_kind,
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
    track_aware = capability["authority_readiness"]["levels"]["track-aware"]
    if track_aware["ready"] is not True:
        blockers.append(
            {
                "code": "migration_execution.required_capability_unavailable",
                "path": edit.get("path"),
                "message": (
                    "Migration execution requires the proposed config to satisfy track-aware."
                ),
                "required_level": "track-aware",
                "missing": track_aware["missing"],
            }
        )
    return blockers


def _migration_target_path_kinds(
    repo: Path,
    target: Path,
    *,
    bound_repo: _BoundRepository | None,
    check_target: bool,
) -> tuple[str, str]:
    owned_bound_repo = bound_repo is None
    try:
        active_bound_repo = bound_repo or _bind_repository(repo)
    except OSError:
        return "uninspectable", "uninspectable"
    try:
        try:
            parent_stat = _bound_lstat(active_bound_repo, target.parent)
        except FileNotFoundError:
            return "missing", "missing"
        except OSError:
            return "uninspectable", "uninspectable"
        parent_kind = _stat_result_kind(parent_stat)
        if parent_kind != "directory" or not check_target:
            return parent_kind, "missing"
        try:
            target_stat = _bound_lstat(active_bound_repo, target)
        except FileNotFoundError:
            return parent_kind, "missing"
        except OSError:
            return parent_kind, "uninspectable"
        return parent_kind, _stat_result_kind(target_stat)
    finally:
        if owned_bound_repo:
            try:
                active_bound_repo.close()
            except OSError:
                pass


def _stat_result_kind(path_stat: os.stat_result) -> str:
    mode = path_stat.st_mode
    if stat.S_ISREG(mode):
        return "regular"
    if stat.S_ISDIR(mode):
        return "directory"
    if stat.S_ISLNK(mode):
        return "symlink"
    return "special"


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
    return repo / target, None


def _retained_source_material_blockers(
    repo: Path,
    retained_materials: list[dict[str, Any]],
    *,
    bound_repo: _BoundRepository | None = None,
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
        try:
            actual_content = (
                _read_bound_regular_file(bound_repo, retained_path)
                if bound_repo is not None
                else _read_file_within_root(repo, retained_path)
            )
        except _BoundedReadError as exc:
            blockers.append(
                {
                    "code": "migration_execution.retained_source_unreadable",
                    "path": raw_path,
                    "message": "Retained source material could not be read safely.",
                    "reason": exc.code,
                }
            )
            continue
        if bound_repo is not None and not _repository_path_has_identity(bound_repo):
            blockers.append(_repository_identity_blocker(OSError("repository root changed")))
            continue
        if hashlib.sha256(actual_content).hexdigest() != expected_sha256:
            blockers.append(
                {
                    "code": "migration_execution.retained_source_changed",
                    "path": raw_path,
                    "message": "Retained source material changed after migration planning.",
                }
            )
    return blockers


def _apply_migration_file_edits(
    repo: _BoundRepository,
    file_edits: list[dict[str, Any]],
) -> tuple[
    list[dict[str, Any]],
    list[dict[str, Any]],
    list[tuple[Path, _CreatedFileIdentity, bytes]],
]:
    applied = []
    blockers = []
    created_targets = []
    for edit in file_edits:
        applied_edit, blocker, identity = _apply_migration_file_edit(repo, edit)
        if blocker is not None:
            blockers.append(blocker)
            if applied_edit is not None:
                applied.append(applied_edit)
        elif applied_edit is not None and identity is not None:
            applied.append(applied_edit)
            created_targets.append(
                (
                    repo.path / str(edit["path"]),
                    identity,
                    _config_content_bytes(str(edit["content"])),
                )
            )
    return applied, blockers, created_targets


def _apply_migration_file_edit(
    repo: _BoundRepository,
    edit: dict[str, Any],
) -> tuple[dict[str, Any] | None, dict[str, Any] | None, _CreatedFileIdentity | None]:
    path, blocker = _migration_edit_target(repo.path, edit.get("path"))
    if blocker:
        return None, blocker, None
    content = edit["content"]
    try:
        parent_descriptor, parent_identity, parent_created = _open_or_create_agents_parent(repo)
    except _CreatedParentUnavailableError as exc:
        return _parent_only_applied_edit(edit, True), {
            "code": "migration_execution.target_parent_unverified",
            "path": edit.get("path"),
            "message": (
                "Migration execution created the target parent, but its exact "
                f"state could not be verified: {exc}"
            ),
        }, None
    except OSError as exc:
        return None, {
            "code": "migration_execution.target_parent_unavailable",
            "path": edit.get("path"),
            "message": f"Migration execution target parent is unavailable: {exc}",
        }, None
    outcome: tuple[
        dict[str, Any] | None,
        dict[str, Any] | None,
        _CreatedFileIdentity | None,
    ]
    try:
        identity = _write_new_file_atomically(
            repo,
            parent_descriptor,
            path,
            content,
            parent_identity=parent_identity,
        )
    except _TargetAlreadyExistsError:
        outcome = (
            _parent_only_applied_edit(edit, parent_created),
            {
                "code": "migration_execution.target_exists",
                "path": edit.get("path"),
                "message": "Refusing to overwrite a target created before config write.",
            },
            None,
        )
    except _IndeterminateCreatedFileError as exc:
        outcome = (
            {
                "path": edit["path"],
                "action": edit["action"],
                "status": "applied_unverified",
                "content_kind": edit.get("content_kind"),
            },
            {
                "code": "migration_execution.write_unverified",
                "path": edit.get("path"),
                "message": (
                    "Migration execution may have created the config, but the exact "
                    f"result could not be verified: {exc}"
                ),
            },
            None,
        )
    except OSError as exc:
        outcome = (
            _parent_only_applied_edit(edit, parent_created),
            {
                "code": "migration_execution.write_failed",
                "path": edit.get("path"),
                "message": f"Migration execution config write failed: {exc}",
            },
            None,
        )
    else:
        content_bytes = _config_content_bytes(content)
        outcome = (
            {
                "path": edit["path"],
                "action": edit["action"],
                "status": "applied",
                "content_kind": edit.get("content_kind"),
                "bytes": len(content_bytes),
                "content_sha256": hashlib.sha256(content_bytes).hexdigest(),
            },
            None,
            identity,
        )
    finally:
        try:
            os.close(parent_descriptor)
        except OSError as exc:
            applied_edit, blocker, _ = outcome
            if applied_edit is not None:
                applied_edit["status"] = "applied_unverified"
                outcome = (
                    applied_edit,
                    {
                        "code": "migration_execution.descriptor_close_unverified",
                        "path": edit.get("path"),
                        "message": (
                            "Migration execution changed repository state, but descriptor "
                            f"cleanup could not be verified: {exc}"
                        ),
                    },
                    None,
                )
            elif blocker is None:
                raise
    return outcome


def _parent_only_applied_edit(
    edit: dict[str, Any],
    parent_created: bool,
) -> dict[str, Any] | None:
    if not parent_created:
        return None
    return {
        "path": edit["path"],
        "action": edit["action"],
        "status": "applied_unverified",
        "content_kind": edit.get("content_kind"),
        "created_parent": CONFIG_RELATIVE_PATH.parent.as_posix(),
        "target_created": False,
    }


def _write_new_file_atomically(
    repo: _BoundRepository,
    parent_descriptor: int,
    path: Path,
    content: str,
    *,
    parent_identity: tuple[int, int],
) -> _CreatedFileIdentity:
    _require_descriptor_relative_operations("open")
    content_bytes = _config_content_bytes(content)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        target_descriptor = os.open(
            path.name,
            flags,
            0o600,
            dir_fd=parent_descriptor,
        )
    except FileExistsError as exc:
        raise _TargetAlreadyExistsError(str(exc)) from exc
    try:
        with os.fdopen(target_descriptor, "wb", closefd=False) as handle:
            handle.write(content_bytes)
            handle.flush()
            os.fsync(handle.fileno())
        created_stat = os.fstat(target_descriptor)
    except Exception as exc:
        raise _IndeterminateCreatedFileError(
            "writing or synchronizing the descriptor-relative target failed"
        ) from exc
    finally:
        try:
            os.close(target_descriptor)
        except OSError as exc:
            raise _IndeterminateCreatedFileError(
                "target descriptor cleanup failed after config creation"
            ) from exc
    if not _repository_path_has_identity(repo):
        raise _IndeterminateCreatedFileError(
            "the repository path changed after config creation"
        )
    return _CreatedFileIdentity(
        device=created_stat.st_dev,
        inode=created_stat.st_ino,
        size=len(content_bytes),
        content_sha256=hashlib.sha256(content_bytes).hexdigest(),
        modified_time_ns=created_stat.st_mtime_ns,
        change_time_ns=created_stat.st_ctime_ns,
        parent_device=parent_identity[0],
        parent_inode=parent_identity[1],
        root_device=repo.device,
        root_inode=repo.inode,
    )


def _bind_repository(repo: Path) -> _BoundRepository:
    _require_descriptor_relative_operations("open")
    lexical_stat = os.stat(repo, follow_symlinks=False)
    if not stat.S_ISDIR(lexical_stat.st_mode):
        raise OSError(errno.ENOTDIR, "repository root is not a directory")
    flags = os.O_RDONLY
    if hasattr(os, "O_DIRECTORY"):
        flags |= os.O_DIRECTORY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(repo, flags)
    try:
        repo_stat = os.fstat(descriptor)
        if not stat.S_ISDIR(repo_stat.st_mode):
            raise OSError(errno.ENOTDIR, "repository root is not a directory")
        if (repo_stat.st_dev, repo_stat.st_ino) != (
            lexical_stat.st_dev,
            lexical_stat.st_ino,
        ):
            raise OSError(
                getattr(errno, "ESTALE", errno.EIO),
                "repository root changed while opening",
            )
        bound_path = _bound_repository_display_path(descriptor, repo)
        bound = _BoundRepository(
            repo,
            bound_path,
            descriptor,
            repo_stat.st_dev,
            repo_stat.st_ino,
        )
        if not _repository_path_has_identity(bound):
            raise OSError(
                getattr(errno, "ESTALE", errno.EIO),
                "repository root path changed while binding",
            )
        return bound
    except Exception:
        os.close(descriptor)
        raise


def _bound_repository_display_path(descriptor: int, lexical_path: Path) -> Path:
    proc_path = Path(f"/proc/self/fd/{descriptor}")
    try:
        target = os.readlink(proc_path)
    except OSError:
        return lexical_path
    if target.endswith(" (deleted)"):
        raise OSError(getattr(errno, "ESTALE", errno.EIO), "repository root was unlinked")
    display_path = Path(target)
    if not display_path.is_absolute():
        raise OSError(errno.EIO, f"repository descriptor path is not absolute: {lexical_path}")
    return display_path


def _duplicate_bound_repository(repo: _BoundRepository) -> _BoundRepository:
    descriptor = os.dup(repo.descriptor)
    return _BoundRepository(
        repo.path,
        repo.canonical_path,
        descriptor,
        repo.device,
        repo.inode,
    )


def _repository_path_has_identity(repo: _BoundRepository) -> bool:
    try:
        repo_stat = os.stat(repo.path, follow_symlinks=False)
    except OSError:
        return False
    return stat.S_ISDIR(repo_stat.st_mode) and (
        repo_stat.st_dev,
        repo_stat.st_ino,
    ) == (repo.device, repo.inode)


def _open_or_create_agents_parent(
    repo: _BoundRepository,
) -> tuple[int, tuple[int, int], bool]:
    _require_descriptor_relative_operations("mkdir", "open", "stat")
    created = False
    try:
        os.mkdir(CONFIG_RELATIVE_PATH.parent.name, 0o755, dir_fd=repo.descriptor)
        created = True
    except FileExistsError:
        pass
    if created:
        raise _CreatedParentUnavailableError(
            "the target parent was created and must be rebound on a subsequent invocation"
        )
    flags = os.O_RDONLY
    if hasattr(os, "O_DIRECTORY"):
        flags |= os.O_DIRECTORY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(
            CONFIG_RELATIVE_PATH.parent.name,
            flags,
            dir_fd=repo.descriptor,
        )
        try:
            parent_stat = os.fstat(descriptor)
            if not stat.S_ISDIR(parent_stat.st_mode):
                raise OSError(errno.ENOTDIR, "migration target parent is not a directory")
            if not _repository_path_has_identity(repo):
                raise OSError(
                    getattr(errno, "ESTALE", errno.EIO),
                    "repository root path changed before config creation",
                )
            return descriptor, (parent_stat.st_dev, parent_stat.st_ino), created
        except Exception:
            os.close(descriptor)
            raise
    except OSError as exc:
        if created:
            raise _CreatedParentUnavailableError(str(exc)) from exc
        raise


def _repository_identity_blocker(exc: OSError) -> dict[str, Any]:
    return {
        "code": "migration_execution.repository_identity_changed",
        "path": ".",
        "message": f"Migration execution repository identity is unavailable: {exc}",
    }


def _require_descriptor_relative_operations(*operation_names: str) -> None:
    supported_names = {operation.__name__ for operation in os.supports_dir_fd}
    unsupported = [name for name in operation_names if name not in supported_names]
    if unsupported:
        names = ", ".join(sorted(unsupported))
        raise OSError(
            errno.ENOTSUP,
            f"descriptor-relative filesystem operations are unavailable: {names}",
        )


def _open_exact_parent_descriptor(
    repo: _BoundRepository,
    expected_identity: tuple[int, int],
) -> int:
    flags = os.O_RDONLY
    if hasattr(os, "O_DIRECTORY"):
        flags |= os.O_DIRECTORY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(
        CONFIG_RELATIVE_PATH.parent.name,
        flags,
        dir_fd=repo.descriptor,
    )
    try:
        parent_stat = os.fstat(descriptor)
        if not stat.S_ISDIR(parent_stat.st_mode):
            raise OSError(errno.ENOTDIR, "migration target parent is not a directory")
        if (parent_stat.st_dev, parent_stat.st_ino) != expected_identity:
            raise OSError(
                getattr(errno, "ESTALE", errno.EIO),
                "migration target parent identity changed",
            )
        return descriptor
    except Exception:
        os.close(descriptor)
        raise


def _config_content_bytes(content: str) -> bytes:
    return content.encode()


def _verify_migration_execution(
    repo: _BoundRepository,
    preview: dict[str, Any],
    created_targets: list[tuple[Path, _CreatedFileIdentity, bytes]],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    target_blockers = _created_target_blockers(created_targets, repo)
    if target_blockers:
        return [], target_blockers
    if not _repository_path_has_identity(repo):
        return [], [_repository_identity_blocker(OSError("repository root path changed"))]
    report = build_status_report(repo.path, include_config=False)
    required_level = "track-aware"
    authority = report["capability"]["authority_readiness"]
    required_ready = authority["levels"][required_level]["ready"] is True
    status = "passed" if required_ready else "failed"
    results = []
    for requirement in _require_preview_list(preview, "expected_verification_commands"):
        results.append(
            {
                "code": requirement.get("code"),
                "command": requirement.get("command"),
                "status": status,
                "highest_authority_ready": authority["highest_authority_ready"],
                "required_level": required_level,
                "required_level_ready": required_ready,
                "diagnostics": report.get("diagnostics", []),
                "note": (
                    "Status reflects Fork Ops capability verification; listed commands "
                    "are not executed."
                ),
            }
        )
    blockers = _created_target_blockers(created_targets, repo)
    repository_diagnostic = _migration_plan_repository_diagnostic(
        preview,
        repo.path,
        bound_repo=repo,
    )
    if repository_diagnostic is not None:
        blockers.append(_equipment_scope_drift_blocker(repository_diagnostic))
    if status != "passed":
        blockers.append(
            {
                "code": "migration_execution.verification_failed",
                "message": "Fork Ops config verification failed after migration execution.",
                "diagnostics": report.get("diagnostics", []),
            }
        )
    return results, blockers


def _created_target_blockers(
    created_targets: list[tuple[Path, _CreatedFileIdentity, bytes]],
    bound_repo: _BoundRepository | None = None,
) -> list[dict[str, Any]]:
    blockers = []
    for path, identity, expected_content in created_targets:
        _, blocker = _verify_created_target(
            path,
            identity,
            expected_content,
            bound_repo,
        )
        if blocker is not None:
            blockers.append(blocker)
    return blockers


def _migration_candidates(
    repo: Path,
    budget: _OperationBudget | None = None,
    *,
    bound_repo: _BoundRepository | None = None,
) -> list[dict[str, Any]]:
    active_budget = budget or _OperationBudget()
    candidates: list[dict[str, Any]] = []
    for rel_path, active_repo in _iter_candidate_paths(
        repo,
        active_budget,
        bound_repo=bound_repo,
    ):
        rel = rel_path.as_posix()
        if rel in MIGRATION_DISCOVERY_EXCLUDED_PATHS:
            continue
        try:
            raw_bytes = _read_bound_regular_file(active_repo, rel_path, budget=active_budget)
        except _BoundedReadError as exc:
            active_budget.mark_incomplete(exc.code, rel)
            continue
        raw_text = raw_bytes.decode(errors="ignore")
        lowered_text = raw_text.lower()
        signals = _fork_signals(lowered_text)
        if not signals:
            continue
        urls = _extract_urls(raw_text, budget=active_budget)
        if active_budget.incomplete_reasons:
            break
        extracted_facts = _extracted_facts(raw_text)
        nested_result_count = len(signals) + len(urls) + len(extracted_facts)
        if active_budget.result_count + nested_result_count + 1 > MAX_RESULT_ITEMS:
            active_budget.mark_incomplete("limit.results", rel)
            break
        candidates.append(
            {
                "path": rel,
                "kind": _candidate_kind(rel),
                "content_sha256": hashlib.sha256(raw_bytes).hexdigest(),
                "signals": signals,
                "domains": _candidate_domains(signals),
                "extracted_facts": extracted_facts,
                "urls": urls,
                "proposed_destination": _proposed_destination(rel, signals),
                "portability_hint": _portability_hint(rel, signals),
            }
        )
        active_budget.result_count += nested_result_count + 1
    return sorted(candidates, key=_path_sort_key)


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
        for candidate in sorted(candidates, key=_path_sort_key)
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
    if proposed_config_patch.get("action") != "create":
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
            "review_decision": _default_review_decision(entry),
            "rationale": _migration_review_rationale(entry),
        }
        for entry in migration_map
    ]
    artifact = {
        "status": "proposed",
        "target_path": MIGRATION_REVIEW_ARTIFACT_RELATIVE_PATH,
        "content_kind": "migration-review-artifact",
        "source_material_review_decision_types": list(SOURCE_MATERIAL_REVIEW_DECISION_TYPES),
        "entries": entries,
    }
    artifact["markdown"] = _migration_review_artifact_markdown(entries)
    return _canonical_nested_artifact(ArtifactKind.MIGRATION_REVIEW_ARTIFACT, artifact)


def _default_review_decision(entry: dict[str, Any]) -> dict[str, Any]:
    return {
        "status": "pending",
        "proposed_choice": _proposed_review_choice(entry),
        "choices": list(SOURCE_MATERIAL_REVIEW_DECISION_TYPES),
    }


def _proposed_review_choice(entry: dict[str, Any]) -> str:
    disposition = entry.get("disposition", {})
    disposition_type = disposition.get("type") if isinstance(disposition, dict) else ""
    return {
        "extracted_into_config": "retain",
        "retained_as_fork_local_authority": "retain",
        "irrelevant_to_fork_ops": "exclude",
        "mapped_to_workflow_backlog": "defer",
        "deferred_with_rationale": "defer",
        "needs_human_decision": "needs-human-decision",
        "unsupported_extractor_shape": "unsupported-extractor",
    }.get(str(disposition_type), "needs-human-decision")


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
                *_review_decision_markdown_lines(entry.get("review_decision")),
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


def _review_decision_markdown_lines(review_decision: Any) -> list[str]:
    if not isinstance(review_decision, dict):
        return []
    lines: list[str] = []
    status = review_decision.get("status")
    if isinstance(status, str) and status:
        lines.append(f"- Review status: {status}")
    choice = review_decision.get("choice")
    if isinstance(choice, str) and choice:
        lines.append(f"- Review choice: {choice}")
    proposed_choice = review_decision.get("proposed_choice")
    if isinstance(proposed_choice, str) and proposed_choice:
        lines.append(f"- Proposed review choice: {proposed_choice}")
    choices = _string_list(review_decision.get("choices"))
    if choices:
        lines.append(f"- Review choices: {', '.join(choices)}")
    rationale = review_decision.get("rationale")
    if isinstance(rationale, str) and rationale:
        lines.append(f"- Review rationale: {rationale}")
    return lines


def _normalize_equipment_source_roots(
    source_roots: Iterable[str | Path] | str | Path | None,
) -> list[Path]:
    if source_roots is None:
        return []
    if isinstance(source_roots, str | Path):
        raw_roots: Iterable[str | Path] = [source_roots]
    else:
        raw_roots = source_roots
    roots: list[Path] = []
    for index, root in enumerate(raw_roots):
        if index >= MAX_SCAN_ROOTS:
            raise ForkOpsError("Equipment source roots exceed the root count limit.")
        path = Path(os.path.abspath(os.path.expanduser(str(root))))
        if len(os.fsencode(path)) > MAX_PATH_BYTES:
            raise ForkOpsError("Equipment source root exceeds the path byte limit.")
        roots.append(path)
    return roots


def _equipment_migration_preflight(
    repo: Path,
    candidates: list[dict[str, Any]],
    migration_map: list[dict[str, Any]],
    blockers: list[dict[str, Any]],
    *,
    source_roots: list[Path] | None,
    workflow_inventory: dict[str, Any] | None,
    scan_profile: str = "custom",
) -> dict[str, Any]:
    map_by_path = {entry["source_path"]: entry for entry in migration_map}
    groups = [
        _repo_candidate_equipment_group(repo, candidate, map_by_path[candidate["path"]])
        for candidate in candidates
    ]
    if workflow_inventory:
        groups.extend(_workflow_inventory_equipment_groups(workflow_inventory))
    groups.sort(key=_equipment_group_sort_key)
    evidence_entries = _equipment_evidence_entries(groups)
    discovery_scopes = _equipment_discovery_scopes(
        repo,
        source_roots or [],
        groups,
        workflow_inventory,
    )
    unassessed_areas = _unassessed_equipment_areas(
        source_roots or [],
        workflow_inventory,
        blockers,
        scan_profile,
    )
    accounting_records = _equipment_preflight_accounting_records(
        repo,
        migration_map,
        workflow_inventory,
        unassessed_areas,
    )
    follow_up_candidates = _accounting_follow_up_candidates(accounting_records)
    _validate_accounting_follow_up_coverage(accounting_records, follow_up_candidates)
    return {
        "repo_path": str(repo),
        "operation": "equipment-migration-preflight",
        "mode": "read-only",
        "scan_profile": scan_profile,
        "default_onboarding_intent": "migrate_toward_fork_ops",
        "discovery_scopes": discovery_scopes,
        "unassessed_equipment_areas": unassessed_areas,
        "summary": {
            "discovery_scope_count": len(discovery_scopes),
            "equipment_group_count": len(groups),
            "evidence_entry_count": len(evidence_entries),
            "unassessed_equipment_area_count": len(unassessed_areas),
            "accounting_record_count": len(accounting_records),
            "follow_up_candidate_count": len(follow_up_candidates),
            "default_onboarding_intent": "migrate_toward_fork_ops",
        },
        "equipment_groups": groups,
        "evidence": evidence_entries,
        "accounting_records": accounting_records,
        "follow_up_candidates": follow_up_candidates,
        "operator_prompts": _equipment_operator_prompts(groups, unassessed_areas),
        "limitations": _equipment_preflight_limitations(),
    }


def _equipment_preflight_limitations() -> list[str]:
    return [
        "Installed or checked-in equipment is not treated as current operator intent.",
        "Group-level dispositions guide review but do not activate overlapping behavior.",
        "Unassessed equipment areas limit activation-readiness and replacement claims.",
    ]


def _repo_candidate_equipment_group(
    repo: Path,
    candidate: dict[str, Any],
    migration_entry: dict[str, Any],
) -> dict[str, Any]:
    source_path = candidate["path"]
    evidence_id = _equipment_evidence_id("repo-local", source_path)
    disposition = _equipment_disposition_from_source_disposition(
        migration_entry["disposition"]["type"]
    )
    return {
        "id": _equipment_group_id("repo-local", source_path),
        "identifier": f"repo-local:{source_path}",
        "source_scope": "repo-local",
        "source_root": str(repo),
        "source_path": source_path,
        "source_kind": candidate["kind"],
        "content_sha256": candidate["content_sha256"],
        "equipment_classification": _repo_equipment_classification(candidate, migration_entry),
        "classification_confidence": _equipment_classification_confidence(
            candidate,
            migration_entry,
        ),
        "disposition": disposition,
        "decision_status": _equipment_decision_status(disposition),
        "activation_impact": _equipment_activation_impact(disposition),
        "evidence_ids": [evidence_id],
        "facets": [
            _source_material_equipment_facet(
                _equipment_group_id("repo-local", source_path),
                candidate["domains"],
                candidate["signals"],
                migration_entry["disposition"]["type"],
                disposition,
            )
        ],
        "compatibility_entries": [],
    }


def _workflow_inventory_equipment_groups(inventory: dict[str, Any]) -> list[dict[str, Any]]:
    groups: list[dict[str, Any]] = []
    for entry in inventory.get("entries", []):
        if not isinstance(entry, dict):
            continue
        source_root = str(entry.get("source_root", ""))
        source_path = str(entry.get("source_path", ""))
        if not source_root or not source_path:
            continue
        scope = str(entry.get("source_scope", "operator-source-root"))
        evidence_id = _equipment_evidence_id(scope, f"{source_root}:{source_path}")
        coverage_status = str(entry.get("coverage_status", "unknown"))
        disposition = _equipment_disposition_from_workflow_coverage(coverage_status)
        equipment_id = _equipment_group_id(scope, f"{source_root}:{source_path}")
        facets, compatibility_entries = _workflow_material_equipment_projections(
            equipment_id,
            entry,
            disposition,
        )
        groups.append(
            {
                "id": equipment_id,
                "identifier": f"{scope}:{source_root}:{source_path}",
                "source_scope": scope,
                "source_root": source_root,
                "source_path": source_path,
                "source_kind": str(entry.get("source_kind", "unknown")),
                "content_sha256": str(entry.get("content_sha256", "")),
                "equipment_classification": _workflow_equipment_classification(entry),
                "classification_confidence": "medium",
                "disposition": disposition,
                "decision_status": _equipment_decision_status(disposition),
                "activation_impact": _equipment_activation_impact(disposition),
                "evidence_ids": [evidence_id],
                "facets": facets,
                "compatibility_entries": compatibility_entries,
            }
        )
    return groups


def _source_material_equipment_facet(
    equipment_id: str,
    domains: Iterable[object],
    signals: Iterable[object],
    source_disposition: str,
    equipment_disposition: str,
) -> dict[str, Any]:
    return {
        "id": f"{equipment_id}:facet:source-material",
        "kind": "source-material",
        "domains": list(domains),
        "signals": list(signals),
        "source_material_disposition": source_disposition,
        "equipment_disposition": equipment_disposition,
    }


def _workflow_material_equipment_projections(
    equipment_id: str,
    workflow_entry: dict[str, Any],
    equipment_disposition: str,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    return [
        {
            "id": f"{equipment_id}:facet:workflow-material",
            "kind": "workflow-material",
            "source_entry_id": workflow_entry.get("id"),
            "material_scope": workflow_entry.get("material_scope"),
            "likely_workflow_catalog_target": workflow_entry.get(
                "likely_workflow_catalog_target"
            ),
            "coverage_status": workflow_entry.get("coverage_status"),
            "equipment_disposition": equipment_disposition,
        }
    ], _consumer_compatibility_entries(workflow_entry)


def _equipment_evidence_entries(groups: list[dict[str, Any]]) -> list[dict[str, Any]]:
    evidence: list[dict[str, Any]] = []
    for group in groups:
        evidence_id = group["evidence_ids"][0]
        entry = {
            "id": evidence_id,
            "equipment_id": group["id"],
            "source_scope": group["source_scope"],
            "source_root": group["source_root"],
            "source_path": group["source_path"],
            "source_kind": group["source_kind"],
            "content_sha256": group.get("content_sha256", ""),
            "basis": "equipment migration discovery",
        }
        workflow_facet = next(
            (
                facet
                for facet in group.get("facets", [])
                if isinstance(facet, dict) and facet.get("kind") == "workflow-material"
            ),
            None,
        )
        if workflow_facet is not None:
            entry.update(
                {
                    "workflow_source_entry_id": workflow_facet.get(
                        "source_entry_id", ""
                    ),
                    "workflow_material_scope": workflow_facet.get(
                        "material_scope", ""
                    ),
                    "workflow_coverage_status": workflow_facet.get(
                        "coverage_status", ""
                    ),
                    "workflow_catalog_target": workflow_facet.get(
                        "likely_workflow_catalog_target", ""
                    ),
                }
            )
        evidence.append(entry)
    return evidence


def _equipment_discovery_scopes(
    repo: Path,
    source_roots: list[Path],
    groups: list[dict[str, Any]],
    workflow_inventory: dict[str, Any] | None,
) -> list[dict[str, Any]]:
    repo_root = str(repo)
    repo_groups = _equipment_scope_entries(groups, "repo-local", repo_root)
    scopes = [
        {
            "id": "scope:repo-local",
            "kind": "repo-local",
            "path": repo_root,
            "status": "scanned",
            "equipment_group_count": len(repo_groups),
            "snapshot_sha256": _equipment_scope_snapshot_sha256(
                repo_groups,
                "repo-local",
                repo_root,
            ),
        }
    ]
    inventory_entries: list[object] = (
        workflow_inventory.get("entries", []) if workflow_inventory else []
    )
    source_root_records: list[object] = (
        workflow_inventory.get("source_root_records", []) if workflow_inventory else []
    )
    if source_root_records:
        roots_for_scope = [
            record for record in source_root_records if isinstance(record, dict)
        ]
    else:
        roots_for_scope = [
            {
                "path": str(root),
                "source_scope": "operator-source-root",
                "root_role": "operator-provided",
                "status": (
                    "scanned"
                    if _lexical_path_kind(root) in {"regular", "directory"}
                    else (
                        "unresolvable"
                        if _lexical_path_kind(root) == "missing"
                        else "rejected"
                    )
                ),
            }
            for root in source_roots
        ]
    for record in roots_for_scope:
        root_text = str(record.get("path", ""))
        if not root_text:
            continue
        scope_kind = str(record.get("source_scope", "operator-source-root"))
        scope_groups = _equipment_scope_entries(groups, scope_kind, root_text)
        entry_count = len(
            [
                entry
                for entry in inventory_entries
                if isinstance(entry, dict) and entry.get("source_root") == root_text
            ]
        )
        scopes.append(
            {
                "id": _equipment_scope_id(root_text),
                "kind": scope_kind,
                "root_role": str(record.get("root_role", "operator-provided")),
                "path": root_text,
                "status": str(record.get("status", "scanned")),
                "equipment_group_count": len(scope_groups),
                "snapshot_sha256": _equipment_scope_snapshot_sha256(
                    scope_groups,
                    scope_kind,
                    root_text,
                ),
            }
        )
        if len(scope_groups) != entry_count:
            raise ForkOpsError(
                "Equipment discovery scope does not match workflow inventory entries."
            )
    return scopes


def _equipment_scope_entries(
    entries: list[dict[str, Any]],
    scope_kind: str,
    scope_path: str,
) -> list[dict[str, Any]]:
    return [
        entry
        for entry in entries
        if entry.get("source_scope") == scope_kind
        and entry.get("source_root") == scope_path
        and entry.get("source_path") != EQUIPMENT_REVIEW_RECORD_RELATIVE_PATH
        and entry.get("decision_status") != "superseded"
    ]


def _equipment_scope_snapshot_sha256(
    entries: list[dict[str, Any]],
    scope_kind: str,
    scope_path: str,
) -> str:
    snapshot = [
        {
            "source_scope": entry.get("source_scope"),
            "source_root": entry.get("source_root"),
            "source_path": entry.get("source_path"),
            "source_kind": entry.get("source_kind"),
            "content_sha256": entry.get("content_sha256"),
        }
        for entry in _equipment_scope_entries(entries, scope_kind, scope_path)
    ]
    snapshot.sort(key=_equipment_scope_snapshot_sort_key)
    encoded = json.dumps(snapshot, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(encoded.encode()).hexdigest()


def _equipment_scope_snapshot_sort_key(
    item: dict[str, Any],
) -> tuple[str, str, str]:
    return (
        str(item["source_path"]),
        str(item["source_kind"]),
        str(item["content_sha256"]),
    )


def _unassessed_equipment_areas(
    source_roots: list[Path],
    workflow_inventory: dict[str, Any] | None,
    blockers: list[dict[str, Any]],
    scan_profile: str,
) -> list[dict[str, Any]]:
    areas: list[dict[str, Any]] = []
    if not source_roots and scan_profile != "full-breadth":
        areas.append(
            {
                "id": "unassessed:user-global-equipment",
                "scope": "user-global",
                "reason": "No operator-provided global or user equipment source root was scanned.",
                "activation_impact": (
                    "Do not claim replacement coverage for global or user equipment."
                ),
            }
        )
    if workflow_inventory:
        unresolved_records = [
            record
            for record in workflow_inventory.get("source_root_records", [])
            if isinstance(record, dict) and record.get("status") != "scanned"
        ]
        for record in unresolved_records:
            root = str(record.get("path", ""))
            status = str(record.get("status", "unresolvable"))
            areas.append(
                {
                    "id": f"unassessed:{_short_digest(root)}",
                    "scope": str(record.get("source_scope", "operator-source-root")),
                    "source_root": root,
                    "path": root,
                    "reason": (
                        "The operator-provided source root could not be resolved."
                        if status == "unresolvable"
                        else "The operator-provided source root was rejected."
                    ),
                    "activation_impact": "Treat this source root as not reviewed.",
                }
            )
    for blocker in blockers:
        if blocker.get("code") != "semantic_coverage.incomplete":
            continue
        for path in _string_list(blocker.get("paths")):
            areas.append(
                {
                    "id": f"unassessed:semantic-coverage:{_short_digest(path)}",
                    "scope": "repo-local",
                    "path": path,
                    "reason": "Deterministic extraction did not prove semantic coverage.",
                    "activation_impact": (
                        "Keep replacement and source-material removal unavailable."
                    ),
                }
            )
    return areas


def _equipment_operator_prompts(
    groups: list[dict[str, Any]],
    unassessed_areas: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    prompts: list[dict[str, Any]] = [
        {
            "id": "onboarding-intent",
            "status": "recommended-default",
            "recommended": "migrate_toward_fork_ops",
            "message": (
                "Confirm overall onboarding intent before resolving per-equipment "
                "dispositions."
            ),
        }
    ]
    if any(group["decision_status"] == "pending_operator_decision" for group in groups):
        prompts.append(
            {
                "id": "equipment-dispositions",
                "status": "required",
                "message": "Review pending equipment dispositions item by item.",
            }
        )
    if unassessed_areas:
        prompts.append(
            {
                "id": "unassessed-equipment-areas",
                "status": "required-before-replacement-coverage",
                "message": "Scan, accept risk for, or keep limits for unassessed areas.",
            }
        )
    return prompts


def _equipment_review_record(preflight: dict[str, Any]) -> dict[str, Any]:
    entries = [
        _equipment_review_record_entry(group) for group in preflight["equipment_groups"]
    ]
    record = {
        "status": "proposed",
        "target_path": EQUIPMENT_REVIEW_RECORD_RELATIVE_PATH,
        "content_kind": "equipment-review-record",
        "default_onboarding_intent": preflight["default_onboarding_intent"],
        "equipment_disposition_types": list(EQUIPMENT_DISPOSITION_TYPES),
        "equipment_decision_status_types": list(EQUIPMENT_DECISION_STATUS_TYPES),
        "accounting_status_types": list(ACCOUNTING_STATUS_TYPES),
        "review_freshness_policy": (
            "revalidate when source hashes, discovery scopes, or activation gates change"
        ),
        "discovery_scopes": copy.deepcopy(preflight["discovery_scopes"]),
        "unassessed_equipment_areas": copy.deepcopy(preflight["unassessed_equipment_areas"]),
        "evidence": copy.deepcopy(preflight["evidence"]),
        "accounting_records": copy.deepcopy(preflight["accounting_records"]),
        "follow_up_candidates": copy.deepcopy(preflight["follow_up_candidates"]),
        "equipment": entries,
    }
    canonical = _canonical_nested_artifact(ArtifactKind.EQUIPMENT_REVIEW, record)
    canonical["toml"] = _equipment_review_record_toml(canonical)
    return canonical


def _equipment_review_record_entry(group: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": f"{group['id']}:decision",
        "equipment_id": group["id"],
        "identifier": group["identifier"],
        "source_scope": group["source_scope"],
        "source_root": group["source_root"],
        "source_path": group["source_path"],
        "source_kind": group["source_kind"],
        "content_sha256": group.get("content_sha256", ""),
        "equipment_classification": group["equipment_classification"],
        "classification_confidence": group["classification_confidence"],
        "disposition": group["disposition"],
        "decision_status": group["decision_status"],
        "activation_impact": group["activation_impact"],
        "evidence_ids": list(group["evidence_ids"]),
        "reason_recommended": _equipment_disposition_reason(group),
    }


def _equipment_review_record_toml(record: dict[str, Any]) -> str:
    return _toml_dumps(_equipment_review_toml_payload(record))


def _equipment_review_toml_payload(record: dict[str, Any]) -> dict[str, Any]:
    fields = (
        "artifact_kind",
        "schema_version",
        "status",
        "default_onboarding_intent",
        "review_freshness_policy",
        "equipment_disposition_types",
        "equipment_decision_status_types",
        "accounting_status_types",
        "discovery_scopes",
        "unassessed_equipment_areas",
        "evidence",
        "accounting_records",
        "follow_up_candidates",
        "equipment",
    )
    return {field: copy.deepcopy(record[field]) for field in fields}


def _equipment_review_record_report(repo: Path) -> dict[str, Any]:
    try:
        raw = _read_file_within_root(repo, EQUIPMENT_REVIEW_RECORD_RELATIVE_PATH)
    except _BoundedReadError as exc:
        if exc.__cause__ and isinstance(exc.__cause__, FileNotFoundError):
            return {
                "path": EQUIPMENT_REVIEW_RECORD_RELATIVE_PATH,
                "exists": False,
                "valid": False,
                **_equipment_review_states(
                    activation=ActivationReadinessValue.UNASSESSED,
                    replacement=ReplacementCoverageValue.UNASSESSED,
                    continuity=OperationalContinuityValue.UNASSESSED,
                ),
                "retained_authority_paths": [],
                "pending_decision_count": 0,
                "unassessed_equipment_area_count": 0,
                "accounting_record_count": 0,
                "follow_up_candidate_count": 0,
                "accounting_claims_verified": False,
                "accounting_status_counts": _empty_accounting_status_counts(),
            }
        return _invalid_equipment_review_report(exc.code)
    try:
        parsed = tomllib.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, tomllib.TOMLDecodeError) as exc:
        return _invalid_equipment_review_report(str(exc))
    if parsed.get("artifact_kind") != _EQUIPMENT_REVIEW_CONTRACT.emitted_artifact_kind:
        return _invalid_equipment_review_report(
            "unsupported_artifact_version",
            compatibility="unsupported",
            observed_artifact_kind=parsed.get("artifact_kind"),
            observed_schema_version=parsed.get("schema_version"),
        )
    if parsed.get("schema_version") != _EQUIPMENT_REVIEW_VERSION:
        return _invalid_equipment_review_report(
            "unsupported_artifact_version",
            compatibility="unsupported",
            observed_artifact_kind=parsed.get("artifact_kind"),
            observed_schema_version=parsed.get("schema_version"),
        )
    malformed_section = None
    for section in (
        "discovery_scopes",
        "evidence",
        "equipment",
        "unassessed_equipment_areas",
        "accounting_records",
        "follow_up_candidates",
    ):
        malformed_section = _malformed_record_section(parsed, section)
        if malformed_section is not None:
            break
    if malformed_section is not None:
        return _invalid_equipment_review_report(
            f"{malformed_section} must be a TOML array of tables"
        )
    semantic_error = _equipment_review_semantic_error(parsed)
    if semantic_error is not None:
        return _invalid_equipment_review_report(semantic_error)
    repository_error = _equipment_review_repository_error(repo, parsed)
    if repository_error is not None:
        return _invalid_equipment_review_report(repository_error)
    equipment_entries = _record_table_list(parsed.get("equipment"))
    unassessed_areas = _record_table_list(parsed.get("unassessed_equipment_areas"))
    accounting_records = _record_table_list(parsed.get("accounting_records"))
    follow_up_candidates = _record_table_list(parsed.get("follow_up_candidates"))
    reviewed_retained: list[str] = (
        [
            entry["source_path"]
            for entry in equipment_entries
            if entry.get("decision_status") == "reviewed"
            and entry.get("disposition") == "retain_authoritative_owner"
            and isinstance(entry.get("source_path"), str)
        ]
        if parsed.get("status") == "reviewed"
        else []
    )
    pending_count = len(
        [
            entry
            for entry in equipment_entries
            if entry.get("decision_status") not in {"reviewed", "superseded"}
        ]
    )
    activation = (
        ActivationReadinessValue.BLOCKED
        if pending_count
        else ActivationReadinessValue.UNASSESSED
        if parsed.get("status") != "reviewed"
        else ActivationReadinessValue.UNASSESSED
        if unassessed_areas
        else ActivationReadinessValue.READY
    )
    replacement = (
        ReplacementCoverageValue.BLOCKED
        if pending_count
        else ReplacementCoverageValue.UNASSESSED
    )
    continuity = (
        OperationalContinuityValue.CONTINUOUS
        if reviewed_retained
        else OperationalContinuityValue.UNASSESSED
    )
    accounting_claims_verified = parsed.get("status") == "reviewed"
    return {
        "path": EQUIPMENT_REVIEW_RECORD_RELATIVE_PATH,
        "exists": True,
        "valid": True,
        "validation_status": (
            "reviewed"
            if parsed.get("status") == "reviewed"
            else "semantically_validated"
        ),
        "compatibility": "current",
        "artifact_kind": parsed.get("artifact_kind"),
        "schema_version": parsed.get("schema_version"),
        **_equipment_review_states(
            activation=activation,
            replacement=replacement,
            continuity=continuity,
        ),
        "equipment_count": len(equipment_entries),
        "reviewed_equipment_count": len(
            [entry for entry in equipment_entries if entry.get("decision_status") == "reviewed"]
        ),
        "pending_decision_count": pending_count,
        "unassessed_equipment_area_count": len(unassessed_areas),
        "accounting_record_count": len(accounting_records),
        "follow_up_candidate_count": len(follow_up_candidates),
        "accounting_claims_verified": accounting_claims_verified,
        "accounting_status_counts": (
            _accounting_status_counts(accounting_records)
            if accounting_claims_verified
            else _empty_accounting_status_counts()
        ),
        "retained_authority_paths": reviewed_retained,
    }


def _equipment_review_states(
    *,
    activation: ActivationReadinessValue,
    replacement: ReplacementCoverageValue,
    continuity: OperationalContinuityValue,
) -> dict[str, Any]:
    common = {
        "subject": "artifact:equipment_review",
        "evidence_ids": ("equipment.review",),
    }
    return {
        "activation_readiness": State(
            dimension=StateDimension.ACTIVATION_READINESS,
            value=activation,
            derivation_rule="activation.equipment_review_validity_and_pending_decisions",
            **common,
        ).to_dict(),
        "replacement_coverage": State(
            dimension=StateDimension.REPLACEMENT_COVERAGE,
            value=replacement,
            derivation_rule="coverage.requires_active_fork_ops_behavior_evidence",
            **common,
        ).to_dict(),
        "operational_continuity": State(
            dimension=StateDimension.OPERATIONAL_CONTINUITY,
            value=continuity,
            derivation_rule="continuity.reviewed_retained_authority",
            **common,
        ).to_dict(),
    }


def _invalid_equipment_review_report(
    error: str,
    *,
    compatibility: str = "invalid",
    observed_artifact_kind: object = None,
    observed_schema_version: object = None,
) -> dict[str, Any]:
    report = {
        "path": EQUIPMENT_REVIEW_RECORD_RELATIVE_PATH,
        "exists": True,
        "valid": False,
        "validation_status": (
            "unsupported" if compatibility == "unsupported" else "shallow"
        ),
        "compatibility": compatibility,
        "error": error,
        "retained_authority_paths": [],
        "pending_decision_count": 0,
        "unassessed_equipment_area_count": 0,
        "accounting_record_count": 0,
        "follow_up_candidate_count": 0,
        "accounting_claims_verified": False,
        "accounting_status_counts": _empty_accounting_status_counts(),
    }
    if compatibility == "unsupported":
        report["diagnostics"] = [
            {
                "severity": "error",
                "code": "unsupported_artifact_version",
                "message": "Equipment review uses an unsupported identity or version.",
                "path": EQUIPMENT_REVIEW_RECORD_RELATIVE_PATH,
                "detail": {
                    "observed_artifact_kind": observed_artifact_kind,
                    "observed_schema_version": observed_schema_version,
                    "supported_artifact_kind": (
                        _EQUIPMENT_REVIEW_CONTRACT.emitted_artifact_kind
                    ),
                    "supported_schema_versions": [_EQUIPMENT_REVIEW_VERSION],
                    "regeneration": (
                        "Regenerate the equipment review with "
                        "`fork-ops migration preflight`."
                    ),
                },
            }
        ]
    return report


def _equipment_review_semantic_error(
    record: dict[str, Any],
    *,
    require_toml: bool = False,
    trusted_workflow_inventory: dict[str, Any] | None = None,
    require_trusted_workflow_inventory: bool = False,
) -> str | None:
    if record.get("status") not in {"proposed", "reviewed"}:
        return "status must be proposed or reviewed"
    if record.get("default_onboarding_intent") != "migrate_toward_fork_ops":
        return "default_onboarding_intent must be migrate_toward_fork_ops"
    review_freshness = record.get("review_freshness_policy")
    if not isinstance(review_freshness, str) or not review_freshness:
        return "review_freshness_policy must be a non-empty string"
    for section in (
        "discovery_scopes",
        "evidence",
        "equipment",
        "unassessed_equipment_areas",
        "accounting_records",
        "follow_up_candidates",
    ):
        malformed_section = _malformed_record_section(record, section)
        if malformed_section is not None:
            return f"{malformed_section} must be a TOML array of tables"
    discovery_scopes = _record_table_list(record.get("discovery_scopes"))
    if not discovery_scopes:
        return "discovery_scopes must contain at least one assessed scope"
    discovery_scope_ids: list[str] = []
    for scope in discovery_scopes:
        scope_id = scope.get("id")
        if not isinstance(scope_id, str) or not scope_id:
            return "discovery scope id must be a non-empty string"
        discovery_scope_ids.append(scope_id)
        for field_name in ("kind", "path", "status"):
            value = scope.get(field_name)
            if not isinstance(value, str) or not value:
                return f"discovery scope {field_name} must be a non-empty string"
        if scope["kind"] not in EQUIPMENT_DISCOVERY_SCOPE_KINDS:
            return "discovery scope kind must use a current contract value"
        if scope["status"] not in EQUIPMENT_DISCOVERY_SCOPE_STATUSES:
            return "discovery scope status must use a current contract value"
        if scope["kind"] != "repo-local":
            root_role = scope.get("root_role")
            if not isinstance(root_role, str) or not root_role:
                return "external discovery scope root_role must be a non-empty string"
        equipment_group_count = scope.get("equipment_group_count")
        if (
            not isinstance(equipment_group_count, int)
            or isinstance(equipment_group_count, bool)
            or equipment_group_count < 0
        ):
            return (
                "discovery scope equipment_group_count must be a non-negative integer"
            )
        snapshot_sha256 = scope.get("snapshot_sha256")
        if (
            not isinstance(snapshot_sha256, str)
            or re.fullmatch(r"[0-9a-f]{64}", snapshot_sha256) is None
        ):
            return "discovery scope snapshot_sha256 must be a lowercase SHA-256 digest"
    if len(discovery_scope_ids) != len(set(discovery_scope_ids)):
        return "discovery scope ids must be unique"
    if record.get("status") == "reviewed" and any(
        scope.get("kind") != "repo-local" for scope in discovery_scopes
    ):
        return "reviewed external discovery scopes cannot be independently verified"
    vocabularies = (
        ("equipment_disposition_types", EQUIPMENT_DISPOSITION_TYPES),
        ("equipment_decision_status_types", EQUIPMENT_DECISION_STATUS_TYPES),
        ("accounting_status_types", ACCOUNTING_STATUS_TYPES),
    )
    for field_name, expected in vocabularies:
        value = record.get(field_name)
        if value != list(expected):
            return f"{field_name} must match the current contract"

    toml_projection = record.get("toml")
    if require_toml and toml_projection is None:
        return "toml must be present for migration plan replay"
    if toml_projection is not None:
        if not isinstance(toml_projection, str) or not toml_projection:
            return "toml must be a non-empty canonical projection"
        try:
            parsed_projection = tomllib.loads(toml_projection)
            expected_projection = _equipment_review_toml_payload(record)
        except (KeyError, tomllib.TOMLDecodeError):
            return "toml must be a valid canonical projection"
        if parsed_projection != expected_projection:
            return "toml must match the structured equipment review"

    evidence = _record_table_list(record.get("evidence"))
    evidence_ids = [item.get("id") for item in evidence]
    if any(not isinstance(item, str) or not item for item in evidence_ids):
        return "evidence ids must be non-empty strings"
    if len(evidence_ids) != len(set(evidence_ids)):
        return "evidence ids must be unique"
    evidence_by_id = {
        str(item["id"]): item for item in evidence if isinstance(item.get("id"), str)
    }
    trusted_workflow_entries_by_id = {
        str(item["id"]): item
        for item in (
            trusted_workflow_inventory.get("entries", [])
            if isinstance(trusted_workflow_inventory, dict)
            else []
        )
        if isinstance(item, dict) and isinstance(item.get("id"), str)
    }
    for item in evidence:
        if item.get("source_path") == EQUIPMENT_REVIEW_RECORD_RELATIVE_PATH:
            return "equipment evidence cannot use the equipment review record as a source"
        for field_name in (
            "equipment_id",
            "source_scope",
            "source_root",
            "source_path",
            "source_kind",
        ):
            value = item.get(field_name)
            if not isinstance(value, str) or not value:
                return f"evidence {field_name} must be a non-empty string"
        content_sha256 = item.get("content_sha256")
        if (
            not isinstance(content_sha256, str)
            or re.fullmatch(r"[0-9a-f]{64}", content_sha256) is None
        ):
            return "evidence content_sha256 must be a lowercase SHA-256 digest"
        workflow_projection_fields = (
            "workflow_source_entry_id",
            "workflow_material_scope",
            "workflow_coverage_status",
            "workflow_catalog_target",
        )
        present_projection_fields = [
            field_name
            for field_name in workflow_projection_fields
            if field_name in item
        ]
        if present_projection_fields and len(present_projection_fields) != len(
            workflow_projection_fields
        ):
            return "workflow evidence must use the complete canonical projection"
        if any(
            not isinstance(item.get(field_name), str) or not item[field_name]
            for field_name in present_projection_fields
        ):
            return "workflow evidence projection fields must be non-empty strings"
        if present_projection_fields and item.get("source_scope") == "repo-local":
            return (
                "repo-local migration evidence cannot self-certify a workflow "
                "inventory projection"
            )
    if trusted_workflow_inventory is not None:
        trusted_inventory_error = _trusted_workflow_inventory_error(
            record,
            trusted_workflow_inventory,
        )
        if trusted_inventory_error is not None:
            return trusted_inventory_error

    equipment = _record_table_list(record.get("equipment"))
    equipment_ids = [item.get("id") for item in equipment]
    if any(not isinstance(item, str) or not item for item in equipment_ids):
        return "equipment ids must be non-empty strings"
    if len(equipment_ids) != len(set(equipment_ids)):
        return "equipment ids must be unique"
    for entry in equipment:
        if entry.get("source_path") == EQUIPMENT_REVIEW_RECORD_RELATIVE_PATH:
            return "equipment decisions cannot review the equipment review record itself"
        for field_name in (
            "equipment_id",
            "source_scope",
            "source_root",
            "source_path",
            "source_kind",
        ):
            if not isinstance(entry.get(field_name), str) or not entry[field_name]:
                return f"equipment {field_name} must be a non-empty string"
        if entry.get("disposition") not in EQUIPMENT_DISPOSITION_TYPES:
            return "equipment disposition must use a current contract value"
        if entry.get("decision_status") not in EQUIPMENT_DECISION_STATUS_TYPES:
            return "equipment decision_status must use a current contract value"
        content_sha256 = entry.get("content_sha256")
        if content_sha256 not in (None, "") and (
            not isinstance(content_sha256, str)
            or re.fullmatch(r"[0-9a-f]{64}", content_sha256) is None
        ):
            return "equipment content_sha256 must be a lowercase SHA-256 digest"
        referenced = entry.get("evidence_ids")
        if (
            not isinstance(referenced, list)
            or not referenced
            or any(not isinstance(item, str) or not item for item in referenced)
        ):
            return "equipment evidence_ids must be a non-empty string list"
        if len(referenced) != len(set(referenced)):
            return "equipment evidence_ids must be unique"
        if any(item not in evidence_by_id for item in referenced):
            return "equipment evidence_ids must reference attached evidence"
        if any(
            evidence_by_id[item].get("equipment_id") != entry["equipment_id"]
            for item in referenced
        ):
            return "equipment evidence must reference the same equipment_id"
        evidence_fields = (
            "source_scope",
            "source_root",
            "source_path",
            "source_kind",
            "content_sha256",
        )
        if any(
            any(
                evidence_by_id[item].get(field) != entry.get(field)
                for field in evidence_fields
            )
            for item in referenced
        ):
            return "equipment evidence must match the reviewed source identity"

    equipment_by_id = {str(item["id"]): item for item in equipment}
    all_equipment_ids: set[str] = set()
    current_equipment_ids: set[str] = set()
    current_equipment_by_id: dict[str, dict[str, Any]] = {}
    current_source_paths: set[tuple[str, str, str]] = set()
    for entry in equipment:
        entry_id = str(entry["id"])
        equipment_id = str(entry["equipment_id"])
        all_equipment_ids.add(equipment_id)
        supersedes_id = entry.get("supersedes")
        if supersedes_id is not None:
            if not isinstance(supersedes_id, str) or not supersedes_id:
                return "equipment supersedes must be a non-empty string"
            predecessor = equipment_by_id.get(supersedes_id)
            if (
                predecessor is None
                or predecessor.get("decision_status") != "superseded"
                or predecessor.get("superseded_by") != entry_id
            ):
                return (
                    "equipment supersedes links must reference a reciprocal "
                    "superseded decision"
                )
            if predecessor.get("equipment_id") != equipment_id:
                return "equipment supersedes links must preserve equipment_id"
        if entry.get("decision_status") == "superseded":
            successor_id = entry.get("superseded_by")
            if not isinstance(successor_id, str) or not successor_id:
                return "superseded equipment must identify superseded_by"
            successor = equipment_by_id.get(successor_id)
            if successor is None or successor.get("supersedes") != entry_id:
                return "superseded equipment links must be reciprocal"
            if successor.get("equipment_id") != equipment_id:
                return "superseded equipment links must preserve equipment_id"
            continue
        if entry.get("superseded_by") is not None:
            return "current equipment decisions cannot identify superseded_by"
        if equipment_id in current_equipment_ids:
            return "equipment must have exactly one current decision per equipment_id"
        current_equipment_ids.add(equipment_id)
        current_equipment_by_id[equipment_id] = entry
        source_key = (
            str(entry["source_scope"]),
            str(entry["source_root"]),
            str(entry["source_path"]),
        )
        if source_key in current_source_paths:
            return "equipment must have exactly one current decision per source"
        current_source_paths.add(source_key)
    if current_equipment_ids != all_equipment_ids:
        return "equipment history must have exactly one current decision per equipment_id"
    for entry in equipment:
        if entry.get("decision_status") != "superseded":
            continue
        equipment_id = str(entry["equipment_id"])
        expected_current_id = str(current_equipment_by_id[equipment_id]["id"])
        cursor = entry
        visited: set[str] = set()
        while cursor.get("decision_status") == "superseded":
            cursor_id = str(cursor["id"])
            if cursor_id in visited:
                return "equipment supersession history must not contain a cycle"
            visited.add(cursor_id)
            successor_id = cursor.get("superseded_by")
            if not isinstance(successor_id, str):
                return "superseded equipment must identify superseded_by"
            successor = equipment_by_id.get(successor_id)
            if successor is None:
                return "equipment supersession history must reach its current decision"
            cursor = successor
        if cursor.get("id") != expected_current_id:
            return "equipment supersession history must reach its current decision"

    unassessed_areas = _record_table_list(record.get("unassessed_equipment_areas"))
    area_ids: list[str] = []
    for area in unassessed_areas:
        area_id = area.get("id")
        if not isinstance(area_id, str) or not area_id:
            return "unassessed equipment area id must be a non-empty string"
        area_ids.append(area_id)
        if not isinstance(area.get("scope"), str) or not area["scope"]:
            return "unassessed equipment area scope must be a non-empty string"
        if not isinstance(area.get("reason"), str) or not area["reason"]:
            return "unassessed equipment area reason must be a non-empty string"
    if len(area_ids) != len(set(area_ids)):
        return "unassessed equipment area ids must be unique"
    if all(scope.get("kind") == "repo-local" for scope in discovery_scopes) and not any(
        area.get("scope") == "user-global" for area in unassessed_areas
    ):
        return "repo-only discovery must retain the user-global unassessed area"
    for scope in discovery_scopes:
        scope_kind = str(scope["kind"])
        scope_path = str(scope["path"])
        scoped_equipment = _equipment_scope_entries(
            equipment,
            scope_kind,
            scope_path,
        )
        if scope["equipment_group_count"] != len(scoped_equipment):
            return "discovery scope equipment_group_count must match equipment entries"
        expected_snapshot = _equipment_scope_snapshot_sha256(
            scoped_equipment,
            scope_kind,
            scope_path,
        )
        if scope["snapshot_sha256"] != expected_snapshot:
            return "discovery scope snapshot_sha256 must match equipment entries"
        if scope["status"] != "scanned" and not any(
            area.get("path") == scope_path or area.get("source_root") == scope_path
            for area in unassessed_areas
        ):
            return "unassessed discovery scopes must have a matching unassessed area"
    scope_keys = {
        (str(scope["kind"]), str(scope["path"])) for scope in discovery_scopes
    }
    if len(scope_keys) != len(discovery_scopes):
        return "discovery scope kind/path pairs must be unique"
    for entry in equipment:
        if (
            entry.get("source_path") != EQUIPMENT_REVIEW_RECORD_RELATIVE_PATH
            and (str(entry.get("source_scope")), str(entry.get("source_root")))
            not in scope_keys
        ):
            return "equipment entries must belong to one discovery scope"
        if (
            entry.get("decision_status") == "reviewed"
            and entry.get("disposition") == "decide_item_by_item"
        ):
            return "decide_item_by_item equipment cannot be marked reviewed"

    accounting_records = _record_table_list(record.get("accounting_records"))
    accounting_ids = [item.get("id") for item in accounting_records]
    if any(not isinstance(item, str) or not item for item in accounting_ids):
        return "accounting record ids must be non-empty strings"
    if len(accounting_ids) != len(set(accounting_ids)):
        return "accounting record ids must be unique"
    expected_area_records = [
        _accounting_record_from_unassessed_area(area)
        for area in unassessed_areas
        if not area.get("path")
    ]
    actual_area_records = [
        entry
        for entry in accounting_records
        if entry.get("source_kind") == "unassessed-area"
    ]
    if sorted(actual_area_records, key=_accounting_record_sort_key) != sorted(
        expected_area_records,
        key=_accounting_record_sort_key,
    ):
        return "unassessed equipment areas must have exact accounting records"
    for area in unassessed_areas:
        area_path = area.get("path")
        if not area_path:
            continue
        matching_records = [
            entry
            for entry in accounting_records
            if entry.get("source_scope") == area.get("scope")
            and entry.get("accounting_status") == "unassessed"
            and (
                entry.get("source_path") == area_path
                or (
                    entry.get("source_kind") == "source-root"
                    and entry.get("source_root") == area_path
                )
            )
        ]
        if len(matching_records) != 1:
            return "unassessed equipment areas must match one exact accounting source"
    current_equipment = list(current_equipment_by_id.values())
    for entry in accounting_records:
        accounting_error = _equipment_accounting_record_error(
            entry,
            current_equipment,
            discovery_scopes,
            unassessed_areas,
            evidence_by_id,
            trusted_workflow_entries_by_id,
            require_trusted_workflow_inventory=require_trusted_workflow_inventory,
        )
        if accounting_error is not None:
            return accounting_error

    follow_ups = _record_table_list(record.get("follow_up_candidates"))
    follow_up_ids = [item.get("id") for item in follow_ups]
    if any(not isinstance(item, str) or not item for item in follow_up_ids):
        return "follow-up ids must be non-empty strings"
    if len(follow_up_ids) != len(set(follow_up_ids)):
        return "follow-up ids must be unique"
    expected_follow_ups = _accounting_follow_up_candidates(accounting_records)
    if follow_ups != expected_follow_ups:
        return "follow-up candidates must match canonical accounting follow-up records"
    return None


def _trusted_workflow_inventory_error(
    record: dict[str, Any],
    trusted_workflow_inventory: dict[str, Any],
) -> str | None:
    trusted_entries = _record_table_list(trusted_workflow_inventory.get("entries"))
    expected_projections = {
        str(entry["id"]): _workflow_inventory_evidence_projection(entry)
        for entry in trusted_entries
        if isinstance(entry.get("id"), str) and entry["id"]
    }
    observed_projection_entries = [
        item
        for item in _record_table_list(record.get("evidence"))
        if "workflow_source_entry_id" in item
    ]
    observed_projections = {
        str(item["workflow_source_entry_id"]): {
            field_name: item.get(field_name)
            for field_name in _WORKFLOW_EVIDENCE_PROJECTION_FIELDS
        }
        for item in observed_projection_entries
        if isinstance(item.get("workflow_source_entry_id"), str)
        and item["workflow_source_entry_id"]
    }
    if (
        len(observed_projections) != len(observed_projection_entries)
        or observed_projections != expected_projections
    ):
        return "workflow accounting discovery evidence no longer matches source bytes"

    observed_accounting_entry_ids = [
        str(item["source_entry_id"])
        for item in _record_table_list(record.get("accounting_records"))
        if item.get("source_scope") != "repo-local"
        and isinstance(item.get("source_entry_id"), str)
        and item["source_entry_id"]
    ]
    if (
        len(observed_accounting_entry_ids) != len(set(observed_accounting_entry_ids))
        or set(observed_accounting_entry_ids) != set(expected_projections)
    ):
        return "workflow accounting must exactly cover current inventory entries"

    trusted_groups = _workflow_inventory_equipment_groups(trusted_workflow_inventory)
    expected_scopes: list[dict[str, Any]] = []
    for root_record in _record_table_list(
        trusted_workflow_inventory.get("source_root_records")
    ):
        root_text = str(root_record.get("path", ""))
        scope_kind = str(root_record.get("source_scope", "operator-source-root"))
        if not root_text:
            continue
        scope_groups = _equipment_scope_entries(
            trusted_groups,
            scope_kind,
            root_text,
        )
        expected_scopes.append(
            {
                "id": _equipment_scope_id(root_text),
                "kind": scope_kind,
                "root_role": str(root_record.get("root_role", "operator-provided")),
                "path": root_text,
                "status": str(root_record.get("status", "scanned")),
                "equipment_group_count": len(scope_groups),
                "snapshot_sha256": _equipment_scope_snapshot_sha256(
                    scope_groups,
                    scope_kind,
                    root_text,
                ),
            }
        )
    observed_scopes = [
        scope
        for scope in _record_table_list(record.get("discovery_scopes"))
        if scope.get("kind") != "repo-local"
    ]
    if sorted(observed_scopes, key=_external_equipment_scope_sort_key) != sorted(
        expected_scopes,
        key=_external_equipment_scope_sort_key,
    ):
        return "external discovery scopes do not exactly match current inventory"
    return None


_WORKFLOW_EVIDENCE_PROJECTION_FIELDS = (
    "source_scope",
    "source_root",
    "source_path",
    "source_kind",
    "content_sha256",
    "workflow_source_entry_id",
    "workflow_material_scope",
    "workflow_coverage_status",
    "workflow_catalog_target",
)


def _workflow_inventory_evidence_projection(
    entry: dict[str, Any],
) -> dict[str, Any]:
    return {
        "source_scope": entry.get("source_scope"),
        "source_root": entry.get("source_root"),
        "source_path": entry.get("source_path"),
        "source_kind": entry.get("source_kind"),
        "content_sha256": entry.get("content_sha256"),
        "workflow_source_entry_id": entry.get("id"),
        "workflow_material_scope": entry.get("material_scope"),
        "workflow_coverage_status": entry.get("coverage_status"),
        "workflow_catalog_target": entry.get("likely_workflow_catalog_target"),
    }


def _external_equipment_scope_sort_key(
    scope: dict[str, Any],
) -> tuple[str, str, str]:
    return (
        str(scope.get("kind", "")),
        str(scope.get("path", "")),
        str(scope.get("id", "")),
    )


def _equipment_review_repository_error(repo: Path, record: dict[str, Any]) -> str | None:
    if record.get("status") != "reviewed":
        return None
    scopes = _record_table_list(record.get("discovery_scopes"))
    if any(scope.get("kind") != "repo-local" for scope in scopes):
        return "reviewed external discovery scopes cannot be verified from this repository"
    if any(scope.get("status") != "scanned" for scope in scopes):
        return "reviewed discovery scopes must be completely scanned"
    scope_error, current_entries = _equipment_review_repo_scope_state(repo, record)
    if scope_error is not None:
        return scope_error
    current_by_path = {
        str(entry["source_path"]): entry for entry in current_entries
    }
    for entry in _record_table_list(record.get("equipment")):
        if (
            entry.get("decision_status") != "reviewed"
            or entry.get("source_scope") != "repo-local"
        ):
            continue
        source_path = entry.get("source_path")
        content_sha256 = entry.get("content_sha256")
        if not isinstance(source_path, str) or not source_path:
            return (
                "reviewed repo-local equipment source_path must be a non-empty string"
            )
        if (
            not isinstance(content_sha256, str)
            or re.fullmatch(r"[0-9a-f]{64}", content_sha256) is None
        ):
            return (
                "reviewed repo-local equipment content_sha256 must be a SHA-256 digest"
            )
        current_entry = current_by_path.get(source_path)
        if current_entry is None:
            return "reviewed repo-local equipment source is unavailable"
        if current_entry["content_sha256"] != content_sha256:
            return (
                "reviewed repo-local equipment content_sha256 does not match source bytes"
            )
    return None


def _equipment_review_repo_scope_state(
    repo: Path,
    record: dict[str, Any],
    *,
    bound_repo: _BoundRepository | None = None,
) -> tuple[str | None, list[dict[str, Any]]]:
    repo_scopes = [
        scope
        for scope in _record_table_list(record.get("discovery_scopes"))
        if scope.get("kind") == "repo-local"
    ]
    if len(repo_scopes) != 1:
        return "equipment review must contain exactly one repo-local discovery scope", []
    scope = repo_scopes[0]
    if scope.get("status") != "scanned":
        return "repo-local discovery scope must be completely scanned", []
    if scope.get("path") != str(repo):
        return "repo-local discovery scope must match the selected repository", []

    budget = _OperationBudget()
    current_candidates = [
        candidate
        for candidate in _migration_candidates(repo, budget, bound_repo=bound_repo)
        if candidate.get("path") != EQUIPMENT_REVIEW_RECORD_RELATIVE_PATH
    ]
    if budget.incomplete_reasons:
        return "repo-local discovery scope could not be completely revalidated", []
    current_entries = [
        {
            "source_scope": "repo-local",
            "source_root": str(repo),
            "source_path": candidate["path"],
            "source_kind": candidate["kind"],
            "content_sha256": candidate["content_sha256"],
        }
        for candidate in current_candidates
    ]
    if scope.get("equipment_group_count") != len(current_entries):
        return "repo-local discovery scope equipment count is stale", current_entries
    current_snapshot = _equipment_scope_snapshot_sha256(
        current_entries,
        "repo-local",
        str(repo),
    )
    if scope.get("snapshot_sha256") != current_snapshot:
        return "repo-local discovery scope snapshot is stale", current_entries
    return None, current_entries


def _record_table_list(value: Any) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        return []
    return [item for item in value if isinstance(item, dict)]


def _malformed_record_section(record: dict[str, Any], key: str) -> str | None:
    value = record.get(key, [])
    if value in (None, []):
        return None
    if not isinstance(value, list):
        return key
    if any(not isinstance(item, dict) for item in value):
        return key
    return None


_EQUIPMENT_ACCOUNTING_RECORD_FIELDS = frozenset(
    {
        "id",
        "source_entry_id",
        "source_scope",
        "source_root",
        "source_path",
        "source_kind",
        "material_scope",
        "accounting_status",
        "coverage_status",
        "target_surface_type",
        "target_workflow_id",
        "target_path",
        "reason",
        "next_action",
        "follow_up_id",
    }
)


def _equipment_accounting_record_error(
    record: dict[str, Any],
    current_equipment: list[dict[str, Any]],
    discovery_scopes: list[dict[str, Any]],
    unassessed_areas: list[dict[str, Any]],
    evidence_by_id: dict[str, dict[str, Any]],
    trusted_workflow_entries_by_id: dict[str, dict[str, Any]],
    *,
    require_trusted_workflow_inventory: bool,
) -> str | None:
    if set(record) != _EQUIPMENT_ACCOUNTING_RECORD_FIELDS:
        return "accounting records must use the complete canonical shape"
    if any(not isinstance(record[field_name], str) for field_name in record):
        return "accounting record fields must be strings"
    for field_name in (
        "id",
        "source_scope",
        "source_kind",
        "material_scope",
        "accounting_status",
        "coverage_status",
        "target_surface_type",
        "reason",
        "next_action",
    ):
        if not record[field_name]:
            return f"accounting record {field_name} must be a non-empty string"
    if record["accounting_status"] not in ACCOUNTING_STATUS_TYPES:
        return "accounting_status must use a current contract value"
    expected_id = _accounting_record_id(
        record["source_scope"],
        record["source_root"],
        record["source_path"],
    )
    if record["id"] != expected_id:
        return "accounting record id must match its exact source identity"

    if record["source_kind"] == "unassessed-area":
        expected = [
            _accounting_record_from_unassessed_area(area)
            for area in unassessed_areas
            if not area.get("path")
            if _accounting_record_from_unassessed_area(area)["id"] == record["id"]
        ]
        if expected != [record]:
            return "unassessed accounting records must match one exact equipment area"
        return None

    if record["source_kind"] == "source-root":
        matching_scopes = [
            scope
            for scope in discovery_scopes
            if scope.get("kind") == record["source_scope"]
            and scope.get("path") == record["source_root"]
            and scope.get("status") != "scanned"
        ]
        if len(matching_scopes) != 1:
            return "source-root accounting must match one unassessed discovery scope"
        expected = _accounting_record_from_unassessed_root(
            {
                "path": record["source_root"],
                "source_scope": record["source_scope"],
                "status": matching_scopes[0]["status"],
            }
        )
        if record != expected:
            return "source-root accounting must use the canonical unassessed shape"
        return None

    matches = [
        entry
        for entry in current_equipment
        if all(
            entry.get(field) == record[field]
            for field in (
                "source_scope",
                "source_root",
                "source_path",
                "source_kind",
            )
        )
    ]
    if len(matches) != 1:
        return "accounting records must match one current equipment decision"
    equipment = matches[0]
    if not record["source_entry_id"]:
        return "accounting record source_entry_id must identify its source projection"

    if record["material_scope"] == "fork-local-source-material":
        disposition = record["coverage_status"]
        if disposition not in SOURCE_MATERIAL_DISPOSITION_TYPES:
            return "migration accounting coverage_status must be a source disposition"
        if record["accounting_status"] != _accounting_status_for_source_disposition(
            disposition
        ):
            return "migration accounting status must match its source disposition"
        if disposition == "mapped_to_workflow_backlog":
            contract = next(
                (
                    item
                    for item in workflow_contracts()
                    if item.id == record["target_workflow_id"]
                ),
                None,
            )
            if contract is None or contract.implementation_extent != "planned":
                return "migration accounting workflow claim must match the workflow catalog"
        if equipment.get("disposition") != _equipment_disposition_from_source_disposition(
            disposition
        ):
            return "migration accounting must match its equipment disposition"
        expected_target = _migration_accounting_target(disposition, record)
        if any(record[field] != value for field, value in expected_target.items()):
            return "migration accounting target must match its source disposition"
        if record["source_entry_id"] != _migration_map_entry_id(record["source_path"]):
            return "migration accounting source_entry_id must match its source path"
        if record["reason"] != _accounting_reason_for_source_disposition(disposition):
            return "migration accounting reason must match its source disposition"
        if record["next_action"] != _accounting_next_action_for_source_disposition(
            disposition
        ):
            return "migration accounting next_action must match its source disposition"
        expected_follow_up = (
            _follow_up_id_for_accounting(
                record["source_scope"],
                record["source_root"],
                record["source_path"],
                disposition,
            )
            if _accounting_status_needs_follow_up(record["accounting_status"])
            else ""
        )
        if record["follow_up_id"] != expected_follow_up:
            return "migration accounting follow_up_id must match its source disposition"
        return None

    referenced_evidence = [
        evidence_by_id[evidence_id]
        for evidence_id in equipment.get("evidence_ids", [])
        if evidence_id in evidence_by_id
    ]
    workflow_evidence = [
        item for item in referenced_evidence if "workflow_source_entry_id" in item
    ]
    if len(workflow_evidence) != 1:
        return "workflow accounting must reference one canonical discovery projection"
    [projection] = workflow_evidence
    trusted_entry = trusted_workflow_entries_by_id.get(record["source_entry_id"])
    if trusted_entry is None and require_trusted_workflow_inventory:
        return "workflow accounting requires freshly derived inventory evidence"
    observed_projection = {
        field_name: projection.get(field_name)
        for field_name in _WORKFLOW_EVIDENCE_PROJECTION_FIELDS
    }
    if (
        trusted_entry is not None
        and observed_projection
        != _workflow_inventory_evidence_projection(trusted_entry)
    ):
        return "workflow accounting discovery evidence no longer matches source bytes"
    workflow_entry = {
        "source_kind": record["source_kind"],
        "material_scope": projection["workflow_material_scope"],
        "coverage_status": projection["workflow_coverage_status"],
        "likely_workflow_catalog_target": projection["workflow_catalog_target"],
        "source_path": record["source_path"],
    }
    if record["source_entry_id"] != projection["workflow_source_entry_id"]:
        return "workflow accounting source_entry_id must match discovery evidence"
    if record["material_scope"] != projection["workflow_material_scope"]:
        return "workflow accounting material_scope must match discovery evidence"
    if record["coverage_status"] != projection["workflow_coverage_status"]:
        return "workflow accounting coverage_status must match discovery evidence"
    source_root = Path(record["source_root"])
    expected_source_entry_ids = {
        _workflow_inventory_entry_id(source_root, source_root),
        _workflow_inventory_entry_id(
            source_root,
            source_root / record["source_path"],
        ),
    }
    if record["source_entry_id"] not in expected_source_entry_ids:
        return "workflow accounting source_entry_id must match its source identity"
    expected_status = _accounting_status_for_workflow_entry(workflow_entry)
    if record["accounting_status"] != expected_status:
        return "workflow accounting status must match canonical coverage evidence"
    if equipment.get("disposition") != _equipment_disposition_from_workflow_coverage(
        record["coverage_status"]
    ):
        return "workflow accounting must match its equipment disposition"
    expected_target = _accounting_target_for_workflow_entry(
        workflow_entry,
        expected_status,
    )
    if record["target_surface_type"] != expected_target["type"]:
        return "workflow accounting target type must match canonical coverage evidence"
    if record["target_workflow_id"] != expected_target.get("workflow_id", ""):
        return "workflow accounting target workflow must match canonical coverage evidence"
    if record["target_path"] != expected_target.get("path", ""):
        return "workflow accounting target path must match canonical coverage evidence"
    if record["reason"] != _accounting_reason(expected_status, workflow_entry):
        return "workflow accounting reason must match canonical coverage evidence"
    if record["next_action"] != _accounting_next_action(expected_status, workflow_entry):
        return "workflow accounting next_action must match canonical coverage evidence"
    if expected_status in {
        "implemented_workflow",
        "partial_workflow",
        "planned_workflow",
    }:
        expected_extent = {
            "implemented_workflow": "implemented",
            "partial_workflow": "partial",
            "planned_workflow": "planned",
        }[expected_status]
        contract = next(
            (
                item
                for item in workflow_contracts()
                if item.id == record["target_workflow_id"]
            ),
            None,
        )
        if contract is None or contract.implementation_extent != expected_extent:
            return "workflow accounting claim must match the current workflow catalog"
    expected_follow_up = (
        _follow_up_id_for_accounting(
            record["source_scope"],
            record["source_root"],
            record["source_path"],
            record["target_workflow_id"],
        )
        if _accounting_status_needs_follow_up(expected_status)
        else ""
    )
    if record["follow_up_id"] != expected_follow_up:
        return "workflow accounting follow_up_id must match canonical coverage evidence"
    return None


def _migration_accounting_target(
    disposition: str,
    record: dict[str, Any],
) -> dict[str, str]:
    if disposition == "extracted_into_config":
        return {
            "target_surface_type": "fork_ops_config",
            "target_workflow_id": "",
            "target_path": CONFIG_RELATIVE_PATH.as_posix(),
        }
    if disposition == "retained_as_fork_local_authority":
        return {
            "target_surface_type": "fork_local_authority",
            "target_workflow_id": "",
            "target_path": record["source_path"],
        }
    if disposition == "mapped_to_workflow_backlog":
        return {
            "target_surface_type": "workflow_catalog_backlog",
            "target_workflow_id": record["target_workflow_id"],
            "target_path": "",
        }
    if disposition == "irrelevant_to_fork_ops":
        return {
            "target_surface_type": "none",
            "target_workflow_id": "",
            "target_path": "",
        }
    return {
        "target_surface_type": "migration_review_artifact",
        "target_workflow_id": "",
        "target_path": MIGRATION_REVIEW_ARTIFACT_RELATIVE_PATH,
    }


def _empty_accounting_status_counts() -> dict[str, int]:
    return {status: 0 for status in ACCOUNTING_STATUS_TYPES}


def _accounting_status_counts(records: list[dict[str, Any]]) -> dict[str, int]:
    counts = _empty_accounting_status_counts()
    for record in records:
        status = record.get("accounting_status")
        if not isinstance(status, str):
            continue
        counts[status] = counts.get(status, 0) + 1
    return counts


def _capability_accounting_summary(equipment_review: dict[str, Any]) -> dict[str, Any]:
    status_counts = _empty_accounting_status_counts()
    raw_counts = equipment_review.get("accounting_status_counts")
    if isinstance(raw_counts, dict):
        for status, count in raw_counts.items():
            if isinstance(status, str) and isinstance(count, int):
                status_counts[status] = count
    summary = {
        "accounting_record_count": int(equipment_review.get("accounting_record_count", 0)),
        "follow_up_candidate_count": int(equipment_review.get("follow_up_candidate_count", 0)),
        "accounting_claims_verified": (
            equipment_review.get("accounting_claims_verified") is True
        ),
        "status_counts": copy.deepcopy(status_counts),
    }
    replacement_coverage = equipment_review.get("replacement_coverage")
    if isinstance(replacement_coverage, dict):
        summary["replacement_coverage"] = copy.deepcopy(replacement_coverage)
    return summary


def _attach_equipment_review(
    capability: dict[str, Any],
    equipment_review: dict[str, Any],
) -> None:
    capability["equipment_review"] = equipment_review
    capability["accounting"] = _capability_accounting_summary(equipment_review)
    if equipment_review.get("exists") is not True or equipment_review.get("valid") is True:
        return
    raw_diagnostics = capability.get("diagnostics")
    diagnostics: list[Any]
    if isinstance(raw_diagnostics, list):
        diagnostics = raw_diagnostics
    else:
        diagnostics = []
        capability["diagnostics"] = diagnostics
    if not any(
        isinstance(item, dict) and item.get("code") == "equipment_review.invalid"
        for item in diagnostics
    ):
        diagnostics.append(
            {
                "severity": "error",
                "code": "equipment_review.invalid",
                "message": "The persisted equipment review could not be validated.",
                "path": EQUIPMENT_REVIEW_RECORD_RELATIVE_PATH,
                "detail": {"error": equipment_review.get("error", "invalid review")},
            }
        )
    if capability.get("outcome") == OutcomeValue.COMPLETED:
        capability["outcome"] = OutcomeValue.BLOCKED


def _activation_readiness_report(
    migration_map: list[dict[str, Any]],
    blockers: list[dict[str, Any]],
    preflight: dict[str, Any],
) -> dict[str, Any]:
    blocker_codes = _blocker_codes(blockers)
    unassessed_areas = _record_table_list(
        preflight.get("unassessed_equipment_areas")
    )
    pending_equipment_decisions = [
        group
        for group in _record_table_list(preflight.get("equipment_groups"))
        if group.get("decision_status") != "reviewed"
    ]
    coverage_entries = [
        _replacement_coverage_entry(entry, preflight) for entry in migration_map
    ]
    continuity_entries = [
        _operational_continuity_entry(entry, preflight) for entry in migration_map
    ]
    readiness = (
        ActivationReadinessValue.BLOCKED
        if blockers
        else ActivationReadinessValue.UNASSESSED
        if unassessed_areas or pending_equipment_decisions
        else ActivationReadinessValue.READY
    )
    activation = State(
        dimension=StateDimension.ACTIVATION_READINESS,
        subject="workflow:fork-authority-migration",
        value=readiness,
        evidence_ids=("migration.blockers", "equipment.preflight"),
        derivation_rule="activation.named_operation_authority_equipment_and_blockers",
    )
    return {
        "activation_readiness": activation.to_dict(),
        "replacement_coverage": coverage_entries,
        "operational_continuity": continuity_entries,
        "activation_blocked_by": blocker_codes,
        "activation_limits": _activation_readiness_limits(
            blockers,
            unassessed_areas,
            pending_equipment_decisions,
        ),
    }


def _migration_state_evidence(
    blockers: list[dict[str, Any]],
    preflight: dict[str, Any],
) -> list[dict[str, object]]:
    return [
        {
            "id": "migration.blockers",
            "source": "migration_plan",
            "blocker_codes": _blocker_codes(blockers),
        },
        {
            "id": "equipment.preflight",
            "source": "embedded_equipment_migration_preflight",
            "unassessed_equipment_area_count": len(
                _optional_preview_list(preflight, "unassessed_equipment_areas")
            ),
            "pending_equipment_decision_count": len(
                [
                    group
                    for group in _optional_preview_list(
                        preflight,
                        "equipment_groups",
                    )
                    if group.get("decision_status") != "reviewed"
                ]
            ),
        },
    ]


def _refreshed_migration_state_evidence(
    evidence: list[dict[str, Any]],
    blockers: list[dict[str, Any]],
    preflight: dict[str, Any],
) -> list[dict[str, Any]]:
    state_evidence_ids = {"migration.blockers", "equipment.preflight"}
    refreshed = [
        copy.deepcopy(item)
        for item in evidence
        if item.get("id") not in state_evidence_ids
    ]
    refreshed.extend(_migration_state_evidence(blockers, preflight))
    return refreshed


def _replacement_coverage_entry(
    migration_entry: dict[str, Any],
    preflight: dict[str, Any],
) -> dict[str, Any]:
    disposition = migration_entry["disposition"]["type"]
    source_path = migration_entry["source_path"]
    group = _equipment_group_for_migration_entry(preflight, migration_entry)
    if disposition == "extracted_into_config":
        coverage = ReplacementCoverageValue.UNASSESSED
    elif disposition in {"retained_as_fork_local_authority", "mapped_to_workflow_backlog"}:
        coverage = ReplacementCoverageValue.NOT_APPLICABLE
    elif disposition == "irrelevant_to_fork_ops":
        coverage = ReplacementCoverageValue.NOT_APPLICABLE
    else:
        coverage = ReplacementCoverageValue.BLOCKED
    state = State(
        dimension=StateDimension.REPLACEMENT_COVERAGE,
        subject=f"source_material:{source_path}",
        value=coverage,
        evidence_ids=tuple(
            evidence_id
            for evidence_id in migration_entry.get("evidence_ids", [])
            if isinstance(evidence_id, str) and evidence_id
        ),
        derivation_rule=(
            "coverage.active_operation_authority_activation_and_behavior_evidence"
        ),
    )
    return {
        "source_path": source_path,
        "source_material_disposition": disposition,
        "equipment_id": group.get("id") if group else "",
        **state.to_dict(),
    }


def _operational_continuity_entry(
    migration_entry: dict[str, Any],
    preflight: dict[str, Any],
) -> dict[str, Any]:
    disposition = migration_entry["disposition"]["type"]
    source_path = migration_entry["source_path"]
    group = _equipment_group_for_migration_entry(preflight, migration_entry)
    reviewed_retained = bool(
        group
        and group.get("decision_status") == "reviewed"
        and group.get("disposition") == "retain_authoritative_owner"
    )
    if disposition == "irrelevant_to_fork_ops":
        continuity = OperationalContinuityValue.NOT_APPLICABLE
    elif reviewed_retained:
        continuity = OperationalContinuityValue.CONTINUOUS
    elif disposition in {"unsupported_extractor_shape", "needs_human_decision"}:
        continuity = OperationalContinuityValue.AT_RISK
    else:
        continuity = OperationalContinuityValue.UNASSESSED
    state = State(
        dimension=StateDimension.OPERATIONAL_CONTINUITY,
        subject=f"source_material:{source_path}",
        value=continuity,
        evidence_ids=tuple(
            evidence_id
            for evidence_id in migration_entry.get("evidence_ids", [])
            if isinstance(evidence_id, str) and evidence_id
        ),
        derivation_rule=(
            "continuity.active_fork_ops_or_verified_retained_owner_or_redirect"
        ),
    )
    return {
        "source_path": source_path,
        "source_material_disposition": disposition,
        "equipment_id": group.get("id") if group else "",
        **state.to_dict(),
    }


def _equipment_group_for_migration_entry(
    preflight: dict[str, Any],
    migration_entry: dict[str, Any],
) -> dict[str, Any]:
    source_path = migration_entry.get("source_path")
    if not isinstance(source_path, str):
        return {}
    for group in preflight.get("equipment_groups", []):
        if (
            isinstance(group, dict)
            and group.get("source_scope") == "repo-local"
            and group.get("source_path") == source_path
        ):
            return group
    return {}


def _activation_readiness_limits(
    blockers: list[dict[str, Any]],
    unassessed_areas: list[dict[str, Any]],
    pending_equipment_decisions: list[dict[str, Any]],
) -> list[str]:
    limits: list[str] = []
    if blockers:
        limits.append("Resolve blockers before guarded config creation.")
    if unassessed_areas:
        limits.append("Do not activate overlapping replacement behavior for unassessed areas.")
    if pending_equipment_decisions:
        limits.append("Review current equipment decisions before activation.")
    limits.append("Do not remove retained source material until replacement coverage validates.")
    return limits


def _migration_workflow_run_mode() -> dict[str, Any]:
    return {
        "default": "dry-run",
        "available": ["dry-run", "wet-run"],
        "wet_run_policy": "replay_reviewed_dry_run",
        "drift_policy": "fail_closed_by_default",
        "override_policy": (
            "Operator overrides do not bypass mutation gates, authority checks, "
            "or unresolved human decisions."
        ),
    }


def _replayable_wet_run(
    plan: dict[str, Any],
    blocked_steps: list[dict[str, Any]],
) -> dict[str, Any]:
    return {
        "available": not blocked_steps,
        "plan_fingerprint": _migration_plan_fingerprint(plan),
        "requires_drift_check": True,
        "drift_policy": "fail_closed_by_default",
        "replay_scope": "guarded_config_creation",
        "blocked_by": _blocker_codes(blocked_steps),
    }


def _migration_plan_fingerprint(plan: dict[str, Any]) -> str:
    stable_plan = {
        key: value
        for key, value in plan.items()
        if key != "narrative"
    }
    encoded = json.dumps(stable_plan, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(encoded.encode()).hexdigest()


def _blocker_codes(blockers: list[dict[str, Any]]) -> list[str]:
    return [
        code
        for blocker in blockers
        if isinstance((code := blocker.get("code")), str) and code
    ]


def _equipment_disposition_from_source_disposition(source_disposition: str) -> str:
    return {
        "extracted_into_config": "migrate_to_fork_ops",
        "retained_as_fork_local_authority": "retain_authoritative_owner",
        "mapped_to_workflow_backlog": "defer_to_follow_up",
        "irrelevant_to_fork_ops": "ignore",
        "unsupported_extractor_shape": "decide_item_by_item",
        "needs_human_decision": "decide_item_by_item",
        "deferred_with_rationale": "decide_item_by_item",
    }.get(source_disposition, "decide_item_by_item")


def _equipment_disposition_from_workflow_coverage(coverage_status: str) -> str:
    if coverage_status == "covered-implemented":
        return "migrate_to_fork_ops"
    if coverage_status in {"cataloged-planned", "backlog-candidate"}:
        return "defer_to_follow_up"
    return "decide_item_by_item"


def _equipment_decision_status(disposition: str) -> str:
    if disposition == "decide_item_by_item":
        return "pending_operator_decision"
    return "proposed"


def _equipment_activation_impact(disposition: str) -> str:
    return {
        "migrate_to_fork_ops": "Fork Ops may proceed only after coverage validates.",
        "retain_authoritative_owner": "Retained owner remains authoritative.",
        "defer_to_follow_up": "Track follow-up before replacement.",
        "ignore": "No Fork Ops activation impact.",
        "decide_item_by_item": "Operator decision required before overlapping activation.",
    }.get(disposition, "Operator decision required before overlapping activation.")


def _repo_equipment_classification(
    candidate: dict[str, Any],
    migration_entry: dict[str, Any],
) -> str:
    disposition = migration_entry["disposition"]["type"]
    if disposition == "irrelevant_to_fork_ops":
        return "unrelated"
    if candidate["kind"] in {"agent_instruction", "config"}:
        return "fork_ops_owner"
    if _has_review_publication_signal(set(candidate["signals"])):
        return "mixed"
    if candidate["extracted_facts"]:
        return "fork_ops_owner"
    return "unknown"


def _workflow_equipment_classification(entry: dict[str, Any]) -> str:
    source_kind = entry.get("source_kind")
    material_scope = entry.get("material_scope")
    if source_kind in {"global-skill", "repo-local-skill", "policy", "gate", "procedure"}:
        return "fork_ops_owner"
    if material_scope == "fork-local-authority-material":
        return "fork_ops_owner"
    if entry.get("likely_workflow_catalog_target"):
        return "mixed"
    return "unknown"


def _equipment_classification_confidence(
    candidate: dict[str, Any],
    migration_entry: dict[str, Any],
) -> str:
    disposition = migration_entry["disposition"]["type"]
    if disposition in {"unsupported_extractor_shape", "needs_human_decision"}:
        return "low"
    if candidate["extracted_facts"] or candidate["kind"] in {"agent_instruction", "config"}:
        return "high"
    return "medium"


def _consumer_compatibility_entries(entry: dict[str, Any]) -> list[dict[str, Any]]:
    coverage_status = str(entry.get("coverage_status", ""))
    if coverage_status != "covered-implemented":
        return []
    return [
        {
            "id": f"{entry['id']}:compatibility",
            "status": "proposed",
            "consumer": entry.get("source_kind"),
            "required_output": entry.get("likely_workflow_catalog_target"),
            "impact": "Verify before replacing or redirecting retained consumers.",
        }
    ]


def _equipment_disposition_reason(group: dict[str, Any]) -> str:
    disposition = group["disposition"]
    return {
        "migrate_to_fork_ops": (
            "The material maps to Fork Ops config or a covered workflow surface."
        ),
        "retain_authoritative_owner": "The material remains authoritative during migration.",
        "defer_to_follow_up": "The material maps to follow-up workflow work.",
        "ignore": "The material does not affect Fork Ops activation.",
        "decide_item_by_item": "The material needs operator review before activation.",
    }.get(disposition, "The material needs operator review before activation.")


def _equipment_group_id(scope: str, source_path: str) -> str:
    return f"equipment:{_short_digest(f'{scope}:{source_path}')}"


def _equipment_evidence_id(scope: str, source_path: str) -> str:
    return f"equipment-evidence:{_short_digest(f'{scope}:{source_path}')}"


def _equipment_scope_id(source_root: str) -> str:
    return f"scope:{_short_digest(source_root)}"


def _short_digest(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()[:16]


def _review_artifact_entries(artifact: dict[str, Any]) -> list[dict[str, Any]]:
    entries = artifact.get("entries", [])
    if not isinstance(entries, list) or any(not isinstance(item, dict) for item in entries):
        return []
    return entries


def _review_decisions_by_path(artifact: dict[str, Any]) -> dict[str, dict[str, Any]]:
    decisions: dict[str, dict[str, Any]] = {}
    seen_paths: set[str] = set()
    for entry in _review_artifact_entries(artifact):
        source_path = entry.get("source_path")
        if not isinstance(source_path, str) or not source_path:
            continue
        if source_path in seen_paths:
            raise ForkOpsError(
                f"Migration review artifact has duplicate source_path: {source_path}"
            )
        seen_paths.add(source_path)
        decision = entry.get("review_decision")
        if isinstance(decision, dict):
            decisions[source_path] = copy.deepcopy(decision)
    return decisions


def _reviewed_retained_source_paths(
    artifact: dict[str, Any],
    equipment_review_record: dict[str, Any] | None = None,
) -> set[str]:
    retained_paths: set[str] = set()
    for path, decision in _review_decisions_by_path(artifact).items():
        if decision.get("status") == "reviewed" and decision.get("choice") == "retain":
            retained_paths.add(path)
    for path, decision in _repo_local_equipment_review_decisions_by_path(
        equipment_review_record or {}
    ).items():
        if (
            decision.get("decision_status") == "reviewed"
            and decision.get("disposition") == "retain_authoritative_owner"
        ):
            retained_paths.add(path)
    return retained_paths


def _retained_authority(
    retained_materials: list[dict[str, Any]],
    migration_review_artifact: dict[str, Any],
    equipment_review_record: dict[str, Any] | None = None,
) -> list[dict[str, Any]]:
    decisions = _review_decisions_by_path(migration_review_artifact)
    equipment_decisions = _repo_local_equipment_review_decisions_by_path(
        equipment_review_record or {}
    )
    authority: list[dict[str, Any]] = []
    for material in retained_materials:
        path = material.get("path")
        if not isinstance(path, str) or not path:
            continue
        decision = decisions.get(path, {})
        equipment_decision = equipment_decisions.get(path, {})
        migration_review_retained = (
            decision.get("status") == "reviewed" and decision.get("choice") == "retain"
        )
        equipment_review_retained = (
            equipment_decision.get("decision_status") == "reviewed"
            and equipment_decision.get("disposition") == "retain_authoritative_owner"
        )
        if not migration_review_retained and not equipment_review_retained:
            continue
        review_decision = copy.deepcopy(decision)
        if equipment_review_retained:
            review_decision["equipment_review"] = copy.deepcopy(equipment_decision)
        authority.append(
            {
                "path": path,
                "kind": material.get("kind"),
                "domains": copy.deepcopy(material.get("domains", [])),
                "authority_status": "authoritative_after_config_creation",
                "read_required": True,
                "replacement_status": material.get("replacement_status", "deferred"),
                "review_decision": review_decision,
                "blocks": ["source-material replacement/removal"],
            }
        )
    return authority


def _repo_local_equipment_review_decisions_by_path(
    record: dict[str, Any],
) -> dict[str, dict[str, Any]]:
    if record.get("status") != "reviewed":
        return {}
    entries = record.get("equipment", [])
    if entries in (None, []):
        return {}
    if not isinstance(entries, list) or any(not isinstance(item, dict) for item in entries):
        raise ForkOpsError(
            "Migration dry run input has malformed equipment_review_record.equipment."
        )
    decisions: dict[str, dict[str, Any]] = {}
    seen_paths: set[str] = set()
    for entry in entries:
        if entry.get("source_scope") != "repo-local":
            continue
        if entry.get("decision_status") == "superseded":
            continue
        source_path = entry.get("source_path")
        if not isinstance(source_path, str) or not source_path:
            continue
        if source_path in seen_paths:
            raise ForkOpsError(
                f"Equipment review record has duplicate source_path: {source_path}"
            )
        seen_paths.add(source_path)
        decisions[source_path] = copy.deepcopy(entry)
    return decisions


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
                "reason": "Blockers must be resolved with durable review evidence before dry run.",
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
    raw_origin_url = _git_output(repo, "remote", "get-url", "origin") or _find_remote_url(
        candidates, "origin"
    )
    raw_upstream_url = _git_output(repo, "remote", "get-url", "upstream") or _find_remote_url(
        candidates, "upstream"
    )
    origin_url = _credential_free_source_url(raw_origin_url)
    upstream_url = _credential_free_source_url(raw_upstream_url)
    origin_slug = _github_slug_from_url(origin_url) or ("OWNER", "REPO")
    upstream_slug = _github_slug_from_url(upstream_url) or (
        "UPSTREAM_OWNER",
        "UPSTREAM_REPO",
    )
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
    upstream_push_url = _credential_free_source_url(
        _git_output(repo, "remote", "get-url", "--push", "upstream") or ""
    )
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
    return [path for path in candidates if _bound_path_kind(repo, path) == "regular"]


def _durable_discovery_destinations(repo: Path) -> list[str]:
    candidates = {
        "CONTEXT.md": "stable vocabulary and relationships",
        "docs/agents/research-map.md": "source maps and scout routes",
        "docs/agents/fork-stewardship.md": "fork operating policy",
        "AGENTS.md": "always-loaded high-impact rules",
    }
    return [
        f"{path}: {purpose}"
        for path, purpose in candidates.items()
        if _bound_path_kind(repo, path) == "regular"
    ]


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


def _github_path_from_url(url: str) -> str:
    normalized = url.strip().rstrip("/")
    if not normalized:
        return ""
    if normalized.startswith("git@github.com:"):
        return normalized.split(":", 1)[1].removesuffix(".git")
    parsed = urlparse(normalized)
    if parsed.hostname != "github.com":
        return ""
    if parsed.scheme not in {"git", "http", "https", "ssh"}:
        return ""
    return parsed.path.strip("/").removesuffix(".git")


def _github_slug_from_url(url: str) -> tuple[str, str] | None:
    path = _github_path_from_url(url)
    if not path:
        return None
    parts = path.strip("/").split("/")
    if len(parts) < 2:
        return None
    return parts[0], parts[1]


def _github_repo_root_slug_from_url(url: str) -> tuple[str, str] | None:
    path = _github_path_from_url(url)
    if not path:
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
    projected = _public_url_projection(url)
    if not projected:
        return False
    parsed = urlparse(projected)
    return (
        parsed.scheme in {"http", "https"} and parsed.netloc != "" and parsed.netloc != "github.com"
    )


def _looks_like_docs_url(url: str) -> bool:
    parsed = urlparse(url)
    host_parts = parsed.netloc.lower().split(".")
    path_parts = [part for part in parsed.path.lower().split("/") if part]
    return "docs" in host_parts or (bool(path_parts) and path_parts[0] == "docs")


def _site_root(url: str) -> str:
    projected = _public_url_projection(url)
    if not projected:
        return ""
    parsed = urlparse(projected)
    if not parsed.scheme or not parsed.netloc:
        return url
    return f"{parsed.scheme}://{parsed.netloc}/"


def _url_parts(raw_url: str) -> SplitResult | None:
    candidate = raw_url.rstrip(".,)>`;'\"")
    if not candidate or "\\" in candidate or any(ord(char) < 32 for char in candidate):
        return None
    try:
        parsed = urlsplit(candidate)
        _ = parsed.port
    except ValueError:
        return None
    if parsed.scheme.lower() not in {"http", "https"} or not parsed.hostname:
        return None
    return parsed


def _url_has_credentials(raw_url: str) -> bool:
    parsed = _url_parts(raw_url)
    return bool(parsed and (parsed.username is not None or parsed.password is not None))


def _public_url_projection(raw_url: str) -> str:
    parsed = _url_parts(raw_url)
    if parsed is None:
        return ""
    hostname = parsed.hostname or ""
    host = f"[{hostname.lower()}]" if ":" in hostname else hostname.lower()
    if parsed.port is not None:
        host = f"{host}:{parsed.port}"
    path = parsed.path or "/"
    return urlunsplit((parsed.scheme.lower(), host, path, "", ""))


def _credential_free_source_url(raw_url: str) -> str:
    if not raw_url:
        return ""
    if re.fullmatch(r"git@github\.com:[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+(?:\.git)?", raw_url):
        github_slug = _github_repo_root_slug_from_url(raw_url)
        if github_slug:
            owner, name = github_slug
            return f"https://github.com/{owner}/{name}.git"
        return ""
    if _url_has_credentials(raw_url):
        parsed = _url_parts(raw_url)
        if not (
            parsed
            and parsed.scheme.lower() == "ssh"
            and parsed.username == "git"
            and parsed.password is None
            and parsed.hostname == "github.com"
            and not parsed.query
            and not parsed.fragment
        ):
            return ""
    github_slug = _github_repo_root_slug_from_url(raw_url)
    if github_slug:
        owner, name = github_slug
        return f"https://github.com/{owner}/{name}.git"
    return _public_url_projection(raw_url)


def _extract_urls(
    text: str,
    *,
    budget: _OperationBudget | None = None,
) -> list[str]:
    seen: set[str] = set()
    projected_urls: list[str] = []
    for match in re.finditer(r"https?://[^\s<)]+", text, flags=re.IGNORECASE):
        projected = _public_url_projection(match.group(0))
        if not projected or projected in seen:
            continue
        if budget is not None and budget.result_count + len(projected_urls) + 1 > MAX_RESULT_ITEMS:
            budget.mark_incomplete("limit.results", "extracted_urls")
            break
        seen.add(projected)
        projected_urls.append(projected)
    return projected_urls


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
    discover_git_remotes: bool = True,
) -> str:
    repo = Path(os.path.abspath(os.path.expanduser(str(repo_path))))
    origin_url = (
        _credential_free_source_url(_git_output(repo, "remote", "get-url", "origin") or "")
        if discover_git_remotes
        else ""
    )
    upstream_url = (
        _credential_free_source_url(_git_output(repo, "remote", "get-url", "upstream") or "")
        if discover_git_remotes
        else ""
    )
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


def initialize_config(
    repo_path: str | Path = "",
    repository_owner: str = "OWNER",
    repository_name: str = "REPO",
    upstream_owner: str = "UPSTREAM_OWNER",
    upstream_name: str = "UPSTREAM_REPO",
    default_branch: str = "main",
) -> dict[str, Any]:
    selected_repo_path = _require_explicit_repository_path(repo_path)
    repo = Path(os.path.abspath(os.path.expanduser(str(selected_repo_path))))
    try:
        bound_repo = _bind_repository(repo)
    except OSError as exc:
        return _config_initialization_result(
            repo,
            status="blocked",
            applied_edits=[],
            blockers=[_repository_identity_blocker(exc)],
            verification=None,
            mutation=_config_initialization_mutation(False, "not-created", "not-needed"),
        )
    try:
        result = _initialize_config_in_bound_repository(
            bound_repo,
            repository_owner=repository_owner,
            repository_name=repository_name,
            upstream_owner=upstream_owner,
            upstream_name=upstream_name,
            default_branch=default_branch,
        )
    except Exception:
        bound_repo.close()
        raise
    try:
        bound_repo.close()
    except OSError as exc:
        applied = result.get("applied_edits")
        if isinstance(applied, list) and applied:
            first_edit = next((edit for edit in applied if isinstance(edit, dict)), None)
            if first_edit is not None:
                return _minimal_applied_unverified_config_result(repo, first_edit, exc)
        result["outcome"] = OutcomeValue.BLOCKED
        result["mutation_state"] = MutationStateValue.NOT_STARTED
        blockers = result.setdefault("blockers", [])
        if isinstance(blockers, list):
            blockers.append(
                {
                    "code": "config_initialization.repository_close_failed",
                    "message": "The selected repository descriptor could not be closed.",
                    "error_type": type(exc).__name__,
                }
            )
    return result


def _initialize_config_in_bound_repository(
    bound_repo: _BoundRepository,
    *,
    repository_owner: str,
    repository_name: str,
    upstream_owner: str,
    upstream_name: str,
    default_branch: str,
) -> dict[str, Any]:
    repo = bound_repo.path
    content = create_initial_config_text(
        repo,
        repository_owner=repository_owner,
        repository_name=repository_name,
        upstream_owner=upstream_owner,
        upstream_name=upstream_name,
        default_branch=default_branch,
        discover_git_remotes=False,
    )
    edit = {
        "path": CONFIG_RELATIVE_PATH.as_posix(),
        "action": "create",
        "content_kind": "fork-ops-config",
        "content": content,
    }
    blockers = _migration_execution_blockers(
        repo,
        {"file_edits": [edit]},
        bound_repo=bound_repo,
        check_target=True,
    )
    if blockers:
        return _config_initialization_result(
            repo,
            status="blocked",
            applied_edits=[],
            blockers=blockers,
            verification=None,
            mutation=_config_initialization_mutation(False, "not-created", "not-needed"),
        )

    if not _repository_path_has_identity(bound_repo):
        return _config_initialization_result(
            repo,
            status="blocked",
            applied_edits=[],
            blockers=[_repository_identity_blocker(OSError("repository root path changed"))],
            verification=None,
            mutation=_config_initialization_mutation(False, "not-created", "not-needed"),
        )
    applied_edit, apply_blocker, created_identity = _apply_migration_file_edit(
        bound_repo,
        edit,
    )
    if apply_blocker is not None or applied_edit is None or created_identity is None:
        mutation_occurred = applied_edit is not None
        parent_only_mutation = bool(
            applied_edit is not None and applied_edit.get("target_created") is False
        )
        try:
            return _config_initialization_result(
                repo,
                status="applied_unverified" if mutation_occurred else "blocked",
                applied_edits=[applied_edit] if applied_edit is not None else [],
                blockers=[apply_blocker] if apply_blocker is not None else [],
                verification=None,
                mutation=_config_initialization_mutation(
                    mutation_occurred,
                    (
                        "not-created"
                        if parent_only_mutation or not mutation_occurred
                        else "unverified"
                    ),
                    (
                        "not-attempted"
                        if mutation_occurred and not parent_only_mutation
                        else "not-needed"
                    ),
                ),
            )
        except Exception as exc:
            if mutation_occurred and applied_edit is not None:
                return _minimal_applied_unverified_config_result(repo, applied_edit, exc)
            raise

    target_path = repo / CONFIG_RELATIVE_PATH
    content_bytes = _config_content_bytes(content)
    try:
        target_verification, target_blocker = _verify_created_target(
            target_path,
            created_identity,
            content_bytes,
            bound_repo,
        )
    except Exception as exc:
        return _minimal_applied_unverified_config_result(repo, applied_edit, exc)
    if target_blocker is not None:
        return _safe_config_initialization_post_create_failure(
            repo,
            applied_edit,
            created_identity,
            content_bytes,
            bound_repo=bound_repo,
            blockers=[target_blocker],
            verification={"status": "failed", "target": target_verification},
        )

    required_level = "track-aware"
    try:
        report = build_status_report(repo, include_config=False)
        authority = report["capability"]["authority_readiness"]
        required_ready = authority["levels"][required_level]["ready"] is True
    except Exception as exc:
        verification = {
            "status": "failed",
            "target": target_verification,
            "capability": {
                "status": "failed",
                "required_level": required_level,
                "error": str(exc),
            },
        }
        return _safe_config_initialization_post_create_failure(
            repo,
            applied_edit,
            created_identity,
            content_bytes,
            bound_repo=bound_repo,
            blockers=[
                {
                    "code": "config_initialization.verification_error",
                    "message": f"Fork Ops config verification failed: {exc}",
                }
            ],
            verification=verification,
        )

    verification = {
        "status": "passed" if required_ready else "failed",
        "target": target_verification,
        "capability": {
            "status": "passed" if required_ready else "failed",
            "required_level": required_level,
            "required_level_ready": required_ready,
            "highest_authority_ready": authority["highest_authority_ready"],
            "diagnostics": report.get("diagnostics", []),
        },
        "required_level": required_level,
        "required_level_ready": required_ready,
        "highest_authority_ready": authority["highest_authority_ready"],
        "diagnostics": report.get("diagnostics", []),
    }
    if not required_ready:
        return _safe_config_initialization_post_create_failure(
            repo,
            applied_edit,
            created_identity,
            content_bytes,
            bound_repo=bound_repo,
            blockers=[
                {
                    "code": "migration_execution.verification_failed",
                    "message": "Fork Ops config verification failed after config initialization.",
                    "diagnostics": report.get("diagnostics", []),
                }
            ],
            verification=verification,
        )

    try:
        final_target_verification, final_target_blocker = _verify_created_target(
            target_path,
            created_identity,
            content_bytes,
            bound_repo,
        )
    except Exception as exc:
        return _minimal_applied_unverified_config_result(repo, applied_edit, exc)
    verification["target"] = final_target_verification
    if final_target_blocker is not None:
        verification["status"] = "failed"
        return _safe_config_initialization_post_create_failure(
            repo,
            applied_edit,
            created_identity,
            content_bytes,
            bound_repo=bound_repo,
            blockers=[final_target_blocker],
            verification=verification,
        )

    try:
        return _config_initialization_result(
            repo,
            status="applied",
            applied_edits=[applied_edit],
            blockers=[],
            verification=verification,
            mutation=_config_initialization_mutation(True, "verified", "not-needed"),
        )
    except Exception as exc:
        return _minimal_applied_unverified_config_result(repo, applied_edit, exc)


def _safe_config_initialization_post_create_failure(
    repo: Path,
    applied_edit: dict[str, Any],
    created_identity: _CreatedFileIdentity,
    expected_content: bytes,
    *,
    bound_repo: _BoundRepository,
    blockers: list[dict[str, Any]],
    verification: dict[str, Any],
) -> dict[str, Any]:
    try:
        return _config_initialization_post_create_failure(
            repo,
            applied_edit,
            created_identity,
            expected_content,
            bound_repo=bound_repo,
            blockers=blockers,
            verification=verification,
        )
    except Exception as exc:
        return _minimal_applied_unverified_config_result(repo, applied_edit, exc)


def _minimal_applied_unverified_config_result(
    repo: Path,
    applied_edit: dict[str, Any],
    error: Exception,
) -> dict[str, Any]:
    applied_edit["status"] = "applied_unverified"
    return cast(
        dict[str, Any],
        operation_artifact(
            ArtifactKind.CONFIG_INITIALIZATION_RESULT,
            "config-initialization",
            {
                "repo_path": str(repo),
                "mode": "mutating",
                "target_path": str(repo / CONFIG_RELATIVE_PATH),
                "applied_edits": [applied_edit],
                "blockers": [
            {
                "code": "config_initialization.post_write_error",
                "message": "Config initialization changed the repository but could not complete.",
                "error_type": type(error).__name__,
            }
                ],
                "verification": None,
                "mutation": _config_initialization_mutation(
                    True,
                    "unverified",
                    "not-attempted",
                ),
            },
            outcome=OutcomeValue.FAILED,
            mutation_state=MutationStateValue.APPLIED_UNVERIFIED,
        ),
    )


def _config_initialization_post_create_failure(
    repo: Path,
    applied_edit: dict[str, Any],
    created_identity: _CreatedFileIdentity,
    expected_content: bytes,
    *,
    bound_repo: _BoundRepository,
    blockers: list[dict[str, Any]],
    verification: dict[str, Any],
) -> dict[str, Any]:
    rollback = _rollback_created_target(
        repo / CONFIG_RELATIVE_PATH,
        created_identity,
        expected_content,
        bound_repo,
    )
    edit = copy.deepcopy(applied_edit)
    if rollback["status"] == "rolled_back":
        status = "rolled_back"
        target_state = "rolled_back"
        rollback_status = "rolled_back"
        edit["status"] = "rolled_back"
    else:
        status = "applied_unverified"
        target_state = "unverified"
        rollback_status = str(rollback["status"])
        edit["status"] = "applied_unverified"
        rollback_blocker = rollback.get("blocker")
        if isinstance(rollback_blocker, dict):
            blockers = [*blockers, rollback_blocker]
    return _config_initialization_result(
        repo,
        status=status,
        applied_edits=[edit],
        blockers=blockers,
        verification=verification,
        mutation=_config_initialization_mutation(True, target_state, rollback_status),
    )


def _verify_created_target(
    path: Path,
    identity: _CreatedFileIdentity,
    expected_content: bytes,
    bound_repo: _BoundRepository | None = None,
) -> tuple[dict[str, Any], dict[str, Any] | None]:
    expected_parent_identity = (identity.parent_device, identity.parent_inode)
    verification_repo: _BoundRepository | None = None
    parent_descriptor: int | None = None
    try:
        verification_repo = (
            _duplicate_bound_repository(bound_repo)
            if bound_repo is not None
            else _bind_repository(path.parent.parent)
        )
        if (verification_repo.device, verification_repo.inode) != (
            identity.root_device,
            identity.root_inode,
        ):
            verification_repo.close()
            verification_repo = None
            raise OSError(
                getattr(errno, "ESTALE", errno.EIO),
                "created config repository identity changed",
            )
        parent_descriptor = _open_exact_parent_descriptor(
            verification_repo,
            expected_parent_identity,
        )
    except OSError as exc:
        if parent_descriptor is not None:
            os.close(parent_descriptor)
            parent_descriptor = None
        if verification_repo is not None:
            verification_repo.close()
            verification_repo = None
        verification = {
            "status": "failed",
            "path": str(path),
            "expected_sha256": identity.content_sha256,
            "parent_identity_matches": False,
            "error": str(exc),
        }
        return verification, {
            "code": "config_initialization.target_parent_identity_changed",
            "path": CONFIG_RELATIVE_PATH.as_posix(),
            "message": "Created config target parent identity changed after creation.",
            "error": str(exc),
        }
    try:
        verification, blocker, target_descriptor = _inspect_created_entry_in_parent(
            parent_descriptor,
            path.name,
            path,
            identity,
            expected_content,
        )
        try:
            if blocker is not None:
                return verification, blocker
            if target_descriptor is None:
                raise OSError(errno.EIO, "created config descriptor is unavailable")
            target_stat = os.fstat(target_descriptor)
            name_stat = os.stat(
                path.name,
                dir_fd=parent_descriptor,
                follow_symlinks=False,
            )
            if (name_stat.st_dev, name_stat.st_ino) != (
                target_stat.st_dev,
                target_stat.st_ino,
            ):
                verification["status"] = "failed"
                verification["identity_matches"] = False
                return verification, {
                    "code": "config_initialization.target_identity_changed",
                    "path": CONFIG_RELATIVE_PATH.as_posix(),
                    "message": "Created config target identity changed during verification.",
                }
            parent_name_stat = os.stat(
                CONFIG_RELATIVE_PATH.parent.name,
                dir_fd=verification_repo.descriptor,
                follow_symlinks=False,
            )
            if (parent_name_stat.st_dev, parent_name_stat.st_ino) != expected_parent_identity:
                verification["status"] = "failed"
                verification["parent_identity_matches"] = False
                return verification, {
                    "code": "config_initialization.target_parent_identity_changed",
                    "path": CONFIG_RELATIVE_PATH.as_posix(),
                    "message": "Created config parent identity changed during final verification.",
                }
            if not _repository_path_has_identity(verification_repo):
                verification["status"] = "failed"
                verification["repository_identity_matches"] = False
                return verification, {
                    "code": "config_initialization.repository_identity_changed",
                    "path": CONFIG_RELATIVE_PATH.as_posix(),
                    "message": (
                        "Created config repository identity changed during final verification."
                    ),
                }
            pre_read_stat = os.fstat(target_descriptor)
            with os.fdopen(target_descriptor, "rb", closefd=False) as handle:
                handle.seek(0)
                final_content = handle.read()
            post_read_stat = os.fstat(target_descriptor)
            expected_stat = (
                identity.device,
                identity.inode,
                identity.size,
                identity.modified_time_ns,
                identity.change_time_ns,
            )
            pre_read_identity = _file_observation_tuple(pre_read_stat)
            post_read_identity = _file_observation_tuple(post_read_stat)
            final_sha256 = hashlib.sha256(final_content).hexdigest()
            if (
                pre_read_identity != expected_stat
                or post_read_identity != expected_stat
                or pre_read_identity != post_read_identity
                or final_content != expected_content
                or final_sha256 != identity.content_sha256
            ):
                verification["status"] = "failed"
                verification["content_unchanged"] = False
                verification["metadata_unchanged"] = False
                verification["actual_bytes"] = len(final_content)
                verification["actual_sha256"] = final_sha256
                return verification, {
                    "code": "config_initialization.target_content_changed",
                    "path": CONFIG_RELATIVE_PATH.as_posix(),
                    "message": "Created config target changed during final verification.",
                    "expected_sha256": identity.content_sha256,
                    "actual_sha256": final_sha256,
                }
            verification["content_unchanged"] = True
            verification["metadata_unchanged"] = True
            verification["parent_identity_matches"] = True
            verification["repository_identity_matches"] = True
            verification["identity_observed_at_final_check"] = True
            return verification, None
        except OSError as exc:
            verification["status"] = "failed"
            verification["identity_matches"] = False
            verification["error"] = str(exc)
            return verification, {
                "code": "config_initialization.target_identity_changed",
                "path": CONFIG_RELATIVE_PATH.as_posix(),
                "message": "Created config target identity could not be confirmed at final check.",
                "error": str(exc),
            }
        finally:
            if target_descriptor is not None:
                os.close(target_descriptor)
    finally:
        if parent_descriptor is not None:
            os.close(parent_descriptor)
        if verification_repo is not None:
            verification_repo.close()


def _file_observation_tuple(file_stat: os.stat_result) -> tuple[int, int, int, int, int]:
    return (
        file_stat.st_dev,
        file_stat.st_ino,
        file_stat.st_size,
        file_stat.st_mtime_ns,
        file_stat.st_ctime_ns,
    )


def _inspect_created_entry_in_parent(
    parent_descriptor: int,
    entry_name: str,
    display_path: Path,
    identity: _CreatedFileIdentity,
    expected_content: bytes,
) -> tuple[dict[str, Any], dict[str, Any] | None, int | None]:
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(entry_name, flags, dir_fd=parent_descriptor)
    except OSError as exc:
        verification = {
            "status": "failed",
            "path": str(display_path),
            "expected_sha256": identity.content_sha256,
            "error": str(exc),
        }
        return verification, {
            "code": "config_initialization.target_unreadable",
            "path": CONFIG_RELATIVE_PATH.as_posix(),
            "message": "Created config target is missing, unreadable, or a symlink.",
            "error": str(exc),
        }, None
    try:
        target_stat = os.fstat(descriptor)
        if not stat.S_ISREG(target_stat.st_mode):
            verification = {
                "status": "failed",
                "path": str(display_path),
                "expected_sha256": identity.content_sha256,
                "file_type": "not-regular",
            }
            return verification, {
                "code": "config_initialization.target_not_regular",
                "path": CONFIG_RELATIVE_PATH.as_posix(),
                "message": "Created config target is not a regular file.",
            }, descriptor
        if (target_stat.st_dev, target_stat.st_ino) != (identity.device, identity.inode):
            verification = {
                "status": "failed",
                "path": str(display_path),
                "expected_sha256": identity.content_sha256,
                "identity_matches": False,
            }
            return verification, {
                "code": "config_initialization.target_identity_changed",
                "path": CONFIG_RELATIVE_PATH.as_posix(),
                "message": "Created config target identity changed after creation.",
            }, descriptor
        with os.fdopen(descriptor, "rb", closefd=False) as handle:
            actual_content = handle.read()
    except OSError as exc:
        verification = {
            "status": "failed",
            "path": str(display_path),
            "expected_sha256": identity.content_sha256,
            "error": str(exc),
        }
        return verification, {
            "code": "config_initialization.target_unreadable",
            "path": CONFIG_RELATIVE_PATH.as_posix(),
            "message": "Created config target could not be read for exact verification.",
            "error": str(exc),
        }, descriptor

    actual_sha256 = hashlib.sha256(actual_content).hexdigest()
    if (
        actual_content != expected_content
        or target_stat.st_size != identity.size
        or actual_sha256 != identity.content_sha256
    ):
        verification = {
            "status": "failed",
            "path": str(display_path),
            "identity_matches": True,
            "expected_bytes": identity.size,
            "actual_bytes": len(actual_content),
            "expected_sha256": identity.content_sha256,
            "actual_sha256": actual_sha256,
        }
        return verification, {
            "code": "config_initialization.target_content_changed",
            "path": CONFIG_RELATIVE_PATH.as_posix(),
            "message": "Created config target bytes changed after creation.",
            "expected_sha256": identity.content_sha256,
            "actual_sha256": actual_sha256,
        }, descriptor
    return {
        "status": "passed",
        "path": str(display_path),
        "regular_file": True,
        "identity_matches": True,
        "bytes": len(actual_content),
        "content_sha256": actual_sha256,
    }, None, descriptor


def _rollback_created_target(
    path: Path,
    identity: _CreatedFileIdentity,
    expected_content: bytes,
    bound_repo: _BoundRepository | None = None,
) -> dict[str, Any]:
    expected_parent_identity = (identity.parent_device, identity.parent_inode)
    rollback_repo: _BoundRepository | None = None
    parent_descriptor: int | None = None
    try:
        _require_descriptor_relative_operations("open", "stat")
        rollback_repo = (
            _duplicate_bound_repository(bound_repo)
            if bound_repo is not None
            else _bind_repository(path.parent.parent)
        )
        if (rollback_repo.device, rollback_repo.inode) != (
            identity.root_device,
            identity.root_inode,
        ):
            rollback_repo.close()
            rollback_repo = None
            raise OSError(
                getattr(errno, "ESTALE", errno.EIO),
                "created config repository identity changed",
            )
        parent_descriptor = _open_exact_parent_descriptor(
            rollback_repo,
            expected_parent_identity,
        )
    except OSError as exc:
        if parent_descriptor is not None:
            os.close(parent_descriptor)
            parent_descriptor = None
        if rollback_repo is not None:
            rollback_repo.close()
            rollback_repo = None
        return {
            "status": "unsafe",
            "blocker": {
                "code": "config_initialization.rollback_unsafe",
                "path": CONFIG_RELATIVE_PATH.as_posix(),
                "message": (
                    "Safe rollback could not bind the exact created config parent with "
                    "descriptor-relative operations."
                ),
                "error": str(exc),
            },
        }
    try:
        try:
            os.stat(path.name, dir_fd=parent_descriptor, follow_symlinks=False)
        except FileNotFoundError:
            return _rollback_failure(
                "unsafe",
                "config_initialization.rollback_unsafe",
                (
                    "The target name is absent, but removal of the task-created "
                    "identity cannot be proven; no rollback was claimed."
                ),
                reason_code="target_absent_unverified",
            )
        except OSError as exc:
            return _rollback_failure(
                "unsafe",
                "config_initialization.rollback_unsafe",
                "Safe rollback could not inspect the created config target.",
                error=exc,
            )

        _, match_blocker = _verify_created_target(
            path,
            identity,
            expected_content,
            rollback_repo,
        )
        if match_blocker is not None:
            return _rollback_failure(
                "unsafe",
                "config_initialization.rollback_unsafe",
                (
                    "Safe rollback refused because the target no longer has the "
                    "task-created identity and exact content."
                ),
                reason_code=str(match_blocker.get("code")),
            )
        return _rollback_failure(
            "unsafe",
            "config_initialization.rollback_unsafe",
            (
                "Automatic rollback is unavailable because this platform does not "
                "provide an atomic exact-identity delete; the target was preserved."
            ),
            reason_code="atomic_identity_delete_unavailable",
        )
    finally:
        if parent_descriptor is not None:
            os.close(parent_descriptor)
        if rollback_repo is not None:
            rollback_repo.close()


def _rollback_failure(
    status: str,
    code: str,
    message: str,
    *,
    error: OSError | None = None,
    reason_code: str | None = None,
) -> dict[str, Any]:
    blocker: dict[str, Any] = {
        "code": code,
        "path": CONFIG_RELATIVE_PATH.as_posix(),
        "message": message,
    }
    if error is not None:
        blocker["error"] = str(error)
    if reason_code is not None:
        blocker["reason_code"] = reason_code
    return {"status": status, "blocker": blocker}


def _config_initialization_mutation(
    occurred: bool,
    target_state: str,
    rollback_status: str,
) -> dict[str, Any]:
    return {
        "occurred": occurred,
        "target_state": target_state,
        "rollback_status": rollback_status,
    }


def _config_initialization_result(
    repo: Path,
    *,
    status: str,
    applied_edits: list[dict[str, Any]],
    blockers: list[dict[str, Any]],
    verification: dict[str, Any] | None,
    mutation: dict[str, Any],
) -> dict[str, Any]:
    outcome = {
        "applied": OutcomeValue.COMPLETED,
        "blocked": OutcomeValue.BLOCKED,
        "rolled_back": OutcomeValue.FAILED,
        "applied_unverified": OutcomeValue.FAILED,
    }.get(status, OutcomeValue.FAILED)
    mutation_state = {
        "applied": MutationStateValue.APPLIED,
        "blocked": MutationStateValue.NOT_STARTED,
        "rolled_back": MutationStateValue.ROLLED_BACK,
        "applied_unverified": MutationStateValue.APPLIED_UNVERIFIED,
    }.get(status, MutationStateValue.APPLIED_UNVERIFIED)
    return _canonical_operation_result(
        ArtifactKind.CONFIG_INITIALIZATION_RESULT,
        {
            "repo_path": str(repo),
            "mode": "mutating",
            "target_path": str(repo / CONFIG_RELATIVE_PATH),
            "applied_edits": applied_edits,
            "blockers": blockers,
            "verification": verification,
            "mutation": mutation,
        },
        operation="config-initialization",
        outcome=outcome,
        mutation_state=mutation_state,
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
    root = Path(os.path.abspath(os.path.expanduser(str(plugin_root))))
    runtime_schema = schema_json().encode("utf-8")
    artifacts = []
    for relative_path in SCHEMA_ARTIFACT_RELATIVE_PATHS:
        path = root / relative_path
        try:
            content = _read_file_within_root(root, relative_path)
        except _BoundedReadError as exc:
            artifacts.append(
                {
                    "path": relative_path.as_posix(),
                    "absolute_path": str(path),
                    "exists": False,
                    "matches_runtime_schema": False,
                    "error": exc.code,
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
    ok = all(artifact["matches_runtime_schema"] for artifact in artifacts)
    return _canonical_operation_result(
        ArtifactKind.SCHEMA_ARTIFACT_REPORT,
        {
            "plugin_root": str(root),
            "runtime_schema_sha256": hashlib.sha256(runtime_schema).hexdigest(),
            "ok": ok,
            "artifacts": artifacts,
        },
        operation="schema-artifact-report",
        outcome=OutcomeValue.COMPLETED if ok else OutcomeValue.FAILED,
    )


def _workflow_inventory_roots(
    source_roots: Iterable[str | Path] | str | Path | None,
    scan_profile: str = "custom",
    budget: _OperationBudget | None = None,
) -> list[Path]:
    active_budget = budget or _OperationBudget()
    profile_roots = _scan_profile_roots(scan_profile)
    if source_roots is None:
        raw_roots: list[str | Path] = [] if scan_profile == "full-breadth" else ["."]
    elif isinstance(source_roots, (str, Path)):
        raw_roots = [source_roots]
    else:
        raw_roots = []
        for index, root in enumerate(source_roots):
            if index >= MAX_SCAN_ROOTS:
                active_budget.mark_incomplete("limit.roots")
                break
            raw_roots.append(root)
    if scan_profile == "full-breadth":
        raw_roots = [*profile_roots, *raw_roots]
    if not raw_roots:
        raw_roots = ["."]
    if len(raw_roots) > MAX_SCAN_ROOTS:
        active_budget.mark_incomplete("limit.roots")
        raw_roots = raw_roots[:MAX_SCAN_ROOTS]
    roots = [Path(os.path.abspath(os.path.expanduser(str(root)))) for root in raw_roots]
    active_budget.root_count = len(roots)
    return _dedupe_paths(roots)


def _normalize_scan_profile(scan_profile: str | None) -> str:
    profile = scan_profile or "custom"
    if profile not in SCAN_PROFILES:
        raise ForkOpsError(
            f"Unknown scan profile: {profile}. Expected one of: {', '.join(SCAN_PROFILES)}."
        )
    return profile


def _scan_profile_roots(scan_profile: str) -> list[Path]:
    if scan_profile != "full-breadth":
        return []
    home = Path(os.path.abspath(os.path.expanduser(str(Path.home()))))
    repo_base = _full_breadth_repo_base()
    roots = [home / relative for relative in FULL_BREADTH_USER_ROOTS]
    if repo_base is not None:
        roots.extend(repo_base / name for name in _full_breadth_maintained_repos())
        roots.extend(repo_base / name for name in _full_breadth_adjacent_repos())
    return roots


def _full_breadth_repo_base() -> Path | None:
    configured = os.environ.get(FULL_BREADTH_REPO_BASE_ENV)
    if configured:
        return Path(os.path.abspath(os.path.expanduser(configured)))
    return None


def _full_breadth_maintained_repos() -> tuple[str, ...]:
    return _full_breadth_repo_names(
        FULL_BREADTH_MAINTAINED_REPOS_ENV,
        FULL_BREADTH_MAINTAINED_REPOS,
    )


def _full_breadth_adjacent_repos() -> tuple[str, ...]:
    return _full_breadth_repo_names(
        FULL_BREADTH_ADJACENT_REPOS_ENV,
        FULL_BREADTH_ADJACENT_REPOS,
    )


def _full_breadth_repo_names(env_name: str, defaults: tuple[str, ...]) -> tuple[str, ...]:
    configured = os.environ.get(env_name)
    if configured is None:
        return defaults
    return tuple(name.strip() for name in configured.split(",") if name.strip())


def _scan_profile_notes(
    scan_profile: str,
    source_root_records: list[dict[str, Any]],
) -> list[str]:
    if scan_profile != "full-breadth":
        return []
    repo_base = _full_breadth_repo_base()
    notes = [
        (
            "full-breadth derives user-global roots from Path.home(). Set "
            f"{FULL_BREADTH_REPO_BASE_ENV} to include maintained-fork and "
            "adjacent repository roots."
        ),
        (
            "Override maintained and adjacent repository directory names with "
            f"{FULL_BREADTH_MAINTAINED_REPOS_ENV} and {FULL_BREADTH_ADJACENT_REPOS_ENV}."
        ),
    ]
    if repo_base is None:
        notes.append(
            "No maintained-fork repository roots were added because "
            f"{FULL_BREADTH_REPO_BASE_ENV} is unset."
        )
    if source_root_records and all(
        record.get("status") == "unresolvable" for record in source_root_records
    ):
        notes.append(
            "All full-breadth profile roots are unresolvable in this environment."
        )
    return notes


def _dedupe_paths(paths: list[Path]) -> list[Path]:
    seen: set[str] = set()
    deduped: list[Path] = []
    for path in paths:
        key = str(path)
        if key in seen:
            continue
        seen.add(key)
        deduped.append(path)
    return deduped


def _workflow_source_root_records(
    roots: list[Path],
    scan_profile: str,
) -> list[dict[str, Any]]:
    return [_workflow_source_root_record(root, scan_profile) for root in roots]


def _workflow_source_root_record(root: Path, scan_profile: str) -> dict[str, Any]:
    scope, role = _workflow_source_root_scope(root, scan_profile)
    try:
        root_stat = os.stat(root, follow_symlinks=False)
    except OSError:
        status = "unresolvable"
    else:
        status = (
            "scanned"
            if stat.S_ISDIR(root_stat.st_mode) or stat.S_ISREG(root_stat.st_mode)
            else "rejected"
        )
    return {
        "id": f"source-root:{_short_digest(str(root))}",
        "path": str(root),
        "source_scope": scope,
        "root_role": role,
        "status": status,
    }


def _workflow_source_root_scope(root: Path, scan_profile: str) -> tuple[str, str]:
    lexical_root = Path(os.path.abspath(os.path.expanduser(str(root))))
    home = Path(os.path.abspath(os.path.expanduser(str(Path.home()))))
    user_global_roots = {
        home / ".agents",
        home / ".agents" / "skills",
        home / ".codex" / "skills",
        home / ".codex" / "plugins" / "cache" / "fork-ops",
    }
    if any(
        lexical_root == user_root or lexical_root.is_relative_to(user_root)
        for user_root in user_global_roots
    ):
        try:
            relative_to_home = lexical_root.relative_to(home)
        except ValueError:
            pass
        else:
            return "user-global", relative_to_home.as_posix()
    if scan_profile != "full-breadth":
        return "operator-source-root", "operator-provided"
    repo_base = _full_breadth_repo_base()
    try:
        relative_to_home = lexical_root.relative_to(home)
    except ValueError:
        relative_to_home = None
    if relative_to_home is not None:
        rel = relative_to_home.as_posix()
        if rel in FULL_BREADTH_USER_ROOTS:
            return "user-global", rel
    if repo_base is not None:
        for name in _full_breadth_maintained_repos():
            if lexical_root == repo_base / name:
                return "maintained-fork", name
        for name in _full_breadth_adjacent_repos():
            if lexical_root == repo_base / name:
                return "adjacent-root", name
    return "operator-source-root", "operator-provided"


def _workflow_root_files(
    root: Path,
    budget: _OperationBudget,
    seen_files: set[tuple[int, int]],
) -> Iterable[tuple[Path, bytes]]:
    try:
        root_stat = os.stat(root, follow_symlinks=False)
    except OSError:
        budget.mark_incomplete("scan.root_unresolvable", str(root))
        return
    if stat.S_ISLNK(root_stat.st_mode):
        budget.mark_incomplete("scan.root_symlink_rejected", str(root))
        return
    if stat.S_ISREG(root_stat.st_mode):
        if root.suffix.lower() not in _CANDIDATE_FILE_SUFFIXES:
            return
        try:
            bound_parent = _bind_repository(root.parent)
        except OSError:
            budget.mark_incomplete("scan.root_parent_open_failed", str(root))
            return
        try:
            try:
                current_stat = _bound_lstat(bound_parent, root.name)
                identity = (root_stat.st_dev, root_stat.st_ino)
                if (
                    not stat.S_ISREG(current_stat.st_mode)
                    or (current_stat.st_dev, current_stat.st_ino) != identity
                ):
                    budget.mark_incomplete("scan.root_changed", str(root))
                    return
                raw_bytes = _read_bound_regular_file(bound_parent, root.name, budget=budget)
                after_stat = _bound_lstat(bound_parent, root.name)
            except (OSError, _BoundedReadError) as exc:
                code = exc.code if isinstance(exc, _BoundedReadError) else "read.failed"
                budget.mark_incomplete(code, str(root))
                return
            if (
                (after_stat.st_dev, after_stat.st_ino) != identity
                or not _repository_path_has_identity(bound_parent)
            ):
                budget.mark_incomplete("scan.root_changed", str(root))
                return
            if identity not in seen_files:
                seen_files.add(identity)
                yield root, raw_bytes
                try:
                    final_stat = _bound_lstat(bound_parent, root.name)
                except OSError:
                    budget.mark_incomplete("scan.root_changed", str(root))
                    return
                if (
                    (final_stat.st_dev, final_stat.st_ino) != identity
                    or not _repository_path_has_identity(bound_parent)
                ):
                    budget.mark_incomplete("scan.root_changed", str(root))
        finally:
            try:
                if not _repository_path_has_identity(bound_parent):
                    budget.mark_incomplete("scan.root_changed", str(root))
                else:
                    try:
                        closing_stat = _bound_lstat(bound_parent, root.name)
                    except OSError:
                        budget.mark_incomplete("scan.root_changed", str(root))
                    else:
                        if (closing_stat.st_dev, closing_stat.st_ino) != (
                            root_stat.st_dev,
                            root_stat.st_ino,
                        ):
                            budget.mark_incomplete("scan.root_changed", str(root))
            finally:
                try:
                    bound_parent.close()
                except OSError:
                    budget.mark_incomplete("scan.root_close_failed", str(root))
        return
    if not stat.S_ISDIR(root_stat.st_mode):
        budget.mark_incomplete("scan.root_special_file_rejected", str(root))
        return
    try:
        bound_root = _bind_repository(root)
    except OSError:
        budget.mark_incomplete("scan.root_open_failed", str(root))
        return
    files: list[tuple[Path, bytes]] = []
    try:
        seen_directories: set[tuple[int, int]] = set()
        for relative_path in _scan_bound_directory(
            bound_root,
            Path("."),
            budget=budget,
            suffixes=_CANDIDATE_FILE_SUFFIXES,
            skip_dirs=_CANDIDATE_SCAN_SKIP_DIRS,
            depth=0,
            seen_directories=seen_directories,
        ):
            try:
                file_stat = _bound_lstat(bound_root, relative_path)
                identity = (file_stat.st_dev, file_stat.st_ino)
                if identity in seen_files:
                    continue
                raw_bytes = _read_bound_regular_file(
                    bound_root,
                    relative_path,
                    budget=budget,
                )
            except (OSError, _BoundedReadError) as exc:
                code = exc.code if isinstance(exc, _BoundedReadError) else "read.failed"
                budget.mark_incomplete(code, relative_path.as_posix())
                continue
            seen_files.add(identity)
            files.append((root / relative_path, raw_bytes))
        if not _repository_path_has_identity(bound_root):
            budget.mark_incomplete("scan.root_changed", str(root))
            files.clear()
        for path, raw_bytes in files:
            if not _repository_path_has_identity(bound_root):
                budget.mark_incomplete("scan.root_changed", str(root))
                return
            yield path, raw_bytes
            if not _repository_path_has_identity(bound_root):
                budget.mark_incomplete("scan.root_changed", str(root))
                return
    finally:
        if not _repository_path_has_identity(bound_root):
            budget.mark_incomplete("scan.root_changed", str(root))
        try:
            bound_root.close()
        except OSError:
            budget.mark_incomplete("scan.root_close_failed", str(root))


def _workflow_inventory_entry(
    root: Path,
    path: Path,
    contracts: dict[str, WorkflowContract],
    *,
    source_scope: str = "operator-source-root",
    raw_bytes: bytes,
) -> dict[str, Any] | None:
    for excluded_path in MIGRATION_DISCOVERY_EXCLUDED_PATHS:
        excluded_parts = Path(excluded_path).parts
        if tuple(path.parts[-len(excluded_parts) :]) == excluded_parts:
            return None
    raw_text = raw_bytes.decode(errors="ignore")
    source_path = path.relative_to(root).as_posix() if path != root else path.name
    source_kind = _workflow_source_kind(root, path, raw_text, source_scope)
    signals = _workflow_inventory_signals(source_path, raw_text, source_kind)
    if not signals:
        return None
    entry_id = _workflow_inventory_entry_id(root, path)
    target = _workflow_catalog_target(signals, source_kind, raw_text)
    coverage_status = _workflow_coverage_status(target, contracts)
    return {
        "id": entry_id,
        "source_root": str(root),
        "source_scope": source_scope,
        "source_path": source_path,
        "source_kind": source_kind,
        "material_scope": _workflow_material_scope(
            source_kind,
            source_path,
            path,
            raw_text,
            source_scope,
        ),
        "content_sha256": hashlib.sha256(raw_bytes).hexdigest(),
        "candidate_operator_intent": _workflow_operator_intent(target, signals, source_kind),
        "likely_workflow_catalog_target": target,
        "coverage_status": coverage_status,
        "evidence": _workflow_inventory_evidence(entry_id, raw_text, signals),
    }


def _workflow_inventory_entry_id(root: Path, path: Path) -> str:
    digest = hashlib.sha256(f"{root}\0{path}".encode()).hexdigest()
    return f"workflow-inventory:{digest[:16]}"


def _workflow_source_kind(
    root: Path,
    path: Path,
    raw_text: str,
    source_scope: str,
) -> str:
    rel_parts = path.relative_to(root).parts if path != root else path.parts[-1:]
    lowered_text = raw_text.lower()
    if path.name in {"AGENTS.md", "CLAUDE.md"}:
        return "agent-instruction"
    if path.name == "SKILL.md":
        return "global-skill" if source_scope == "user-global" else "repo-local-skill"
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
    source_scope: str,
) -> str:
    lowered_text = raw_text.lower()
    if source_kind == "global-skill":
        return "reusable-workflow-material"
    if source_kind in {"repo-local-skill", "agent-instruction", "config"}:
        return "fork-local-authority-material"
    if source_kind in {"policy", "gate"}:
        if _workflow_path_or_content_is_fork_local_authority(
            source_path,
            path,
            lowered_text,
            source_scope,
        ):
            return "fork-local-authority-material"
        return "reusable-workflow-material"
    if _workflow_path_or_content_is_fork_local_authority(
        source_path,
        path,
        lowered_text,
        source_scope,
    ):
        return "fork-local-authority-material"
    return "reusable-workflow-material"


def _workflow_path_or_content_is_fork_local_authority(
    source_path: str,
    path: Path,
    lowered_text: str,
    source_scope: str,
) -> bool:
    lowered_path = source_path.lower()
    path_parts = tuple(part.lower() for part in path.parts)
    user_global_agents_path = source_scope == "user-global"
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
        return "migration-blocker-explanation"
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
        "migration-blocker-explanation": (
            "Explain a Fork Ops blocker and route the next safe action."
        ),
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
    if contract.implementation_extent == "implemented":
        return "covered-implemented"
    if contract.implementation_extent == "partial":
        return "covered-partial"
    return "cataloged-planned"


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
                "implementation_extent": contract.implementation_extent,
                "available_operations": [
                    operation.id for operation in contract.operations if operation.available
                ],
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
    return sorted(candidates, key=_candidate_target_and_source_path_sort_key)


def _workflow_inventory_accounting_records(
    entries: list[dict[str, Any]],
    source_root_records: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    records = [_accounting_record_from_workflow_entry(entry) for entry in entries]
    for root in source_root_records:
        if root.get("status") == "scanned":
            continue
        records.append(_accounting_record_from_unassessed_root(root))
    return sorted(
        records,
        key=_accounting_record_sort_key,
    )


def _validate_workflow_accounting(
    entries: list[dict[str, Any]],
    source_root_records: list[dict[str, Any]],
    accounting_records: list[dict[str, Any]],
    follow_up_candidates: list[dict[str, Any]],
) -> None:
    expected_entry_ids = sorted(str(entry["id"]) for entry in entries)
    actual_entry_ids = sorted(
        str(record.get("source_entry_id", ""))
        for record in accounting_records
        if record.get("source_entry_id")
    )
    if actual_entry_ids != expected_entry_ids:
        raise ForkOpsError(
            "Workflow inventory accounting must map every scanned entry exactly once."
        )
    expected_unassessed_roots = sorted(
        str(root.get("path", ""))
        for root in source_root_records
        if root.get("status") != "scanned"
    )
    actual_unassessed_roots = sorted(
        str(record.get("source_root", ""))
        for record in accounting_records
        if record.get("source_kind") == "source-root"
        and record.get("accounting_status") == "unassessed"
    )
    if actual_unassessed_roots != expected_unassessed_roots:
        raise ForkOpsError(
            "Workflow inventory accounting must map every unassessed source root."
        )
    _validate_accounting_follow_up_coverage(accounting_records, follow_up_candidates)


def _validate_accounting_follow_up_coverage(
    accounting_records: list[dict[str, Any]],
    follow_up_candidates: list[dict[str, Any]],
) -> None:
    candidate_record_ids = {
        str(candidate.get("accounting_record_id", ""))
        for candidate in follow_up_candidates
        if candidate.get("accounting_record_id")
    }
    missing = [
        str(record.get("id", ""))
        for record in accounting_records
        if _accounting_status_needs_follow_up(str(record.get("accounting_status", "")))
        and str(record.get("id", "")) not in candidate_record_ids
    ]
    if missing:
        raise ForkOpsError(
            "Accounting follow-up candidates are required for planned, candidate, "
            "and unassessed records."
        )


def _accounting_record_from_workflow_entry(entry: dict[str, Any]) -> dict[str, Any]:
    status = _accounting_status_for_workflow_entry(entry)
    target = _accounting_target_for_workflow_entry(entry, status)
    follow_up_id = _follow_up_id_for_accounting(
        entry["source_scope"],
        entry["source_root"],
        entry["source_path"],
        entry["likely_workflow_catalog_target"],
    )
    record: dict[str, Any] = {
        "id": _accounting_record_id(
            entry["source_scope"],
            entry["source_root"],
            entry["source_path"],
        ),
        "source_entry_id": entry["id"],
        "source_scope": entry["source_scope"],
        "source_root": entry["source_root"],
        "source_path": entry["source_path"],
        "source_kind": entry["source_kind"],
        "material_scope": entry["material_scope"],
        "accounting_status": status,
        "coverage_status": entry["coverage_status"],
        "target_surface_type": target["type"],
        "target_workflow_id": target.get("workflow_id", ""),
        "target_path": target.get("path", ""),
        "reason": _accounting_reason(status, entry),
        "next_action": _accounting_next_action(status, entry),
    }
    if _accounting_status_needs_follow_up(status):
        record["follow_up_id"] = follow_up_id
    else:
        record["follow_up_id"] = ""
    return record


def _accounting_status_for_workflow_entry(entry: dict[str, Any]) -> str:
    material_scope = str(entry.get("material_scope", ""))
    source_kind = str(entry.get("source_kind", ""))
    if material_scope == "fork-local-authority-material":
        if source_kind == "config":
            return "fork_local_config"
        return "retained_fork_local_authority"
    coverage_status = str(entry.get("coverage_status", ""))
    if coverage_status == "covered-implemented":
        return "implemented_workflow"
    if coverage_status == "covered-partial":
        return "partial_workflow"
    if coverage_status == "cataloged-planned":
        return "planned_workflow"
    return "repo_ops_candidate"


def _accounting_target_for_workflow_entry(
    entry: dict[str, Any],
    status: str,
) -> dict[str, str]:
    if status in {"implemented_workflow", "partial_workflow", "planned_workflow"}:
        return {
            "type": "workflow",
            "workflow_id": str(entry.get("likely_workflow_catalog_target", "")),
        }
    if status == "fork_local_config":
        return {"type": "fork_local_config", "path": str(entry.get("source_path", ""))}
    if status == "retained_fork_local_authority":
        return {"type": "fork_local_authority", "path": str(entry.get("source_path", ""))}
    if status == "repo_ops_candidate":
        return {
            "type": "repo_ops_candidate",
            "workflow_id": str(entry.get("likely_workflow_catalog_target", "")),
        }
    if status == "out_of_scope":
        return {"type": "none"}
    return {"type": "unassessed"}


def _accounting_record_from_unassessed_root(root: dict[str, Any]) -> dict[str, Any]:
    source_root = str(root.get("path", ""))
    root_status = str(root.get("status", "unresolvable"))
    record_id = _accounting_record_id(str(root.get("source_scope", "")), source_root, "")
    return {
        "id": record_id,
        "source_entry_id": "",
        "source_scope": str(root.get("source_scope", "operator-source-root")),
        "source_root": source_root,
        "source_path": "",
        "source_kind": "source-root",
        "material_scope": "unassessed-source-root",
        "accounting_status": "unassessed",
        "coverage_status": "unassessed",
        "target_surface_type": "unassessed_area",
        "target_workflow_id": "",
        "target_path": "",
        "reason": (
            "The source root could not be resolved."
            if root_status == "unresolvable"
            else "The source root is not a regular file or directory."
        ),
        "next_action": (
            "Resolve or remove this source root."
            if root_status == "unresolvable"
            else "Replace or remove the rejected source root."
        ),
        "follow_up_id": _follow_up_id_for_accounting(
            str(root.get("source_scope", "operator-source-root")),
            source_root,
            "",
            "unassessed-source-root",
        ),
    }


def _equipment_preflight_accounting_records(
    repo: Path,
    migration_map: list[dict[str, Any]],
    workflow_inventory: dict[str, Any] | None,
    unassessed_areas: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    records = [
        _accounting_record_from_migration_entry(repo, entry) for entry in migration_map
    ]
    if workflow_inventory:
        records.extend(copy.deepcopy(workflow_inventory.get("accounting_records", [])))
    for area in unassessed_areas:
        if area.get("path"):
            continue
        records.append(_accounting_record_from_unassessed_area(area))
    return _dedupe_accounting_records(records)


def _accounting_record_from_migration_entry(
    repo: Path,
    entry: dict[str, Any],
) -> dict[str, Any]:
    disposition = str(entry.get("disposition", {}).get("type", ""))
    status = _accounting_status_for_source_disposition(disposition)
    source_path = str(entry.get("source_path", ""))
    record: dict[str, Any] = {
        "id": _accounting_record_id("repo-local", str(repo), source_path),
        "source_entry_id": str(entry.get("id", "")),
        "source_scope": "repo-local",
        "source_root": str(repo),
        "source_path": source_path,
        "source_kind": str(entry.get("source_kind", "")),
        "material_scope": "fork-local-source-material",
        "accounting_status": status,
        "coverage_status": disposition or "unknown",
        "target_surface_type": str(entry.get("target_surface", {}).get("type", "")),
        "target_workflow_id": str(entry.get("target_surface", {}).get("workflow_id", "")),
        "target_path": str(entry.get("target_surface", {}).get("path", "")),
        "reason": _accounting_reason_for_source_disposition(disposition),
        "next_action": _accounting_next_action_for_source_disposition(disposition),
    }
    if _accounting_status_needs_follow_up(status):
        record["follow_up_id"] = _follow_up_id_for_accounting(
            "repo-local",
            str(repo),
            source_path,
            disposition,
        )
    else:
        record["follow_up_id"] = ""
    return record


def _accounting_status_for_source_disposition(disposition: str) -> str:
    if disposition == "extracted_into_config":
        return "fork_local_config"
    if disposition == "retained_as_fork_local_authority":
        return "retained_fork_local_authority"
    if disposition == "mapped_to_workflow_backlog":
        return "planned_workflow"
    if disposition == "irrelevant_to_fork_ops":
        return "out_of_scope"
    return "unassessed"


def _accounting_record_from_unassessed_area(area: dict[str, Any]) -> dict[str, Any]:
    scope = str(area.get("scope", area.get("source_scope", "unassessed")))
    path = str(area.get("path", ""))
    record_id = _accounting_record_id(scope, str(area.get("source_root", "")), path)
    return {
        "id": record_id,
        "source_entry_id": "",
        "source_scope": scope,
        "source_root": str(area.get("source_root", "")),
        "source_path": path,
        "source_kind": "unassessed-area",
        "material_scope": "unassessed-area",
        "accounting_status": "unassessed",
        "coverage_status": "unassessed",
        "target_surface_type": "unassessed_area",
        "target_workflow_id": "",
        "target_path": path,
        "reason": str(area.get("reason", "Equipment area has not been assessed.")),
        "next_action": str(area.get("next_action", "Scan, accept risk for, or keep limits.")),
        "follow_up_id": _follow_up_id_for_accounting(
            scope,
            str(area.get("source_root", "")),
            path,
            "unassessed",
        ),
    }


def _dedupe_accounting_records(records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    deduped: list[dict[str, Any]] = []
    seen: set[str] = set()
    for record in records:
        record_id = str(record.get("id", ""))
        if record_id in seen:
            continue
        seen.add(record_id)
        deduped.append(record)
    return sorted(
        deduped,
        key=_accounting_record_sort_key,
    )


def _accounting_follow_up_candidates(
    accounting_records: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    candidates: list[dict[str, Any]] = []
    seen: set[str] = set()
    for record in accounting_records:
        if not _accounting_status_needs_follow_up(str(record.get("accounting_status", ""))):
            continue
        follow_up_id = str(record.get("follow_up_id", ""))
        if not follow_up_id or follow_up_id in seen:
            continue
        seen.add(follow_up_id)
        candidates.append(
            {
                "id": follow_up_id,
                "accounting_record_id": str(record.get("id", "")),
                "audience_scope": _follow_up_audience_scope(record),
                "status": "candidate",
                "target_tracker": _follow_up_target_tracker(record),
                "title": _follow_up_title(record),
                "reason": str(record.get("reason", "")),
                "next_action": _follow_up_next_action(record),
            }
        )
    return candidates


def _accounting_status_needs_follow_up(status: str) -> bool:
    return status in {
        "partial_workflow",
        "planned_workflow",
        "repo_ops_candidate",
        "unassessed",
    }


def _follow_up_audience_scope(record: dict[str, Any]) -> str:
    if str(record.get("source_scope")) == "user-global":
        return "user-specific"
    return "team-wide"


def _follow_up_target_tracker(record: dict[str, Any]) -> str:
    if _follow_up_audience_scope(record) == "user-specific":
        return "user-follow-up-registry"
    return "github-issues"


def _follow_up_title(record: dict[str, Any]) -> str:
    workflow_id = str(record.get("target_workflow_id", ""))
    if workflow_id:
        return f"Account for {workflow_id} behavior"
    subject = (
        str(record.get("source_path", ""))
        or str(record.get("source_root", ""))
        or str(record.get("source_scope", ""))
        or str(record.get("id", ""))
    )
    return f"Account for {subject}"


def _follow_up_next_action(record: dict[str, Any]) -> str:
    if _follow_up_audience_scope(record) == "user-specific":
        return "Record in the user follow-up registry or resolve the user-scoped equipment gap."
    return "Create or link a durable GitHub issue for this follow-up candidate."


def _accounting_record_id(source_scope: str, source_root: str, source_path: str) -> str:
    return f"accounting:{_short_digest(f'{source_scope}:{source_root}:{source_path}')}"


def _follow_up_id_for_accounting(
    source_scope: str,
    source_root: str,
    source_path: str,
    target: str,
) -> str:
    return f"follow-up:{_short_digest(f'{source_scope}:{source_root}:{source_path}:{target}')}"


def _accounting_reason(status: str, entry: dict[str, Any]) -> str:
    workflow_id = str(entry.get("likely_workflow_catalog_target", ""))
    if status == "implemented_workflow":
        return f"{workflow_id} is implemented in Fork Ops."
    if status == "partial_workflow":
        return f"{workflow_id} has only some named operations implemented."
    if status == "planned_workflow":
        return f"{workflow_id} is cataloged but not implemented."
    if status == "fork_local_config":
        return "This config remains fork-local authority."
    if status == "retained_fork_local_authority":
        return "This source remains retained fork-local authority."
    if status == "repo_ops_candidate":
        return "This reusable behavior is a future Repo Ops or workflow-catalog candidate."
    if status == "out_of_scope":
        return "This source is outside Fork Ops behavior."
    return "This source has not been assessed enough for coverage claims."


def _accounting_next_action(status: str, entry: dict[str, Any]) -> str:
    if status == "implemented_workflow":
        return "Keep coverage evidence visible in inventory output."
    if status == "partial_workflow":
        return "Create or link follow-up work for unavailable named operations."
    if status == "planned_workflow":
        return "Create or link a durable follow-up issue for the planned workflow."
    if status == "fork_local_config":
        return "Retain as fork-local config authority."
    if status == "retained_fork_local_authority":
        return "Retain and read this fork-local authority until replacement coverage validates."
    if status == "repo_ops_candidate":
        return "Track as a future Repo Ops or workflow-catalog follow-up."
    if status == "out_of_scope":
        return "No Fork Ops action is required."
    return "Resolve the unassessed area before making replacement coverage claims."


def _accounting_reason_for_source_disposition(disposition: str) -> str:
    return {
        "extracted_into_config": "Machine-actionable facts are represented in proposed config.",
        "retained_as_fork_local_authority": "The source remains retained fork-local authority.",
        "mapped_to_workflow_backlog": "The source maps to planned workflow follow-up work.",
        "irrelevant_to_fork_ops": "The source does not describe fork ops behavior.",
        "unsupported_extractor_shape": "The source was relevant but not semantically extracted.",
        "needs_human_decision": "The source requires an operator decision.",
        "deferred_with_rationale": (
            "The source requires migration work outside this execution slice."
        ),
    }.get(disposition, "The source has not been assessed enough for coverage claims.")


def _accounting_next_action_for_source_disposition(disposition: str) -> str:
    return {
        "extracted_into_config": "Review proposed config before creating Fork Ops config.",
        "retained_as_fork_local_authority": (
            "Retain and read this authority until replacement coverage validates."
        ),
        "mapped_to_workflow_backlog": (
            "Create or link a durable follow-up issue for the workflow gap."
        ),
        "irrelevant_to_fork_ops": "No Fork Ops action is required.",
        "unsupported_extractor_shape": "Review, retain, or improve semantic extraction.",
        "needs_human_decision": "Record the operator decision before proceeding.",
        "deferred_with_rationale": "Keep as deferred migration work with rationale.",
    }.get(disposition, "Resolve the unassessed area before making coverage claims.")


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
        "identified": "Authority identifies the maintained fork and its local surfaces.",
        "scoutable": "Authority identifies upstream sources and fork remotes for inspection.",
        "track-aware": (
            "Authority identifies release channels and upstream tracks for operations that "
            "require them."
        ),
        "sync-ready": "Authority defines sync baselines and guarded history policy.",
        "review-ready": "Authority defines review, publication, and local gate policy.",
        "provenance-ready": "Authority defines required provenance gates.",
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
    if isinstance(current, _EMPTY_REQUIREMENT_TYPES) and not current:
        return False
    return True


def _path_value(config: dict[str, Any], dotted_path: str) -> tuple[bool, Any]:
    current: Any = config
    for part in dotted_path.split("."):
        if not isinstance(current, dict) or part not in current:
            return False, None
        current = current[part]
    return True, current


def _source_root_and_path_sort_key(item: dict[str, Any]) -> tuple[str, str]:
    return item["source_root"], item["source_path"]


def _path_sort_key(item: dict[str, Any]) -> str:
    return item["path"]


def _equipment_group_sort_key(item: dict[str, Any]) -> tuple[str, str, str, str]:
    return item["source_scope"], item["source_root"], item["source_path"], item["id"]


def _candidate_target_and_source_path_sort_key(item: dict[str, Any]) -> tuple[str, str]:
    return item["candidate_target"], item["source_path"]


def _accounting_record_sort_key(item: dict[str, Any]) -> tuple[str, str, str]:
    return item["source_scope"], item["source_root"], item["source_path"]


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
                detail={
                    "configured": _public_url_projection(str(expected_url)),
                    "actual": _public_url_projection(actual_url),
                },
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
    return _default_command_runner(command, repo, 10.0)


def _iter_candidate_paths(
    repo: Path,
    budget: _OperationBudget,
    *,
    bound_repo: _BoundRepository | None = None,
) -> Iterable[tuple[Path, _BoundRepository]]:
    owns_repository = bound_repo is None
    if bound_repo is None:
        try:
            bound_repo = _bind_repository(repo)
        except OSError:
            budget.mark_incomplete("scan.root_open_failed", str(repo))
            return
    budget.root_count += 1
    paths: list[Path] = []
    try:
        seen_directories: set[tuple[int, int]] = set()
        for relative_root in (
            Path("AGENTS.md"),
            Path("CLAUDE.md"),
            Path("docs/agents"),
            Path("docs/adr"),
            Path("docs/maintainers"),
            Path(".agents"),
            Path(".codex"),
        ):
            try:
                root_stat = _bound_lstat(bound_repo, relative_root)
            except FileNotFoundError:
                continue
            except OSError:
                budget.mark_incomplete("scan.root_stat_failed", relative_root.as_posix())
                continue
            if stat.S_ISLNK(root_stat.st_mode):
                budget.mark_incomplete("scan.symlink_rejected", relative_root.as_posix())
            elif stat.S_ISREG(root_stat.st_mode):
                if relative_root.suffix.lower() in _CANDIDATE_FILE_SUFFIXES:
                    paths.append(relative_root)
            elif stat.S_ISDIR(root_stat.st_mode):
                for path in _scan_bound_directory(
                    bound_repo,
                    relative_root,
                    budget=budget,
                    suffixes=_CANDIDATE_FILE_SUFFIXES,
                    skip_dirs=_CANDIDATE_SCAN_SKIP_DIRS,
                    depth=len(relative_root.parts),
                    seen_directories=seen_directories,
                ):
                    paths.append(path)
                if any(
                    reason["code"].startswith("limit.")
                    for reason in budget.incomplete_reasons
                ):
                    return
            else:
                budget.mark_incomplete("scan.special_file_rejected", relative_root.as_posix())
        if not _repository_path_has_identity(bound_repo):
            budget.mark_incomplete("scan.root_changed", str(repo))
            paths.clear()
        for path in paths:
            if not _repository_path_has_identity(bound_repo):
                budget.mark_incomplete("scan.root_changed", str(repo))
                return
            yield path, bound_repo
            if not _repository_path_has_identity(bound_repo):
                budget.mark_incomplete("scan.root_changed", str(repo))
                return
    finally:
        if not _repository_path_has_identity(bound_repo):
            budget.mark_incomplete("scan.root_changed", str(repo))
        if owns_repository:
            try:
                bound_repo.close()
            except OSError:
                budget.mark_incomplete("scan.root_close_failed", str(repo))


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
        raw_urls = re.findall(r"https?://[^\s<)]+", line, flags=re.IGNORECASE)
        for raw_url in raw_urls:
            if _url_has_credentials(raw_url):
                continue
            url = _public_url_projection(raw_url)
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
