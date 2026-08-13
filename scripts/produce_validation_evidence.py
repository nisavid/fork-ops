#!/usr/bin/env python3
"""Produce versioned, exact-identity Fork Ops validation evidence."""

from __future__ import annotations

import argparse
import contextlib
import hashlib
import hmac
import json
import os
import platform
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import threading
import time
import tomllib
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Iterator
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, BinaryIO

ARTIFACT_KIND = "validation_evidence_result"
SCHEMA_VERSION = "1.0"
TEST_CONTRACT = "fork-ops-validation-1.1"
MODES = ("locked-source", "fresh-source", "build", "release-preflight", "installed")
EXECUTION_BOUNDARIES = ("local-observational", "container")
SUPPORTED_PYTHON_MINORS = ("3.11", "3.12", "3.13", "3.14")
PYTHON_CONTAINER_IMAGES = {
    "3.11": "python:3.11-slim@sha256:"
    "90744cff8f32887f075c47d747a173ff333e9e98801667af93c357fa9f5e28ff",
    "3.12": "python:3.12-slim@sha256:"
    "229a2c5bfa27522db7815ea81f9bed70af17ccb9de9fc7ad142b1877b5830d36",
    "3.13": "python:3.13-slim@sha256:"
    "ffb752e139c0a19692a43af8d8523b274222dd68eebad5d583b45c2201c6e30a",
    "3.14": "python:3.14-slim@sha256:"
    "a7fb1e634c4a578f9e0bd6327f11a3cde11b7a9395f48e24360c0988bcc5c2bc",
}
DEPENDENCY_SCOPES = ("runtime", "optional", "build", "test", "development")
CLI_LEAVES = (
    "capability report",
    "config init",
    "config show",
    "config validate",
    "migration assess",
    "migration dry-run",
    "migration execute",
    "migration explain-blocker",
    "migration plan",
    "migration preflight",
    "migration propose-config",
    "plugin health",
    "schema check",
    "schema print",
    "workflow catalog",
    "workflow inventory",
)
WORKFLOW_CONTRACT_IDS = (
    "authority-source-routing",
    "blocker-resolution",
    "carried-divergence-review",
    "fork-authority-migration",
    "guarded-sync-execution",
    "operator-onboarding",
    "publication-closeout",
    "review-preparation",
    "upstream-status-assessment",
    "upstream-sync-planning",
    "workflow-migration-inventory",
)
MCP_TOOL_NAMES = (
    "fork_ops_capability_report",
    "fork_ops_config_read",
    "fork_ops_config_validate",
    "fork_ops_equipment_migration_preflight",
    "fork_ops_migration_assessment",
    "fork_ops_migration_blocker_resolution",
    "fork_ops_migration_config_patch",
    "fork_ops_migration_dry_run",
    "fork_ops_migration_execute",
    "fork_ops_migration_plan",
    "fork_ops_plugin_health",
    "fork_ops_schema",
    "fork_ops_workflow_catalog",
    "fork_ops_workflow_migration_inventory",
)
CONTAINER_PYTHON_BOOTSTRAP = r"""
import json
import runpy
import sys

marker = "fork_ops_validation_container_bootstrap"
paths = json.loads(sys.argv[1])
target = sys.argv[2:]
if not isinstance(paths, list) or not all(isinstance(path, str) for path in paths):
    raise TypeError("isolated Python paths must be a string array")
sys.path.extend(paths)
if target[:1] == ["-m"] and len(target) >= 2:
    sys.argv = [target[1], *target[2:]]
    runpy.run_module(target[1], run_name="__main__", alter_sys=True)
elif target[:1] == ["-c"] and len(target) >= 2:
    sys.argv = ["-c", *target[2:]]
    namespace = {"__name__": "__main__"}
    exec(compile(target[1], "<validation-client>", "exec"), namespace)
else:
    raise ValueError("isolated Python requires -m MODULE or -c CODE")
"""
DEFAULT_COMMAND_TIMEOUT_SECONDS = 600.0
DEFAULT_OVERALL_TIMEOUT_SECONDS = 720.0
MAX_SUBPROCESS_OUTPUT_BYTES = 8 * 1024 * 1024
MAX_EVIDENCE_INPUT_BYTES = 16 * 1024 * 1024
MAX_SOURCE_FILE_BYTES = 32 * 1024 * 1024
MAX_SOURCE_FILES = 20_000
MAX_SOURCE_BYTES = 512 * 1024 * 1024
RELEASE_EVIDENCE_MAX_AGE_SECONDS = 24 * 60 * 60
RELEASE_PREFLIGHT_KEY_BYTES = 32
RELEASE_PREFLIGHT_RECEIPT_VERSION = "1.0"
_COMMAND_TIMEOUT_SECONDS = DEFAULT_COMMAND_TIMEOUT_SECONDS
_VALIDATION_DEADLINE: float | None = None
_TRUSTED_UV_EXECUTABLE: Path | None = None
_TRUSTED_UV_SHA256 = ""
_TRUSTED_GIT_EXECUTABLE: Path | None = None
_TRUSTED_GIT_SHA256 = ""
SOURCE_SNAPSHOT_EXCLUDES = {
    ".mypy_cache",
    ".pyrefly_cache",
    ".pytest_cache",
    ".ruff_cache",
    ".venv",
    "__pycache__",
    "build",
    "dist",
}


@dataclass(frozen=True)
class CandidateContainerBoundary:
    source_repo: Path
    site_packages: Path
    image: str
    host_environment: dict[str, str]
    user: str


class ValidationDeadlineExceeded(RuntimeError):
    """The producer's overall validation-work budget was exhausted."""


class SubprocessOutputLimitExceeded(RuntimeError):
    """A child process exceeded the verifier's captured-output budget."""


@dataclass(frozen=True)
class BoundedProcessResult:
    returncode: int
    stdout: bytes
    stderr: bytes
    stdout_bytes: int
    stderr_bytes: int


def _deadline_checkpoint() -> None:
    if _VALIDATION_DEADLINE is not None and time.monotonic() >= _VALIDATION_DEADLINE:
        raise ValidationDeadlineExceeded("Validation overall deadline was exhausted.")


def _effective_timeout(limit: float | None = None) -> float:
    _deadline_checkpoint()
    timeout = (
        _COMMAND_TIMEOUT_SECONDS
        if limit is None
        else min(
            _COMMAND_TIMEOUT_SECONDS,
            limit,
        )
    )
    if _VALIDATION_DEADLINE is not None:
        timeout = min(timeout, max(_VALIDATION_DEADLINE - time.monotonic(), 0.001))
    return timeout


def _terminate_process_tree(process: subprocess.Popen[bytes]) -> None:
    if os.name == "posix":
        with contextlib.suppress(OSError):
            os.killpg(process.pid, 15)
    else:
        if process.poll() is not None:
            return
        with contextlib.suppress(OSError):
            process.terminate()
    with contextlib.suppress(subprocess.TimeoutExpired):
        process.wait(timeout=0.5)
    if process.poll() is None:
        if os.name == "posix":
            with contextlib.suppress(OSError):
                os.killpg(process.pid, 9)
        else:
            with contextlib.suppress(OSError):
                process.kill()
        with contextlib.suppress(subprocess.TimeoutExpired):
            process.wait(timeout=0.5)


def _run_bounded_process(
    command: list[str],
    *,
    cwd: Path,
    env: dict[str, str] | None,
    timeout: float,
    max_output_bytes: int = MAX_SUBPROCESS_OUTPUT_BYTES,
) -> BoundedProcessResult:
    process = subprocess.Popen(
        command,
        cwd=cwd,
        env=env,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        start_new_session=os.name == "posix",
    )
    streams = (process.stdout, process.stderr)
    if any(stream is None for stream in streams):
        _terminate_process_tree(process)
        raise RuntimeError("Bounded subprocess pipes were unavailable")
    overflow = threading.Event()
    byte_lock = threading.Lock()
    total_bytes = 0
    stream_bytes = [0, 0]
    buffers = (bytearray(), bytearray())

    def drain(index: int) -> None:
        nonlocal total_bytes
        stream = streams[index]
        assert stream is not None
        with stream:
            while chunk := stream.read(64 * 1024):
                with byte_lock:
                    stream_bytes[index] += len(chunk)
                    remaining = max_output_bytes - total_bytes
                    total_bytes += len(chunk)
                    if remaining > 0:
                        buffers[index].extend(chunk[:remaining])
                    if total_bytes > max_output_bytes:
                        overflow.set()

    readers = [threading.Thread(target=drain, args=(index,), daemon=True) for index in range(2)]
    for reader in readers:
        reader.start()
    deadline = time.monotonic() + timeout
    timed_out = False
    while process.poll() is None:
        if overflow.is_set():
            _terminate_process_tree(process)
            break
        if time.monotonic() >= deadline:
            timed_out = True
            _terminate_process_tree(process)
            break
        time.sleep(0.01)
    returncode = process.poll()
    for reader in readers:
        reader.join(timeout=0.1)
    if any(reader.is_alive() for reader in readers):
        _terminate_process_tree(process)
        for reader in readers:
            reader.join(timeout=0.5)
        raise SubprocessOutputLimitExceeded("A child process retained a captured-output pipe")
    if timed_out:
        raise subprocess.TimeoutExpired(command, timeout)
    if overflow.is_set():
        raise SubprocessOutputLimitExceeded(
            f"Combined subprocess output exceeded {max_output_bytes} bytes"
        )
    if returncode is None:
        raise RuntimeError("Subprocess did not reach a terminal state")
    return BoundedProcessResult(
        returncode,
        bytes(buffers[0]),
        bytes(buffers[1]),
        stream_bytes[0],
        stream_bytes[1],
    )


def _trusted_git_executable() -> Path:
    global _TRUSTED_GIT_EXECUTABLE, _TRUSTED_GIT_SHA256
    if _TRUSTED_GIT_EXECUTABLE is None:
        executable = _trusted_executable("git")
        _TRUSTED_GIT_EXECUTABLE = executable
        _TRUSTED_GIT_SHA256 = _sha256(executable)
    if _sha256(_TRUSTED_GIT_EXECUTABLE) != _TRUSTED_GIT_SHA256:
        raise RuntimeError("Trusted Git executable changed during validation")
    return _TRUSTED_GIT_EXECUTABLE


def _trusted_executable(command: str) -> Path:
    selected = shutil.which(command)
    if selected is None:
        candidate = Path(command).expanduser()
        if not candidate.is_absolute():
            raise FileNotFoundError(f"{command} is not available on PATH")
        selected = str(candidate)
    executable = Path(selected).resolve(strict=True)
    metadata = executable.stat()
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_mode & 0o111 == 0:
        raise ValueError(f"{command} must resolve to an executable regular file")
    return executable


def _trusted_uv_executable() -> Path:
    if _TRUSTED_UV_EXECUTABLE is None or not _TRUSTED_UV_SHA256:
        raise RuntimeError("Trusted uv identity was not established")
    if _sha256(_TRUSTED_UV_EXECUTABLE) != _TRUSTED_UV_SHA256:
        raise RuntimeError("Trusted uv executable changed during validation")
    return _TRUSTED_UV_EXECUTABLE


@contextlib.contextmanager
def _trusted_git_environment() -> Iterator[dict[str, str]]:
    with tempfile.TemporaryDirectory(prefix="fork-ops-trusted-git-") as temp_dir:
        home = Path(temp_dir) / "home"
        home.mkdir(mode=0o700)
        environment = {
            "GIT_ASKPASS": "",
            "GIT_ATTR_NOSYSTEM": "1",
            "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_EXTERNAL_DIFF": "",
            "GIT_OPTIONAL_LOCKS": "0",
            "GIT_PAGER": "cat",
            "GIT_PROTOCOL_FROM_USER": "0",
            "GIT_TERMINAL_PROMPT": "0",
            "HOME": str(home),
            "LANG": "C",
            "LC_ALL": "C",
            "PAGER": "cat",
            "PATH": os.defpath,
        }
        if os.name == "nt":
            for name in ("COMSPEC", "PATHEXT", "SYSTEMROOT", "WINDIR"):
                if value := os.environ.get(name):
                    environment[name] = value
        yield environment


def _trusted_git_command(arguments: list[str]) -> list[str]:
    return [
        str(_trusted_git_executable()),
        "-c",
        "core.fsmonitor=false",
        "-c",
        f"core.hooksPath={os.devnull}",
        "-c",
        f"core.attributesFile={os.devnull}",
        "-c",
        "core.untrackedCache=false",
        "-c",
        "credential.helper=",
        "-c",
        "diff.external=",
        "-c",
        "protocol.allow=never",
        *arguments,
    ]


def _run_trusted_git(repo: Path, arguments: list[str]) -> BoundedProcessResult:
    with _trusted_git_environment() as environment:
        return _run_bounded_process(
            _trusted_git_command(arguments),
            cwd=repo,
            env=environment,
            timeout=_effective_timeout(),
        )


@contextlib.contextmanager
def _open_regular_nofollow(path: Path) -> Iterator[BinaryIO]:
    lexical = path.lstat()
    if not stat.S_ISREG(lexical.st_mode):
        raise ValueError(f"{path} must be a regular non-symlink file")
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    with os.fdopen(descriptor, "rb") as source:
        opened = os.fstat(source.fileno())
        if (
            not stat.S_ISREG(opened.st_mode)
            or opened.st_dev != lexical.st_dev
            or opened.st_ino != lexical.st_ino
        ):
            raise ValueError(f"{path} changed before its no-follow read")
        yield source
        finished = os.fstat(source.fileno())
        if (
            finished.st_size != opened.st_size
            or finished.st_mtime_ns != opened.st_mtime_ns
            or finished.st_ctime_ns != opened.st_ctime_ns
        ):
            raise RuntimeError(f"{path} changed during its no-follow read")


def _sha256(path: Path) -> str:
    _deadline_checkpoint()
    digest = hashlib.sha256()
    with _open_regular_nofollow(path) as source:
        bytes_read = 0
        while chunk := source.read(1024 * 1024):
            _deadline_checkpoint()
            bytes_read += len(chunk)
            digest.update(chunk)
        if bytes_read != os.fstat(source.fileno()).st_size:
            raise RuntimeError(f"{path} changed during its no-follow read")
    return digest.hexdigest()


def _read_bytes(path: Path, *, max_bytes: int = MAX_EVIDENCE_INPUT_BYTES) -> bytes:
    _deadline_checkpoint()
    chunks: list[bytes] = []
    with _open_regular_nofollow(path) as source:
        if os.fstat(source.fileno()).st_size > max_bytes:
            raise ValueError(f"{path} exceeds the {max_bytes}-byte input limit")
        bytes_read = 0
        while chunk := source.read(1024 * 1024):
            _deadline_checkpoint()
            chunks.append(chunk)
            bytes_read += len(chunk)
            if bytes_read > max_bytes:
                raise ValueError(f"{path} exceeds the {max_bytes}-byte input limit")
        if bytes_read != os.fstat(source.fileno()).st_size:
            raise RuntimeError(f"{path} changed during its no-follow read")
    return b"".join(chunks)


def _read_text(path: Path) -> str:
    return _read_bytes(path).decode("utf-8")


@contextlib.contextmanager
def _open_directory_nofollow(path: Path, *, create: bool = False) -> Iterator[int]:
    absolute = Path(os.path.abspath(path))
    if os.name == "nt":
        _require_windows_plain_parent_chain(absolute)
        descriptor = os.open(absolute, os.O_RDONLY)
        try:
            if not stat.S_ISDIR(os.fstat(descriptor).st_mode):
                raise ValueError(f"Evidence output parent must be a directory: {absolute}")
            yield descriptor
        finally:
            os.close(descriptor)
        return

    flags = os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(absolute.anchor, flags)
    try:
        for component in absolute.parts[1:]:
            try:
                child = os.open(component, flags, dir_fd=descriptor)
            except FileNotFoundError:
                if not create:
                    raise
                os.mkdir(component, mode=0o700, dir_fd=descriptor)
                child = os.open(component, flags, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = child
        yield descriptor
    finally:
        os.close(descriptor)


def _atomic_write_text_nofollow(path: Path, rendered: str) -> None:
    absolute = Path(os.path.abspath(path))
    if absolute.name in {"", ".", ".."}:
        raise ValueError("Evidence output must name a file")
    payload = rendered.encode("utf-8")
    temporary_name = f".{absolute.name}.tmp-{os.urandom(16).hex()}"
    if os.name == "nt":
        _atomic_write_text_windows(absolute, temporary_name, payload)
        return
    with _open_directory_nofollow(absolute.parent, create=True) as parent_descriptor:
        try:
            destination = os.stat(
                absolute.name,
                dir_fd=parent_descriptor,
                follow_symlinks=False,
            )
        except FileNotFoundError:
            destination = None
        if destination is not None and not stat.S_ISREG(destination.st_mode):
            raise ValueError(f"Evidence output must be a regular non-symlink file: {absolute}")
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
        temporary_descriptor = os.open(
            temporary_name,
            flags,
            0o600,
            dir_fd=parent_descriptor,
        )
        try:
            view = memoryview(payload)
            while view:
                written = os.write(temporary_descriptor, view)
                if written <= 0:
                    raise OSError(f"Could not write evidence output {absolute}")
                view = view[written:]
            os.fsync(temporary_descriptor)
        finally:
            os.close(temporary_descriptor)
        try:
            os.replace(
                temporary_name,
                absolute.name,
                src_dir_fd=parent_descriptor,
                dst_dir_fd=parent_descriptor,
            )
            os.fsync(parent_descriptor)
        except BaseException:
            with contextlib.suppress(FileNotFoundError):
                os.unlink(temporary_name, dir_fd=parent_descriptor)
            raise


def _is_windows_reparse_point(metadata: os.stat_result) -> bool:
    return bool(
        getattr(metadata, "st_file_attributes", 0) & stat.FILE_ATTRIBUTE_REPARSE_POINT
    )


def _require_windows_plain_parent_chain(parent: Path) -> None:
    for candidate in (parent, *parent.parents):
        try:
            metadata = candidate.lstat()
        except FileNotFoundError as exc:
            raise ValueError("Evidence output parents must already exist on Windows") from exc
        if stat.S_ISLNK(metadata.st_mode) or _is_windows_reparse_point(metadata):
            raise ValueError(
                f"Evidence output parent must not be a symlink or reparse point: {candidate}"
            )
        if not stat.S_ISDIR(metadata.st_mode):
            raise ValueError(f"Evidence output parent must be a directory: {candidate}")


def _require_windows_regular_destination(path: Path, *, changed: bool = False) -> None:
    try:
        metadata = path.lstat()
    except FileNotFoundError:
        return
    if not stat.S_ISREG(metadata.st_mode) or _is_windows_reparse_point(metadata):
        if changed:
            raise ValueError(f"Evidence output changed before replacement: {path}")
        raise ValueError(f"Evidence output must be a regular non-symlink file: {path}")


def _atomic_write_text_windows(absolute: Path, temporary_name: str, payload: bytes) -> None:
    # Python 3.11 does not expose Windows handle-relative filesystem operations.
    # This advisory-only path rejects every observable reparse/symlink boundary,
    # then uses a native-path replace. It fails closed but cannot eliminate a
    # concurrent parent-swap race the way the POSIX descriptor-relative path can.
    _require_windows_plain_parent_chain(absolute.parent)
    _require_windows_regular_destination(absolute)
    temporary = absolute.parent / temporary_name
    flags = (
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL
        | getattr(os, "O_BINARY", 0)
        | getattr(os, "O_NOINHERIT", 0)
    )
    descriptor = os.open(temporary, flags, 0o600)
    try:
        view = memoryview(payload)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise OSError(f"Could not write evidence output {absolute}")
            view = view[written:]
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    try:
        _require_windows_plain_parent_chain(absolute.parent)
        temporary_metadata = temporary.lstat()
        if not stat.S_ISREG(temporary_metadata.st_mode) or _is_windows_reparse_point(
            temporary_metadata
        ):
            raise ValueError("Evidence output temporary path changed before replacement")
        _require_windows_regular_destination(absolute, changed=True)
        os.replace(temporary, absolute)
    except BaseException:
        with contextlib.suppress(FileNotFoundError):
            temporary.unlink()
        raise


def _require_path_outside_repo(path: Path, repo: Path, label: str) -> Path:
    absolute = Path(os.path.abspath(path))
    lexical_repo = Path(os.path.abspath(repo))
    if absolute == lexical_repo or lexical_repo in absolute.parents:
        raise ValueError(f"{label} must be stored outside the candidate checkout")
    return absolute


def _create_release_preflight_key(path: Path, repo: Path) -> bytes:
    absolute = _require_path_outside_repo(path, repo, "Release preflight key")
    key = os.urandom(RELEASE_PREFLIGHT_KEY_BYTES)
    with _open_directory_nofollow(absolute.parent, create=True) as parent_descriptor:
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(absolute.name, flags, 0o600, dir_fd=parent_descriptor)
        try:
            view = memoryview(key)
            while view:
                written = os.write(descriptor, view)
                if written <= 0:
                    raise OSError("Could not persist the release preflight key")
                view = view[written:]
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        os.fsync(parent_descriptor)
    return key


def _consume_release_preflight_key(path: Path, repo: Path) -> bytes:
    absolute = _require_path_outside_repo(path, repo, "Release preflight key")
    with _open_directory_nofollow(absolute.parent) as parent_descriptor:
        flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(absolute.name, flags, dir_fd=parent_descriptor)
        try:
            opened = os.fstat(descriptor)
            if not stat.S_ISREG(opened.st_mode) or opened.st_size != RELEASE_PREFLIGHT_KEY_BYTES:
                raise ValueError("Release preflight key must be an exact regular key file")
            chunks: list[bytes] = []
            while chunk := os.read(descriptor, RELEASE_PREFLIGHT_KEY_BYTES):
                chunks.append(chunk)
            current = os.stat(
                absolute.name,
                dir_fd=parent_descriptor,
                follow_symlinks=False,
            )
            if current.st_dev != opened.st_dev or current.st_ino != opened.st_ino:
                raise ValueError("Release preflight key changed before consumption")
            os.unlink(absolute.name, dir_fd=parent_descriptor)
            os.fsync(parent_descriptor)
        finally:
            os.close(descriptor)
    key = b"".join(chunks)
    if len(key) != RELEASE_PREFLIGHT_KEY_BYTES:
        raise ValueError("Release preflight key was truncated")
    return key


@contextlib.contextmanager
def _verified_execution_snapshot(
    repo: Path,
    lock_bytes: bytes,
    excluded_paths: list[Path],
    *,
    bound_root_descriptor: int | None = None,
) -> Iterator[tuple[Path, str]]:
    lexical_repo = Path(os.path.abspath(repo))
    excluded = [Path(os.path.abspath(path)) for path in excluded_paths]
    if os.name != "posix":
        raise ValueError("Verified execution snapshots require POSIX no-follow descriptors")
    directory_flags = os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_NOFOLLOW", 0)
    root_descriptor = (
        os.dup(bound_root_descriptor)
        if bound_root_descriptor is not None
        else os.open(lexical_repo, directory_flags)
    )
    root_identity = os.fstat(root_descriptor)
    with tempfile.TemporaryDirectory(prefix="fork-ops-verified-") as temp_dir:
        snapshot = Path(temp_dir) / "repository"
        snapshot.mkdir(mode=0o700)
        try:
            descriptor_repo = Path(f"/proc/self/fd/{root_descriptor}")
            listed = _run_trusted_git(
                descriptor_repo,
                ["ls-files", "-z", "--cached", "--others", "--exclude-standard"],
            )
            if listed.returncode != 0:
                raise subprocess.CalledProcessError(listed.returncode, "git ls-files")
            digest = hashlib.sha256()
            copied_files = 0
            copied_bytes = 0
            lock_written = False
            for raw_path in sorted(raw for raw in listed.stdout.split(b"\0") if raw):
                _deadline_checkpoint()
                relative = Path(os.fsdecode(raw_path))
                if relative.is_absolute() or ".." in relative.parts or not relative.parts:
                    raise ValueError(f"Git returned an unsafe source path: {relative!s}")
                absolute = lexical_repo / relative
                if any(absolute == path or path in absolute.parents for path in excluded):
                    continue
                if SOURCE_SNAPSHOT_EXCLUDES.intersection(relative.parts):
                    continue
                parent_descriptor = os.dup(root_descriptor)
                try:
                    for component in relative.parts[:-1]:
                        child_descriptor = os.open(
                            component,
                            directory_flags,
                            dir_fd=parent_descriptor,
                        )
                        os.close(parent_descriptor)
                        parent_descriptor = child_descriptor
                    metadata = os.stat(
                        relative.name,
                        dir_fd=parent_descriptor,
                        follow_symlinks=False,
                    )
                    if stat.S_ISLNK(metadata.st_mode):
                        raise ValueError(f"Source snapshot rejects symlink: {relative!s}")
                    if not stat.S_ISREG(metadata.st_mode):
                        raise ValueError(f"Source snapshot rejects special file: {relative!s}")
                    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0)
                    flags |= getattr(os, "O_NOFOLLOW", 0)
                    source_descriptor = os.open(
                        relative.name,
                        flags,
                        dir_fd=parent_descriptor,
                    )
                finally:
                    os.close(parent_descriptor)
                with os.fdopen(source_descriptor, "rb") as source:
                    opened = os.fstat(source.fileno())
                    if (
                        opened.st_dev != metadata.st_dev
                        or opened.st_ino != metadata.st_ino
                        or opened.st_mode != metadata.st_mode
                        or opened.st_size != metadata.st_size
                    ):
                        raise RuntimeError(f"Source changed before copying {relative!s}")
                    content_size = opened.st_size
                    if content_size > MAX_SOURCE_FILE_BYTES:
                        raise ValueError(f"Source file exceeds size limit: {relative!s}")
                    copied_files += 1
                    copied_bytes += content_size
                    if copied_files > MAX_SOURCE_FILES or copied_bytes > MAX_SOURCE_BYTES:
                        raise ValueError(
                            "Source snapshot exceeds file-count or aggregate-byte limit"
                        )
                    destination = snapshot / relative
                    destination.parent.mkdir(parents=True, exist_ok=True)
                    destination_flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
                    destination_flags |= getattr(os, "O_NOFOLLOW", 0)
                    destination_descriptor = os.open(
                        destination,
                        destination_flags,
                        0o600,
                    )
                    encoded_path = os.fsencode(relative.as_posix())
                    executable = (
                        b"executable" if opened.st_mode & 0o111 else b"non-executable"
                    )
                    for field in (b"file", executable, encoded_path):
                        digest.update(len(field).to_bytes(8, "big"))
                        digest.update(field)
                    digest.update(content_size.to_bytes(8, "big"))
                    bytes_written = 0
                    try:
                        while chunk := source.read(1024 * 1024):
                            _deadline_checkpoint()
                            bytes_written += len(chunk)
                            if bytes_written > content_size:
                                raise RuntimeError(f"Source changed while copying {relative!s}")
                            digest.update(chunk)
                            view = memoryview(chunk)
                            while view:
                                written = os.write(destination_descriptor, view)
                                if written <= 0:
                                    raise OSError(f"Could not copy source file {relative!s}")
                                view = view[written:]
                        os.fsync(destination_descriptor)
                    finally:
                        os.close(destination_descriptor)
                    finished = os.fstat(source.fileno())
                    if (
                        bytes_written != content_size
                        or finished.st_size != opened.st_size
                        or finished.st_mtime_ns != opened.st_mtime_ns
                        or finished.st_ctime_ns != opened.st_ctime_ns
                    ):
                        raise RuntimeError(f"Source changed while copying {relative!s}")
                    os.chmod(destination, 0o500 if opened.st_mode & 0o111 else 0o400)
                    if relative.as_posix() == "uv.lock":
                        if _read_bytes(destination) != lock_bytes:
                            raise RuntimeError(
                                "Verified uv.lock snapshot differs from the no-follow read"
                            )
                        lock_written = True
            current_root = os.stat(lexical_repo, follow_symlinks=False)
            if (
                current_root.st_dev != root_identity.st_dev
                or current_root.st_ino != root_identity.st_ino
            ):
                raise RuntimeError("Candidate repository root changed while snapshotting")
            if not lock_written:
                raise RuntimeError("Verified snapshot did not include uv.lock")
            yield snapshot, digest.hexdigest()
        finally:
            os.close(root_descriptor)


def _bind_candidate_repository(repo: Path) -> tuple[int, Path, os.stat_result]:
    if os.name != "posix":
        raise ValueError("Candidate repository binding requires POSIX descriptors")
    flags = os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(repo, flags)
    identity = os.fstat(descriptor)
    return descriptor, Path(f"/proc/self/fd/{descriptor}"), identity


def _verify_candidate_repository_binding(
    repo: Path,
    descriptor: int,
    identity: os.stat_result,
) -> None:
    current_descriptor = os.fstat(descriptor)
    current_path = os.stat(repo, follow_symlinks=False)
    for current in (current_descriptor, current_path):
        if current.st_dev != identity.st_dev or current.st_ino != identity.st_ino:
            raise RuntimeError("Candidate repository root changed during validation")


def _run_command(
    check_id: str,
    behavior_classes: list[str],
    required_ids: list[str],
    command: list[str],
    *,
    cwd: Path,
    env: dict[str, str] | None = None,
    allowed_returncodes: frozenset[int] = frozenset({0}),
) -> dict[str, Any]:
    started = time.monotonic()
    execution_command = (
        [str(_trusted_uv_executable()), *command[1:]]
        if command[:1] == ["uv"]
        else command
    )
    if _VALIDATION_DEADLINE is not None and time.monotonic() >= _VALIDATION_DEADLINE:
        return {
            "id": check_id,
            "behavior_classes": behavior_classes,
            "required_ids": required_ids,
            "status": "failed",
            "exit_code": 124,
            "duration_ms": 0,
            "command": command,
            "command_cwd": str(cwd),
            "stdout_tail": "",
            "stderr_tail": "Validation overall deadline was exhausted.",
            "stdout_sha256": hashlib.sha256(b"").hexdigest(),
            "stdout_bytes": 0,
            "stderr_bytes": 0,
            "output_limit_exceeded": False,
            "timed_out": True,
        }
    command_timeout = _effective_timeout()
    try:
        completed = _run_bounded_process(
            execution_command,
            cwd=cwd,
            env=env,
            timeout=command_timeout,
        )
    except subprocess.TimeoutExpired:
        duration_ms = round((time.monotonic() - started) * 1000)
        stdout = ""
        stderr = ""
        return {
            "id": check_id,
            "behavior_classes": behavior_classes,
            "required_ids": required_ids,
            "status": "failed",
            "exit_code": 124,
            "duration_ms": duration_ms,
            "command": command,
            "command_cwd": str(cwd),
            "stdout_tail": stdout[-4000:],
            "stderr_tail": (
                stderr[-3800:] + f"\nCommand timed out after {command_timeout:g} seconds."
            ).lstrip(),
            "stdout_sha256": hashlib.sha256(stdout.encode("utf-8")).hexdigest(),
            "stdout_bytes": 0,
            "stderr_bytes": 0,
            "output_limit_exceeded": False,
            "timed_out": True,
        }
    except (OSError, SubprocessOutputLimitExceeded) as exc:
        duration_ms = round((time.monotonic() - started) * 1000)
        return {
            "id": check_id,
            "behavior_classes": behavior_classes,
            "required_ids": required_ids,
            "status": "failed",
            "exit_code": 126 if isinstance(exc, SubprocessOutputLimitExceeded) else 127,
            "duration_ms": duration_ms,
            "command": command,
            "command_cwd": str(cwd),
            "stdout_tail": "",
            "stderr_tail": str(exc),
            "stdout_sha256": hashlib.sha256(b"").hexdigest(),
            "stdout_bytes": 0,
            "stderr_bytes": 0,
            "output_limit_exceeded": isinstance(exc, SubprocessOutputLimitExceeded),
            "timed_out": False,
        }
    duration_ms = round((time.monotonic() - started) * 1000)
    stdout = completed.stdout.decode("utf-8", errors="replace")
    stderr = completed.stderr.decode("utf-8", errors="replace")
    return {
        "id": check_id,
        "behavior_classes": behavior_classes,
        "required_ids": required_ids,
        "status": "passed" if completed.returncode in allowed_returncodes else "failed",
        "exit_code": completed.returncode,
        "duration_ms": duration_ms,
        "command": command,
        "command_cwd": str(cwd),
        "stdout_tail": stdout[-4000:],
        "stderr_tail": stderr[-4000:],
        "stdout_sha256": hashlib.sha256(completed.stdout).hexdigest(),
        "stdout_bytes": completed.stdout_bytes,
        "stderr_bytes": completed.stderr_bytes,
        "output_limit_exceeded": False,
        "timed_out": False,
        "_stdout_complete": stdout,
        **({"environment_policy": "explicit_minimal"} if env is not None else {}),
    }


def _run_git_check(
    check_id: str,
    behavior_classes: list[str],
    required_ids: list[str],
    arguments: list[str],
    *,
    cwd: Path,
) -> dict[str, Any]:
    with _trusted_git_environment() as environment:
        return _run_command(
            check_id,
            behavior_classes,
            required_ids,
            _trusted_git_command(arguments),
            cwd=cwd,
            env=environment,
        )


def _discard_private_check_payloads(checks: list[dict[str, Any]]) -> None:
    for check in checks:
        check.pop("_stdout_complete", None)


@contextlib.contextmanager
def _minimal_subprocess_environment(root: Path) -> Iterator[dict[str, str]]:
    home = root / "home"
    temp = root / "tmp"
    cache = root / "cache"
    for path in (home, temp, cache):
        path.mkdir(parents=True, mode=0o700, exist_ok=True)
    environment = {
        "HOME": str(home),
        "PATH": os.environ.get("PATH", os.defpath),
        "TMPDIR": str(temp),
        "UV_CACHE_DIR": str(cache),
        "UV_DEFAULT_INDEX": "https://pypi.org/simple",
        "UV_INDEX_STRATEGY": "first-index",
        "UV_KEYRING_PROVIDER": "disabled",
        "UV_NO_BUILD": "1",
        "UV_NO_CONFIG": "1",
        "UV_NO_SOURCES": "1",
        "UV_PYTHON_DOWNLOADS": "never",
    }
    if os.name == "nt":
        for name in ("COMSPEC", "PATHEXT", "SYSTEMROOT", "WINDIR"):
            if value := os.environ.get(name):
                environment[name] = value
    yield environment


def _host_group_container_user() -> str:
    if not hasattr(os, "getuid") or not hasattr(os, "getgid"):
        raise ValueError("Hosted candidate containers require a POSIX host user")
    user_id = os.getuid()
    group_id = os.getgid()
    if user_id <= 0 or group_id <= 0:
        raise ValueError("Hosted candidate containers require a non-root host user")
    return f"65532:{group_id}"


def _make_private_tree_group_writable(path: Path) -> None:
    if not hasattr(os, "getuid") or not hasattr(os, "getgid"):
        raise ValueError("Hosted writable candidate mounts require a POSIX host")
    expected_user = os.getuid()
    expected_group = os.getgid()
    for directory, directory_names, file_names in os.walk(
        path,
        topdown=True,
        followlinks=False,
    ):
        entries = [Path(directory), *[Path(directory) / name for name in directory_names]]
        entries.extend(Path(directory) / name for name in file_names)
        for entry in entries:
            metadata = entry.lstat()
            if stat.S_ISLNK(metadata.st_mode):
                raise ValueError(f"Writable candidate mount must not contain symlinks: {entry}")
            if metadata.st_uid != expected_user or metadata.st_gid != expected_group:
                raise ValueError(f"Writable candidate mount has unexpected ownership: {entry}")
            if stat.S_ISDIR(metadata.st_mode):
                os.chmod(entry, 0o770, follow_symlinks=False)
            elif stat.S_ISREG(metadata.st_mode):
                executable = 0o110 if metadata.st_mode & 0o100 else 0
                os.chmod(entry, 0o660 | executable, follow_symlinks=False)
            else:
                raise ValueError(f"Writable candidate mount has an unsupported entry: {entry}")


def _candidate_container_base(*, user: str = "65532:65532") -> list[str]:
    if re.fullmatch(r"[1-9][0-9]*:[0-9]+", user) is None:
        raise ValueError("Candidate containers require a numeric non-root user and group")
    user_id, group_id = user.split(":", 1)
    return [
        "docker",
        "run",
        "--rm",
        "--network=none",
        "--read-only",
        "--cap-drop=ALL",
        "--security-opt=no-new-privileges",
        "--pid=private",
        "--pids-limit=256",
        "--memory=2g",
        "--cpus=2",
        f"--user={user}",
        "--tmpfs=/home/fork-ops:rw,noexec,nosuid,nodev,size=16m,"
        f"mode=0700,uid={user_id},gid={group_id}",
        "--tmpfs=/tmp:rw,noexec,nosuid,nodev,size=256m,mode=1777",
        "--tmpfs=/run:rw,noexec,nosuid,nodev,size=8m,mode=0755",
        "--env=HOME=/home/fork-ops",
        "--env=PYTHONDONTWRITEBYTECODE=1",
        "--env=PYTHONNOUSERSITE=1",
        "--env=PYTHONSAFEPATH=1",
    ]


def _isolated_python_argv(paths: list[str], python_args: list[str]) -> list[str]:
    return [
        "python",
        "-I",
        "-S",
        "-c",
        CONTAINER_PYTHON_BOOTSTRAP,
        json.dumps(paths, separators=(",", ":")),
        *python_args,
    ]


def _source_candidate_container_command(
    boundary: CandidateContainerBoundary,
    python_args: list[str],
    *,
    scratch: Path | None = None,
) -> list[str]:
    command = [
        *_candidate_container_base(user=boundary.user),
        "--workdir=/workspace",
        f"--mount=type=bind,src={boundary.source_repo},dst=/workspace,readonly",
        f"--mount=type=bind,src={boundary.site_packages},dst=/opt/fork-ops/site-packages,readonly",
    ]
    if scratch is not None:
        command.append(f"--mount=type=bind,src={scratch},dst=/scratch")
    return [
        *command,
        boundary.image,
        *_isolated_python_argv(
            ["/opt/fork-ops/site-packages", "/workspace/plugins/fork-ops/src"],
            python_args,
        ),
    ]


def _prepare_source_candidate_container(
    repo: Path,
    interpreter: str,
    root: Path,
) -> tuple[dict[str, Any], CandidateContainerBoundary | None]:
    python_minor = _python_minor(interpreter)
    image = PYTHON_CONTAINER_IMAGES.get(python_minor)
    environment = root / "environment"
    requirements = root / "source-requirements.txt"
    with _minimal_subprocess_environment(root) as subprocess_env:
        parts = [
            _run_command(
                "candidate_isolation_venv",
                ["candidate_isolation"],
                ["candidate.container_dependencies"],
                ["uv", "venv", "--python", interpreter, str(environment)],
                cwd=repo,
                env=subprocess_env,
            ),
            _run_command(
                "candidate_isolation_export",
                ["candidate_isolation"],
                ["candidate.container_dependencies"],
                [
                    "uv",
                    "export",
                    "--locked",
                    "--package",
                    "fork-ops",
                    "--extra",
                    "mcp",
                    "--group",
                    "test",
                    "--group",
                    "development",
                    "--no-emit-project",
                    "--no-emit-workspace",
                    "--no-annotate",
                    "--no-header",
                    "--output-file",
                    str(requirements),
                    "--python",
                    interpreter,
                ],
                cwd=repo,
                env=subprocess_env,
            ),
        ]
        environment_python = environment / ("Scripts" if os.name == "nt" else "bin") / (
            "python.exe" if os.name == "nt" else "python"
        )
        if all(part["status"] == "passed" for part in parts):
            parts.append(
                _run_command(
                    "candidate_isolation_sync",
                    ["candidate_isolation"],
                    ["candidate.container_dependencies"],
                    [
                        "uv",
                        "pip",
                        "sync",
                        "--python",
                        str(environment_python),
                        "--strict",
                        "--require-hashes",
                        "--only-binary",
                        ":all:",
                        str(requirements),
                    ],
                    cwd=repo,
                    env=subprocess_env,
                )
            )
        else:
            parts.append(
                _blocked_check(
                    "candidate_isolation_sync",
                    ["candidate_isolation"],
                    ["candidate.container_dependencies"],
                    "Candidate container dependencies were not installed because setup failed.",
                )
            )
    failed = [part for part in parts if part["status"] != "passed"]
    if image is None or os.name == "nt":
        failed.append(
            _blocked_check(
                "candidate_isolation_image",
                ["candidate_isolation"],
                ["candidate.digest_pinned_python_container"],
                f"No digest-pinned Linux container is defined for Python {python_minor}.",
            )
        )
    container_user = ""
    if not failed and image is not None:
        try:
            container_user = _host_group_container_user()
        except ValueError as exc:
            failed.append(
                _blocked_check(
                    "candidate_isolation_user",
                    ["candidate_isolation"],
                    ["candidate.non_root_container_user"],
                    str(exc),
                )
            )
    stdout = "".join(part["stdout_tail"] for part in parts)
    stderr = "".join(part["stderr_tail"] for part in failed)
    aggregate = {
        "id": "candidate_isolation",
        "behavior_classes": ["candidate_isolation"],
        "required_ids": [
            "candidate.container_dependencies",
            "candidate.digest_pinned_python_container",
            "candidate.no_host_credentials",
            "candidate.no_host_network",
            "candidate.non_root_container_user",
            "candidate.read_only_source",
        ],
        "status": "failed" if failed else "passed",
        "exit_code": failed[0]["exit_code"] if failed else 0,
        "duration_ms": sum(part["duration_ms"] for part in parts),
        "command": ["docker", "run", "<digest-pinned-python-container>"],
        "commands": [part["command"] for part in parts],
        "stdout_tail": stdout[-4000:],
        "stderr_tail": stderr[-4000:],
        "stdout_sha256": hashlib.sha256(stdout.encode("utf-8")).hexdigest(),
        "timed_out": any(part["timed_out"] for part in parts),
        "environment_policy": "container_explicit_minimal",
    }
    if failed or image is None:
        return aggregate, None
    site_packages = environment / "lib" / f"python{python_minor}" / "site-packages"
    return aggregate, CandidateContainerBoundary(
        repo,
        site_packages,
        image,
        dict(subprocess_env),
        container_user,
    )


def _untracked_whitespace_check(repo: Path) -> dict[str, Any]:
    started = time.monotonic()
    command = _trusted_git_command(
        ["ls-files", "-z", "--others", "--exclude-standard"]
    )
    try:
        with _trusted_git_environment() as environment:
            result = _run_bounded_process(
                command,
                cwd=repo,
                env=environment,
                timeout=_effective_timeout(),
            )
        if result.returncode != 0:
            raise subprocess.CalledProcessError(result.returncode, command)
        listed = result.stdout.split(b"\0")
    except (
        OSError,
        subprocess.CalledProcessError,
        subprocess.TimeoutExpired,
        SubprocessOutputLimitExceeded,
    ) as exc:
        return {
            "id": "diff_untracked",
            "behavior_classes": ["source_diff_hygiene"],
            "required_ids": ["diff.untracked_nonignored"],
            "status": "failed",
            "exit_code": 124 if isinstance(exc, subprocess.TimeoutExpired) else 1,
            "duration_ms": round((time.monotonic() - started) * 1000),
            "command": command,
            "stdout_tail": "",
            "stderr_tail": f"Unable to inspect untracked files: {exc}",
            "stdout_sha256": hashlib.sha256(b"").hexdigest(),
            "timed_out": isinstance(exc, subprocess.TimeoutExpired),
        }

    lexical_repo = Path(os.path.abspath(repo))
    findings: list[str] = []
    for raw_path in sorted(path for path in listed if path):
        _deadline_checkpoint()
        relative = Path(os.fsdecode(raw_path))
        absolute = Path(os.path.abspath(lexical_repo / relative))
        try:
            absolute.relative_to(lexical_repo)
            mode = absolute.lstat().st_mode
        except (FileNotFoundError, ValueError):
            continue
        if not stat.S_ISREG(mode):
            continue
        line_number = 1
        line_tail = b""
        with absolute.open("rb") as source:
            while chunk := source.read(1024 * 1024):
                _deadline_checkpoint()
                start = 0
                while (newline := chunk.find(b"\n", start)) >= 0:
                    segment = chunk[start:newline]
                    ending = (line_tail + segment)[-2:]
                    if ending.endswith(b"\r"):
                        ending = ending[:-1]
                    if ending.endswith((b" ", b"\t")):
                        findings.append(
                            f"{os.fsdecode(raw_path)}:{line_number}: trailing whitespace."
                        )
                    line_number += 1
                    line_tail = b""
                    start = newline + 1
                line_tail = (line_tail + chunk[start:])[-2:]
        if line_tail.endswith((b" ", b"\t")):
            findings.append(f"{os.fsdecode(raw_path)}:{line_number}: trailing whitespace.")
    stdout = "\n".join(findings)
    if stdout:
        stdout += "\n"
    return {
        "id": "diff_untracked",
        "behavior_classes": ["source_diff_hygiene"],
        "required_ids": ["diff.untracked_nonignored"],
        "status": "failed" if findings else "passed",
        "exit_code": 1 if findings else 0,
        "duration_ms": round((time.monotonic() - started) * 1000),
        "command": command,
        "stdout_tail": stdout[-4000:],
        "stderr_tail": "",
        "stdout_sha256": hashlib.sha256(
            stdout.encode("utf-8", errors="surrogateescape")
        ).hexdigest(),
        "timed_out": False,
    }


def _diff_hygiene_check(repo: Path, diff_base: str | None) -> dict[str, Any]:
    parts = [
        _run_git_check(
            "diff_unstaged",
            ["source_diff_hygiene"],
            ["diff.unstaged"],
            ["diff", "--no-ext-diff", "--no-textconv", "--check"],
            cwd=repo,
        ),
        _run_git_check(
            "diff_staged",
            ["source_diff_hygiene"],
            ["diff.staged"],
            ["diff", "--no-ext-diff", "--no-textconv", "--cached", "--check"],
            cwd=repo,
        ),
        _untracked_whitespace_check(repo),
    ]
    if diff_base:
        parts.append(
            _run_git_check(
                "diff_committed_range",
                ["source_diff_hygiene"],
                ["diff.committed_candidate_range"],
                [
                    "diff",
                    "--no-ext-diff",
                    "--no-textconv",
                    "--check",
                    f"{diff_base}...HEAD",
                ],
                cwd=repo,
            )
        )
    stdout = "".join(part["stdout_tail"] for part in parts)
    stderr = "".join(part["stderr_tail"] for part in parts)
    failed = [part for part in parts if part["status"] != "passed"]
    return {
        "id": "diff_hygiene",
        "behavior_classes": ["source_diff_hygiene"],
        "required_ids": [required_id for part in parts for required_id in part["required_ids"]],
        "status": "failed" if failed else "passed",
        "exit_code": failed[0]["exit_code"] if failed else 0,
        "duration_ms": sum(part["duration_ms"] for part in parts),
        "command": parts[-1]["command"],
        "commands": [part["command"] for part in parts],
        "stdout_tail": stdout[-4000:],
        "stderr_tail": stderr[-4000:],
        "stdout_sha256": hashlib.sha256(
            stdout.encode("utf-8", errors="surrogateescape")
        ).hexdigest(),
        "timed_out": any(part["timed_out"] for part in parts),
    }


CLI_SURFACE_DISCOVERY_CLIENT = r"""
import argparse
import json

from fork_ops.cli import build_parser


def leaves(parser, prefix=()):
    subparsers = [
        action
        for action in parser._actions
        if isinstance(action, argparse._SubParsersAction)
    ]
    if not subparsers:
        return [" ".join(prefix)]
    discovered = []
    for action in subparsers:
        for name, child in action.choices.items():
            discovered.extend(leaves(child, (*prefix, name)))
    return discovered


print(json.dumps({"leaves": sorted(leaves(build_parser()))}, sort_keys=True))
"""


WORKFLOW_CATALOG_DISCOVERY_CLIENT = r"""
import json

from fork_ops.workflow_catalog import workflow_catalog

contracts = [
    {
        "available": workflow.get("available"),
        "id": workflow.get("id"),
        "implementation_status": workflow.get("implementation_status"),
    }
    for workflow in workflow_catalog().get("workflows", [])
]
print(json.dumps({"contracts": contracts}, sort_keys=True))
"""


def _cli_surface_inventory_check(
    repo: Path,
    uv_run: list[str],
    candidate_boundary: CandidateContainerBoundary | None = None,
) -> dict[str, Any]:
    check = _run_command(
        "cli_surface_inventory",
        ["cli_surface_inventory"],
        [f"cli.parser.{leaf.replace(' ', '.')}" for leaf in CLI_LEAVES],
        (
            _source_candidate_container_command(
                candidate_boundary,
                ["-c", CLI_SURFACE_DISCOVERY_CLIENT],
            )
            if candidate_boundary is not None
            else [*uv_run, "python", "-c", CLI_SURFACE_DISCOVERY_CLIENT]
        ),
        cwd=repo,
        env=candidate_boundary.host_environment if candidate_boundary is not None else None,
    )
    if check["status"] != "passed":
        return check
    try:
        payload = json.loads(check["_stdout_complete"])
        leaves = payload["leaves"]
        if not isinstance(leaves, list) or not all(isinstance(leaf, str) for leaf in leaves):
            raise TypeError("CLI leaves must be an array of strings")
    except (KeyError, json.JSONDecodeError, TypeError) as exc:
        check["status"] = "failed"
        check["exit_code"] = 1
        check["stderr_tail"] = f"CLI surface discovery was not usable: {exc}"
        return check
    check["leaves"] = leaves
    if tuple(leaves) != CLI_LEAVES:
        check["status"] = "failed"
        check["exit_code"] = 1
        check["stderr_tail"] = "CLI parser leaves did not match the validation contract."
    return check


def _workflow_catalog_check(
    repo: Path,
    uv_run: list[str],
    candidate_boundary: CandidateContainerBoundary | None = None,
) -> dict[str, Any]:
    check = _run_command(
        "workflow_catalog",
        ["workflow_catalog"],
        [f"workflow.catalog_contract.{item}" for item in WORKFLOW_CONTRACT_IDS],
        (
            _source_candidate_container_command(
                candidate_boundary,
                ["-c", WORKFLOW_CATALOG_DISCOVERY_CLIENT],
            )
            if candidate_boundary is not None
            else [*uv_run, "python", "-c", WORKFLOW_CATALOG_DISCOVERY_CLIENT]
        ),
        cwd=repo,
        env=candidate_boundary.host_environment if candidate_boundary is not None else None,
    )
    check["coverage_kind"] = "catalog_contract_discovery_not_execution"
    if check["status"] != "passed":
        return check
    try:
        payload = json.loads(check["_stdout_complete"])
        records = payload["contracts"]
        if not isinstance(records, list):
            raise TypeError("workflow contracts must be an array")
        contracts: dict[str, dict[str, Any]] = {}
        for record in records:
            if not isinstance(record, dict):
                raise TypeError("workflow contract entries must be objects")
            contract_id = record.get("id")
            status = record.get("implementation_status")
            available = record.get("available")
            if (
                not isinstance(contract_id, str)
                or status not in {"current", "diagnostic-only", "next-slice", "planned"}
                or not isinstance(available, bool)
                or contract_id in contracts
            ):
                raise ValueError("workflow contract identity or status is invalid")
            contracts[contract_id] = {
                "available": available,
                "implementation_status": status,
            }
    except (KeyError, json.JSONDecodeError, TypeError, ValueError) as exc:
        check["status"] = "failed"
        check["exit_code"] = 1
        check["stderr_tail"] = f"Workflow catalog discovery was not usable: {exc}"
        return check
    check["contracts"] = dict(sorted(contracts.items()))
    if tuple(sorted(contracts)) != WORKFLOW_CONTRACT_IDS:
        check["status"] = "failed"
        check["exit_code"] = 1
        check["stderr_tail"] = "Workflow catalog IDs did not match the validation contract."
    return check


def _source_checks(
    repo: Path,
    interpreter: str,
    *,
    diff_repo: Path | None = None,
    diff_base: str | None = None,
    scope_inventory: tuple[
        dict[str, Any],
        dict[str, dict[str, list[str]]],
        dict[str, dict[str, str]],
        str,
    ]
    | None = None,
    candidate_container: bool = False,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    if not candidate_container:
        return _source_checks_in_boundary(
            repo,
            interpreter,
            diff_repo=diff_repo,
            diff_base=diff_base,
            scope_inventory=scope_inventory,
        )
    with tempfile.TemporaryDirectory(prefix="fork-ops-source-container-") as temp_dir:
        isolation_check, boundary = _prepare_source_candidate_container(
            repo,
            interpreter,
            Path(temp_dir),
        )
        if boundary is None:
            return [isolation_check], {}
        checks, provenance = _source_checks_in_boundary(
            repo,
            interpreter,
            diff_repo=diff_repo,
            diff_base=diff_base,
            scope_inventory=scope_inventory,
            candidate_boundary=boundary,
        )
        return [isolation_check, *checks], provenance


def _source_checks_in_boundary(
    repo: Path,
    interpreter: str,
    *,
    diff_repo: Path | None = None,
    diff_base: str | None = None,
    scope_inventory: tuple[
        dict[str, Any],
        dict[str, dict[str, list[str]]],
        dict[str, dict[str, str]],
        str,
    ]
    | None = None,
    candidate_boundary: CandidateContainerBoundary | None = None,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    uv_run = [
        "uv",
        "run",
        "--locked",
        "--exact",
        "--python",
        interpreter,
        "--package",
        "fork-ops",
        "--extra",
        "mcp",
        "--group",
        "test",
        "--group",
        "development",
    ]
    checks = [
        _run_command(
            "lock_integrity",
            ["dependency_lock"],
            ["lock.uv_locked"],
            ["uv", "lock", "--check", "--python", interpreter],
            cwd=repo,
            env=(
                candidate_boundary.host_environment
                if candidate_boundary is not None
                else None
            ),
        ),
    ]
    inventory_check, package_scopes, package_versions, inventory_digest = (
        scope_inventory
        or _package_scope_inventory_check(
            repo,
            subprocess_env=(
                candidate_boundary.host_environment
                if candidate_boundary is not None
                else None
            ),
        )
    )
    checks.extend(
        [
            inventory_check,
            _cli_surface_inventory_check(repo, uv_run, candidate_boundary),
            _workflow_catalog_check(repo, uv_run, candidate_boundary),
            _run_command(
                "ruff",
                ["source", "tests", "validation_entrypoint"],
                ["lint.repository_python"],
                (
                    _source_candidate_container_command(
                        candidate_boundary,
                        [
                            "-m",
                            "ruff",
                            "check",
                            "--no-cache",
                            "scripts",
                            "plugins/fork-ops/src",
                            "plugins/fork-ops/tests",
                        ],
                    )
                    if candidate_boundary is not None
                    else [
                        *uv_run,
                        "ruff",
                        "check",
                        "--cache-dir",
                        ".ruff_cache",
                        "scripts",
                        "plugins/fork-ops/src",
                        "plugins/fork-ops/tests",
                    ]
                ),
                cwd=repo,
                env=(
                    candidate_boundary.host_environment
                    if candidate_boundary is not None
                    else None
                ),
            ),
        ]
    )
    with tempfile.TemporaryDirectory(prefix="fork-ops-coverage-") as coverage_dir_text:
        coverage_dir = Path(coverage_dir_text)
        if candidate_boundary is not None:
            _make_private_tree_group_writable(coverage_dir)
        coverage_data = coverage_dir / "coverage.data"
        coverage_json = coverage_dir / "coverage.json"
        pytest_check = _run_command(
            "pytest",
            ["plugin_test_suite"],
            ["pytest.plugins/fork-ops/tests", "coverage.production_modules"],
            (
                _source_candidate_container_command(
                    candidate_boundary,
                    [
                        "-m",
                        "coverage",
                        "run",
                        "--data-file",
                        "/scratch/coverage.data",
                        "--source",
                        "fork_ops",
                        "-m",
                        "pytest",
                        "-p",
                        "no:cacheprovider",
                        "plugins/fork-ops/tests",
                        "-q",
                    ],
                    scratch=coverage_dir,
                )
                if candidate_boundary is not None
                else [
                    *uv_run,
                    "coverage",
                    "run",
                    "--data-file",
                    str(coverage_data),
                    "--source",
                    "fork_ops",
                    "-m",
                    "pytest",
                    "plugins/fork-ops/tests",
                    "-q",
                ]
            ),
            cwd=repo,
            env=(
                candidate_boundary.host_environment
                if candidate_boundary is not None
                else None
            ),
        )
        if coverage_data.is_file():
            coverage_check = _run_command(
                "coverage_json",
                ["plugin_test_suite"],
                ["coverage.production_modules"],
                (
                    _source_candidate_container_command(
                        candidate_boundary,
                        [
                            "-m",
                            "coverage",
                            "json",
                            "--data-file",
                            "/scratch/coverage.data",
                            "-o",
                            "/scratch/coverage.json",
                        ],
                        scratch=coverage_dir,
                    )
                    if candidate_boundary is not None
                    else [
                        *uv_run,
                        "coverage",
                        "json",
                        "--data-file",
                        str(coverage_data),
                        "-o",
                        str(coverage_json),
                    ]
                ),
                cwd=repo,
                env=(
                    candidate_boundary.host_environment
                    if candidate_boundary is not None
                    else None
                ),
            )
            if coverage_check["status"] == "passed":
                try:
                    coverage_payload = json.loads(_read_text(coverage_json))
                    totals = coverage_payload["totals"]
                except (FileNotFoundError, KeyError, json.JSONDecodeError, TypeError) as exc:
                    pytest_check["status"] = "failed"
                    pytest_check["exit_code"] = 1
                    pytest_check["stderr_tail"] += f"\nInvalid coverage JSON: {exc}"
                else:
                    measured_files = coverage_payload.get("files", {})
                    production_files = sorted(
                        path
                        for path in measured_files
                        if "/fork_ops/" in f"/{path.replace(chr(92), '/')}"
                        or path.replace(chr(92), "/").startswith("fork_ops/")
                    )
                    if not production_files or totals.get("num_statements", 0) <= 0:
                        pytest_check["status"] = "failed"
                        pytest_check["exit_code"] = 1
                        pytest_check["stderr_tail"] += (
                            "\nCoverage JSON did not measure any production fork_ops files "
                            "with statements."
                        )
                    normalized_summary = {
                        "files": {
                            path: file_data.get("summary", {})
                            for path, file_data in sorted(measured_files.items())
                        },
                        "totals": totals,
                    }
                    pytest_check["coverage"] = {
                        "policy": "collected_without_numeric_threshold",
                        "tool_version": coverage_payload.get("meta", {}).get("version", ""),
                        "summary_sha256": hashlib.sha256(
                            json.dumps(
                                normalized_summary,
                                sort_keys=True,
                                separators=(",", ":"),
                            ).encode("utf-8")
                        ).hexdigest(),
                        "measured_files": len(measured_files),
                        "production_measured_files": production_files,
                        "totals": {
                            "num_statements": totals.get("num_statements", 0),
                            "covered_lines": totals.get("covered_lines", 0),
                            "missing_lines": totals.get("missing_lines", 0),
                            "excluded_lines": totals.get("excluded_lines", 0),
                            "percent_covered": totals.get("percent_covered", 0.0),
                        },
                    }
            elif pytest_check["status"] == "passed":
                pytest_check["status"] = "failed"
                pytest_check["exit_code"] = coverage_check["exit_code"]
                pytest_check["stderr_tail"] += "\n" + coverage_check["stderr_tail"]
        elif pytest_check["status"] == "passed":
            pytest_check["status"] = "failed"
            pytest_check["exit_code"] = 1
            pytest_check["stderr_tail"] += "\nCoverage data file was not produced."
    checks.extend(
        [
            pytest_check,
            _run_command(
                "pyrefly_strict",
                ["source", "tests"],
                ["types.pyrefly_strict"],
                (
                    _source_candidate_container_command(
                        candidate_boundary,
                        ["-m", "pyrefly", "check"],
                    )
                    if candidate_boundary is not None
                    else [*uv_run, "pyrefly", "check"]
                ),
                cwd=repo,
                env=(
                    candidate_boundary.host_environment
                    if candidate_boundary is not None
                    else None
                ),
            ),
        ]
    )
    schema_check = _run_command(
        "schema_parity",
        ["cli", "packaged_schema"],
        ["schema.source_packaged_runtime_parity"],
        (
            _source_candidate_container_command(
                candidate_boundary,
                ["-m", "fork_ops.cli", "schema", "print"],
            )
            if candidate_boundary is not None
            else [*uv_run, "fork-ops", "schema", "print"]
        ),
        cwd=repo,
        env=(
            candidate_boundary.host_environment
            if candidate_boundary is not None
            else None
        ),
    )
    schema_paths = (
        repo / "plugins" / "fork-ops" / "schema" / "fork-ops.schema.json",
        repo / "plugins" / "fork-ops" / "src" / "fork_ops" / "fork-ops.schema.json",
    )
    if schema_check["status"] == "passed":
        expected = _read_text(schema_paths[0])
        packaged = _read_text(schema_paths[1])
        expected_digest = hashlib.sha256(expected.encode("utf-8")).hexdigest()
        if schema_check["stdout_sha256"] != expected_digest or packaged != expected:
            schema_check["status"] = "failed"
            schema_check["exit_code"] = 1
            schema_check["stderr_tail"] = "Schema output and checked-in schema copies differ."
    checks.append(schema_check)
    checks.append(_diff_hygiene_check(diff_repo or repo, diff_base))
    return checks, {
        "package_scopes_by_python": package_scopes,
        "package_versions_by_python": package_versions,
        "package_scope_inventory_sha256": inventory_digest,
    }


def _python_minor(interpreter: str) -> str:
    version_script = "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')"
    executable = _trusted_executable(interpreter)
    completed = _run_bounded_process(
        [str(executable), "-I", "-S", "-c", version_script],
        cwd=Path.cwd(),
        env=None,
        timeout=_effective_timeout(),
    )
    if completed.returncode != 0:
        raise subprocess.CalledProcessError(completed.returncode, str(executable))
    return completed.stdout.decode("ascii", errors="strict").strip()


def _canonical_json_bytes(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def _dependency_matrix(
    scopes_by_python: dict[str, dict[str, list[str]]],
    versions_by_python: dict[str, dict[str, str]],
) -> dict[str, object]:
    if (
        set(scopes_by_python) != set(SUPPORTED_PYTHON_MINORS)
        or set(versions_by_python) != set(SUPPORTED_PYTHON_MINORS)
    ):
        raise ValueError("Dependency matrix must cover every supported Python minor")
    package_tuples: list[dict[str, object]] = []
    for minor in SUPPORTED_PYTHON_MINORS:
        scopes = scopes_by_python[minor]
        versions = versions_by_python[minor]
        if not scopes or set(scopes) != set(versions):
            raise ValueError(f"Python {minor} dependency matrix is incomplete")
        covered: set[str] = set()
        for package in sorted(scopes):
            selected_scopes = scopes[package]
            version = versions[package]
            ordered = [scope for scope in DEPENDENCY_SCOPES if scope in selected_scopes]
            if (
                re.sub(r"[-_.]+", "-", package).lower() != package
                or not version
                or version != version.strip()
                or selected_scopes != ordered
                or len(selected_scopes) != len(set(selected_scopes))
            ):
                raise ValueError("Dependency matrix contains a noncanonical package tuple")
            covered.update(selected_scopes)
            package_tuples.append(
                {
                    "python_version": minor,
                    "package": package,
                    "locked_version": version,
                    "dependency_scopes": selected_scopes,
                }
            )
        if covered != set(DEPENDENCY_SCOPES):
            raise ValueError(f"Python {minor} dependency scopes are incomplete")
    return {
        "platform": "linux",
        "python_versions": list(SUPPORTED_PYTHON_MINORS),
        "package_tuples": package_tuples,
    }


def _normalize_audit_advisory(
    value: object,
    minor: str,
    scopes: dict[str, list[str]],
    versions: dict[str, str],
) -> dict[str, object]:
    if not isinstance(value, dict) or set(value) != {
        "id",
        "aliases",
        "dependency",
        "fix_versions",
    }:
        raise ValueError("Provider advisory has an unsupported shape")
    dependency = value.get("dependency")
    if not isinstance(dependency, dict) or set(dependency) != {"name", "version"}:
        raise ValueError("Provider advisory dependency has an unsupported shape")
    raw_package = dependency.get("name")
    locked_version = dependency.get("version")
    advisory_id = value.get("id")
    aliases = value.get("aliases")
    fix_versions = value.get("fix_versions")
    package = re.sub(r"[-_.]+", "-", raw_package).lower() if isinstance(raw_package, str) else ""
    if not (
        package in scopes
        and isinstance(locked_version, str)
        and versions.get(package) == locked_version
        and isinstance(advisory_id, str)
        and advisory_id
        and isinstance(aliases, list)
        and all(isinstance(alias, str) and alias for alias in aliases)
        and isinstance(fix_versions, list)
        and all(isinstance(version, str) and version for version in fix_versions)
    ):
        raise ValueError("Provider advisory does not bind an exact locked package tuple")
    return {
        "advisory_id": advisory_id,
        "aliases": sorted(set(aliases).difference({advisory_id})),
        "package": package,
        "locked_version": locked_version,
        "affected": True,
        "affected_range": "",
        "fixed_versions": sorted(set(fix_versions)),
        "dependency_scopes": scopes[package],
        "python_versions": [minor],
    }


def _merge_audit_advisories(
    advisories: list[dict[str, object]],
) -> list[dict[str, object]]:
    merged: dict[bytes, dict[str, object]] = {}
    for advisory in advisories:
        identity = _canonical_json_bytes(
            {key: value for key, value in advisory.items() if key != "python_versions"}
        )
        selected = merged.setdefault(identity, {**advisory, "python_versions": []})
        selected_versions = selected.get("python_versions")
        advisory_versions = advisory.get("python_versions")
        if not isinstance(selected_versions, list) or not isinstance(advisory_versions, list):
            raise ValueError("Normalized advisory Python coverage is malformed")
        selected_versions.extend(advisory_versions)
        selected["python_versions"] = [
            minor for minor in SUPPORTED_PYTHON_MINORS if minor in selected_versions
        ]
    return sorted(
        merged.values(),
        key=_normalized_advisory_sort_key,
    )


def _normalized_advisory_sort_key(item: dict[str, object]) -> tuple[str, str, str]:
    return (
        str(item["package"]),
        str(item["locked_version"]),
        str(item["advisory_id"]),
    )


def _validate_fresh_resolution_project(repo: Path) -> dict[str, object]:
    root = tomllib.loads(_read_text(repo / "pyproject.toml"))
    package = tomllib.loads(_read_text(repo / "plugins" / "fork-ops" / "pyproject.toml"))
    if set(root) - {"project", "dependency-groups", "tool"}:
        raise ValueError("Fresh resolution root project has unsupported top-level tables")
    root_tool = root.get("tool")
    if not isinstance(root_tool, dict):
        raise ValueError("Fresh resolution requires the workspace tool table")
    uv = root_tool.get("uv")
    if not isinstance(uv, dict) or set(uv) != {"package", "default-groups", "sources", "workspace"}:
        raise ValueError("Fresh resolution requires the closed workspace uv contract")
    if uv.get("sources") != {"fork-ops": {"workspace": True}}:
        raise ValueError("Fresh resolution permits only the fork-ops workspace source")
    if uv.get("workspace") != {"members": ["plugins/fork-ops"]}:
        raise ValueError("Fresh resolution workspace membership is unsupported")
    if set(package) - {"build-system", "project", "dependency-groups", "tool"}:
        raise ValueError("Fresh resolution package has unsupported top-level tables")
    if package.get("build-system") != {
        "requires": ["setuptools==83.0.0", "wheel==0.46.2"],
        "build-backend": "setuptools.build_meta",
    }:
        raise ValueError("Fresh resolution package build contract is unsupported")
    package_tool = package.get("tool")
    if not isinstance(package_tool, dict) or "uv" in package_tool:
        raise ValueError("Fresh resolution package tool configuration is unsupported")
    for relative in ("uv.toml", ".uv.toml"):
        if (repo / relative).exists():
            raise ValueError(f"Fresh resolution rejects candidate uv config {relative}")
    dependencies: list[str] = []
    for project in (root.get("project"), package.get("project")):
        if not isinstance(project, dict):
            raise ValueError("Fresh resolution project metadata is malformed")
        if "dynamic" in project:
            raise ValueError("Fresh resolution rejects dynamic project metadata")
        raw_dependencies = project.get("dependencies", [])
        if not isinstance(raw_dependencies, list):
            raise ValueError("Fresh resolution dependencies must be arrays")
        dependencies.extend(raw_dependencies)
        optional = project.get("optional-dependencies", {})
        if not isinstance(optional, dict):
            raise ValueError("Fresh resolution optional dependencies must be a table")
        for values in optional.values():
            if not isinstance(values, list):
                raise ValueError("Fresh resolution optional dependency groups must be arrays")
            dependencies.extend(values)
    for project in (root, package):
        groups = project.get("dependency-groups", {})
        if not isinstance(groups, dict):
            raise ValueError("Fresh resolution dependency groups must be a table")
        for values in groups.values():
            if not isinstance(values, list):
                raise ValueError("Fresh resolution dependency groups must be arrays")
            dependencies.extend(values)
    for dependency in dependencies:
        if not isinstance(dependency, str) or not dependency.strip():
            raise ValueError("Fresh resolution dependencies must be nonempty strings")
        lowered = dependency.lower()
        if (
            " @ " in dependency
            or "git+" in lowered
            or "http://" in lowered
            or "https://" in lowered
            or "file:" in lowered
            or "ssh:" in lowered
        ):
            raise ValueError("Fresh resolution rejects URL, VCS, path, and direct sources")
    policy: dict[str, object] = {
        "index": "https://pypi.org/simple",
        "sources": "registry-only-plus-exact-workspace-member",
        "uv_config": "disabled",
        "dependency_declaration_sha256": hashlib.sha256(
            _canonical_json_bytes(dependencies)
        ).hexdigest(),
    }
    policy["policy_sha256"] = hashlib.sha256(_canonical_json_bytes(policy)).hexdigest()
    return policy


def _dependency_audit_matrix_check(
    repo: Path,
    interpreter: str,
    package_scopes_by_python: dict[str, dict[str, list[str]]],
    package_versions_by_python: dict[str, dict[str, str]],
    candidate_identity: dict[str, Any],
    producer_identity: dict[str, Any] | None,
) -> dict[str, Any]:
    if producer_identity is None:
        return _blocked_check(
            "dependency_audit_matrix",
            ["dependency_audit"],
            [f"audit.osv.python.{minor}" for minor in SUPPORTED_PYTHON_MINORS],
            "Trusted GitHub Actions producer identity is required for sealed audit evidence.",
        )
    del interpreter
    started = time.monotonic()
    required_ids = [f"audit.osv.python.{minor}" for minor in SUPPORTED_PYTHON_MINORS]
    observation_epoch = os.urandom(32).hex()
    observation_started = _utc_now()
    try:
        matrix = _dependency_matrix(package_scopes_by_python, package_versions_by_python)
    except ValueError as exc:
        return _blocked_check(
            "dependency_audit_matrix",
            ["dependency_audit"],
            required_ids,
            str(exc),
        )
    inventory_digest = hashlib.sha256(
        _canonical_json_bytes({"package_tuples": matrix["package_tuples"]})
    ).hexdigest()
    matrix_package_tuples = matrix["package_tuples"]
    if not isinstance(matrix_package_tuples, list):
        return _blocked_check(
            "dependency_audit_matrix",
            ["dependency_audit"],
            required_ids,
            "Dependency matrix package tuples are malformed.",
        )
    if candidate_identity.get("package_scope_inventory_sha256") != inventory_digest:
        return _blocked_check(
            "dependency_audit_matrix",
            ["dependency_audit"],
            required_ids,
            "Candidate identity does not bind the exact dependency matrix.",
        )
    child_checks: list[dict[str, Any]] = []
    normalized_advisories: list[dict[str, object]] = []
    provider_requests: list[dict[str, object]] = []
    with tempfile.TemporaryDirectory(prefix="fork-ops-dependency-audit-") as temp_dir:
        with _minimal_subprocess_environment(Path(temp_dir)) as environment:
            for minor in SUPPORTED_PYTHON_MINORS:
                check = _run_command(
                    f"dependency_audit:{minor}",
                    ["dependency_audit"],
                    [f"audit.osv.python.{minor}"],
                    [
                        str(_trusted_uv_executable()),
                        "audit",
                        "--locked",
                        "--frozen",
                        "--no-config",
                        "--no-sources",
                        "--no-build",
                        "--default-index",
                        "https://pypi.org/simple",
                        "--index-strategy",
                        "first-index",
                        "--keyring-provider",
                        "disabled",
                        "--service-url",
                        "https://api.osv.dev/v1/querybatch",
                        "--output-format",
                        "json",
                        "--python-platform",
                        "linux",
                        "--python-version",
                        minor,
                    ],
                    cwd=repo,
                    env=environment,
                    allowed_returncodes=frozenset({0, 1}),
                )
                child_checks.append(check)
                if check["status"] != "passed":
                    continue
                try:
                    raw = json.loads(check["_stdout_complete"])
                    if not isinstance(raw, dict) or set(raw) != {
                        "vulnerabilities",
                        "adverse_statuses",
                    }:
                        raise ValueError("Provider response has an unsupported root shape")
                    vulnerabilities = raw["vulnerabilities"]
                    adverse = raw["adverse_statuses"]
                    if not isinstance(vulnerabilities, list) or not isinstance(adverse, list):
                        raise ValueError("Provider response collections are malformed")
                    if adverse:
                        raise ValueError("Provider reported adverse package statuses")
                    normalized_advisories.extend(
                        _normalize_audit_advisory(
                            advisory,
                            minor,
                            package_scopes_by_python[minor],
                            package_versions_by_python[minor],
                        )
                        for advisory in vulnerabilities
                    )
                    tuples = [
                        item
                        for item in matrix_package_tuples
                        if isinstance(item, dict) and item.get("python_version") == minor
                    ]
                    request: dict[str, object] = {
                        "provider": "osv.dev:uv-audit",
                        "python_version": minor,
                        "package_tuple_count": len(tuples),
                        "package_tuples_sha256": hashlib.sha256(
                            _canonical_json_bytes(tuples)
                        ).hexdigest(),
                        "response_sha256": check["stdout_sha256"],
                        "advisory_count": len(vulnerabilities),
                        "complete": True,
                    }
                    request["request_sha256"] = hashlib.sha256(
                        _canonical_json_bytes(
                            {
                                "provider": request["provider"],
                                "python_version": minor,
                                "package_tuples": tuples,
                                "observation_epoch": observation_epoch,
                            }
                        )
                    ).hexdigest()
                    provider_requests.append(request)
                except (json.JSONDecodeError, KeyError, TypeError, ValueError) as exc:
                    check["status"] = "failed"
                    check["exit_code"] = 1
                    check["stderr_tail"] = f"Trusted provider response validation failed: {exc}"
    failures = [check for check in child_checks if check["status"] != "passed"]
    if len(provider_requests) != len(SUPPORTED_PYTHON_MINORS):
        failures.append(
            _blocked_check(
                "dependency_audit_completeness",
                ["dependency_audit"],
                required_ids,
                "Provider observations are incomplete for the supported Python matrix.",
            )
        )
    merged_advisories = _merge_audit_advisories(normalized_advisories)
    evidence: dict[str, object] = {
        "artifact_kind": "normalized_dependency_vulnerability_evidence",
        "schema_version": "2.0",
        "source": "osv",
        "status": "available" if not failures else "unavailable",
        "platforms": ["linux"],
        "dependency_scopes": list(DEPENDENCY_SCOPES),
        "python_versions": list(SUPPORTED_PYTHON_MINORS),
        "advisories": merged_advisories,
        "diagnostics": [] if not failures else [
            {
                "code": "evidence.incomplete",
                "source": "osv",
                "message": "The verifier did not obtain four complete provider observations.",
            }
        ],
        "provenance": {
            "schema_version": "1.0",
            "candidate": candidate_identity,
            "matrix": matrix,
            "producer": producer_identity,
            "source_observation": {
                "provider": "osv",
                "source_identity": "osv.dev:uv-audit",
                "authenticated": False,
                "pagination_complete": not failures,
                "page_count": len(provider_requests),
                "item_count": len(merged_advisories),
                "observation_epoch": observation_epoch,
                "started_at": observation_started,
                "completed_at": _utc_now(),
                "valid_until": (
                    datetime.now(UTC) + timedelta(minutes=15)
                ).isoformat().replace("+00:00", "Z"),
            },
        },
    }
    evidence["payload_sha256"] = hashlib.sha256(_canonical_json_bytes(evidence)).hexdigest()
    stdout = "".join(check["stdout_tail"] for check in child_checks)
    stderr = "".join(check["stderr_tail"] for check in failures)
    return {
        "id": "dependency_audit_matrix",
        "behavior_classes": ["dependency_audit"],
        "required_ids": required_ids,
        "status": "failed" if failures or merged_advisories else "passed",
        "exit_code": failures[0]["exit_code"] if failures else (1 if merged_advisories else 0),
        "duration_ms": round((time.monotonic() - started) * 1000),
        "command": ["uv", "audit", "<trusted-four-minor-provider-matrix>"],
        "commands": [check["command"] for check in child_checks],
        "stdout_tail": stdout[-4000:],
        "stderr_tail": stderr[-4000:],
        "stdout_sha256": hashlib.sha256(stdout.encode("utf-8")).hexdigest(),
        "timed_out": any(check["timed_out"] for check in child_checks),
        "environment_policy": "explicit_minimal",
        "evidence": evidence,
        "evidence_sha256": hashlib.sha256(_canonical_json_bytes(evidence)).hexdigest(),
        "provider_requests": provider_requests,
        "provider_requests_sha256": hashlib.sha256(
            _canonical_json_bytes(provider_requests)
        ).hexdigest(),
    }


def _validate_resolved_snapshot_tree(snapshot: Path) -> None:
    for directory, directory_names, file_names in os.walk(
        snapshot,
        topdown=True,
        followlinks=False,
    ):
        _deadline_checkpoint()
        for name in [*directory_names, *file_names]:
            entry = Path(directory) / name
            mode = entry.lstat().st_mode
            if not (stat.S_ISDIR(mode) or stat.S_ISREG(mode)):
                raise ValueError(
                    f"Fresh resolver produced an unsupported filesystem entry: {entry}"
                )


def _fresh_resolution_check(
    snapshot: Path,
    interpreter: str,
    *,
    candidate_container: bool,
) -> dict[str, Any]:
    try:
        policy = _validate_fresh_resolution_project(snapshot)
    except (OSError, UnicodeError, tomllib.TOMLDecodeError, ValueError) as exc:
        return _blocked_check(
            "fresh_resolution",
            ["dependency_resolution", "candidate_isolation"],
            ["resolution.closed_registry_policy"],
            str(exc),
        )
    input_manifest_sha256 = hashlib.sha256(
        _canonical_json_bytes(
            {
                "root_pyproject_sha256": _sha256(snapshot / "pyproject.toml"),
                "package_pyproject_sha256": _sha256(
                    snapshot / "plugins" / "fork-ops" / "pyproject.toml"
                ),
                "input_lock_sha256": _sha256(snapshot / "uv.lock"),
            }
        )
    ).hexdigest()
    protected_inputs = {
        relative: _read_bytes(snapshot / relative)
        for relative in (
            "pyproject.toml",
            "plugins/fork-ops/pyproject.toml",
        )
    }
    command = [
        "uv",
        "lock",
        "--upgrade",
        "--refresh",
        "--no-config",
        "--no-sources",
        "--no-build",
        "--default-index",
        "https://pypi.org/simple",
        "--python",
        interpreter,
    ]
    if candidate_container:
        minor = _python_minor(interpreter)
        image = PYTHON_CONTAINER_IMAGES.get(minor)
        if image is None or os.name != "posix":
            return _blocked_check(
                "fresh_resolution",
                ["dependency_resolution", "candidate_isolation"],
                ["resolution.digest_pinned_container"],
                f"No digest-pinned resolver container is available for Python {minor}.",
            )
        try:
            user = _host_group_container_user()
            _make_private_tree_group_writable(snapshot)
        except ValueError as exc:
            return _blocked_check(
                "fresh_resolution",
                ["dependency_resolution", "candidate_isolation"],
                ["resolution.private_writable_snapshot"],
                str(exc),
            )
        base = [
            argument
            for argument in _candidate_container_base(user=user)
            if argument != "--network=none"
        ]
        uv_executable = _trusted_uv_executable()
        with tempfile.TemporaryDirectory(prefix="fork-ops-resolver-host-") as host_dir:
            with _minimal_subprocess_environment(Path(host_dir)) as host_environment:
                check = _run_command(
                    "fresh_resolution",
                    ["dependency_resolution", "candidate_isolation"],
                    [
                        "resolution.closed_registry_policy",
                        "resolution.digest_pinned_container",
                        "resolution.no_host_credentials",
                        "resolution.private_writable_snapshot",
                    ],
                    [
                        *base,
                        "--network=bridge",
                        "--workdir=/workspace",
                        "--env=UV_NO_CONFIG=1",
                        "--env=UV_DEFAULT_INDEX=https://pypi.org/simple",
                        "--env=UV_INDEX_STRATEGY=first-index",
                        "--env=UV_PYTHON_DOWNLOADS=never",
                        f"--mount=type=bind,src={snapshot},dst=/workspace",
                        f"--mount=type=bind,src={uv_executable},dst=/opt/fork-ops/uv,readonly",
                        image,
                        "/opt/fork-ops/uv",
                        *command[1:-1],
                        minor,
                    ],
                    cwd=snapshot,
                    env=host_environment,
                )
        check["environment_policy"] = "networked_resolver_container_explicit_minimal"
    else:
        with tempfile.TemporaryDirectory(prefix="fork-ops-fresh-resolution-") as temp_dir:
            with _minimal_subprocess_environment(Path(temp_dir)) as environment:
                check = _run_command(
                    "fresh_resolution",
                    ["dependency_resolution"],
                    ["resolution.closed_registry_policy"],
                    command,
                    cwd=snapshot,
                    env=environment,
                )
    check["resolution_policy"] = policy
    check["resolver"] = {
        "uv_executable_sha256": _TRUSTED_UV_SHA256,
        "input_manifest_sha256": input_manifest_sha256,
        "container_image": PYTHON_CONTAINER_IMAGES.get(_python_minor(interpreter), "")
        if candidate_container
        else "",
    }
    if check["status"] == "passed":
        try:
            _validate_resolved_snapshot_tree(snapshot)
            for relative, expected in protected_inputs.items():
                if _read_bytes(snapshot / relative) != expected:
                    raise ValueError(f"Fresh resolver changed protected input {relative}")
            for relative in ("uv.toml", ".uv.toml"):
                if (snapshot / relative).exists():
                    raise ValueError(f"Fresh resolver created forbidden config {relative}")
            check["resolver"]["output_lock_sha256"] = _sha256(snapshot / "uv.lock")
        except (OSError, ValueError, RuntimeError) as exc:
            check["status"] = "failed"
            check["exit_code"] = 1
            check["stderr_tail"] = f"Fresh resolver output validation failed: {exc}"
    check["resolver"]["receipt_sha256"] = hashlib.sha256(
        _canonical_json_bytes(
            {
                "policy": policy,
                "resolver": check["resolver"],
                "command": check["command"],
                "exit_code": check["exit_code"],
            }
        )
    ).hexdigest()
    return check


def _fresh_source_checks(
    repo: Path,
    interpreter: str,
    diff_base: str | None,
    *,
    diff_repo: Path | None = None,
    commit_sha: str,
    source_snapshot_sha256: str,
    producer_identity: dict[str, Any] | None,
    candidate_container: bool = False,
) -> tuple[list[dict[str, Any]], str, dict[str, Any]]:
    ignored_names = {
        ".git",
        ".mypy_cache",
        ".pyrefly_cache",
        ".pytest_cache",
        ".ruff_cache",
        ".venv",
        "__pycache__",
        "build",
        "dist",
    }

    def ignore_snapshot_paths(_directory: str, names: list[str]) -> set[str]:
        _deadline_checkpoint()
        return ignored_names.intersection(names)

    def copy_snapshot_file(source: str, destination: str) -> str:
        nonlocal copied_files, copied_bytes
        _deadline_checkpoint()
        metadata = os.lstat(source)
        if metadata.st_size > MAX_SOURCE_FILE_BYTES:
            raise ValueError(f"Fresh source file exceeds size limit: {source}")
        copied_files += 1
        copied_bytes += metadata.st_size
        if copied_files > MAX_SOURCE_FILES or copied_bytes > MAX_SOURCE_BYTES:
            raise ValueError("Fresh source snapshot exceeds file-count or aggregate-byte limit")
        copied = shutil.copy2(source, destination)
        _deadline_checkpoint()
        return copied

    with tempfile.TemporaryDirectory(prefix="fork-ops-fresh-") as temp_dir:
        copied_files = 0
        copied_bytes = 0
        snapshot = Path(temp_dir) / "repository"
        _deadline_checkpoint()
        shutil.copytree(
            repo,
            snapshot,
            symlinks=True,
            ignore=ignore_snapshot_paths,
            copy_function=copy_snapshot_file,
        )
        # Fresh-resolution mode intentionally mutates only this second-generation
        # private copy. The verified execution snapshot remains immutable.
        (snapshot / "uv.lock").chmod(0o600)
        _deadline_checkpoint()
        checks = [
            _fresh_resolution_check(
                snapshot,
                interpreter,
                candidate_container=candidate_container,
            )
        ]
        if checks[0]["status"] != "passed":
            return checks, _sha256(snapshot / "uv.lock"), {}
        with tempfile.TemporaryDirectory(prefix="fork-ops-fresh-inventory-") as inventory_dir:
            with _minimal_subprocess_environment(Path(inventory_dir)) as environment:
                scope_inventory = _package_scope_inventory_check(
                    snapshot,
                    subprocess_env=environment,
                )
        lock_digest = _sha256(snapshot / "uv.lock")
        matrix = _dependency_matrix(scope_inventory[1], scope_inventory[2])
        matrix_digest = hashlib.sha256(
            _canonical_json_bytes({"package_tuples": matrix["package_tuples"]})
        ).hexdigest()
        candidate_identity = {
            "commit_sha": commit_sha,
            "source_snapshot_sha256": source_snapshot_sha256,
            "uv_lock_sha256": lock_digest,
            "package_scope_inventory_sha256": matrix_digest,
            "package_scope_collection_sha256": scope_inventory[3],
        }
        checks.append(
            _dependency_audit_matrix_check(
                snapshot,
                interpreter,
                scope_inventory[1],
                scope_inventory[2],
                candidate_identity,
                producer_identity,
            )
        )
        source_checks, scope_provenance = _source_checks(
            snapshot,
            interpreter,
            diff_repo=diff_repo or repo,
            diff_base=diff_base,
            scope_inventory=scope_inventory,
            candidate_container=candidate_container,
        )
        checks.extend(source_checks)
        return checks, lock_digest, scope_provenance


def _requirements_provenance(path: Path, scope: str) -> dict[str, Any]:
    text = _read_text(path)
    logical_lines = text.replace("\\\n", " ").splitlines()
    requirements = [
        line.strip()
        for line in logical_lines
        if line.strip() and not line.lstrip().startswith(("#", "--"))
    ]
    unhashed = [line for line in requirements if "--hash=sha256:" not in line]
    non_registry = [
        line
        for line in requirements
        if re.match(r"^[A-Za-z0-9][A-Za-z0-9._-]*==[^\s;\\]+", line) is None
    ]
    if not requirements:
        raise ValueError(f"{scope} export did not contain any requirements")
    if unhashed:
        raise ValueError(f"{scope} export contains requirements without SHA-256 hashes")
    if non_registry:
        raise ValueError(f"{scope} export contains non-registry or non-exact requirements")
    return {
        "scope": scope,
        "sha256": _sha256(path),
        "requirement_count": len(requirements),
        "hash_policy": "sha256_required",
    }


def _normalized_requirement_names(path: Path) -> set[str]:
    logical_lines = _read_text(path).replace("\\\n", " ").splitlines()
    names: set[str] = set()
    for line in logical_lines:
        stripped = line.strip()
        if not stripped or stripped.startswith(("#", "--")):
            continue
        match = re.match(r"^([A-Za-z0-9][A-Za-z0-9._-]*)\s*(?:==|@|[<>=!~;])", stripped)
        if match is None:
            raise ValueError(f"Unable to identify exported requirement: {stripped}")
        names.add(re.sub(r"[-_.]+", "-", match.group(1)).lower())
    if not names:
        raise ValueError("Locked export did not contain any package names")
    return names


def _normalized_requirement_versions(path: Path) -> dict[str, str]:
    logical_lines = _read_text(path).replace("\\\n", " ").splitlines()
    versions: dict[str, str] = {}
    for line in logical_lines:
        stripped = line.strip()
        if not stripped or stripped.startswith(("#", "--")):
            continue
        match = re.match(
            r"^([A-Za-z0-9][A-Za-z0-9._-]*)==([^\s;\\]+)",
            stripped,
        )
        if match is None:
            raise ValueError(f"Unable to identify exact locked version: {stripped}")
        package = re.sub(r"[-_.]+", "-", match.group(1)).lower()
        version = match.group(2)
        if package in versions and versions[package] != version:
            raise ValueError(f"Conflicting locked versions for {package}")
        versions[package] = version
    if not versions:
        raise ValueError("Locked export did not contain any exact package versions")
    return versions


def _package_scope_inventory_check(
    repo: Path,
    *,
    subprocess_env: dict[str, str] | None = None,
) -> tuple[
    dict[str, Any],
    dict[str, dict[str, list[str]]],
    dict[str, dict[str, str]],
    str,
]:
    started = time.monotonic()
    inventory: dict[str, dict[str, list[str]]] = {}
    version_inventory: dict[str, dict[str, str]] = {}
    export_records: list[dict[str, Any]] = []
    child_checks: list[dict[str, Any]] = []
    graph_arguments = {
        "runtime": ["--package", "fork-ops", "--no-dev"],
        "optional": ["--package", "fork-ops", "--extra", "mcp", "--no-dev"],
        "build": ["--package", "fork-ops", "--only-group", "build"],
        "test": ["--package", "fork-ops", "--only-group", "test"],
        "development": [
            "--package",
            "fork-ops",
            "--only-group",
            "development",
        ],
    }
    with tempfile.TemporaryDirectory(prefix="fork-ops-package-scopes-") as temp_dir:
        root = Path(temp_dir)
        for python_minor in SUPPORTED_PYTHON_MINORS:
            graph_packages: dict[str, set[str]] = {}
            graph_versions: dict[str, dict[str, str]] = {}
            for scope in DEPENDENCY_SCOPES:
                locked_export_path = root / f"python-{python_minor}-{scope}-locked.txt"
                resolved_scope_path = root / f"python-{python_minor}-{scope}.txt"
                export_check = _run_command(
                    f"package_scope_export:{python_minor}:{scope}",
                    ["dependency_scope_inventory"],
                    [f"dependency_scope.{python_minor}.{scope}"],
                    [
                        "uv",
                        "export",
                        "--locked",
                        *graph_arguments[scope],
                        "--no-default-groups",
                        "--no-emit-project",
                        "--no-emit-workspace",
                        "--no-annotate",
                        "--no-header",
                        "--output-file",
                        str(locked_export_path),
                        "--python",
                        python_minor,
                    ],
                    cwd=repo,
                    env=subprocess_env,
                )
                child_checks.append(export_check)
                if export_check["status"] != "passed":
                    continue
                try:
                    locked_provenance = _requirements_provenance(
                        locked_export_path,
                        f"{scope}_python_{python_minor}",
                    )
                except (OSError, UnicodeError, ValueError) as exc:
                    export_check["status"] = "failed"
                    export_check["exit_code"] = 1
                    export_check["stderr_tail"] = str(exc)
                    continue
                marker_check = _run_command(
                    f"package_scope_markers:{python_minor}:{scope}",
                    ["dependency_scope_inventory"],
                    [f"dependency_scope.{python_minor}.{scope}"],
                    [
                        "uv",
                        "pip",
                        "compile",
                        str(locked_export_path),
                        "--python-version",
                        python_minor,
                        "--python-platform",
                        "linux",
                        "--no-deps",
                        "--no-header",
                        "--no-annotate",
                        "--generate-hashes",
                        "--output-file",
                        str(resolved_scope_path),
                    ],
                    cwd=repo,
                    env=subprocess_env,
                )
                child_checks.append(marker_check)
                if marker_check["status"] != "passed":
                    continue
                try:
                    resolved_provenance = _requirements_provenance(
                        resolved_scope_path,
                        f"resolved_{scope}_python_{python_minor}",
                    )
                    graph_packages[scope] = _normalized_requirement_names(resolved_scope_path)
                    graph_versions[scope] = _normalized_requirement_versions(resolved_scope_path)
                except (OSError, UnicodeError, ValueError) as exc:
                    marker_check["status"] = "failed"
                    marker_check["exit_code"] = 1
                    marker_check["stderr_tail"] = str(exc)
                    continue
                export_records.append(
                    {
                        "python_minor": python_minor,
                        "scope": scope,
                        "locked_export_sha256": locked_provenance["sha256"],
                        "locked_requirement_count": locked_provenance["requirement_count"],
                        "resolved_scope_sha256": resolved_provenance["sha256"],
                        "resolved_requirement_count": resolved_provenance["requirement_count"],
                    }
                )
            if set(graph_packages) != set(DEPENDENCY_SCOPES):
                continue
            graph_packages["optional"] -= graph_packages["runtime"]
            package_scopes: dict[str, list[str]] = {}
            for scope in DEPENDENCY_SCOPES:
                for package in sorted(graph_packages[scope]):
                    package_scopes.setdefault(package, []).append(scope)
            if any(
                not any(scope in scopes for scopes in package_scopes.values())
                for scope in DEPENDENCY_SCOPES
            ):
                child_checks.append(
                    _blocked_check(
                        f"package_scope_coverage:{python_minor}",
                        ["dependency_scope_inventory"],
                        [f"dependency_scope.{python_minor}.all_scopes"],
                        f"Python {python_minor} inventory did not cover all dependency scopes.",
                    )
                )
                continue
            inventory[python_minor] = dict(sorted(package_scopes.items()))
            versions: dict[str, str] = {}
            for scope in DEPENDENCY_SCOPES:
                for package, version in graph_versions[scope].items():
                    if package in versions and versions[package] != version:
                        child_checks.append(
                            _blocked_check(
                                f"package_version_conflict:{python_minor}:{package}",
                                ["dependency_scope_inventory"],
                                [f"dependency_version.{python_minor}.{package}"],
                                f"Conflicting locked versions for {package}.",
                            )
                        )
                    versions[package] = version
            version_inventory[python_minor] = dict(sorted(versions.items()))

    failed = [check for check in child_checks if check["status"] != "passed"]
    if set(inventory) != set(SUPPORTED_PYTHON_MINORS):
        failed.append(
            _blocked_check(
                "package_scope_supported_python",
                ["dependency_scope_inventory"],
                ["dependency_scope.supported_python_minors"],
                "Package scope inventory is incomplete for Python 3.11 through 3.14.",
            )
        )
    package_tuples = [
        {
            "python_version": python_minor,
            "package": package,
            "locked_version": version_inventory[python_minor][package],
            "dependency_scopes": scopes,
        }
        for python_minor in SUPPORTED_PYTHON_MINORS
        if python_minor in inventory and python_minor in version_inventory
        for package, scopes in inventory[python_minor].items()
        if package in version_inventory[python_minor]
    ]
    normalized = json.dumps(
        {"package_tuples": package_tuples},
        sort_keys=True,
        separators=(",", ":"),
    )
    digest = hashlib.sha256(normalized.encode("utf-8")).hexdigest()
    stdout = "".join(check["stdout_tail"] for check in child_checks)
    stderr = "".join(check["stderr_tail"] for check in failed)
    aggregate: dict[str, Any] = {
        "id": "package_scope_inventory",
        "behavior_classes": ["dependency_scope_inventory"],
        "required_ids": [
            f"dependency_scope.{python_minor}.{scope}"
            for python_minor in SUPPORTED_PYTHON_MINORS
            for scope in DEPENDENCY_SCOPES
        ],
        "status": "failed" if failed else "passed",
        "exit_code": failed[0]["exit_code"] if failed else 0,
        "duration_ms": round((time.monotonic() - started) * 1000),
        "command": [
            "uv",
            "export",
            "--locked",
            "<scope-matrix>",
            "then",
            "uv",
            "pip",
            "compile",
            "<per-minor-markers>",
        ],
        "commands": [check["command"] for check in child_checks],
        "stdout_tail": stdout[-4000:],
        "stderr_tail": stderr[-4000:],
        "stdout_sha256": hashlib.sha256(stdout.encode("utf-8")).hexdigest(),
        "timed_out": any(check["timed_out"] for check in child_checks),
        "inventory_sha256": digest,
        "exports": export_records,
    }
    return aggregate, inventory, version_inventory, digest


def _blocked_check(
    check_id: str,
    behavior_classes: list[str],
    required_ids: list[str],
    message: str,
) -> dict[str, Any]:
    return {
        "id": check_id,
        "behavior_classes": behavior_classes,
        "required_ids": required_ids,
        "status": "failed",
        "exit_code": 1,
        "duration_ms": 0,
        "command": [],
        "stdout_tail": "",
        "stderr_tail": message,
        "stdout_sha256": hashlib.sha256(b"").hexdigest(),
        "timed_out": False,
    }


def _build_checks(
    repo: Path,
    interpreter: str,
    artifact_dir: Path,
    *,
    candidate_container: bool = False,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    if artifact_dir.exists() and any(artifact_dir.iterdir()):
        return (
            [
                _blocked_check(
                    "build_distributions",
                    ["candidate_packaging"],
                    ["build.wheel_and_sdist_once"],
                    "Artifact directory must be absent or empty.",
                )
            ],
            {},
        )
    artifact_dir.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="fork-ops-build-constraints-") as temp_dir:
        temp_root = Path(temp_dir)
        if candidate_container:
            with _minimal_subprocess_environment(temp_root / "host") as subprocess_env:
                return _build_checks_in_environment(
                    repo,
                    interpreter,
                    artifact_dir,
                    temp_root,
                    subprocess_env,
                    candidate_container=True,
                )
        return _build_checks_in_environment(
            repo,
            interpreter,
            artifact_dir,
            temp_root,
            None,
            candidate_container=False,
        )


def _build_checks_in_environment(
    repo: Path,
    interpreter: str,
    artifact_dir: Path,
    temp_root: Path,
    subprocess_env: dict[str, str] | None,
    *,
    candidate_container: bool,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    constraints_path = temp_root / "build-requirements.txt"
    constraints_check = _run_command(
        "build_constraints",
        ["build_dependency_lock"],
        ["build.requirements_locked_hashed"],
        [
            "uv",
            "export",
            "--locked",
            "--only-group",
            "build",
            "--no-default-groups",
            "--no-emit-project",
            "--no-emit-workspace",
            "--no-annotate",
            "--no-header",
            "--output-file",
            str(constraints_path),
            "--python",
            interpreter,
        ],
        cwd=repo,
        env=subprocess_env,
    )
    provenance: dict[str, Any] = {}
    if constraints_check["status"] == "passed":
        try:
            provenance = _requirements_provenance(
                constraints_path,
                "pep517_build_isolation",
            )
        except (OSError, UnicodeError, ValueError) as exc:
            constraints_check["status"] = "failed"
            constraints_check["exit_code"] = 1
            constraints_check["stderr_tail"] = str(exc)
        else:
            constraints_check["requirements"] = provenance
    audit_check = _run_command(
        "build_dependency_audit",
        ["build_dependency_audit"],
        ["build.requirements_audited"],
        [
            "uv",
            "audit",
            "--locked",
            "--only-group",
            "build",
            "--python-version",
            _python_minor(interpreter),
        ],
        cwd=repo,
        env=subprocess_env,
    )
    isolation_check: dict[str, Any] | None = None
    if constraints_check["status"] == "passed" and audit_check["status"] == "passed":
        if candidate_container:
            isolation_check, build_check = _isolated_build_backend_checks(
                repo,
                interpreter,
                artifact_dir,
                temp_root,
                constraints_path,
                subprocess_env or {},
            )
        else:
            build_check = _run_command(
                "build_distributions",
                ["candidate_packaging"],
                ["build.wheel_and_sdist_once"],
                [
                    "uv",
                    "build",
                    "--package",
                    "fork-ops",
                    "--python",
                    interpreter,
                    "--build-constraints",
                    str(constraints_path),
                    "--require-hashes",
                    "--out-dir",
                    str(artifact_dir),
                    "--no-create-gitignore",
                ],
                cwd=repo,
            )
    else:
        build_check = _blocked_check(
            "build_distributions",
            ["candidate_packaging"],
            ["build.wheel_and_sdist_once"],
            "Build was not executed because its locked constraints or audit failed.",
        )
    wheels, sdists, unexpected = _candidate_artifact_paths(artifact_dir)
    if build_check["status"] == "passed" and (
        len(wheels) != 1 or len(sdists) != 1 or unexpected
    ):
        build_check["status"] = "failed"
        build_check["exit_code"] = 1
        build_check["stderr_tail"] = (
            "Build must produce a closed artifact set containing exactly one regular "
            "wheel and one regular source distribution. Unexpected entries: "
            + (", ".join(unexpected) if unexpected else "none")
        )
    checks = [constraints_check, audit_check]
    if isolation_check is not None:
        checks.append(isolation_check)
    checks.append(build_check)
    return checks, provenance


def _isolated_build_backend_checks(
    repo: Path,
    interpreter: str,
    artifact_dir: Path,
    temp_root: Path,
    constraints_path: Path,
    subprocess_env: dict[str, str],
) -> tuple[dict[str, Any], dict[str, Any]]:
    environment = temp_root / "environment"
    environment_python = environment / "bin" / "python"
    parts = [
        _run_command(
            "build_isolation_venv",
            ["candidate_isolation"],
            ["build.container_dependencies"],
            ["uv", "venv", "--python", interpreter, str(environment)],
            cwd=repo,
            env=subprocess_env,
        )
    ]
    if parts[0]["status"] == "passed":
        parts.append(
            _run_command(
                "build_isolation_sync",
                ["candidate_isolation"],
                ["build.container_dependencies"],
                [
                    "uv",
                    "pip",
                    "sync",
                    "--python",
                    str(environment_python),
                    "--strict",
                    "--require-hashes",
                    "--only-binary",
                    ":all:",
                    str(constraints_path),
                ],
                cwd=repo,
                env=subprocess_env,
            )
        )
    python_minor = _python_minor(interpreter)
    image = PYTHON_CONTAINER_IMAGES.get(python_minor)
    failures = [part for part in parts if part["status"] != "passed"]
    if image is None or os.name == "nt":
        failures.append(
            _blocked_check(
                "build_isolation_image",
                ["candidate_isolation"],
                ["build.digest_pinned_python_container"],
                f"No digest-pinned Linux container is defined for Python {python_minor}.",
            )
        )
    stdout = "".join(part["stdout_tail"] for part in parts)
    stderr = "".join(part["stderr_tail"] for part in failures)
    isolation_check = {
        "id": "build_isolation",
        "behavior_classes": ["candidate_isolation", "candidate_packaging"],
        "required_ids": [
            "build.container_dependencies",
            "build.digest_pinned_python_container",
            "build.no_host_credentials",
            "build.no_host_network",
            "build.private_writable_source",
            "build.explicit_output_mount",
        ],
        "status": "failed" if failures else "passed",
        "exit_code": failures[0]["exit_code"] if failures else 0,
        "duration_ms": sum(part["duration_ms"] for part in parts),
        "command": ["docker", "run", "<digest-pinned-python-container>"],
        "commands": [part["command"] for part in parts],
        "stdout_tail": stdout[-4000:],
        "stderr_tail": stderr[-4000:],
        "stdout_sha256": hashlib.sha256(stdout.encode("utf-8")).hexdigest(),
        "timed_out": any(part["timed_out"] for part in parts),
        "environment_policy": "container_explicit_minimal",
    }
    if failures or image is None:
        return isolation_check, _blocked_check(
            "build_distributions",
            ["candidate_packaging", "candidate_isolation"],
            ["build.wheel_and_sdist_once", "build.pep517_backend_isolated"],
            "Build backend was not executed because candidate isolation failed.",
        )
    scratch_repo = temp_root / "candidate-scratch"
    shutil.copytree(repo, scratch_repo)
    _make_private_tree_group_writable(scratch_repo)
    original_artifact_mode = stat.S_IMODE(artifact_dir.lstat().st_mode)
    _make_private_tree_group_writable(artifact_dir)
    site_packages = environment / "lib" / f"python{python_minor}" / "site-packages"
    build_script = (
        "from pathlib import Path; "
        "from setuptools import build_meta; "
        "output=Path('/output'); "
        "build_meta.build_wheel(str(output)); "
        "build_meta.build_sdist(str(output))"
    )
    try:
        build_check = _run_command(
            "build_distributions",
            ["candidate_packaging", "candidate_isolation"],
            ["build.wheel_and_sdist_once", "build.pep517_backend_isolated"],
            [
                *_candidate_container_base(user=_host_group_container_user()),
                "--workdir=/workspace/plugins/fork-ops",
                f"--mount=type=bind,src={scratch_repo},dst=/workspace",
                f"--mount=type=bind,src={site_packages},dst=/opt/fork-ops/site-packages,readonly",
                f"--mount=type=bind,src={artifact_dir},dst=/output",
                image,
                *_isolated_python_argv(
                    ["/opt/fork-ops/site-packages", "/workspace/plugins/fork-ops"],
                    ["-c", build_script],
                ),
            ],
            cwd=repo,
            env=subprocess_env,
        )
    finally:
        os.chmod(artifact_dir, original_artifact_mode, follow_symlinks=False)
    build_check["environment_policy"] = "container_explicit_minimal"
    return isolation_check, build_check


MCP_PROTOCOL_CLIENT = r"""
import json
import sys
from datetime import timedelta

import anyio
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client


async def validate() -> None:
    server = StdioServerParameters(command=sys.argv[1], args=sys.argv[2:])
    protocol = {}
    async with stdio_client(server) as (read_stream, write_stream):
        async with ClientSession(
            read_stream,
            write_stream,
            read_timeout_seconds=timedelta(seconds=30),
        ) as session:
            initialized = await session.initialize()
            listed = await session.list_tools()
            tool_names = sorted(tool.name for tool in listed.tools)
            if "fork_ops_schema" not in tool_names:
                raise RuntimeError("fork_ops_schema was not advertised")
            called = await session.call_tool("fork_ops_schema", {})
            if called.isError:
                raise RuntimeError("fork_ops_schema returned an MCP tool error")
            protocol = {
                "protocol_version": initialized.protocolVersion,
                "tools": tool_names,
                "call": "fork_ops_schema",
            }
    protocol["shutdown"] = "clean"
    print(json.dumps(protocol, sort_keys=True))


anyio.run(validate)
"""


INSTALLED_GRAPH_SCRIPT = r"""
import importlib.metadata
import json

distributions = sorted(
    f"{distribution.metadata['Name']}=={distribution.version}"
    for distribution in importlib.metadata.distributions()
    if distribution.metadata.get('Name')
)
print(json.dumps({'distributions': distributions}, sort_keys=True))
"""


def _installed_checks(
    repo: Path,
    interpreter: str,
    artifact_dir: Path,
    *,
    release_container: bool = False,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    wheels, sdists, unexpected = _candidate_artifact_paths(artifact_dir)
    if len(wheels) != 1 or len(sdists) != 1 or unexpected:
        return (
            [
                _blocked_check(
                    "candidate_artifacts",
                    ["candidate_packaging"],
                    ["installed.exactly_one_wheel"],
                    "Installed validation requires a closed artifact set containing one "
                    "regular wheel and one regular sdist. Unexpected entries: "
                    + (", ".join(unexpected) if unexpected else "none"),
                )
            ],
            {},
        )

    with tempfile.TemporaryDirectory(prefix="fork-ops-installed-") as temp_dir:
        temp_root = Path(temp_dir)
        environment = temp_root / "environment"
        with _minimal_subprocess_environment(temp_root) as subprocess_env:
            return _installed_checks_in_environment(
                repo,
                interpreter,
                artifact_dir,
                environment,
                subprocess_env,
                release_container=release_container,
            )


def _installed_checks_in_environment(
    repo: Path,
    interpreter: str,
    artifact_dir: Path,
    environment: Path,
    subprocess_env: dict[str, str],
    *,
    release_container: bool,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    wheels, _, _ = _candidate_artifact_paths(artifact_dir)
    scripts_dir = environment / ("Scripts" if os.name == "nt" else "bin")
    environment_python = scripts_dir / ("python.exe" if os.name == "nt" else "python")
    cli = scripts_dir / ("fork-ops.exe" if os.name == "nt" else "fork-ops")
    mcp_server = scripts_dir / ("fork-ops-mcp.exe" if os.name == "nt" else "fork-ops-mcp")
    python_minor = _python_minor(interpreter)
    container_image = PYTHON_CONTAINER_IMAGES.get(python_minor)
    site_packages = environment / "lib" / f"python{python_minor}" / "site-packages"
    runtime_requirements = environment.parent / "runtime-requirements.txt"
    checks = [
        _run_command(
            "clean_environment",
            ["installed_wheel"],
            ["installed.clean_environment"],
            ["uv", "venv", "--python", interpreter, str(environment)],
            cwd=repo,
            env=subprocess_env,
        )
    ]
    constraints_check = _run_command(
        "runtime_constraints",
        ["runtime_dependency_lock"],
        ["runtime.fork-ops[mcp]_locked_hashed"],
        [
            "uv",
            "export",
            "--locked",
            "--package",
            "fork-ops",
            "--extra",
            "mcp",
            "--no-dev",
            "--no-default-groups",
            "--no-emit-workspace",
            "--no-annotate",
            "--no-header",
            "--output-file",
            str(runtime_requirements),
            "--python",
            interpreter,
        ],
        cwd=repo,
        env=subprocess_env,
    )
    runtime_provenance: dict[str, Any] = {}
    if constraints_check["status"] == "passed":
        try:
            exported = _requirements_provenance(
                runtime_requirements,
                "fork-ops[mcp]_runtime",
            )
        except (OSError, UnicodeError, ValueError) as exc:
            constraints_check["status"] = "failed"
            constraints_check["exit_code"] = 1
            constraints_check["stderr_tail"] = str(exc)
        else:
            constraints_check["requirements"] = exported
            runtime_provenance = {
                "scope": exported["scope"],
                "requirements_sha256": exported["sha256"],
                "requirement_count": exported["requirement_count"],
                "hash_policy": exported["hash_policy"],
            }
    checks.append(constraints_check)
    if constraints_check["status"] == "passed" and checks[0]["status"] == "passed":
        sync_check = _run_command(
            "sync_runtime_dependencies",
            ["runtime_dependency_lock"],
            ["runtime.sync_exact_hashed_graph"],
            [
                "uv",
                "pip",
                "sync",
                "--python",
                str(environment_python),
                "--strict",
                "--require-hashes",
                "--only-binary",
                ":all:",
                str(runtime_requirements),
            ],
            cwd=repo,
            env=subprocess_env,
        )
    else:
        sync_check = _blocked_check(
            "sync_runtime_dependencies",
            ["runtime_dependency_lock"],
            ["runtime.sync_exact_hashed_graph"],
            "Runtime sync was not executed because the environment or export failed.",
        )
    checks.append(sync_check)
    if sync_check["status"] == "passed":
        install_check = _run_command(
            "install_wheel",
            ["installed_wheel", "candidate_packaging"],
            ["installed.wheel_no_dependency_resolution"],
            [
                "uv",
                "pip",
                "install",
                "--python",
                str(environment_python),
                "--strict",
                "--no-deps",
                "--no-index",
                "--only-binary",
                ":all:",
                str(wheels[0]),
            ],
            cwd=repo,
            env=subprocess_env,
        )
    else:
        install_check = _blocked_check(
            "install_wheel",
            ["installed_wheel", "candidate_packaging"],
            ["installed.wheel_no_dependency_resolution"],
            "Wheel installation was not executed because runtime sync failed.",
        )
    checks.append(install_check)
    dependency_check = (
        _run_command(
            "installed_dependency_check",
            ["runtime_dependency_lock"],
            ["runtime.installed_dependency_consistency"],
            [
                "uv",
                "pip",
                "check",
                "--python",
                str(environment_python),
            ],
            cwd=repo,
            env=subprocess_env,
        )
        if install_check["status"] == "passed"
        else _blocked_check(
            "installed_dependency_check",
            ["runtime_dependency_lock"],
            ["runtime.installed_dependency_consistency"],
            "Dependency check was not executed because wheel installation failed.",
        )
    )
    checks.append(dependency_check)
    if release_container and install_check["status"] == "passed":
        site_packages.mkdir(parents=True, exist_ok=True)
        if container_image is None or os.name == "nt":
            container_identity = _blocked_check(
                "container_python_identity",
                ["installed_wheel", "candidate_isolation"],
                ["installed.digest_pinned_python_container"],
                f"No digest-pinned Linux container is defined for Python {python_minor}.",
            )
        else:
            container_identity = _run_container_command(
                "container_python_identity",
                ["installed_wheel", "candidate_isolation"],
                ["installed.digest_pinned_python_container"],
                repo=repo,
                environment_root=environment.parent,
                subprocess_env=subprocess_env,
                site_packages=site_packages,
                expected_schema=repo / "plugins" / "fork-ops" / "schema" / "fork-ops.schema.json",
                image=container_image,
                python_args=[
                    "-c",
                    "import json,platform; print(json.dumps({'minor': "
                    "'.'.join(platform.python_version_tuple()[:2])}))",
                ],
            )
            if container_identity["status"] == "passed":
                try:
                    observed_minor = json.loads(container_identity["_stdout_complete"])["minor"]
                except (json.JSONDecodeError, KeyError, TypeError):
                    observed_minor = ""
                if observed_minor != python_minor:
                    container_identity["status"] = "failed"
                    container_identity["exit_code"] = 1
                    container_identity["stderr_tail"] = (
                        "Pinned container Python minor did not match the requested interpreter."
                    )
        checks.append(container_identity)
    else:
        container_identity = None
    candidate_ready = install_check["status"] == "passed" and (
        not release_container
        or (container_identity is not None and container_identity["status"] == "passed")
    )
    graph_check = (
        _run_command(
            "installed_graph",
            ["runtime_dependency_lock"],
            ["runtime.installed_graph_identity"],
            (
                _container_command(
                    site_packages,
                    repo / "plugins" / "fork-ops" / "schema" / "fork-ops.schema.json",
                    container_image or "",
                    ["-c", INSTALLED_GRAPH_SCRIPT],
                )
                if release_container
                else [str(environment_python), "-c", INSTALLED_GRAPH_SCRIPT]
            ),
            cwd=repo,
            env=subprocess_env,
        )
        if candidate_ready
        else _blocked_check(
            "installed_graph",
            ["runtime_dependency_lock"],
            ["runtime.installed_graph_identity"],
            "Installed graph was not captured because wheel installation failed.",
        )
    )
    if graph_check["status"] == "passed":
        try:
            graph_payload = json.loads(graph_check["_stdout_complete"])
            distributions = graph_payload["distributions"]
            if not isinstance(distributions, list) or not all(
                isinstance(item, str) for item in distributions
            ):
                raise TypeError("distributions must be a string list")
        except (json.JSONDecodeError, KeyError, TypeError) as exc:
            graph_check["status"] = "failed"
            graph_check["exit_code"] = 1
            graph_check["stderr_tail"] = f"Invalid installed graph result: {exc}"
        else:
            normalized = json.dumps(
                sorted(distributions),
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8")
            runtime_provenance["installed_distributions"] = sorted(distributions)
            runtime_provenance["installed_graph_sha256"] = hashlib.sha256(normalized).hexdigest()
            graph_check["graph_sha256"] = runtime_provenance["installed_graph_sha256"]
    checks.append(graph_check)
    cli_check = (
        _run_command(
            "installed_cli",
            ["cli", "installed_wheel"],
            ["cli.installed_help"],
            (
                _container_command(
                    site_packages,
                    repo / "plugins" / "fork-ops" / "schema" / "fork-ops.schema.json",
                    container_image or "",
                    ["-m", "fork_ops.cli", "--help"],
                )
                if release_container
                else [str(cli), "--help"]
            ),
            cwd=repo,
            env=subprocess_env,
        )
        if candidate_ready
        else _blocked_check(
            "installed_cli",
            ["cli", "installed_wheel"],
            ["cli.installed_help"],
            "Installed CLI was not executed because candidate isolation was not ready.",
        )
    )
    checks.append(cli_check)
    schema_check = (
        _run_command(
            "installed_schema",
            ["cli", "packaged_schema", "installed_wheel"],
            ["schema.installed_resource_parity"],
            (
                _container_command(
                    site_packages,
                    repo / "plugins" / "fork-ops" / "schema" / "fork-ops.schema.json",
                    container_image or "",
                    ["-m", "fork_ops.cli", "schema", "print"],
                )
                if release_container
                else [str(cli), "schema", "print"]
            ),
            cwd=repo,
            env=subprocess_env,
        )
        if candidate_ready
        else _blocked_check(
            "installed_schema",
            ["cli", "packaged_schema", "installed_wheel"],
            ["schema.installed_resource_parity"],
            "Installed schema was not executed because candidate isolation was not ready.",
        )
    )
    expected_schema = _read_bytes(repo / "plugins" / "fork-ops" / "schema" / "fork-ops.schema.json")
    if (
        schema_check["status"] == "passed"
        and schema_check["stdout_sha256"] != hashlib.sha256(expected_schema).hexdigest()
    ):
        schema_check["status"] = "failed"
        schema_check["exit_code"] = 1
        schema_check["stderr_tail"] = "Installed schema resource differs from source schema."
    checks.append(schema_check)
    mcp_check = (
        _run_command(
            "mcp_protocol",
            ["mcp", "mcp_tool_catalog", "installed_wheel"],
            [
                "mcp.initialize",
                "mcp.tools/list",
                *[f"mcp.tool_discovery.{tool}" for tool in MCP_TOOL_NAMES],
                "mcp.tools/call:fork_ops_schema",
                "mcp.shutdown",
            ],
            (
                _container_command(
                    site_packages,
                    repo / "plugins" / "fork-ops" / "schema" / "fork-ops.schema.json",
                    container_image or "",
                    [
                        "-c",
                        MCP_PROTOCOL_CLIENT,
                        *_isolated_python_argv(
                            ["/opt/fork-ops/site-packages"],
                            ["-m", "fork_ops.mcp_server"],
                        ),
                    ],
                )
                if release_container
                else [str(environment_python), "-c", MCP_PROTOCOL_CLIENT, str(mcp_server)]
            ),
            cwd=repo,
            env=subprocess_env,
        )
        if candidate_ready
        else _blocked_check(
            "mcp_protocol",
            ["mcp", "mcp_tool_catalog", "installed_wheel"],
            [
                "mcp.initialize",
                "mcp.tools/list",
                *[f"mcp.tool_discovery.{tool}" for tool in MCP_TOOL_NAMES],
                "mcp.tools/call:fork_ops_schema",
                "mcp.shutdown",
            ],
            "MCP protocol was not executed because candidate isolation was not ready.",
        )
    )
    if mcp_check["status"] == "passed":
        try:
            protocol = json.loads(mcp_check["_stdout_complete"])
            if not isinstance(protocol, dict):
                raise TypeError("MCP protocol result must be an object")
        except (json.JSONDecodeError, TypeError):
            mcp_check["status"] = "failed"
            mcp_check["exit_code"] = 1
            mcp_check["stderr_tail"] = "MCP protocol smoke did not emit its JSON result."
        else:
            mcp_check["protocol"] = protocol
            if protocol.get("tools") != list(MCP_TOOL_NAMES):
                mcp_check["status"] = "failed"
                mcp_check["exit_code"] = 1
                mcp_check["stderr_tail"] = (
                    "MCP advertised tool names did not match the validation contract."
                )
    checks.append(mcp_check)
    for check in checks:
        command = check.get("command")
        if isinstance(command, list) and command and command[0] == "docker":
            check["environment_policy"] = "container_explicit_minimal"
        else:
            check.setdefault("environment_policy", "explicit_minimal")
    return checks, runtime_provenance


def _container_command(
    site_packages: Path,
    expected_schema: Path,
    image: str,
    python_args: list[str],
) -> list[str]:
    return [
        *_candidate_container_base(),
        f"--mount=type=bind,src={site_packages},dst=/opt/fork-ops/site-packages,readonly",
        f"--mount=type=bind,src={expected_schema},dst=/opt/fork-ops/expected-schema.json,readonly",
        image,
        *_isolated_python_argv(["/opt/fork-ops/site-packages"], python_args),
    ]


def _run_container_command(
    check_id: str,
    behavior_classes: list[str],
    required_ids: list[str],
    *,
    repo: Path,
    environment_root: Path,
    subprocess_env: dict[str, str],
    site_packages: Path,
    expected_schema: Path,
    image: str,
    python_args: list[str],
) -> dict[str, Any]:
    del environment_root
    check = _run_command(
        check_id,
        behavior_classes,
        required_ids,
        _container_command(site_packages, expected_schema, image, python_args),
        cwd=repo,
        env=subprocess_env,
    )
    check["environment_policy"] = "container_explicit_minimal"
    return check


def _candidate_artifact_paths(
    artifact_dir: Path,
) -> tuple[list[Path], list[Path], list[str]]:
    wheels: list[Path] = []
    sdists: list[Path] = []
    unexpected: list[str] = []
    if not artifact_dir.is_dir():
        return wheels, sdists, unexpected
    for path in sorted(artifact_dir.iterdir()):
        _deadline_checkpoint()
        try:
            mode = path.lstat().st_mode
        except FileNotFoundError:
            unexpected.append(path.name)
            continue
        if not stat.S_ISREG(mode):
            unexpected.append(path.name)
        elif path.name.endswith(".whl"):
            wheels.append(path)
        elif path.name.endswith(".tar.gz"):
            sdists.append(path)
        else:
            unexpected.append(path.name)
    return wheels, sdists, unexpected


def _artifact_records(artifact_dir: Path | None) -> list[dict[str, Any]]:
    if artifact_dir is None or not artifact_dir.is_dir():
        return []
    wheels, sdists, unexpected = _candidate_artifact_paths(artifact_dir)
    if len(wheels) != 1 or len(sdists) != 1 or unexpected:
        return []
    records = []
    for path in sorted((*wheels, *sdists)):
        records.append(
            {
                "filename": path.name,
                "kind": "wheel" if path.suffix == ".whl" else "sdist",
                "sha256": _sha256(path),
                "size": path.stat().st_size,
            }
        )
    return records


def _candidate_identity_check(
    repo: Path,
    artifact_dir: Path,
    build_evidence_path: Path,
    source_snapshot_sha256: str,
) -> dict[str, Any]:
    check: dict[str, Any] = {
        "id": "candidate_identity",
        "behavior_classes": ["candidate_packaging", "validation_evidence"],
        "required_ids": [
            "candidate.commit",
            "candidate.source_snapshot",
            "candidate.lock",
            "candidate.artifact_hashes",
            "candidate.test_contract",
        ],
        "status": "passed",
        "exit_code": 0,
        "duration_ms": 0,
        "command": [],
        "stdout_tail": "",
        "stderr_tail": "",
        "stdout_sha256": hashlib.sha256(b"").hexdigest(),
        "timed_out": False,
    }
    try:
        build_evidence = json.loads(_read_text(build_evidence_path))
        expected_identity = build_evidence["identity"]
        expected_artifacts = expected_identity["artifacts"]
    except (FileNotFoundError, KeyError, json.JSONDecodeError, TypeError) as exc:
        check["status"] = "failed"
        check["exit_code"] = 1
        check["stderr_tail"] = f"Build evidence is not usable: {exc}"
        return check

    mismatches = []
    if build_evidence.get("artifact_kind") != ARTIFACT_KIND:
        mismatches.append("artifact_kind")
    if build_evidence.get("schema_version") != SCHEMA_VERSION:
        mismatches.append("schema_version")
    if build_evidence.get("mode") != "build" or build_evidence.get("outcome") != "passed":
        mismatches.append("build_outcome")
    if expected_identity.get("commit_sha") != _git_commit(repo):
        mismatches.append("commit_sha")
    if expected_identity.get("source_snapshot_sha256") != source_snapshot_sha256:
        mismatches.append("source_snapshot_sha256")
    if expected_identity.get("lock_sha256") != _sha256(repo / "uv.lock"):
        mismatches.append("lock_sha256")
    wheels, sdists, unexpected = _candidate_artifact_paths(artifact_dir)
    if len(wheels) != 1 or len(sdists) != 1 or unexpected:
        mismatches.append("artifact_set")
    if expected_artifacts != _artifact_records(artifact_dir):
        mismatches.append("artifact_hashes")
    if expected_identity.get("test_contract") != f"{TEST_CONTRACT}/build":
        mismatches.append("test_contract")
    if mismatches:
        check["status"] = "failed"
        check["exit_code"] = 1
        check["stderr_tail"] = "Candidate identity mismatch: " + ", ".join(mismatches)
    return check


def _github_json(url: str, token: str) -> dict[str, Any]:
    request = urllib.request.Request(
        url,
        headers={
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {token}",
            "User-Agent": "fork-ops-validation-evidence",
            "X-GitHub-Api-Version": "2022-11-28",
        },
    )
    try:
        with urllib.request.urlopen(
            request,
            timeout=_effective_timeout(60.0),
        ) as response:
            chunks: list[bytes] = []
            while chunk := response.read(1024 * 1024):
                _deadline_checkpoint()
                chunks.append(chunk)
            payload = json.loads(b"".join(chunks))
    except (OSError, urllib.error.HTTPError, urllib.error.URLError, json.JSONDecodeError) as exc:
        raise RuntimeError(f"GitHub Actions API request failed for {url}: {exc}") from exc
    if not isinstance(payload, dict):
        raise TypeError(f"GitHub Actions API response for {url} must be an object")
    return payload


def _nested(payload: dict[str, Any], *keys: str) -> Any:
    value: Any = payload
    for key in keys:
        if not isinstance(value, dict):
            return None
        value = value.get(key)
    return value


def _github_timestamp(value: object, label: str) -> datetime:
    if not isinstance(value, str) or not value.endswith("Z"):
        raise ValueError(f"{label} must be an RFC 3339 UTC timestamp")
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        raise ValueError(f"{label} must include a timezone")
    return parsed.astimezone(UTC)


def _release_preflight_receipt_payload(evidence: dict[str, Any]) -> dict[str, Any]:
    return {
        key: value
        for key, value in evidence.items()
        if key != "preflight_receipt"
    }


def _release_preflight_receipt(
    evidence: dict[str, Any],
    key: bytes,
) -> dict[str, str]:
    payload = json.dumps(
        _release_preflight_receipt_payload(evidence),
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return {
        "version": RELEASE_PREFLIGHT_RECEIPT_VERSION,
        "algorithm": "hmac-sha256",
        "payload_sha256": hashlib.sha256(payload).hexdigest(),
        "mac": hmac.new(key, payload, hashlib.sha256).hexdigest(),
    }


def _release_provenance_freshness_mismatches(
    provenance: dict[str, Any],
) -> list[str]:
    mismatches: list[str] = []
    now = datetime.now(UTC)
    observed_bound = provenance.get("freshness_bound_seconds")
    bound = RELEASE_EVIDENCE_MAX_AGE_SECONDS
    if observed_bound != bound:
        mismatches.append("release.freshness_bound_seconds")
    try:
        evaluated_at = _github_timestamp(provenance.get("evaluated_at"), "release.evaluated_at")
        if evaluated_at > now or (now - evaluated_at).total_seconds() > bound:
            raise ValueError("release evaluation is stale or future-dated")
    except (TypeError, ValueError) as exc:
        mismatches.append(f"release.evaluated_at:{exc}")
        evaluated_at = now

    run_timestamps = provenance.get("run_timestamps")
    try:
        if not isinstance(run_timestamps, dict):
            raise TypeError("release run timestamps must be an object")
        run_times = {
            name: _github_timestamp(run_timestamps.get(name), f"release.run.{name}")
            for name in ("created_at", "run_started_at", "updated_at")
        }
        if not (
            run_times["created_at"]
            <= run_times["run_started_at"]
            <= run_times["updated_at"]
            <= evaluated_at
            <= now
        ):
            raise ValueError("release run timestamps are stale, future-dated, or out of order")
        if (now - run_times["created_at"]).total_seconds() > bound:
            raise ValueError("release run exceeds the freshness bound")
    except (TypeError, ValueError) as exc:
        mismatches.append(f"release.run_timestamps:{exc}")
        run_times = {"created_at": evaluated_at}

    artifact_ids = provenance.get("artifact_ids")
    artifact_digests = provenance.get("artifact_digests")
    artifact_timestamps = provenance.get("artifact_timestamps")
    if (
        not isinstance(artifact_ids, dict)
        or len(artifact_ids) != 2
        or any(not isinstance(artifact_id, int) for artifact_id in artifact_ids.values())
    ):
        mismatches.append("release.artifact_ids")
        artifact_names: set[str] = set()
    else:
        artifact_names = set(artifact_ids)
    if (
        not isinstance(artifact_digests, dict)
        or set(artifact_digests) != artifact_names
        or any(
            not isinstance(digest, str)
            or re.fullmatch(r"sha256:[0-9a-f]{64}", digest) is None
            for digest in artifact_digests.values()
        )
    ):
        mismatches.append("release.artifact_digests")
    if not isinstance(artifact_timestamps, dict) or set(artifact_timestamps) != artifact_names:
        mismatches.append("release.artifact_timestamps")
    else:
        for artifact_name in sorted(artifact_names):
            timestamps = artifact_timestamps.get(artifact_name)
            try:
                if not isinstance(timestamps, dict):
                    raise TypeError("artifact timestamps must be an object")
                artifact_times = {
                    name: _github_timestamp(
                        timestamps.get(name),
                        f"release.artifact.{artifact_name}.{name}",
                    )
                    for name in ("created_at", "updated_at", "expires_at")
                }
                if not (
                    run_times["created_at"]
                    <= artifact_times["created_at"]
                    <= artifact_times["updated_at"]
                    <= evaluated_at
                    <= now
                    < artifact_times["expires_at"]
                ):
                    raise ValueError("artifact timestamps are stale, future-dated, or out of order")
                if (now - artifact_times["created_at"]).total_seconds() > bound:
                    raise ValueError("artifact exceeds the freshness bound")
            except (TypeError, ValueError) as exc:
                mismatches.append(f"release.artifact.{artifact_name}.timestamps:{exc}")
    return mismatches


def _release_trust_check(
    repo: Path,
    build_evidence_path: Path | None,
    *,
    run_id: str,
    run_attempt: str,
    workflow_path: str,
    event_name: str,
    candidate_artifact_name: str,
    evidence_artifact_name: str,
    release_workflow_ref: str,
    release_workflow_sha: str,
    release_workflow_path: str,
    verifier_repository: str,
    trusted_verifier_sha: str,
) -> dict[str, Any]:
    started = time.monotonic()
    check: dict[str, Any] = {
        "id": "release_trust",
        "behavior_classes": ["release_provenance"],
        "required_ids": [
            "release.api_successful_completed_run",
            "release.api_exact_head_main",
            "release.api_workflow_path_event_attempt",
            "release.api_candidate_and_evidence_artifacts",
            "release.build_evidence_producer_binding",
            "release.current_workflow_candidate_binding",
            "release.immutable_verifier",
            "release.dispatch_defining_workflow_main_candidate",
        ],
        "status": "passed",
        "exit_code": 0,
        "duration_ms": 0,
        "command": ["GET", "GitHub Actions run and artifact metadata"],
        "stdout_tail": "",
        "stderr_tail": "",
        "stdout_sha256": hashlib.sha256(b"").hexdigest(),
        "timed_out": False,
    }
    mismatches: list[str] = []
    token = os.environ.get("GITHUB_TOKEN", "")
    repository = os.environ.get("GITHUB_REPOSITORY", "")
    current_candidate_sha = os.environ.get("GITHUB_SHA", "")
    api_url = os.environ.get("GITHUB_API_URL", "https://api.github.com").rstrip("/")
    if not token:
        mismatches.append("environment.GITHUB_TOKEN")
    if not repository or "/" not in repository:
        mismatches.append("environment.GITHUB_REPOSITORY")
    try:
        expected_attempt = int(run_attempt)
        expected_run_id = int(run_id)
    except ValueError:
        mismatches.append("input.run_id_or_attempt")
        expected_attempt = -1
        expected_run_id = -1

    run_payload: dict[str, Any] = {}
    artifacts_payload: dict[str, Any] = {}
    latest_runs_payload: dict[str, Any] = {}
    build_evidence: dict[str, Any] = {}
    if not mismatches:
        try:
            run_payload = _github_json(
                f"{api_url}/repos/{repository}/actions/runs/{run_id}",
                token,
            )
            artifacts_payload = _github_json(
                f"{api_url}/repos/{repository}/actions/runs/{run_id}/artifacts?per_page=100",
                token,
            )
            encoded_workflow = urllib.parse.quote(workflow_path, safe="")
            latest_runs_payload = _github_json(
                f"{api_url}/repos/{repository}/actions/workflows/{encoded_workflow}/"
                f"runs?branch=main&event={urllib.parse.quote(event_name, safe='')}"
                "&status=success&per_page=100",
                token,
            )
            if build_evidence_path is None:
                raise FileNotFoundError(
                    "--build-evidence is required for trusted release validation"
                )
            loaded = json.loads(_read_text(build_evidence_path))
            if not isinstance(loaded, dict):
                raise TypeError("build evidence must be an object")
            build_evidence = loaded
        except (OSError, RuntimeError, TypeError, json.JSONDecodeError) as exc:
            mismatches.append(f"provenance_unavailable:{exc}")

    commit_sha = _git_commit(repo)
    expected_workflow_ref = f"{repository}/{workflow_path}@refs/heads/main"
    release_workflow_prefix = f"{verifier_repository}/{release_workflow_path}@"
    verifier_repo = Path(__file__).resolve().parents[1]
    try:
        verifier_commit = _git_commit(verifier_repo)
    except (OSError, subprocess.CalledProcessError, subprocess.TimeoutExpired):
        verifier_commit = ""
    release_expectations = {
        "release.candidate_sha": (current_candidate_sha, commit_sha),
        "release.workflow_sha": (release_workflow_sha, trusted_verifier_sha),
        "release.verifier_commit": (verifier_commit, trusted_verifier_sha),
    }
    mismatches.extend(
        label
        for label, (actual, expected) in release_expectations.items()
        if not expected or actual != expected
    )

    evaluated_at = datetime.now(UTC)
    run_times: dict[str, datetime] = {}
    try:
        run_times = {
            name: _github_timestamp(run_payload.get(name), f"run.{name}")
            for name in ("created_at", "run_started_at", "updated_at")
        }
        if not (
            run_times["created_at"]
            <= run_times["run_started_at"]
            <= run_times["updated_at"]
            <= evaluated_at
        ):
            raise ValueError("run timestamps are future-dated or out of order")
        if (
            evaluated_at - run_times["created_at"]
        ).total_seconds() > RELEASE_EVIDENCE_MAX_AGE_SECONDS:
            raise ValueError("run exceeds the 24-hour release freshness bound")
    except (TypeError, ValueError) as exc:
        mismatches.append(f"run.timestamps:{exc}")

    latest_runs = latest_runs_payload.get("workflow_runs", [])
    if not isinstance(latest_runs, list):
        latest_runs = list[Any]()
        mismatches.append("latest_runs.response_shape")
    latest_total = latest_runs_payload.get("total_count")
    if not isinstance(latest_total, int) or latest_total != len(latest_runs):
        mismatches.append("latest_runs.complete_listing")
    matching_latest = [
        item
        for item in latest_runs
        if isinstance(item, dict)
        and item.get("head_sha") == commit_sha
        and item.get("path") == workflow_path
        and item.get("event") == event_name
        and item.get("conclusion") == "success"
        and item.get("status") == "completed"
    ]
    if not matching_latest or matching_latest[0].get("id") != expected_run_id:
        mismatches.append("run.latest_successful_candidate_lineage")
    if not verifier_repository or "/" not in verifier_repository:
        mismatches.append("release.verifier_repository")
    if release_workflow_path != ".github/workflows/release-validation.yml":
        mismatches.append("release.workflow_file_path")
    allowed_release_workflow_refs = {
        f"{release_workflow_prefix}refs/heads/main",
        f"{release_workflow_prefix}{trusted_verifier_sha}",
    }
    if release_workflow_ref not in allowed_release_workflow_refs:
        mismatches.append("release.workflow_ref")
    if (
        os.environ.get("GITHUB_EVENT_NAME") == "workflow_dispatch"
        and verifier_repository == repository
        and (
            release_workflow_ref != f"{release_workflow_prefix}refs/heads/main"
            or release_workflow_sha != commit_sha
        )
    ):
        mismatches.append("release.dispatch_defining_workflow_main_candidate")
    run_expectations = {
        "run.id": (run_payload.get("id"), expected_run_id),
        "run.attempt": (run_payload.get("run_attempt"), expected_attempt),
        "run.name": (run_payload.get("name"), "Validation"),
        "run.path": (run_payload.get("path"), workflow_path),
        "run.event": (run_payload.get("event"), event_name),
        "run.status": (run_payload.get("status"), "completed"),
        "run.conclusion": (run_payload.get("conclusion"), "success"),
        "run.head_sha": (run_payload.get("head_sha"), commit_sha),
        "run.head_branch": (run_payload.get("head_branch"), "main"),
        "run.repository": (_nested(run_payload, "repository", "full_name"), repository),
        "run.head_repository": (
            _nested(run_payload, "head_repository", "full_name"),
            repository,
        ),
    }
    mismatches.extend(
        label for label, (actual, expected) in run_expectations.items() if actual != expected
    )

    artifacts: list[Any] = artifacts_payload.get("artifacts", [])
    if not isinstance(artifacts, list):
        artifacts = list[Any]()
        mismatches.append("artifacts.response_shape")
    total_count = artifacts_payload.get("total_count")
    if not isinstance(total_count, int) or total_count != len(artifacts):
        mismatches.append("artifacts.complete_listing")
    trusted_artifact_ids: dict[str, int] = {}
    trusted_artifact_digests: dict[str, str] = {}
    trusted_artifact_timestamps: dict[str, dict[str, str]] = {}
    for expected_name in (candidate_artifact_name, evidence_artifact_name):
        matches = [
            artifact
            for artifact in artifacts
            if isinstance(artifact, dict)
            and artifact.get("name") == expected_name
            and artifact.get("expired") is False
        ]
        if len(matches) != 1:
            mismatches.append(f"artifact.{expected_name}")
            continue
        artifact = matches[0]
        artifact_expectations = {
            f"artifact.{expected_name}.run_id": (
                _nested(artifact, "workflow_run", "id"),
                expected_run_id,
            ),
            f"artifact.{expected_name}.head_sha": (
                _nested(artifact, "workflow_run", "head_sha"),
                commit_sha,
            ),
            f"artifact.{expected_name}.head_branch": (
                _nested(artifact, "workflow_run", "head_branch"),
                "main",
            ),
        }
        mismatches.extend(
            label
            for label, (actual, expected) in artifact_expectations.items()
            if actual != expected
        )
        artifact_id = artifact.get("id")
        if isinstance(artifact_id, int):
            trusted_artifact_ids[expected_name] = artifact_id
        digest = artifact.get("digest")
        if not isinstance(digest, str) or re.fullmatch(r"sha256:[0-9a-f]{64}", digest) is None:
            mismatches.append(f"artifact.{expected_name}.digest")
        else:
            trusted_artifact_digests[expected_name] = digest
        try:
            artifact_times = {
                name: _github_timestamp(
                    artifact.get(name),
                    f"artifact.{expected_name}.{name}",
                )
                for name in ("created_at", "updated_at", "expires_at")
            }
            if not (
                run_times.get("created_at", evaluated_at)
                <= artifact_times["created_at"]
                <= artifact_times["updated_at"]
                <= evaluated_at
                < artifact_times["expires_at"]
            ):
                raise ValueError("artifact timestamps are stale, future-dated, or out of order")
            if (
                evaluated_at - artifact_times["created_at"]
            ).total_seconds() > RELEASE_EVIDENCE_MAX_AGE_SECONDS:
                raise ValueError("artifact exceeds the 24-hour release freshness bound")
        except (TypeError, ValueError) as exc:
            mismatches.append(f"artifact.{expected_name}.timestamps:{exc}")
        else:
            trusted_artifact_timestamps[expected_name] = {
                name: artifact_times[name].isoformat().replace("+00:00", "Z")
                for name in ("created_at", "updated_at", "expires_at")
            }

    producer: dict[str, Any] = build_evidence.get("producer", {})
    if not isinstance(producer, dict):
        producer = dict[str, Any]()
    producer_expectations = {
        "producer.identity": (producer.get("identity"), "github-actions"),
        "producer.repository": (producer.get("repository"), repository),
        "producer.workflow_ref": (producer.get("workflow_ref"), expected_workflow_ref),
        "producer.workflow_sha": (producer.get("workflow_sha"), commit_sha),
        "producer.run_id": (producer.get("run_id"), run_id),
        "producer.run_attempt": (producer.get("run_attempt"), run_attempt),
        "producer.event_name": (producer.get("event_name"), event_name),
        "producer.candidate_sha": (producer.get("candidate_sha"), commit_sha),
        "producer.test_contract": (
            producer.get("test_contract"),
            f"{TEST_CONTRACT}/build",
        ),
    }
    mismatches.extend(
        label for label, (actual, expected) in producer_expectations.items() if actual != expected
    )

    if mismatches:
        check["status"] = "failed"
        check["exit_code"] = 1
        check["stderr_tail"] = "Release trust mismatch: " + ", ".join(dict.fromkeys(mismatches))
    else:
        provenance = {
            "repository": repository,
            "workflow_name": "Validation",
            "workflow_path": workflow_path,
            "event": event_name,
            "head_branch": "main",
            "head_sha": commit_sha,
            "run_id": run_id,
            "run_attempt": run_attempt,
            "artifact_ids": trusted_artifact_ids,
            "artifact_digests": trusted_artifact_digests,
            "artifact_timestamps": trusted_artifact_timestamps,
            "run_timestamps": {
                name: value.isoformat().replace("+00:00", "Z") for name, value in run_times.items()
            },
            "evaluated_at": evaluated_at.isoformat().replace("+00:00", "Z"),
            "freshness_bound_seconds": RELEASE_EVIDENCE_MAX_AGE_SECONDS,
            "release_candidate_sha": current_candidate_sha,
            "release_workflow_ref": release_workflow_ref,
            "release_workflow_sha": release_workflow_sha,
            "release_workflow_file_path": release_workflow_path,
            "verifier_repository": verifier_repository,
            "verifier_sha": trusted_verifier_sha,
            "assurance_scope": "repository_owned_observational_validation",
        }
        rendered = json.dumps(provenance, sort_keys=True, separators=(",", ":"))
        check["provenance"] = provenance
        check["stdout_sha256"] = hashlib.sha256(rendered.encode("utf-8")).hexdigest()
    check["duration_ms"] = round((time.monotonic() - started) * 1000)
    return check


def _release_preflight_evidence_check(
    repo: Path,
    artifact_dir: Path,
    preflight_evidence_path: Path,
    preflight_key_path: Path,
    source_snapshot_sha256: str,
    trusted_release_workflow_ref: str,
    trusted_release_workflow_sha: str,
    trusted_release_workflow_path: str,
    trusted_verifier_repository: str,
    trusted_verifier_sha: str,
) -> tuple[dict[str, Any], dict[str, Any]]:
    check: dict[str, Any] = {
        "id": "release_preflight",
        "behavior_classes": ["release_provenance"],
        "required_ids": [
            "release.preflight_terminal_success",
            "release.preflight_candidate_identity",
            "release.preflight_verifier_binding",
            "release.candidate_process_token_isolation",
        ],
        "status": "passed",
        "exit_code": 0,
        "duration_ms": 0,
        "command": [],
        "stdout_tail": "",
        "stderr_tail": "",
        "stdout_sha256": hashlib.sha256(b"").hexdigest(),
        "timed_out": False,
    }
    started = time.monotonic()
    mismatches: list[str] = []
    try:
        preflight_key = _consume_release_preflight_key(preflight_key_path, repo)
    except (FileNotFoundError, OSError, ValueError) as exc:
        check["status"] = "failed"
        check["exit_code"] = 1
        check["stderr_tail"] = f"Release preflight key is not usable: {exc}"
        check["duration_ms"] = round((time.monotonic() - started) * 1000)
        return check, {}
    try:
        loaded = json.loads(_read_text(preflight_evidence_path))
        if not isinstance(loaded, dict):
            raise TypeError("release preflight evidence must be an object")
        preflight_evidence: dict[str, Any] = loaded
        preflight_identity = preflight_evidence.get("identity", {})
        preflight_producer = preflight_evidence.get("producer", {})
        preflight_checks = preflight_evidence.get("checks", [])
        preflight_assurance = preflight_evidence.get("assurance_boundary", {})
        dependency_provenance = preflight_evidence.get("dependency_provenance", {})
        preflight_receipt = preflight_evidence.get("preflight_receipt", {})
        if not isinstance(preflight_identity, dict):
            raise TypeError("release preflight identity must be an object")
        if not isinstance(preflight_producer, dict):
            raise TypeError("release preflight producer must be an object")
        if not isinstance(preflight_checks, list):
            raise TypeError("release preflight checks must be an array")
        if not isinstance(preflight_assurance, dict):
            raise TypeError("release preflight assurance boundary must be an object")
        if not isinstance(dependency_provenance, dict):
            raise TypeError("release preflight dependency provenance must be an object")
        if not isinstance(preflight_receipt, dict):
            raise TypeError("release preflight receipt must be an object")
        release_provenance = dependency_provenance.get("release", {})
        if not isinstance(release_provenance, dict):
            raise TypeError("release provenance must be an object")
    except (FileNotFoundError, json.JSONDecodeError, OSError, TypeError) as exc:
        check["status"] = "failed"
        check["exit_code"] = 1
        check["stderr_tail"] = f"Release preflight evidence is not usable: {exc}"
        check["duration_ms"] = round((time.monotonic() - started) * 1000)
        return check, {}

    expected_receipt = _release_preflight_receipt(preflight_evidence, preflight_key)
    if preflight_receipt != expected_receipt:
        mismatches.append("preflight_receipt")

    expected_identity = {
        "commit_sha": _git_commit(repo),
        "source_snapshot_sha256": source_snapshot_sha256,
        "lock_sha256": _sha256(repo / "uv.lock"),
        "artifacts": _artifact_records(artifact_dir),
        "test_contract": f"{TEST_CONTRACT}/release-preflight",
    }
    repository = os.environ.get("GITHUB_REPOSITORY", "")
    evidence_expectations = {
        "artifact_kind": (preflight_evidence.get("artifact_kind"), ARTIFACT_KIND),
        "schema_version": (preflight_evidence.get("schema_version"), SCHEMA_VERSION),
        "mode": (preflight_evidence.get("mode"), "release-preflight"),
        "outcome": (preflight_evidence.get("outcome"), "passed"),
        "assurance.scope": (
            preflight_assurance.get("scope"),
            "repository_owned_observational_validation",
        ),
        "assurance.security_evidence_envelope": (
            preflight_assurance.get("security_evidence_envelope"),
            False,
        ),
        "assurance.security_authority": (
            preflight_assurance.get("security_authority"),
            False,
        ),
        **{
            f"identity.{key}": (preflight_identity.get(key), value)
            for key, value in expected_identity.items()
        },
        "producer.identity": (preflight_producer.get("identity"), "github-actions"),
        "producer.repository": (preflight_producer.get("repository"), repository),
        "producer.workflow_ref": (
            preflight_producer.get("workflow_ref"),
            trusted_release_workflow_ref,
        ),
        "producer.workflow_sha": (
            preflight_producer.get("workflow_sha"),
            trusted_release_workflow_sha,
        ),
        "producer.run_id": (
            preflight_producer.get("run_id"),
            os.environ.get("GITHUB_RUN_ID", ""),
        ),
        "producer.run_attempt": (
            preflight_producer.get("run_attempt"),
            os.environ.get("GITHUB_RUN_ATTEMPT", ""),
        ),
        "producer.event_name": (
            preflight_producer.get("event_name"),
            os.environ.get("GITHUB_EVENT_NAME", ""),
        ),
        "producer.candidate_sha": (
            preflight_producer.get("candidate_sha"),
            expected_identity["commit_sha"],
        ),
        "producer.test_contract": (
            preflight_producer.get("test_contract"),
            f"{TEST_CONTRACT}/release-preflight",
        ),
        "release.repository": (release_provenance.get("repository"), repository),
        "release.workflow_name": (release_provenance.get("workflow_name"), "Validation"),
        "release.workflow_path": (
            release_provenance.get("workflow_path"),
            ".github/workflows/validation.yml",
        ),
        "release.event": (release_provenance.get("event"), "push"),
        "release.head_branch": (release_provenance.get("head_branch"), "main"),
        "release.head_sha": (
            release_provenance.get("head_sha"),
            expected_identity["commit_sha"],
        ),
        "release.release_candidate_sha": (
            release_provenance.get("release_candidate_sha"),
            expected_identity["commit_sha"],
        ),
        "release.release_workflow_ref": (
            release_provenance.get("release_workflow_ref"),
            trusted_release_workflow_ref,
        ),
        "release.release_workflow_sha": (
            release_provenance.get("release_workflow_sha"),
            trusted_release_workflow_sha,
        ),
        "release.release_workflow_file_path": (
            release_provenance.get("release_workflow_file_path"),
            trusted_release_workflow_path,
        ),
        "release.verifier_repository": (
            release_provenance.get("verifier_repository"),
            trusted_verifier_repository,
        ),
        "release.verifier_sha": (
            release_provenance.get("verifier_sha"),
            trusted_verifier_sha,
        ),
        "release.assurance_scope": (
            release_provenance.get("assurance_scope"),
            "repository_owned_observational_validation",
        ),
    }
    mismatches.extend(
        label for label, (actual, expected) in evidence_expectations.items() if actual != expected
    )
    observed_checks = [
        (item.get("id"), item.get("status")) for item in preflight_checks if isinstance(item, dict)
    ]
    if observed_checks != [("release_trust", "passed"), ("candidate_identity", "passed")]:
        mismatches.append("checks.release_trust_and_candidate_identity")
    run_id = release_provenance.get("run_id")
    run_attempt = release_provenance.get("run_attempt")
    if not isinstance(run_id, str) or re.fullmatch(r"[1-9][0-9]*", run_id) is None:
        mismatches.append("release.run_id")
    if not isinstance(run_attempt, str) or re.fullmatch(r"[1-9][0-9]*", run_attempt) is None:
        mismatches.append("release.run_attempt")
    mismatches.extend(_release_provenance_freshness_mismatches(release_provenance))
    if os.environ.get("GITHUB_TOKEN"):
        mismatches.append("environment.GITHUB_TOKEN")
    if trusted_release_workflow_sha != trusted_verifier_sha:
        mismatches.append("release.workflow_sha")
    verifier_repo = Path(__file__).resolve().parents[1]
    try:
        verifier_commit = _git_commit(verifier_repo)
    except (OSError, subprocess.CalledProcessError, subprocess.TimeoutExpired):
        verifier_commit = ""
    if not trusted_verifier_sha or verifier_commit != trusted_verifier_sha:
        mismatches.append("release.verifier_commit")
    if mismatches:
        check["status"] = "failed"
        check["exit_code"] = 1
        check["stderr_tail"] = "Release preflight mismatch: " + ", ".join(dict.fromkeys(mismatches))
        release_provenance = dict[str, Any]()
    else:
        rendered = json.dumps(
            release_provenance,
            sort_keys=True,
            separators=(",", ":"),
        )
        check["stdout_sha256"] = hashlib.sha256(rendered.encode("utf-8")).hexdigest()
    check["duration_ms"] = round((time.monotonic() - started) * 1000)
    return check, release_provenance


def _interpreter_identity(interpreter: str) -> dict[str, str]:
    script = (
        "import json,platform,sys,sysconfig; "
        "print(json.dumps({'executable':sys.executable,'implementation':platform.python_implementation(),"
        "'version':platform.python_version(),'abi':sysconfig.get_config_var('SOABI') or ''}))"
    )
    executable = _trusted_executable(interpreter)
    completed = _run_bounded_process(
        [str(executable), "-I", "-S", "-c", script],
        cwd=Path.cwd(),
        env=None,
        timeout=_effective_timeout(),
    )
    if completed.returncode != 0:
        raise subprocess.CalledProcessError(completed.returncode, str(executable))
    identity = json.loads(completed.stdout)
    identity["requested"] = interpreter
    identity["resolved"] = str(executable)
    identity["executable_sha256"] = _sha256(executable)
    return identity


def _git_commit(repo: Path) -> str:
    completed = _run_trusted_git(repo, ["rev-parse", "--verify", "HEAD^{commit}"])
    if completed.returncode != 0:
        raise subprocess.CalledProcessError(completed.returncode, "git rev-parse")
    return completed.stdout.decode("ascii", errors="strict").strip()


def _git_tree_state(repo: Path) -> str:
    completed = _run_trusted_git(
        repo,
        ["status", "--porcelain", "--untracked-files=all"],
    )
    if completed.returncode != 0:
        raise subprocess.CalledProcessError(completed.returncode, "git status")
    return "clean" if not completed.stdout else "dirty"


def _utc_now() -> str:
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


def _dependency_producer_identity() -> dict[str, Any] | None:
    values = {
        "repository": os.environ.get("GITHUB_REPOSITORY", ""),
        "workflow_ref": os.environ.get("GITHUB_WORKFLOW_REF", ""),
        "workflow_sha": os.environ.get("GITHUB_WORKFLOW_SHA", ""),
        "run_id": os.environ.get("GITHUB_RUN_ID", ""),
        "run_attempt": os.environ.get("GITHUB_RUN_ATTEMPT", ""),
    }
    try:
        run_id = int(values["run_id"])
        run_attempt = int(values["run_attempt"])
    except ValueError:
        return None
    if (
        not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", values["repository"])
        or not values["workflow_ref"]
        or re.fullmatch(r"[0-9a-f]{40,64}", values["workflow_sha"]) is None
        or run_id <= 0
        or run_attempt <= 0
    ):
        return None
    return {
        "integration": "github-actions",
        "repository": values["repository"],
        "workflow_ref": values["workflow_ref"],
        "workflow_sha": values["workflow_sha"],
        "run_id": run_id,
        "run_attempt": run_attempt,
        "conclusion": "success",
    }


def _uv_identity() -> dict[str, str]:
    global _TRUSTED_UV_EXECUTABLE, _TRUSTED_UV_SHA256
    executable = _trusted_executable("uv")
    completed = _run_bounded_process(
        [str(executable), "--version"],
        cwd=Path.cwd(),
        env=None,
        timeout=_effective_timeout(),
    )
    if completed.returncode != 0:
        raise subprocess.CalledProcessError(completed.returncode, str(executable))
    digest = _sha256(executable)
    _TRUSTED_UV_EXECUTABLE = executable
    _TRUSTED_UV_SHA256 = digest
    return {
        "version": completed.stdout.decode("utf-8", errors="replace").strip(),
        "executable": str(executable),
        "executable_sha256": digest,
    }


def _producer_identity(
    test_contract: str,
    uv_identity: dict[str, str],
    *,
    workflow_ref_override: str | None = None,
    workflow_sha_override: str | None = None,
) -> dict[str, Any]:
    repository = os.environ.get("GITHUB_REPOSITORY")
    run_id = os.environ.get("GITHUB_RUN_ID")
    workflow_ref = workflow_ref_override or os.environ.get("GITHUB_WORKFLOW_REF")
    if repository and run_id and workflow_ref:
        return {
            "identity": "github-actions",
            "repository": repository,
            "workflow_ref": workflow_ref,
            "workflow_sha": workflow_sha_override or os.environ.get("GITHUB_WORKFLOW_SHA", ""),
            "run_id": run_id,
            "run_attempt": os.environ.get("GITHUB_RUN_ATTEMPT", ""),
            "event_name": os.environ.get("GITHUB_EVENT_NAME", ""),
            "candidate_sha": os.environ.get("GITHUB_SHA", ""),
            "test_contract": test_contract,
            "uv": uv_identity,
        }
    return {
        "identity": "local",
        "executable": str(Path(sys.argv[0]).resolve()),
        "test_contract": test_contract,
        "uv": uv_identity,
    }


def _write_evidence(evidence: dict[str, Any], output: Path | None) -> None:
    rendered = json.dumps(evidence, indent=2, sort_keys=True) + "\n"
    if output is not None:
        _atomic_write_text_nofollow(output, rendered)
    print(rendered, end="")


def _reuse_key(identity: dict[str, Any]) -> str | None:
    interpreter = identity["interpreter"]
    if (
        len(identity["commit_sha"]) != 40
        or len(identity["lock_sha256"]) != 64
        or identity.get("source_tree") != "clean"
        or len(identity.get("source_snapshot_sha256", "")) != 64
        or not interpreter.get("executable")
        or not interpreter.get("version")
    ):
        return None
    return hashlib.sha256(
        json.dumps(identity, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()


def main(argv: list[str] | None = None) -> int:
    global _COMMAND_TIMEOUT_SECONDS, _VALIDATION_DEADLINE

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mode", required=True, choices=MODES)
    parser.add_argument("--interpreter", required=True)
    parser.add_argument("--repo", type=Path, default=Path.cwd())
    parser.add_argument("--artifact-dir", type=Path)
    parser.add_argument("--build-evidence", type=Path)
    parser.add_argument("--release-preflight-evidence", type=Path)
    parser.add_argument("--release-preflight-key-file", type=Path)
    parser.add_argument(
        "--execution-boundary",
        choices=EXECUTION_BOUNDARIES,
        default="local-observational",
        help=(
            "Run candidate code locally without authority, or require the fail-closed "
            "networkless container boundary used by hosted validation."
        ),
    )
    parser.add_argument("--diff-base")
    parser.add_argument("--trusted-main-run-id")
    parser.add_argument("--trusted-main-run-attempt")
    parser.add_argument("--trusted-release-workflow-ref")
    parser.add_argument("--trusted-release-workflow-sha")
    parser.add_argument("--trusted-release-workflow-path")
    parser.add_argument("--trusted-verifier-repository")
    parser.add_argument("--trusted-verifier-sha")
    parser.add_argument(
        "--trusted-workflow-path",
        default=".github/workflows/validation.yml",
    )
    parser.add_argument("--trusted-event", default="push")
    parser.add_argument("--trusted-artifact-name", default="candidate-dist")
    parser.add_argument(
        "--trusted-evidence-artifact-name",
        default="validation-evidence-build",
    )
    parser.add_argument(
        "--command-timeout-seconds",
        type=float,
        default=DEFAULT_COMMAND_TIMEOUT_SECONDS,
    )
    parser.add_argument(
        "--overall-timeout-seconds",
        type=float,
        default=DEFAULT_OVERALL_TIMEOUT_SECONDS,
    )
    parser.add_argument("--output", type=Path)
    args = parser.parse_args(argv)
    if args.command_timeout_seconds <= 0:
        parser.error("--command-timeout-seconds must be greater than zero")
    if args.overall_timeout_seconds <= 0:
        parser.error("--overall-timeout-seconds must be greater than zero")
    _COMMAND_TIMEOUT_SECONDS = args.command_timeout_seconds
    _VALIDATION_DEADLINE = time.monotonic() + args.overall_timeout_seconds

    started_at = _utc_now()
    repo = args.repo.resolve()
    artifact_dir = args.artifact_dir.resolve() if args.artifact_dir is not None else None
    identity: dict[str, Any] = {
        "commit_sha": "",
        "source_tree": "unknown",
        "source_snapshot_sha256": "",
        "lock_sha256": "",
        "artifacts": [],
        "interpreter": {"requested": args.interpreter},
        "platform": {
            "system": platform.system(),
            "release": platform.release(),
            "machine": platform.machine(),
        },
        "test_contract": f"{TEST_CONTRACT}/{args.mode}",
        "diff_base": args.diff_base or "",
    }
    checks: list[dict[str, Any]] = []
    dependency_provenance: dict[str, Any] = {}
    uv_identity = {
        "version": "unavailable",
        "executable": "",
        "executable_sha256": "",
    }
    outcome = "failed"
    exit_code = 1
    release_preflight_key: bytes | None = None
    resources = contextlib.ExitStack()
    try:
        uv_identity = _uv_identity()
        interpreter_identity = _interpreter_identity(args.interpreter)
        identity["interpreter"] = interpreter_identity
        resolved_interpreter = interpreter_identity["resolved"]
        candidate_descriptor, candidate_repo, candidate_root_identity = (
            _bind_candidate_repository(repo)
        )
        resources.callback(os.close, candidate_descriptor)
        identity["commit_sha"] = _git_commit(candidate_repo)
        identity["source_tree"] = _git_tree_state(candidate_repo)
        excluded_paths = [path for path in (artifact_dir, args.output) if path is not None]
        if args.build_evidence is not None:
            excluded_paths.append(args.build_evidence.resolve())
        if args.release_preflight_evidence is not None:
            excluded_paths.append(args.release_preflight_evidence.resolve())
        lock_bytes = _read_bytes(candidate_repo / "uv.lock")
        identity["lock_sha256"] = hashlib.sha256(lock_bytes).hexdigest()
        execution_repo, identity["source_snapshot_sha256"] = resources.enter_context(
            _verified_execution_snapshot(
                repo,
                lock_bytes,
                excluded_paths,
                bound_root_descriptor=candidate_descriptor,
            )
        )
        if args.mode == "locked-source":
            checks, scope_provenance = _source_checks(
                execution_repo,
                resolved_interpreter,
                diff_repo=candidate_repo,
                diff_base=args.diff_base or None,
                candidate_container=args.execution_boundary == "container",
            )
            dependency_provenance.update(scope_provenance)
        elif args.mode == "fresh-source":
            checks, identity["lock_sha256"], scope_provenance = _fresh_source_checks(
                execution_repo,
                resolved_interpreter,
                args.diff_base or None,
                diff_repo=candidate_repo,
                commit_sha=identity["commit_sha"],
                source_snapshot_sha256=identity["source_snapshot_sha256"],
                producer_identity=_dependency_producer_identity(),
                candidate_container=args.execution_boundary == "container",
            )
            dependency_provenance.update(scope_provenance)
        elif args.mode == "build" and artifact_dir is not None:
            checks, build_provenance = _build_checks(
                execution_repo,
                resolved_interpreter,
                artifact_dir,
                candidate_container=args.execution_boundary == "container",
            )
            if build_provenance:
                dependency_provenance["build"] = build_provenance
        elif args.mode == "release-preflight" and artifact_dir is not None:
            if (
                args.build_evidence is None
                or not args.trusted_main_run_id
                or not args.trusted_main_run_attempt
                or not args.trusted_release_workflow_ref
                or not args.trusted_release_workflow_sha
                or not args.trusted_release_workflow_path
                or not args.trusted_verifier_repository
                or not args.trusted_verifier_sha
                or args.release_preflight_key_file is None
            ):
                checks = [
                    _blocked_check(
                        "release_trust",
                        ["release_provenance"],
                        ["release.preflight_inputs"],
                        "Release preflight requires build evidence, run ID, run attempt, "
                        "an immutable called-workflow ref, repository, and SHA, and a "
                        "one-time key path outside the candidate checkout.",
                    )
                ]
            else:
                trust_check = _release_trust_check(
                    candidate_repo,
                    args.build_evidence.resolve(),
                    run_id=args.trusted_main_run_id,
                    run_attempt=args.trusted_main_run_attempt,
                    workflow_path=args.trusted_workflow_path,
                    event_name=args.trusted_event,
                    candidate_artifact_name=args.trusted_artifact_name,
                    evidence_artifact_name=args.trusted_evidence_artifact_name,
                    release_workflow_ref=args.trusted_release_workflow_ref,
                    release_workflow_sha=args.trusted_release_workflow_sha,
                    release_workflow_path=args.trusted_release_workflow_path,
                    verifier_repository=args.trusted_verifier_repository,
                    trusted_verifier_sha=args.trusted_verifier_sha,
                )
                checks = [trust_check]
                if trust_check["status"] == "passed":
                    dependency_provenance["release"] = trust_check["provenance"]
                    checks.append(
                        _candidate_identity_check(
                            candidate_repo,
                            artifact_dir,
                            args.build_evidence.resolve(),
                            identity["source_snapshot_sha256"],
                        )
                    )
        elif args.mode == "installed" and artifact_dir is not None:
            if args.release_preflight_evidence is not None:
                if args.build_evidence is None:
                    checks = [
                        _blocked_check(
                            "release_preflight_inputs",
                            ["release_provenance", "candidate_packaging"],
                            ["release.preflight_and_build_evidence"],
                            "Release installation requires both successful preflight evidence "
                            "and its exact build evidence before candidate execution.",
                        )
                    ]
                elif args.release_preflight_key_file is None:
                    checks = [
                        _blocked_check(
                            "release_preflight",
                            ["release_provenance"],
                            ["release.one_time_preflight_receipt"],
                            "Release installation requires the one-time preflight key path.",
                        )
                    ]
                elif (
                    not args.trusted_release_workflow_ref
                    or not args.trusted_release_workflow_sha
                    or not args.trusted_release_workflow_path
                    or not args.trusted_verifier_repository
                    or not args.trusted_verifier_sha
                ):
                    checks = [
                        _blocked_check(
                            "release_preflight",
                            ["release_provenance"],
                            ["release.immutable_verifier"],
                            "Release installation requires an immutable verifier SHA.",
                        )
                    ]
                else:
                    preflight_check, release_provenance = _release_preflight_evidence_check(
                        candidate_repo,
                        artifact_dir,
                        args.release_preflight_evidence.resolve(),
                        args.release_preflight_key_file,
                        identity["source_snapshot_sha256"],
                        args.trusted_release_workflow_ref,
                        args.trusted_release_workflow_sha,
                        args.trusted_release_workflow_path,
                        args.trusted_verifier_repository,
                        args.trusted_verifier_sha,
                    )
                    checks = [preflight_check]
                    if release_provenance:
                        dependency_provenance["release"] = release_provenance
            if (not checks or checks[0]["status"] == "passed") and args.build_evidence:
                identity_check = _candidate_identity_check(
                    candidate_repo,
                    artifact_dir,
                    args.build_evidence.resolve(),
                    identity["source_snapshot_sha256"],
                )
                checks.append(identity_check)
            if args.build_evidence is None and args.release_preflight_evidence is None:
                installed_checks, runtime_provenance = _installed_checks(
                    execution_repo,
                    resolved_interpreter,
                    artifact_dir,
                    release_container=args.execution_boundary == "container",
                )
                checks.extend(installed_checks)
                if runtime_provenance:
                    dependency_provenance["runtime"] = runtime_provenance
            elif checks and checks[-1]["id"] == "candidate_identity":
                if checks[-1]["status"] == "passed":
                    installed_checks, runtime_provenance = _installed_checks(
                        execution_repo,
                        resolved_interpreter,
                        artifact_dir,
                        release_container=(
                            args.execution_boundary == "container"
                            or args.release_preflight_evidence is not None
                        ),
                    )
                    checks.extend(installed_checks)
                    if runtime_provenance:
                        dependency_provenance["runtime"] = runtime_provenance
        else:
            raise ValueError(f"--mode {args.mode} requires --artifact-dir")
        _verify_candidate_repository_binding(
            repo,
            candidate_descriptor,
            candidate_root_identity,
        )
        _deadline_checkpoint()
        identity["artifacts"] = _artifact_records(artifact_dir)
        outcome = "passed" if all(check["status"] == "passed" for check in checks) else "failed"
        exit_code = 0 if outcome == "passed" else 1
        if args.mode == "release-preflight" and outcome == "passed":
            assert args.release_preflight_key_file is not None
            release_preflight_key = _create_release_preflight_key(
                args.release_preflight_key_file,
                repo,
            )
    except KeyboardInterrupt:
        checks.append(
            {
                "id": "evidence_finalization",
                "behavior_classes": ["validation_evidence"],
                "required_ids": ["evidence.terminal_outcome"],
                "status": "cancelled",
                "exit_code": 130,
                "duration_ms": 0,
                "command": [],
                "stdout_tail": "",
                "stderr_tail": "Validation was interrupted.",
                "stdout_sha256": hashlib.sha256(b"").hexdigest(),
                "timed_out": False,
            }
        )
        outcome = "cancelled"
        exit_code = 130
    except Exception as exc:
        timed_out = isinstance(
            exc,
            (subprocess.TimeoutExpired, ValidationDeadlineExceeded),
        )
        if timed_out:
            exit_code = 124
        if (
            isinstance(exc, subprocess.TimeoutExpired)
            and _VALIDATION_DEADLINE is not None
            and time.monotonic() >= _VALIDATION_DEADLINE
        ):
            failure_detail = (
                f"Validation overall deadline was exhausted while waiting for a subprocess: {exc}"
            )
        else:
            failure_detail = f"{type(exc).__name__}: {exc}"
        checks.append(
            {
                "id": "evidence_finalization",
                "behavior_classes": ["validation_evidence"],
                "required_ids": ["evidence.terminal_outcome"],
                "status": "failed",
                "exit_code": 124 if timed_out else 1,
                "duration_ms": 0,
                "command": [],
                "stdout_tail": "",
                "stderr_tail": failure_detail,
                "stdout_sha256": hashlib.sha256(b"").hexdigest(),
                "timed_out": timed_out,
            }
        )
    resources.close()
    if (
        exit_code not in {124, 130}
        and _VALIDATION_DEADLINE is not None
        and time.monotonic() >= _VALIDATION_DEADLINE
        and any(check.get("timed_out") is True for check in checks)
    ):
        checks.append(
            {
                "id": "evidence_finalization",
                "behavior_classes": ["validation_evidence"],
                "required_ids": ["evidence.terminal_outcome"],
                "status": "failed",
                "exit_code": 124,
                "duration_ms": 0,
                "command": [],
                "stdout_tail": "",
                "stderr_tail": "Validation overall deadline was exhausted.",
                "stdout_sha256": hashlib.sha256(b"").hexdigest(),
                "timed_out": True,
            }
        )
        outcome = "failed"
        exit_code = 124
    _discard_private_check_payloads(checks)
    evidence = {
        "artifact_kind": ARTIFACT_KIND,
        "schema_version": SCHEMA_VERSION,
        "assurance_boundary": {
            "scope": "repository_owned_observational_validation",
            "security_evidence_envelope": False,
            "security_authority": False,
        },
        "mode": args.mode,
        "execution_boundary": args.execution_boundary,
        "outcome": outcome,
        "started_at": started_at,
        "finished_at": _utc_now(),
        "identity": identity,
        "producer": _producer_identity(
            identity["test_contract"],
            uv_identity,
            workflow_ref_override=args.trusted_release_workflow_ref,
            workflow_sha_override=args.trusted_release_workflow_sha,
        ),
        "reuse_key": _reuse_key(identity),
        "checks": checks,
        "dependency_provenance": dependency_provenance,
        "behavior_coverage": {
            "policy": "collected_without_numeric_threshold",
            "classes": sorted({item for check in checks for item in check["behavior_classes"]}),
            "claims": [
                {
                    "class": behavior_class,
                    "required_ids": sorted(
                        {
                            required_id
                            for check in checks
                            if behavior_class in check["behavior_classes"]
                            for required_id in check["required_ids"]
                        }
                    ),
                }
                for behavior_class in sorted(
                    {item for check in checks for item in check["behavior_classes"]}
                )
            ],
        },
    }
    if release_preflight_key is not None:
        evidence["preflight_receipt"] = _release_preflight_receipt(
            evidence,
            release_preflight_key,
        )
    try:
        _write_evidence(evidence, args.output)
    except BaseException:
        if release_preflight_key is not None and args.release_preflight_key_file is not None:
            with contextlib.suppress(FileNotFoundError, OSError, ValueError):
                _consume_release_preflight_key(args.release_preflight_key_file, repo)
        raise
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
