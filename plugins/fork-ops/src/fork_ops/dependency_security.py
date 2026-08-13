"""Deterministic dependency-security evidence evaluation."""

from __future__ import annotations

import contextlib
import hashlib
import json
import os
import re
import stat
import subprocess
import tempfile
import threading
import time
import tomllib
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, Final, SupportsIndex

from .security_exceptions import (
    SecurityExceptionInventory,
    SecurityExceptionRecord,
    is_structural_security_exception_inventory,
)

DEPENDENCY_SCOPES = ("runtime", "optional", "build", "test", "development")
SUPPORTED_PYTHON_VERSIONS = ("3.11", "3.12", "3.13", "3.14")
SUPPORTED_PLATFORMS = ("linux",)
DEPENDENCY_EVIDENCE_SCHEMA_VERSION: Final = "2.0"
DEPENDENCY_PROVENANCE_SCHEMA_VERSION: Final = "1.0"
MAX_OBSERVATION_VALIDITY: Final = timedelta(minutes=15)
UV_AUDIT_TIMEOUT_SECONDS: Final = 120
UV_AUDIT_MAX_OUTPUT_BYTES: Final = 8 * 1024 * 1024
UV_AUDIT_MAX_INPUT_BYTES: Final = 16 * 1024 * 1024
UvAuditRunner = Callable[[list[str], Path], subprocess.CompletedProcess[str]]

_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_GIT_OBJECT_RE = re.compile(r"^(?:[0-9a-f]{40}|[0-9a-f]{64})$")
_OBSERVATION_SEAL: Final = object()
_EVALUATION_SEAL: Final = object()


class VerifiedDependencyEvidence:
    """Immutable in-process evidence returned by a trusted source adapter.

    Serialized projections intentionally lose this capability.  The canonical
    payload is copied into bytes at construction and recomputed at evaluation,
    so later mutation of any adapter-owned mapping cannot change the evidence.
    """

    __slots__ = ("__canonical_payload", "__canonical_payload_sha256", "__seal")
    __canonical_payload: bytes
    __canonical_payload_sha256: str
    __seal: object

    def __new__(cls, *_args: object, **_kwargs: object) -> VerifiedDependencyEvidence:
        raise TypeError("VerifiedDependencyEvidence is created only by a trusted adapter.")

    @classmethod
    def _from_adapter(
        cls,
        payload: Mapping[str, object],
        *,
        seal: object,
    ) -> VerifiedDependencyEvidence:
        if seal is not _OBSERVATION_SEAL:
            raise TypeError("Dependency evidence requires the private adapter seal.")
        canonical_payload = _canonical_json_bytes(payload)
        instance = object.__new__(cls)
        object.__setattr__(
            instance,
            "_VerifiedDependencyEvidence__canonical_payload",
            canonical_payload,
        )
        object.__setattr__(
            instance,
            "_VerifiedDependencyEvidence__canonical_payload_sha256",
            hashlib.sha256(canonical_payload).hexdigest(),
        )
        object.__setattr__(instance, "_VerifiedDependencyEvidence__seal", seal)
        return instance

    def __setattr__(self, _name: str, _value: object) -> None:
        raise AttributeError("VerifiedDependencyEvidence is immutable.")

    def __reduce_ex__(self, _protocol: SupportsIndex, /) -> tuple[Any, ...]:
        raise TypeError("VerifiedDependencyEvidence cannot cross a serialization boundary.")

    def to_dict(self) -> dict[str, object]:
        """Return an observational projection that carries no in-process trust."""
        payload = json.loads(self.__canonical_payload)
        if not isinstance(payload, dict):
            raise RuntimeError("Canonical dependency evidence is not an object.")
        return payload

    def _trusted_payload(self) -> dict[str, object] | None:
        if self.__seal is not _OBSERVATION_SEAL:
            return None
        if hashlib.sha256(self.__canonical_payload).hexdigest() != self.__canonical_payload_sha256:
            return None
        payload = json.loads(self.__canonical_payload)
        if (
            not isinstance(payload, dict)
            or _canonical_json_bytes(payload) != self.__canonical_payload
        ):
            return None
        return payload


class TrustedDependencyEvaluation:
    """Immutable trusted interval and identity binding for one evaluation epoch."""

    __slots__ = ("__canonical_context", "__canonical_context_sha256", "__seal")
    __canonical_context: bytes
    __canonical_context_sha256: str
    __seal: object

    def __new__(cls, *_args: object, **_kwargs: object) -> TrustedDependencyEvaluation:
        raise TypeError("TrustedDependencyEvaluation is created only by a trusted adapter.")

    @classmethod
    def _from_adapter(
        cls,
        context: Mapping[str, object],
        *,
        seal: object,
    ) -> TrustedDependencyEvaluation:
        if seal is not _EVALUATION_SEAL:
            raise TypeError("Dependency evaluation requires the private adapter seal.")
        canonical_context = _canonical_json_bytes(context)
        instance = object.__new__(cls)
        object.__setattr__(
            instance,
            "_TrustedDependencyEvaluation__canonical_context",
            canonical_context,
        )
        object.__setattr__(
            instance,
            "_TrustedDependencyEvaluation__canonical_context_sha256",
            hashlib.sha256(canonical_context).hexdigest(),
        )
        object.__setattr__(instance, "_TrustedDependencyEvaluation__seal", seal)
        return instance

    def __setattr__(self, _name: str, _value: object) -> None:
        raise AttributeError("TrustedDependencyEvaluation is immutable.")

    def __reduce_ex__(self, _protocol: SupportsIndex, /) -> tuple[Any, ...]:
        raise TypeError("TrustedDependencyEvaluation cannot cross a serialization boundary.")

    def _trusted_context(self) -> dict[str, object] | None:
        if self.__seal is not _EVALUATION_SEAL:
            return None
        if hashlib.sha256(self.__canonical_context).hexdigest() != self.__canonical_context_sha256:
            return None
        context = json.loads(self.__canonical_context)
        if (
            not isinstance(context, dict)
            or _canonical_json_bytes(context) != self.__canonical_context
        ):
            return None
        return context


@dataclass(frozen=True)
class _Advisory:
    source: str
    identifiers: tuple[str, ...]
    package: str
    locked_version: str
    affected: bool
    affected_range: str
    fixed_versions: tuple[str, ...]
    dependency_scopes: tuple[str, ...]
    python_versions: tuple[str, ...]


@dataclass(frozen=True)
class _ClaimCoverage:
    dependency_scope: str
    python_version: str


@dataclass(frozen=True)
class _SourceClaim:
    affected: bool
    affected_range: str
    fixed_versions: tuple[str, ...]
    coverage: tuple[_ClaimCoverage, ...]


def collect_uv_audit_evidence(
    repo_path: str | Path,
    *,
    package_scopes_by_python: dict[str, dict[str, list[str]]] | None = None,
    package_versions_by_python: dict[str, dict[str, str]] | None = None,
    candidate_identity: Mapping[str, object] | None = None,
    producer_identity: Mapping[str, object] | None = None,
    observation_epoch: str | None = None,
    runner: UvAuditRunner | None = None,
    uv_executable: str | Path | None = None,
) -> dict[str, object]:
    """Run four locked audits using each interpreter's package-scope inventory."""
    observation_started = datetime.now(UTC)
    inventories = _package_scope_inventories(package_scopes_by_python)
    versions = _package_version_inventories(package_versions_by_python)
    if inventories is None or versions is None:
        return _uv_evidence_failure(
            "Per-interpreter locked package tuple membership is unavailable or invalid."
        )
    package_tuples = _package_tuple_matrix(inventories, versions)
    if package_tuples is None:
        return _uv_evidence_failure(
            "Per-interpreter package names, versions, and scopes do not describe one exact matrix."
        )
    matrix: dict[str, object] = {
        "platform": "linux",
        "python_versions": list(SUPPORTED_PYTHON_VERSIONS),
        "package_tuples": package_tuples,
    }
    normalized_candidate = _candidate_identity(candidate_identity, matrix)
    normalized_producer = _producer_identity(producer_identity)
    if normalized_candidate is None or normalized_producer is None:
        return _uv_evidence_failure(
            "Candidate and immutable producer identities are required for dependency evidence."
        )
    if not isinstance(observation_epoch, str) or _SHA256_RE.fullmatch(observation_epoch) is None:
        return _uv_evidence_failure(
            "A canonical dependency observation epoch is required."
        )
    repo = Path(os.path.abspath(Path(repo_path).expanduser()))
    if runner is not None and uv_executable is not None:
        return _uv_evidence_failure(
            "An injected audit runner and explicit uv executable cannot be combined."
        )
    trusted_uv: Path | None = None
    if runner is None:
        try:
            _validate_uv_audit_project(repo)
            trusted_uv = _trusted_uv_executable(uv_executable)
        except ValueError as exc:
            return _uv_evidence_failure(f"uv audit project policy rejected the candidate: {exc}")
        except (OSError, UnicodeError, tomllib.TOMLDecodeError):
            return _uv_evidence_failure(
                "uv audit project policy could not safely inspect the candidate."
            )
    execute = runner or _run_uv_audit
    matrix_advisories: list[dict[str, object]] = []
    for python_version in SUPPORTED_PYTHON_VERSIONS:
        command = [
            str(trusted_uv) if trusted_uv is not None else "uv",
            "audit",
            "--locked",
            *(
                [
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
                ]
                if trusted_uv is not None
                else []
            ),
            "--output-format",
            "json",
            "--python-platform",
            "linux",
            "--python-version",
            python_version,
        ]
        try:
            completed = execute(command, repo)
        except subprocess.TimeoutExpired:
            return _uv_evidence_failure(
                f"uv audit timed out for Python {python_version}."
            )
        except (OSError, subprocess.SubprocessError, UnicodeError):
            return _uv_evidence_failure(
                f"uv audit could not be executed for Python {python_version}."
            )
        if completed.returncode not in {0, 1}:
            return _uv_evidence_failure(
                f"uv audit did not produce usable evidence for Python {python_version} "
                f"(exit {completed.returncode})."
            )
        try:
            raw = json.loads(completed.stdout)
        except (json.JSONDecodeError, TypeError):
            return _uv_evidence_failure(
                f"uv audit returned malformed JSON evidence for Python {python_version}."
            )
        normalized = _normalize_uv_audit_output(
            raw,
            python_version,
            inventories[python_version],
            versions[python_version],
        )
        if normalized.get("status") != "available":
            return normalized
        advisories = normalized.get("advisories")
        if not isinstance(advisories, list):
            return _uv_evidence_failure("uv audit normalization returned invalid evidence.")
        matrix_advisories.extend(item for item in advisories if isinstance(item, dict))
    merged_advisories = _merge_matrix_advisories(matrix_advisories)
    observation_completed = datetime.now(UTC)
    provenance: dict[str, object] = {
        "schema_version": DEPENDENCY_PROVENANCE_SCHEMA_VERSION,
        "candidate": normalized_candidate,
        "matrix": matrix,
        "producer": normalized_producer,
        "source_observation": {
            "provider": "osv",
            "source_identity": "osv.dev:uv-audit",
            "authenticated": False,
            "pagination_complete": True,
            "page_count": len(SUPPORTED_PYTHON_VERSIONS),
            "item_count": len(merged_advisories),
            "observation_epoch": observation_epoch,
            "started_at": _format_time(observation_started),
            "completed_at": _format_time(observation_completed),
            "valid_until": _format_time(observation_completed + MAX_OBSERVATION_VALIDITY),
        },
    }
    payload = _uv_evidence("available", merged_advisories, [], provenance=provenance)
    return payload


def _trusted_uv_executable(requested: str | Path | None) -> Path:
    if requested is None:
        raise ValueError("an explicit trusted uv executable is required")
    selected = os.fspath(requested)
    if not Path(selected).expanduser().is_absolute():
        raise ValueError("the trusted uv executable must be an absolute path")
    executable = Path(selected).expanduser().resolve(strict=True)
    metadata = executable.stat()
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_mode & 0o111 == 0:
        raise ValueError("uv must be an executable regular file")
    return executable


def _read_regular_input(path: Path) -> bytes:
    lexical = path.lstat()
    if not stat.S_ISREG(lexical.st_mode) or lexical.st_size > UV_AUDIT_MAX_INPUT_BYTES:
        raise ValueError(f"{path.name} must be a bounded regular file")
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    with os.fdopen(descriptor, "rb") as source:
        opened = os.fstat(source.fileno())
        if opened.st_dev != lexical.st_dev or opened.st_ino != lexical.st_ino:
            raise ValueError(f"{path.name} changed before its no-follow read")
        content = source.read(UV_AUDIT_MAX_INPUT_BYTES + 1)
        finished = os.fstat(source.fileno())
    if (
        len(content) > UV_AUDIT_MAX_INPUT_BYTES
        or finished.st_size != opened.st_size
        or finished.st_mtime_ns != opened.st_mtime_ns
        or finished.st_ctime_ns != opened.st_ctime_ns
    ):
        raise ValueError(f"{path.name} changed or exceeded its bounded read")
    return content


def _validate_uv_audit_project(repo: Path) -> None:
    metadata = repo.lstat()
    if not stat.S_ISDIR(metadata.st_mode) or repo.is_symlink():
        raise ValueError("repository must be a plain directory")
    for name in ("uv.toml", ".uv.toml"):
        try:
            (repo / name).lstat()
        except FileNotFoundError:
            continue
        raise ValueError(f"candidate {name} configuration is not permitted")
    _read_regular_input(repo / "uv.lock")
    project = tomllib.loads(_read_regular_input(repo / "pyproject.toml").decode("utf-8"))
    tool = project.get("tool", {})
    if not isinstance(tool, dict):
        raise ValueError("project tool configuration must be a table")
    uv = tool.get("uv", {})
    if not isinstance(uv, dict):
        raise ValueError("project uv configuration must be a table")
    forbidden_uv_keys = {
        "index",
        "index-url",
        "extra-index-url",
        "find-links",
        "keyring-provider",
        "allow-insecure-host",
        "config-settings",
    }
    if forbidden_uv_keys.intersection(uv):
        raise ValueError("candidate index, transport, or build configuration is not permitted")
    sources = uv.get("sources", {})
    if not isinstance(sources, dict) or any(
        not isinstance(value, dict) or value != {"workspace": True}
        for value in sources.values()
    ):
        raise ValueError("candidate URL, VCS, or path sources are not permitted")
    workspace = uv.get("workspace", {})
    if not isinstance(workspace, dict):
        raise ValueError("candidate workspace configuration must be a table")
    members = workspace.get("members", [])
    if not isinstance(members, list) or any(
        not isinstance(member, str)
        or Path(member).is_absolute()
        or ".." in Path(member).parts
        for member in members
    ):
        raise ValueError("candidate workspace members must stay within the repository")
    dependency_values: list[object] = []
    project_table = project.get("project", {})
    if not isinstance(project_table, dict) or "dynamic" in project_table:
        raise ValueError("dynamic project metadata is not permitted")
    dependency_values.extend(project_table.get("dependencies", []))
    optional = project_table.get("optional-dependencies", {})
    groups = project.get("dependency-groups", {})
    for collection in (optional, groups):
        if not isinstance(collection, dict):
            raise ValueError("dependency groups must be tables")
        for values in collection.values():
            if not isinstance(values, list):
                raise ValueError("dependency groups must be arrays")
            dependency_values.extend(values)
    for dependency in dependency_values:
        if not isinstance(dependency, str) or re.search(
            r"(?:\s@\s|https?://|git\+|file:|ssh:)",
            dependency,
            re.IGNORECASE,
        ):
            raise ValueError("direct URL, VCS, and path dependencies are not permitted")


def _run_uv_audit(
    command: list[str],
    cwd: Path,
) -> subprocess.CompletedProcess[str]:
    if os.name != "posix":
        raise OSError("The secure uv audit adapter requires POSIX process-group isolation")
    with tempfile.TemporaryDirectory(prefix="fork-ops-uv-audit-") as temp_dir:
        root = Path(temp_dir)
        home = root / "home"
        cache = root / "cache"
        scratch = root / "tmp"
        for directory in (home, cache, scratch):
            directory.mkdir(mode=0o700)
        environment = {
            "HOME": str(home),
            "LANG": "C",
            "LC_ALL": "C",
            "PATH": os.defpath,
            "TMPDIR": str(scratch),
            "UV_CACHE_DIR": str(cache),
            "UV_DEFAULT_INDEX": "https://pypi.org/simple",
            "UV_INDEX_STRATEGY": "first-index",
            "UV_KEYRING_PROVIDER": "disabled",
            "UV_NO_BUILD": "1",
            "UV_NO_CONFIG": "1",
            "UV_NO_PROGRESS": "1",
            "UV_NO_SOURCES": "1",
            "UV_PYTHON_DOWNLOADS": "never",
        }
        stdout, stderr, returncode = _run_bounded_uv_process(
            command,
            cwd=cwd,
            environment=environment,
        )
    return subprocess.CompletedProcess(
        command,
        returncode,
        stdout.decode("utf-8"),
        stderr.decode("utf-8"),
    )


def _terminate_uv_process_group(process: subprocess.Popen[bytes]) -> None:
    with contextlib.suppress(OSError):
        os.killpg(process.pid, 15)
    with contextlib.suppress(subprocess.TimeoutExpired):
        process.wait(timeout=0.5)
    if process.poll() is None:
        with contextlib.suppress(OSError):
            os.killpg(process.pid, 9)
        with contextlib.suppress(subprocess.TimeoutExpired):
            process.wait(timeout=0.5)


def _run_bounded_uv_process(
    command: list[str],
    *,
    cwd: Path,
    environment: dict[str, str],
) -> tuple[bytes, bytes, int]:
    process = subprocess.Popen(
        command,
        cwd=cwd,
        env=environment,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        start_new_session=True,
    )
    if process.stdout is None or process.stderr is None:
        _terminate_uv_process_group(process)
        raise OSError("uv audit output pipes were unavailable")
    streams = (process.stdout, process.stderr)
    buffers = (bytearray(), bytearray())
    counts = [0, 0]
    total = 0
    lock = threading.Lock()
    overflow = threading.Event()

    def drain(index: int) -> None:
        nonlocal total
        with streams[index]:
            while chunk := streams[index].read(64 * 1024):
                with lock:
                    counts[index] += len(chunk)
                    remaining = UV_AUDIT_MAX_OUTPUT_BYTES - total
                    total += len(chunk)
                    if remaining > 0:
                        buffers[index].extend(chunk[:remaining])
                    if total > UV_AUDIT_MAX_OUTPUT_BYTES:
                        overflow.set()

    readers = [threading.Thread(target=drain, args=(index,), daemon=True) for index in range(2)]
    for reader in readers:
        reader.start()
    deadline = time.monotonic() + UV_AUDIT_TIMEOUT_SECONDS
    timed_out = False
    while process.poll() is None:
        if overflow.is_set():
            _terminate_uv_process_group(process)
            break
        if time.monotonic() >= deadline:
            timed_out = True
            _terminate_uv_process_group(process)
            break
        time.sleep(0.01)
    returncode = process.poll()
    for reader in readers:
        reader.join(timeout=1)
    if any(reader.is_alive() for reader in readers):
        _terminate_uv_process_group(process)
        raise subprocess.SubprocessError("uv audit descendant retained an output pipe")
    if timed_out:
        raise subprocess.TimeoutExpired(command, UV_AUDIT_TIMEOUT_SECONDS)
    if overflow.is_set():
        raise subprocess.SubprocessError("uv audit exceeded the combined output limit")
    if returncode is None:
        raise subprocess.SubprocessError("uv audit did not reach a terminal state")
    return bytes(buffers[0]), bytes(buffers[1]), returncode


def _normalize_uv_audit_output(
    raw: object,
    python_version: str,
    package_scopes: dict[str, tuple[str, ...]],
    package_versions: dict[str, str],
) -> dict[str, object]:
    if not isinstance(raw, dict):
        return _uv_evidence_failure("uv audit JSON root must be an object.")
    vulnerabilities = raw.get("vulnerabilities")
    adverse_statuses = raw.get("adverse_statuses")
    if not isinstance(vulnerabilities, list) or not isinstance(adverse_statuses, list):
        return _uv_evidence_failure("uv audit JSON omitted required result collections.")
    if adverse_statuses:
        return _uv_evidence_failure("uv audit reported adverse package statuses.")
    advisories: list[dict[str, object]] = []
    for index, vulnerability in enumerate(vulnerabilities):
        normalized = _normalize_uv_vulnerability(
            vulnerability,
            python_version,
            package_scopes,
            package_versions,
        )
        if normalized is None:
            return _uv_evidence_failure(
                f"uv audit vulnerability at index {index} has an unsupported shape."
            )
        advisories.append(normalized)
    advisories.sort(key=_raw_advisory_sort_key)
    return _uv_evidence("available", advisories, [], provenance=None)


def _normalize_uv_vulnerability(
    raw: object,
    python_version: str,
    package_scopes: dict[str, tuple[str, ...]],
    package_versions: dict[str, str],
) -> dict[str, object] | None:
    if not isinstance(raw, dict):
        return None
    dependency = raw.get("dependency")
    if not isinstance(dependency, dict):
        return None
    package = dependency.get("name")
    locked_version = dependency.get("version")
    advisory_id = raw.get("id")
    aliases = _strict_string_list(raw.get("aliases"), allow_empty=True)
    fix_versions = _strict_string_list(raw.get("fix_versions"), allow_empty=True)
    normalized_package = (
        re.sub(r"[-_.]+", "-", package).lower()
        if isinstance(package, str)
        else ""
    )
    scopes = package_scopes.get(normalized_package)
    expected_version = package_versions.get(normalized_package)
    if not (
        isinstance(package, str)
        and package
        and isinstance(locked_version, str)
        and locked_version
        and locked_version == expected_version
        and isinstance(advisory_id, str)
        and advisory_id
        and aliases is not None
        and fix_versions is not None
        and scopes is not None
    ):
        return None
    return {
        "advisory_id": advisory_id,
        "aliases": sorted(set(aliases).difference({advisory_id})),
        "package": normalized_package,
        "locked_version": locked_version,
        "affected": True,
        "affected_range": "",
        "fixed_versions": sorted(set(fix_versions)),
        "dependency_scopes": list(scopes),
        "python_versions": [python_version],
    }


def _merge_matrix_advisories(
    advisories: list[dict[str, object]],
) -> list[dict[str, object]]:
    merged: dict[str, dict[str, object]] = {}
    for advisory in advisories:
        identity_payload = {
            key: advisory[key]
            for key in (
                "advisory_id",
                "aliases",
                "package",
                "locked_version",
                "affected",
                "affected_range",
                "fixed_versions",
                "dependency_scopes",
            )
        }
        identity = json.dumps(identity_payload, sort_keys=True, separators=(",", ":"))
        existing = merged.setdefault(identity, {**advisory, "python_versions": []})
        versions = existing["python_versions"]
        if isinstance(versions, list):
            advisory_versions = _strict_string_list(
                advisory.get("python_versions"),
                allow_empty=False,
            )
            if advisory_versions is None:
                continue
            versions.extend(advisory_versions)
            existing["python_versions"] = _ordered_subset(
                sorted(set(versions)),
                SUPPORTED_PYTHON_VERSIONS,
            )
    result = list(merged.values())
    result.sort(key=_raw_advisory_sort_key)
    return result


def _raw_advisory_sort_key(advisory: dict[str, object]) -> tuple[str, str, str]:
    return (
        str(advisory["package"]),
        str(advisory["locked_version"]),
        str(advisory["advisory_id"]),
    )


def _uv_evidence_failure(message: str) -> dict[str, object]:
    return _uv_evidence(
        "unavailable",
        [],
        [_diagnostic("evidence.unavailable", "osv", message)],
        provenance=None,
    )


def _uv_evidence(
    status: str,
    advisories: list[dict[str, object]],
    diagnostics: list[dict[str, str]],
    *,
    provenance: dict[str, object] | None,
) -> dict[str, object]:
    payload: dict[str, object] = {
        "artifact_kind": "normalized_dependency_vulnerability_evidence",
        "schema_version": DEPENDENCY_EVIDENCE_SCHEMA_VERSION,
        "source": "osv",
        "status": status,
        "platforms": list(SUPPORTED_PLATFORMS),
        "dependency_scopes": list(DEPENDENCY_SCOPES),
        "python_versions": list(SUPPORTED_PYTHON_VERSIONS),
        "advisories": advisories,
        "diagnostics": diagnostics,
    }
    if provenance is None:
        return payload
    payload["provenance"] = provenance
    payload["payload_sha256"] = _payload_digest(payload)
    return payload


def evaluate_dependency_security(
    osv_evidence: VerifiedDependencyEvidence | Mapping[str, object],
    dependabot_evidence: VerifiedDependencyEvidence | Mapping[str, object],
    security_exception_inventory: SecurityExceptionInventory,
    *,
    evaluation_context: TrustedDependencyEvaluation | None = None,
    evaluated_at: str | None = None,
) -> dict[str, object]:
    """Evaluate two trusted source observations into an observational result."""
    evidence_payloads: dict[str, dict[str, object]] = {}
    diagnostics: list[dict[str, str]] = []
    for source, evidence in (("osv", osv_evidence), ("dependabot", dependabot_evidence)):
        if not isinstance(evidence, VerifiedDependencyEvidence):
            diagnostics.append(
                _diagnostic(
                    "evidence.unverified",
                    source,
                    f"{source} evidence is serialized or otherwise unverified.",
                )
            )
            continue
        payload = evidence._trusted_payload()
        if payload is None:
            diagnostics.append(
                _diagnostic(
                    "evidence.integrity_failure",
                    source,
                    f"{source} evidence lost its immutable adapter binding.",
                )
            )
            continue
        evidence_payloads[source] = payload

    context = (
        evaluation_context._trusted_context()
        if isinstance(evaluation_context, TrustedDependencyEvaluation)
        else None
    )
    if context is None:
        diagnostics.append(
            _diagnostic(
                "evaluation.untrusted_time",
                "evaluation",
                (
                    "A caller-provided evaluated_at value is not a trusted evaluation "
                    "interval."
                ),
            )
        )
    else:
        diagnostics.extend(_evaluation_context_diagnostics(context))

    inventory_is_valid = is_structural_security_exception_inventory(
        security_exception_inventory
    )
    dependency_records: tuple[SecurityExceptionRecord, ...] = ()
    if not inventory_is_valid:
        diagnostics.append(
            _diagnostic(
                "exceptions.invalid_inventory",
                "security-exception-inventory",
                "Security Exception 1.0 inventory must be a structural typed projection.",
            )
        )
    else:
        dependency_records = security_exception_inventory.dependency_records
    if len(evidence_payloads) == 2:
        diagnostics.extend(
            _input_diagnostics(
                evidence_payloads["osv"],
                evidence_payloads["dependabot"],
            )
        )
        if context is not None and not _evaluation_context_diagnostics(context):
            diagnostics.extend(
                _provenance_diagnostics("osv", evidence_payloads["osv"], context)
            )
            diagnostics.extend(
                _provenance_diagnostics(
                    "dependabot",
                    evidence_payloads["dependabot"],
                    context,
                )
            )
            diagnostics.extend(
                _cross_source_provenance_diagnostics(
                    evidence_payloads["osv"],
                    evidence_payloads["dependabot"],
                )
            )
    advisories: list[_Advisory] = []
    if not diagnostics:
        for source in ("osv", "dependabot"):
            evidence = evidence_payloads[source]
            parsed, parse_diagnostics = _parse_advisories(source, evidence)
            advisories.extend(parsed)
            diagnostics.extend(parse_diagnostics)
    advisory_groups: list[dict[str, object]] = []
    matched_inventory_record_ids: set[str] = set()
    if not diagnostics:
        (
            advisory_groups,
            reconciliation_diagnostics,
            matched_inventory_record_ids,
        ) = _reconcile_advisories(
            advisories,
            dependency_records,
        )
        diagnostics.extend(reconciliation_diagnostics)
    affected_count = sum(group.get("affected") is True for group in advisory_groups)
    unexcepted_count = sum(group.get("disposition") == "unexcepted" for group in advisory_groups)
    disagreement_count = sum(
        group.get("disposition") == "disagreement" for group in advisory_groups
    )
    summary: dict[str, object] = {
        "advisory_group_count": len(advisory_groups),
        "affected_group_count": affected_count,
        "excepted_group_count": 0,
        "unexcepted_group_count": unexcepted_count,
        "disagreement_count": disagreement_count,
    }
    trusted_evaluated_at = _context_evaluated_at(context)
    return {
        "artifact_kind": "dependency_security_result",
        "schema_version": "1.0",
        "status": "failed" if diagnostics or affected_count else "passed",
        "evaluated_at": trusted_evaluated_at or evaluated_at or "",
        "evidence_trust": (
            "verified_observations" if not diagnostics else "observational_unverified"
        ),
        "assurance_boundary": {
            "security_authority": False,
            "finding_waiver_authority": False,
            "gate_or_release_authority": False,
        },
        "platforms": list(SUPPORTED_PLATFORMS),
        "dependency_scopes": list(DEPENDENCY_SCOPES),
        "python_versions": list(SUPPORTED_PYTHON_VERSIONS),
        "security_exception_inventory": {
            "contract_version": (
                security_exception_inventory.contract_version
                if inventory_is_valid
                else ""
            ),
            "finding_effect": "inventory_only",
            "unmatched_dependency_record_ids": sorted(
                record.exception_id
                for record in dependency_records
                if record.exception_id not in matched_inventory_record_ids
            ),
        },
        "summary": summary,
        "advisory_groups": advisory_groups,
        "diagnostics": diagnostics,
    }


def _input_diagnostics(
    osv_evidence: dict[str, object],
    dependabot_evidence: dict[str, object],
) -> list[dict[str, str]]:
    diagnostics: list[dict[str, str]] = []
    for expected_source, evidence in (
        ("osv", osv_evidence),
        ("dependabot", dependabot_evidence),
    ):
        evidence_keys = set(evidence)
        required_evidence_keys = {
            "artifact_kind",
            "schema_version",
            "source",
            "status",
            "platforms",
            "dependency_scopes",
            "python_versions",
            "advisories",
            "diagnostics",
            "provenance",
            "payload_sha256",
        }
        if not required_evidence_keys.issubset(evidence_keys):
            diagnostics.append(
                _diagnostic(
                    "evidence.invalid",
                    expected_source,
                    f"{expected_source} evidence is missing required root fields.",
                )
            )
        if not evidence_keys.issubset(required_evidence_keys):
            diagnostics.append(
                _diagnostic(
                    "evidence.invalid",
                    expected_source,
                    f"{expected_source} evidence contains unknown root fields.",
                )
            )
        if evidence.get("artifact_kind") != "normalized_dependency_vulnerability_evidence":
            diagnostics.append(
                _diagnostic(
                    "evidence.invalid_artifact_kind",
                    expected_source,
                    (
                        f"{expected_source} evidence artifact_kind must be "
                        "normalized_dependency_vulnerability_evidence."
                    ),
                )
            )
        if evidence.get("schema_version") != DEPENDENCY_EVIDENCE_SCHEMA_VERSION:
            diagnostics.append(
                _diagnostic(
                    "evidence.unsupported_version",
                    expected_source,
                    (
                        f"{expected_source} evidence schema_version must be "
                        f"{DEPENDENCY_EVIDENCE_SCHEMA_VERSION}."
                    ),
                )
            )
        if evidence.get("source") != expected_source:
            diagnostics.append(
                _diagnostic(
                    "evidence.source_mismatch",
                    expected_source,
                    f"{expected_source} evidence source must be {expected_source}.",
                )
            )
        if evidence.get("status") != "available":
            diagnostics.append(
                _diagnostic(
                    "evidence.unavailable",
                    expected_source,
                    f"{expected_source} evidence is unavailable.",
                )
            )
        evidence_diagnostics = evidence.get("diagnostics")
        if not _valid_evidence_diagnostics(evidence_diagnostics):
            diagnostics.append(
                _diagnostic(
                    "evidence.invalid",
                    expected_source,
                    (
                        f"{expected_source} evidence diagnostics must be an exact "
                        "list of diagnostic tables."
                    ),
                )
            )
        elif evidence.get("status") == "available" and evidence_diagnostics:
            diagnostics.append(
                _diagnostic(
                    "evidence.invalid",
                    expected_source,
                    f"{expected_source} available evidence diagnostics must be empty.",
                )
            )
        if not _exact_string_set(evidence.get("platforms"), SUPPORTED_PLATFORMS):
            diagnostics.append(
                _diagnostic(
                    "evidence.unsupported_platform",
                    expected_source,
                    f"{expected_source} evidence must cover Linux.",
                )
            )
        if not _exact_string_set(evidence.get("dependency_scopes"), DEPENDENCY_SCOPES):
            diagnostics.append(
                _diagnostic(
                    "evidence.incomplete_scope",
                    expected_source,
                    f"{expected_source} evidence must cover every supported dependency scope.",
                )
            )
        if not _exact_string_set(evidence.get("python_versions"), SUPPORTED_PYTHON_VERSIONS):
            diagnostics.append(
                _diagnostic(
                    "evidence.incomplete_python_matrix",
                    expected_source,
                    f"{expected_source} evidence must cover Python 3.11 through 3.14.",
                )
            )
        if not isinstance(evidence.get("payload_sha256"), str) or not _valid_payload_digest(
            evidence
        ):
            diagnostics.append(
                _diagnostic(
                    "evidence.payload_digest_mismatch",
                    expected_source,
                    f"{expected_source} canonical payload digest does not match its content.",
                )
            )
    return diagnostics


def _evaluation_context_diagnostics(
    context: dict[str, object],
) -> list[dict[str, str]]:
    if set(context) != {
        "schema_version",
        "observation_epoch",
        "candidate",
        "matrix",
        "producer",
        "interval",
    }:
        return [
            _diagnostic(
                "evaluation.invalid_context",
                "evaluation",
                "Trusted dependency evaluation context has an unsupported shape.",
            )
        ]
    matrix = _matrix_identity(context.get("matrix"))
    candidate = _candidate_identity(context.get("candidate"), matrix)
    producer = _producer_identity(context.get("producer"))
    epoch = context.get("observation_epoch")
    interval = context.get("interval")
    if (
        context.get("schema_version") != "1.0"
        or matrix is None
        or candidate is None
        or producer is None
        or not isinstance(epoch, str)
        or _SHA256_RE.fullmatch(epoch) is None
        or not isinstance(interval, dict)
        or set(interval) != {"started_at", "evaluated_at"}
    ):
        return [
            _diagnostic(
                "evaluation.invalid_context",
                "evaluation",
                "Trusted dependency evaluation context is invalid or incomplete.",
            )
        ]
    started = _parse_utc(interval.get("started_at"))
    completed = _parse_utc(interval.get("evaluated_at"))
    if (
        started is None
        or completed is None
        or completed < started
        or completed - started > MAX_OBSERVATION_VALIDITY
    ):
        return [
            _diagnostic(
                "evaluation.invalid_interval",
                "evaluation",
                "Trusted dependency evaluation interval is invalid or too broad.",
            )
        ]
    return []


def _provenance_diagnostics(
    source: str,
    evidence: dict[str, object],
    context: dict[str, object],
) -> list[dict[str, str]]:
    provenance = evidence.get("provenance")
    if not isinstance(provenance, dict) or set(provenance) != {
        "schema_version",
        "candidate",
        "matrix",
        "producer",
        "source_observation",
    }:
        return [
            _diagnostic(
                "evidence.invalid_provenance",
                source,
                f"{source} provenance envelope has an unsupported shape.",
            )
        ]
    matrix = _matrix_identity(provenance.get("matrix"))
    candidate = _candidate_identity(provenance.get("candidate"), matrix)
    producer = _producer_identity(provenance.get("producer"))
    if (
        provenance.get("schema_version") != DEPENDENCY_PROVENANCE_SCHEMA_VERSION
        or matrix is None
        or candidate is None
        or producer is None
    ):
        return [
            _diagnostic(
                "evidence.invalid_provenance",
                source,
                f"{source} provenance envelope is invalid or incomplete.",
            )
        ]
    if (
        candidate != context.get("candidate")
        or matrix != context.get("matrix")
        or producer != context.get("producer")
    ):
        return [
            _diagnostic(
                "evidence.identity_mismatch",
                source,
                f"{source} evidence does not bind the trusted candidate, matrix, and producer.",
            )
        ]
    observation = provenance.get("source_observation")
    if not isinstance(observation, dict) or set(observation) != {
        "provider",
        "source_identity",
        "authenticated",
        "pagination_complete",
        "page_count",
        "item_count",
        "observation_epoch",
        "started_at",
        "completed_at",
        "valid_until",
    }:
        return [
            _diagnostic(
                "evidence.invalid_provenance",
                source,
                f"{source} source observation has an unsupported shape.",
            )
        ]
    expected_source_identity = {
        "osv": "osv.dev:uv-audit",
        "dependabot": "github:dependabot-alerts",
    }[source]
    advisories = evidence.get("advisories")
    item_count = observation.get("item_count")
    page_count = observation.get("page_count")
    if (
        observation.get("provider") != source
        or observation.get("source_identity") != expected_source_identity
        or observation.get("authenticated") is not True
        or observation.get("pagination_complete") is not True
        or not isinstance(page_count, int)
        or isinstance(page_count, bool)
        or page_count < 1
        or not isinstance(item_count, int)
        or isinstance(item_count, bool)
        or not isinstance(advisories, list)
        or item_count != len(advisories)
    ):
        return [
            _diagnostic(
                "evidence.incomplete_observation",
                source,
                f"{source} evidence is not a positive complete source observation.",
            )
        ]
    if observation.get("observation_epoch") != context.get("observation_epoch"):
        return [
            _diagnostic(
                "evidence.epoch_mismatch",
                source,
                f"{source} evidence belongs to a different observation epoch.",
            )
        ]
    started = _parse_utc(observation.get("started_at"))
    completed = _parse_utc(observation.get("completed_at"))
    valid_until = _parse_utc(observation.get("valid_until"))
    interval = context.get("interval")
    if not isinstance(interval, dict):
        return []
    interval_started = _parse_utc(interval.get("started_at"))
    evaluated = _parse_utc(interval.get("evaluated_at"))
    if (
        started is None
        or completed is None
        or valid_until is None
        or interval_started is None
        or evaluated is None
        or completed < started
        or valid_until < completed
        or valid_until - completed > MAX_OBSERVATION_VALIDITY
    ):
        return [
            _diagnostic(
                "evidence.invalid_observation_time",
                source,
                f"{source} observation times are invalid.",
            )
        ]
    if started < interval_started:
        return [
            _diagnostic(
                "evidence.replayed",
                source,
                f"{source} observation predates the trusted evaluation interval.",
            )
        ]
    if completed > evaluated:
        return [
            _diagnostic(
                "evidence.future_observation",
                source,
                f"{source} observation completes after the trusted evaluation time.",
            )
        ]
    if evaluated >= valid_until:
        return [
            _diagnostic(
                "evidence.stale",
                source,
                f"{source} observation is stale at the trusted evaluation time.",
            )
        ]
    return []


def _cross_source_provenance_diagnostics(
    osv_evidence: dict[str, object],
    dependabot_evidence: dict[str, object],
) -> list[dict[str, str]]:
    osv_provenance = osv_evidence.get("provenance")
    dependabot_provenance = dependabot_evidence.get("provenance")
    if not isinstance(osv_provenance, dict) or not isinstance(dependabot_provenance, dict):
        return []
    for field in ("candidate", "matrix", "producer"):
        if osv_provenance.get(field) != dependabot_provenance.get(field):
            return [
                _diagnostic(
                    "evidence.cross_source_mismatch",
                    "reconciliation",
                    "OSV and Dependabot evidence do not bind one candidate observation.",
                )
            ]
    osv_observation = osv_provenance.get("source_observation")
    dependabot_observation = dependabot_provenance.get("source_observation")
    if (
        isinstance(osv_observation, dict)
        and isinstance(dependabot_observation, dict)
        and osv_observation.get("observation_epoch")
        != dependabot_observation.get("observation_epoch")
    ):
        return [
            _diagnostic(
                "evidence.cross_source_mismatch",
                "reconciliation",
                "OSV and Dependabot evidence do not share one observation epoch.",
            )
        ]
    return []


def _context_evaluated_at(context: dict[str, object] | None) -> str | None:
    if context is None or _evaluation_context_diagnostics(context):
        return None
    interval = context.get("interval")
    if not isinstance(interval, dict):
        return None
    value = interval.get("evaluated_at")
    return value if isinstance(value, str) else None


def _parse_advisories(
    source: str,
    evidence: dict[str, object],
) -> tuple[list[_Advisory], list[dict[str, str]]]:
    raw_advisories = evidence.get("advisories")
    if not isinstance(raw_advisories, list):
        return [], [_diagnostic("evidence.invalid", source, "advisories must be a list.")]
    advisories: list[_Advisory] = []
    diagnostics: list[dict[str, str]] = []
    for index, raw_advisory in enumerate(raw_advisories):
        if not isinstance(raw_advisory, dict):
            diagnostics.append(
                _diagnostic("evidence.invalid", source, f"advisories[{index}] must be a table.")
            )
            continue
        advisory = _parse_advisory(source, raw_advisory)
        if advisory is None:
            diagnostics.append(
                _diagnostic(
                    "evidence.invalid",
                    source,
                    f"advisories[{index}] has invalid or incomplete fields.",
                )
            )
            continue
        advisories.append(advisory)
    return advisories, diagnostics


def _parse_advisory(source: str, raw: dict[object, object]) -> _Advisory | None:
    if set(raw) != {
        "advisory_id",
        "aliases",
        "package",
        "locked_version",
        "affected",
        "affected_range",
        "fixed_versions",
        "dependency_scopes",
        "python_versions",
    }:
        return None
    advisory_id = raw.get("advisory_id")
    aliases = _strict_string_list(raw.get("aliases"), allow_empty=True)
    package = raw.get("package")
    locked_version = raw.get("locked_version")
    affected = raw.get("affected")
    affected_range = raw.get("affected_range")
    fixed_versions = _strict_string_list(raw.get("fixed_versions"), allow_empty=True)
    dependency_scopes = _strict_string_list(raw.get("dependency_scopes"), allow_empty=False)
    python_versions = _strict_string_list(raw.get("python_versions"), allow_empty=False)
    if not (
        isinstance(advisory_id, str)
        and advisory_id
        and advisory_id == advisory_id.strip()
        and aliases is not None
        and len(aliases) == len(set(aliases))
        and isinstance(package, str)
        and package
        and re.sub(r"[-_.]+", "-", package).lower() == package
        and isinstance(locked_version, str)
        and locked_version
        and isinstance(affected, bool)
        and isinstance(affected_range, str)
        and fixed_versions is not None
        and len(fixed_versions) == len(set(fixed_versions))
        and dependency_scopes is not None
        and _valid_known_subset(dependency_scopes, DEPENDENCY_SCOPES)
        and python_versions is not None
        and _valid_known_subset(python_versions, SUPPORTED_PYTHON_VERSIONS)
    ):
        return None
    identifiers = tuple(sorted({advisory_id, *aliases}))
    return _Advisory(
        source=source,
        identifiers=identifiers,
        package=package,
        locked_version=locked_version,
        affected=affected,
        affected_range=affected_range,
        fixed_versions=tuple(sorted(fixed_versions)),
        dependency_scopes=tuple(_ordered_subset(dependency_scopes, DEPENDENCY_SCOPES)),
        python_versions=tuple(_ordered_subset(python_versions, SUPPORTED_PYTHON_VERSIONS)),
    )


def _reconcile_advisories(
    advisories: list[_Advisory],
    dependency_records: tuple[SecurityExceptionRecord, ...],
) -> tuple[list[dict[str, object]], list[dict[str, str]], set[str]]:
    groups: list[list[_Advisory]] = []
    for advisory in sorted(advisories, key=_advisory_sort_key):
        matching_indexes = [
            index
            for index, group in enumerate(groups)
            if advisory.package == group[0].package
            and advisory.locked_version == group[0].locked_version
            and set(advisory.identifiers).intersection(_group_identifiers(group))
        ]
        if not matching_indexes:
            groups.append([advisory])
            continue
        first_index = matching_indexes[0]
        groups[first_index].append(advisory)
        for index in reversed(matching_indexes[1:]):
            groups[first_index].extend(groups.pop(index))

    normalized: list[dict[str, object]] = []
    diagnostics: list[dict[str, str]] = []
    matched_inventory_record_ids: set[str] = set()
    for group in groups:
        group.sort(key=_advisory_sort_key)
        identifiers = sorted(_group_identifiers(group))
        canonical_id = min(identifiers, key=_identifier_sort_key)
        reference = group[0]
        claims_by_source = _source_claims(group)
        claims = [
            claim
            for source_claims in claims_by_source.values()
            for claim in source_claims
        ]
        coverage = {
            item
            for claim in claims
            for item in claim.coverage
        }
        affected = any(claim.affected for claim in claims)
        affected_ranges = sorted({claim.affected_range for claim in claims})
        fixed_versions = sorted(
            {
                fixed_version
                for claim in claims
                for fixed_version in claim.fixed_versions
            }
        )
        dependency_scopes = _ordered_subset(
            sorted({item.dependency_scope for item in coverage}),
            DEPENDENCY_SCOPES,
        )
        python_versions = _ordered_subset(
            sorted({item.python_version for item in coverage}),
            SUPPORTED_PYTHON_VERSIONS,
        )
        sources = sorted(claims_by_source)
        disagreement = _has_material_disagreement(claims_by_source)
        if disagreement:
            disposition = "disagreement"
        else:
            disposition = "unexcepted" if affected else "fixed"
        matching_records: list[SecurityExceptionRecord] = []
        if disposition == "unexcepted":
            matching_records = _matching_inventory_records(
                identifiers=tuple(identifiers),
                package=reference.package,
                locked_version=reference.locked_version,
                dependency_scopes=tuple(dependency_scopes),
                python_versions=tuple(python_versions),
                records=dependency_records,
            )
        inventory_record_ids = sorted(record.exception_id for record in matching_records)
        matched_inventory_record_ids.update(inventory_record_ids)
        if disposition == "unexcepted" and len(matching_records) > 1:
            diagnostics.append(
                _diagnostic(
                    "exceptions.duplicate_inventory_match",
                    "security-exception-inventory",
                    (
                        "Multiple Security Exception 1.0 inventory records match advisory "
                        f"group {canonical_id}; inventory records do not waive dependency "
                        "findings."
                    ),
                )
            )
        normalized.append(
            {
                "canonical_id": canonical_id,
                "aliases": identifiers,
                "package": reference.package,
                "locked_version": reference.locked_version,
                "affected": affected,
                "affected_range": affected_ranges[0] if len(affected_ranges) == 1 else "",
                "fixed_versions": fixed_versions,
                "dependency_scopes": dependency_scopes,
                "python_versions": python_versions,
                "coverage": _coverage_output(coverage),
                "sources": sources,
                "source_claims": _source_claim_output(group, claims_by_source),
                "disposition": disposition,
                "inventory_record_ids": inventory_record_ids,
            }
        )
        if disposition == "disagreement":
            diagnostics.append(
                _diagnostic(
                    "evidence.material_disagreement",
                    "reconciliation",
                    (
                        f"OSV and Dependabot disagree on whether {canonical_id} affects or fixes "
                        f"{reference.package} {reference.locked_version}. Security Exception "
                        "1.0 inventory records do not waive dependency findings."
                    ),
                )
            )
        elif disposition == "unexcepted":
            diagnostics.append(
                _diagnostic(
                    "finding.unexcepted",
                    "reconciliation",
                    (
                        f"{canonical_id} affects {reference.package} "
                        f"{reference.locked_version}. Security Exception 1.0 inventory "
                        "records do not waive dependency findings."
                    ),
                )
            )
    normalized.sort(key=_normalized_group_sort_key)
    diagnostics.sort(key=_diagnostic_sort_key)
    return normalized, diagnostics, matched_inventory_record_ids


def _matching_inventory_records(
    *,
    identifiers: tuple[str, ...],
    package: str,
    locked_version: str,
    dependency_scopes: tuple[str, ...],
    python_versions: tuple[str, ...],
    records: tuple[SecurityExceptionRecord, ...],
) -> list[SecurityExceptionRecord]:
    return [
        record
        for record in records
        if record.subject_kind == "dependency_advisory"
        and record.aliases == identifiers
        and record.package == package
        and record.locked_version == locked_version
        and record.dependency_scopes == dependency_scopes
        and record.python_versions == python_versions
        and record.platforms == SUPPORTED_PLATFORMS
    ]


def _group_identifiers(group: list[_Advisory]) -> set[str]:
    return {identifier for advisory in group for identifier in advisory.identifiers}


def _source_claims(group: list[_Advisory]) -> dict[str, tuple[_SourceClaim, ...]]:
    pending: dict[
        str,
        dict[tuple[bool, str, tuple[str, ...]], set[_ClaimCoverage]],
    ] = {}
    for advisory in group:
        claim_key = (
            advisory.affected,
            advisory.affected_range,
            advisory.fixed_versions,
        )
        coverage = {
            _ClaimCoverage(dependency_scope, python_version)
            for dependency_scope in advisory.dependency_scopes
            for python_version in advisory.python_versions
        }
        pending.setdefault(advisory.source, {}).setdefault(claim_key, set()).update(
            coverage
        )
    normalized: dict[str, tuple[_SourceClaim, ...]] = {}
    for source, source_claims in pending.items():
        normalized[source] = tuple(
            _SourceClaim(
                affected=claim_key[0],
                affected_range=claim_key[1],
                fixed_versions=claim_key[2],
                coverage=tuple(
                    sorted(source_claims[claim_key], key=_claim_coverage_sort_key)
                ),
            )
            for claim_key in sorted(source_claims, key=_source_claim_key_sort_key)
        )
    return normalized


def _source_claim_output(
    group: list[_Advisory],
    claims_by_source: dict[str, tuple[_SourceClaim, ...]],
) -> list[dict[str, object]]:
    identifiers_by_source: dict[str, set[str]] = {}
    for advisory in group:
        identifiers_by_source.setdefault(advisory.source, set()).update(
            advisory.identifiers
        )
    return [
        {
            "source": source,
            "identifiers": sorted(identifiers_by_source[source]),
            "claims": [
                {
                    "affected": claim.affected,
                    "affected_range": claim.affected_range,
                    "fixed_versions": list(claim.fixed_versions),
                    "coverage": _coverage_output(set(claim.coverage)),
                }
                for claim in claims_by_source[source]
            ],
        }
        for source in sorted(claims_by_source)
    ]


def _coverage_output(
    coverage: set[_ClaimCoverage],
) -> list[dict[str, object]]:
    result: list[dict[str, object]] = []
    for python_version in SUPPORTED_PYTHON_VERSIONS:
        scopes = [
            dependency_scope
            for dependency_scope in DEPENDENCY_SCOPES
            if _ClaimCoverage(dependency_scope, python_version) in coverage
        ]
        if scopes:
            result.append(
                {
                    "python_version": python_version,
                    "dependency_scopes": scopes,
                }
            )
    return result


def _has_material_disagreement(
    claims_by_source: dict[str, tuple[_SourceClaim, ...]],
) -> bool:
    return (
        set(claims_by_source) != {"osv", "dependabot"}
        or claims_by_source["osv"] != claims_by_source["dependabot"]
    )


def _source_claim_key_sort_key(
    claim_key: tuple[bool, str, tuple[str, ...]],
) -> tuple[bool, str, tuple[str, ...]]:
    return claim_key


def _claim_coverage_sort_key(coverage: _ClaimCoverage) -> tuple[int, int]:
    return (
        DEPENDENCY_SCOPES.index(coverage.dependency_scope),
        SUPPORTED_PYTHON_VERSIONS.index(coverage.python_version),
    )


def _advisory_sort_key(advisory: _Advisory) -> tuple[str, str, str, tuple[str, ...]]:
    return advisory.package, advisory.locked_version, advisory.source, advisory.identifiers


def _identifier_sort_key(identifier: str) -> tuple[int, str]:
    for priority, prefix in enumerate(("GHSA-", "CVE-", "PYSEC-")):
        if identifier.startswith(prefix):
            return priority, identifier
    return 3, identifier


def _normalized_group_sort_key(group: dict[str, object]) -> tuple[str, str, str]:
    return str(group["package"]), str(group["locked_version"]), str(group["canonical_id"])


def _diagnostic_sort_key(diagnostic: dict[str, str]) -> tuple[str, str, str]:
    return diagnostic["code"], diagnostic["source"], diagnostic["message"]


def _diagnostic(code: str, source: str, message: str) -> dict[str, str]:
    return {"code": code, "source": source, "message": message}


def _valid_evidence_diagnostics(value: object) -> bool:
    if not isinstance(value, list):
        return False
    for diagnostic in value:
        if not isinstance(diagnostic, dict) or set(diagnostic) != {
            "code",
            "source",
            "message",
        }:
            return False
        if any(
            not isinstance(diagnostic.get(key), str) or not diagnostic.get(key)
            for key in ("code", "source", "message")
        ):
            return False
    return True


def _strict_string_list(value: object, *, allow_empty: bool) -> list[str] | None:
    if not isinstance(value, list):
        return None
    if any(not isinstance(item, str) or not item for item in value):
        return None
    if not value and not allow_empty:
        return None
    return value


def _package_scope_inventory(
    value: object,
) -> dict[str, tuple[str, ...]] | None:
    if not isinstance(value, dict) or not value:
        return None
    normalized: dict[str, tuple[str, ...]] = {}
    covered_scopes: set[str] = set()
    for package, raw_scopes in value.items():
        scopes = _strict_string_list(raw_scopes, allow_empty=False)
        if not (
            isinstance(package, str)
            and package
            and re.sub(r"[-_.]+", "-", package).lower() == package
            and scopes is not None
            and _valid_known_subset(scopes, DEPENDENCY_SCOPES)
        ):
            return None
        ordered_scopes = tuple(_ordered_subset(scopes, DEPENDENCY_SCOPES))
        normalized[package] = ordered_scopes
        covered_scopes.update(ordered_scopes)
    if covered_scopes != set(DEPENDENCY_SCOPES):
        return None
    return normalized


def _package_scope_inventories(
    value: object,
) -> dict[str, dict[str, tuple[str, ...]]] | None:
    if not isinstance(value, dict) or set(value) != set(SUPPORTED_PYTHON_VERSIONS):
        return None
    normalized: dict[str, dict[str, tuple[str, ...]]] = {}
    for python_version in SUPPORTED_PYTHON_VERSIONS:
        inventory = _package_scope_inventory(value.get(python_version))
        if inventory is None:
            return None
        normalized[python_version] = inventory
    return normalized


def _package_version_inventories(
    value: object,
) -> dict[str, dict[str, str]] | None:
    if not isinstance(value, dict) or set(value) != set(SUPPORTED_PYTHON_VERSIONS):
        return None
    normalized: dict[str, dict[str, str]] = {}
    for python_version in SUPPORTED_PYTHON_VERSIONS:
        raw_inventory = value.get(python_version)
        if not isinstance(raw_inventory, dict) or not raw_inventory:
            return None
        inventory: dict[str, str] = {}
        for package, locked_version in raw_inventory.items():
            if not (
                isinstance(package, str)
                and package
                and re.sub(r"[-_.]+", "-", package).lower() == package
                and isinstance(locked_version, str)
                and locked_version
                and locked_version == locked_version.strip()
            ):
                return None
            inventory[package] = locked_version
        normalized[python_version] = inventory
    return normalized


def _package_tuple_matrix(
    scopes_by_python: dict[str, dict[str, tuple[str, ...]]],
    versions_by_python: dict[str, dict[str, str]],
) -> list[dict[str, object]] | None:
    package_tuples: list[dict[str, object]] = []
    for python_version in SUPPORTED_PYTHON_VERSIONS:
        scopes = scopes_by_python[python_version]
        versions = versions_by_python[python_version]
        if set(scopes) != set(versions):
            return None
        for package in sorted(scopes):
            package_tuples.append(
                {
                    "python_version": python_version,
                    "package": package,
                    "locked_version": versions[package],
                    "dependency_scopes": list(scopes[package]),
                }
            )
    return package_tuples


def _matrix_identity(value: object) -> dict[str, object] | None:
    if not isinstance(value, Mapping) or set(value) != {
        "platform",
        "python_versions",
        "package_tuples",
    }:
        return None
    python_versions = _strict_string_list(value.get("python_versions"), allow_empty=False)
    raw_tuples = value.get("package_tuples")
    if (
        value.get("platform") != "linux"
        or python_versions != list(SUPPORTED_PYTHON_VERSIONS)
        or not isinstance(raw_tuples, list)
        or not raw_tuples
    ):
        return None
    package_tuples: list[dict[str, object]] = []
    covered_scopes: dict[str, set[str]] = {
        python_version: set() for python_version in SUPPORTED_PYTHON_VERSIONS
    }
    identities: set[tuple[str, str, str]] = set()
    for raw_tuple in raw_tuples:
        if not isinstance(raw_tuple, Mapping) or set(raw_tuple) != {
            "python_version",
            "package",
            "locked_version",
            "dependency_scopes",
        }:
            return None
        python_version = raw_tuple.get("python_version")
        package = raw_tuple.get("package")
        locked_version = raw_tuple.get("locked_version")
        scopes = _strict_string_list(raw_tuple.get("dependency_scopes"), allow_empty=False)
        if not (
            isinstance(python_version, str)
            and python_version in SUPPORTED_PYTHON_VERSIONS
            and isinstance(package, str)
            and package
            and re.sub(r"[-_.]+", "-", package).lower() == package
            and isinstance(locked_version, str)
            and locked_version
            and locked_version == locked_version.strip()
            and scopes is not None
            and scopes == _ordered_subset(scopes, DEPENDENCY_SCOPES)
            and _valid_known_subset(scopes, DEPENDENCY_SCOPES)
        ):
            return None
        identity = (python_version, package, locked_version)
        if identity in identities:
            return None
        identities.add(identity)
        covered_scopes[python_version].update(scopes)
        package_tuples.append(
            {
                "python_version": python_version,
                "package": package,
                "locked_version": locked_version,
                "dependency_scopes": scopes,
            }
        )
    expected_order = sorted(
        package_tuples,
        key=_package_tuple_sort_key,
    )
    if package_tuples != expected_order or any(
        scopes != set(DEPENDENCY_SCOPES) for scopes in covered_scopes.values()
    ):
        return None
    return {
        "platform": "linux",
        "python_versions": list(SUPPORTED_PYTHON_VERSIONS),
        "package_tuples": package_tuples,
    }


def _package_tuple_sort_key(item: dict[str, object]) -> tuple[int, str, str]:
    return (
        SUPPORTED_PYTHON_VERSIONS.index(str(item["python_version"])),
        str(item["package"]),
        str(item["locked_version"]),
    )


def _candidate_identity(
    value: object,
    matrix: dict[str, object] | None,
) -> dict[str, object] | None:
    if not isinstance(value, Mapping) or set(value) != {
        "commit_sha",
        "source_snapshot_sha256",
        "uv_lock_sha256",
        "package_scope_inventory_sha256",
    }:
        return None
    commit_sha = value.get("commit_sha")
    source_snapshot_sha256 = value.get("source_snapshot_sha256")
    uv_lock_sha256 = value.get("uv_lock_sha256")
    package_scope_inventory_sha256 = value.get("package_scope_inventory_sha256")
    if not (
        isinstance(commit_sha, str)
        and _GIT_OBJECT_RE.fullmatch(commit_sha) is not None
        and isinstance(source_snapshot_sha256, str)
        and _SHA256_RE.fullmatch(source_snapshot_sha256) is not None
        and isinstance(uv_lock_sha256, str)
        and _SHA256_RE.fullmatch(uv_lock_sha256) is not None
        and isinstance(package_scope_inventory_sha256, str)
        and _SHA256_RE.fullmatch(package_scope_inventory_sha256) is not None
        and matrix is not None
        and package_scope_inventory_sha256 == _matrix_inventory_digest(matrix)
    ):
        return None
    return {
        "commit_sha": commit_sha,
        "source_snapshot_sha256": source_snapshot_sha256,
        "uv_lock_sha256": uv_lock_sha256,
        "package_scope_inventory_sha256": package_scope_inventory_sha256,
    }


def _producer_identity(value: object) -> dict[str, object] | None:
    if not isinstance(value, Mapping) or set(value) != {
        "integration",
        "repository",
        "workflow_ref",
        "workflow_sha",
        "run_id",
        "run_attempt",
        "conclusion",
    }:
        return None
    integration = value.get("integration")
    repository = value.get("repository")
    workflow_ref = value.get("workflow_ref")
    workflow_sha = value.get("workflow_sha")
    run_id = value.get("run_id")
    run_attempt = value.get("run_attempt")
    if not (
        isinstance(integration, str)
        and integration == "github-actions"
        and isinstance(repository, str)
        and re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repository) is not None
        and isinstance(workflow_ref, str)
        and workflow_ref
        and workflow_ref == workflow_ref.strip()
        and isinstance(workflow_sha, str)
        and _GIT_OBJECT_RE.fullmatch(workflow_sha) is not None
        and isinstance(run_id, int)
        and not isinstance(run_id, bool)
        and run_id > 0
        and isinstance(run_attempt, int)
        and not isinstance(run_attempt, bool)
        and run_attempt > 0
        and value.get("conclusion") == "success"
    ):
        return None
    return {
        "integration": integration,
        "repository": repository,
        "workflow_ref": workflow_ref,
        "workflow_sha": workflow_sha,
        "run_id": run_id,
        "run_attempt": run_attempt,
        "conclusion": "success",
    }


def _matrix_inventory_digest(matrix: Mapping[str, object]) -> str:
    return hashlib.sha256(
        _canonical_json_bytes({"package_tuples": matrix.get("package_tuples")})
    ).hexdigest()


def _canonical_json_bytes(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def _payload_digest(payload: Mapping[str, object]) -> str:
    return hashlib.sha256(
        _canonical_json_bytes(
            {key: value for key, value in payload.items() if key != "payload_sha256"}
        )
    ).hexdigest()


def _valid_payload_digest(payload: Mapping[str, object]) -> bool:
    claimed = payload.get("payload_sha256")
    return (
        isinstance(claimed, str)
        and _SHA256_RE.fullmatch(claimed) is not None
        and claimed == _payload_digest(payload)
    )


def _parse_utc(value: object) -> datetime | None:
    if not isinstance(value, str) or not value.endswith("Z"):
        return None
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError:
        return None
    if parsed.tzinfo is None or parsed.utcoffset() != timedelta(0):
        return None
    return parsed.astimezone(UTC)


def _format_time(value: datetime) -> str:
    normalized = value.astimezone(UTC)
    timespec = "microseconds" if normalized.microsecond else "seconds"
    return normalized.isoformat(timespec=timespec).replace("+00:00", "Z")


def _ordered_subset(values: list[str], order: tuple[str, ...]) -> list[str]:
    return [value for value in order if value in values]


def _valid_known_subset(values: list[str], allowed: tuple[str, ...]) -> bool:
    return len(values) == len(set(values)) and set(values).issubset(allowed)


def _exact_string_set(value: object, expected: tuple[str, ...]) -> bool:
    values = _strict_string_list(value, allow_empty=False)
    return values is not None and len(values) == len(expected) and set(values) == set(expected)
