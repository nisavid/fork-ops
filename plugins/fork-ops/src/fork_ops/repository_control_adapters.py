"""Read-only adapters and operation-scoped repository-control coordination."""

from __future__ import annotations

import hashlib
import json
import math
import os
import re
import secrets
import selectors
import shutil
import stat
import subprocess
import sys
import time
import tomllib
from collections.abc import Callable, Hashable, Iterable, Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path, PurePosixPath
from queue import Empty, Queue
from threading import Thread
from typing import Final, Protocol

import yaml

from .bounded_io import StableFileReadError, read_stable_regular_file
from .repository_controls import (
    ALERT_CONTROL_IDS,
    CONTROL_SOURCES,
    FAILURE_CLASSES,
    MAX_OBSERVATION_VALIDITY,
    RepositoryControlObservation,
    RepositoryControlObservationError,
    canonical_repository_control_json_bytes,
    parse_repository_control_observation,
    validate_repository_control_projection,
)
from .security_exceptions import (
    SecurityExceptionContractError,
    SecurityExceptionValidationError,
    validate_public_security_exception_ledger,
)

Clock = Callable[[], datetime]
MonotonicClock = Callable[[], float]
EpochFactory = Callable[[], str]
MAX_PACKAGE_FILE_BYTES: Final = 1_048_576
MAX_POLICY_DOCUMENT_BYTES: Final = 8 * MAX_PACKAGE_FILE_BYTES
MAX_WORKFLOW_FILES: Final = 128
MAX_LOCAL_ACTIONS: Final = 128
MAX_LOCAL_ACTION_DEPTH: Final = 16
MAX_LOCAL_DOCKERFILES: Final = 128
MAX_DOCKERFILE_STAGES: Final = 128
MAX_LOCAL_REFERENCE_CHARACTERS: Final = 4_096
_DEPENDABOT_VERSIONING_STRATEGIES: Final = frozenset(
    {"auto", "increase", "increase-if-necessary", "widen"}
)

_REMOTE_ACTION_RE = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+(?:/[^@\s]+)?@[0-9a-f]{40}$")
_DOCKER_ACTION_RE = re.compile(r"^docker://[^@\s]+@sha256:[0-9a-f]{64}$")
_DOCKERFILE_BASE_IMAGE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]*@sha256:[0-9a-f]{64}$")
_SAFE_OPAQUE_ID_RE = re.compile(r"^[A-Za-z0-9._:=+-]{1,128}$")
_REPOSITORY_RE = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
_GIT_SHA_RE = re.compile(r"^[0-9a-f]{40}$")
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


class _Yaml12SafeLoader(yaml.SafeLoader):
    """Safe YAML loader whose booleans match GitHub and Dependabot syntax."""


def _construct_unique_mapping(
    loader: _Yaml12SafeLoader,
    node: yaml.Node,
) -> dict[object, object]:
    if not isinstance(node, yaml.MappingNode):
        raise yaml.constructor.ConstructorError(
            None,
            None,
            "expected a mapping node",
            node.start_mark,
        )
    loader.flatten_mapping(node)
    mapping: dict[object, object] = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=False)
        if not isinstance(key, Hashable):
            raise yaml.constructor.ConstructorError(
                "while constructing a mapping",
                node.start_mark,
                "found an unhashable key",
                key_node.start_mark,
            )
        if key in mapping:
            raise yaml.constructor.ConstructorError(
                "while constructing a mapping",
                node.start_mark,
                f"found duplicate key {key!r}",
                key_node.start_mark,
            )
        mapping[key] = loader.construct_object(value_node, deep=False)
    return mapping


_Yaml12SafeLoader.yaml_implicit_resolvers = {
    key: [(tag, expression) for tag, expression in resolvers if tag != "tag:yaml.org,2002:bool"]
    for key, resolvers in yaml.SafeLoader.yaml_implicit_resolvers.items()
}
_Yaml12SafeLoader.add_implicit_resolver(
    "tag:yaml.org,2002:bool",
    re.compile(r"^(?:true|false)$", re.IGNORECASE),
    list("tTfF"),
)
_Yaml12SafeLoader.add_constructor(
    yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG,
    _construct_unique_mapping,
)


class RepositoryObservationCoordinationError(ValueError):
    """A repository observation request or adapter set is invalid."""


class RepositoryControlReadError(RuntimeError):
    """A read-only provider operation failed with a safe closed class."""

    def __init__(self, failure_class: str) -> None:
        if failure_class not in FAILURE_CLASSES:
            raise ValueError("Unsupported repository-control failure class.")
        super().__init__(failure_class)
        self.failure_class: Final = failure_class


@dataclass(frozen=True)
class RepositoryIdentity:
    full_name: str
    database_id: int
    node_id: str
    default_branch: str

    def __post_init__(self) -> None:
        if (
            not isinstance(self.full_name, str)
            or _REPOSITORY_RE.fullmatch(self.full_name) is None
            or not isinstance(self.database_id, int)
            or isinstance(self.database_id, bool)
            or self.database_id <= 0
            or not isinstance(self.node_id, str)
            or _SAFE_OPAQUE_ID_RE.fullmatch(self.node_id) is None
            or not isinstance(self.default_branch, str)
            or not self.default_branch
            or len(self.default_branch) > 255
        ):
            raise RepositoryObservationCoordinationError(
                "Repository observation identity is malformed."
            )

    def to_dict(self) -> dict[str, object]:
        return {
            "full_name": self.full_name,
            "database_id": self.database_id,
            "node_id": self.node_id,
            "default_branch": self.default_branch,
        }


@dataclass(frozen=True)
class ProducerIdentity:
    kind: str
    opaque_id: str
    workflow_sha: str
    evaluator_sha256: str

    def __post_init__(self) -> None:
        if (
            not isinstance(self.kind, str)
            or self.kind not in {"github_app", "github_actions_oidc"}
            or not isinstance(self.opaque_id, str)
            or _SAFE_OPAQUE_ID_RE.fullmatch(self.opaque_id) is None
            or not isinstance(self.workflow_sha, str)
            or _GIT_SHA_RE.fullmatch(self.workflow_sha) is None
            or not isinstance(self.evaluator_sha256, str)
            or _SHA256_RE.fullmatch(self.evaluator_sha256) is None
        ):
            raise RepositoryObservationCoordinationError(
                "Repository observation producer identity is malformed."
            )

    def to_dict(self) -> dict[str, object]:
        return {
            "kind": self.kind,
            "opaque_id": self.opaque_id,
            "workflow_sha": self.workflow_sha,
            "evaluator_sha256": self.evaluator_sha256,
        }


@dataclass(frozen=True)
class RepositoryObservationRequest:
    repository: RepositoryIdentity
    candidate_sha: str
    producer: ProducerIdentity
    timeout_seconds: int = 60

    def __post_init__(self) -> None:
        if (
            not isinstance(self.candidate_sha, str)
            or _GIT_SHA_RE.fullmatch(self.candidate_sha) is None
        ):
            raise RepositoryObservationCoordinationError(
                "Repository observation candidate SHA is malformed."
            )
        if (
            type(self.timeout_seconds) is not int
            or self.timeout_seconds <= 0
            or self.timeout_seconds > int(MAX_OBSERVATION_VALIDITY.total_seconds())
        ):
            raise RepositoryObservationCoordinationError(
                "Repository observation timeout must be between 1 and 900 seconds."
            )


@dataclass(frozen=True)
class ControlReadContext:
    repository: RepositoryIdentity
    candidate_sha: str
    producer: ProducerIdentity
    operation_epoch: str
    started_at: datetime
    deadline_at: datetime
    monotonic_deadline: float
    deadline_remaining: Callable[[], float] = field(repr=False, compare=False)

    def remaining_seconds(self) -> float:
        """Return the bounded time left for a provider transport read."""
        value = self.deadline_remaining()
        if (
            isinstance(value, bool)
            or not isinstance(value, (int, float))
            or not math.isfinite(value)
        ):
            return 0.0
        return max(0.0, float(value))


@dataclass(frozen=True)
class _AdapterCompletion:
    projection: dict[str, object] | None
    completed_monotonic: float
    failed: bool


@dataclass(frozen=True)
class _AdapterWorkerResult:
    control_id: str
    completion: _AdapterCompletion | None


ControlReader = Callable[[ControlReadContext], Mapping[str, object]]


class RepositoryControlAdapter(Protocol):
    control_id: str
    source: str

    def observe(self, context: ControlReadContext) -> dict[str, object]: ...


class _ReadOnlyControlAdapter:
    __slots__ = ("control_id", "source", "_reader")

    def __init__(self, control_id: str, source: str, reader: ControlReader) -> None:
        if CONTROL_SOURCES.get(control_id) != source:
            raise RepositoryObservationCoordinationError(
                f"{source} does not own repository control {control_id!r}."
            )
        self.control_id = control_id
        self.source = source
        self._reader = reader

    def observe(self, context: ControlReadContext) -> dict[str, object]:
        try:
            if context.remaining_seconds() <= 0:
                raise RepositoryControlReadError("timeout")
            raw = self._reader(context)
            if context.remaining_seconds() <= 0:
                raise RepositoryControlReadError("timeout")
        except RepositoryControlReadError as error:
            return self._unavailable(context, error.failure_class)
        except Exception:
            return self._unavailable(context, "adapter_error")
        try:
            return self._project(raw, context)
        except RepositoryControlReadError as error:
            return self._unavailable(context, error.failure_class)
        except (KeyError, TypeError, ValueError):
            return self._unavailable(context, "malformed")

    def _project(
        self,
        raw: Mapping[str, object],
        context: ControlReadContext,
    ) -> dict[str, object]:
        if not isinstance(raw, Mapping):
            raise TypeError("provider response is not a mapping")
        if (
            raw.get("repository_full_name") != context.repository.full_name
            or raw.get("repository_database_id") != context.repository.database_id
            or raw.get("repository_node_id") != context.repository.node_id
            or raw.get("candidate_sha") != context.candidate_sha
            or raw.get("operation_epoch") != context.operation_epoch
        ):
            return self._unavailable(context, "identity_mismatch")
        status = self._provider_status(raw)
        observed = _provider_time(raw.get("observed_at"))
        valid = _provider_time(raw.get("valid_until"))
        if not context.started_at <= observed <= context.deadline_at:
            raise RepositoryControlReadError("identity_mismatch")
        if valid <= observed:
            raise RepositoryControlReadError("stale")
        if valid - observed > MAX_OBSERVATION_VALIDITY:
            raise ValueError("provider validity exceeds the contract")
        observed_at = _format_time(observed)
        valid_until = _format_time(valid)
        opaque_values = raw.get("opaque_ids")
        if not isinstance(opaque_values, list) or not all(
            isinstance(value, str) for value in opaque_values
        ):
            raise TypeError("opaque identifiers are malformed")
        opaque_ids = sorted(set(opaque_values))
        if len(opaque_ids) > 32 or any(
            _SAFE_OPAQUE_ID_RE.fullmatch(value) is None for value in opaque_ids
        ):
            raise TypeError("opaque identifiers are unsafe")
        projection: dict[str, object] = {
            "control_id": self.control_id,
            "source": self.source,
            "status": status,
            "observed_at": observed_at,
            "valid_until": valid_until,
            "opaque_ids": opaque_ids,
        }
        if status == "unavailable":
            failure_class = _required_string(raw, "failure_class")
            if failure_class not in FAILURE_CLASSES:
                raise ValueError("unsupported failure class")
            projection["failure_class"] = failure_class
        projection["projection_sha256"] = _projection_digest(projection)
        return projection

    def _provider_status(self, raw: Mapping[str, object]) -> str:
        if raw.get("status") == "unavailable":
            return "unavailable"
        if self.control_id in ALERT_CONTROL_IDS:
            pagination_complete = raw.get("pagination_complete")
            if not isinstance(pagination_complete, bool):
                raise TypeError("alert pagination state is malformed")
            if not pagination_complete:
                raise RepositoryControlReadError("pagination_incomplete")
            open_count = raw.get("open_count")
            if isinstance(open_count, bool) or not isinstance(open_count, int) or open_count < 0:
                raise TypeError("alert count is malformed")
            return "passed" if open_count == 0 else "failed"
        if self.control_id == "private_security_exception_state":
            pagination_complete = raw.get("pagination_complete")
            if not isinstance(pagination_complete, bool):
                raise TypeError("private projection pagination state is malformed")
            if not pagination_complete or raw.get("semantic_pass_count") != 2:
                raise RepositoryControlReadError("pagination_incomplete")
            semantically_identical = raw.get("semantically_identical")
            if not isinstance(semantically_identical, bool):
                raise TypeError("private projection reconciliation state is malformed")
            return "passed" if semantically_identical else "failed"
        status = raw.get("status")
        if status not in {"passed", "failed"}:
            raise ValueError("unsupported status")
        return status

    def _unavailable(
        self,
        context: ControlReadContext,
        failure_class: str,
    ) -> dict[str, object]:
        return _unavailable_projection(
            self.control_id,
            self.source,
            context,
            failure_class,
        )


class GitHubControlAdapter(_ReadOnlyControlAdapter):
    """Project one deadline-bounded read-only GitHub response into safe state.

    Readers must pass ``context.remaining_seconds()`` as the hard timeout for
    every provider transport request.
    """

    def __init__(self, control_id: str, reader: ControlReader) -> None:
        super().__init__(control_id, "github", reader)


class PackageControlAdapter(_ReadOnlyControlAdapter):
    """Project one bounded read-only package-tree response into safe state."""

    def __init__(self, control_id: str, reader: ControlReader) -> None:
        super().__init__(control_id, "package", reader)


def build_github_control_adapters(
    readers: Mapping[str, ControlReader],
) -> tuple[GitHubControlAdapter, ...]:
    """Bind exactly one read-only provider reader to every GitHub control."""
    expected = {control_id for control_id, source in CONTROL_SOURCES.items() if source == "github"}
    if set(readers) != expected:
        raise RepositoryObservationCoordinationError(
            "GitHub observation requires exactly one reader for every GitHub control."
        )
    return tuple(
        GitHubControlAdapter(control_id, readers[control_id])
        for control_id, source in CONTROL_SOURCES.items()
        if source == "github"
    )


def build_package_control_adapters(
    repo_path: str | Path,
) -> tuple[PackageControlAdapter, ...]:
    """Build bounded no-follow readers for every package-owned control."""
    if not _secure_package_platform_available():
        raise RepositoryObservationCoordinationError(
            "Package control adapters require Linux descriptor anchoring."
        )
    root = Path(repo_path).absolute()
    try:
        root_descriptor = _open_root_directory(root)
    except OSError as error:
        raise RepositoryObservationCoordinationError(
            "Package repository root is unavailable."
        ) from error
    else:
        os.close(root_descriptor)
    return tuple(
        PackageControlAdapter(control_id, _package_reader(root, control_id))
        for control_id, source in CONTROL_SOURCES.items()
        if source == "package"
    )


def _complete_adapter_observation(
    adapter: RepositoryControlAdapter,
    context: ControlReadContext,
    monotonic: MonotonicClock,
) -> _AdapterCompletion:
    try:
        projection = adapter.observe(context)
    except Exception:
        projection = None
        failed = True
    else:
        failed = False
    return _AdapterCompletion(
        projection=projection,
        completed_monotonic=monotonic(),
        failed=failed,
    )


def _run_adapter_worker(
    control_id: str,
    adapter: RepositoryControlAdapter,
    context: ControlReadContext,
    monotonic: MonotonicClock,
    completions: Queue[_AdapterWorkerResult],
) -> None:
    try:
        completion = _complete_adapter_observation(adapter, context, monotonic)
    except Exception:
        completion = None
    completions.put(_AdapterWorkerResult(control_id=control_id, completion=completion))


def collect_repository_control_observation(
    request: RepositoryObservationRequest,
    adapters: Iterable[RepositoryControlAdapter],
    *,
    clock: Clock = lambda: datetime.now(UTC).replace(microsecond=0),
    monotonic: MonotonicClock = time.monotonic,
    epoch_factory: EpochFactory = lambda: secrets.token_hex(32),
) -> RepositoryControlObservation:
    """Fan out one bounded read-only snapshot and normalize every control."""
    adapter_values = tuple(adapters)
    adapters_by_id: dict[str, RepositoryControlAdapter] = {}
    for adapter in adapter_values:
        if adapter.control_id in adapters_by_id:
            raise RepositoryObservationCoordinationError(
                f"Duplicate repository control adapter {adapter.control_id!r}."
            )
        if CONTROL_SOURCES.get(adapter.control_id) != adapter.source:
            raise RepositoryObservationCoordinationError(
                f"Repository control adapter {adapter.control_id!r} has the wrong source."
            )
        adapters_by_id[adapter.control_id] = adapter
    if set(adapters_by_id) != set(CONTROL_SOURCES):
        raise RepositoryObservationCoordinationError(
            "Repository observation requires exactly one adapter for every control."
        )

    started_at = _whole_utc(clock(), "started_at")
    started_monotonic = monotonic()
    deadline_at = started_at + timedelta(seconds=request.timeout_seconds)
    operation_epoch = epoch_factory()
    if not isinstance(operation_epoch, str) or _SHA256_RE.fullmatch(operation_epoch) is None:
        raise RepositoryObservationCoordinationError(
            "Repository observation epoch must be SHA-256."
        )
    monotonic_deadline = started_monotonic + request.timeout_seconds
    context = ControlReadContext(
        repository=request.repository,
        candidate_sha=request.candidate_sha,
        producer=request.producer,
        operation_epoch=operation_epoch,
        started_at=started_at,
        deadline_at=deadline_at,
        monotonic_deadline=monotonic_deadline,
        deadline_remaining=lambda: monotonic_deadline - monotonic(),
    )
    controls_by_id: dict[str, dict[str, object]] = {}
    completions: Queue[_AdapterWorkerResult] = Queue()
    pending_control_ids: set[str] = set()
    for control_id, adapter in adapters_by_id.items():
        worker = Thread(
            target=_run_adapter_worker,
            args=(control_id, adapter, context, monotonic, completions),
            name=f"fork-ops-control-{control_id}",
            daemon=True,
        )
        try:
            worker.start()
        except RuntimeError:
            controls_by_id[control_id] = _unavailable_projection(
                adapter.control_id,
                adapter.source,
                context,
                "adapter_error",
            )
        else:
            pending_control_ids.add(control_id)
    while pending_control_ids:
        remaining = context.remaining_seconds()
        if remaining <= 0:
            break
        try:
            result = completions.get(timeout=remaining)
        except Empty:
            break
        control_id = result.control_id
        if control_id not in pending_control_ids:
            continue
        pending_control_ids.remove(control_id)
        adapter = adapters_by_id[control_id]
        completion = result.completion
        if completion is None:
            controls_by_id[control_id] = _unavailable_projection(
                adapter.control_id,
                adapter.source,
                context,
                "adapter_error",
            )
        elif (
            isinstance(completion.completed_monotonic, bool)
            or not isinstance(completion.completed_monotonic, (int, float))
            or not math.isfinite(completion.completed_monotonic)
            or completion.completed_monotonic >= monotonic_deadline
        ):
            controls_by_id[control_id] = _unavailable_projection(
                adapter.control_id,
                adapter.source,
                context,
                "timeout",
            )
        elif completion.failed or completion.projection is None:
            controls_by_id[control_id] = _unavailable_projection(
                adapter.control_id,
                adapter.source,
                context,
                "adapter_error",
            )
        elif not isinstance(completion.projection, dict):
            controls_by_id[control_id] = _unavailable_projection(
                adapter.control_id,
                adapter.source,
                context,
                "adapter_error",
            )
        else:
            controls_by_id[control_id] = completion.projection
    for control_id in pending_control_ids:
        adapter = adapters_by_id[control_id]
        controls_by_id[control_id] = _unavailable_projection(
            adapter.control_id,
            adapter.source,
            context,
            "timeout",
        )

    completed_at = max(
        started_at,
        min(_whole_utc(clock(), "completed_at"), deadline_at),
    )
    for control_id, control in tuple(controls_by_id.items()):
        try:
            observed = _provider_time(control.get("observed_at"))
            valid_until = _provider_time(control.get("valid_until"))
        except ValueError:
            adapter = adapters_by_id[control_id]
            controls_by_id[control_id] = _unavailable_projection(
                adapter.control_id,
                adapter.source,
                context,
                "malformed",
            )
            continue
        if observed > completed_at:
            adapter = adapters_by_id[control_id]
            controls_by_id[control_id] = _unavailable_projection(
                adapter.control_id,
                adapter.source,
                context,
                "identity_mismatch",
            )
            continue
        if control.get("status") == "passed" and valid_until <= completed_at:
            adapter = adapters_by_id[control_id]
            controls_by_id[control_id] = _unavailable_projection(
                adapter.control_id,
                adapter.source,
                context,
                "stale",
            )
            continue
        try:
            controls_by_id[control_id] = validate_repository_control_projection(
                control,
                expected_control_id=control_id,
                started_at=started_at,
                completed_at=completed_at,
            )
        except RepositoryControlObservationError:
            adapter = adapters_by_id[control_id]
            controls_by_id[control_id] = _unavailable_projection(
                adapter.control_id,
                adapter.source,
                context,
                "adapter_error",
            )
    payload: dict[str, object] = {
        "artifact_kind": "repository_control_observation",
        "schema_version": "1.0",
        "repository": request.repository.to_dict(),
        "candidate_sha": request.candidate_sha,
        "producer": request.producer.to_dict(),
        "operation": {
            "epoch": context.operation_epoch,
            "started_at": _format_time(started_at),
            "completed_at": _format_time(completed_at),
            "deadline_at": _format_time(deadline_at),
        },
        "controls": [controls_by_id[control_id] for control_id in CONTROL_SOURCES],
    }
    payload["observation_sha256"] = _projection_digest(payload)
    return parse_repository_control_observation(payload)


def _package_reader(root: Path, control_id: str) -> ControlReader:
    def read(context: ControlReadContext) -> Mapping[str, object]:
        scopes = {
            "immutable_action_pins": (".github/workflows",),
            "dependabot_grouped_updates": (
                ".github/dependabot.yml",
                ".github/dependabot.yaml",
                "uv.lock",
            ),
            "dependency_review": (".github/workflows",),
            "public_security_exception_state": ("docs/agents/security-exceptions.toml",),
        }
        scope = scopes.get(control_id)
        if scope is None:
            raise RepositoryControlReadError("malformed")
        try:
            root_descriptor = _open_root_directory(root)
        except OSError as error:
            raise RepositoryControlReadError("not_found_or_inaccessible") from error
        try:
            _verify_candidate_materialization(root_descriptor, context, scope)
            final_scope = scope
            if control_id == "immutable_action_pins":
                passed, opaque_ids, action_paths = _observe_action_pins(
                    root_descriptor,
                    context,
                )
                final_scope = (*scope, *action_paths)
            elif control_id == "dependabot_grouped_updates":
                passed, opaque_ids = _observe_dependabot_grouping(
                    root_descriptor,
                    context,
                )
            elif control_id == "dependency_review":
                passed, opaque_ids = _observe_dependency_review(root_descriptor, context)
            else:
                passed, opaque_ids = _observe_public_exception_ledger(
                    root_descriptor,
                    context,
                )
            _verify_candidate_materialization(root_descriptor, context, final_scope)
            return _package_result(context, passed=passed, opaque_ids=opaque_ids)
        finally:
            os.close(root_descriptor)

    return read


def _unavailable_projection(
    control_id: str,
    source: str,
    context: ControlReadContext,
    failure_class: str,
) -> dict[str, object]:
    projection: dict[str, object] = {
        "control_id": control_id,
        "source": source,
        "status": "unavailable",
        "observed_at": _format_time(context.started_at),
        "valid_until": _format_time(context.started_at + MAX_OBSERVATION_VALIDITY),
        "opaque_ids": [],
        "failure_class": failure_class,
    }
    projection["projection_sha256"] = _projection_digest(projection)
    return projection


def _package_result(
    context: ControlReadContext,
    *,
    passed: bool,
    opaque_ids: list[str],
) -> dict[str, object]:
    return {
        "repository_full_name": context.repository.full_name,
        "repository_database_id": context.repository.database_id,
        "repository_node_id": context.repository.node_id,
        "candidate_sha": context.candidate_sha,
        "operation_epoch": context.operation_epoch,
        "status": "passed" if passed else "failed",
        "observed_at": _format_time(context.started_at),
        "valid_until": _format_time(context.started_at + MAX_OBSERVATION_VALIDITY),
        "opaque_ids": opaque_ids,
    }


def _observe_action_pins(
    root_descriptor: int,
    context: ControlReadContext,
) -> tuple[bool, list[str], tuple[str, ...]]:
    workflow_documents = _workflow_documents(root_descriptor, context)
    documents = list(workflow_documents)
    traversal = _LocalActionTraversal(
        root_descriptor=root_descriptor,
        context=context,
        documents=documents,
        workflow_paths=frozenset(path for path, _document, _digest, _size in workflow_documents),
        remaining_document_bytes=(
            MAX_POLICY_DOCUMENT_BYTES
            - sum(size for _path, _document, _digest, size in workflow_documents)
        ),
    )
    for _path, document, _digest, _size in workflow_documents:
        for reference in _workflow_uses(document):
            if not traversal.validate_reference(reference, stack=()):
                return (
                    False,
                    _document_digests(documents),
                    traversal.materialization_paths(),
                )
    return True, _document_digests(documents), traversal.materialization_paths()


def _observe_dependency_review(
    root_descriptor: int,
    context: ControlReadContext,
) -> tuple[bool, list[str]]:
    documents = _workflow_documents(root_descriptor, context)
    for _path, document, _digest, _size in documents:
        if not _has_pull_request_trigger(document):
            continue
        for job in _workflow_jobs(document):
            if (
                "if" in job
                or "needs" in job
                or "uses" in job
                or job.get("continue-on-error", False) is not False
                or not _job_has_runner(job)
                or not _dependency_review_permissions_enforce(document, job)
            ):
                continue
            for step in _workflow_steps(job):
                reference = step.get("uses")
                if (
                    not isinstance(reference, str)
                    or not reference.startswith("actions/dependency-review-action@")
                    or _REMOTE_ACTION_RE.fullmatch(reference) is None
                    or "if" in step
                    or step.get("continue-on-error", False) is not False
                ):
                    continue
                parameters = step.get("with")
                if _dependency_review_parameters_enforce(parameters):
                    return True, _document_digests(documents)
    return False, _document_digests(documents)


def _observe_dependabot_grouping(
    root_descriptor: int,
    context: ControlReadContext,
) -> tuple[bool, list[str]]:
    candidates = (
        Path(".github/dependabot.yml"),
        Path(".github/dependabot.yaml"),
    )
    payloads = [(path, _read_candidate_file(root_descriptor, context, path)) for path in candidates]
    existing = [(path, payload) for path, payload in payloads if payload is not None]
    if len(existing) != 1:
        return False, []
    _path, payload = existing[0]
    digest = hashlib.sha256(payload).hexdigest()
    lock_payload = _read_candidate_file(root_descriptor, context, Path("uv.lock"))
    if lock_payload is None:
        return False, [digest]
    evidence_digests = sorted((digest, hashlib.sha256(lock_payload).hexdigest()))
    try:
        data = yaml.load(payload.decode("utf-8"), Loader=_Yaml12SafeLoader)
    except (UnicodeDecodeError, yaml.YAMLError):
        return False, evidence_digests
    if not isinstance(data, Mapping) or data.get("version") != 2:
        return False, evidence_digests
    updates = data.get("updates")
    if not isinstance(updates, list) or not all(isinstance(update, Mapping) for update in updates):
        return False, evidence_digests
    authoritative_updates = [
        update
        for update in updates
        if isinstance(update, Mapping)
        and update.get("package-ecosystem") == "uv"
        and update.get("target-branch", context.repository.default_branch)
        == context.repository.default_branch
        and _dependabot_update_covers_root(update)
    ]
    if len(authoritative_updates) != 1:
        return False, evidence_digests
    return (
        _dependabot_update_enforces_grouping(authoritative_updates[0]),
        evidence_digests,
    )


def _dependabot_update_covers_root(update: Mapping[object, object]) -> bool:
    if update.get("directory") == "/":
        return True
    directories = update.get("directories")
    return isinstance(directories, list) and "/" in directories


def _dependabot_update_enforces_grouping(update: Mapping[object, object]) -> bool:
    if (
        update.get("directory") != "/"
        or "directories" in update
        or "allow" in update
        or "cooldown" in update
        or "multi-ecosystem-group" in update
    ):
        return False
    versioning_strategy = update.get("versioning-strategy")
    if versioning_strategy is not None and (
        not isinstance(versioning_strategy, str)
        or versioning_strategy not in _DEPENDABOT_VERSIONING_STRATEGIES
    ):
        return False
    if update.get("ignore") not in (None, []) or update.get("exclude-paths") not in (None, []):
        return False
    pull_request_limit = update.get("open-pull-requests-limit")
    if pull_request_limit is not None and (
        isinstance(pull_request_limit, bool)
        or not isinstance(pull_request_limit, int)
        or pull_request_limit <= 0
    ):
        return False
    schedule = update.get("schedule")
    if not isinstance(schedule, Mapping) or schedule.get("interval") != "weekly":
        return False
    groups = update.get("groups")
    if not isinstance(groups, Mapping):
        return False
    version_groups: list[Mapping[object, object]] = []
    for group in groups.values():
        if not isinstance(group, Mapping):
            return False
        applies_to = group.get("applies-to", "version-updates")
        if applies_to == "security-updates":
            continue
        if applies_to != "version-updates":
            return False
        version_groups.append(group)
    if len(version_groups) != 1:
        return False
    group = version_groups[0]
    if "dependency-type" in group or group.get("exclude-patterns") not in (None, []):
        return False
    patterns = group.get("patterns")
    update_types = group.get("update-types")
    return (
        isinstance(patterns, list)
        and patterns == ["*"]
        and isinstance(update_types, list)
        and len(update_types) == 2
        and _string_set(update_types) == {"minor", "patch"}
    )


def _observe_public_exception_ledger(
    root_descriptor: int,
    context: ControlReadContext,
) -> tuple[bool, list[str]]:
    path = Path("docs/agents/security-exceptions.toml")
    payload = _read_candidate_file(root_descriptor, context, path)
    if payload is None:
        return False, []
    digest = hashlib.sha256(payload).hexdigest()
    try:
        data = tomllib.loads(payload.decode("utf-8"))
        validate_public_security_exception_ledger(
            data,
            evaluated_at=_format_time(context.started_at),
        )
    except (
        UnicodeDecodeError,
        tomllib.TOMLDecodeError,
        SecurityExceptionContractError,
        SecurityExceptionValidationError,
    ):
        return False, [digest]
    return True, [digest]


WorkflowDocument = tuple[Path, Mapping[object, object], str, int]


@dataclass
class _LocalActionTraversal:
    root_descriptor: int
    context: ControlReadContext
    documents: list[WorkflowDocument]
    workflow_paths: frozenset[Path]
    remaining_document_bytes: int
    observed_paths: set[Path] = field(default_factory=set)
    visited_actions: set[Path] = field(default_factory=set)
    observed_dockerfiles: set[Path] = field(default_factory=set)
    dockerfile_stage_count: int = 0

    def validate_reference(
        self,
        reference: str,
        *,
        stack: tuple[Path, ...],
    ) -> bool:
        if reference.startswith("docker://"):
            return _DOCKER_ACTION_RE.fullmatch(reference) is not None
        if not reference.startswith("./"):
            return _REMOTE_ACTION_RE.fullmatch(reference) is not None
        relative_path = _local_reference_path(reference)
        if relative_path is None:
            return False
        if relative_path.parent == Path(".github/workflows") and relative_path.suffix.lower() in {
            ".yml",
            ".yaml",
        }:
            return relative_path in self.workflow_paths
        return self._validate_local_action(relative_path, stack=stack)

    def materialization_paths(self) -> tuple[str, ...]:
        return tuple(path.as_posix() for path in sorted(self.observed_paths))

    def _validate_local_action(
        self,
        action_directory: Path,
        *,
        stack: tuple[Path, ...],
    ) -> bool:
        if action_directory in stack or len(stack) >= MAX_LOCAL_ACTION_DEPTH:
            return False
        if action_directory in self.visited_actions:
            return True
        if len(self.visited_actions) >= MAX_LOCAL_ACTIONS:
            return False
        manifest = self._read_manifest(action_directory)
        if manifest is None:
            return False
        path, document, _digest, _size = manifest
        self.documents.append(manifest)
        next_stack = (*stack, action_directory)
        for reference in _local_action_uses(document):
            if not self.validate_reference(reference, stack=next_stack):
                return False
        if not self._validate_local_dockerfile(action_directory, document):
            return False
        self.visited_actions.add(action_directory)
        return True

    def _validate_local_dockerfile(
        self,
        action_directory: Path,
        document: Mapping[object, object],
    ) -> bool:
        runs = document.get("runs")
        if not isinstance(runs, Mapping) or runs.get("using") != "docker":
            return True
        image = runs.get("image")
        if not isinstance(image, str) or image.startswith("docker://"):
            return True
        dockerfile_path = _local_dockerfile_path(action_directory, image)
        if dockerfile_path is None:
            return False
        if dockerfile_path not in self.observed_dockerfiles:
            if len(self.observed_dockerfiles) >= MAX_LOCAL_DOCKERFILES:
                raise RepositoryControlReadError("malformed")
            self.observed_dockerfiles.add(dockerfile_path)
        payload = _read_candidate_file(
            self.root_descriptor,
            self.context,
            dockerfile_path,
        )
        if payload is None:
            return False
        self.remaining_document_bytes -= len(payload)
        if self.remaining_document_bytes < 0:
            raise RepositoryControlReadError("malformed")
        self.observed_paths.add(dockerfile_path)
        self.documents.append(
            (
                dockerfile_path,
                {},
                hashlib.sha256(payload).hexdigest(),
                len(payload),
            )
        )
        try:
            dockerfile = payload.decode("utf-8")
        except UnicodeDecodeError as error:
            raise RepositoryControlReadError("malformed") from error
        dockerfile = dockerfile.removeprefix("\ufeff")
        parser_configuration = _dockerfile_parser_configuration(dockerfile)
        if parser_configuration is None:
            return False
        escape_character = parser_configuration
        saw_stage = False
        prior_stage_count = 0
        prior_stage_names: set[str] = set()
        current_stage_name: str | None = None
        for line in _dockerfile_logical_lines(
            dockerfile,
            escape_character=escape_character,
        ):
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            if re.match(r"(?i:ONBUILD)\b", stripped):
                return False
            if re.match(r"(?i:ADD)\b", stripped):
                return False
            match = re.fullmatch(
                r"(?i:FROM)\s+(\S+)(?:\s+(?i:AS)\s+([A-Za-z0-9][A-Za-z0-9._-]*))?\s*",
                stripped,
            )
            if match is None:
                if re.match(r"(?i:FROM)\b", stripped):
                    return False
                if re.match(r"(?i:COPY)\b", stripped) and not _dockerfile_copy_source_is_safe(
                    stripped,
                    stage_names=prior_stage_names,
                    prior_stage_count=prior_stage_count,
                    escape_character=escape_character,
                ):
                    return False
                if re.match(r"(?i:RUN)\b", stripped) and not _dockerfile_run_mount_sources_are_safe(
                    stripped,
                    stage_names=prior_stage_names,
                    prior_stage_count=prior_stage_count,
                    escape_character=escape_character,
                ):
                    return False
                continue
            if saw_stage:
                prior_stage_count += 1
                if current_stage_name is not None:
                    prior_stage_names.add(current_stage_name)
            saw_stage = True
            self.dockerfile_stage_count += 1
            if self.dockerfile_stage_count > MAX_DOCKERFILE_STAGES:
                raise RepositoryControlReadError("malformed")
            base = match.group(1)
            if (
                base.casefold() != "scratch"
                and base.casefold() not in prior_stage_names
                and not _is_immutable_docker_image(base)
            ):
                return False
            stage_name = match.group(2)
            if stage_name is not None:
                normalized_stage_name = stage_name.casefold()
                if normalized_stage_name in prior_stage_names:
                    return False
                current_stage_name = normalized_stage_name
            else:
                current_stage_name = None
        return saw_stage

    def _read_manifest(self, action_directory: Path) -> WorkflowDocument | None:
        candidates = (
            action_directory / "action.yml",
            action_directory / "action.yaml",
        )
        payloads = [
            (
                path,
                _read_candidate_file(
                    self.root_descriptor,
                    self.context,
                    path,
                ),
            )
            for path in candidates
        ]
        existing = [(path, payload) for path, payload in payloads if payload is not None]
        if len(existing) != 1:
            return None
        path, payload = existing[0]
        self.remaining_document_bytes -= len(payload)
        if self.remaining_document_bytes < 0:
            raise RepositoryControlReadError("malformed")
        self.observed_paths.add(path)
        try:
            document = yaml.load(
                payload.decode("utf-8"),
                Loader=_Yaml12SafeLoader,
            )
        except (UnicodeDecodeError, yaml.YAMLError) as error:
            raise RepositoryControlReadError("malformed") from error
        if not isinstance(document, Mapping):
            raise RepositoryControlReadError("malformed")
        return path, document, hashlib.sha256(payload).hexdigest(), len(payload)


def _local_reference_path(reference: str) -> Path | None:
    if (
        len(reference) > MAX_LOCAL_REFERENCE_CHARACTERS
        or not reference.startswith("./")
        or "\\" in reference
    ):
        return None
    raw_path = reference[2:]
    parts = raw_path.split("/")
    if not parts or any(part in {"", ".", ".."} for part in parts):
        return None
    path = PurePosixPath(*parts)
    if path.is_absolute():
        return None
    return Path(*path.parts)


def _local_dockerfile_path(action_directory: Path, image: str) -> Path | None:
    if image == "Dockerfile":
        return action_directory / image
    relative_path = _local_reference_path(image)
    if relative_path is None:
        return None
    return action_directory / relative_path


def _dockerfile_logical_lines(
    dockerfile: str,
    *,
    escape_character: str,
) -> tuple[str, ...]:
    logical_lines: list[str] = []
    for line in dockerfile.splitlines():
        stripped = line.strip()
        if stripped.startswith("#"):
            logical_lines.append(line)
            continue
        if line.rstrip(" \t").endswith(escape_character) or "<<" in line:
            raise RepositoryControlReadError("malformed")
        logical_lines.append(line)
    return tuple(logical_lines)


def _dockerfile_parser_configuration(dockerfile: str) -> str | None:
    escape_character = "\\"
    seen_directives: set[str] = set()
    lines = dockerfile.splitlines()
    line_index = 1 if lines and lines[0].startswith("#!") else 0
    for line in lines[line_index:]:
        stripped = line.lstrip()
        slash_match = re.fullmatch(
            r"//\s*(?P<key>syntax)\s*=\s*(?P<value>.+?)\s*",
            stripped,
            flags=re.IGNORECASE,
        )
        if slash_match is not None:
            key = slash_match.group("key").casefold()
            value = slash_match.group("value")
        elif stripped.startswith("//"):
            return None
        elif stripped.startswith("{"):
            try:
                json_directive = json.loads(stripped)
            except json.JSONDecodeError:
                return None
            if (
                not isinstance(json_directive, dict)
                or set(json_directive) != {"syntax"}
                or not isinstance(json_directive.get("syntax"), str)
            ):
                return None
            key = "syntax"
            value = json_directive["syntax"]
        else:
            match = re.fullmatch(
                r"#\s*(?P<key>[A-Za-z]+)\s*=\s*(?P<value>.+?)\s*",
                stripped,
            )
            if match is None:
                break
            key = match.group("key").casefold()
            value = match.group("value")
            if key not in {"check", "escape", "syntax"}:
                break
        value = value.strip()
        if not value:
            return None
        if key in seen_directives:
            return None
        seen_directives.add(key)
        if key == "escape":
            if value not in {"\\", "`"}:
                return None
            escape_character = value
        elif key == "syntax":
            reference = value.split(maxsplit=1)[0]
            if not _is_immutable_docker_image(reference):
                return None
    return escape_character


def _is_immutable_docker_image(reference: str) -> bool:
    return "://" not in reference and _DOCKERFILE_BASE_IMAGE_RE.fullmatch(reference) is not None


def _dockerfile_copy_source_is_safe(
    instruction: str,
    *,
    stage_names: set[str],
    prior_stage_count: int,
    escape_character: str,
) -> bool:
    match = re.fullmatch(r"(?i:COPY)\s+(?P<body>.+)", instruction)
    if match is None:
        return False
    body = match.group("body").lstrip()
    sources: list[str] = []
    while body.startswith("--"):
        flag_match = re.match(r"(?P<flag>--\S+)(?:\s+|$)", body)
        if flag_match is None:
            return False
        raw_flag = flag_match.group("flag")
        if not _dockerfile_flag_token_is_unambiguous(
            raw_flag,
            escape_character=escape_character,
        ):
            return False
        flag = raw_flag[2:]
        name, separator, value = flag.partition("=")
        if name.casefold() == "from":
            if not separator or not value:
                return False
            sources.append(value)
        body = body[flag_match.end() :].lstrip()
    if not sources:
        return True
    if len(sources) != 1 or not body:
        return False
    return _dockerfile_materialization_source_is_safe(
        sources[0],
        stage_names=stage_names,
        prior_stage_count=prior_stage_count,
        allow_scratch=True,
        allow_numeric_stage=True,
    )


def _dockerfile_run_mount_sources_are_safe(
    instruction: str,
    *,
    stage_names: set[str],
    prior_stage_count: int,
    escape_character: str,
) -> bool:
    match = re.fullmatch(r"(?i:RUN)\s+(?P<body>.+)", instruction)
    if match is None:
        return False
    body = match.group("body").lstrip()
    saw_mount = False
    while body.startswith("--"):
        flag_match = re.match(r"(?P<flag>--\S+)(?:\s+|$)", body)
        if flag_match is None:
            return False
        raw_flag = flag_match.group("flag")
        if not _dockerfile_flag_token_is_unambiguous(
            raw_flag,
            escape_character=escape_character,
        ):
            return False
        flag = raw_flag[2:]
        name, separator, value = flag.partition("=")
        if name.casefold() == "mount":
            if not separator or not value:
                return False
            saw_mount = True
            sources: list[str] = []
            seen_fields: set[str] = set()
            for field in value.split(","):
                field_name, field_separator, field_value = field.partition("=")
                normalized_field_name = field_name.casefold()
                if (
                    not field_separator
                    or not field_name
                    or not field_value
                    or normalized_field_name in seen_fields
                ):
                    return False
                seen_fields.add(normalized_field_name)
                if normalized_field_name != "from":
                    continue
                sources.append(field_value)
            if len(sources) > 1 or (
                sources
                and not _dockerfile_materialization_source_is_safe(
                    sources[0],
                    stage_names=stage_names,
                    prior_stage_count=prior_stage_count,
                    allow_scratch=False,
                    allow_numeric_stage=False,
                )
            ):
                return False
        body = body[flag_match.end() :].lstrip()
    return not saw_mount or bool(body)


def _dockerfile_materialization_source_is_safe(
    source: str,
    *,
    stage_names: set[str],
    prior_stage_count: int,
    allow_scratch: bool,
    allow_numeric_stage: bool,
) -> bool:
    normalized_source = source.casefold()
    if source.isdecimal():
        return bool(
            allow_numeric_stage
            and re.fullmatch(r"(?:0|[1-9][0-9]{0,5})", source)
            and int(source) < prior_stage_count
        )
    if (allow_scratch and normalized_source == "scratch") or normalized_source in stage_names:
        return True
    return _is_immutable_docker_image(source)


def _dockerfile_flag_token_is_unambiguous(
    token: str,
    *,
    escape_character: str,
) -> bool:
    return not any(character in token for character in ('"', "'", escape_character))


def _local_action_uses(document: Mapping[object, object]) -> tuple[str, ...]:
    runs = document.get("runs")
    if not isinstance(runs, Mapping):
        raise RepositoryControlReadError("malformed")
    using = runs.get("using")
    if using == "composite":
        steps = runs.get("steps")
        if not isinstance(steps, list) or not all(isinstance(step, Mapping) for step in steps):
            raise RepositoryControlReadError("malformed")
        references: list[str] = []
        for step in steps:
            if not isinstance(step, Mapping) or "uses" not in step:
                continue
            reference = step.get("uses")
            if not isinstance(reference, str):
                raise RepositoryControlReadError("malformed")
            references.append(reference)
        return tuple(references)
    if using == "docker":
        image = runs.get("image")
        if not isinstance(image, str):
            raise RepositoryControlReadError("malformed")
        if image.startswith("docker://"):
            return (image,)
        if image == "Dockerfile" or image.startswith("./"):
            return ()
        raise RepositoryControlReadError("malformed")
    if using in {"node12", "node16", "node20", "node24"}:
        return ()
    raise RepositoryControlReadError("malformed")


def _workflow_documents(
    root_descriptor: int,
    context: ControlReadContext,
) -> list[WorkflowDocument]:
    relative_directory = Path(".github/workflows")
    candidate_paths = _candidate_workflow_paths(root_descriptor, context)
    try:
        directory_descriptor = _open_directory_from_root(
            root_descriptor,
            relative_directory,
        )
    except FileNotFoundError:
        if candidate_paths:
            raise RepositoryControlReadError("identity_mismatch") from None
        return []
    except OSError as error:
        raise RepositoryControlReadError("not_found_or_inaccessible") from error
    try:
        try:
            names = sorted(os.listdir(directory_descriptor))
        except OSError as error:
            raise RepositoryControlReadError("not_found_or_inaccessible") from error
        materialized_paths = tuple(
            sorted(
                (
                    relative_directory / name
                    for name in names
                    if Path(name).suffix.lower() in {".yml", ".yaml"}
                ),
                key=_path_as_posix,
            )
        )
        if materialized_paths != candidate_paths:
            raise RepositoryControlReadError("identity_mismatch")
        documents: list[WorkflowDocument] = []
        cumulative_bytes = 0
        for relative_path in candidate_paths:
            payload = _read_candidate_file(
                root_descriptor,
                context,
                relative_path,
                directory_descriptor=directory_descriptor,
            )
            if payload is None:
                raise RepositoryControlReadError("identity_mismatch")
            cumulative_bytes += len(payload)
            if cumulative_bytes > MAX_POLICY_DOCUMENT_BYTES:
                raise RepositoryControlReadError("malformed")
            try:
                document = yaml.load(
                    payload.decode("utf-8"),
                    Loader=_Yaml12SafeLoader,
                )
            except (UnicodeDecodeError, yaml.YAMLError) as error:
                raise RepositoryControlReadError("malformed") from error
            if not isinstance(document, Mapping):
                raise RepositoryControlReadError("malformed")
            documents.append(
                (
                    relative_path,
                    document,
                    hashlib.sha256(payload).hexdigest(),
                    len(payload),
                )
            )
        return documents
    finally:
        os.close(directory_descriptor)


def _workflow_jobs(
    document: Mapping[object, object],
) -> tuple[Mapping[object, object], ...]:
    jobs = document.get("jobs")
    if not isinstance(jobs, Mapping) or not all(isinstance(job, Mapping) for job in jobs.values()):
        raise RepositoryControlReadError("malformed")
    return tuple(job for job in jobs.values() if isinstance(job, Mapping))


def _workflow_steps(
    job: Mapping[object, object],
) -> tuple[Mapping[object, object], ...]:
    steps = job.get("steps", [])
    if not isinstance(steps, list) or not all(isinstance(step, Mapping) for step in steps):
        raise RepositoryControlReadError("malformed")
    return tuple(step for step in steps if isinstance(step, Mapping))


def _workflow_uses(document: Mapping[object, object]) -> tuple[str, ...]:
    references: list[str] = []
    for job in _workflow_jobs(document):
        if "uses" in job:
            value = job.get("uses")
            if not isinstance(value, str):
                raise RepositoryControlReadError("malformed")
            references.append(value)
        for step in _workflow_steps(job):
            if "uses" not in step:
                continue
            value = step.get("uses")
            if not isinstance(value, str):
                raise RepositoryControlReadError("malformed")
            references.append(value)
    return tuple(references)


def _dependency_review_parameters_enforce(parameters: object) -> bool:
    normalized = _normalized_action_inputs(parameters)
    if normalized is None or normalized.get("fail-on-severity") != "low":
        return False
    if not _action_boolean_input_matches(normalized.get("warn-only"), expected=False):
        return False
    if not _action_boolean_input_matches(
        normalized.get("vulnerability-check"),
        expected=True,
    ):
        return False
    scopes = normalized.get("fail-on-scopes")
    if not isinstance(scopes, str):
        return False
    scope_values = tuple(value.strip() for value in scopes.split(","))
    if len(scope_values) != 3 or set(scope_values) != {
        "development",
        "runtime",
        "unknown",
    }:
        return False
    weakening_overrides = {
        "allow-ghsas",
        "base-ref",
        "config-file",
        "head-ref",
    }
    return not weakening_overrides.intersection(normalized)


def _dependency_review_permissions_enforce(
    workflow: Mapping[object, object],
    job: Mapping[object, object],
) -> bool:
    if "permissions" in job:
        permissions = job.get("permissions")
    elif "permissions" in workflow:
        permissions = workflow.get("permissions")
    else:
        return False
    if permissions == "read-all":
        return True
    if not isinstance(permissions, Mapping):
        return False
    return permissions.get("contents", "none") == "read"


def _normalized_action_inputs(parameters: object) -> dict[str, object] | None:
    if not isinstance(parameters, Mapping):
        return None
    normalized: dict[str, object] = {}
    for key, value in parameters.items():
        if not isinstance(key, str) or not key.isascii():
            return None
        normalized_key = key.casefold()
        if normalized_key in normalized:
            return None
        normalized[normalized_key] = value
    return normalized


def _action_boolean_input_matches(value: object, *, expected: bool) -> bool:
    if isinstance(value, bool):
        return value is expected
    if isinstance(value, str):
        return value.casefold() == str(expected).lower()
    return False


def _job_has_runner(job: Mapping[object, object]) -> bool:
    runner = job.get("runs-on")
    if isinstance(runner, str):
        return bool(runner.strip())
    if isinstance(runner, list):
        return bool(runner) and all(isinstance(value, str) and value.strip() for value in runner)
    if (
        not isinstance(runner, Mapping)
        or not runner
        or not set(runner).issubset({"group", "labels"})
    ):
        return False
    group = runner.get("group")
    labels = runner.get("labels")
    group_is_valid = isinstance(group, str) and bool(group.strip())
    labels_are_valid = isinstance(labels, str) and bool(labels.strip())
    if isinstance(labels, list):
        labels_are_valid = bool(labels) and all(
            isinstance(value, str) and value.strip() for value in labels
        )
    return group_is_valid or labels_are_valid


def _has_pull_request_trigger(document: Mapping[object, object]) -> bool:
    trigger = document.get("on")
    if trigger == "pull_request":
        return True
    if isinstance(trigger, list):
        return "pull_request" in trigger
    if not isinstance(trigger, Mapping) or "pull_request" not in trigger:
        return False
    pull_request = trigger.get("pull_request")
    return pull_request is None or (isinstance(pull_request, Mapping) and not pull_request)


def _string_set(value: object) -> set[str]:
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        return set()
    return set(value)


def _read_candidate_file(
    root_descriptor: int,
    context: ControlReadContext,
    relative_path: Path,
    *,
    directory_descriptor: int | None = None,
) -> bytes | None:
    owned_directory_descriptor = directory_descriptor is None
    parent_descriptor = directory_descriptor
    if parent_descriptor is None:
        try:
            parent_descriptor = _open_directory_from_root(
                root_descriptor,
                relative_path.parent,
            )
        except FileNotFoundError:
            parent_descriptor = None
        except OSError as error:
            raise RepositoryControlReadError("not_found_or_inaccessible") from error
    try:
        if parent_descriptor is None:
            payload = None
        else:
            try:
                payload = read_stable_regular_file(
                    relative_path.name,
                    maximum_bytes=MAX_PACKAGE_FILE_BYTES,
                    directory_descriptor=parent_descriptor,
                )
            except FileNotFoundError:
                payload = None
            except StableFileReadError as error:
                failure_class = (
                    "not_found_or_inaccessible" if error.failure == "not_regular" else "malformed"
                )
                raise RepositoryControlReadError(failure_class) from error
            except OSError as error:
                raise RepositoryControlReadError("not_found_or_inaccessible") from error
    finally:
        if owned_directory_descriptor and parent_descriptor is not None:
            os.close(parent_descriptor)
    candidate_payload = _candidate_blob(root_descriptor, context, relative_path)
    if payload is None and candidate_payload is None:
        return None
    if payload is None or candidate_payload is None or payload != candidate_payload:
        raise RepositoryControlReadError("identity_mismatch")
    return payload


def _open_root_directory(root: Path) -> int:
    return os.open(
        root,
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_NOFOLLOW", 0),
    )


def _secure_package_platform_available() -> bool:
    return (
        sys.platform == "linux"
        and Path("/proc/self/fd").is_dir()
        and os.open in os.supports_dir_fd
        and hasattr(os, "O_DIRECTORY")
        and hasattr(os, "O_NOFOLLOW")
    )


def _open_directory_from_root(root_descriptor: int, relative_path: Path) -> int:
    descriptor = os.dup(root_descriptor)
    try:
        for part in relative_path.parts:
            if part in {"", ".", ".."}:
                raise OSError("Unsafe package authority path.")
            next_descriptor = os.open(
                part,
                os.O_RDONLY
                | getattr(os, "O_CLOEXEC", 0)
                | getattr(os, "O_DIRECTORY", 0)
                | getattr(os, "O_NOFOLLOW", 0),
                dir_fd=descriptor,
            )
            os.close(descriptor)
            descriptor = next_descriptor
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def _verify_candidate_materialization(
    root_descriptor: int,
    context: ControlReadContext,
    paths: tuple[str, ...],
) -> None:
    _status, candidate = _run_git(
        root_descriptor,
        context,
        ("rev-parse", "--verify", f"{context.candidate_sha}^{{commit}}"),
        maximum_output_bytes=128,
    )
    if candidate.strip().decode("ascii", errors="replace") != context.candidate_sha:
        raise RepositoryControlReadError("identity_mismatch")
    _status, head = _run_git(
        root_descriptor,
        context,
        ("rev-parse", "--verify", "HEAD^{commit}"),
        maximum_output_bytes=128,
    )
    if head.strip().decode("ascii", errors="replace") != context.candidate_sha:
        raise RepositoryControlReadError("identity_mismatch")
    _verify_index_materialization_flags(root_descriptor, context, paths)
    status, _output = _run_git(
        root_descriptor,
        context,
        (
            "diff-index",
            "--cached",
            "--quiet",
            "--no-ext-diff",
            "--no-textconv",
            context.candidate_sha,
            "--",
            *paths,
        ),
        maximum_output_bytes=0,
        accepted_statuses=(0, 1),
    )
    if status != 0:
        raise RepositoryControlReadError("identity_mismatch")
    _verify_scoped_worktree(root_descriptor, context, paths)


def _verify_scoped_worktree(
    root_descriptor: int,
    context: ControlReadContext,
    paths: tuple[str, ...],
) -> None:
    for path in dict.fromkeys(paths):
        if path == ".github/workflows":
            _workflow_documents(root_descriptor, context)
        else:
            _read_candidate_file(root_descriptor, context, Path(path))


def _verify_index_materialization_flags(
    root_descriptor: int,
    context: ControlReadContext,
    paths: tuple[str, ...],
) -> None:
    _status, payload = _run_git(
        root_descriptor,
        context,
        ("ls-files", "-v", "-z", "--", *paths),
        maximum_output_bytes=MAX_POLICY_DOCUMENT_BYTES,
    )
    if payload and not payload.endswith(b"\0"):
        raise RepositoryControlReadError("malformed")
    records = payload[:-1].split(b"\0") if payload else []
    for record in records:
        tag, separator, path = record.partition(b" ")
        if separator != b" " or len(tag) != 1 or not path:
            raise RepositoryControlReadError("malformed")
        if tag != b"H":
            raise RepositoryControlReadError("identity_mismatch")


def _candidate_workflow_paths(
    root_descriptor: int,
    context: ControlReadContext,
) -> tuple[Path, ...]:
    _status, payload = _run_git(
        root_descriptor,
        context,
        (
            "ls-tree",
            "-r",
            "-z",
            "--name-only",
            context.candidate_sha,
            "--",
            ".github/workflows",
        ),
        maximum_output_bytes=MAX_POLICY_DOCUMENT_BYTES,
    )
    if payload and not payload.endswith(b"\0"):
        raise RepositoryControlReadError("malformed")
    records = payload[:-1].split(b"\0") if payload else []
    paths: list[Path] = []
    for record in records:
        try:
            name = record.decode("utf-8")
        except UnicodeDecodeError as error:
            raise RepositoryControlReadError("malformed") from error
        pure_path = PurePosixPath(name)
        if (
            pure_path.is_absolute()
            or pure_path.as_posix() != name
            or any(part in {"", ".", ".."} for part in pure_path.parts)
        ):
            raise RepositoryControlReadError("malformed")
        if pure_path.parent == PurePosixPath(".github/workflows") and pure_path.suffix.lower() in {
            ".yml",
            ".yaml",
        }:
            paths.append(Path(*pure_path.parts))
    if len(paths) > MAX_WORKFLOW_FILES:
        raise RepositoryControlReadError("malformed")
    return tuple(sorted(paths, key=_path_as_posix))


def _candidate_blob(
    root_descriptor: int,
    context: ControlReadContext,
    relative_path: Path,
) -> bytes | None:
    object_name = f"{context.candidate_sha}:{relative_path.as_posix()}"
    status, _output = _run_git(
        root_descriptor,
        context,
        ("cat-file", "-e", object_name),
        maximum_output_bytes=0,
        accepted_statuses=(0, 1, 128),
    )
    if status != 0:
        return None
    _status, size_payload = _run_git(
        root_descriptor,
        context,
        ("cat-file", "-s", object_name),
        maximum_output_bytes=32,
    )
    try:
        size = int(size_payload.strip())
    except ValueError as error:
        raise RepositoryControlReadError("malformed") from error
    if size < 0 or size > MAX_PACKAGE_FILE_BYTES:
        raise RepositoryControlReadError("malformed")
    _status, payload = _run_git(
        root_descriptor,
        context,
        ("cat-file", "blob", object_name),
        maximum_output_bytes=MAX_PACKAGE_FILE_BYTES,
    )
    if len(payload) != size:
        raise RepositoryControlReadError("malformed")
    return payload


def _run_git(
    root_descriptor: int,
    context: ControlReadContext,
    arguments: tuple[str, ...],
    *,
    maximum_output_bytes: int,
    accepted_statuses: tuple[int, ...] = (0,),
) -> tuple[int, bytes]:
    if (
        isinstance(maximum_output_bytes, bool)
        or not isinstance(maximum_output_bytes, int)
        or maximum_output_bytes < 0
    ):
        raise RepositoryControlReadError("malformed")
    remaining = context.remaining_seconds()
    if remaining <= 0:
        raise RepositoryControlReadError("timeout")
    descriptor_path = f"/proc/self/fd/{root_descriptor}"
    try:
        administration = os.stat(".git", dir_fd=root_descriptor, follow_symlinks=False)
    except OSError as error:
        raise RepositoryControlReadError("identity_mismatch") from error
    if not (stat.S_ISDIR(administration.st_mode) or stat.S_ISREG(administration.st_mode)):
        raise RepositoryControlReadError("identity_mismatch")
    environment = {
        "GIT_ASKPASS": "",
        "GIT_ATTR_NOSYSTEM": "1",
        "GIT_CEILING_DIRECTORIES": os.path.realpath(descriptor_path),
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_DISCOVERY_ACROSS_FILESYSTEM": "0",
        "GIT_EXTERNAL_DIFF": "",
        "GIT_LITERAL_PATHSPECS": "1",
        "GIT_NO_REPLACE_OBJECTS": "1",
        "GIT_OPTIONAL_LOCKS": "0",
        "GIT_PAGER": "cat",
        "GIT_PROTOCOL_FROM_USER": "0",
        "GIT_TERMINAL_PROMPT": "0",
        "LANG": "C",
        "LC_ALL": "C",
        "PAGER": "cat",
        "PATH": os.defpath,
    }
    command = (
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
        "-c",
        f"core.worktree={descriptor_path}",
        "-c",
        "core.bare=false",
        *arguments,
    )
    process: subprocess.Popen[bytes] | None = None
    selector: selectors.BaseSelector | None = None
    try:
        process = subprocess.Popen(
            command,
            cwd=descriptor_path,
            env=environment,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            pass_fds=(root_descriptor,),
        )
        stdout = process.stdout
        if stdout is None:
            raise RepositoryControlReadError("adapter_error")
        selector = selectors.DefaultSelector()
        selector.register(stdout, selectors.EVENT_READ)
        payload = bytearray()
        while True:
            remaining = context.remaining_seconds()
            if remaining <= 0:
                raise RepositoryControlReadError("timeout")
            if not selector.select(timeout=remaining):
                raise RepositoryControlReadError("timeout")
            read_limit = min(64 * 1024, maximum_output_bytes - len(payload) + 1)
            chunk = os.read(stdout.fileno(), read_limit)
            if not chunk:
                break
            payload.extend(chunk)
            if len(payload) > maximum_output_bytes:
                raise RepositoryControlReadError("malformed")
        remaining = context.remaining_seconds()
        if remaining <= 0:
            raise RepositoryControlReadError("timeout")
        try:
            returncode = process.wait(timeout=remaining)
        except subprocess.TimeoutExpired as error:
            raise RepositoryControlReadError("timeout") from error
    except OSError as error:
        raise RepositoryControlReadError("not_found_or_inaccessible") from error
    finally:
        if selector is not None:
            selector.close()
        if process is not None:
            if process.poll() is None:
                process.kill()
            process.wait()
            if process.stdout is not None:
                process.stdout.close()
    if returncode not in accepted_statuses:
        raise RepositoryControlReadError("identity_mismatch")
    return returncode, bytes(payload)


def _trusted_git_executable() -> Path:
    selected = shutil.which("git", path=os.defpath)
    if selected is None:
        raise RepositoryControlReadError("not_found_or_inaccessible")
    try:
        executable = Path(selected).resolve(strict=True)
        metadata = executable.stat()
    except OSError as error:
        raise RepositoryControlReadError("not_found_or_inaccessible") from error
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_mode & 0o111 == 0:
        raise RepositoryControlReadError("not_found_or_inaccessible")
    return executable


def _document_digests(documents: list[WorkflowDocument]) -> list[str]:
    document_identities = [
        {"path": path.as_posix(), "sha256": digest}
        for path, _document, digest, _size in sorted(
            documents,
            key=_workflow_document_path,
        )
    ]
    aggregate = hashlib.sha256(
        canonical_repository_control_json_bytes(document_identities)
    ).hexdigest()
    return [f"workflow-set:{aggregate}"]


def _workflow_document_path(document: WorkflowDocument) -> Path:
    return document[0]


def _path_as_posix(path: Path) -> str:
    return path.as_posix()


def _required_string(value: Mapping[str, object], field: str) -> str:
    result = value.get(field)
    if not isinstance(result, str):
        raise TypeError(f"{field} is not a string")
    return result


def _provider_time(value: object) -> datetime:
    if not isinstance(value, str) or not value.endswith("Z"):
        raise ValueError("provider time is not RFC 3339 UTC")
    try:
        result = datetime.fromisoformat(value.removesuffix("Z") + "+00:00")
    except ValueError as error:
        raise ValueError("provider time is not RFC 3339 UTC") from error
    if result.tzinfo != UTC or result.microsecond:
        raise ValueError("provider time must use whole UTC seconds")
    return result


def _projection_digest(value: object) -> str:
    return hashlib.sha256(canonical_repository_control_json_bytes(value)).hexdigest()


def _format_time(value: datetime) -> str:
    return value.astimezone(UTC).isoformat(timespec="seconds").replace("+00:00", "Z")


def _whole_utc(value: datetime, field: str) -> datetime:
    if value.tzinfo is None or value.utcoffset() != timedelta(0) or value.microsecond:
        raise RepositoryObservationCoordinationError(
            f"Repository observation {field} must use whole UTC seconds."
        )
    return value.astimezone(UTC)
