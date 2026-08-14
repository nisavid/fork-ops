"""Versioned repository-control observations and first-party evaluation."""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from hmac import compare_digest
from pathlib import Path
from typing import Any, Final, NoReturn, SupportsIndex

from .bounded_io import read_stable_regular_file
from .security_exceptions import (
    SecurityExceptionInventory,
    is_structural_security_exception_inventory,
)

MAX_OBSERVATION_VALIDITY: Final = timedelta(minutes=15)
CONTRACT_FILENAME: Final = "repository-control-observation-contract-1.0.json"
EXPECTED_CONTRACT_SHA256: Final = "10f7dfa6fc8a02cc80fdacf1ff60c500aa64f223e969dbcc2c1100b3c16b595d"
MAX_CONTRACT_BYTES: Final = 1_048_576
CONTROL_SOURCES: Final[dict[str, str]] = {
    "main_ruleset": "github",
    "human_review": "github",
    "stale_approval_dismissal": "github",
    "last_push_approval": "github",
    "resolved_review_threads": "github",
    "validation_required": "github",
    "codeql_required": "github",
    "code_quality_required": "github",
    "copilot_review_required": "github",
    "approved_producer_identities": "github",
    "dependabot_grouped_updates": "package",
    "dependabot_security_updates": "github",
    "dependency_auto_merge_disabled": "github",
    "dependency_review": "package",
    "immutable_action_pins": "package",
    "code_scanning": "github",
    "secret_scanning": "github",
    "push_protection": "github",
    "private_vulnerability_reporting": "github",
    "codeql_alerts": "github",
    "dependabot_alerts": "github",
    "secret_scanning_alerts": "github",
    "public_security_exception_state": "package",
    "private_security_exception_state": "github",
}
FAILURE_CLASSES: Final = (
    "unauthorized",
    "forbidden",
    "not_found_or_inaccessible",
    "rate_limited",
    "timeout",
    "malformed",
    "pagination_incomplete",
    "identity_mismatch",
    "stale",
    "adapter_error",
)
CONTROL_STATUSES: Final = ("passed", "failed", "unavailable")
ALERT_CONTROL_IDS: Final = (
    "codeql_alerts",
    "dependabot_alerts",
    "secret_scanning_alerts",
)
CONTROL_PROJECTION_FIELDS: Final = (
    "control_id",
    "source",
    "status",
    "observed_at",
    "valid_until",
    "projection_sha256",
    "opaque_ids",
    "failure_class",
)

_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_GIT_SHA_RE = re.compile(r"^[0-9a-f]{40}$")
_REPOSITORY_RE = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
_OPAQUE_ID_RE = re.compile(r"^[A-Za-z0-9._:=+-]{1,128}$")


class RepositoryControlObservationError(ValueError):
    """A repository-control observation is malformed or unsupported."""


class RepositoryControlContractError(ValueError):
    """The canonical repository-control observation contract is unavailable."""


@dataclass(frozen=True)
class RepositoryControlContract:
    artifact_kind: str
    contract_version: str
    control_sources: dict[str, str]
    maximum_validity_seconds: int
    data: dict[str, object]
    sha256: str


class RepositoryControlObservation:
    """Immutable normalized repository-control observation 1.0."""

    __slots__ = ("__canonical_payload",)
    __canonical_payload: bytes

    def __new__(cls, *_args: object, **_kwargs: object) -> RepositoryControlObservation:
        raise TypeError("Use parse_repository_control_observation().")

    @classmethod
    def _from_mapping(
        cls,
        value: Mapping[str, object],
    ) -> RepositoryControlObservation:
        instance = object.__new__(cls)
        object.__setattr__(
            instance,
            "_RepositoryControlObservation__canonical_payload",
            canonical_repository_control_json_bytes(value),
        )
        return instance

    def __setattr__(self, _name: str, _value: object) -> None:
        raise AttributeError("RepositoryControlObservation is immutable.")

    def __reduce_ex__(self, _protocol: SupportsIndex, /) -> tuple[Any, ...]:
        raise TypeError("RepositoryControlObservation must cross boundaries as its mapping.")

    def to_dict(self) -> dict[str, object]:
        value = json.loads(self.__canonical_payload)
        if not isinstance(value, dict):
            raise RuntimeError("Canonical repository-control observation is not an object.")
        return value


def parse_repository_control_observation(
    value: Mapping[str, object],
) -> RepositoryControlObservation:
    """Parse the supported repository-control observation contract."""
    if value.get("artifact_kind") != "repository_control_observation":
        raise RepositoryControlObservationError(
            "Unsupported repository control observation artifact kind."
        )
    if value.get("schema_version") != "1.0":
        raise RepositoryControlObservationError(
            "Unsupported repository control observation schema version."
        )
    contract = load_repository_control_contract()
    canonical = canonical_repository_control_json_bytes(value)
    normalized = json.loads(canonical)
    if not isinstance(normalized, dict):
        raise RepositoryControlObservationError(
            "Repository control observation root must be an object."
        )
    _validate_observation(normalized, contract=contract)
    return RepositoryControlObservation._from_mapping(normalized)


def validate_repository_control_projection(
    value: object,
    *,
    expected_control_id: str,
    started_at: datetime,
    completed_at: datetime,
) -> dict[str, object]:
    """Validate one adapter projection at the coordinator trust boundary."""
    if not isinstance(value, dict):
        _invalid("adapter control projection must be an object")
    projection = dict(value)
    control_id = _validate_control(
        projection,
        index=0,
        started_at=started_at,
        completed_at=completed_at,
        control_sources=CONTROL_SOURCES,
    )
    if control_id != expected_control_id:
        _invalid("adapter control projection identity does not match its adapter")
    return projection


def load_repository_control_contract(
    path: str | Path | None = None,
) -> RepositoryControlContract:
    """Load and reverify exact contract 1.0 bytes without retaining cached trust."""
    contract_path = Path(path) if path is not None else Path(__file__).with_name(CONTRACT_FILENAME)
    try:
        payload = read_stable_regular_file(
            contract_path,
            maximum_bytes=MAX_CONTRACT_BYTES,
        )
    except OSError as error:
        raise RepositoryControlContractError(
            "Repository control observation contract 1.0 is unavailable."
        ) from error
    digest = hashlib.sha256(payload).hexdigest()
    if not compare_digest(digest, EXPECTED_CONTRACT_SHA256):
        raise RepositoryControlContractError(
            "Repository control observation contract 1.0 does not match its SHA-256."
        )
    try:
        data = json.loads(payload)
    except json.JSONDecodeError as error:
        raise RepositoryControlContractError(
            "Repository control observation contract 1.0 is not valid JSON."
        ) from error
    if not isinstance(data, dict):
        raise RepositoryControlContractError(
            "Repository control observation contract root must be an object."
        )
    if data.get("artifact_kind") != "repository_control_observation_contract":
        raise RepositoryControlContractError(
            "Unsupported repository control observation contract artifact kind."
        )
    if data.get("contract_version") != "1.0":
        raise RepositoryControlContractError(
            "Unsupported repository control observation contract version."
        )
    source_values = data.get("control_sources")
    if not isinstance(source_values, dict) or not all(
        isinstance(key, str) and isinstance(source, str) for key, source in source_values.items()
    ):
        raise RepositoryControlContractError(
            "Repository control observation contract sources are malformed."
        )
    control_sources = dict(source_values)
    maximum_validity_seconds = data.get("maximum_validity_seconds")
    if isinstance(maximum_validity_seconds, bool) or not isinstance(maximum_validity_seconds, int):
        raise RepositoryControlContractError(
            "Repository control observation validity drifted from the evaluator."
        )
    _validate_contract_sections(data)
    _validate_contract_observation_schema(data)
    return RepositoryControlContract(
        artifact_kind="repository_control_observation_contract",
        contract_version="1.0",
        control_sources=control_sources,
        maximum_validity_seconds=maximum_validity_seconds,
        data=data,
        sha256=digest,
    )


def _validate_contract_sections(data: Mapping[str, object]) -> None:
    expected_sections: tuple[tuple[str, object, str], ...] = (
        (
            "supported_schema_versions",
            ["1.0"],
            "Repository control supported schema versions drifted from the parser.",
        ),
        (
            "control_sources",
            CONTROL_SOURCES,
            "Repository control observation contract sources drifted from the evaluator.",
        ),
        (
            "maximum_validity_seconds",
            int(MAX_OBSERVATION_VALIDITY.total_seconds()),
            "Repository control observation validity drifted from the evaluator.",
        ),
        (
            "failure_classes",
            list(FAILURE_CLASSES),
            "Repository control observation failure classes drifted from the evaluator.",
        ),
        (
            "statuses",
            list(CONTROL_STATUSES),
            "Repository control observation statuses drifted from the evaluator.",
        ),
        (
            "provider_requirements",
            {
                "alert_controls": {
                    "control_ids": list(ALERT_CONTROL_IDS),
                    "complete_pagination_required": True,
                    "pass_requires_open_count": 0,
                },
                "private_security_exception_state": {
                    "complete_pagination_required": True,
                    "semantic_pass_count": 2,
                    "passes_must_be_semantically_identical": True,
                },
                "package_controls": {
                    "candidate_commit_binding": (
                        "exact_candidate_sha_candidate_path_set_scoped_index_worktree_and_blob_"
                        "with_post_read_reverification"
                    ),
                    "git_execution": "trusted_executable_and_hardened_configuration",
                    "local_action_traversal": ("recursive_bounded_exact_candidate_manifests"),
                    "policy_document_budget_bytes": 8_388_608,
                    "policy_parsing": "structural",
                    "secure_materialization_platform": "linux",
                    "workflow_evidence": (
                        "aggregate_sha256_over_sorted_path_and_file_sha256_records"
                    ),
                },
            },
            "Repository control provider requirements drifted from the adapters.",
        ),
        (
            "operation",
            {
                "one_shared_epoch": True,
                "one_shared_deadline": True,
                "fanout_is_read_only": True,
                "late_results_are_ignored": True,
                "unavailable_or_incomplete_is_failed": True,
            },
            "Repository control operation requirements drifted from the coordinator.",
        ),
        (
            "confidentiality",
            {
                "raw_private_responses": "ephemeral",
                "control_projection_fields": list(CONTROL_PROJECTION_FIELDS),
                "free_form_messages": False,
                "raw_response_fields": False,
            },
            ("Repository control confidentiality requirements drifted from the projection."),
        ),
        (
            "evaluation",
            {
                "pure": True,
                "deterministic": True,
                "security_exception_1_0_effect": "inventory_only",
                "failure_conditions": [
                    "required_control_failed",
                    "required_control_unavailable",
                    "observation_stale",
                    "identity_mismatch",
                    "unsupported_version",
                    "incomplete_control_set",
                ],
            },
            "Repository control evaluation requirements drifted from the evaluator.",
        ),
        (
            "canonicalization",
            {
                "encoding": "utf-8",
                "object_keys": "lexicographic-by-unicode-code-point",
                "numbers": "integers-only",
                "json_separators": [",", ":"],
                "digest_algorithm": "sha256",
                "control_digest_projection": ("complete control without projection_sha256"),
                "observation_digest_projection": (
                    "complete observation without observation_sha256"
                ),
            },
            "Repository control canonicalization drifted from the evaluator.",
        ),
    )
    for section, expected, message in expected_sections:
        if data.get(section) != expected:
            raise RepositoryControlContractError(message)


def _validate_contract_observation_schema(data: Mapping[str, object]) -> None:
    observation_schema = data.get("observation_schema")
    if not isinstance(observation_schema, dict):
        raise RepositoryControlContractError(
            "Repository control observation contract schema is malformed."
        )
    properties = observation_schema.get("properties")
    if not isinstance(properties, dict):
        raise RepositoryControlContractError(
            "Repository control observation contract schema is malformed."
        )
    controls = properties.get("controls")
    definitions = data.get("$defs")
    if not isinstance(controls, dict) or not isinstance(definitions, dict):
        raise RepositoryControlContractError(
            "Repository control observation contract schema is malformed."
        )
    control = definitions.get("control")
    if not isinstance(control, dict):
        raise RepositoryControlContractError(
            "Repository control observation contract schema is malformed."
        )
    control_properties = control.get("properties")
    if not isinstance(control_properties, dict):
        raise RepositoryControlContractError(
            "Repository control observation contract schema is malformed."
        )
    control_id = _require_contract_dict(control_properties.get("control_id"))
    source = _require_contract_dict(control_properties.get("source"))
    status = _require_contract_dict(control_properties.get("status"))
    projection_sha256 = _require_contract_dict(control_properties.get("projection_sha256"))
    failure_class = _require_contract_dict(control_properties.get("failure_class"))
    failure_class_condition = control.get("allOf")
    if (
        controls.get("minItems") != len(CONTROL_SOURCES)
        or controls.get("maxItems") != len(CONTROL_SOURCES)
        or control_id.get("enum") != list(CONTROL_SOURCES)
        or source.get("enum") != ["github", "package"]
        or status.get("enum") != list(CONTROL_STATUSES)
        or projection_sha256.get("$ref") != "#/$defs/sha256"
        or failure_class.get("enum") != list(FAILURE_CLASSES)
        or failure_class_condition
        != [
            {
                "if": {
                    "properties": {"status": {"const": "unavailable"}},
                    "required": ["status"],
                },
                "then": {"required": ["failure_class"]},
                "else": {"not": {"required": ["failure_class"]}},
            }
        ]
    ):
        raise RepositoryControlContractError(
            "Repository control observation contract schema drifted from the evaluator."
        )


def _require_contract_dict(value: object) -> dict[str, object]:
    if not isinstance(value, dict):
        raise RepositoryControlContractError(
            "Repository control observation contract schema is malformed."
        )
    return value


def evaluate_first_party_security(
    observation: RepositoryControlObservation,
    security_exception_inventory: SecurityExceptionInventory,
    *,
    evaluated_at: str,
) -> dict[str, object]:
    """Evaluate one normalized repository snapshot without side effects."""
    if not isinstance(observation, RepositoryControlObservation):
        raise RepositoryControlObservationError(
            "First-party evaluation requires a normalized repository control observation."
        )
    payload = observation.to_dict()
    evaluated = _parse_time(evaluated_at, "evaluated_at")
    operation = _require_dict(payload, "operation")
    completed = _parse_time(operation.get("completed_at"), "operation.completed_at")
    controls_value = payload.get("controls")
    if not isinstance(controls_value, list):
        raise RuntimeError("Normalized observation controls are unavailable.")
    controls: list[dict[str, object]] = []
    diagnostics: list[dict[str, str]] = []
    passed_count = 0
    failed_count = 0
    unavailable_count = 0
    for value in controls_value:
        if not isinstance(value, dict):
            raise RuntimeError("Normalized observation contains a malformed control.")
        status = _require_str(value, "status")
        if status == "passed":
            passed_count += 1
        elif status == "failed":
            failed_count += 1
            diagnostics.append(
                _diagnostic(
                    "control.failed",
                    _require_str(value, "control_id"),
                    "The required repository control is not satisfied.",
                )
            )
        else:
            unavailable_count += 1
            diagnostics.append(
                _diagnostic(
                    "control.unavailable",
                    _require_str(value, "control_id"),
                    (
                        "The required repository control is unavailable with failure class "
                        f"{_require_str(value, 'failure_class')}."
                    ),
                )
            )
        valid_until = _parse_time(
            value.get("valid_until"),
            f"{_require_str(value, 'control_id')}.valid_until",
        )
        if evaluated >= valid_until:
            diagnostics.append(
                _diagnostic(
                    "control.stale",
                    _require_str(value, "control_id"),
                    "The required repository control evidence is stale.",
                )
            )
        controls.append(
            {
                "control_id": _require_str(value, "control_id"),
                "status": status,
                "projection_sha256": _require_str(value, "projection_sha256"),
            }
        )
    repository = _require_dict(payload, "repository")
    producer = _require_dict(payload, "producer")
    inventory_is_structural = is_structural_security_exception_inventory(
        security_exception_inventory
    )
    if evaluated < completed:
        diagnostics.append(
            _diagnostic(
                "observation.future",
                "repository-control-observation",
                "The repository control observation completes after evaluation.",
            )
        )
    if not inventory_is_structural:
        diagnostics.append(
            _diagnostic(
                "exceptions.invalid_inventory",
                "security-exception-inventory",
                "Security Exception 1.0 inventory is not a typed structural projection.",
            )
        )
    status = (
        "passed" if not diagnostics and failed_count == 0 and unavailable_count == 0 else "failed"
    )
    return {
        "artifact_kind": "first_party_security_result",
        "schema_version": "1.0",
        "status": status,
        "evaluated_at": _format_time(evaluated),
        "repository": dict(repository),
        "candidate_sha": _require_str(payload, "candidate_sha"),
        "producer": dict(producer),
        "observation_epoch": _require_str(operation, "epoch"),
        "observation_sha256": _require_str(payload, "observation_sha256"),
        "evidence_trust": (
            "normalized_observation" if not diagnostics else "observational_unverified"
        ),
        "assurance_boundary": {
            "security_exception_1_0_gate_effect": False,
            "merge_or_admission_authority": False,
            "baseline_or_release_eligibility": False,
        },
        "security_exception_inventory": {
            "contract_version": (
                security_exception_inventory.contract_version if inventory_is_structural else ""
            ),
            "authority_status": (
                security_exception_inventory.authority_status
                if inventory_is_structural
                else "invalid"
            ),
            "finding_effect": "inventory_only",
            "public_record_count": (
                len(security_exception_inventory.public_records) if inventory_is_structural else 0
            ),
            "private_record_count": (
                len(security_exception_inventory.private_records) if inventory_is_structural else 0
            ),
        },
        "summary": {
            "required_control_count": len(CONTROL_SOURCES),
            "passed_control_count": passed_count,
            "failed_control_count": failed_count,
            "unavailable_control_count": unavailable_count,
        },
        "controls": controls,
        "diagnostics": diagnostics,
    }


def _validate_observation(
    value: dict[str, object],
    *,
    contract: RepositoryControlContract,
) -> None:
    _require_exact_keys(
        value,
        {
            "artifact_kind",
            "schema_version",
            "repository",
            "candidate_sha",
            "producer",
            "operation",
            "controls",
            "observation_sha256",
        },
        "observation",
    )
    repository = _require_dict(value, "repository")
    _require_exact_keys(
        repository,
        {"full_name", "database_id", "node_id", "default_branch"},
        "repository",
    )
    full_name = _require_str(repository, "full_name")
    if not _REPOSITORY_RE.fullmatch(full_name):
        _invalid("repository.full_name is malformed")
    database_id = repository.get("database_id")
    if isinstance(database_id, bool) or not isinstance(database_id, int) or database_id <= 0:
        _invalid("repository.database_id must be a positive integer")
    _validate_opaque_id(_require_str(repository, "node_id"), "repository.node_id")
    default_branch = _require_str(repository, "default_branch")
    if not default_branch or len(default_branch) > 255:
        _invalid("repository.default_branch is malformed")

    candidate_sha = _require_str(value, "candidate_sha")
    if not _GIT_SHA_RE.fullmatch(candidate_sha):
        _invalid("candidate_sha must be a full lowercase Git SHA")

    producer = _require_dict(value, "producer")
    _require_exact_keys(
        producer,
        {"kind", "opaque_id", "workflow_sha", "evaluator_sha256"},
        "producer",
    )
    if _require_str(producer, "kind") not in {"github_app", "github_actions_oidc"}:
        _invalid("producer.kind is unsupported")
    _validate_opaque_id(_require_str(producer, "opaque_id"), "producer.opaque_id")
    if not _GIT_SHA_RE.fullmatch(_require_str(producer, "workflow_sha")):
        _invalid("producer.workflow_sha must be a full lowercase Git SHA")
    if not _SHA256_RE.fullmatch(_require_str(producer, "evaluator_sha256")):
        _invalid("producer.evaluator_sha256 must be SHA-256")

    operation = _require_dict(value, "operation")
    _require_exact_keys(
        operation,
        {"epoch", "started_at", "completed_at", "deadline_at"},
        "operation",
    )
    if not _SHA256_RE.fullmatch(_require_str(operation, "epoch")):
        _invalid("operation.epoch must be SHA-256")
    started_at = _parse_time(operation.get("started_at"), "operation.started_at")
    completed_at = _parse_time(operation.get("completed_at"), "operation.completed_at")
    deadline_at = _parse_time(operation.get("deadline_at"), "operation.deadline_at")
    if not started_at <= completed_at <= deadline_at:
        _invalid("operation times are not ordered")
    if deadline_at - started_at > MAX_OBSERVATION_VALIDITY:
        _invalid("operation deadline exceeds 15 minutes")

    controls = value.get("controls")
    if not isinstance(controls, list):
        _invalid("controls must be an array")
    if len(controls) != len(contract.control_sources):
        _invalid("controls must contain every required control exactly once")
    observed_ids: list[str] = []
    for index, control_value in enumerate(controls):
        if not isinstance(control_value, dict):
            _invalid(f"controls[{index}] must be an object")
        control_id = _validate_control(
            control_value,
            index=index,
            started_at=started_at,
            completed_at=completed_at,
            control_sources=contract.control_sources,
        )
        observed_ids.append(control_id)
    if observed_ids != list(contract.control_sources):
        _invalid("controls must use the closed canonical control order")

    claimed_digest = _require_str(value, "observation_sha256")
    if not _SHA256_RE.fullmatch(claimed_digest):
        _invalid("observation_sha256 must be SHA-256")
    digest_projection = dict(value)
    del digest_projection["observation_sha256"]
    actual_digest = hashlib.sha256(
        canonical_repository_control_json_bytes(digest_projection)
    ).hexdigest()
    if not compare_digest(claimed_digest, actual_digest):
        _invalid("observation_sha256 does not match the canonical observation")


def _validate_control(
    control: dict[str, object],
    *,
    index: int,
    started_at: datetime,
    completed_at: datetime,
    control_sources: Mapping[str, str],
) -> str:
    status = _require_str(control, "status")
    required_keys = {
        "control_id",
        "source",
        "status",
        "observed_at",
        "valid_until",
        "projection_sha256",
        "opaque_ids",
    }
    if status == "unavailable":
        required_keys.add("failure_class")
    _require_exact_keys(control, required_keys, f"controls[{index}]")
    control_id = _require_str(control, "control_id")
    expected_source = control_sources.get(control_id)
    if expected_source is None:
        _invalid(f"controls[{index}].control_id is unsupported")
    if _require_str(control, "source") != expected_source:
        _invalid(f"controls[{index}].source does not own {control_id}")
    if status not in {"passed", "failed", "unavailable"}:
        _invalid(f"controls[{index}].status is unsupported")
    if status == "unavailable":
        if _require_str(control, "failure_class") not in FAILURE_CLASSES:
            _invalid(f"controls[{index}].failure_class is unsupported")
    observed_at = _parse_time(control.get("observed_at"), f"controls[{index}].observed_at")
    valid_until = _parse_time(control.get("valid_until"), f"controls[{index}].valid_until")
    if not started_at <= observed_at <= completed_at:
        _invalid(f"controls[{index}] was observed outside the operation")
    if status == "passed" and valid_until <= completed_at:
        _invalid(f"controls[{index}] is stale at operation completion")
    if valid_until - observed_at > MAX_OBSERVATION_VALIDITY:
        _invalid(f"controls[{index}] validity exceeds 15 minutes")
    claimed_projection_digest = _require_str(control, "projection_sha256")
    if not _SHA256_RE.fullmatch(claimed_projection_digest):
        _invalid(f"controls[{index}].projection_sha256 must be SHA-256")
    digest_projection = dict(control)
    del digest_projection["projection_sha256"]
    actual_projection_digest = hashlib.sha256(
        canonical_repository_control_json_bytes(digest_projection)
    ).hexdigest()
    if not compare_digest(claimed_projection_digest, actual_projection_digest):
        _invalid(f"controls[{index}].projection_sha256 does not match the control")
    opaque_ids = control.get("opaque_ids")
    if not isinstance(opaque_ids, list) or len(opaque_ids) > 32:
        _invalid(f"controls[{index}].opaque_ids must be a bounded array")
    for opaque_id in opaque_ids:
        if not isinstance(opaque_id, str):
            _invalid(f"controls[{index}].opaque_ids must contain strings")
        _validate_opaque_id(opaque_id, f"controls[{index}].opaque_ids")
    if opaque_ids != sorted(set(opaque_ids)):
        _invalid(f"controls[{index}].opaque_ids must be sorted and unique")
    return control_id


def _require_exact_keys(value: Mapping[str, object], keys: set[str], field: str) -> None:
    if set(value) != keys:
        _invalid(f"{field} fields do not match contract 1.0")


def _require_dict(value: Mapping[str, object], field: str) -> dict[str, object]:
    result = value.get(field)
    if not isinstance(result, dict):
        _invalid(f"{field} must be an object")
    return result


def _require_str(value: Mapping[str, object], field: str) -> str:
    result = value.get(field)
    if not isinstance(result, str):
        _invalid(f"{field} must be a string")
    return result


def _validate_opaque_id(value: str, field: str) -> None:
    if not _OPAQUE_ID_RE.fullmatch(value):
        _invalid(f"{field} must be an opaque identifier")


def _parse_time(value: object, field: str) -> datetime:
    if not isinstance(value, str) or not value.endswith("Z"):
        _invalid(f"{field} must be an RFC 3339 UTC time")
    try:
        parsed = datetime.fromisoformat(value.removesuffix("Z") + "+00:00")
    except ValueError:
        _invalid(f"{field} must be an RFC 3339 UTC time")
    if parsed.tzinfo != UTC or parsed.microsecond:
        _invalid(f"{field} must use whole UTC seconds")
    return parsed


def _format_time(value: datetime) -> str:
    return value.astimezone(UTC).isoformat(timespec="seconds").replace("+00:00", "Z")


def _diagnostic(code: str, source: str, message: str) -> dict[str, str]:
    return {"code": code, "source": source, "message": message}


def _invalid(message: str) -> NoReturn:
    raise RepositoryControlObservationError(f"Repository control observation invalid: {message}.")


def canonical_repository_control_json_bytes(value: object) -> bytes:
    """Return the exact JSON bytes used by repository-control digests."""
    try:
        return json.dumps(
            value,
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    except (TypeError, ValueError) as error:
        raise RepositoryControlObservationError(
            "Repository control observation is not canonical JSON data."
        ) from error
