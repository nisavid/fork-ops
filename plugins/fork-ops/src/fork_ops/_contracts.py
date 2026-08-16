"""Internal foundations for canonical Fork Ops payload contracts."""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from enum import StrEnum
from types import MappingProxyType
from typing import cast

from .schema import Diagnostic

_SCHEMA_VERSION_PATTERN = re.compile(r"^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$")


class ArtifactKind(StrEnum):
    """Internal identities for every current independently consumed payload family."""

    FORK_OPS_CONFIG = "fork_ops_config"
    FORK_OPS_CONFIG_SCHEMA = "fork_ops_config_schema"
    PLUGIN_HEALTH_REPORT = "plugin_health_report"
    CONFIG_READ_RESULT = "config_read_result"
    STATUS_REPORT = "status_report"
    CAPABILITY_REPORT = "capability_report"
    CONFIG_INITIALIZATION_RESULT = "config_initialization_result"
    MIGRATION_ASSESSMENT = "migration_assessment"
    EQUIPMENT_MIGRATION_PREFLIGHT = "equipment_migration_preflight"
    EMBEDDED_EQUIPMENT_MIGRATION_PREFLIGHT = (
        "embedded_equipment_migration_preflight"
    )
    MIGRATION_CONFIG_PATCH = "migration_config_patch"
    MIGRATION_PLAN = "migration_plan"
    MIGRATION_DRY_RUN = "migration_dry_run"
    MIGRATION_EXECUTION_RESULT = "migration_execution_result"
    MIGRATION_BLOCKER_EXPLANATION = "migration_blocker_explanation"
    MIGRATION_NARRATIVE = "migration_narrative"
    MIGRATION_REVIEW_ARTIFACT = "migration_review_artifact"
    EQUIPMENT_REVIEW = "equipment_review"
    WORKFLOW_CATALOG = "workflow_catalog"
    WORKFLOW_CONTRACT_SET = "workflow_contract_set"
    WORKFLOW_MIGRATION_INVENTORY = "workflow_migration_inventory"
    SCHEMA_ARTIFACT_REPORT = "schema_artifact_report"
    MCP_HEALTHCHECK = "mcp_healthcheck"
    REPOSITORY_CONTROL_OBSERVATION_CONTRACT = (
        "repository_control_observation_contract"
    )
    REPOSITORY_CONTROL_OBSERVATION = "repository_control_observation"
    REPOSITORY_CONTROL_PROJECTION = "repository_control_projection"
    FIRST_PARTY_SECURITY_RESULT = "first_party_security_result"
    VALIDATION_EVIDENCE_RESULT = "validation_evidence_result"
    VALIDATION_WORKFLOW_AGGREGATE = "validation_workflow_aggregate"
    NORMALIZED_DEPENDENCY_VULNERABILITY_EVIDENCE = (
        "normalized_dependency_vulnerability_evidence"
    )
    DEPENDENCY_SECURITY_RESULT = "dependency_security_result"
    SECURITY_EXCEPTION_CONTRACT = "security_exception_contract"
    SECURITY_EXCEPTION_GUIDE = "security_exception_guide"
    SECURITY_EXCEPTION_INVENTORY = "security_exception_inventory"
    SECURITY_EXCEPTION_LEDGER = "security_exception_ledger"
    SECURITY_EXCEPTION_PRIVATE_PROJECTION = "security_exception_private_projection"
    SECURITY_EXCEPTION_LINEAGE_INDEX_PROJECTION = (
        "security_exception_lineage_index_projection"
    )
    SECURITY_EXCEPTION_AUTHORITY_OBSERVATION = "security_exception_authority_observation"
    SECURITY_EXCEPTION_PUBLIC_COMMAND_REQUEST = (
        "security_exception_public_command_request"
    )
    SECURITY_EXCEPTION_TRANSITION_PROJECTION = "security_exception_transition_projection"
    SECURITY_EXCEPTION_PROVIDER_OBSERVATION = "security_exception_provider_observation"
    SECURITY_EXCEPTION_STRUCTURAL_PROVIDER_OBSERVATION = (
        "security_exception_structural_provider_observation"
    )
    SECURITY_EXCEPTION_RESPONSE_CLOCK_INVENTORY = (
        "security_exception_response_clock_inventory"
    )
    SECURITY_EXCEPTION_LINEAGE_ISSUANCE_PROJECTION = (
        "security_exception_lineage_issuance_projection"
    )
    SECURITY_EXCEPTION_ADVISORY_RECONCILIATION_PROJECTION = (
        "security_exception_advisory_reconciliation_projection"
    )
    SECURITY_EXCEPTION_AUTHORITY_MIGRATION = "security_exception_authority_migration"


@dataclass(frozen=True, order=True)
class SchemaVersion:
    """A strict ``major.minor`` machine-contract version."""

    major: int
    minor: int

    def __post_init__(self) -> None:
        if type(self.major) is not int or type(self.minor) is not int:
            raise TypeError("schema version components must be exact integers")
        if self.major < 0 or self.minor < 0:
            raise ValueError("schema version components must be non-negative")

    @classmethod
    def parse(cls, value: str) -> SchemaVersion:
        match = _SCHEMA_VERSION_PATTERN.fullmatch(value)
        if match is None:
            raise ValueError("schema version must use canonical major.minor form")
        return cls(major=int(match.group(1)), minor=int(match.group(2)))

    def __str__(self) -> str:
        return f"{self.major}.{self.minor}"


@dataclass(frozen=True)
class ArtifactContract:
    """One authoritative identity policy for an inventoried payload family."""

    kind: ArtifactKind
    current_version: SchemaVersion | None
    version_field: str | None
    emitted_artifact_kind: str | None


def _contract(
    kind: ArtifactKind,
    version: str | None = "1.0",
    version_field: str | None = "schema_version",
    *,
    root_identity: bool = True,
) -> ArtifactContract:
    return ArtifactContract(
        kind=kind,
        current_version=SchemaVersion.parse(version) if version is not None else None,
        version_field=version_field,
        emitted_artifact_kind=kind.value if root_identity else None,
    )


_ARTIFACT_CONTRACTS = {
    ArtifactKind.FORK_OPS_CONFIG: _contract(
        ArtifactKind.FORK_OPS_CONFIG,
        "0.1",
        root_identity=False,
    ),
    ArtifactKind.FORK_OPS_CONFIG_SCHEMA: _contract(
        ArtifactKind.FORK_OPS_CONFIG_SCHEMA
    ),
    ArtifactKind.PLUGIN_HEALTH_REPORT: _contract(
        ArtifactKind.PLUGIN_HEALTH_REPORT
    ),
    ArtifactKind.CONFIG_READ_RESULT: _contract(ArtifactKind.CONFIG_READ_RESULT),
    ArtifactKind.STATUS_REPORT: _contract(ArtifactKind.STATUS_REPORT),
    ArtifactKind.CAPABILITY_REPORT: _contract(ArtifactKind.CAPABILITY_REPORT),
    ArtifactKind.CONFIG_INITIALIZATION_RESULT: _contract(
        ArtifactKind.CONFIG_INITIALIZATION_RESULT
    ),
    ArtifactKind.MIGRATION_ASSESSMENT: _contract(
        ArtifactKind.MIGRATION_ASSESSMENT
    ),
    ArtifactKind.EQUIPMENT_MIGRATION_PREFLIGHT: _contract(
        ArtifactKind.EQUIPMENT_MIGRATION_PREFLIGHT
    ),
    ArtifactKind.EMBEDDED_EQUIPMENT_MIGRATION_PREFLIGHT: _contract(
        ArtifactKind.EMBEDDED_EQUIPMENT_MIGRATION_PREFLIGHT
    ),
    ArtifactKind.MIGRATION_CONFIG_PATCH: _contract(
        ArtifactKind.MIGRATION_CONFIG_PATCH
    ),
    ArtifactKind.MIGRATION_PLAN: _contract(ArtifactKind.MIGRATION_PLAN),
    ArtifactKind.MIGRATION_DRY_RUN: _contract(ArtifactKind.MIGRATION_DRY_RUN),
    ArtifactKind.MIGRATION_EXECUTION_RESULT: _contract(
        ArtifactKind.MIGRATION_EXECUTION_RESULT
    ),
    ArtifactKind.MIGRATION_BLOCKER_EXPLANATION: _contract(
        ArtifactKind.MIGRATION_BLOCKER_EXPLANATION
    ),
    ArtifactKind.MIGRATION_NARRATIVE: _contract(ArtifactKind.MIGRATION_NARRATIVE),
    ArtifactKind.MIGRATION_REVIEW_ARTIFACT: _contract(
        ArtifactKind.MIGRATION_REVIEW_ARTIFACT
    ),
    ArtifactKind.EQUIPMENT_REVIEW: _contract(ArtifactKind.EQUIPMENT_REVIEW),
    ArtifactKind.WORKFLOW_CATALOG: _contract(ArtifactKind.WORKFLOW_CATALOG),
    ArtifactKind.WORKFLOW_CONTRACT_SET: _contract(
        ArtifactKind.WORKFLOW_CONTRACT_SET
    ),
    ArtifactKind.WORKFLOW_MIGRATION_INVENTORY: _contract(
        ArtifactKind.WORKFLOW_MIGRATION_INVENTORY
    ),
    ArtifactKind.SCHEMA_ARTIFACT_REPORT: _contract(
        ArtifactKind.SCHEMA_ARTIFACT_REPORT
    ),
    ArtifactKind.MCP_HEALTHCHECK: _contract(ArtifactKind.MCP_HEALTHCHECK),
    ArtifactKind.REPOSITORY_CONTROL_OBSERVATION_CONTRACT: _contract(
        ArtifactKind.REPOSITORY_CONTROL_OBSERVATION_CONTRACT,
        version_field="contract_version",
    ),
    ArtifactKind.REPOSITORY_CONTROL_OBSERVATION: _contract(
        ArtifactKind.REPOSITORY_CONTROL_OBSERVATION
    ),
    ArtifactKind.REPOSITORY_CONTROL_PROJECTION: _contract(
        ArtifactKind.REPOSITORY_CONTROL_PROJECTION,
        version_field=None,
        root_identity=False,
    ),
    ArtifactKind.FIRST_PARTY_SECURITY_RESULT: _contract(
        ArtifactKind.FIRST_PARTY_SECURITY_RESULT
    ),
    ArtifactKind.VALIDATION_EVIDENCE_RESULT: _contract(
        ArtifactKind.VALIDATION_EVIDENCE_RESULT
    ),
    ArtifactKind.VALIDATION_WORKFLOW_AGGREGATE: _contract(
        ArtifactKind.VALIDATION_WORKFLOW_AGGREGATE
    ),
    ArtifactKind.NORMALIZED_DEPENDENCY_VULNERABILITY_EVIDENCE: _contract(
        ArtifactKind.NORMALIZED_DEPENDENCY_VULNERABILITY_EVIDENCE,
        "2.0",
    ),
    ArtifactKind.DEPENDENCY_SECURITY_RESULT: _contract(
        ArtifactKind.DEPENDENCY_SECURITY_RESULT
    ),
    ArtifactKind.SECURITY_EXCEPTION_CONTRACT: _contract(
        ArtifactKind.SECURITY_EXCEPTION_CONTRACT,
        version_field="contract_version",
    ),
    ArtifactKind.SECURITY_EXCEPTION_GUIDE: _contract(
        ArtifactKind.SECURITY_EXCEPTION_GUIDE,
        None,
        version_field=None,
        root_identity=False,
    ),
    ArtifactKind.SECURITY_EXCEPTION_INVENTORY: _contract(
        ArtifactKind.SECURITY_EXCEPTION_INVENTORY,
        version_field="contract_version",
        root_identity=False,
    ),
    ArtifactKind.SECURITY_EXCEPTION_LEDGER: _contract(
        ArtifactKind.SECURITY_EXCEPTION_LEDGER
    ),
    ArtifactKind.SECURITY_EXCEPTION_PRIVATE_PROJECTION: _contract(
        ArtifactKind.SECURITY_EXCEPTION_PRIVATE_PROJECTION
    ),
    ArtifactKind.SECURITY_EXCEPTION_LINEAGE_INDEX_PROJECTION: _contract(
        ArtifactKind.SECURITY_EXCEPTION_LINEAGE_INDEX_PROJECTION
    ),
    ArtifactKind.SECURITY_EXCEPTION_AUTHORITY_OBSERVATION: _contract(
        ArtifactKind.SECURITY_EXCEPTION_AUTHORITY_OBSERVATION
    ),
    ArtifactKind.SECURITY_EXCEPTION_PUBLIC_COMMAND_REQUEST: _contract(
        ArtifactKind.SECURITY_EXCEPTION_PUBLIC_COMMAND_REQUEST,
        version_field=None,
        root_identity=False,
    ),
    ArtifactKind.SECURITY_EXCEPTION_TRANSITION_PROJECTION: _contract(
        ArtifactKind.SECURITY_EXCEPTION_TRANSITION_PROJECTION
    ),
    ArtifactKind.SECURITY_EXCEPTION_PROVIDER_OBSERVATION: _contract(
        ArtifactKind.SECURITY_EXCEPTION_PROVIDER_OBSERVATION
    ),
    ArtifactKind.SECURITY_EXCEPTION_STRUCTURAL_PROVIDER_OBSERVATION: _contract(
        ArtifactKind.SECURITY_EXCEPTION_STRUCTURAL_PROVIDER_OBSERVATION,
        version_field=None,
        root_identity=False,
    ),
    ArtifactKind.SECURITY_EXCEPTION_RESPONSE_CLOCK_INVENTORY: _contract(
        ArtifactKind.SECURITY_EXCEPTION_RESPONSE_CLOCK_INVENTORY
    ),
    ArtifactKind.SECURITY_EXCEPTION_LINEAGE_ISSUANCE_PROJECTION: _contract(
        ArtifactKind.SECURITY_EXCEPTION_LINEAGE_ISSUANCE_PROJECTION
    ),
    ArtifactKind.SECURITY_EXCEPTION_ADVISORY_RECONCILIATION_PROJECTION: _contract(
        ArtifactKind.SECURITY_EXCEPTION_ADVISORY_RECONCILIATION_PROJECTION
    ),
    ArtifactKind.SECURITY_EXCEPTION_AUTHORITY_MIGRATION: _contract(
        ArtifactKind.SECURITY_EXCEPTION_AUTHORITY_MIGRATION
    ),
}
if set(_ARTIFACT_CONTRACTS) != set(ArtifactKind):
    raise RuntimeError("artifact contract registry must explicitly cover every artifact kind")
ARTIFACT_CONTRACTS: Mapping[ArtifactKind, ArtifactContract] = MappingProxyType(
    _ARTIFACT_CONTRACTS
)


def artifact_contract(kind: ArtifactKind) -> ArtifactContract:
    """Return the single identity policy for ``kind``."""

    return ARTIFACT_CONTRACTS[kind]


def current_artifact_version(kind: ArtifactKind) -> SchemaVersion:
    contract = artifact_contract(kind)
    if contract.current_version is None:
        raise ValueError(f"{kind.value} has no machine contract version")
    return contract.current_version


def artifact_identity_diagnostic(
    payload: Mapping[str, object],
    *,
    expected_kind: ArtifactKind,
    path: str,
    label: str,
) -> Diagnostic | None:
    """Validate root identity against the authoritative artifact registry."""

    contract = artifact_contract(expected_kind)
    if contract.emitted_artifact_kind is None or contract.version_field is None:
        raise ValueError(f"{expected_kind.value} does not expose a root artifact identity")
    expected_version = str(current_artifact_version(expected_kind))
    observed_kind = payload.get("artifact_kind")
    observed_version = payload.get(contract.version_field)
    if (
        observed_kind == contract.emitted_artifact_kind
        and observed_version == expected_version
    ):
        return None
    return Diagnostic(
        severity="error",
        code="unsupported_artifact_version",
        message=f"{label} uses an unsupported artifact identity or version.",
        path=path,
        detail={
            "expected_artifact_kind": contract.emitted_artifact_kind,
            f"supported_{contract.version_field}s": [expected_version],
            "observed_artifact_kind": observed_kind,
            f"observed_{contract.version_field}": observed_version,
            "regeneration": f"Regenerate the {label.lower()} with Fork Ops {expected_version}.",
        },
    )


class CompatibilityState(StrEnum):
    """A consumer's finding for one payload version."""

    CURRENT = "current"
    SUPPORTED = "supported"
    UNSUPPORTED = "unsupported"
    LEGACY_UNVERSIONED = "legacy_unversioned"


class LegacyPolicy(StrEnum):
    """What a consumer may do with a legacy unversioned payload."""

    ACCEPT = "accept"
    REFUSE = "refuse"
    IDENTIFY_ONLY = "identify_only"


class ObservedVersionHandling(StrEnum):
    """How a current consumer actually examines a version field."""

    ENFORCED = "enforced"
    PERMISSIVE = "permissive"
    UNINSPECTED = "uninspected"


class ObservedVersionOutcome(StrEnum):
    """Current externally observable result for a missing or unknown version."""

    ACCEPTED = "accepted"
    REPORTED = "reported"
    REFUSED = "refused"


@dataclass(frozen=True)
class ObservedCompatibility:
    """Observed version behavior, independent of emitted and cutover versions."""

    version_handling: ObservedVersionHandling
    missing_version: ObservedVersionOutcome
    unknown_version: ObservedVersionOutcome
    legacy_policy: LegacyPolicy


@dataclass(frozen=True)
class Compatibility:
    """Target supported versions and legacy policy for one cutover boundary."""

    current: SchemaVersion
    supported: tuple[SchemaVersion, ...] = ()
    legacy_policy: LegacyPolicy = LegacyPolicy.REFUSE

    def __post_init__(self) -> None:
        object.__setattr__(self, "supported", tuple(self.supported) or (self.current,))
        if self.current not in self.supported:
            raise ValueError("current schema version must be supported")
        if len(set(self.supported)) != len(self.supported):
            raise ValueError("supported schema versions must not contain duplicates")

    def classify(self, value: str | SchemaVersion | None) -> CompatibilityState:
        if value is None:
            return CompatibilityState.LEGACY_UNVERSIONED
        try:
            version = value if isinstance(value, SchemaVersion) else SchemaVersion.parse(value)
        except ValueError:
            return CompatibilityState.UNSUPPORTED
        if version == self.current:
            return CompatibilityState.CURRENT
        if version in self.supported:
            return CompatibilityState.SUPPORTED
        return CompatibilityState.UNSUPPORTED


@dataclass(frozen=True)
class Evidence:
    """Evidence with immutable canonical detail; integers are accepted, floats refused."""

    id: str
    source: str
    detail: Mapping[str, object] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.id or not self.source:
            raise ValueError("evidence id and source must not be empty")
        object.__setattr__(self, "detail", _freeze_evidence_mapping(self.detail))

    def to_dict(self) -> dict[str, object]:
        return {
            "id": self.id,
            "source": self.source,
            "detail": _thaw_evidence_value(self.detail),
        }


def _freeze_evidence_mapping(value: Mapping[str, object]) -> Mapping[str, object]:
    if any(not isinstance(key, str) for key in value):
        raise ValueError("evidence detail must use canonical string keys")
    return MappingProxyType(
        {
            key: _freeze_evidence_value(value[key])
            for key in sorted(value)
            if isinstance(key, str)
        }
    )


def _freeze_evidence_value(value: object) -> object:
    if value is None or isinstance(value, (bool, int, str)):
        return value
    if isinstance(value, Mapping):
        return _freeze_evidence_mapping(cast(Mapping[str, object], value))
    if isinstance(value, (list, tuple)):
        return tuple(_freeze_evidence_value(item) for item in value)
    raise ValueError("evidence detail contains a non-canonical value")


def _thaw_evidence_value(value: object) -> object:
    if isinstance(value, Mapping):
        return {key: _thaw_evidence_value(item) for key, item in value.items()}
    if isinstance(value, tuple):
        return [_thaw_evidence_value(item) for item in value]
    return value


class StateDimension(StrEnum):
    """Independent state dimensions accepted for the truthful contract."""

    AUTHORITY_READINESS = "authority_readiness"
    WORKFLOW_IMPLEMENTATION = "workflow_implementation"
    SURFACE_HEALTH = "surface_health"
    PLAN_EXECUTABILITY = "plan_executability"
    EXECUTION_OUTCOME = "execution_outcome"
    MUTATION_STATE = "mutation_state"
    ACTIVATION_READINESS = "activation_readiness"
    REPLACEMENT_COVERAGE = "replacement_coverage"
    OPERATIONAL_CONTINUITY = "operational_continuity"


class AuthorityReadinessValue(StrEnum):
    UNASSESSED = "unassessed"
    BLOCKED = "blocked"
    READY = "ready"
    NOT_APPLICABLE = "not_applicable"


class WorkflowImplementationValue(StrEnum):
    IMPLEMENTED = "implemented"
    PARTIAL = "partial"
    PLANNED = "planned"


class SurfaceHealthValue(StrEnum):
    READY = "ready"
    FAILED = "failed"
    UNAVAILABLE = "unavailable"
    UNINSPECTABLE = "uninspectable"


class PlanExecutabilityValue(StrEnum):
    EXECUTABLE = "executable"
    BLOCKED = "blocked"
    NOT_APPLICABLE = "not_applicable"


class MutationStateValue(StrEnum):
    NOT_REQUESTED = "not_requested"
    NOT_STARTED = "not_started"
    APPLIED = "applied"
    ROLLED_BACK = "rolled_back"
    APPLIED_UNVERIFIED = "applied_unverified"


class ActivationReadinessValue(StrEnum):
    UNASSESSED = "unassessed"
    BLOCKED = "blocked"
    READY = "ready"
    NOT_APPLICABLE = "not_applicable"


class ReplacementCoverageValue(StrEnum):
    UNASSESSED = "unassessed"
    BLOCKED = "blocked"
    COVERED = "covered"
    NOT_APPLICABLE = "not_applicable"


class OperationalContinuityValue(StrEnum):
    UNASSESSED = "unassessed"
    AT_RISK = "at_risk"
    CONTINUOUS = "continuous"
    NOT_APPLICABLE = "not_applicable"


class OutcomeValue(StrEnum):
    """Canonical operation outcome values accepted for the cutover."""

    COMPLETED = "completed"
    BLOCKED = "blocked"
    REFUSED = "refused"
    FAILED = "failed"


_STATE_VALUES_BY_DIMENSION = {
    StateDimension.AUTHORITY_READINESS: frozenset(AuthorityReadinessValue),
    StateDimension.WORKFLOW_IMPLEMENTATION: frozenset(WorkflowImplementationValue),
    StateDimension.SURFACE_HEALTH: frozenset(SurfaceHealthValue),
    StateDimension.PLAN_EXECUTABILITY: frozenset(PlanExecutabilityValue),
    StateDimension.EXECUTION_OUTCOME: frozenset(OutcomeValue),
    StateDimension.MUTATION_STATE: frozenset(MutationStateValue),
    StateDimension.ACTIVATION_READINESS: frozenset(ActivationReadinessValue),
    StateDimension.REPLACEMENT_COVERAGE: frozenset(ReplacementCoverageValue),
    StateDimension.OPERATIONAL_CONTINUITY: frozenset(OperationalContinuityValue),
}


def _validate_state_value_registry(
    registry: Mapping[StateDimension, object],
) -> None:
    if set(registry) != set(StateDimension):
        raise RuntimeError(
            "state value registry must explicitly cover every state dimension"
        )


_validate_state_value_registry(_STATE_VALUES_BY_DIMENSION)


@dataclass(frozen=True)
class State:
    """One value in one state dimension, bound to named evidence when available."""

    dimension: StateDimension
    value: str
    subject: str = ""
    evidence_ids: tuple[str, ...] = ()
    derivation_rule: str = ""

    def __post_init__(self) -> None:
        object.__setattr__(self, "value", str(self.value))
        object.__setattr__(self, "evidence_ids", tuple(self.evidence_ids))
        if not self.value:
            raise ValueError("state value must not be empty")
        if self.value not in _STATE_VALUES_BY_DIMENSION[self.dimension]:
            raise ValueError(
                f"{self.value!r} is not valid for state dimension {self.dimension.value}"
            )
        if any(not evidence_id for evidence_id in self.evidence_ids):
            raise ValueError("state evidence ids must not be empty")
        if len(set(self.evidence_ids)) != len(self.evidence_ids):
            raise ValueError("state evidence ids must not contain duplicates")

    def to_dict(self) -> dict[str, object]:
        payload: dict[str, object] = {
            "value": self.value,
            "evidence_ids": list(self.evidence_ids),
        }
        if self.subject:
            payload["subject"] = self.subject
        if self.derivation_rule:
            payload["derivation_rule"] = self.derivation_rule
        return payload


@dataclass(frozen=True)
class Outcome:
    """An operation outcome kept separate from state, diagnostics, and evidence."""

    value: OutcomeValue
    states: tuple[State, ...] = ()
    diagnostics: tuple[Diagnostic, ...] = ()
    evidence: tuple[Evidence, ...] = ()

    def __post_init__(self) -> None:
        object.__setattr__(self, "states", tuple(self.states))
        object.__setattr__(self, "diagnostics", tuple(self.diagnostics))
        object.__setattr__(self, "evidence", tuple(self.evidence))
        dimensions = [state.dimension for state in self.states]
        if len(set(dimensions)) != len(dimensions):
            raise ValueError("outcome states must not repeat a dimension")
        evidence_ids = [item.id for item in self.evidence]
        if len(set(evidence_ids)) != len(evidence_ids):
            raise ValueError("outcome evidence ids must not contain duplicates")
        missing_evidence = {
            evidence_id
            for state in self.states
            for evidence_id in state.evidence_ids
            if evidence_id not in evidence_ids
        }
        if missing_evidence:
            raise ValueError("outcome states reference evidence that is not attached")


def versioned_artifact(
    kind: ArtifactKind,
    fields: Mapping[str, object],
    *,
    schema_version: str | None = None,
) -> dict[str, object]:
    """Attach the canonical root identity to one machine artifact."""

    collisions = {"artifact_kind", "schema_version"}.intersection(fields)
    if collisions:
        raise ValueError("artifact fields must not replace canonical root identity")
    contract = artifact_contract(kind)
    if (
        contract.emitted_artifact_kind is None
        or contract.version_field != "schema_version"
    ):
        raise ValueError(f"{kind.value} is not a schema-versioned artifact root")
    current_version = str(current_artifact_version(kind))
    if schema_version is not None and schema_version != current_version:
        raise ValueError(f"{kind.value} must emit schema version {current_version}")
    return {
        "artifact_kind": contract.emitted_artifact_kind,
        "schema_version": current_version,
        **fields,
    }


def operation_artifact(
    kind: ArtifactKind,
    operation: str,
    fields: Mapping[str, object],
    *,
    outcome: OutcomeValue = OutcomeValue.COMPLETED,
    plan_executability: PlanExecutabilityValue = PlanExecutabilityValue.NOT_APPLICABLE,
    mutation_state: MutationStateValue = MutationStateValue.NOT_REQUESTED,
    schema_version: str | None = None,
) -> dict[str, object]:
    """Build one canonical operation result without redefining domain fields."""

    if not operation:
        raise ValueError("operation must not be empty")
    reserved = {
        "artifact_kind",
        "schema_version",
        "operation",
        "outcome",
        "plan_executability",
        "mutation_state",
    }
    collisions = reserved.intersection(fields)
    if collisions:
        raise ValueError("operation fields must not replace canonical result fields")
    payload = versioned_artifact(
        kind,
        {
            "operation": operation,
            "outcome": outcome.value,
            "plan_executability": plan_executability.value,
            "mutation_state": mutation_state.value,
            **fields,
        },
        schema_version=schema_version,
    )
    payload.setdefault("diagnostics", [])
    payload.setdefault("evidence", [])
    _validate_operation_payload(payload)
    return payload


def _validate_operation_payload(payload: Mapping[str, object]) -> None:
    diagnostics = payload.get("diagnostics")
    evidence = payload.get("evidence")
    if not isinstance(diagnostics, list) or not isinstance(evidence, list):
        raise ValueError("operation diagnostics and evidence must be lists")
    evidence_ids = [
        item.get("id")
        for item in evidence
        if isinstance(item, Mapping) and isinstance(item.get("id"), str)
    ]
    if len(evidence_ids) != len(set(evidence_ids)):
        raise ValueError("operation evidence ids must not contain duplicates")
    missing = _referenced_state_evidence_ids(payload).difference(evidence_ids)
    if missing:
        raise ValueError(
            "operation states reference unattached evidence: " + ", ".join(sorted(missing))
        )


_STATE_FIELD_NAMES = frozenset(
    {
        "activation_readiness",
        "replacement_coverage",
        "operational_continuity",
    }
)
_STATE_CONTAINER_NAMES = frozenset(
    {
        "accounting",
        "capability",
        "equipment_migration_preflight",
        "equipment_review",
        "equipment_review_record",
        "migration_plan",
        "preview",
    }
)


def _canonical_state_payloads(
    value: object,
    *,
    path: tuple[str, ...] = (),
    state_container: bool = True,
) -> tuple[tuple[tuple[str, ...], Mapping[str, object]], ...]:
    """Return explicit canonical state fields without shape-inferring opaque data."""

    if not isinstance(value, Mapping):
        return ()
    states: list[tuple[tuple[str, ...], Mapping[str, object]]] = []
    for key, nested in value.items():
        nested_path = (*path, str(key))
        if (
            state_container
            and key in _STATE_FIELD_NAMES
        ):
            if isinstance(nested, Mapping):
                states.append((nested_path, nested))
            elif isinstance(nested, (list, tuple)):
                states.extend(
                    ((*nested_path, str(index)), item)
                    for index, item in enumerate(nested)
                    if isinstance(item, Mapping)
                )
            continue
        if key in _STATE_CONTAINER_NAMES:
            states.extend(
                _canonical_state_payloads(
                    nested,
                    path=nested_path,
                    state_container=True,
                )
            )
    return tuple(states)


def _state_evidence_ids(value: object) -> set[str]:
    if isinstance(value, Mapping):
        evidence_ids = value.get("evidence_ids")
        return (
            {
                evidence_id
                for evidence_id in evidence_ids
                if isinstance(evidence_id, str)
            }
            if isinstance(evidence_ids, list)
            else set()
        )
    if isinstance(value, (list, tuple)):
        return {
            evidence_id
            for nested in value
            for evidence_id in _state_evidence_ids(nested)
        }
    return set()


def _referenced_state_evidence_ids(
    value: object,
) -> set[str]:
    return {
        evidence_id
        for _, state in _canonical_state_payloads(value)
        for evidence_id in _state_evidence_ids(state)
    }
