"""Internal foundations for versioned Fork Ops payload contracts.

The current public payloads are intentionally unchanged.  This module gives a
later atomic cutover one shared vocabulary for identifying and validating
artifact families without teaching legacy producers to emit new fields early.
"""

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


@dataclass(frozen=True)
class State:
    """One value in one state dimension, bound to named evidence when available."""

    dimension: StateDimension
    value: str
    evidence_ids: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        object.__setattr__(self, "evidence_ids", tuple(self.evidence_ids))
        if not self.value:
            raise ValueError("state value must not be empty")
        if any(not evidence_id for evidence_id in self.evidence_ids):
            raise ValueError("state evidence ids must not be empty")
        if len(set(self.evidence_ids)) != len(self.evidence_ids):
            raise ValueError("state evidence ids must not contain duplicates")


class OutcomeValue(StrEnum):
    """Canonical operation outcome values accepted for the cutover."""

    COMPLETED = "completed"
    BLOCKED = "blocked"
    REFUSED = "refused"
    FAILED = "failed"


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
