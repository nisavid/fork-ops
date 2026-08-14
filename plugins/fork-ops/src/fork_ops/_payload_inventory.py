"""Complete internal inventory of current Fork Ops payload boundaries.

External identity and observed compatibility describe current truth.
``cutover_compatibility`` names issue #66 policy separately; legacy producers
still emit no internal artifact kind and replay consumers still accept their
current unversioned payloads.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from enum import StrEnum
from typing import TypeVar

from ._contracts import (
    ArtifactKind,
    Compatibility,
    LegacyPolicy,
    ObservedCompatibility,
    ObservedVersionHandling,
    ObservedVersionOutcome,
    SchemaVersion,
)


class Transport(StrEnum):
    PYTHON = "python"
    CLI_JSON = "cli_json"
    CLI_TEXT = "cli_text"
    MCP = "mcp"
    JSON_FILE = "json_file"
    TOML_FILE = "toml_file"
    MARKDOWN_FILE = "markdown_file"
    PACKAGE_RESOURCE = "package_resource"
    GITHUB_ACTIONS_LOG = "github_actions_log"


class ExternalIdentity(StrEnum):
    LEGACY_UNVERSIONED = "legacy_unversioned"
    VERSIONED_ARTIFACT = "versioned_artifact"
    VERSIONED_CONFIG = "versioned_config"
    VERSIONED_CONTRACT = "versioned_contract"
    INTERNAL_TYPED = "internal_typed"


class PersistenceRole(StrEnum):
    PRODUCED = "produced"
    CONSUMED = "consumed"
    BOTH = "both"
    PROPOSED = "proposed"
    CALLER_MANAGED = "caller_managed"


class EndpointRole(StrEnum):
    PRODUCER = "producer"
    CONSUMER = "consumer"
    PERSISTENCE = "persistence"


class ConsumerPurpose(StrEnum):
    VALIDATION = "validation"
    DERIVATION = "derivation"
    DIAGNOSTIC = "diagnostic"
    REPLAY = "replay"
    EXECUTION = "execution"


@dataclass(frozen=True)
class Endpoint:
    id: str
    transport: Transport
    characterized_by: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if not self.id:
            raise ValueError("payload endpoint id must not be empty")


@dataclass(frozen=True)
class ConsumerEndpoint:
    id: str
    transport: Transport
    purpose: ConsumerPurpose
    observed_compatibility: ObservedCompatibility
    cutover_compatibility: Compatibility | None = None
    legacy_regeneration: str | None = None
    characterized_by: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if not self.id:
            raise ValueError("payload consumer id must not be empty")
        if self.purpose in {ConsumerPurpose.REPLAY, ConsumerPurpose.EXECUTION}:
            if (
                self.cutover_compatibility is None
                or self.cutover_compatibility.legacy_policy is not LegacyPolicy.REFUSE
            ):
                raise ValueError(
                    "replay and execution consumers require an explicit refusing cutover"
                )
            if not self.legacy_regeneration:
                raise ValueError("replay and execution consumers must name regeneration")
        elif self.legacy_regeneration is not None:
            raise ValueError("only replay and execution consumers name regeneration")


@dataclass(frozen=True)
class PersistenceEndpoint:
    path: str
    transport: Transport
    role: PersistenceRole
    characterized_by: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if not self.path:
            raise ValueError("payload persistence path must not be empty")


@dataclass(frozen=True)
class PayloadFamily:
    kind: ArtifactKind
    external_identity: ExternalIdentity
    emitted_artifact_kind: str | None
    emitted_version: SchemaVersion | None
    version_field: str | None
    producers: tuple[Endpoint, ...]
    consumers: tuple[ConsumerEndpoint, ...]
    persistence: tuple[PersistenceEndpoint, ...] = ()
    documented_by: tuple[str, ...] = ()
    characterized_by: tuple[str, ...] = ()
    producer_gap: str = ""
    consumer_gap: str = ""
    persistence_gap: str = ""

    def __post_init__(self) -> None:
        is_legacy = self.external_identity is ExternalIdentity.LEGACY_UNVERSIONED
        if is_legacy and (
            self.emitted_artifact_kind is not None
            or self.emitted_version is not None
            or self.version_field is not None
        ):
            raise ValueError("legacy unversioned families cannot claim emitted identity fields")
        if not is_legacy and self.emitted_version is None:
            raise ValueError("versioned families require an emitted version")
        if (
            not is_legacy
            and self.external_identity is not ExternalIdentity.INTERNAL_TYPED
            and self.version_field is None
        ):
            raise ValueError("externally versioned families require a version field")
        if (
            self.external_identity is ExternalIdentity.VERSIONED_ARTIFACT
            and self.emitted_artifact_kind is None
        ):
            raise ValueError("versioned artifacts require an emitted artifact kind")
        if not self.producers and not self.producer_gap:
            raise ValueError("payload families require a producer or an explicit producer gap")
        if self.producers and self.producer_gap:
            raise ValueError("payload production cannot be both inventoried and unavailable")
        if not self.consumers and not self.consumer_gap:
            raise ValueError("payload families require a consumer or an explicit consumer gap")
        if self.consumers and self.consumer_gap:
            raise ValueError("payload consumption cannot be both inventoried and unavailable")
        if not self.persistence and not self.persistence_gap:
            raise ValueError(
                "payload families require a persistence endpoint or an explicit persistence gap"
            )
        if len({(endpoint.id, endpoint.transport) for endpoint in self.producers}) != len(
            self.producers
        ):
            raise ValueError("payload producer endpoints must not contain duplicates")
        if len({(endpoint.id, endpoint.transport) for endpoint in self.consumers}) != len(
            self.consumers
        ):
            raise ValueError("payload consumer endpoints must not contain duplicates")
        for label, endpoints in (("producer", self.producers), ("consumer", self.consumers)):
            if any(not endpoint.characterized_by for endpoint in endpoints):
                raise ValueError(f"payload {label} endpoints require exact characterization")
        if len(
            {
                (endpoint.path, endpoint.transport, endpoint.role)
                for endpoint in self.persistence
            }
        ) != len(self.persistence):
            raise ValueError("payload persistence endpoints must not contain duplicates")
        if self.persistence and self.persistence_gap:
            raise ValueError("payload persistence cannot be both inventoried and unavailable")
        if any(not endpoint.characterized_by for endpoint in self.persistence):
            raise ValueError("payload persistence endpoints require exact characterization")
        if not self.documented_by or len(set(self.documented_by)) != len(
            self.documented_by
        ):
            raise ValueError("payload documentation references must be non-empty and unique")
        if not self.characterized_by or len(set(self.characterized_by)) != len(
            self.characterized_by
        ):
            raise ValueError("payload test references must be non-empty and unique")
        if is_legacy:
            for consumer in self.consumers:
                if (
                    consumer.purpose is ConsumerPurpose.DIAGNOSTIC
                    and consumer.observed_compatibility.legacy_policy
                    is not LegacyPolicy.IDENTIFY_ONLY
                ):
                    raise ValueError("legacy diagnostic consumers must identify legacy payloads")


def _nodes(value: str | tuple[str, ...]) -> tuple[str, ...]:
    return (value,) if isinstance(value, str) else value


_CharacterizationKey = TypeVar("_CharacterizationKey")


def _required_characterization(
    table: Mapping[_CharacterizationKey, tuple[str, ...]],
    key: _CharacterizationKey,
    *,
    label: str,
) -> tuple[str, ...]:
    try:
        return table[key]
    except KeyError as error:
        raise RuntimeError(
            f"payload inventory is missing {label} characterization for {key!r}"
        ) from error


def _endpoint(
    id: str,
    transport: Transport = Transport.PYTHON,
    *,
    characterized_by: str | tuple[str, ...] | None = None,
) -> Endpoint:
    nodes = (
        _required_characterization(
            _PRODUCER_CHARACTERIZATION,
            (id, transport),
            label="producer",
        )
        if characterized_by is None
        else _nodes(characterized_by)
    )
    return Endpoint(id=id, transport=transport, characterized_by=nodes)


def _consumer(
    id: str,
    *,
    transport: Transport = Transport.PYTHON,
    purpose: ConsumerPurpose = ConsumerPurpose.VALIDATION,
    observed_version_handling: ObservedVersionHandling = (
        ObservedVersionHandling.UNINSPECTED
    ),
    missing_version: ObservedVersionOutcome = ObservedVersionOutcome.ACCEPTED,
    unknown_version: ObservedVersionOutcome = ObservedVersionOutcome.ACCEPTED,
    legacy_policy: LegacyPolicy = LegacyPolicy.ACCEPT,
    cutover_version: str | None = None,
    cutover_legacy_policy: LegacyPolicy = LegacyPolicy.REFUSE,
    legacy_regeneration: str | None = None,
    characterized_by: str | tuple[str, ...] | None = None,
) -> ConsumerEndpoint:
    cutover = (
        Compatibility(
            current=SchemaVersion.parse(cutover_version),
            legacy_policy=cutover_legacy_policy,
        )
        if cutover_version is not None
        else None
    )
    return ConsumerEndpoint(
        id=id,
        transport=transport,
        purpose=purpose,
        observed_compatibility=ObservedCompatibility(
            version_handling=observed_version_handling,
            missing_version=missing_version,
            unknown_version=unknown_version,
            legacy_policy=legacy_policy,
        ),
        cutover_compatibility=cutover,
        legacy_regeneration=legacy_regeneration,
        characterized_by=(
            _required_characterization(
                _CONSUMER_CHARACTERIZATION,
                (id, transport),
                label="consumer",
            )
            if characterized_by is None
            else _nodes(characterized_by)
        ),
    )


def _enforced_consumer(
    id: str,
    *,
    version: str,
    transport: Transport = Transport.PYTHON,
    purpose: ConsumerPurpose = ConsumerPurpose.VALIDATION,
    legacy_regeneration: str | None = None,
    characterized_by: str | tuple[str, ...] | None = None,
) -> ConsumerEndpoint:
    return _consumer(
        id,
        transport=transport,
        purpose=purpose,
        observed_version_handling=ObservedVersionHandling.ENFORCED,
        missing_version=ObservedVersionOutcome.REFUSED,
        unknown_version=ObservedVersionOutcome.REFUSED,
        legacy_policy=LegacyPolicy.REFUSE,
        cutover_version=version,
        legacy_regeneration=legacy_regeneration,
        characterized_by=characterized_by,
    )


def _persistence(
    path: str,
    transport: Transport,
    role: PersistenceRole,
    *,
    characterized_by: str | tuple[str, ...] | None = None,
) -> PersistenceEndpoint:
    return PersistenceEndpoint(
        path=path,
        transport=transport,
        role=role,
        characterized_by=(
            _required_characterization(
                _PERSISTENCE_CHARACTERIZATION,
                (path, transport, role),
                label="persistence",
            )
            if characterized_by is None
            else _nodes(characterized_by)
        ),
    )


def _unique(values: tuple[str, ...]) -> tuple[str, ...]:
    return tuple(dict.fromkeys(values))


def _legacy(
    kind: ArtifactKind,
    *,
    producers: tuple[Endpoint, ...],
    consumers: tuple[ConsumerEndpoint, ...],
    persistence: tuple[PersistenceEndpoint, ...] = (),
    docs: tuple[str, ...],
    tests: tuple[str, ...],
    consumer_gap: str = "",
    persistence_gap: str = "",
) -> PayloadFamily:
    endpoint_tests = tuple(
        node
        for endpoint in (*producers, *consumers, *persistence)
        for node in endpoint.characterized_by
    )
    return PayloadFamily(
        kind=kind,
        external_identity=ExternalIdentity.LEGACY_UNVERSIONED,
        emitted_artifact_kind=None,
        emitted_version=None,
        version_field=None,
        producers=producers,
        consumers=consumers,
        persistence=persistence,
        documented_by=_unique(docs),
        characterized_by=_unique(tests + endpoint_tests),
        consumer_gap=consumer_gap,
        persistence_gap=persistence_gap,
    )


def _versioned(
    kind: ArtifactKind,
    version: str,
    *,
    producers: tuple[Endpoint, ...],
    consumers: tuple[ConsumerEndpoint, ...],
    persistence: tuple[PersistenceEndpoint, ...] = (),
    docs: tuple[str, ...],
    tests: tuple[str, ...],
    external_identity: ExternalIdentity = ExternalIdentity.VERSIONED_ARTIFACT,
    version_field: str | None = "schema_version",
    emitted_artifact_kind: str | None = None,
    producer_gap: str = "",
    consumer_gap: str = "",
    persistence_gap: str = "",
) -> PayloadFamily:
    parsed_version = SchemaVersion.parse(version)
    endpoint_tests = tuple(
        node
        for endpoint in (*producers, *consumers, *persistence)
        for node in endpoint.characterized_by
    )
    return PayloadFamily(
        kind=kind,
        external_identity=external_identity,
        emitted_artifact_kind=(
            kind.value
            if emitted_artifact_kind is None
            and external_identity is ExternalIdentity.VERSIONED_ARTIFACT
            else emitted_artifact_kind
        ),
        emitted_version=parsed_version,
        version_field=version_field,
        producers=producers,
        consumers=consumers,
        persistence=persistence,
        documented_by=_unique(docs),
        characterized_by=_unique(tests + endpoint_tests),
        producer_gap=producer_gap,
        consumer_gap=consumer_gap,
        persistence_gap=persistence_gap,
    )


_LANDING_GUIDES = ("README.md", "plugins/fork-ops/README.md")
_OPERATION_GUIDE = _LANDING_GUIDES + (
    "plugins/fork-ops/docs/operation-guide.md",
    "specs/fork-ops-foundation/capability-card.md",
    "specs/fork-ops-foundation/domain-map.md",
)
_MIGRATION_GUIDE = _LANDING_GUIDES + (
    "docs/agents/fork-ops-32-equipment-migration-case-study.md",
    "plugins/fork-ops/docs/migration.md",
    "specs/fork-ops-foundation/interface-decision-record.md",
    "specs/fork-ops-foundation/migration-pressure-cases.md",
)
_CONFIG_GUIDE = _LANDING_GUIDES + (
    "plugins/fork-ops/docs/config-schema.md",
    "specs/fork-ops-foundation/config-model.md",
    "specs/fork-ops-foundation/examples/track-aware.toml",
)
_SECURITY_GUIDE = ("SECURITY.md", "docs/agents/security-exceptions.md")
_REPOSITORY_CONTROL_GUIDE = (
    "plugins/fork-ops/README.md",
    "plugins/fork-ops/docs/repository-controls.md",
)
_VALIDATION_GUIDE = ("docs/agents/validation-evidence.md",)
_PYTHON_TEST = (
    "plugins/fork-ops/tests/test_contracts.py::"
    "test_python_payload_endpoints_execute_with_exact_role_attribution",
)
_CORE_TEST = _PYTHON_TEST
_CLI_TEST = (
    "plugins/fork-ops/tests/test_contracts.py::"
    "test_all_cli_payload_modes_execute_with_exact_family_attribution",
)
_MCP_TEST = (
    "plugins/fork-ops/tests/test_contracts.py::"
    "test_real_mcp_stdio_executes_every_payload_tool_with_exact_family_attribution",
)
_PERSISTENCE_TEST = (
    "plugins/fork-ops/tests/test_contracts.py::"
    "test_legacy_replay_and_persisted_payloads_remain_accepted_and_exact",
)
_SECURITY_TEST = (
    "plugins/fork-ops/tests/test_contracts.py::"
    "test_typed_security_exception_inventory_roundtrips_to_dependency_evaluation",
)
_SECURITY_CONTRACT_TEST = (
    "plugins/fork-ops/tests/test_security_exceptions.py::"
    "test_packaged_security_exception_contract_is_verified",
)
_SECURITY_LEDGER_TEST = (
    "plugins/fork-ops/tests/test_security_exceptions.py::"
    "test_empty_checked_in_public_ledger_validates_with_no_bootstrap_path",
)
_SECURITY_INVENTORY_TEST = (
    "plugins/fork-ops/tests/test_security_exceptions.py::"
    "test_empty_public_and_private_projections_form_a_typed_inventory",
)
_SECURITY_COMMAND_TEST = (
    "plugins/fork-ops/tests/test_security_exceptions.py::"
    "test_public_command_parser_enforces_exact_six_and_eight_token_grammars",
)
_SECURITY_GUIDE_TEST = (
    "plugins/fork-ops/tests/test_security_exceptions.py::"
    "test_generated_guide_contract_hash_and_golden_vectors_cannot_drift",
)
_SECURITY_TRANSITION_TEST = (
    "plugins/fork-ops/tests/test_security_exceptions.py::"
    "test_transition_projection_never_claims_authenticated_persistence",
)
_SECURITY_PROVIDER_TEST = (
    "plugins/fork-ops/tests/test_security_exceptions.py::"
    "test_provider_observation_requires_two_complete_identical_structural_passes",
)
_SECURITY_RESPONSE_CLOCK_TEST = (
    "plugins/fork-ops/tests/test_security_exceptions.py::"
    "test_response_clock_zero_is_positive_only_for_complete_empty_inventory",
)
_SECURITY_ISSUANCE_TEST = (
    "plugins/fork-ops/tests/test_security_exceptions.py::"
    "test_new_lineage_and_advisory_revision_projections_are_pure_and_exact",
)
_DEPENDENCY_TEST = (
    "plugins/fork-ops/tests/test_contracts.py::"
    "test_both_normalized_dependency_evidence_producers_emit_the_same_family",
)
_DEPENDENCY_EVALUATION_TEST = (
    "plugins/fork-ops/tests/test_dependency_security.py::"
    "DependencySecurityTests::"
    "test_exact_current_complete_observations_produce_canonical_pass",
)
_VALIDATION_TEST = (
    "plugins/fork-ops/tests/test_validation_evidence.py::"
    "ValidationEvidenceEntrypointTests::test_locked_source_emits_reusable_terminal_evidence",
)
_VALIDATION_IDENTITY_TEST = (
    "plugins/fork-ops/tests/test_validation_evidence.py::"
    "ValidationEvidenceEntrypointTests::"
    "test_installed_mode_refuses_candidate_identity_mismatch",
)
_VALIDATION_RELEASE_TEST = (
    "plugins/fork-ops/tests/test_validation_evidence.py::"
    "ValidationEvidenceEntrypointTests::"
    "test_release_trust_binds_api_and_producer_before_wheel_execution",
)
_WORKFLOW_AGGREGATE_TEST = (
    "plugins/fork-ops/tests/test_contracts.py::"
    "test_workflow_aggregate_variants_remain_versioned_and_shape_compatible",
)
_AUTHORITY_MIGRATION_TEST = (
    "plugins/fork-ops/tests/test_contracts.py::"
    "test_authority_migration_projection_is_shape_checked_then_refused",
)
_VERSION_BEHAVIOR_TEST = (
    "plugins/fork-ops/tests/test_contracts.py::"
    "test_config_and_equipment_version_behavior_is_characterized_per_consumer",
)
_SECURITY_INVENTORY_PREDICATE_TEST = (
    "plugins/fork-ops/tests/test_security_exceptions.py::"
    "test_caller_asserted_authority_can_only_form_a_structural_inventory",
)
_REPOSITORY_CONTROL_CONTRACT_TEST = (
    "plugins/fork-ops/tests/test_repository_controls.py::"
    "test_packaged_repository_control_contract_is_verified",
)
_REPOSITORY_CONTROL_OBSERVATION_TEST = (
    "plugins/fork-ops/tests/test_repository_controls.py::"
    "test_complete_repository_control_observation_is_immutable_and_round_trips",
)
_REPOSITORY_CONTROL_COORDINATION_TEST = (
    "plugins/fork-ops/tests/test_repository_control_adapters.py::"
    "test_coordinator_binds_every_control_to_one_epoch_and_deadline",
)
_REPOSITORY_CONTROL_FAILURE_TEST = (
    "plugins/fork-ops/tests/test_repository_control_adapters.py::"
    "test_adapter_failures_are_closed_and_confidentiality_safe",
)
_FIRST_PARTY_SECURITY_RESULT_TEST = (
    "plugins/fork-ops/tests/test_repository_controls.py::"
    "test_complete_current_controls_produce_a_deterministic_first_party_pass",
)
_REPOSITORY_CONTROL_PUBLIC_LEDGER_TEST = (
    "plugins/fork-ops/tests/test_repository_control_adapters.py::"
    "test_package_adapters_observe_dependency_workflow_and_public_ledger_state",
)


def _for_ids(
    ids: tuple[str, ...],
    transport: Transport,
    node: tuple[str, ...],
) -> dict[tuple[str, Transport], tuple[str, ...]]:
    return {(id, transport): node for id in ids}


_PRODUCER_CHARACTERIZATION: dict[
    tuple[str, Transport], tuple[str, ...]
] = {
    **_for_ids(
        (
            "fork_ops.core:create_initial_config_text",
            "fork_ops.core:propose_migration_config_patch",
            "fork_ops.core:schema_json",
            "fork_ops.core:build_plugin_health_report",
            "fork_ops.core:build_status_report",
            "fork_ops.core:capability_report",
            "fork_ops.core:initialize_config",
            "fork_ops.core:assess_migration",
            "fork_ops.core:build_equipment_migration_preflight",
            "fork_ops.core:_equipment_migration_preflight",
            "fork_ops.core:build_equipment_migration_preflight(equipment_review_record)",
            "fork_ops.core:generate_migration_plan",
            "fork_ops.core:dry_run_migration(plan=None)",
            "fork_ops.core:dry_run_migration(plan=)",
            "fork_ops.core:dry_run_migration_plan",
            "fork_ops.core:execute_migration(plan=None)",
            "fork_ops.core:execute_migration(plan=)",
            "fork_ops.core:execute_migration_plan",
            "fork_ops.core:explain_migration_blocker",
            "fork_ops:render_migration_narrative(workflow_output)",
            "fork_ops.core:_migration_review_artifact",
            "fork_ops.core:_equipment_review_record",
            "fork_ops.workflow_catalog:workflow_catalog",
            "fork_ops.workflow_catalog:workflow_contracts",
            "fork_ops.core:build_workflow_migration_inventory",
            "fork_ops.core:schema_artifact_report",
            "fork_ops.mcp_server:mcp_healthcheck",
        ),
        Transport.PYTHON,
        _PYTHON_TEST,
    ),
    **_for_ids(
        (
            "fork-ops config init (without --write)",
            "fork-ops config show [--format toml]",
            "fork-ops migration propose-config --format toml",
            "fork-ops capability report (without --json)",
        ),
        Transport.CLI_TEXT,
        _CLI_TEST,
    ),
    **_for_ids(
        (
            "fork-ops config show --format json|--normalized",
            "fork-ops schema print",
            "fork-ops config validate --json",
            "fork-ops capability report --json",
            "fork-ops migration assess (without --with-proposed-config)",
            "fork-ops migration assess --with-proposed-config",
            "fork-ops migration preflight",
            "fork-ops migration propose-config --format json",
            "fork-ops migration plan",
            "fork-ops migration dry-run (without --plan)",
            "fork-ops migration dry-run --plan",
            "fork-ops migration execute (without --plan)",
            "fork-ops migration execute --plan",
            "fork-ops migration explain-blocker --input",
            "fork-ops workflow catalog",
            "fork-ops workflow inventory",
            "fork-ops plugin health",
            "fork-ops schema check --json",
            "fork-ops-mcp --health-check",
        ),
        Transport.CLI_JSON,
        _CLI_TEST,
    ),
    **_for_ids(
        (
            "fork_ops_config_read(normalized=True)",
            "fork_ops_plugin_health",
            "fork_ops_config_read(normalized=False)",
            "fork_ops_config_validate",
            "fork_ops_capability_report",
            "fork_ops_migration_assessment",
            "fork_ops_equipment_migration_preflight",
            "fork_ops_migration_config_patch",
            "fork_ops_migration_plan",
            "fork_ops_migration_dry_run(migration_plan=None)",
            "fork_ops_migration_dry_run(migration_plan=)",
            "fork_ops_migration_execute(migration_plan=None)",
            "fork_ops_migration_execute(migration_plan=)",
            "fork_ops_migration_blocker_resolution(workflow_output=)",
            "fork_ops_schema",
            "fork_ops_workflow_catalog",
            "fork_ops_workflow_migration_inventory",
        ),
        Transport.MCP,
        _MCP_TEST,
    ),
    ("scripts/produce_validation_evidence.py:main", Transport.PYTHON): _VALIDATION_TEST,
    (
        "fork_ops.dependency_security:collect_uv_audit_evidence",
        Transport.PYTHON,
    ): _DEPENDENCY_TEST,
    (
        "scripts/produce_validation_evidence.py:_dependency_audit_matrix_check",
        Transport.PYTHON,
    ): _DEPENDENCY_TEST,
    (
        "fork_ops.dependency_security:evaluate_dependency_security",
        Transport.PYTHON,
    ): _DEPENDENCY_EVALUATION_TEST,
    ("canonical checked-in contract", Transport.PACKAGE_RESOURCE): (
        _SECURITY_CONTRACT_TEST
    ),
    (
        "scripts/security_exception_projections.py:_render_guide",
        Transport.PYTHON,
    ): _SECURITY_GUIDE_TEST,
    ("checked-in public governance ledger", Transport.TOML_FILE): (
        _SECURITY_LEDGER_TEST
    ),
    (
        "fork_ops.security_exceptions:validate_security_exception_inventory",
        Transport.PYTHON,
    ): _SECURITY_INVENTORY_TEST,
    (
        "fork_ops.security_exceptions:parse_public_security_exception_command",
        Transport.PYTHON,
    ): _SECURITY_TRANSITION_TEST,
    (
        "fork_ops.security_exceptions:validate_provider_observation_envelope",
        Transport.PYTHON,
    ): _SECURITY_RESPONSE_CLOCK_TEST,
    (
        ".github/workflows/validation.yml:validation",
        Transport.GITHUB_ACTIONS_LOG,
    ): _WORKFLOW_AGGREGATE_TEST,
    (
        ".github/workflows/release-validation.yml:validation",
        Transport.GITHUB_ACTIONS_LOG,
    ): _WORKFLOW_AGGREGATE_TEST,
    (
        "canonical packaged repository-control observation contract",
        Transport.PACKAGE_RESOURCE,
    ): _REPOSITORY_CONTROL_CONTRACT_TEST,
    (
        "fork_ops.repository_control_adapters:collect_repository_control_observation",
        Transport.PYTHON,
    ): _REPOSITORY_CONTROL_COORDINATION_TEST,
    (
        "fork_ops.repository_control_adapters:GitHubControlAdapter.observe",
        Transport.PYTHON,
    ): _REPOSITORY_CONTROL_COORDINATION_TEST,
    (
        "fork_ops.repository_control_adapters:PackageControlAdapter.observe",
        Transport.PYTHON,
    ): _REPOSITORY_CONTROL_COORDINATION_TEST,
    (
        "fork_ops.repository_control_adapters:_unavailable_projection",
        Transport.PYTHON,
    ): _REPOSITORY_CONTROL_FAILURE_TEST,
    (
        "fork_ops.repository_controls:evaluate_first_party_security",
        Transport.PYTHON,
    ): _FIRST_PARTY_SECURITY_RESULT_TEST,
}


_CONSUMER_CHARACTERIZATION: dict[
    tuple[str, Transport], tuple[str, ...]
] = {
    **_for_ids(
        (
            "fork_ops.core:load_config",
            "fork_ops.core:build_status_report",
            "fork_ops.schema:schema_diagnostics",
            "fork_ops.core:schema_artifact_report",
            "fork_ops.core:generate_migration_plan",
            "fork_ops.core:assess_migration(include_proposed_config_patch=True)",
            "fork_ops.core:build_equipment_migration_preflight(proposed_config_patch)",
            "fork_ops.core:build_equipment_migration_preflight(workflow_inventory)",
            "fork_ops.core:build_equipment_migration_preflight(embedded_preflight)",
            "fork_ops.core:generate_migration_plan(embedded_preflight)",
            "fork_ops.core:_equipment_review_record_report",
            "fork_ops:explain_migration_blocker(workflow_output)",
            "fork_ops:render_migration_narrative(workflow_output)",
            "fork_ops.core:build_workflow_migration_inventory",
            "fork_ops.core:explain_migration_blocker via _workflow_contract_dict",
            "fork_ops.core:_cli_execution_check",
            "fork_ops.core:build_plugin_health_report",
        ),
        Transport.PYTHON,
        _PYTHON_TEST,
    ),
    **_for_ids(
        (
            "fork_ops.core:dry_run_migration(plan=)",
            "fork_ops.core:dry_run_migration_plan(plan)",
            "fork_ops.core:execute_migration(plan=)",
            "fork_ops.core:execute_migration_plan(plan)",
        ),
        Transport.PYTHON,
        _PERSISTENCE_TEST,
    ),
    **_for_ids(
        (
            "fork-ops config show [--format toml]",
            "fork-ops config validate (without --json)",
            "fork-ops capability report (without --json)",
            "fork_ops.cli:cmd_config_init(--write)",
            "fork-ops schema check (without --json)",
        ),
        Transport.CLI_TEXT,
        _CLI_TEST,
    ),
    **_for_ids(
        (
            "fork-ops config show --format json|--normalized",
            "fork-ops config validate --json",
            "fork-ops migration dry-run --plan",
            "fork-ops migration execute --plan",
            "fork-ops migration explain-blocker --input",
            "fork-ops schema check --json",
        ),
        Transport.CLI_JSON,
        _CLI_TEST,
    ),
    **_for_ids(
        (
            "fork_ops_config_read(normalized=False)",
            "fork_ops_config_read(normalized=True)",
            "fork_ops_config_validate",
            "fork_ops_migration_dry_run(migration_plan=)",
            "fork_ops_migration_execute(migration_plan=)",
            "fork_ops_migration_blocker_resolution(workflow_output=)",
        ),
        Transport.MCP,
        _MCP_TEST,
    ),
    (
        "scripts/produce_validation_evidence.py:_workflow_catalog_check",
        Transport.PYTHON,
    ): _VALIDATION_TEST,
    (
        "scripts/produce_validation_evidence.py:_candidate_identity_check",
        Transport.PYTHON,
    ): _VALIDATION_IDENTITY_TEST + _VALIDATION_RELEASE_TEST,
    (
        "scripts/produce_validation_evidence.py:_release_trust_check",
        Transport.PYTHON,
    ): _VALIDATION_RELEASE_TEST,
    (
        "scripts/produce_validation_evidence.py:_release_preflight_evidence_check",
        Transport.PYTHON,
    ): _VALIDATION_RELEASE_TEST,
    (
        "fork_ops.dependency_security:evaluate_dependency_security",
        Transport.PYTHON,
    ): _DEPENDENCY_EVALUATION_TEST,
    (
        "fork_ops.security_exceptions:load_security_exception_contract",
        Transport.PYTHON,
    ): _SECURITY_CONTRACT_TEST,
    (
        "scripts/security_exception_projections.py:main",
        Transport.PYTHON,
    ): _SECURITY_GUIDE_TEST,
    (
        "scripts/security_exception_projections.py:main(--check)",
        Transport.PYTHON,
    ): _SECURITY_GUIDE_TEST,
    (
        "fork_ops.security_exceptions:validate_security_exception_inventory(public_ledger=)",
        Transport.PYTHON,
    ): _SECURITY_LEDGER_TEST,
    (
        "fork_ops.security_exceptions:validate_security_exception_inventory(private_projection=)",
        Transport.PYTHON,
    ): _SECURITY_INVENTORY_TEST,
    (
        "fork_ops.security_exceptions:validate_security_exception_inventory(lineage_index=)",
        Transport.PYTHON,
    ): _SECURITY_INVENTORY_TEST,
    (
        "fork_ops.security_exceptions:validate_security_exception_inventory(authority_observation=)",
        Transport.PYTHON,
    ): _SECURITY_INVENTORY_TEST,
    (
        "fork_ops.security_exceptions:parse_public_security_exception_command(current_inventory=)",
        Transport.PYTHON,
    ): _SECURITY_COMMAND_TEST,
    (
        "fork_ops.security_exceptions:validate_public_transition_projection(current_inventory=)",
        Transport.PYTHON,
    ): _SECURITY_TRANSITION_TEST,
    (
        "fork_ops.security_exceptions:validate_lineage_issuance_projection(current_inventory=)",
        Transport.PYTHON,
    ): _SECURITY_ISSUANCE_TEST,
    (
        "fork_ops.security_exceptions:validate_advisory_reconciliation_projection(current_inventory=)",
        Transport.PYTHON,
    ): _SECURITY_ISSUANCE_TEST,
    (
        "fork_ops.security_exceptions:validate_response_clock_inventory(current_inventory=)",
        Transport.PYTHON,
    ): _SECURITY_RESPONSE_CLOCK_TEST,
    (
        "fork_ops.security_exceptions:validate_public_transition_projection",
        Transport.PYTHON,
    ): _SECURITY_TRANSITION_TEST,
    (
        "fork_ops.security_exceptions:validate_provider_observation_envelope",
        Transport.PYTHON,
    ): _SECURITY_PROVIDER_TEST,
    (
        "fork_ops.security_exceptions:validate_response_clock_inventory",
        Transport.PYTHON,
    ): _SECURITY_RESPONSE_CLOCK_TEST,
    (
        "fork_ops.security_exceptions:validate_lineage_issuance_projection",
        Transport.PYTHON,
    ): _SECURITY_ISSUANCE_TEST,
    (
        "fork_ops.security_exceptions:validate_advisory_reconciliation_projection",
        Transport.PYTHON,
    ): _SECURITY_ISSUANCE_TEST,
    (
        "fork_ops.security_exceptions:validate_authority_migration_projection",
        Transport.PYTHON,
    ): _AUTHORITY_MIGRATION_TEST,
    (
        "fork_ops.security_exceptions:is_structural_security_exception_inventory",
        Transport.PYTHON,
    ): _SECURITY_INVENTORY_PREDICATE_TEST,
    (
        "fork_ops.security_exceptions:is_validated_security_exception_inventory",
        Transport.PYTHON,
    ): _SECURITY_INVENTORY_PREDICATE_TEST,
    (
        "fork_ops.security_exceptions:validate_public_transition_projection(request=)",
        Transport.PYTHON,
    ): _SECURITY_TRANSITION_TEST,
    (
        "fork_ops.security_exceptions:validate_response_clock_inventory(structural_observations=)",
        Transport.PYTHON,
    ): _SECURITY_RESPONSE_CLOCK_TEST,
    (
        "fork_ops.repository_controls:load_repository_control_contract",
        Transport.PYTHON,
    ): _REPOSITORY_CONTROL_CONTRACT_TEST,
    (
        "fork_ops.repository_controls:parse_repository_control_observation",
        Transport.PYTHON,
    ): _REPOSITORY_CONTROL_OBSERVATION_TEST,
    (
        "fork_ops.repository_controls:evaluate_first_party_security",
        Transport.PYTHON,
    ): _FIRST_PARTY_SECURITY_RESULT_TEST,
    (
        "fork_ops.repository_controls:validate_repository_control_projection",
        Transport.PYTHON,
    ): _REPOSITORY_CONTROL_COORDINATION_TEST,
    (
        "fork_ops.repository_control_adapters:"
        "collect_repository_control_observation(control projections)",
        Transport.PYTHON,
    ): _REPOSITORY_CONTROL_COORDINATION_TEST,
    (
        "fork_ops.security_exceptions:validate_public_security_exception_ledger",
        Transport.PYTHON,
    ): _REPOSITORY_CONTROL_PUBLIC_LEDGER_TEST,
    (
        "fork_ops.repository_controls:"
        "evaluate_first_party_security(security_exception_inventory=)",
        Transport.PYTHON,
    ): _FIRST_PARTY_SECURITY_RESULT_TEST,
}


_PERSISTENCE_CHARACTERIZATION: dict[
    tuple[str, Transport, PersistenceRole], tuple[str, ...]
] = {
    (
        ".agents/fork-ops.toml",
        Transport.TOML_FILE,
        PersistenceRole.BOTH,
    ): _PERSISTENCE_TEST,
    (
        "plugins/fork-ops/schema/fork-ops.schema.json",
        Transport.JSON_FILE,
        PersistenceRole.BOTH,
    ): _PERSISTENCE_TEST,
    (
        "plugins/fork-ops/src/fork_ops/fork-ops.schema.json",
        Transport.PACKAGE_RESOURCE,
        PersistenceRole.BOTH,
    ): _PERSISTENCE_TEST,
    (
        "<operator-path>/migration-plan.json",
        Transport.JSON_FILE,
        PersistenceRole.CALLER_MANAGED,
    ): _PERSISTENCE_TEST,
    (
        "<operator-path>/migration-output.json",
        Transport.JSON_FILE,
        PersistenceRole.CALLER_MANAGED,
    ): _PERSISTENCE_TEST,
    (
        "docs/agents/fork-ops-migration-review.md",
        Transport.MARKDOWN_FILE,
        PersistenceRole.PROPOSED,
    ): _PERSISTENCE_TEST,
    (
        "docs/agents/fork-ops-equipment-review.toml",
        Transport.TOML_FILE,
        PersistenceRole.BOTH,
    ): _PERSISTENCE_TEST,
    (
        "<validation-evidence-output>.json",
        Transport.JSON_FILE,
        PersistenceRole.BOTH,
    ): _VALIDATION_TEST,
    (
        "plugins/fork-ops/src/fork_ops/security-exception-contract-1.0.json",
        Transport.PACKAGE_RESOURCE,
        PersistenceRole.BOTH,
    ): _SECURITY_CONTRACT_TEST,
    (
        "plugins/fork-ops/src/fork_ops/"
        "repository-control-observation-contract-1.0.json",
        Transport.PACKAGE_RESOURCE,
        PersistenceRole.BOTH,
    ): _REPOSITORY_CONTROL_CONTRACT_TEST,
    (
        "docs/agents/security-exceptions.md",
        Transport.MARKDOWN_FILE,
        PersistenceRole.BOTH,
    ): _SECURITY_GUIDE_TEST,
    (
        "docs/agents/security-exceptions.toml",
        Transport.TOML_FILE,
        PersistenceRole.BOTH,
    ): _SECURITY_LEDGER_TEST,
}

def _plan_replay_and_execution(
    *,
    cutover_version: str = "1.0",
    additional_characterization: tuple[str, ...] = (),
) -> tuple[ConsumerEndpoint, ...]:
    def characterization(id: str, transport: Transport) -> tuple[str, ...]:
        return _required_characterization(
            _CONSUMER_CHARACTERIZATION,
            (id, transport),
            label="consumer",
        ) + additional_characterization

    return (
        _consumer(
            "fork_ops.core:dry_run_migration(plan=)",
            cutover_version=cutover_version,
            purpose=ConsumerPurpose.REPLAY,
            legacy_regeneration="fork_ops.core:generate_migration_plan",
            characterized_by=characterization(
                "fork_ops.core:dry_run_migration(plan=)",
                Transport.PYTHON,
            ),
        ),
        _consumer(
            "fork_ops.core:dry_run_migration_plan(plan)",
            cutover_version=cutover_version,
            purpose=ConsumerPurpose.REPLAY,
            legacy_regeneration="fork_ops.core:generate_migration_plan",
            characterized_by=characterization(
                "fork_ops.core:dry_run_migration_plan(plan)",
                Transport.PYTHON,
            ),
        ),
        _consumer(
            "fork-ops migration dry-run --plan",
            cutover_version=cutover_version,
            transport=Transport.CLI_JSON,
            purpose=ConsumerPurpose.REPLAY,
            legacy_regeneration="fork-ops migration plan",
            characterized_by=characterization(
                "fork-ops migration dry-run --plan",
                Transport.CLI_JSON,
            ),
        ),
        _consumer(
            "fork_ops_migration_dry_run(migration_plan=)",
            cutover_version=cutover_version,
            transport=Transport.MCP,
            purpose=ConsumerPurpose.REPLAY,
            legacy_regeneration="fork_ops_migration_plan",
            characterized_by=characterization(
                "fork_ops_migration_dry_run(migration_plan=)",
                Transport.MCP,
            ),
        ),
        _consumer(
            "fork_ops.core:execute_migration(plan=)",
            cutover_version=cutover_version,
            purpose=ConsumerPurpose.EXECUTION,
            legacy_regeneration="fork_ops.core:generate_migration_plan",
            characterized_by=characterization(
                "fork_ops.core:execute_migration(plan=)",
                Transport.PYTHON,
            ),
        ),
        _consumer(
            "fork_ops.core:execute_migration_plan(plan)",
            cutover_version=cutover_version,
            purpose=ConsumerPurpose.EXECUTION,
            legacy_regeneration="fork_ops.core:generate_migration_plan",
            characterized_by=characterization(
                "fork_ops.core:execute_migration_plan(plan)",
                Transport.PYTHON,
            ),
        ),
        _consumer(
            "fork-ops migration execute --plan",
            cutover_version=cutover_version,
            transport=Transport.CLI_JSON,
            purpose=ConsumerPurpose.EXECUTION,
            legacy_regeneration="fork-ops migration plan",
            characterized_by=characterization(
                "fork-ops migration execute --plan",
                Transport.CLI_JSON,
            ),
        ),
        _consumer(
            "fork_ops_migration_execute(migration_plan=)",
            cutover_version=cutover_version,
            transport=Transport.MCP,
            purpose=ConsumerPurpose.EXECUTION,
            legacy_regeneration="fork_ops_migration_plan",
            characterized_by=characterization(
                "fork_ops_migration_execute(migration_plan=)",
                Transport.MCP,
            ),
        ),
    )


_PLAN_REPLAY_AND_EXECUTION = _plan_replay_and_execution()
_MIGRATION_NARRATIVE_DIAGNOSTIC = _consumer(
    "fork_ops:render_migration_narrative(workflow_output)",
    purpose=ConsumerPurpose.DIAGNOSTIC,
    legacy_policy=LegacyPolicy.IDENTIFY_ONLY,
)
_WORKFLOW_DIAGNOSTICS = (
    _consumer(
        "fork_ops:explain_migration_blocker(workflow_output)",
        purpose=ConsumerPurpose.DIAGNOSTIC,
        legacy_policy=LegacyPolicy.IDENTIFY_ONLY,
    ),
    _consumer(
        "fork-ops migration explain-blocker --input",
        transport=Transport.CLI_JSON,
        purpose=ConsumerPurpose.DIAGNOSTIC,
        legacy_policy=LegacyPolicy.IDENTIFY_ONLY,
    ),
    _consumer(
        "fork_ops_migration_blocker_resolution(workflow_output=)",
        transport=Transport.MCP,
        purpose=ConsumerPurpose.DIAGNOSTIC,
        legacy_policy=LegacyPolicy.IDENTIFY_ONLY,
    ),
    _MIGRATION_NARRATIVE_DIAGNOSTIC,
)
_MIGRATION_PLAN_FILE = _persistence(
    "<operator-path>/migration-plan.json",
    Transport.JSON_FILE,
    PersistenceRole.CALLER_MANAGED,
)
_MIGRATION_OUTPUT_FILE = _persistence(
    "<operator-path>/migration-output.json",
    Transport.JSON_FILE,
    PersistenceRole.CALLER_MANAGED,
)


PAYLOAD_FAMILIES: tuple[PayloadFamily, ...] = (
    _versioned(
        ArtifactKind.FORK_OPS_CONFIG,
        "0.1",
        external_identity=ExternalIdentity.VERSIONED_CONFIG,
        version_field="schema_version",
        emitted_artifact_kind=None,
        producers=(
            _endpoint("fork_ops.core:create_initial_config_text"),
            _endpoint("fork_ops.core:propose_migration_config_patch"),
            _endpoint("fork-ops config init (without --write)", Transport.CLI_TEXT),
            _endpoint("fork-ops config show [--format toml]", Transport.CLI_TEXT),
            _endpoint(
                "fork-ops config show --format json|--normalized",
                Transport.CLI_JSON,
            ),
            _endpoint("fork-ops migration propose-config --format toml", Transport.CLI_TEXT),
            _endpoint("fork_ops_config_read(normalized=True)", Transport.MCP),
        ),
        consumers=(
            _consumer(
                "fork_ops.core:load_config",
                cutover_version="0.1",
                characterized_by=_PYTHON_TEST + _VERSION_BEHAVIOR_TEST,
            ),
            _consumer(
                "fork_ops.core:build_status_report",
                observed_version_handling=ObservedVersionHandling.PERMISSIVE,
                missing_version=ObservedVersionOutcome.REPORTED,
                cutover_version="0.1",
                characterized_by=_PYTHON_TEST + _VERSION_BEHAVIOR_TEST,
            ),
            _consumer(
                "fork-ops config show [--format toml]",
                transport=Transport.CLI_TEXT,
                purpose=ConsumerPurpose.DIAGNOSTIC,
                cutover_version="0.1",
                cutover_legacy_policy=LegacyPolicy.IDENTIFY_ONLY,
                characterized_by=_CLI_TEST + _VERSION_BEHAVIOR_TEST,
            ),
            _consumer(
                "fork-ops config show --format json|--normalized",
                transport=Transport.CLI_JSON,
                observed_version_handling=ObservedVersionHandling.PERMISSIVE,
                cutover_version="0.1",
                characterized_by=_CLI_TEST + _VERSION_BEHAVIOR_TEST,
            ),
            _consumer(
                "fork-ops config validate (without --json)",
                transport=Transport.CLI_TEXT,
                observed_version_handling=ObservedVersionHandling.PERMISSIVE,
                missing_version=ObservedVersionOutcome.REFUSED,
                cutover_version="0.1",
                characterized_by=_CLI_TEST + _VERSION_BEHAVIOR_TEST,
            ),
            _consumer(
                "fork-ops config validate --json",
                transport=Transport.CLI_JSON,
                observed_version_handling=ObservedVersionHandling.PERMISSIVE,
                missing_version=ObservedVersionOutcome.REFUSED,
                cutover_version="0.1",
                characterized_by=_CLI_TEST + _VERSION_BEHAVIOR_TEST,
            ),
            _consumer(
                "fork_ops_config_read(normalized=False)",
                transport=Transport.MCP,
                purpose=ConsumerPurpose.DIAGNOSTIC,
                cutover_version="0.1",
                cutover_legacy_policy=LegacyPolicy.IDENTIFY_ONLY,
                characterized_by=_MCP_TEST + _VERSION_BEHAVIOR_TEST,
            ),
            _consumer(
                "fork_ops_config_read(normalized=True)",
                transport=Transport.MCP,
                observed_version_handling=ObservedVersionHandling.PERMISSIVE,
                missing_version=ObservedVersionOutcome.REPORTED,
                cutover_version="0.1",
                characterized_by=_MCP_TEST + _VERSION_BEHAVIOR_TEST,
            ),
            _consumer(
                "fork_ops_config_validate",
                transport=Transport.MCP,
                observed_version_handling=ObservedVersionHandling.PERMISSIVE,
                missing_version=ObservedVersionOutcome.REPORTED,
                cutover_version="0.1",
                characterized_by=_MCP_TEST + _VERSION_BEHAVIOR_TEST,
            ),
        ),
        persistence=(
            _persistence(
                ".agents/fork-ops.toml",
                Transport.TOML_FILE,
                PersistenceRole.BOTH,
            ),
        ),
        docs=_CONFIG_GUIDE + _OPERATION_GUIDE,
        tests=_CORE_TEST + _CLI_TEST + _MCP_TEST + _PERSISTENCE_TEST,
    ),
    _legacy(
        ArtifactKind.FORK_OPS_CONFIG_SCHEMA,
        producers=(
            _endpoint("fork_ops.core:schema_json"),
            _endpoint("fork-ops schema print", Transport.CLI_JSON),
            _endpoint("fork_ops_schema", Transport.MCP),
        ),
        consumers=(
            _consumer("fork_ops.schema:schema_diagnostics"),
            _consumer("fork_ops.core:schema_artifact_report"),
            _consumer(
                "fork-ops schema check (without --json)",
                transport=Transport.CLI_TEXT,
            ),
            _consumer(
                "fork-ops schema check --json",
                transport=Transport.CLI_JSON,
            ),
        ),
        persistence=(
            _persistence(
                "plugins/fork-ops/schema/fork-ops.schema.json",
                Transport.JSON_FILE,
                PersistenceRole.BOTH,
            ),
            _persistence(
                "plugins/fork-ops/src/fork_ops/fork-ops.schema.json",
                Transport.PACKAGE_RESOURCE,
                PersistenceRole.BOTH,
            ),
        ),
        docs=_CONFIG_GUIDE + _OPERATION_GUIDE,
        tests=_CORE_TEST + _CLI_TEST + _MCP_TEST + _PERSISTENCE_TEST,
    ),
    _legacy(
        ArtifactKind.PLUGIN_HEALTH_REPORT,
        producers=(
            _endpoint("fork_ops.core:build_plugin_health_report"),
            _endpoint("fork-ops plugin health", Transport.CLI_JSON),
            _endpoint("fork_ops_plugin_health", Transport.MCP),
        ),
        consumers=(),
        consumer_gap="No in-repository consumer; emitted to the exact Python, CLI, or MCP caller.",
        persistence_gap="Plugin health reports are returned, not persisted by Fork Ops.",
        docs=_OPERATION_GUIDE,
        tests=_CORE_TEST + _CLI_TEST + _MCP_TEST,
    ),
    _legacy(
        ArtifactKind.CONFIG_READ_RESULT,
        producers=(
            _endpoint("fork_ops_config_read(normalized=False)", Transport.MCP),
        ),
        consumers=(),
        consumer_gap="No in-repository consumer; emitted to the exact MCP caller.",
        persistence_gap="Config-read results are returned, not persisted by Fork Ops.",
        docs=_OPERATION_GUIDE,
        tests=_CORE_TEST + _MCP_TEST,
    ),
    _legacy(
        ArtifactKind.STATUS_REPORT,
        producers=(
            _endpoint("fork_ops.core:build_status_report"),
            _endpoint("fork-ops config validate --json", Transport.CLI_JSON),
            _endpoint("fork-ops capability report --json", Transport.CLI_JSON),
            _endpoint("fork_ops_config_read(normalized=True)", Transport.MCP),
            _endpoint("fork_ops_config_validate", Transport.MCP),
        ),
        consumers=(),
        consumer_gap="No in-repository consumer; emitted to the exact Python, CLI, or MCP caller.",
        persistence_gap="Status reports are returned, not persisted by Fork Ops.",
        docs=_CONFIG_GUIDE + _OPERATION_GUIDE,
        tests=_CORE_TEST + _CLI_TEST + _MCP_TEST,
    ),
    _legacy(
        ArtifactKind.CAPABILITY_REPORT,
        producers=(
            _endpoint("fork_ops.core:capability_report"),
            _endpoint("fork-ops capability report (without --json)", Transport.CLI_TEXT),
            _endpoint("fork_ops_capability_report", Transport.MCP),
        ),
        consumers=(
            _consumer(
                "fork_ops.core:build_status_report",
                purpose=ConsumerPurpose.DERIVATION,
            ),
        ),
        persistence_gap="Capability reports are returned or embedded, not persisted independently.",
        docs=_CONFIG_GUIDE + _OPERATION_GUIDE,
        tests=_CORE_TEST + _CLI_TEST + _MCP_TEST,
    ),
    _legacy(
        ArtifactKind.CONFIG_INITIALIZATION_RESULT,
        producers=(_endpoint("fork_ops.core:initialize_config"),),
        consumers=(
            _consumer(
                "fork_ops.cli:cmd_config_init(--write)",
                transport=Transport.CLI_TEXT,
                purpose=ConsumerPurpose.DERIVATION,
            ),
        ),
        persistence_gap=(
            "Initialization results are returned; only the authored config is persisted."
        ),
        docs=_OPERATION_GUIDE,
        tests=_CORE_TEST + _CLI_TEST + _PERSISTENCE_TEST,
    ),
    _legacy(
        ArtifactKind.MIGRATION_ASSESSMENT,
        producers=(
            _endpoint("fork_ops.core:assess_migration"),
            _endpoint(
                "fork-ops migration assess (without --with-proposed-config)",
                Transport.CLI_JSON,
            ),
            _endpoint(
                "fork-ops migration assess --with-proposed-config",
                Transport.CLI_JSON,
            ),
            _endpoint("fork_ops_migration_assessment", Transport.MCP),
        ),
        consumers=_WORKFLOW_DIAGNOSTICS,
        persistence=(_MIGRATION_OUTPUT_FILE,),
        docs=_MIGRATION_GUIDE,
        tests=_CORE_TEST + _CLI_TEST + _MCP_TEST + _PERSISTENCE_TEST,
    ),
    _legacy(
        ArtifactKind.EQUIPMENT_MIGRATION_PREFLIGHT,
        producers=(
            _endpoint("fork_ops.core:build_equipment_migration_preflight"),
            _endpoint("fork-ops migration preflight", Transport.CLI_JSON),
            _endpoint("fork_ops_equipment_migration_preflight", Transport.MCP),
        ),
        consumers=(),
        consumer_gap="No in-repository consumer; emitted to the exact Python, CLI, or MCP caller.",
        persistence_gap="Equipment preflight results are returned, not persisted independently.",
        docs=_MIGRATION_GUIDE,
        tests=_CORE_TEST + _CLI_TEST + _MCP_TEST,
    ),
    _legacy(
        ArtifactKind.EMBEDDED_EQUIPMENT_MIGRATION_PREFLIGHT,
        producers=(_endpoint("fork_ops.core:_equipment_migration_preflight"),),
        consumers=(
            _consumer(
                "fork_ops.core:build_equipment_migration_preflight(embedded_preflight)",
                purpose=ConsumerPurpose.DERIVATION,
            ),
            _consumer(
                "fork_ops.core:generate_migration_plan(embedded_preflight)",
                purpose=ConsumerPurpose.DERIVATION,
            ),
        )
        + _PLAN_REPLAY_AND_EXECUTION,
        persistence_gap=(
            "Embedded equipment preflight data is stored only inside migration-plan payloads."
        ),
        docs=_MIGRATION_GUIDE,
        tests=_CORE_TEST + _CLI_TEST + _MCP_TEST + _PERSISTENCE_TEST,
    ),
    _legacy(
        ArtifactKind.MIGRATION_CONFIG_PATCH,
        producers=(
            _endpoint("fork_ops.core:propose_migration_config_patch"),
            _endpoint(
                "fork-ops migration propose-config --format json",
                Transport.CLI_JSON,
            ),
            _endpoint("fork_ops_migration_config_patch", Transport.MCP),
        ),
        consumers=(
            _consumer(
                "fork_ops.core:generate_migration_plan",
                purpose=ConsumerPurpose.DERIVATION,
            ),
            _consumer(
                "fork_ops.core:assess_migration(include_proposed_config_patch=True)",
                purpose=ConsumerPurpose.DERIVATION,
            ),
            _consumer(
                "fork_ops.core:build_equipment_migration_preflight(proposed_config_patch)",
                purpose=ConsumerPurpose.DERIVATION,
            ),
        )
        + _PLAN_REPLAY_AND_EXECUTION,
        persistence_gap=(
            "Config patches are returned or embedded in migration payloads, "
            "not persisted independently."
        ),
        docs=_MIGRATION_GUIDE,
        tests=_CORE_TEST + _CLI_TEST + _MCP_TEST,
    ),
    _legacy(
        ArtifactKind.MIGRATION_PLAN,
        producers=(
            _endpoint("fork_ops.core:generate_migration_plan"),
            _endpoint("fork-ops migration plan", Transport.CLI_JSON),
            _endpoint("fork_ops_migration_plan", Transport.MCP),
        ),
        consumers=_PLAN_REPLAY_AND_EXECUTION + _WORKFLOW_DIAGNOSTICS,
        persistence=(_MIGRATION_PLAN_FILE, _MIGRATION_OUTPUT_FILE),
        docs=_MIGRATION_GUIDE,
        tests=_CORE_TEST + _CLI_TEST + _MCP_TEST + _PERSISTENCE_TEST,
    ),
    _legacy(
        ArtifactKind.MIGRATION_DRY_RUN,
        producers=(
            _endpoint("fork_ops.core:dry_run_migration(plan=None)"),
            _endpoint("fork_ops.core:dry_run_migration(plan=)"),
            _endpoint("fork_ops.core:dry_run_migration_plan"),
            _endpoint(
                "fork-ops migration dry-run (without --plan)",
                Transport.CLI_JSON,
            ),
            _endpoint("fork-ops migration dry-run --plan", Transport.CLI_JSON),
            _endpoint(
                "fork_ops_migration_dry_run(migration_plan=None)",
                Transport.MCP,
            ),
            _endpoint(
                "fork_ops_migration_dry_run(migration_plan=)",
                Transport.MCP,
            ),
        ),
        consumers=_WORKFLOW_DIAGNOSTICS,
        persistence=(_MIGRATION_OUTPUT_FILE,),
        docs=_MIGRATION_GUIDE,
        tests=_CORE_TEST + _CLI_TEST + _MCP_TEST + _PERSISTENCE_TEST,
    ),
    _legacy(
        ArtifactKind.MIGRATION_EXECUTION_RESULT,
        producers=(
            _endpoint("fork_ops.core:execute_migration(plan=None)"),
            _endpoint("fork_ops.core:execute_migration(plan=)"),
            _endpoint("fork_ops.core:execute_migration_plan"),
            _endpoint(
                "fork-ops migration execute (without --plan)",
                Transport.CLI_JSON,
            ),
            _endpoint("fork-ops migration execute --plan", Transport.CLI_JSON),
            _endpoint(
                "fork_ops_migration_execute(migration_plan=None)",
                Transport.MCP,
            ),
            _endpoint(
                "fork_ops_migration_execute(migration_plan=)",
                Transport.MCP,
            ),
        ),
        consumers=_WORKFLOW_DIAGNOSTICS,
        persistence=(_MIGRATION_OUTPUT_FILE,),
        docs=_MIGRATION_GUIDE,
        tests=_CORE_TEST + _CLI_TEST + _MCP_TEST + _PERSISTENCE_TEST,
    ),
    _legacy(
        ArtifactKind.MIGRATION_BLOCKER_EXPLANATION,
        producers=(
            _endpoint("fork_ops.core:explain_migration_blocker"),
            _endpoint(
                "fork-ops migration explain-blocker --input",
                Transport.CLI_JSON,
            ),
            _endpoint(
                "fork_ops_migration_blocker_resolution(workflow_output=)",
                Transport.MCP,
            ),
        ),
        consumers=(_MIGRATION_NARRATIVE_DIAGNOSTIC,),
        persistence_gap=(
            "Blocker explanations are returned or embedded in workflow payloads, "
            "not persisted independently."
        ),
        docs=_MIGRATION_GUIDE,
        tests=_CORE_TEST + _CLI_TEST + _MCP_TEST,
    ),
    _legacy(
        ArtifactKind.MIGRATION_NARRATIVE,
        producers=(_endpoint("fork_ops:render_migration_narrative(workflow_output)"),),
        consumers=(),
        consumer_gap="No in-repository consumer; embedded into migration workflow payloads.",
        persistence_gap=(
            "Migration narratives are embedded in workflow payloads, "
            "not persisted independently."
        ),
        docs=_MIGRATION_GUIDE,
        tests=_CORE_TEST,
    ),
    _legacy(
        ArtifactKind.MIGRATION_REVIEW_ARTIFACT,
        producers=(_endpoint("fork_ops.core:_migration_review_artifact"),),
        consumers=_PLAN_REPLAY_AND_EXECUTION,
        persistence=(
            _persistence(
                "docs/agents/fork-ops-migration-review.md",
                Transport.MARKDOWN_FILE,
                PersistenceRole.PROPOSED,
            ),
        ),
        docs=_MIGRATION_GUIDE,
        tests=_CORE_TEST + _CLI_TEST + _MCP_TEST + _PERSISTENCE_TEST,
    ),
    _versioned(
        ArtifactKind.EQUIPMENT_REVIEW,
        "0.1",
        producers=(
            _endpoint("fork_ops.core:_equipment_review_record"),
            _endpoint(
                "fork_ops.core:build_equipment_migration_preflight(equipment_review_record)"
            ),
        ),
        consumers=(
            _consumer(
                "fork_ops.core:_equipment_review_record_report",
                observed_version_handling=ObservedVersionHandling.PERMISSIVE,
                cutover_version="1.0",
                characterized_by=_PYTHON_TEST + _VERSION_BEHAVIOR_TEST,
            ),
            _consumer(
                "fork_ops.core:build_status_report",
                observed_version_handling=ObservedVersionHandling.PERMISSIVE,
                cutover_version="1.0",
                characterized_by=_PYTHON_TEST + _VERSION_BEHAVIOR_TEST,
            ),
        )
        + _plan_replay_and_execution(
            cutover_version="1.0",
            additional_characterization=_VERSION_BEHAVIOR_TEST,
        ),
        persistence=(
            _persistence(
                "docs/agents/fork-ops-equipment-review.toml",
                Transport.TOML_FILE,
                PersistenceRole.BOTH,
            ),
        ),
        docs=_MIGRATION_GUIDE,
        tests=_CORE_TEST + _CLI_TEST + _MCP_TEST + _PERSISTENCE_TEST,
    ),
    _legacy(
        ArtifactKind.WORKFLOW_CATALOG,
        producers=(
            _endpoint("fork_ops.workflow_catalog:workflow_catalog"),
            _endpoint("fork-ops workflow catalog", Transport.CLI_JSON),
            _endpoint("fork_ops_workflow_catalog", Transport.MCP),
        ),
        consumers=(
            _consumer(
                "fork_ops.core:_cli_execution_check",
                purpose=ConsumerPurpose.DIAGNOSTIC,
                legacy_policy=LegacyPolicy.IDENTIFY_ONLY,
            ),
            _consumer(
                "scripts/produce_validation_evidence.py:_workflow_catalog_check",
                purpose=ConsumerPurpose.DERIVATION,
            ),
        ),
        persistence_gap="Workflow catalogs are generated and consumed in memory, not persisted.",
        docs=_OPERATION_GUIDE,
        tests=_CORE_TEST + _CLI_TEST + _MCP_TEST,
    ),
    _legacy(
        ArtifactKind.WORKFLOW_CONTRACT_SET,
        producers=(_endpoint("fork_ops.workflow_catalog:workflow_contracts"),),
        consumers=(
            _consumer(
                "fork_ops.core:build_workflow_migration_inventory",
                purpose=ConsumerPurpose.DERIVATION,
            ),
            _consumer(
                "fork_ops.core:explain_migration_blocker via _workflow_contract_dict",
                purpose=ConsumerPurpose.DERIVATION,
            ),
        ),
        persistence_gap=(
            "Workflow contract sets are generated and consumed in memory, not persisted."
        ),
        docs=_OPERATION_GUIDE,
        tests=_CORE_TEST,
    ),
    _legacy(
        ArtifactKind.WORKFLOW_MIGRATION_INVENTORY,
        producers=(
            _endpoint("fork_ops.core:build_workflow_migration_inventory"),
            _endpoint("fork-ops workflow inventory", Transport.CLI_JSON),
            _endpoint("fork_ops_workflow_migration_inventory", Transport.MCP),
        ),
        consumers=(
            _consumer(
                "fork_ops.core:generate_migration_plan",
                purpose=ConsumerPurpose.DERIVATION,
            ),
            _consumer(
                "fork_ops.core:build_equipment_migration_preflight(workflow_inventory)",
                purpose=ConsumerPurpose.DERIVATION,
            ),
        ),
        persistence_gap=(
            "Workflow inventories are returned or embedded in migration plans, "
            "not persisted independently."
        ),
        docs=_MIGRATION_GUIDE + _OPERATION_GUIDE,
        tests=_CORE_TEST + _CLI_TEST + _MCP_TEST,
    ),
    _legacy(
        ArtifactKind.SCHEMA_ARTIFACT_REPORT,
        producers=(
            _endpoint("fork_ops.core:schema_artifact_report"),
            _endpoint("fork-ops schema check --json", Transport.CLI_JSON),
        ),
        consumers=(),
        consumer_gap="No in-repository consumer; emitted to the exact CLI or validation caller.",
        persistence_gap="Schema artifact reports are returned, not persisted by Fork Ops.",
        docs=_OPERATION_GUIDE,
        tests=_CORE_TEST + _CLI_TEST,
    ),
    _legacy(
        ArtifactKind.MCP_HEALTHCHECK,
        producers=(
            _endpoint("fork_ops.mcp_server:mcp_healthcheck"),
            _endpoint("fork-ops-mcp --health-check", Transport.CLI_JSON),
        ),
        consumers=(
            _consumer(
                "fork_ops.core:build_plugin_health_report",
                purpose=ConsumerPurpose.DIAGNOSTIC,
                legacy_policy=LegacyPolicy.IDENTIFY_ONLY,
            ),
        ),
        persistence_gap="MCP health-check results are returned, not persisted by Fork Ops.",
        docs=_OPERATION_GUIDE,
        tests=_CORE_TEST + _CLI_TEST,
    ),
    _versioned(
        ArtifactKind.REPOSITORY_CONTROL_OBSERVATION_CONTRACT,
        "1.0",
        external_identity=ExternalIdentity.VERSIONED_CONTRACT,
        version_field="contract_version",
        emitted_artifact_kind=(
            ArtifactKind.REPOSITORY_CONTROL_OBSERVATION_CONTRACT.value
        ),
        producers=(
            _endpoint(
                "canonical packaged repository-control observation contract",
                Transport.PACKAGE_RESOURCE,
            ),
        ),
        consumers=(
            _enforced_consumer(
                "fork_ops.repository_controls:load_repository_control_contract",
                version="1.0",
            ),
        ),
        persistence=(
            _persistence(
                "plugins/fork-ops/src/fork_ops/"
                "repository-control-observation-contract-1.0.json",
                Transport.PACKAGE_RESOURCE,
                PersistenceRole.BOTH,
            ),
        ),
        docs=_REPOSITORY_CONTROL_GUIDE,
        tests=_REPOSITORY_CONTROL_CONTRACT_TEST,
    ),
    _versioned(
        ArtifactKind.REPOSITORY_CONTROL_OBSERVATION,
        "1.0",
        producers=(
            _endpoint(
                "fork_ops.repository_control_adapters:"
                "collect_repository_control_observation"
            ),
        ),
        consumers=(
            _enforced_consumer(
                "fork_ops.repository_controls:parse_repository_control_observation",
                version="1.0",
            ),
            _enforced_consumer(
                "fork_ops.repository_controls:evaluate_first_party_security",
                version="1.0",
            ),
        ),
        persistence_gap=(
            "No shipped storage adapter; callers retain normalized observations."
        ),
        docs=_REPOSITORY_CONTROL_GUIDE,
        tests=(
            _REPOSITORY_CONTROL_COORDINATION_TEST
            + _REPOSITORY_CONTROL_OBSERVATION_TEST
            + _FIRST_PARTY_SECURITY_RESULT_TEST
        ),
    ),
    _versioned(
        ArtifactKind.REPOSITORY_CONTROL_PROJECTION,
        "1.0",
        external_identity=ExternalIdentity.INTERNAL_TYPED,
        version_field=None,
        producers=(
            _endpoint(
                "fork_ops.repository_control_adapters:GitHubControlAdapter.observe"
            ),
            _endpoint(
                "fork_ops.repository_control_adapters:PackageControlAdapter.observe"
            ),
            _endpoint(
                "fork_ops.repository_control_adapters:_unavailable_projection"
            ),
        ),
        consumers=(
            _consumer(
                "fork_ops.repository_controls:validate_repository_control_projection"
            ),
            _consumer(
                "fork_ops.repository_control_adapters:"
                "collect_repository_control_observation(control projections)"
            ),
        ),
        persistence_gap="Operation-scoped control projections are not persisted.",
        docs=_REPOSITORY_CONTROL_GUIDE,
        tests=(
            _REPOSITORY_CONTROL_COORDINATION_TEST
            + _REPOSITORY_CONTROL_FAILURE_TEST
        ),
    ),
    _versioned(
        ArtifactKind.FIRST_PARTY_SECURITY_RESULT,
        "1.0",
        producers=(
            _endpoint("fork_ops.repository_controls:evaluate_first_party_security"),
        ),
        consumers=(),
        consumer_gap="No in-repository consumer; returned to the evaluation caller.",
        persistence_gap="No shipped storage adapter; callers own result persistence.",
        docs=_REPOSITORY_CONTROL_GUIDE,
        tests=_FIRST_PARTY_SECURITY_RESULT_TEST,
    ),
    _versioned(
        ArtifactKind.VALIDATION_EVIDENCE_RESULT,
        "1.0",
        producers=(_endpoint("scripts/produce_validation_evidence.py:main"),),
        consumers=(
            _enforced_consumer(
                "scripts/produce_validation_evidence.py:_release_preflight_evidence_check",
                version="1.0",
            ),
            _enforced_consumer(
                "scripts/produce_validation_evidence.py:_candidate_identity_check",
                version="1.0",
            ),
            _enforced_consumer(
                "scripts/produce_validation_evidence.py:_release_trust_check",
                version="1.0",
            ),
        ),
        persistence=(
            _persistence(
                "<validation-evidence-output>.json",
                Transport.JSON_FILE,
                PersistenceRole.BOTH,
            ),
        ),
        docs=_VALIDATION_GUIDE,
        tests=_VALIDATION_TEST,
    ),
    _versioned(
        ArtifactKind.VALIDATION_WORKFLOW_AGGREGATE,
        "1.0",
        producers=(
            _endpoint(
                ".github/workflows/validation.yml:validation",
                Transport.GITHUB_ACTIONS_LOG,
            ),
            _endpoint(
                ".github/workflows/release-validation.yml:validation",
                Transport.GITHUB_ACTIONS_LOG,
            ),
        ),
        consumers=(),
        consumer_gap="No in-repository consumer; emitted into the exact GitHub Actions job log.",
        persistence_gap="Workflow aggregates are logged, with no separate persisted artifact.",
        docs=_VALIDATION_GUIDE,
        tests=_WORKFLOW_AGGREGATE_TEST,
    ),
    _versioned(
        ArtifactKind.NORMALIZED_DEPENDENCY_VULNERABILITY_EVIDENCE,
        "2.0",
        producers=(
            _endpoint("fork_ops.dependency_security:collect_uv_audit_evidence"),
            _endpoint("scripts/produce_validation_evidence.py:_dependency_audit_matrix_check"),
        ),
        consumers=(
            _enforced_consumer(
                "fork_ops.dependency_security:evaluate_dependency_security",
                version="2.0",
            ),
        ),
        persistence_gap=(
            "Normalized dependency evidence is consumed in process, not persisted independently."
        ),
        docs=_VALIDATION_GUIDE,
        tests=_DEPENDENCY_TEST,
    ),
    _versioned(
        ArtifactKind.DEPENDENCY_SECURITY_RESULT,
        "1.0",
        producers=(_endpoint("fork_ops.dependency_security:evaluate_dependency_security"),),
        consumers=(),
        consumer_gap="No in-repository consumer; returned to the evaluation caller.",
        persistence_gap="Dependency-security results are returned, not persisted by Fork Ops.",
        docs=_VALIDATION_GUIDE,
        tests=_DEPENDENCY_EVALUATION_TEST + _SECURITY_TEST,
    ),
    _versioned(
        ArtifactKind.SECURITY_EXCEPTION_CONTRACT,
        "1.0",
        external_identity=ExternalIdentity.VERSIONED_CONTRACT,
        version_field="contract_version",
        emitted_artifact_kind=ArtifactKind.SECURITY_EXCEPTION_CONTRACT.value,
        producers=(_endpoint("canonical checked-in contract", Transport.PACKAGE_RESOURCE),),
        consumers=(
            _enforced_consumer(
                "fork_ops.security_exceptions:load_security_exception_contract",
                version="1.0",
            ),
            _enforced_consumer(
                "scripts/security_exception_projections.py:main",
                version="1.0",
            ),
        ),
        persistence=(
            _persistence(
                "plugins/fork-ops/src/fork_ops/security-exception-contract-1.0.json",
                Transport.PACKAGE_RESOURCE,
                PersistenceRole.BOTH,
            ),
        ),
        docs=_SECURITY_GUIDE,
        tests=_SECURITY_TEST,
    ),
    _legacy(
        ArtifactKind.SECURITY_EXCEPTION_GUIDE,
        producers=(
            _endpoint("scripts/security_exception_projections.py:_render_guide"),
        ),
        consumers=(
            _consumer(
                "scripts/security_exception_projections.py:main(--check)",
                purpose=ConsumerPurpose.DIAGNOSTIC,
                legacy_policy=LegacyPolicy.IDENTIFY_ONLY,
            ),
        ),
        persistence=(
            _persistence(
                "docs/agents/security-exceptions.md",
                Transport.MARKDOWN_FILE,
                PersistenceRole.BOTH,
            ),
        ),
        docs=_SECURITY_GUIDE,
        tests=_SECURITY_GUIDE_TEST,
    ),
    _versioned(
        ArtifactKind.SECURITY_EXCEPTION_LEDGER,
        "1.0",
        producers=(_endpoint("checked-in public governance ledger", Transport.TOML_FILE),),
        consumers=(
            _enforced_consumer(
                "fork_ops.security_exceptions:validate_security_exception_inventory(public_ledger=)",
                version="1.0",
            ),
            _enforced_consumer(
                "fork_ops.security_exceptions:validate_public_security_exception_ledger",
                version="1.0",
            ),
        ),
        persistence=(
            _persistence(
                "docs/agents/security-exceptions.toml",
                Transport.TOML_FILE,
                PersistenceRole.BOTH,
            ),
        ),
        docs=_SECURITY_GUIDE + _REPOSITORY_CONTROL_GUIDE,
        tests=_SECURITY_TEST,
    ),
    _versioned(
        ArtifactKind.SECURITY_EXCEPTION_PRIVATE_PROJECTION,
        "1.0",
        producers=(),
        producer_gap="Private persistence adapter is intentionally not implemented.",
        consumers=(
            _enforced_consumer(
                "fork_ops.security_exceptions:validate_security_exception_inventory(private_projection=)",
                version="1.0",
            ),
        ),
        persistence_gap="Private projection persistence adapter is not implemented.",
        docs=_SECURITY_GUIDE,
        tests=_SECURITY_TEST,
    ),
    _versioned(
        ArtifactKind.SECURITY_EXCEPTION_LINEAGE_INDEX_PROJECTION,
        "1.0",
        producers=(),
        producer_gap="Private lineage persistence adapter is intentionally not implemented.",
        consumers=(
            _enforced_consumer(
                "fork_ops.security_exceptions:validate_security_exception_inventory(lineage_index=)",
                version="1.0",
            ),
        ),
        persistence_gap="Private lineage persistence adapter is not implemented.",
        docs=_SECURITY_GUIDE,
        tests=_SECURITY_TEST,
    ),
    _versioned(
        ArtifactKind.SECURITY_EXCEPTION_AUTHORITY_OBSERVATION,
        "1.0",
        producers=(),
        producer_gap="Authenticated authority observation adapter is not implemented.",
        consumers=(
            _enforced_consumer(
                "fork_ops.security_exceptions:validate_security_exception_inventory(authority_observation=)",
                version="1.0",
            ),
        ),
        persistence_gap="Authority-observation persistence adapter is not implemented.",
        docs=_SECURITY_GUIDE,
        tests=_SECURITY_TEST,
    ),
    _versioned(
        ArtifactKind.SECURITY_EXCEPTION_INVENTORY,
        "1.0",
        external_identity=ExternalIdentity.INTERNAL_TYPED,
        version_field="contract_version",
        emitted_artifact_kind=None,
        producers=(
            _endpoint(
                "fork_ops.security_exceptions:validate_security_exception_inventory"
            ),
        ),
        consumers=(
            _enforced_consumer(
                "fork_ops.security_exceptions:parse_public_security_exception_command(current_inventory=)",
                version="1.0",
            ),
            _enforced_consumer(
                "fork_ops.security_exceptions:validate_public_transition_projection(current_inventory=)",
                version="1.0",
            ),
            _enforced_consumer(
                "fork_ops.security_exceptions:validate_lineage_issuance_projection(current_inventory=)",
                version="1.0",
            ),
            _enforced_consumer(
                "fork_ops.security_exceptions:validate_advisory_reconciliation_projection(current_inventory=)",
                version="1.0",
            ),
            _enforced_consumer(
                "fork_ops.security_exceptions:validate_response_clock_inventory(current_inventory=)",
                version="1.0",
            ),
            _enforced_consumer(
                "fork_ops.dependency_security:evaluate_dependency_security",
                version="1.0",
                characterized_by=_SECURITY_TEST,
            ),
            _enforced_consumer(
                "fork_ops.security_exceptions:is_structural_security_exception_inventory",
                version="1.0",
            ),
            _enforced_consumer(
                "fork_ops.security_exceptions:is_validated_security_exception_inventory",
                version="1.0",
            ),
            _enforced_consumer(
                "fork_ops.repository_controls:"
                "evaluate_first_party_security(security_exception_inventory=)",
                version="1.0",
            ),
        ),
        docs=_SECURITY_GUIDE + _VALIDATION_GUIDE + _REPOSITORY_CONTROL_GUIDE,
        persistence_gap=(
            "Validated security-exception inventories are internal typed values, not persisted."
        ),
        tests=_SECURITY_TEST,
    ),
    _versioned(
        ArtifactKind.SECURITY_EXCEPTION_PUBLIC_COMMAND_REQUEST,
        "1.0",
        external_identity=ExternalIdentity.INTERNAL_TYPED,
        version_field=None,
        emitted_artifact_kind=None,
        producers=(
            _endpoint(
                "fork_ops.security_exceptions:parse_public_security_exception_command"
            ),
        ),
        consumers=(
            _consumer(
                "fork_ops.security_exceptions:validate_public_transition_projection(request=)"
            ),
        ),
        persistence_gap="Parsed public command requests are internal typed values, not persisted.",
        docs=_SECURITY_GUIDE,
        tests=_SECURITY_TRANSITION_TEST,
    ),
    _versioned(
        ArtifactKind.SECURITY_EXCEPTION_TRANSITION_PROJECTION,
        "1.0",
        producers=(),
        producer_gap="Authenticated transition persistence adapter is not implemented.",
        consumers=(
            _enforced_consumer(
                "fork_ops.security_exceptions:validate_public_transition_projection",
                version="1.0",
            ),
        ),
        persistence_gap="Transition persistence adapter is not implemented.",
        docs=_SECURITY_GUIDE,
        tests=_SECURITY_TRANSITION_TEST,
    ),
    _versioned(
        ArtifactKind.SECURITY_EXCEPTION_PROVIDER_OBSERVATION,
        "1.0",
        producers=(),
        producer_gap="Authenticated provider observation adapter is not implemented.",
        consumers=(
            _enforced_consumer(
                "fork_ops.security_exceptions:validate_provider_observation_envelope",
                version="1.0",
            ),
        ),
        persistence_gap="Provider-observation persistence adapter is not implemented.",
        docs=_SECURITY_GUIDE,
        tests=_SECURITY_PROVIDER_TEST,
    ),
    _versioned(
        ArtifactKind.SECURITY_EXCEPTION_STRUCTURAL_PROVIDER_OBSERVATION,
        "1.0",
        external_identity=ExternalIdentity.INTERNAL_TYPED,
        version_field=None,
        emitted_artifact_kind=None,
        producers=(
            _endpoint(
                "fork_ops.security_exceptions:validate_provider_observation_envelope"
            ),
        ),
        consumers=(
            _consumer(
                "fork_ops.security_exceptions:validate_response_clock_inventory(structural_observations=)"
            ),
        ),
        persistence_gap=(
            "Structural provider observations are internal typed values, not persisted."
        ),
        docs=_SECURITY_GUIDE,
        tests=_SECURITY_RESPONSE_CLOCK_TEST,
    ),
    _versioned(
        ArtifactKind.SECURITY_EXCEPTION_RESPONSE_CLOCK_INVENTORY,
        "1.0",
        producers=(),
        producer_gap="Response-clock collection adapter is not implemented.",
        consumers=(
            _enforced_consumer(
                "fork_ops.security_exceptions:validate_response_clock_inventory",
                version="1.0",
            ),
        ),
        persistence_gap="Response-clock persistence adapter is not implemented.",
        docs=_SECURITY_GUIDE,
        tests=_SECURITY_RESPONSE_CLOCK_TEST,
    ),
    _versioned(
        ArtifactKind.SECURITY_EXCEPTION_LINEAGE_ISSUANCE_PROJECTION,
        "1.0",
        producers=(),
        producer_gap="Authenticated lineage issuance adapter is not implemented.",
        consumers=(
            _enforced_consumer(
                "fork_ops.security_exceptions:validate_lineage_issuance_projection",
                version="1.0",
            ),
        ),
        persistence_gap="Lineage-issuance persistence adapter is not implemented.",
        docs=_SECURITY_GUIDE,
        tests=_SECURITY_ISSUANCE_TEST,
    ),
    _versioned(
        ArtifactKind.SECURITY_EXCEPTION_ADVISORY_RECONCILIATION_PROJECTION,
        "1.0",
        producers=(),
        producer_gap="Authenticated advisory reconciliation adapter is not implemented.",
        consumers=(
            _enforced_consumer(
                "fork_ops.security_exceptions:validate_advisory_reconciliation_projection",
                version="1.0",
            ),
        ),
        persistence_gap="Advisory-reconciliation persistence adapter is not implemented.",
        docs=_SECURITY_GUIDE,
        tests=_SECURITY_ISSUANCE_TEST,
    ),
    _versioned(
        ArtifactKind.SECURITY_EXCEPTION_AUTHORITY_MIGRATION,
        "1.0",
        producers=(),
        producer_gap="Authority migration projection producer is intentionally unavailable.",
        consumers=(
            _enforced_consumer(
                "fork_ops.security_exceptions:validate_authority_migration_projection",
                version="1.0",
            ),
        ),
        persistence_gap="Authority-migration persistence adapter is not implemented.",
        docs=_SECURITY_GUIDE,
        tests=_AUTHORITY_MIGRATION_TEST,
    ),
)


_PAYLOAD_FAMILIES_BY_KIND = {family.kind: family for family in PAYLOAD_FAMILIES}
if len(_PAYLOAD_FAMILIES_BY_KIND) != len(PAYLOAD_FAMILIES):
    raise RuntimeError("payload inventory contains duplicate artifact kinds")
_MISSING_ARTIFACT_KINDS = set(ArtifactKind) - set(_PAYLOAD_FAMILIES_BY_KIND)
if _MISSING_ARTIFACT_KINDS:
    missing = ", ".join(sorted(kind.value for kind in _MISSING_ARTIFACT_KINDS))
    raise RuntimeError(f"payload inventory is missing artifact kinds: {missing}")


def payload_family(kind: ArtifactKind) -> PayloadFamily:
    try:
        return _PAYLOAD_FAMILIES_BY_KIND[kind]
    except KeyError as error:
        raise ValueError(f"unsupported payload artifact kind: {kind!r}") from error
