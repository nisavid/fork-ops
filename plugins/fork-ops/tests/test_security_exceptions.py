from __future__ import annotations

import hashlib
import json
import os
import runpy
import subprocess
import sys
import tomllib
from pathlib import Path
from typing import cast

import pytest

from fork_ops.security_exceptions import (
    PublicCommandRequest,
    RevocationPendingRequest,
    SecurityExceptionContractError,
    SecurityExceptionInventory,
    SecurityExceptionValidationError,
    StructuralProviderObservation,
    StructuralTransitionProjection,
    _freeze_projection_mapping,
    canonicalize_security_exception_projection,
    compute_security_exception_digest,
    compute_security_exception_lifecycle,
    compute_security_exception_record_digests,
    is_structural_security_exception_inventory,
    is_validated_security_exception_inventory,
    load_security_exception_contract,
    parse_public_security_exception_command,
    validate_advisory_reconciliation_projection,
    validate_lineage_issuance_projection,
    validate_provider_observation_envelope,
    validate_public_transition_projection,
    validate_response_clock_inventory,
    validate_security_exception_inventory,
)

ZERO_DIGEST = "0" * 64
LINEAGE_ID = "11111111-1111-4111-8111-111111111111"
EXCEPTION_ID = "22222222-2222-4222-8222-222222222222"
EFFECTS = {
    "inventory_recorded": True,
    "decision_recorded": True,
    "lifecycle_recorded": True,
    "security_posture_green": False,
    "admission_or_merge_authorized": False,
    "repository_control_relaxed_disabled_or_mutated": False,
    "assurance_validated": False,
    "baseline_or_release_eligible": False,
    "product_or_dogfood_authorized": False,
    "underlying_failure_cleared": False,
    "underlying_failure_remains_blocking": True,
}
REPOSITORY_ROOT = Path(__file__).resolve().parents[3]
PROJECTION_SCRIPT = REPOSITORY_ROOT / "scripts" / "security_exception_projections.py"


def test_packaged_security_exception_contract_is_verified() -> None:
    contract = load_security_exception_contract()

    assert contract.contract_version == "1.0"
    assert contract.artifact_kind == "security_exception_contract"
    assert contract.authority.login == "nisavid"
    assert contract.authority.database_id == 576874
    assert contract.authority.node_id == "MDQ6VXNlcjU3Njg3NA=="


def test_empty_public_and_private_projections_form_a_typed_inventory() -> None:
    inventory = validate_security_exception_inventory(
        {
            "artifact_kind": "security_exception_ledger",
            "schema_version": "1.0",
        },
        {
            "artifact_kind": "security_exception_private_projection",
            "schema_version": "1.0",
            "contract_version": "1.0",
            "status": "available",
            "records": [],
            "lineage_index": {
                "artifact_kind": "security_exception_lineage_index_projection",
                "schema_version": "1.0",
                "contract_version": "1.0",
                "entries": [],
            },
        },
        {
            "artifact_kind": "security_exception_authority_observation",
            "schema_version": "1.0",
            "contract_version": "1.0",
            "status": "available",
            "provider": "github",
            "authentication_status": "unverified_projection",
            "observed_at": "2026-08-12T12:00:00Z",
            "repository_full_name": "nisavid/fork-ops",
            "repository_database_id": 1241799725,
            "repository_node_id": "R_kgDOSgRcLQ",
            "login": "nisavid",
            "account_database_id": 576874,
            "account_node_id": "MDQ6VXNlcjU3Njg3NA==",
        },
        evaluated_at="2026-08-12T12:01:00Z",
    )

    assert inventory.public_records == ()
    assert inventory.private_records == ()
    assert inventory.lineages == ()
    assert inventory.contract_version == "1.0"


def test_caller_asserted_authority_can_only_form_a_structural_inventory() -> None:
    inventory = validate_security_exception_inventory(
        _public_ledger(),
        _private_projection(),
        _authority_observation(),
        evaluated_at="2026-08-12T12:01:00Z",
    )

    assert inventory.authority_status == "structural_unverified"
    assert is_structural_security_exception_inventory(inventory) is True
    assert is_validated_security_exception_inventory(inventory) is False


def test_structural_inventory_detaches_lineage_history_from_caller_mutation() -> None:
    record = _dependency_record()
    lineage = _lineage_entry(record)
    inventory = validate_security_exception_inventory(
        _public_ledger(record),
        _private_projection(lineage),
        _authority_observation(),
        evaluated_at="2026-08-12T12:01:00Z",
    )

    lineage["exception_id"] = "33333333-3333-4333-8333-333333333333"

    assert inventory.lineages[0].data["exception_id"] == EXCEPTION_ID


def test_validated_projection_snapshot_recursively_freezes_nested_values() -> None:
    nested_items = ["before"]
    nested_mapping: dict[str, object] = {"items": nested_items}
    source: dict[str, object] = {"nested": nested_mapping}

    frozen = _freeze_projection_mapping(source)
    nested_items.append("after")
    nested_mapping["other"] = "after"

    frozen_nested = cast(dict[str, object], frozen["nested"])
    assert frozen_nested == {"items": ("before",)}
    with pytest.raises(TypeError):
        cast(dict[str, object], frozen)["new"] = "value"
    with pytest.raises(TypeError):
        frozen_nested["new"] = "value"


def test_contract_hash_mismatch_is_refused(tmp_path: Path) -> None:
    contract_path = (
        REPOSITORY_ROOT
        / "plugins"
        / "fork-ops"
        / "src"
        / "fork_ops"
        / "security-exception-contract-1.0.json"
    )
    altered = tmp_path / contract_path.name
    altered.write_bytes(contract_path.read_bytes() + b"\n")

    with pytest.raises(SecurityExceptionContractError, match="embedded SHA-256"):
        load_security_exception_contract(altered)


def test_contract_reader_rejects_symlink_fifo_and_oversize(tmp_path: Path) -> None:
    contract_path = (
        REPOSITORY_ROOT
        / "plugins"
        / "fork-ops"
        / "src"
        / "fork_ops"
        / "security-exception-contract-1.0.json"
    )
    link = tmp_path / "contract-link.json"
    link.symlink_to(contract_path)
    with pytest.raises(SecurityExceptionContractError, match="unavailable"):
        load_security_exception_contract(link)

    fifo = tmp_path / "contract-fifo.json"
    os.mkfifo(fifo)
    with pytest.raises(SecurityExceptionContractError, match="unavailable"):
        load_security_exception_contract(fifo)

    oversized = tmp_path / "contract-large.json"
    oversized.write_bytes(b"x" * (1_048_576 + 1))
    with pytest.raises(SecurityExceptionContractError, match="unavailable"):
        load_security_exception_contract(oversized)


def test_contract_closes_kind_subject_pairs_and_all_v1_effects() -> None:
    contract = load_security_exception_contract().data
    enums = contract["enums"]
    state_machine = contract["state_machine"]
    assert isinstance(enums, dict)
    assert isinstance(state_machine, dict)
    exception_kinds = enums["exception_kinds"]
    actions = state_machine["actions"]
    assert isinstance(exception_kinds, list)
    assert isinstance(actions, dict)

    assert contract["kind_subject_matrix"] == {
        "finding_exception": ["dependency_advisory", "first_party_finding"],
        "control_bypass": ["repository_control", "assurance_gate"],
        "control_unavailability": ["repository_control", "assurance_gate"],
        "policy_deviation": [
            "security_invariant",
            "repository_control",
            "package_source",
            "assurance_gate",
        ],
    }
    assert contract["v1_total_effects"] == {
        "inventory_recorded": True,
        "decision_recorded": True,
        "lifecycle_recorded": True,
        "security_posture_green": False,
        "admission_or_merge_authorized": False,
        "repository_control_relaxed_disabled_or_mutated": False,
        "assurance_validated": False,
        "baseline_or_release_eligible": False,
        "product_or_dogfood_authorized": False,
        "underlying_failure_cleared": False,
        "underlying_failure_remains_blocking": True,
    }
    assert "bootstrap" not in exception_kinds
    assert "bootstrap" not in actions


def test_whole_inventory_rejects_a_kind_subject_pair_outside_the_closed_matrix() -> None:
    record = _dependency_record()
    record["kind"] = "control_bypass"

    with pytest.raises(SecurityExceptionValidationError, match="kind/subject pair"):
        validate_security_exception_inventory(
            _public_ledger(record),
            _private_projection(_lineage_entry(record)),
            _authority_observation(),
            evaluated_at="2026-08-12T12:01:00Z",
        )


def test_public_ledger_refuses_confidential_or_free_form_evidence_fields() -> None:
    record = _dependency_record()
    record["confidential_evidence"] = "private exploit details"

    with pytest.raises(SecurityExceptionValidationError, match="confidential_evidence"):
        validate_security_exception_inventory(
            _public_ledger(record),
            _private_projection(_lineage_entry(record)),
            _authority_observation(),
            evaluated_at="2026-08-12T12:01:00Z",
        )


@pytest.mark.parametrize(
    "reference",
    [
        "https://user:secret@github.com/advisories/GHSA-aaaa-bbbb-cccc",
        "https://github.com/ghp_FAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKE",
        "https://github.com/ghp_FAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKE/fork-ops/security/advisories/GHSA-aaaa-bbbb-cccc",
        "https://github.com/repos/nisavid/fork-ops/security-advisories/GHSA-aaaa-bbbb-cccc",
        "https://api.github.com/repos/nisavid/fork-ops/security-advisories/GHSA-aaaa-bbbb-cccc/extra",
        "https://osv.dev/vulnerability/GHSA-aaaa-bbbb-cccc/extra",
        "https://pypi.org/project/starlette/1.0.0/admin",
        "https://pypi.org/project/ghp_FAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKE",
        "https://pypi.org/project/pypi-" + "A" * 85,
        "https://localhost/advisories/GHSA-aaaa-bbbb-cccc",
        "https://github.com.evil.example/advisories/GHSA-aaaa-bbbb-cccc",
        "https://127.0.0.1/advisories/GHSA-aaaa-bbbb-cccc",
        "file:///tmp/private-evidence",
    ],
)
def test_public_references_reject_credentials_and_untrusted_hosts(reference: str) -> None:
    record = _dependency_record()
    record["public_references"] = [reference]

    with pytest.raises(
        SecurityExceptionValidationError,
        match="credential-free HTTPS|public_ledger is invalid",
    ):
        validate_security_exception_inventory(
            _public_ledger(record),
            _private_projection(_lineage_entry(record)),
            _authority_observation(),
            evaluated_at="2026-08-12T12:01:00Z",
        )


@pytest.mark.parametrize(
    "reference",
    [
        "https://github.com/advisories/GHSA-aaaa-bbbb-cccc",
        "https://github.com/nisavid/fork-ops/security/advisories/GHSA-aaaa-bbbb-cccc",
        "https://api.github.com/advisories/GHSA-aaaa-bbbb-cccc",
        "https://api.github.com/repos/nisavid/fork-ops/security-advisories/GHSA-aaaa-bbbb-cccc",
        "https://osv.dev/vulnerability/GHSA-aaaa-bbbb-cccc",
        "https://pypi.org/project/starlette/1.0.0",
    ],
)
def test_public_references_accept_closed_public_resource_paths(reference: str) -> None:
    record = _dependency_record()
    record["public_references"] = [reference]

    inventory = validate_security_exception_inventory(
        _public_ledger(record),
        _private_projection(_lineage_entry(record)),
        _authority_observation(),
        evaluated_at="2026-08-12T12:01:00Z",
    )

    assert len(inventory.public_records) == 1


def test_private_projection_unavailability_or_raw_claims_fail_whole_validation() -> None:
    with pytest.raises(SecurityExceptionValidationError, match="private projection is unavailable"):
        validate_security_exception_inventory(
            _public_ledger(),
            None,
            _authority_observation(),
            evaluated_at="2026-08-12T12:01:00Z",
        )

    projection = _private_projection()
    projection["raw_confidential_evidence"] = {"claim": "trust me"}
    with pytest.raises(SecurityExceptionValidationError, match="Additional properties"):
        validate_security_exception_inventory(
            _public_ledger(),
            projection,
            _authority_observation(),
            evaluated_at="2026-08-12T12:01:00Z",
        )


def test_sanitized_private_dependency_record_projects_into_whole_inventory() -> None:
    record = _dependency_record()
    record["visibility"] = "private"
    record.pop("public_references")
    projection = _private_projection(_lineage_entry(record))
    projection["records"] = [record]

    inventory = validate_security_exception_inventory(
        _public_ledger(),
        projection,
        _authority_observation(),
        evaluated_at="2026-08-12T12:01:00Z",
    )

    assert inventory.public_records == ()
    assert inventory.private_records[0].visibility == "private"
    assert inventory.private_records[0].package == "starlette"
    assert inventory.dependency_records == inventory.private_records


def test_authority_login_and_immutable_identity_must_all_match() -> None:
    observation = _authority_observation()
    observation["login"] = "renamed-login"

    with pytest.raises(SecurityExceptionValidationError, match="login"):
        validate_security_exception_inventory(
            _public_ledger(),
            _private_projection(),
            observation,
            evaluated_at="2026-08-12T12:01:00Z",
        )


def test_stale_caller_asserted_authority_observation_fails_closed() -> None:
    observation = _authority_observation()
    observation["observed_at"] = "2000-01-01T00:00:00Z"

    with pytest.raises(SecurityExceptionValidationError, match="stale"):
        validate_security_exception_inventory(
            _public_ledger(),
            _private_projection(),
            observation,
            evaluated_at="2026-08-12T12:01:00Z",
        )


def test_dependency_record_projects_to_the_typed_cutover_api() -> None:
    record = _dependency_record()

    inventory = validate_security_exception_inventory(
        _public_ledger(record),
        _private_projection(_lineage_entry(record)),
        _authority_observation(),
        evaluated_at="2026-08-12T12:01:00Z",
    )

    assert inventory.all_records == inventory.public_records
    assert len(inventory.dependency_records) == 1
    dependency = inventory.dependency_records[0]
    assert dependency.exception_id == EXCEPTION_ID
    assert dependency.lineage_id == LINEAGE_ID
    assert dependency.package == "starlette"
    assert dependency.locked_version == "1.0.0"
    assert dependency.dependency_scopes == ("runtime",)
    assert dependency.python_versions == ("3.11", "3.12", "3.13", "3.14")
    assert dependency.platforms == ("linux",)
    assert dependency.aliases == ("GHSA-aaaa-bbbb-cccc",)
    assert dependency.effects.security_posture_green is False
    assert dependency.effects.underlying_failure_remains_blocking is True


def test_record_cannot_claim_any_effect_outside_inventory_governance() -> None:
    record = _dependency_record()
    effects = dict(EFFECTS)
    effects["security_posture_green"] = True
    record["effects"] = effects

    with pytest.raises(SecurityExceptionValidationError, match="invalid"):
        validate_security_exception_inventory(
            _public_ledger(record),
            _private_projection(_lineage_entry(record)),
            _authority_observation(),
            evaluated_at="2026-08-12T12:01:00Z",
        )


def test_dependency_subject_key_is_exact_and_lineage_scoped() -> None:
    record = _dependency_record()
    record["subject_key"] = str(record["subject_key"]).replace("starlette", "Starlette")
    lineage = _lineage_entry(record)

    with pytest.raises(SecurityExceptionValidationError, match="dependency subject_key"):
        validate_security_exception_inventory(
            _public_ledger(record),
            _private_projection(lineage),
            _authority_observation(),
            evaluated_at="2026-08-12T12:01:00Z",
        )


@pytest.mark.parametrize(
    ("kind", "subject_kind", "subject_key"),
    (
        ("finding_exception", "first_party_finding", "finding:scanner:item-123"),
        ("control_bypass", "repository_control", "control:main-ruleset"),
        ("control_unavailability", "assurance_gate", "gate:release-validation"),
        (
            "policy_deviation",
            "security_invariant",
            "invariant:no-untrusted-execution",
        ),
        ("policy_deviation", "package_source", "package-source:pypi"),
    ),
)
def test_lineage_rejects_split_non_dependency_subjects(
    kind: str,
    subject_kind: str,
    subject_key: str,
) -> None:
    first_record = _non_dependency_record(
        kind=kind,
        subject_kind=subject_kind,
        subject_key=subject_key,
        exception_id="33333333-3333-4333-8333-333333333333",
        lineage_id="44444444-4444-4444-8444-444444444444",
    )
    first_lineage = _lineage_entry(first_record)
    _bind_test_lineage_subject_identity(
        first_record,
        first_lineage,
        f"attacker:first:{subject_key}",
    )
    second_record = _non_dependency_record(
        kind=kind,
        subject_kind=subject_kind,
        subject_key=subject_key,
        exception_id="55555555-5555-4555-8555-555555555555",
        lineage_id="66666666-6666-4666-8666-666666666666",
    )
    second_lineage = _lineage_entry(second_record)
    _bind_test_lineage_subject_identity(
        second_record,
        second_lineage,
        f"attacker:second:{subject_key}",
    )

    with pytest.raises(SecurityExceptionValidationError, match="subject identity"):
        validate_security_exception_inventory(
            _public_ledger(first_record, second_record),
            _private_projection(first_lineage, second_lineage),
            _authority_observation(),
            evaluated_at="2026-08-12T12:01:00Z",
        )


def test_lineage_rejects_anchor_reset_and_unlinked_subject_reuse() -> None:
    record, lineage = _dependency_lineage_for_states("approved", "renewed")
    first, second = lineage
    second["response_started_at"] = "2026-08-02T12:00:00Z"

    with pytest.raises(SecurityExceptionValidationError, match="anchor reset"):
        validate_security_exception_inventory(
            _public_ledger(record),
            _private_projection(first, second),
            _authority_observation(),
            evaluated_at="2026-08-12T12:01:00Z",
        )

    other = _dependency_record()
    other["exception_id"] = "33333333-3333-4333-8333-333333333333"
    other["lineage_id"] = "44444444-4444-4444-8444-444444444444"
    other["subject_key"] = (
        "dependency:44444444-4444-4444-8444-444444444444:starlette@1.0.0|"
        "scopes=runtime|python=3.11,3.12,3.13,3.14|platform=linux"
    )
    other["event_digest"] = "8" * 64
    other["record_digest"] = "9" * 64
    other_lineage = _lineage_entry(other)
    with pytest.raises(
        SecurityExceptionValidationError,
        match="subject identity reuse|dependency subject overlap",
    ):
        validate_security_exception_inventory(
            _public_ledger(_dependency_record(), other),
            _private_projection(_lineage_entry(_dependency_record()), other_lineage),
            _authority_observation(),
            evaluated_at="2026-08-12T12:01:00Z",
        )


def test_lineage_rejects_any_successor_after_a_terminal_state() -> None:
    record, lineage = _dependency_lineage_for_states(
        "approved",
        "revoked",
        "renewed",
    )

    with pytest.raises(SecurityExceptionValidationError, match="terminal state"):
        validate_security_exception_inventory(
            _public_ledger(record),
            _private_projection(*lineage),
            _authority_observation(),
            evaluated_at="2026-08-12T12:01:00Z",
        )


@pytest.mark.parametrize(
    "state",
    (
        "renewed",
        "revocation_pending",
        "recomputation_required",
        "revoked",
        "resolved",
    ),
)
def test_lineage_must_begin_with_the_approved_result(state: str) -> None:
    record = _dependency_record()
    record["state"] = state
    lineage = _lineage_entry(record)

    with pytest.raises(SecurityExceptionValidationError, match="begin with approved"):
        validate_security_exception_inventory(
            _public_ledger(record),
            _private_projection(lineage),
            _authority_observation(),
            evaluated_at="2026-08-12T12:01:00Z",
        )


@pytest.mark.parametrize("state", ("expired", "withdrawn"))
def test_lineage_rejects_states_outside_the_closed_record_state_set(state: str) -> None:
    record = _dependency_record()
    record["state"] = state
    lineage = _lineage_entry(record)

    with pytest.raises(SecurityExceptionValidationError, match="invalid"):
        validate_security_exception_inventory(
            _public_ledger(record),
            _private_projection(lineage),
            _authority_observation(),
            evaluated_at="2026-08-12T12:01:00Z",
        )


@pytest.mark.parametrize(
    "states",
    (
        ("approved", "renewed"),
        ("approved", "renewed", "renewed"),
        ("approved", "revoked"),
        ("approved", "renewed", "revoked"),
        ("approved", "revocation_pending"),
        ("approved", "renewed", "revocation_pending"),
        ("approved", "revocation_pending", "recomputation_required"),
        (
            "approved",
            "revocation_pending",
            "recomputation_required",
            "revoked",
        ),
        ("approved", "resolved"),
        ("approved", "renewed", "resolved"),
        (
            "approved",
            "revocation_pending",
            "recomputation_required",
            "resolved",
        ),
    ),
)
def test_lineage_accepts_every_closed_transition_edge(states: tuple[str, ...]) -> None:
    record, lineage = _dependency_lineage_for_states(*states)

    inventory = validate_security_exception_inventory(
        _public_ledger(record),
        _private_projection(*lineage),
        _authority_observation(),
        evaluated_at="2026-08-12T12:01:00Z",
    )

    assert inventory.public_records[0].state == states[-1]


@pytest.mark.parametrize(
    "states",
    (
        ("approved", "approved"),
        ("approved", "recomputation_required"),
        ("approved", "renewed", "approved"),
        ("approved", "renewed", "recomputation_required"),
        ("approved", "revocation_pending", "approved"),
        ("approved", "revocation_pending", "renewed"),
        ("approved", "revocation_pending", "revocation_pending"),
        ("approved", "revocation_pending", "revoked"),
        ("approved", "revocation_pending", "resolved"),
        (
            "approved",
            "revocation_pending",
            "recomputation_required",
            "approved",
        ),
        (
            "approved",
            "revocation_pending",
            "recomputation_required",
            "renewed",
        ),
        (
            "approved",
            "revocation_pending",
            "recomputation_required",
            "revocation_pending",
        ),
        (
            "approved",
            "revocation_pending",
            "recomputation_required",
            "recomputation_required",
        ),
    ),
)
def test_lineage_rejects_every_nonterminal_edge_outside_the_closed_actions(
    states: tuple[str, ...],
) -> None:
    record, lineage = _dependency_lineage_for_states(*states)

    with pytest.raises(SecurityExceptionValidationError, match="forbidden state transition"):
        validate_security_exception_inventory(
            _public_ledger(record),
            _private_projection(*lineage),
            _authority_observation(),
            evaluated_at="2026-08-12T12:01:00Z",
        )


def test_renewal_rotates_to_a_fresh_successor_exception_id() -> None:
    record, lineage = _dependency_lineage_for_states("approved", "renewed")

    inventory = validate_security_exception_inventory(
        _public_ledger(record),
        _private_projection(*lineage),
        _authority_observation(),
        evaluated_at="2026-08-12T12:01:00Z",
    )

    assert lineage[0]["exception_id"] != lineage[1]["exception_id"]
    assert record["exception_id"] == lineage[1]["exception_id"]
    assert record["predecessor_record_digest"] == lineage[0]["record_digest"]
    assert inventory.public_records[0].exception_id == lineage[1]["exception_id"]


def test_renewal_rejects_a_missing_exception_id_rotation() -> None:
    record, lineage = _dependency_lineage_for_states(
        "approved",
        "renewed",
        exception_ids=(EXCEPTION_ID, EXCEPTION_ID),
    )

    with pytest.raises(SecurityExceptionValidationError, match="renewal must rotate"):
        validate_security_exception_inventory(
            _public_ledger(record),
            _private_projection(*lineage),
            _authority_observation(),
            evaluated_at="2026-08-12T12:01:00Z",
        )


def test_nonrenewal_transition_rejects_an_exception_id_rotation() -> None:
    record, lineage = _dependency_lineage_for_states(
        "approved",
        "revocation_pending",
        exception_ids=(EXCEPTION_ID, "77777777-7777-4777-8777-777777777777"),
    )

    with pytest.raises(SecurityExceptionValidationError, match="must retain"):
        validate_security_exception_inventory(
            _public_ledger(record),
            _private_projection(*lineage),
            _authority_observation(),
            evaluated_at="2026-08-12T12:01:00Z",
        )


def test_renewal_rejects_reusing_an_earlier_exception_id() -> None:
    record, lineage = _dependency_lineage_for_states(
        "approved",
        "renewed",
        "renewed",
        exception_ids=(
            EXCEPTION_ID,
            "77777777-7777-4777-8777-777777777777",
            EXCEPTION_ID,
        ),
    )

    with pytest.raises(SecurityExceptionValidationError, match="history-unique"):
        validate_security_exception_inventory(
            _public_ledger(record),
            _private_projection(*lineage),
            _authority_observation(),
            evaluated_at="2026-08-12T12:01:00Z",
        )


def test_lineages_reject_a_cross_lineage_historical_exception_id_collision() -> None:
    first_record, first_lineage = _dependency_lineage_for_states(
        "approved",
        "renewed",
    )
    collision_id = str(first_lineage[0]["exception_id"])
    second_record = _non_dependency_record(
        kind="finding_exception",
        subject_kind="first_party_finding",
        subject_key="finding:scanner:item-456",
        exception_id="99999999-9999-4999-8999-999999999999",
        lineage_id="66666666-6666-4666-8666-666666666666",
    )
    second_record["exception_id"] = collision_id
    second_lineage = _lineage_entry(second_record)
    _bind_test_lineage_subject_identity(
        second_record,
        second_lineage,
        "first_party_finding:finding:scanner:item-456",
    )

    with pytest.raises(SecurityExceptionValidationError, match="collision"):
        validate_security_exception_inventory(
            _public_ledger(first_record, second_record),
            _private_projection(*first_lineage, second_lineage),
            _authority_observation(),
            evaluated_at="2026-08-12T12:01:00Z",
        )


def test_current_record_expiry_must_equal_the_lineage_head() -> None:
    record = _dependency_record()
    head = _lineage_entry(record)
    head["expires_at"] = "2026-08-26T12:00:00Z"

    with pytest.raises(SecurityExceptionValidationError, match="exactly equal"):
        validate_security_exception_inventory(
            _public_ledger(record),
            _private_projection(head),
            _authority_observation(),
            evaluated_at="2026-08-12T12:01:00Z",
        )


def test_current_approval_anchor_must_equal_the_approved_event_time() -> None:
    record = _dependency_record()
    head = _lineage_entry(record)
    head["effective_at"] = "2026-08-03T12:00:00Z"

    with pytest.raises(SecurityExceptionValidationError, match="last_approval_or_renewal"):
        validate_security_exception_inventory(
            _public_ledger(record),
            _private_projection(head),
            _authority_observation(),
            evaluated_at="2026-08-12T12:01:00Z",
        )


def test_nonrenewal_transition_cannot_reset_the_last_approval_anchor() -> None:
    record, lineage = _dependency_lineage_for_states(
        "approved",
        "revocation_pending",
        "recomputation_required",
    )
    record["last_approval_or_renewal"] = lineage[-1]["effective_at"]
    _bind_test_lineage_subject_identity(
        record,
        lineage[-1],
        str(lineage[-1]["subject_identity"]),
    )

    with pytest.raises(
        SecurityExceptionValidationError,
        match="last_approval_or_renewal",
    ):
        validate_security_exception_inventory(
            _public_ledger(record),
            _private_projection(*lineage),
            _authority_observation(),
            evaluated_at="2026-08-12T12:01:00Z",
        )


def test_nonrenewal_lineage_event_cannot_be_from_the_future() -> None:
    record, lineage = _dependency_lineage_for_states("approved", "revoked")
    lineage[-1]["effective_at"] = "2026-08-13T12:00:00Z"
    _bind_test_lineage_subject_identity(
        record,
        lineage[-1],
        str(lineage[-1]["subject_identity"]),
    )

    with pytest.raises(SecurityExceptionValidationError, match="effective_at is from the future"):
        validate_security_exception_inventory(
            _public_ledger(record),
            _private_projection(*lineage),
            _authority_observation(),
            evaluated_at="2026-08-12T12:01:00Z",
        )


def test_lineage_rejects_alias_or_evidence_revision_reset() -> None:
    record, lineage = _dependency_lineage_for_states("approved", "renewed")
    first, second = lineage
    first["alias_revision"] = 2

    with pytest.raises(SecurityExceptionValidationError, match="revision reset"):
        validate_security_exception_inventory(
            _public_ledger(record),
            _private_projection(first, second),
            _authority_observation(),
            evaluated_at="2026-08-12T12:01:00Z",
        )


def test_lineage_rejects_exception_id_reuse_and_dependency_overlap() -> None:
    first = _dependency_record()
    second = _dependency_record()
    second["lineage_id"] = "44444444-4444-4444-8444-444444444444"
    second["package"] = "httpx"
    second["subject_key"] = (
        "dependency:44444444-4444-4444-8444-444444444444:httpx@1.0.0|"
        "scopes=runtime|python=3.11,3.12,3.13,3.14|platform=linux"
    )
    second["event_digest"] = "8" * 64
    second["record_digest"] = "9" * 64
    second_lineage = _lineage_entry(second)
    second_lineage["subject_identity"] = (
        "dependency:httpx@1.0.0|scopes=runtime|"
        "python=3.11,3.12,3.13,3.14|platform=linux"
    )

    with pytest.raises(SecurityExceptionValidationError, match="exception identifier reuse"):
        validate_security_exception_inventory(
            _public_ledger(first, second),
            _private_projection(_lineage_entry(first), second_lineage),
            _authority_observation(),
            evaluated_at="2026-08-12T12:01:00Z",
        )

    second["exception_id"] = "33333333-3333-4333-8333-333333333333"
    second["package"] = "starlette"
    second["dependency_scopes"] = ["runtime", "test"]
    second["subject_key"] = (
        "dependency:44444444-4444-4444-8444-444444444444:starlette@1.0.0|"
        "scopes=runtime,test|python=3.11,3.12,3.13,3.14|platform=linux"
    )
    second_lineage = _lineage_entry(second)
    second_lineage["subject_identity"] = (
        "dependency:starlette@1.0.0|scopes=runtime,test|"
        "python=3.11,3.12,3.13,3.14|platform=linux"
    )
    with pytest.raises(SecurityExceptionValidationError, match="dependency subject overlap"):
        validate_security_exception_inventory(
            _public_ledger(first, second),
            _private_projection(_lineage_entry(first), second_lineage),
            _authority_observation(),
            evaluated_at="2026-08-12T12:01:00Z",
        )


def test_dependency_lineage_subject_identity_must_be_exact() -> None:
    record = _dependency_record()
    lineage = _lineage_entry(record)
    lineage["subject_identity"] = "caller-asserted-identity"

    with pytest.raises(SecurityExceptionValidationError, match="subject identity"):
        validate_security_exception_inventory(
            _public_ledger(record),
            _private_projection(lineage),
            _authority_observation(),
            evaluated_at="2026-08-12T12:01:00Z",
        )


def test_canonicalization_and_domain_digests_match_contract_golden_vectors() -> None:
    payload = {
        "sequence": 1,
        "exception_id": EXCEPTION_ID,
        "action": "approve",
    }

    assert canonicalize_security_exception_projection(payload) == (
        b'{"action":"approve","exception_id":"22222222-2222-4222-8222-222222222222",'
        b'"sequence":1}'
    )
    assert compute_security_exception_digest("proposal", payload) == (
        "aff2929302e1925f95e29787cdd598283dcbcea853cdec8a049ed7352f34650c"
    )
    assert compute_security_exception_digest("event", payload) == (
        "a73af83e681a554c9ebcfed7a16282801fbe3c715600af779d37d87b85e14b83"
    )
    assert compute_security_exception_digest("record", payload) == (
        "8501ddb0ba945fb6da90508625784153b7322254918a6dc9ce37737ebe3445c2"
    )
    assert compute_security_exception_digest("result", payload) == (
        "8eca3297b427ce0a71ef5e56ddf39752f12f6484a17423df54e2f3fe782799d4"
    )
    assert canonicalize_security_exception_projection({"value": "e\u0301"}) == (
        '{"value":"é"}'.encode()
    )
    with pytest.raises(SecurityExceptionValidationError, match="floating-point"):
        canonicalize_security_exception_projection({"value": 1.5})


def test_caller_chosen_consistent_lineage_digests_are_recomputed() -> None:
    record = _dependency_record()
    lineage = _lineage_entry(record)
    record["evidence_digest"] = "a" * 64
    record["proposal_digest"] = "b" * 64
    record["event_digest"] = "c" * 64
    record["result_digest"] = "d" * 64
    record["record_digest"] = "e" * 64
    lineage["event_digest"] = record["event_digest"]
    lineage["result_digest"] = record["result_digest"]
    lineage["record_digest"] = record["record_digest"]

    with pytest.raises(SecurityExceptionValidationError, match="canonical .* digest"):
        validate_security_exception_inventory(
            _public_ledger(record),
            _private_projection(lineage),
            _authority_observation(),
            evaluated_at="2026-08-12T12:01:00Z",
        )


def test_record_head_digest_binds_the_complete_security_record() -> None:
    record = _dependency_record()
    lineage = _lineage_entry(record)
    original_record_digest = record["record_digest"]

    record["aliases"] = ["CVE-2099-9999"]
    record["severity"] = "low"
    record["owner"] = "replacement-owner"
    record["compensating_control_ids"] = ["replacement-control"]

    recomputed = compute_security_exception_record_digests(record, lineage)

    assert recomputed.record_digest != original_record_digest


def test_record_rewrite_cannot_retain_the_prior_lineage_head() -> None:
    record = _dependency_record()
    lineage = _lineage_entry(record)
    prior_record_digest = record["record_digest"]
    record["aliases"] = ["CVE-2099-9999"]
    record["severity"] = "low"
    recomputed = compute_security_exception_record_digests(record, lineage)
    record.update(
        {
            "evidence_digest": recomputed.evidence_digest,
            "proposal_digest": recomputed.proposal_digest,
            "event_digest": recomputed.event_digest,
            "result_digest": recomputed.result_digest,
            "record_digest": prior_record_digest,
        }
    )
    lineage.update(
        {
            "event_digest": recomputed.event_digest,
            "result_digest": recomputed.result_digest,
            "record_digest": prior_record_digest,
        }
    )

    with pytest.raises(SecurityExceptionValidationError, match="canonical record digest"):
        validate_security_exception_inventory(
            _public_ledger(record),
            _private_projection(lineage),
            _authority_observation(),
            evaluated_at="2026-08-12T12:01:00Z",
        )


def test_record_digest_projections_match_independent_known_literals() -> None:
    record = _dependency_record()
    lineage = _lineage_entry(record)

    assert record["evidence_digest"] == (
        "5ac35c37b28be6e14fc3a58a9ef3974b6bea25d24aad6c61d1f90f2c0c38852c"
    )
    assert record["proposal_digest"] == (
        "315dcb5645967c6da389a64252e591d52e4759876fd55137d5c89176d45d9188"
    )
    assert lineage["event_digest"] == (
        "7b61df1df3809dc4d379d528da3be3db08a8866fa65c1ceedf8d0a8c492ac982"
    )
    assert record["result_digest"] == (
        "4f7b1c210166e36c440a7cece1bf40e890831363234efd182fde92a7ca1cb30e"
    )
    assert lineage["record_digest"] == (
        "518c6ba02077806f1662d00af2b9dc9d8a76d6419ca8906dc5f4bcddd9e7d3ba"
    )


def test_public_command_parser_enforces_exact_six_and_eight_token_grammars() -> None:
    current_inventory = _structural_dependency_inventory()
    approve = parse_public_security_exception_command(
        f"/security-exception approve 1.0 {EXCEPTION_ID} {'a' * 64} none",
        comment_node_id="IC_approve901",
    )
    assert isinstance(approve, PublicCommandRequest)
    assert approve.action == "approve"
    assert approve.exception_id == EXCEPTION_ID
    assert approve.proposal_digest == "a" * 64
    assert approve.predecessor_effective_event_digest is None
    assert approve.comment_node_id == "IC_approve901"

    renew = parse_public_security_exception_command(
        f"/security-exception renew 1.0 {EXCEPTION_ID} {'b' * 64} {'c' * 64}",
        comment_node_id="IC_renew901",
    )
    assert isinstance(renew, PublicCommandRequest)
    assert renew.action == "renew"
    assert renew.predecessor_effective_event_digest == "c" * 64

    revoke = parse_public_security_exception_command(
        f"/security-exception revoke 1.0 {EXCEPTION_ID} {'d' * 64} {'e' * 64}",
        comment_node_id="IC_revoke901",
        current_inventory=current_inventory,
    )
    assert isinstance(revoke, PublicCommandRequest)
    assert revoke.action == "revoke"
    assert revoke.predecessor_effective_event_digest == "e" * 64

    withdraw = parse_public_security_exception_command(
        (
            f"/security-exception withdraw-invalid 1.0 {EXCEPTION_ID} {'b' * 64} "
            f"{'c' * 64} IC_malformed900 {'d' * 64}"
        ),
        comment_node_id="IC_withdraw902",
        current_inventory=current_inventory,
    )
    assert isinstance(withdraw, PublicCommandRequest)
    assert withdraw.action == "withdraw_invalid"
    assert withdraw.pending_transition_digest == "b" * 64
    assert withdraw.predecessor_effective_event_digest == "c" * 64
    assert withdraw.malformed_comment_node_id == "IC_malformed900"
    assert withdraw.malformed_raw_comment_digest == "d" * 64

    with pytest.raises(SecurityExceptionValidationError, match="exact public command grammar"):
        parse_public_security_exception_command(
            f"/security-exception approve 1.0 {EXCEPTION_ID} {'a' * 64} none extra",
            comment_node_id="IC_invalid903",
        )
    with pytest.raises(SecurityExceptionValidationError, match="exact public command grammar"):
        parse_public_security_exception_command(
            f"/security-exception approve 1.0 {EXCEPTION_ID} {'a' * 64} {ZERO_DIGEST}",
            comment_node_id="IC_invalid904",
        )
    with pytest.raises(SecurityExceptionValidationError, match="exact public command grammar"):
        parse_public_security_exception_command(
            f"/security-exception Approve 1.0 {EXCEPTION_ID} {'a' * 64} none",
            comment_node_id="IC_invalid905",
        )
    with pytest.raises(SecurityExceptionValidationError, match="known public exception ID"):
        parse_public_security_exception_command(
            (
                "/security-exception revoke 1.0 "
                f"33333333-3333-4333-8333-333333333333 {'a' * 64} {'b' * 64}"
            ),
            comment_node_id="IC_unknown906",
            current_inventory=current_inventory,
        )


def test_renew_transition_projection_binds_a_fresh_successor_id_to_current_head() -> None:
    current_inventory = _structural_dependency_inventory()
    predecessor_digest = str(current_inventory.lineages[0].data["event_digest"])
    successor_id = "77777777-7777-4777-8777-777777777777"
    request = parse_public_security_exception_command(
        f"/security-exception renew 1.0 {successor_id} {'b' * 64} {predecessor_digest}",
        comment_node_id="IC_renew_successor",
    )
    assert isinstance(request, PublicCommandRequest)
    projection: dict[str, object] = {
        "artifact_kind": "security_exception_transition_projection",
        "schema_version": "1.0",
        "contract_version": "1.0",
        "visibility": "public",
        "action": "renew",
        "from_state": "approved",
        "to_state": "renewed",
        "exception_id": successor_id,
        "predecessor_effective_event_digest": predecessor_digest,
        "current_head_effective_event_digest": predecessor_digest,
        "proposal_digest": "b" * 64,
        "request_comment_node_id": "IC_renew_successor",
        "request_raw_comment_digest": request.raw_comment_digest,
        "authority_login": "nisavid",
        "authority_database_id": 576874,
        "authority_node_id": "MDQ6VXNlcjU3Njg3NA==",
        "persistence_status": "unverified_projection",
        "persisted_result_digest": ZERO_DIGEST,
    }
    _seal_transition_projection(projection)

    transition = validate_public_transition_projection(
        request,
        projection,
        current_state="approved",
        current_inventory=current_inventory,
        evaluated_at="2026-08-12T12:02:00Z",
    )

    assert transition.to_state == "renewed"


def test_renew_transition_projection_rejects_a_reused_exception_id() -> None:
    current_inventory = _structural_dependency_inventory()
    predecessor_digest = str(current_inventory.lineages[0].data["event_digest"])
    request = parse_public_security_exception_command(
        f"/security-exception renew 1.0 {EXCEPTION_ID} {'b' * 64} {predecessor_digest}",
        comment_node_id="IC_renew_reuse",
    )
    assert isinstance(request, PublicCommandRequest)
    projection: dict[str, object] = {
        "artifact_kind": "security_exception_transition_projection",
        "schema_version": "1.0",
        "contract_version": "1.0",
        "visibility": "public",
        "action": "renew",
        "from_state": "approved",
        "to_state": "renewed",
        "exception_id": EXCEPTION_ID,
        "predecessor_effective_event_digest": predecessor_digest,
        "current_head_effective_event_digest": predecessor_digest,
        "proposal_digest": "b" * 64,
        "request_comment_node_id": "IC_renew_reuse",
        "request_raw_comment_digest": request.raw_comment_digest,
        "authority_login": "nisavid",
        "authority_database_id": 576874,
        "authority_node_id": "MDQ6VXNlcjU3Njg3NA==",
        "persistence_status": "unverified_projection",
        "persisted_result_digest": ZERO_DIGEST,
    }
    _seal_transition_projection(projection)

    with pytest.raises(SecurityExceptionValidationError, match="fresh successor"):
        validate_public_transition_projection(
            request,
            projection,
            current_state="approved",
            current_inventory=current_inventory,
            evaluated_at="2026-08-12T12:02:00Z",
        )


def test_renew_transition_projection_rejects_a_historical_exception_id() -> None:
    record, lineage = _dependency_lineage_for_states("approved", "renewed")
    current_inventory = validate_security_exception_inventory(
        _public_ledger(record),
        _private_projection(*lineage),
        _authority_observation(),
        evaluated_at="2026-08-12T12:01:00Z",
    )
    predecessor_digest = str(current_inventory.lineages[-1].data["event_digest"])
    request = parse_public_security_exception_command(
        f"/security-exception renew 1.0 {EXCEPTION_ID} {'b' * 64} {predecessor_digest}",
        comment_node_id="IC_renew_historical_reuse",
    )
    assert isinstance(request, PublicCommandRequest)
    projection: dict[str, object] = {
        "artifact_kind": "security_exception_transition_projection",
        "schema_version": "1.0",
        "contract_version": "1.0",
        "visibility": "public",
        "action": "renew",
        "from_state": "renewed",
        "to_state": "renewed",
        "exception_id": EXCEPTION_ID,
        "predecessor_effective_event_digest": predecessor_digest,
        "current_head_effective_event_digest": predecessor_digest,
        "proposal_digest": "b" * 64,
        "request_comment_node_id": "IC_renew_historical_reuse",
        "request_raw_comment_digest": request.raw_comment_digest,
        "authority_login": "nisavid",
        "authority_database_id": 576874,
        "authority_node_id": "MDQ6VXNlcjU3Njg3NA==",
        "persistence_status": "unverified_projection",
        "persisted_result_digest": ZERO_DIGEST,
    }
    _seal_transition_projection(projection)

    with pytest.raises(SecurityExceptionValidationError, match="fresh successor"):
        validate_public_transition_projection(
            request,
            projection,
            current_state="renewed",
            current_inventory=current_inventory,
            evaluated_at="2026-08-12T12:02:00Z",
        )


def test_malformed_exact_revoke_prefix_only_requests_revocation_pending() -> None:
    current_inventory = _structural_dependency_inventory()
    predecessor_digest = str(current_inventory.lineages[0].data["event_digest"])
    malformed = parse_public_security_exception_command(
        f"/security-exception revoke 1.0 {EXCEPTION_ID} missing-digests",
        comment_node_id="IC_malformed904",
        current_inventory=current_inventory,
    )

    assert isinstance(malformed, RevocationPendingRequest)
    assert malformed.action == "malformed_revoke"
    assert malformed.exception_id == EXCEPTION_ID
    assert malformed.comment_node_id == "IC_malformed904"
    assert malformed.raw_comment_digest == hashlib.sha256(
        (
            f"/security-exception revoke 1.0 {EXCEPTION_ID} missing-digests"
        ).encode()
    ).hexdigest()

    projection: dict[str, object] = {
        "artifact_kind": "security_exception_transition_projection",
        "schema_version": "1.0",
        "contract_version": "1.0",
        "visibility": "public",
        "action": "malformed_revoke",
        "from_state": "approved",
        "to_state": "revocation_pending",
        "exception_id": EXCEPTION_ID,
        "predecessor_effective_event_digest": predecessor_digest,
        "current_head_effective_event_digest": predecessor_digest,
        "request_comment_node_id": "IC_malformed904",
        "request_raw_comment_digest": malformed.raw_comment_digest,
        "authority_login": "nisavid",
        "authority_database_id": 576874,
        "authority_node_id": "MDQ6VXNlcjU3Njg3NA==",
        "persistence_status": "unverified_projection",
        "persisted_result_digest": "e" * 64,
    }
    _seal_transition_projection(projection)
    transition = validate_public_transition_projection(
        malformed,
        projection,
        current_state="approved",
        current_inventory=current_inventory,
        evaluated_at="2026-08-12T12:02:00Z",
    )
    assert transition.to_state == "revocation_pending"

    with pytest.raises(SecurityExceptionValidationError, match="exact public command grammar"):
        parse_public_security_exception_command(
            f"/security-exception revoke 2.0 {EXCEPTION_ID} missing-digests",
            comment_node_id="IC_wrongversion905",
            current_inventory=_structural_dependency_inventory(),
        )


def test_transition_projection_never_claims_authenticated_persistence() -> None:
    current_inventory = _structural_empty_inventory()
    request = parse_public_security_exception_command(
        f"/security-exception approve 1.0 {EXCEPTION_ID} {'a' * 64} none",
        comment_node_id="IC_approve905",
    )
    assert isinstance(request, PublicCommandRequest)
    projection: dict[str, object] = {
        "artifact_kind": "security_exception_transition_projection",
        "schema_version": "1.0",
        "contract_version": "1.0",
        "visibility": "public",
        "action": "approve",
        "from_state": "proposal",
        "to_state": "approved",
        "exception_id": EXCEPTION_ID,
        "predecessor_effective_event_digest": "none",
        "current_head_effective_event_digest": "none",
        "proposal_digest": "a" * 64,
        "request_comment_node_id": "IC_approve905",
        "request_raw_comment_digest": request.raw_comment_digest,
        "authority_login": "nisavid",
        "authority_database_id": 576874,
        "authority_node_id": "MDQ6VXNlcjU3Njg3NA==",
        "persistence_status": "unverified_projection",
        "persisted_result_digest": ZERO_DIGEST,
    }
    _seal_transition_projection(projection)

    missing_status = dict(projection)
    missing_status.pop("persistence_status")
    with pytest.raises(SecurityExceptionValidationError, match="persistence_status"):
        validate_public_transition_projection(
            request,
            missing_status,
            current_state="proposal",
            current_inventory=current_inventory,
            evaluated_at="2026-08-12T12:02:00Z",
        )

    transition = validate_public_transition_projection(
        request,
        projection,
        current_state="proposal",
        current_inventory=current_inventory,
        evaluated_at="2026-08-12T12:02:00Z",
    )
    assert transition.to_state == "approved"
    assert isinstance(transition, StructuralTransitionProjection)
    assert transition.trust_status == "structural_unverified"

    projection["persisted_result_digest"] = "e" * 64
    with pytest.raises(SecurityExceptionValidationError, match="canonical transition result"):
        validate_public_transition_projection(
            request,
            projection,
            current_state="proposal",
            current_inventory=current_inventory,
            evaluated_at="2026-08-12T12:02:00Z",
        )

    _seal_transition_projection(projection)
    projection["persisted_at"] = "2026-08-12T12:03:00Z"
    _seal_transition_projection(projection)
    projection["persisted_at"] = "2026-08-12T12:03:00Z"
    with pytest.raises(SecurityExceptionValidationError, match="future"):
        validate_public_transition_projection(
            request,
            projection,
            current_state="proposal",
            current_inventory=current_inventory,
            evaluated_at="2026-08-12T12:02:00Z",
        )


def test_transition_projection_rejects_stale_persistence_at_evaluation() -> None:
    current_inventory = _structural_empty_inventory()
    request = parse_public_security_exception_command(
        f"/security-exception approve 1.0 {EXCEPTION_ID} {'a' * 64} none",
        comment_node_id="IC_approve_stale",
    )
    assert isinstance(request, PublicCommandRequest)
    projection: dict[str, object] = {
        "artifact_kind": "security_exception_transition_projection",
        "schema_version": "1.0",
        "contract_version": "1.0",
        "visibility": "public",
        "action": "approve",
        "from_state": "proposal",
        "to_state": "approved",
        "exception_id": EXCEPTION_ID,
        "predecessor_effective_event_digest": "none",
        "current_head_effective_event_digest": "none",
        "proposal_digest": "a" * 64,
        "request_comment_node_id": "IC_approve_stale",
        "request_raw_comment_digest": request.raw_comment_digest,
        "authority_login": "nisavid",
        "authority_database_id": 576874,
        "authority_node_id": "MDQ6VXNlcjU3Njg3NA==",
        "persistence_status": "unverified_projection",
        "persisted_result_digest": ZERO_DIGEST,
    }
    _seal_transition_projection(
        projection,
        observed_at="2000-01-01T00:00:00Z",
        persisted_at="2000-01-01T00:01:00Z",
    )

    with pytest.raises(SecurityExceptionValidationError, match="stale"):
        validate_public_transition_projection(
            request,
            projection,
            current_state="proposal",
            current_inventory=current_inventory,
            evaluated_at="2026-08-12T12:02:00Z",
        )


def test_withdraw_invalid_binds_pending_predecessor_and_comment_and_forces_recompute() -> None:
    record, lineage = _dependency_lineage_for_states(
        "approved",
        "revocation_pending",
    )
    current_inventory = validate_security_exception_inventory(
        _public_ledger(record),
        _private_projection(*lineage),
        _authority_observation(),
        evaluated_at="2026-08-12T12:01:00Z",
    )
    predecessor_digest = str(current_inventory.lineages[-1].data["event_digest"])
    command = (
        f"/security-exception withdraw-invalid 1.0 {EXCEPTION_ID} {'b' * 64} "
        f"{predecessor_digest} IC_malformed900 {'d' * 64}"
    )
    request = parse_public_security_exception_command(
        command,
        comment_node_id="IC_withdraw906",
        current_inventory=current_inventory,
    )
    assert isinstance(request, PublicCommandRequest)
    projection: dict[str, object] = {
        "artifact_kind": "security_exception_transition_projection",
        "schema_version": "1.0",
        "contract_version": "1.0",
        "visibility": "public",
        "action": "withdraw_invalid",
        "from_state": "revocation_pending",
        "to_state": "recomputation_required",
        "exception_id": EXCEPTION_ID,
        "pending_transition_digest": "b" * 64,
        "predecessor_effective_event_digest": predecessor_digest,
        "current_head_effective_event_digest": predecessor_digest,
        "malformed_comment_node_id": "IC_malformed900",
        "malformed_raw_comment_digest": "d" * 64,
        "request_comment_node_id": "IC_withdraw906",
        "request_raw_comment_digest": request.raw_comment_digest,
        "authority_login": "nisavid",
        "authority_database_id": 576874,
        "authority_node_id": "MDQ6VXNlcjU3Njg3NA==",
        "persistence_status": "unverified_projection",
        "persisted_result_digest": "e" * 64,
        "clears": "pending_transition_only",
        "restores_snapshot": False,
        "forces_fresh_recomputation": True,
    }
    _seal_transition_projection(projection)

    transition = validate_public_transition_projection(
        request,
        projection,
        current_state="revocation_pending",
        current_inventory=current_inventory,
        evaluated_at="2026-08-12T12:02:00Z",
    )
    assert transition.to_state == "recomputation_required"
    projection["malformed_raw_comment_digest"] = "f" * 64
    with pytest.raises(SecurityExceptionValidationError, match="does not bind"):
        validate_public_transition_projection(
            request,
            projection,
            current_state="revocation_pending",
            current_inventory=current_inventory,
            evaluated_at="2026-08-12T12:02:00Z",
        )


def test_provider_observation_requires_two_complete_identical_structural_passes() -> None:
    envelope = _provider_observation()

    observation = validate_provider_observation_envelope(
        envelope,
        evaluated_at="2026-08-12T12:01:00Z",
    )
    assert observation.valid_until == "2026-08-12T12:15:00Z"
    assert observation.semantic_digest == envelope["semantic_digest"]
    assert isinstance(observation, StructuralProviderObservation)
    assert observation.trust_status == "structural_unverified"

    passes = envelope["passes"]
    assert isinstance(passes, list)
    second_pass = passes[1]
    assert isinstance(second_pass, dict)
    second_pass["semantic_digest"] = "b" * 64
    with pytest.raises(SecurityExceptionValidationError, match="semantic-identical"):
        validate_provider_observation_envelope(
            envelope,
            evaluated_at="2026-08-12T12:01:00Z",
        )


def test_semantic_identical_provider_passes_allow_distinct_receipt_times() -> None:
    envelope = _provider_observation()
    producer_provenance = envelope["producer_provenance"]
    passes = envelope["passes"]
    assert isinstance(passes, list)
    second_pass = passes[1]
    assert isinstance(second_pass, dict)
    pages = second_pass["pages"]
    assert isinstance(pages, list)
    for page in pages:
        assert isinstance(page, dict)
        page["provider_date"] = "2026-08-12T12:01:00Z"
        page["receipt_digest"] = _test_digest(
            "provider_receipt",
            {
                "producer_provenance": producer_provenance,
                "response_digest": page["response_digest"],
                "provider_date": page["provider_date"],
            },
        )

    observation = validate_provider_observation_envelope(
        envelope,
        evaluated_at="2026-08-12T12:01:00Z",
    )

    assert observation.semantic_digest == envelope["semantic_digest"]


def test_semantic_identical_provider_passes_allow_distinct_response_validators() -> None:
    envelope = _provider_observation()
    producer_provenance = envelope["producer_provenance"]
    passes = envelope["passes"]
    assert isinstance(passes, list)
    second_pass = passes[1]
    assert isinstance(second_pass, dict)
    pages = second_pass["pages"]
    assert isinstance(pages, list)
    for page in pages:
        assert isinstance(page, dict)
        page["validator"] = "etag:def"
        page["response_digest"] = _test_digest(
            "provider_response",
            {
                "request_digest": page["request_digest"],
                "semantic_digest": page["semantic_digest"],
                "status": page["status"],
                "validator": page["validator"],
                "next_cursor": page["next_cursor"],
                "next_fact": page["next_fact"],
            },
        )
        page["receipt_digest"] = _test_digest(
            "provider_receipt",
            {
                "producer_provenance": producer_provenance,
                "response_digest": page["response_digest"],
                "provider_date": page["provider_date"],
            },
        )

    observation = validate_provider_observation_envelope(
        envelope,
        evaluated_at="2026-08-12T12:01:00Z",
    )

    assert observation.semantic_digest == envelope["semantic_digest"]


def test_provider_observation_binds_every_source_and_page_digest() -> None:
    missing_source = _provider_observation()
    passes = missing_source["passes"]
    assert isinstance(passes, list)
    for pass_value in passes:
        assert isinstance(pass_value, dict)
        pages = pass_value["pages"]
        assert isinstance(pages, list)
        pages.pop()
    with pytest.raises(SecurityExceptionValidationError, match="every required source"):
        validate_provider_observation_envelope(
            missing_source,
            evaluated_at="2026-08-12T12:01:00Z",
        )

    forged = _provider_observation()
    forged_passes = forged["passes"]
    assert isinstance(forged_passes, list)
    for pass_value in forged_passes:
        assert isinstance(pass_value, dict)
        pages = pass_value["pages"]
        assert isinstance(pages, list)
        page = pages[0]
        assert isinstance(page, dict)
        page["response_digest"] = "f" * 64
        page["receipt_digest"] = "d" * 64
    with pytest.raises(SecurityExceptionValidationError, match="canonical provider_response"):
        validate_provider_observation_envelope(
            forged,
            evaluated_at="2026-08-12T12:01:00Z",
        )


def test_provider_observation_strict_time_window_and_skew_fail_closed() -> None:
    envelope = _provider_observation()

    with pytest.raises(SecurityExceptionValidationError, match="strict observation window"):
        validate_provider_observation_envelope(
            envelope,
            evaluated_at="2026-08-12T12:15:00Z",
        )

    passes = envelope["passes"]
    assert isinstance(passes, list)
    first_pass = passes[0]
    assert isinstance(first_pass, dict)
    pages = first_pass["pages"]
    assert isinstance(pages, list)
    first_page = pages[0]
    assert isinstance(first_page, dict)
    first_page["provider_date"] = "2026-08-12T12:03:01Z"
    with pytest.raises(SecurityExceptionValidationError, match="120 seconds"):
        validate_provider_observation_envelope(
            envelope,
            evaluated_at="2026-08-12T12:04:00Z",
        )


def test_provider_observation_honors_earlier_provider_and_auth_bounds() -> None:
    provider_expired = _provider_observation()
    provider_expired["provider_valid_until"] = "2026-08-12T12:10:00Z"
    with pytest.raises(
        SecurityExceptionValidationError,
        match="provider or authentication bound",
    ):
        validate_provider_observation_envelope(
            provider_expired,
            evaluated_at="2026-08-12T12:01:00Z",
        )

    auth_expired = _provider_observation()
    auth_expired["provider_auth_valid_until"] = "2026-08-12T12:10:00Z"
    with pytest.raises(
        SecurityExceptionValidationError,
        match="provider or authentication bound",
    ):
        validate_provider_observation_envelope(
            auth_expired,
            evaluated_at="2026-08-12T12:01:00Z",
        )


def test_response_clock_zero_is_positive_only_for_complete_empty_inventory() -> None:
    with pytest.raises(SecurityExceptionValidationError, match="authenticated provider adapter"):
        validate_response_clock_inventory(
            _response_clock_inventory(),
            structural_observations=(
                validate_provider_observation_envelope(
                    _provider_observation(),
                    evaluated_at="2026-08-12T12:01:00Z",
                ),
            ),
            current_inventory=_structural_empty_inventory(),
            evaluated_at="2026-08-12T12:01:00Z",
        )

    missing_source = _response_clock_inventory()
    missing_source["sources"] = ["github_dependabot", "osv"]
    with pytest.raises(SecurityExceptionValidationError, match="sources"):
        validate_response_clock_inventory(
            missing_source,
            structural_observations=(
                validate_provider_observation_envelope(
                    _provider_observation(),
                    evaluated_at="2026-08-12T12:01:00Z",
                ),
            ),
            current_inventory=_structural_empty_inventory(),
            evaluated_at="2026-08-12T12:01:00Z",
        )

    incomplete = _response_clock_inventory()
    incomplete["pagination_complete"] = False
    incomplete["positive_zero"] = False
    with pytest.raises(SecurityExceptionValidationError, match="complete"):
        validate_response_clock_inventory(
            incomplete,
            structural_observations=(
                validate_provider_observation_envelope(
                    _provider_observation(),
                    evaluated_at="2026-08-12T12:01:00Z",
                ),
            ),
            current_inventory=_structural_empty_inventory(),
            evaluated_at="2026-08-12T12:01:00Z",
        )

    with pytest.raises(SecurityExceptionValidationError, match="whole-ledger lineages"):
        validate_response_clock_inventory(
            _response_clock_inventory(),
            structural_observations=(
                validate_provider_observation_envelope(
                    _provider_observation(),
                    evaluated_at="2026-08-12T12:01:00Z",
                ),
            ),
            current_inventory=_structural_dependency_inventory(),
            evaluated_at="2026-08-12T12:01:00Z",
        )


def test_missing_authoritative_source_time_is_retained_but_sla_is_uncertain() -> None:
    inventory = _response_clock_inventory()
    inventory["positive_zero"] = False
    inventory["entries"] = [_response_clock_entry()]

    with pytest.raises(SecurityExceptionValidationError, match="authenticated provider adapter"):
        validate_response_clock_inventory(
            inventory,
            structural_observations=(
                validate_provider_observation_envelope(
                    _provider_observation(),
                    evaluated_at="2026-08-12T12:01:00Z",
                ),
            ),
            current_inventory=_structural_response_inventory(),
            evaluated_at="2026-08-12T12:01:00Z",
        )


def test_response_clock_entry_must_bind_the_exact_current_lineage_head() -> None:
    response_inventory = _response_clock_inventory()
    response_inventory["positive_zero"] = False
    entry = _response_clock_entry()
    entry["exact_lineage_head_record_digest"] = "f" * 64
    response_inventory["entries"] = [entry]

    with pytest.raises(SecurityExceptionValidationError, match="exact current lineage head"):
        validate_response_clock_inventory(
            response_inventory,
            structural_observations=(
                validate_provider_observation_envelope(
                    _provider_observation(),
                    evaluated_at="2026-08-12T12:01:00Z",
                ),
            ),
            current_inventory=_structural_dependency_inventory(),
            evaluated_at="2026-08-12T12:01:00Z",
        )


def test_response_clock_rechecks_provider_window_at_its_evaluation_time() -> None:
    observation = validate_provider_observation_envelope(
        _provider_observation(),
        evaluated_at="2026-08-12T12:01:00Z",
    )

    with pytest.raises(SecurityExceptionValidationError, match="strict observation window"):
        validate_response_clock_inventory(
            _response_clock_inventory(),
            structural_observations=(observation,),
            current_inventory=_structural_empty_inventory(),
            evaluated_at="2026-08-12T12:15:00Z",
        )


def test_lifecycle_equality_is_inactive_and_terminal_states_never_reactivate() -> None:
    record = _dependency_record()
    inventory = validate_security_exception_inventory(
        _public_ledger(record),
        _private_projection(_lineage_entry(record)),
        _authority_observation(),
        evaluated_at="2026-08-12T12:01:00Z",
    )
    typed = inventory.public_records[0]

    assert compute_security_exception_lifecycle(
        typed, evaluated_at="2026-08-20T11:59:59Z"
    ).reason == "structurally_current"
    at_review = compute_security_exception_lifecycle(
        typed, evaluated_at="2026-08-20T12:00:00Z"
    )
    assert at_review.active is False
    assert at_review.reason == "review_due"
    at_expiry = compute_security_exception_lifecycle(
        typed, evaluated_at="2026-08-25T12:00:00Z"
    )
    assert at_expiry.active is False
    assert at_expiry.reason == "expired"

    record, lineage = _dependency_lineage_for_states("approved", "revoked")
    revoked = validate_security_exception_inventory(
        _public_ledger(record),
        _private_projection(*lineage),
        _authority_observation(),
        evaluated_at="2026-08-12T12:01:00Z",
    ).public_records[0]
    assert compute_security_exception_lifecycle(
        revoked, evaluated_at="2026-08-12T12:01:00Z"
    ).reason == "revoked_terminal"


def test_lifecycle_never_activates_before_the_effective_event() -> None:
    record = _dependency_record()
    typed = validate_security_exception_inventory(
        _public_ledger(record),
        _private_projection(_lineage_entry(record)),
        _authority_observation(),
        evaluated_at="2026-08-12T12:01:00Z",
    ).public_records[0]

    before_effective = compute_security_exception_lifecycle(
        typed,
        evaluated_at="2026-08-02T11:59:59Z",
    )
    assert before_effective.active is False
    assert before_effective.reason == "not_effective"

    future_record = _dependency_record()
    future_record["last_approval_or_renewal"] = "2026-08-13T12:00:00Z"
    future_record["review_after"] = "2026-08-20T12:00:00Z"
    future_record["expires_at"] = "2026-08-25T12:00:00Z"
    with pytest.raises(SecurityExceptionValidationError, match="future"):
        validate_security_exception_inventory(
            _public_ledger(future_record),
            _private_projection(_lineage_entry(future_record)),
            _authority_observation(),
            evaluated_at="2026-08-12T12:01:00Z",
        )


def test_lifecycle_preserves_structural_authority_and_never_claims_active() -> None:
    record = _dependency_record()
    typed = validate_security_exception_inventory(
        _public_ledger(record),
        _private_projection(_lineage_entry(record)),
        _authority_observation(),
        evaluated_at="2026-08-12T12:01:00Z",
    ).public_records[0]

    lifecycle = compute_security_exception_lifecycle(
        typed,
        evaluated_at="2026-08-12T12:02:00Z",
    )

    assert lifecycle.trust_status == "structural_unverified"
    assert lifecycle.active is False
    assert lifecycle.reason == "structurally_current"


def test_lifecycle_rejects_review_expiry_and_absolute_cap_violations() -> None:
    record = _dependency_record()
    record["review_after"] = record["last_approval_or_renewal"]
    with pytest.raises(SecurityExceptionValidationError, match="review_after"):
        validate_security_exception_inventory(
            _public_ledger(record),
            _private_projection(_lineage_entry(record)),
            _authority_observation(),
            evaluated_at="2026-08-12T12:01:00Z",
        )

    critical = _dependency_record()
    critical["severity"] = "critical"
    with pytest.raises(SecurityExceptionValidationError, match="absolute_cap"):
        validate_security_exception_inventory(
            _public_ledger(critical),
            _private_projection(_lineage_entry(critical)),
            _authority_observation(),
            evaluated_at="2026-08-12T12:01:00Z",
        )


def test_new_lineage_and_advisory_revision_projections_are_pure_and_exact() -> None:
    empty_inventory = validate_security_exception_inventory(
        _public_ledger(),
        _private_projection(),
        _authority_observation(),
        evaluated_at="2026-08-12T12:01:00Z",
    )
    issuance = validate_lineage_issuance_projection(
        {
            "artifact_kind": "security_exception_lineage_issuance_projection",
            "schema_version": "1.0",
            "contract_version": "1.0",
            "coordinator_id": "55555555-5555-4555-8555-555555555555",
            "lineage_id": LINEAGE_ID,
            "exception_id": EXCEPTION_ID,
            "visibility": "public",
            "subject_identity": "dependency:starlette@1.0.0|scopes=runtime|"
            "python=3.11,3.12,3.13,3.14|platform=linux",
            "issued_at": "2026-08-12T12:00:00Z",
            "random_nonce_digest": "6" * 64,
            "network_collected": False,
            "persisted": False,
        },
        current_inventory=empty_inventory,
        evaluated_at="2026-08-12T12:01:00Z",
    )
    assert issuance.lineage_id == LINEAGE_ID
    assert issuance.persisted is False

    record = _dependency_record()
    inventory = validate_security_exception_inventory(
        _public_ledger(record),
        _private_projection(_lineage_entry(record)),
        _authority_observation(),
        evaluated_at="2026-08-12T12:01:00Z",
    )
    revision = {
        "artifact_kind": "security_exception_advisory_reconciliation_projection",
        "schema_version": "1.0",
        "contract_version": "1.0",
        "lineage_id": LINEAGE_ID,
        "current_record_digest": inventory.public_records[0].record_digest,
        "prior_alias_revision": 1,
        "alias_revision": 2,
        "aliases": ["CVE-2026-0001", "GHSA-aaaa-bbbb-cccc"],
        "prior_evidence_revision": 1,
        "evidence_revision": 2,
        "evidence_digest": "7" * 64,
        "network_collected": False,
        "persisted": False,
    }
    reconciled = validate_advisory_reconciliation_projection(
        revision,
        current_inventory=inventory,
    )
    assert reconciled.alias_revision == 2
    revision["alias_revision"] = 3
    with pytest.raises(SecurityExceptionValidationError, match="exactly one"):
        validate_advisory_reconciliation_projection(
            revision,
            current_inventory=inventory,
        )


def test_lineage_issuance_rejects_a_future_issue_time() -> None:
    empty_inventory = validate_security_exception_inventory(
        _public_ledger(),
        _private_projection(),
        _authority_observation(),
        evaluated_at="2026-08-12T12:01:00Z",
    )

    with pytest.raises(SecurityExceptionValidationError, match="future"):
        validate_lineage_issuance_projection(
            {
                "artifact_kind": "security_exception_lineage_issuance_projection",
                "schema_version": "1.0",
                "contract_version": "1.0",
                "coordinator_id": "55555555-5555-4555-8555-555555555555",
                "lineage_id": LINEAGE_ID,
                "exception_id": EXCEPTION_ID,
                "visibility": "public",
                "subject_identity": "dependency:starlette@1.0.0|scopes=runtime|"
                "python=3.11,3.12,3.13,3.14|platform=linux",
                "issued_at": "2999-01-01T00:00:00Z",
                "random_nonce_digest": "6" * 64,
                "network_collected": False,
                "persisted": False,
            },
            current_inventory=empty_inventory,
            evaluated_at="2026-08-12T12:01:00Z",
        )


def test_lineage_issuance_rejects_reusing_a_historical_exception_id() -> None:
    record, lineage = _dependency_lineage_for_states("approved", "renewed")
    inventory = validate_security_exception_inventory(
        _public_ledger(record),
        _private_projection(*lineage),
        _authority_observation(),
        evaluated_at="2026-08-12T12:01:00Z",
    )

    with pytest.raises(SecurityExceptionValidationError, match="historical"):
        validate_lineage_issuance_projection(
            {
                "artifact_kind": "security_exception_lineage_issuance_projection",
                "schema_version": "1.0",
                "contract_version": "1.0",
                "coordinator_id": "55555555-5555-4555-8555-555555555555",
                "lineage_id": "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
                "exception_id": EXCEPTION_ID,
                "visibility": "public",
                "subject_identity": "dependency:httpx@1.0.0|scopes=runtime|"
                "python=3.11,3.12,3.13,3.14|platform=linux",
                "issued_at": "2026-08-12T12:00:00Z",
                "random_nonce_digest": "6" * 64,
                "network_collected": False,
                "persisted": False,
            },
            current_inventory=inventory,
            evaluated_at="2026-08-12T12:01:00Z",
        )


@pytest.mark.parametrize(
    "subject_identity",
    (
        "caller-selected:starlette",
        "dependency:Starlette@1.0.0|scopes=runtime|"
        "python=3.11,3.12,3.13,3.14|platform=linux",
        "dependency:starlette@1.0.0|scopes=test,runtime|"
        "python=3.11,3.12,3.13,3.14|platform=linux",
        "dependency:starlette@1.0.0|scopes=runtime|"
        "python=3.12,3.11|platform=linux",
        "dependency:starlette@1.0.0|scopes=runtime|"
        "python=3.11,3.12,3.13,3.14|platform=windows",
        "repository_control:bränch-protection",
    ),
)
def test_lineage_issuance_rejects_a_caller_selected_subject_identity(
    subject_identity: str,
) -> None:
    with pytest.raises(SecurityExceptionValidationError, match="canonical subject identity"):
        validate_lineage_issuance_projection(
            {
                "artifact_kind": "security_exception_lineage_issuance_projection",
                "schema_version": "1.0",
                "contract_version": "1.0",
                "coordinator_id": "55555555-5555-4555-8555-555555555555",
                "lineage_id": LINEAGE_ID,
                "exception_id": EXCEPTION_ID,
                "visibility": "public",
                "subject_identity": subject_identity,
                "issued_at": "2026-08-12T12:00:00Z",
                "random_nonce_digest": "6" * 64,
                "network_collected": False,
                "persisted": False,
            },
            current_inventory=_structural_empty_inventory(),
            evaluated_at="2026-08-12T12:01:00Z",
        )


def test_empty_checked_in_public_ledger_validates_with_no_bootstrap_path() -> None:
    ledger = tomllib.loads(
        (REPOSITORY_ROOT / "docs" / "agents" / "security-exceptions.toml").read_text()
    )

    inventory = validate_security_exception_inventory(
        ledger,
        _private_projection(),
        _authority_observation(),
        evaluated_at="2026-08-12T12:01:00Z",
    )

    assert inventory.all_records == ()
    assert "exceptions" not in ledger
    assert "bootstrap" not in ledger


def test_generated_guide_contract_hash_and_golden_vectors_cannot_drift() -> None:
    completed = subprocess.run(
        [sys.executable, str(PROJECTION_SCRIPT), "--check"],
        cwd=REPOSITORY_ROOT,
        check=False,
        capture_output=True,
        text=True,
    )

    assert completed.returncode == 0, completed.stderr
    guide = (REPOSITORY_ROOT / "docs" / "agents" / "security-exceptions.md").read_text()
    contract = load_security_exception_contract()
    assert f"Contract SHA-256: `{contract.sha256}`" in guide
    assert "bootstrap" not in guide.lower()


def test_projection_generator_refuses_a_symlink_destination(tmp_path: Path) -> None:
    projection_root = tmp_path / "repo"
    guide_parent = projection_root / "docs" / "agents"
    guide_parent.mkdir(parents=True)
    victim = tmp_path / "outside.md"
    victim.write_text("do not overwrite\n", encoding="utf-8")
    guide = guide_parent / "security-exceptions.md"
    guide.symlink_to(victim)
    namespace = runpy.run_path(str(PROJECTION_SCRIPT), run_name="projection_test")
    main = namespace["main"]
    assert callable(main)
    main.__globals__["REPOSITORY_ROOT"] = projection_root
    main.__globals__["GUIDE_PATH"] = guide

    with pytest.raises(ValueError, match="symlink|regular in-tree file"):
        main([])

    assert victim.read_text(encoding="utf-8") == "do not overwrite\n"


def test_projection_generator_refuses_a_symlink_parent(tmp_path: Path) -> None:
    projection_root = tmp_path / "repo"
    projection_root.mkdir()
    outside_parent = tmp_path / "outside-agents"
    outside_parent.mkdir()
    victim = outside_parent / "security-exceptions.md"
    victim.write_text("do not overwrite\n", encoding="utf-8")
    (projection_root / "docs").symlink_to(outside_parent, target_is_directory=True)
    guide = projection_root / "docs" / "security-exceptions.md"
    namespace = runpy.run_path(str(PROJECTION_SCRIPT), run_name="projection_parent_test")
    main = namespace["main"]
    assert callable(main)
    main.__globals__["REPOSITORY_ROOT"] = projection_root
    main.__globals__["GUIDE_PATH"] = guide

    with pytest.raises(ValueError, match="regular in-tree file"):
        main([])

    assert victim.read_text(encoding="utf-8") == "do not overwrite\n"


def _provider_observation() -> dict[str, object]:
    epoch_id = "e" * 64
    producer_provenance = {
        "adapter_id": "fork-ops-security-exception-provider",
        "adapter_version": "1.0.0",
        "executable_digest": "a" * 64,
        "configuration_digest": "b" * 64,
        "authenticated_session_digest": "c" * 64,
        "authentication_status": "unverified_projection",
    }
    source_queries = (
        ("github_dependabot", "repository-vulnerability-alerts"),
        ("osv", "osv-locked-dependencies"),
        ("github_private_advisory", "private-security-advisories"),
        ("first_party_validation", "validated-first-party-findings"),
    )
    pages: list[dict[str, object]] = []
    aggregate_sources: list[dict[str, object]] = []
    for page_number, (source, query_id) in enumerate(source_queries, start=1):
        request_digest = _test_digest(
            "provider_request",
            {
                "epoch_id": epoch_id,
                "source": source,
                "query_id": query_id,
                "page_number": page_number,
                "cursor_in": "",
            },
        )
        semantic_projection: dict[str, object] = {
            "source": source,
            "query_id": query_id,
            "item_digests": list[str](),
        }
        semantic_digest = _test_digest("provider_semantic", semantic_projection)
        response_digest = _test_digest(
            "provider_response",
            {
                "request_digest": request_digest,
                "semantic_digest": semantic_digest,
                "status": 200,
                "validator": "etag:abc",
                "next_cursor": "",
                "next_fact": "terminal",
            },
        )
        receipt_digest = _test_digest(
            "provider_receipt",
            {
                "producer_provenance": producer_provenance,
                "response_digest": response_digest,
                "provider_date": "2026-08-12T12:00:00Z",
            },
        )
        pages.append(
            {
                "page_number": page_number,
                "source": source,
                "query_id": query_id,
                "request_digest": request_digest,
                "cursor_in": "",
                "response_digest": response_digest,
                "semantic_digest": semantic_digest,
                "item_digests": [],
                "provider_date": "2026-08-12T12:00:00Z",
                "validator": "etag:abc",
                "next_cursor": "",
                "next_fact": "terminal",
                "status": 200,
                "receipt_digest": receipt_digest,
            }
        )
        aggregate_sources.append(semantic_projection)
    semantic_digest = _test_digest(
        "provider_aggregate",
        {
            "epoch_id": epoch_id,
            "repository_full_name": "nisavid/fork-ops",
            "issue_number": 59,
            "account_login": "nisavid",
            "sources": aggregate_sources,
        },
    )
    return {
        "artifact_kind": "security_exception_provider_observation",
        "schema_version": "1.0",
        "contract_version": "1.0",
        "provider": "github",
        "authentication_status": "unverified_projection",
        "repository_full_name": "nisavid/fork-ops",
        "repository_database_id": 1241799725,
        "repository_node_id": "R_kgDOSgRcLQ",
        "issue_number": 59,
        "issue_database_id": 5126688352,
        "issue_node_id": "I_kwDOSgRcLc8AAAABMZMOYA",
        "account_login": "nisavid",
        "account_database_id": 576874,
        "account_node_id": "MDQ6VXNlcjU3Njg3NA==",
        "observation_completed_at": "2026-08-12T12:00:00Z",
        "valid_until": "2026-08-12T12:15:00Z",
        "provider_valid_until": "2026-08-12T12:30:00Z",
        "provider_auth_valid_until": "2026-08-12T13:00:00Z",
        "semantic_digest": semantic_digest,
        "epoch_id": epoch_id,
        "sources": [source for source, _query_id in source_queries],
        "producer_provenance": producer_provenance,
        "passes": [
            {
                "pass_number": 1,
                "authentication_status": "unverified_projection",
                "complete": True,
                "semantic_digest": semantic_digest,
                "pages": [dict(page) for page in pages],
            },
            {
                "pass_number": 2,
                "authentication_status": "unverified_projection",
                "complete": True,
                "semantic_digest": semantic_digest,
                "pages": [dict(page) for page in pages],
            },
        ],
    }


def _response_clock_inventory() -> dict[str, object]:
    observation_digest = _provider_observation()["semantic_digest"]
    assert isinstance(observation_digest, str)
    return {
        "artifact_kind": "security_exception_response_clock_inventory",
        "schema_version": "1.0",
        "contract_version": "1.0",
        "sources": [
            "github_dependabot",
            "osv",
            "github_private_advisory",
            "first_party_validation",
        ],
        "query_ids": [
            "repository-vulnerability-alerts",
            "osv-locked-dependencies",
            "private-security-advisories",
            "validated-first-party-findings",
        ],
        "dependency_scopes": ["runtime", "optional", "build", "test", "development"],
        "python_versions": ["3.11", "3.12", "3.13", "3.14"],
        "platforms": ["linux"],
        "source_available": True,
        "pagination_complete": True,
        "reconciliation_complete": True,
        "positive_zero": True,
        "observation_semantic_digests": [observation_digest],
        "entries": [],
    }


def _response_clock_entry() -> dict[str, object]:
    record = _dependency_record()
    record["severity"] = "high"
    record["source_time_status"] = "first_observed_upper_bound"
    record["review_after"] = "2026-08-10T12:00:00Z"
    record["expires_at"] = "2026-08-15T12:00:00Z"
    record["absolute_cap"] = "2026-08-15T12:00:00Z"
    _lineage_entry(record)
    return {
        "lineage_id": LINEAGE_ID,
        "exception_id": EXCEPTION_ID,
        "lineage_sequence": 1,
        "exact_lineage_head_record_digest": record["record_digest"],
        "source": "github_dependabot",
        "query_id": "repository-vulnerability-alerts",
        "scope": "runtime",
        "python_versions": ["3.11", "3.12", "3.13", "3.14"],
        "platforms": ["linux"],
        "source_item_identity": "GHSA-aaaa-bbbb-cccc:starlette@1.0.0",
        "severity": "high",
        "credible_severities": ["high", "medium"],
        "authoritative_source_published_at": None,
        "first_observed_at": "2026-08-01T12:00:00Z",
    }


def _authority_observation() -> dict[str, object]:
    return {
        "artifact_kind": "security_exception_authority_observation",
        "schema_version": "1.0",
        "contract_version": "1.0",
        "status": "available",
        "provider": "github",
        "authentication_status": "unverified_projection",
        "observed_at": "2026-08-12T12:00:00Z",
        "repository_full_name": "nisavid/fork-ops",
        "repository_database_id": 1241799725,
        "repository_node_id": "R_kgDOSgRcLQ",
        "login": "nisavid",
        "account_database_id": 576874,
        "account_node_id": "MDQ6VXNlcjU3Njg3NA==",
    }


def _structural_dependency_inventory() -> SecurityExceptionInventory:
    record = _dependency_record()
    return validate_security_exception_inventory(
        _public_ledger(record),
        _private_projection(_lineage_entry(record)),
        _authority_observation(),
        evaluated_at="2026-08-12T12:01:00Z",
    )


def _structural_response_inventory() -> SecurityExceptionInventory:
    record = _dependency_record()
    record["severity"] = "high"
    record["source_time_status"] = "first_observed_upper_bound"
    record["review_after"] = "2026-08-10T12:00:00Z"
    record["expires_at"] = "2026-08-15T12:00:00Z"
    record["absolute_cap"] = "2026-08-15T12:00:00Z"
    return validate_security_exception_inventory(
        _public_ledger(record),
        _private_projection(_lineage_entry(record)),
        _authority_observation(),
        evaluated_at="2026-08-12T12:01:00Z",
    )


def _structural_empty_inventory() -> SecurityExceptionInventory:
    return validate_security_exception_inventory(
        _public_ledger(),
        _private_projection(),
        _authority_observation(),
        evaluated_at="2026-08-12T12:01:00Z",
    )


def _public_ledger(*records: dict[str, object]) -> dict[str, object]:
    return {
        "artifact_kind": "security_exception_ledger",
        "schema_version": "1.0",
        "exceptions": list(records),
    }


def _private_projection(*entries: dict[str, object]) -> dict[str, object]:
    return {
        "artifact_kind": "security_exception_private_projection",
        "schema_version": "1.0",
        "contract_version": "1.0",
        "status": "available",
        "records": [],
        "lineage_index": {
            "artifact_kind": "security_exception_lineage_index_projection",
            "schema_version": "1.0",
            "contract_version": "1.0",
            "entries": list(entries),
        },
    }


def _dependency_record() -> dict[str, object]:
    return {
        "exception_id": EXCEPTION_ID,
        "lineage_id": LINEAGE_ID,
        "lineage_sequence": 1,
        "visibility": "public",
        "kind": "finding_exception",
        "subject_kind": "dependency_advisory",
        "subject_key": (
            f"dependency:{LINEAGE_ID}:starlette@1.0.0|scopes=runtime|"
            "python=3.11,3.12,3.13,3.14|platform=linux"
        ),
        "package": "starlette",
        "locked_version": "1.0.0",
        "dependency_scopes": ["runtime"],
        "python_versions": ["3.11", "3.12", "3.13", "3.14"],
        "platforms": ["linux"],
        "severity": "medium",
        "state": "approved",
        "owner": "nisavid",
        "authority_login": "nisavid",
        "authority_database_id": 576874,
        "authority_node_id": "MDQ6VXNlcjU3Njg3NA==",
        "aliases": ["GHSA-aaaa-bbbb-cccc"],
        "alias_revision": 1,
        "evidence_revision": 1,
        "evidence_digest": "1" * 64,
        "compensating_control_ids": ["dependency-isolation"],
        "public_references": ["https://github.com/advisories/GHSA-aaaa-bbbb-cccc"],
        "response_started_at": "2026-08-01T12:00:00Z",
        "source_time_status": "authoritative",
        "last_approval_or_renewal": "2026-08-02T12:00:00Z",
        "review_after": "2026-08-20T12:00:00Z",
        "expires_at": "2026-08-25T12:00:00Z",
        "absolute_cap": "2026-08-31T12:00:00Z",
        "removal_condition_code": "compatible_fix_available",
        "fix_availability": "unavailable",
        "proposal_digest": "2" * 64,
        "event_digest": "3" * 64,
        "record_digest": "4" * 64,
        "result_digest": "5" * 64,
        "predecessor_record_digest": ZERO_DIGEST,
        "effects": dict(EFFECTS),
    }


def _non_dependency_record(
    *,
    kind: str,
    subject_kind: str,
    subject_key: str,
    exception_id: str,
    lineage_id: str,
) -> dict[str, object]:
    record = _dependency_record()
    record.update(
        exception_id=exception_id,
        lineage_id=lineage_id,
        kind=kind,
        subject_kind=subject_kind,
        subject_key=subject_key,
        aliases=[subject_key],
    )
    if kind in {"control_bypass", "control_unavailability"}:
        record.update(
            review_after="2026-08-05T12:00:00Z",
            expires_at="2026-08-07T12:00:00Z",
            absolute_cap="2026-08-08T12:00:00Z",
        )
    for field_name in (
        "package",
        "locked_version",
        "dependency_scopes",
        "python_versions",
        "platforms",
    ):
        del record[field_name]
    return record


def _lineage_entry(
    record: dict[str, object],
    *,
    predecessor_event_digest: str = ZERO_DIGEST,
    effective_at: str | None = None,
) -> dict[str, object]:
    digest_fields = {
        "evidence_digest",
        "proposal_digest",
        "event_digest",
        "result_digest",
        "record_digest",
        "predecessor_record_digest",
    }
    evidence_projection = {
        key: value for key, value in record.items() if key not in digest_fields
    }
    record["evidence_digest"] = _test_digest("evidence", evidence_projection)
    proposal_projection = {
        key: value
        for key, value in record.items()
        if key not in {"proposal_digest", "event_digest", "result_digest", "record_digest"}
    }
    record["proposal_digest"] = _test_digest("proposal", proposal_projection)
    entry = {
        "lineage_id": record["lineage_id"],
        "exception_id": record["exception_id"],
        "visibility": record["visibility"],
        "sequence": record["lineage_sequence"],
        "state": record["state"],
        "subject_key": record["subject_key"],
        "subject_identity": "dependency:starlette@1.0.0|scopes=runtime|"
        "python=3.11,3.12,3.13,3.14|platform=linux",
        "alias_revision": record["alias_revision"],
        "evidence_revision": record["evidence_revision"],
        "response_started_at": record["response_started_at"],
        "absolute_cap": record["absolute_cap"],
        "effective_at": (
            record["last_approval_or_renewal"] if effective_at is None else effective_at
        ),
        "expires_at": record["expires_at"],
        "predecessor_event_digest": predecessor_event_digest,
        "event_digest": record["event_digest"],
        "record_digest": record["record_digest"],
    }
    event_projection = {
        key: value
        for key, value in entry.items()
        if key not in {"event_digest", "result_digest", "record_digest"}
    }
    entry["event_digest"] = _test_digest("event", event_projection)
    record["event_digest"] = entry["event_digest"]
    result_projection = {
        key: value
        for key, value in record.items()
        if key not in {"result_digest", "record_digest"}
    }
    record["result_digest"] = _test_digest("result", result_projection)
    entry["result_digest"] = record["result_digest"]
    record_projection = {
        key: value for key, value in entry.items() if key != "record_digest"
    }
    entry["record_digest"] = _test_digest("record", record_projection)
    record["record_digest"] = entry["record_digest"]
    return entry


def _dependency_lineage_for_states(
    *states: str,
    exception_ids: tuple[str, ...] | None = None,
) -> tuple[dict[str, object], tuple[dict[str, object], ...]]:
    assert states
    if exception_ids is None:
        issued_ids = iter(
            (
                EXCEPTION_ID,
                "77777777-7777-4777-8777-777777777777",
                "88888888-8888-4888-8888-888888888888",
                "99999999-9999-4999-8999-999999999999",
            )
        )
        current_exception_id = next(issued_ids)
        selected_exception_ids: list[str] = []
        for sequence, state in enumerate(states, start=1):
            if sequence > 1 and state == "renewed":
                current_exception_id = next(issued_ids)
            selected_exception_ids.append(current_exception_id)
        exception_ids = tuple(selected_exception_ids)
    assert len(exception_ids) == len(states)
    record = _dependency_record()
    record["exception_id"] = exception_ids[-1]
    record["lineage_sequence"] = len(states)
    record["state"] = states[-1]
    last_approval_sequence = max(
        sequence
        for sequence, state in enumerate(states, start=1)
        if state in {"approved", "renewed"}
    )
    record["last_approval_or_renewal"] = _lineage_effective_at(last_approval_sequence)
    entries: list[dict[str, object]] = []
    predecessor_event_digest = ZERO_DIGEST
    predecessor_record_digest = ZERO_DIGEST
    for sequence, state in enumerate(states[:-1], start=1):
        entry: dict[str, object] = {
            "lineage_id": record["lineage_id"],
            "exception_id": exception_ids[sequence - 1],
            "visibility": record["visibility"],
            "sequence": sequence,
            "state": state,
            "subject_key": record["subject_key"],
            "subject_identity": "dependency:starlette@1.0.0|scopes=runtime|"
            "python=3.11,3.12,3.13,3.14|platform=linux",
            "alias_revision": record["alias_revision"],
            "evidence_revision": record["evidence_revision"],
            "response_started_at": record["response_started_at"],
            "absolute_cap": record["absolute_cap"],
            "effective_at": _lineage_effective_at(sequence),
            "expires_at": record["expires_at"],
            "predecessor_event_digest": predecessor_event_digest,
            "event_digest": ZERO_DIGEST,
            "result_digest": hashlib.sha256(
                f"historical-result:{sequence}:{state}".encode()
            ).hexdigest(),
            "record_digest": ZERO_DIGEST,
        }
        event_projection = {
            key: value
            for key, value in entry.items()
            if key not in {"event_digest", "result_digest", "record_digest"}
        }
        entry["event_digest"] = _test_digest("event", event_projection)
        record_projection = {
            key: value for key, value in entry.items() if key != "record_digest"
        }
        entry["record_digest"] = _test_digest("record", record_projection)
        entries.append(entry)
        predecessor_event_digest = str(entry["event_digest"])
        predecessor_record_digest = str(entry["record_digest"])
    record["predecessor_record_digest"] = predecessor_record_digest
    entries.append(
        _lineage_entry(
            record,
            predecessor_event_digest=predecessor_event_digest,
            effective_at=_lineage_effective_at(len(states)),
        )
    )
    return record, tuple(entries)


def _lineage_effective_at(sequence: int) -> str:
    return f"2026-08-{sequence + 1:02d}T12:00:00Z"


def _bind_test_lineage_subject_identity(
    record: dict[str, object],
    entry: dict[str, object],
    subject_identity: str,
) -> None:
    entry["subject_identity"] = subject_identity
    digests = compute_security_exception_record_digests(record, entry)
    record.update(
        evidence_digest=digests.evidence_digest,
        proposal_digest=digests.proposal_digest,
        event_digest=digests.event_digest,
        result_digest=digests.result_digest,
        record_digest=digests.record_digest,
    )
    entry.update(
        event_digest=digests.event_digest,
        result_digest=digests.result_digest,
        record_digest=digests.record_digest,
    )


def _test_digest(domain: str, projection: object) -> str:
    separators = {
        "evidence": "fork-ops/security-exception/evidence/1.0\0",
        "proposal": "fork-ops/security-exception/proposal/1.0\0",
        "event": "fork-ops/security-exception/event/1.0\0",
        "result": "fork-ops/security-exception/result/1.0\0",
        "record": "fork-ops/security-exception/record/1.0\0",
        "provider_request": "fork-ops/security-exception/provider-request/1.0\0",
        "provider_semantic": "fork-ops/security-exception/provider-semantic/1.0\0",
        "provider_response": "fork-ops/security-exception/provider-response/1.0\0",
        "provider_receipt": "fork-ops/security-exception/provider-receipt/1.0\0",
        "provider_aggregate": "fork-ops/security-exception/provider-aggregate/1.0\0",
    }
    canonical = json.dumps(
        projection,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(separators[domain].encode() + canonical).hexdigest()


def _seal_transition_projection(
    projection: dict[str, object],
    *,
    persisted: bool = True,
    observed_at: str = "2026-08-12T12:00:00Z",
    persisted_at: str = "2026-08-12T12:01:00Z",
) -> None:
    projection.update(
        {
            "authority_observation_digest": "6" * 64,
            "command_provider_receipt_digest": "7" * 64,
            "producer_attestation_digest": "8" * 64,
            "persistence_receipt_digest": "9" * 64,
            "observed_at": observed_at,
            "persisted_at": persisted_at,
        }
    )
    if persisted:
        projection["persisted_result_digest"] = _test_digest(
            "result",
            {
                key: value
                for key, value in projection.items()
                if key != "persisted_result_digest"
            },
        )
