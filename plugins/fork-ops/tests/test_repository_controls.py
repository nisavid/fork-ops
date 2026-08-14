from __future__ import annotations

import hashlib
import json
from copy import deepcopy
from pathlib import Path
from typing import cast

import pytest
from jsonschema import Draft202012Validator

from fork_ops import bounded_io, repository_controls
from fork_ops.repository_controls import (
    RepositoryControlContractError,
    RepositoryControlObservationError,
    evaluate_first_party_security,
    load_repository_control_contract,
    parse_repository_control_observation,
)
from fork_ops.security_exceptions import (
    SecurityExceptionInventory,
    compute_security_exception_digest,
    validate_security_exception_inventory,
)


def test_unsupported_repository_control_observation_version_is_refused() -> None:
    with pytest.raises(
        RepositoryControlObservationError,
        match="Unsupported repository control observation schema version",
    ):
        parse_repository_control_observation(
            {
                "artifact_kind": "repository_control_observation",
                "schema_version": "2.0",
            }
        )


def test_packaged_repository_control_contract_is_verified() -> None:
    contract = load_repository_control_contract()

    assert contract.artifact_kind == "repository_control_observation_contract"
    assert contract.contract_version == "1.0"
    assert contract.control_sources == _CONTROL_SOURCES
    assert contract.maximum_validity_seconds == 900


@pytest.mark.parametrize(
    ("status", "failure_class"),
    (("passed", "forbidden"), ("unavailable", None)),
)
def test_contract_schema_matches_status_dependent_failure_class_parser(
    status: str,
    failure_class: str | None,
) -> None:
    contract = load_repository_control_contract()
    definitions = contract.data["$defs"]
    assert isinstance(definitions, dict)
    control_schema = definitions["control"]
    assert isinstance(control_schema, dict)
    schema = {
        "$schema": contract.data["$schema"],
        "$defs": definitions,
        **control_schema,
    }
    control = _valid_control("main_ruleset", "github")
    control["status"] = status
    if failure_class is not None:
        control["failure_class"] = failure_class

    assert list(Draft202012Validator(schema).iter_errors(control))

    observation = _valid_observation()
    controls = observation["controls"]
    assert isinstance(controls, list)
    controls[0] = control
    with pytest.raises(RepositoryControlObservationError):
        parse_repository_control_observation(observation)


def test_contract_loader_collects_partial_regular_file_reads(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    original_read = bounded_io._read_bytes

    def short_read(descriptor: int, count: int) -> bytes:
        return original_read(descriptor, min(count, 17))

    monkeypatch.setattr(bounded_io, "_read_bytes", short_read)

    assert load_repository_control_contract().contract_version == "1.0"


@pytest.mark.parametrize(
    ("case", "message"),
    (
        ("schema", "schema drifted"),
        ("schema_versions", "supported schema versions drifted"),
        ("sources", "sources drifted"),
        ("validity", "validity drifted"),
        ("failure_classes", "failure classes drifted"),
        ("statuses", "statuses drifted"),
        ("operation", "operation requirements drifted"),
        ("evaluation", "evaluation requirements drifted"),
        ("provider", "provider requirements drifted"),
        ("confidentiality", "confidentiality requirements drifted"),
        ("canonicalization", "canonicalization drifted"),
    ),
)
def test_contract_assumptions_must_match_the_evaluator(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    case: str,
    message: str,
) -> None:
    data = deepcopy(load_repository_control_contract().data)
    if case == "schema":
        observation_schema = data["observation_schema"]
        assert isinstance(observation_schema, dict)
        properties = observation_schema["properties"]
        assert isinstance(properties, dict)
        controls = properties["controls"]
        assert isinstance(controls, dict)
        controls["minItems"] = 23
    elif case == "schema_versions":
        data["supported_schema_versions"] = ["1.0", "2.0"]
    elif case == "sources":
        sources = data["control_sources"]
        assert isinstance(sources, dict)
        sources["main_ruleset"] = "package"
    elif case == "validity":
        data["maximum_validity_seconds"] = 901
    elif case == "failure_classes":
        data["failure_classes"] = ["timeout"]
    elif case == "statuses":
        data["statuses"] = ["passed", "failed"]
    elif case == "operation":
        operation = data["operation"]
        assert isinstance(operation, dict)
        operation["late_results_are_ignored"] = False
    elif case == "evaluation":
        evaluation = data["evaluation"]
        assert isinstance(evaluation, dict)
        evaluation["security_exception_1_0_effect"] = "gate"
    elif case == "provider":
        provider = data["provider_requirements"]
        assert isinstance(provider, dict)
        alerts = provider["alert_controls"]
        assert isinstance(alerts, dict)
        alerts["complete_pagination_required"] = False
    elif case == "confidentiality":
        confidentiality = data["confidentiality"]
        assert isinstance(confidentiality, dict)
        confidentiality["raw_response_fields"] = True
    elif case == "canonicalization":
        canonicalization = data["canonicalization"]
        assert isinstance(canonicalization, dict)
        canonicalization["digest_algorithm"] = "sha512"
    else:
        raise AssertionError(f"unknown contract drift case {case}")
    payload = json.dumps(data, separators=(",", ":")).encode()
    path = tmp_path / "contract.json"
    path.write_bytes(payload)
    monkeypatch.setattr(
        repository_controls,
        "EXPECTED_CONTRACT_SHA256",
        hashlib.sha256(payload).hexdigest(),
    )

    with pytest.raises(RepositoryControlContractError, match=message):
        load_repository_control_contract(path)


def test_complete_repository_control_observation_is_immutable_and_round_trips() -> None:
    raw = _valid_observation()

    observation = parse_repository_control_observation(raw)
    raw["candidate_sha"] = "f" * 40

    assert observation.to_dict()["candidate_sha"] == "a" * 40
    assert observation.to_dict() == _valid_observation()


@pytest.mark.parametrize(
    "case",
    (
        "unknown_root_field",
        "missing_control",
        "unknown_control",
        "wrong_source",
        "duplicate_control",
        "digest_mismatch",
        "control_digest_mismatch",
        "completion_after_deadline",
        "stale_control",
        "excessive_validity",
    ),
)
def test_repository_control_observation_contract_fails_closed(case: str) -> None:
    with pytest.raises(RepositoryControlObservationError):
        parse_repository_control_observation(_invalid_observation(case))


def test_opaque_identifiers_reject_mixed_types_after_digest_verification() -> None:
    with pytest.raises(
        RepositoryControlObservationError,
        match=r"controls\[0\]\.opaque_ids must contain strings",
    ):
        parse_repository_control_observation(_invalid_observation("mixed_opaque_id_types"))


def test_complete_current_controls_produce_a_deterministic_first_party_pass() -> None:
    observation = parse_repository_control_observation(_valid_observation())

    result = evaluate_first_party_security(
        observation,
        _structural_empty_inventory(),
        evaluated_at="2026-08-14T00:00:20Z",
    )

    assert result == {
        "artifact_kind": "first_party_security_result",
        "schema_version": "1.0",
        "status": "passed",
        "evaluated_at": "2026-08-14T00:00:20Z",
        "repository": {
            "full_name": "nisavid/fork-ops",
            "database_id": 1_241_799_725,
            "node_id": "R_kgDOSgRcLQ",
            "default_branch": "main",
        },
        "candidate_sha": "a" * 40,
        "producer": {
            "kind": "github_app",
            "opaque_id": "github-app:1234",
            "workflow_sha": "b" * 40,
            "evaluator_sha256": "c" * 64,
        },
        "observation_epoch": "e" * 64,
        "observation_sha256": _valid_observation()["observation_sha256"],
        "evidence_trust": "normalized_observation",
        "assurance_boundary": {
            "security_exception_1_0_gate_effect": False,
            "merge_or_admission_authority": False,
            "baseline_or_release_eligibility": False,
        },
        "security_exception_inventory": {
            "contract_version": "1.0",
            "authority_status": "structural_unverified",
            "finding_effect": "inventory_only",
            "public_record_count": 0,
            "private_record_count": 0,
        },
        "summary": {
            "required_control_count": len(_CONTROL_SOURCES),
            "passed_control_count": len(_CONTROL_SOURCES),
            "failed_control_count": 0,
            "unavailable_control_count": 0,
        },
        "controls": [
            {
                "control_id": control_id,
                "status": "passed",
                "projection_sha256": _valid_control(control_id, source)["projection_sha256"],
            }
            for control_id, source in _CONTROL_SOURCES.items()
        ],
        "diagnostics": [],
    }


@pytest.mark.parametrize(
    ("case", "evaluated_at", "expected_codes"),
    (
        ("failed", "2026-08-14T00:00:20Z", {"control.failed"}),
        ("unavailable", "2026-08-14T00:00:20Z", {"control.unavailable"}),
        ("passed", "2026-08-14T00:10:10Z", {"control.stale"}),
        ("passed", "2026-08-14T00:00:19Z", {"observation.future"}),
    ),
)
def test_first_party_evaluation_fails_closed_for_control_and_time_state(
    case: str,
    evaluated_at: str,
    expected_codes: set[str],
) -> None:
    raw = _valid_observation()
    controls = raw["controls"]
    if not isinstance(controls, list) or not isinstance(controls[0], dict):
        raise AssertionError("valid fixture control shape changed")
    controls[0]["status"] = case
    if case == "unavailable":
        controls[0]["failure_class"] = "forbidden"
    _redigest_control(controls[0])
    _redigest(raw)

    result = evaluate_first_party_security(
        parse_repository_control_observation(raw),
        _structural_empty_inventory(),
        evaluated_at=evaluated_at,
    )

    assert result["status"] == "failed"
    diagnostics = result["diagnostics"]
    assert isinstance(diagnostics, list)
    assert {diagnostic["code"] for diagnostic in diagnostics} == expected_codes


def test_first_party_evaluation_rejects_an_untyped_exception_inventory() -> None:
    result = evaluate_first_party_security(
        parse_repository_control_observation(_valid_observation()),
        cast(SecurityExceptionInventory, object()),
        evaluated_at="2026-08-14T00:00:20Z",
    )

    assert result["status"] == "failed"
    assert result["security_exception_inventory"] == {
        "contract_version": "",
        "authority_status": "invalid",
        "finding_effect": "inventory_only",
        "public_record_count": 0,
        "private_record_count": 0,
    }
    assert result["diagnostics"] == [
        {
            "code": "exceptions.invalid_inventory",
            "source": "security-exception-inventory",
            "message": ("Security Exception 1.0 inventory is not a typed structural projection."),
        }
    ]


def test_security_exception_1_0_record_cannot_clear_a_failed_control() -> None:
    raw = _valid_observation()
    controls = raw["controls"]
    if not isinstance(controls, list) or not isinstance(controls[0], dict):
        raise AssertionError("valid fixture control shape changed")
    controls[0]["status"] = "failed"
    _redigest_control(controls[0])
    _redigest(raw)

    result = evaluate_first_party_security(
        parse_repository_control_observation(raw),
        _structural_dependency_inventory(),
        evaluated_at="2026-08-14T00:00:20Z",
    )

    assert result["status"] == "failed"
    assert result["security_exception_inventory"] == {
        "contract_version": "1.0",
        "authority_status": "structural_unverified",
        "finding_effect": "inventory_only",
        "public_record_count": 1,
        "private_record_count": 0,
    }
    assert result["assurance_boundary"] == {
        "security_exception_1_0_gate_effect": False,
        "merge_or_admission_authority": False,
        "baseline_or_release_eligibility": False,
    }
    assert result["diagnostics"] == [
        {
            "code": "control.failed",
            "source": "main_ruleset",
            "message": "The required repository control is not satisfied.",
        }
    ]


_CONTROL_SOURCES = {
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


def _valid_observation() -> dict[str, object]:
    controls = [
        _valid_control(control_id, source) for control_id, source in _CONTROL_SOURCES.items()
    ]
    payload: dict[str, object] = {
        "artifact_kind": "repository_control_observation",
        "schema_version": "1.0",
        "repository": {
            "full_name": "nisavid/fork-ops",
            "database_id": 1_241_799_725,
            "node_id": "R_kgDOSgRcLQ",
            "default_branch": "main",
        },
        "candidate_sha": "a" * 40,
        "producer": {
            "kind": "github_app",
            "opaque_id": "github-app:1234",
            "workflow_sha": "b" * 40,
            "evaluator_sha256": "c" * 64,
        },
        "operation": {
            "epoch": "e" * 64,
            "started_at": "2026-08-14T00:00:00Z",
            "completed_at": "2026-08-14T00:00:20Z",
            "deadline_at": "2026-08-14T00:15:00Z",
        },
        "controls": controls,
    }
    payload["observation_sha256"] = hashlib.sha256(_canonical_json(payload)).hexdigest()
    return payload


def _invalid_observation(case: str) -> dict[str, object]:
    payload = deepcopy(_valid_observation())
    controls = payload["controls"]
    operation = payload["operation"]
    if not isinstance(controls, list) or not isinstance(operation, dict):
        raise AssertionError("valid fixture shape changed")
    if case == "unknown_root_field":
        payload["raw_response"] = "must not survive projection"
    elif case == "missing_control":
        controls.pop()
    elif case == "unknown_control":
        control = controls[-1]
        if not isinstance(control, dict):
            raise AssertionError("valid fixture control shape changed")
        control["control_id"] = "unreviewed_control"
        _redigest_control(control)
    elif case == "wrong_source":
        control = controls[0]
        if not isinstance(control, dict):
            raise AssertionError("valid fixture control shape changed")
        control["source"] = "package"
        _redigest_control(control)
    elif case == "duplicate_control":
        controls[-1] = deepcopy(controls[0])
    elif case == "digest_mismatch":
        payload["observation_sha256"] = "0" * 64
        return payload
    elif case == "control_digest_mismatch":
        control = controls[0]
        if not isinstance(control, dict):
            raise AssertionError("valid fixture control shape changed")
        control["projection_sha256"] = "0" * 64
    elif case == "completion_after_deadline":
        operation["completed_at"] = "2026-08-14T00:15:01Z"
    elif case == "stale_control":
        control = controls[0]
        if not isinstance(control, dict):
            raise AssertionError("valid fixture control shape changed")
        control["valid_until"] = "2026-08-14T00:00:20Z"
        _redigest_control(control)
    elif case == "excessive_validity":
        control = controls[0]
        if not isinstance(control, dict):
            raise AssertionError("valid fixture control shape changed")
        control["valid_until"] = "2026-08-14T00:15:11Z"
        _redigest_control(control)
    elif case == "mixed_opaque_id_types":
        control = controls[0]
        if not isinstance(control, dict):
            raise AssertionError("valid fixture control shape changed")
        control["opaque_ids"] = [1, "safe-id"]
        _redigest_control(control)
    else:
        raise AssertionError(f"unknown invalid fixture case {case}")
    _redigest(payload)
    return payload


def _redigest(payload: dict[str, object]) -> None:
    payload.pop("observation_sha256", None)
    payload["observation_sha256"] = hashlib.sha256(_canonical_json(payload)).hexdigest()


def _redigest_control(control: dict[str, object]) -> None:
    control.pop("projection_sha256", None)
    control["projection_sha256"] = hashlib.sha256(_canonical_json(control)).hexdigest()


def _valid_control(control_id: str, source: str) -> dict[str, object]:
    control: dict[str, object] = {
        "control_id": control_id,
        "source": source,
        "status": "passed",
        "observed_at": "2026-08-14T00:00:10Z",
        "valid_until": "2026-08-14T00:10:10Z",
        "opaque_ids": [],
    }
    control["projection_sha256"] = hashlib.sha256(_canonical_json(control)).hexdigest()
    return control


def _canonical_json(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode()


def _structural_empty_inventory() -> SecurityExceptionInventory:
    return validate_security_exception_inventory(
        {
            "artifact_kind": "security_exception_ledger",
            "schema_version": "1.0",
            "exceptions": [],
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
            "observed_at": "2026-08-14T00:00:00Z",
            "repository_full_name": "nisavid/fork-ops",
            "repository_database_id": 1_241_799_725,
            "repository_node_id": "R_kgDOSgRcLQ",
            "login": "nisavid",
            "account_database_id": 576_874,
            "account_node_id": "MDQ6VXNlcjU3Njg3NA==",
        },
        evaluated_at="2026-08-14T00:00:20Z",
    )


def _structural_dependency_inventory() -> SecurityExceptionInventory:
    lineage_id = "11111111-1111-4111-8111-111111111111"
    record: dict[str, object] = {
        "exception_id": "22222222-2222-4222-8222-222222222222",
        "lineage_id": lineage_id,
        "lineage_sequence": 1,
        "visibility": "public",
        "kind": "finding_exception",
        "subject_kind": "dependency_advisory",
        "subject_key": (
            f"dependency:{lineage_id}:starlette@1.0.0|scopes=runtime|"
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
        "authority_database_id": 576_874,
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
        "predecessor_record_digest": "0" * 64,
        "effects": {
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
        },
    }
    lineage = _bind_security_exception_lineage(record)
    return validate_security_exception_inventory(
        {
            "artifact_kind": "security_exception_ledger",
            "schema_version": "1.0",
            "exceptions": [record],
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
                "entries": [lineage],
            },
        },
        {
            "artifact_kind": "security_exception_authority_observation",
            "schema_version": "1.0",
            "contract_version": "1.0",
            "status": "available",
            "provider": "github",
            "authentication_status": "unverified_projection",
            "observed_at": "2026-08-14T00:00:00Z",
            "repository_full_name": "nisavid/fork-ops",
            "repository_database_id": 1_241_799_725,
            "repository_node_id": "R_kgDOSgRcLQ",
            "login": "nisavid",
            "account_database_id": 576_874,
            "account_node_id": "MDQ6VXNlcjU3Njg3NA==",
        },
        evaluated_at="2026-08-14T00:00:20Z",
    )


def _bind_security_exception_lineage(record: dict[str, object]) -> dict[str, object]:
    """Bind evidence, proposal, event, result, then record digests in place.

    The input record is mutated while the returned lineage is a separate mapping.
    """
    digest_fields = {
        "evidence_digest",
        "proposal_digest",
        "event_digest",
        "result_digest",
        "record_digest",
        "predecessor_record_digest",
    }
    record["evidence_digest"] = compute_security_exception_digest(
        "evidence",
        {key: value for key, value in record.items() if key not in digest_fields},
    )
    record["proposal_digest"] = compute_security_exception_digest(
        "proposal",
        {
            key: value
            for key, value in record.items()
            if key not in {"proposal_digest", "event_digest", "result_digest", "record_digest"}
        },
    )
    lineage: dict[str, object] = {
        "lineage_id": record["lineage_id"],
        "exception_id": record["exception_id"],
        "visibility": record["visibility"],
        "sequence": record["lineage_sequence"],
        "state": record["state"],
        "subject_key": record["subject_key"],
        "subject_identity": (
            "dependency:starlette@1.0.0|scopes=runtime|python=3.11,3.12,3.13,3.14|platform=linux"
        ),
        "alias_revision": record["alias_revision"],
        "evidence_revision": record["evidence_revision"],
        "response_started_at": record["response_started_at"],
        "absolute_cap": record["absolute_cap"],
        "effective_at": record["last_approval_or_renewal"],
        "expires_at": record["expires_at"],
        "predecessor_event_digest": "0" * 64,
        "event_digest": record["event_digest"],
        "record_digest": record["record_digest"],
    }
    lineage["event_digest"] = compute_security_exception_digest(
        "event",
        {
            key: value
            for key, value in lineage.items()
            if key not in {"event_digest", "result_digest", "record_digest"}
        },
    )
    record["event_digest"] = lineage["event_digest"]
    record["result_digest"] = compute_security_exception_digest(
        "result",
        {
            key: value
            for key, value in record.items()
            if key not in {"result_digest", "record_digest"}
        },
    )
    lineage["result_digest"] = record["result_digest"]
    lineage["record_digest"] = compute_security_exception_digest(
        "record",
        {key: value for key, value in lineage.items() if key != "record_digest"},
    )
    record["record_digest"] = lineage["record_digest"]
    return lineage
