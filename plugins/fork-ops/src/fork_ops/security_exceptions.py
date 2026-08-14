"""Pure Security Exception contract 1.0 validation and projection."""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
import unicodedata
import uuid
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path
from types import MappingProxyType
from typing import Any, Final
from urllib.parse import urlsplit

from jsonschema import Draft202012Validator, FormatChecker
from jsonschema.exceptions import ValidationError

CONTRACT_FILENAME: Final = "security-exception-contract-1.0.json"
EXPECTED_CONTRACT_SHA256: Final = (
    "b060b477b1fdcc9155a34939e607a7794ccb82f5d544816cfb95a3f6392f34f4"
)
MAX_CONTRACT_BYTES: Final = 1_048_576


class SecurityExceptionContractError(ValueError):
    """The canonical Security Exception contract is unavailable or unsupported."""


class SecurityExceptionValidationError(ValueError):
    """A Security Exception projection violates contract 1.0."""


@dataclass(frozen=True)
class PublicCommandRequest:
    action: str
    exception_id: str
    comment_node_id: str
    raw_comment_digest: str
    proposal_digest: str | None = None
    predecessor_effective_event_digest: str | None = None
    pending_transition_digest: str | None = None
    malformed_comment_node_id: str | None = None
    malformed_raw_comment_digest: str | None = None


@dataclass(frozen=True)
class RevocationPendingRequest:
    action: str
    exception_id: str
    comment_node_id: str
    raw_comment_digest: str


@dataclass(frozen=True)
class StructuralTransitionProjection:
    action: str
    from_state: str
    to_state: str
    persisted_result_digest: str
    trust_status: str


@dataclass(frozen=True)
class StructuralProviderObservation:
    provider: str
    observation_completed_at: str
    valid_until: str
    semantic_digest: str
    trust_status: str


@dataclass(frozen=True)
class ResponseClockEntry:
    lineage_id: str
    exception_id: str
    lineage_sequence: int
    exact_lineage_head_record_digest: str
    source: str
    query_id: str
    scope: str
    python_versions: tuple[str, ...]
    platforms: tuple[str, ...]
    source_item_identity: str
    severity: str
    credible_severities: tuple[str, ...]
    response_started_at: str
    source_time_status: str
    triage_deadline: str | None
    disposition_deadline: str
    triage_state: str
    disposition_state: str


@dataclass(frozen=True)
class ResponseClockState:
    positive_zero: bool
    entries: tuple[ResponseClockEntry, ...]
    evaluated_at: str
    observation_semantic_digests: tuple[str, ...]


@dataclass(frozen=True)
class SecurityExceptionLifecycle:
    state: str
    active: bool
    reason: str
    evaluated_at: str
    trust_status: str


@dataclass(frozen=True)
class StructuralLineageIssuanceProjection:
    coordinator_id: str
    lineage_id: str
    exception_id: str
    visibility: str
    subject_identity: str
    persisted: bool


@dataclass(frozen=True)
class StructuralAdvisoryReconciliationProjection:
    lineage_id: str
    alias_revision: int
    aliases: tuple[str, ...]
    evidence_revision: int
    evidence_digest: str
    persisted: bool


@dataclass(frozen=True)
class RiskAuthority:
    login: str
    database_id: int
    node_id: str


@dataclass(frozen=True)
class SecurityExceptionContract:
    artifact_kind: str
    contract_version: str
    authority: RiskAuthority
    data: dict[str, object]
    sha256: str


@dataclass(frozen=True)
class SecurityExceptionEffects:
    inventory_recorded: bool
    decision_recorded: bool
    lifecycle_recorded: bool
    security_posture_green: bool
    admission_or_merge_authorized: bool
    repository_control_relaxed_disabled_or_mutated: bool
    assurance_validated: bool
    baseline_or_release_eligible: bool
    product_or_dogfood_authorized: bool
    underlying_failure_cleared: bool
    underlying_failure_remains_blocking: bool


@dataclass(frozen=True)
class SecurityExceptionDigestBundle:
    evidence_digest: str
    proposal_digest: str
    event_digest: str
    result_digest: str
    record_digest: str


@dataclass(frozen=True)
class SecurityExceptionRecord:
    exception_id: str
    lineage_id: str
    lineage_sequence: int
    visibility: str
    kind: str
    subject_kind: str
    subject_key: str
    severity: str
    state: str
    package: str | None
    locked_version: str | None
    dependency_scopes: tuple[str, ...]
    python_versions: tuple[str, ...]
    platforms: tuple[str, ...]
    aliases: tuple[str, ...]
    alias_revision: int
    evidence_revision: int
    evidence_digest: str
    response_started_at: str
    source_time_status: str
    last_approval_or_renewal: str
    review_after: str
    expires_at: str
    absolute_cap: str
    event_digest: str
    record_digest: str
    predecessor_record_digest: str
    effects: SecurityExceptionEffects


@dataclass(frozen=True)
class LineageEntry:
    data: Mapping[str, object]


@dataclass(frozen=True, init=False)
class SecurityExceptionInventory:
    contract_version: str
    contract_sha256: str
    public_records: tuple[SecurityExceptionRecord, ...]
    private_records: tuple[SecurityExceptionRecord, ...]
    lineages: tuple[LineageEntry, ...]
    authority_status: str

    @property
    def all_records(self) -> tuple[SecurityExceptionRecord, ...]:
        return self.public_records + self.private_records

    @property
    def dependency_records(self) -> tuple[SecurityExceptionRecord, ...]:
        """Typed dependency inventory for the issue #67 atomic cutover."""
        return tuple(
            record for record in self.all_records if record.subject_kind == "dependency_advisory"
        )


def is_structural_security_exception_inventory(value: object) -> bool:
    """Return whether value is a contract-shaped, explicitly untrusted inventory."""
    return (
        isinstance(value, SecurityExceptionInventory)
        and value.contract_version == "1.0"
        and value.contract_sha256 == EXPECTED_CONTRACT_SHA256
        and value.authority_status == "structural_unverified"
    )


def is_validated_security_exception_inventory(value: object) -> bool:
    """Return whether a live adapter authenticated the inventory.

    Contract 1.0 ships no such adapter.  Pure mapping validation therefore can
    never satisfy this predicate, even when the mapping claims authentication.
    """
    del value
    return False


def canonicalize_security_exception_projection(value: object) -> bytes:
    """Canonicalize a JSON-domain projection according to contract 1.0."""
    normalized = _normalize_canonical_value(value)
    return json.dumps(
        normalized,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def compute_security_exception_digest(domain: str, projection: object) -> str:
    """Hash a canonical projection with a contract-defined domain separator."""
    contract = load_security_exception_contract()
    canonicalization = contract.data.get("canonicalization")
    if not isinstance(canonicalization, Mapping):
        raise SecurityExceptionContractError("Contract canonicalization rules are missing.")
    domains = canonicalization.get("digest_domains")
    if not isinstance(domains, Mapping):
        raise SecurityExceptionContractError("Contract digest domains are missing.")
    separator = domains.get(domain)
    if not isinstance(separator, str):
        raise SecurityExceptionValidationError(
            f"Unsupported Security Exception digest domain {domain!r}."
        )
    return hashlib.sha256(
        separator.encode("utf-8") + canonicalize_security_exception_projection(projection)
    ).hexdigest()


def compute_security_exception_record_digests(
    record: Mapping[str, object],
    lineage_entry: Mapping[str, object],
) -> SecurityExceptionDigestBundle:
    """Compute the canonical digest bundle for one current record and lineage event."""
    contract = load_security_exception_contract()
    working_record = dict(record)
    working_entry = dict(lineage_entry)
    all_digest_fields = {
        "evidence_digest",
        "proposal_digest",
        "event_digest",
        "result_digest",
        "record_digest",
        "predecessor_record_digest",
    }
    evidence_digest = _compute_contract_digest(
        contract,
        "evidence",
        {key: value for key, value in working_record.items() if key not in all_digest_fields},
    )
    working_record["evidence_digest"] = evidence_digest
    proposal_digest = _compute_contract_digest(
        contract,
        "proposal",
        {
            key: value
            for key, value in working_record.items()
            if key not in {"proposal_digest", "event_digest", "result_digest", "record_digest"}
        },
    )
    working_record["proposal_digest"] = proposal_digest
    event_digest = _compute_contract_digest(
        contract,
        "event",
        {
            key: value
            for key, value in working_entry.items()
            if key not in {"event_digest", "result_digest", "record_digest"}
        },
    )
    working_entry["event_digest"] = event_digest
    working_record["event_digest"] = event_digest
    result_digest = _compute_contract_digest(
        contract,
        "result",
        {
            key: value
            for key, value in working_record.items()
            if key not in {"result_digest", "record_digest"}
        },
    )
    working_record["result_digest"] = result_digest
    working_entry["result_digest"] = result_digest
    record_digest = _compute_contract_digest(
        contract,
        "record",
        {
            key: value for key, value in working_entry.items() if key != "record_digest"
        },
    )
    return SecurityExceptionDigestBundle(
        evidence_digest=evidence_digest,
        proposal_digest=proposal_digest,
        event_digest=event_digest,
        result_digest=result_digest,
        record_digest=record_digest,
    )


def _compute_contract_digest(
    contract: SecurityExceptionContract,
    domain: str,
    projection: object,
) -> str:
    canonicalization = contract.data.get("canonicalization")
    domains = (
        canonicalization.get("digest_domains")
        if isinstance(canonicalization, Mapping)
        else None
    )
    separator = domains.get(domain) if isinstance(domains, Mapping) else None
    if not isinstance(separator, str):
        raise SecurityExceptionContractError(
            f"Contract digest domain {domain!r} is missing."
        )
    return hashlib.sha256(
        separator.encode("utf-8") + canonicalize_security_exception_projection(projection)
    ).hexdigest()


def parse_public_security_exception_command(
    command: str,
    *,
    comment_node_id: str,
    current_inventory: SecurityExceptionInventory | None = None,
    edited: bool = False,
    visibility: str = "public",
) -> PublicCommandRequest | RevocationPendingRequest:
    """Parse a public comment command without granting it any effect."""
    _validate_comment_node_id(comment_node_id, "comment_node_id")
    if edited:
        raise SecurityExceptionValidationError("Edited public command comments are rejected.")
    if visibility != "public":
        raise SecurityExceptionValidationError("Public commands govern public records only.")
    if not isinstance(command, str) or not command or command != command.strip():
        raise SecurityExceptionValidationError(
            "Command does not match an exact public command grammar."
        )
    if not command.isascii():
        raise SecurityExceptionValidationError(
            "Command does not match an exact public command grammar."
        )
    contract = load_security_exception_contract()
    grammars = contract.data.get("public_command_grammars")
    if not isinstance(grammars, Mapping):
        raise SecurityExceptionContractError("Public command grammars are missing.")
    tokens = command.split()
    raw_digest = hashlib.sha256(command.encode("utf-8")).hexdigest()
    malformed = grammars.get("malformed_revoke")
    if not isinstance(malformed, Mapping):
        raise SecurityExceptionContractError("Malformed revoke contract is missing.")
    prefix = malformed.get("exact_prefix")
    if tokens and tokens[0] == "/security-exception" and len(tokens) >= 2:
        action_token = tokens[1]
    else:
        action_token = ""
    if action_token in {"approve", "renew", "revoke"}:
        grammar = grammars.get(action_token)
        if not isinstance(grammar, list):
            raise SecurityExceptionContractError(f"Public {action_token} grammar is missing.")
        if len(tokens) == len(grammar):
            try:
                exception_id = _parse_uuid4_token(tokens[3], "exception_id")
                _validate_digest(tokens[4], "proposal_digest")
                if tokens[2] != "1.0":
                    raise SecurityExceptionValidationError(
                        "Command contract version must be 1.0."
                    )
                if action_token == "approve":
                    if tokens[5] != "none":
                        raise SecurityExceptionValidationError(
                            "Approve predecessor must be the literal none."
                        )
                else:
                    _validate_digest(tokens[5], "predecessor_effective_event_digest")
            except SecurityExceptionValidationError:
                if action_token != "revoke":
                    raise SecurityExceptionValidationError(
                        "Command does not match an exact public command grammar."
                    ) from None
            else:
                if action_token == "revoke":
                    _require_known_public_exception(current_inventory, exception_id)
                return PublicCommandRequest(
                    action=action_token,
                    exception_id=exception_id,
                    comment_node_id=comment_node_id,
                    raw_comment_digest=raw_digest,
                    proposal_digest=tokens[4],
                    predecessor_effective_event_digest=(
                        None if action_token == "approve" else tokens[5]
                    ),
                )
        if action_token == "revoke" and len(tokens) >= 4:
            exact_prefix = isinstance(prefix, list) and tokens[:3] == prefix[:3]
            exception_id = _parse_uuid4_token(tokens[3], "exception_id")
            if not exact_prefix:
                raise SecurityExceptionValidationError(
                    "Command does not match an exact public command grammar."
                )
            _require_known_public_exception(current_inventory, exception_id)
            return RevocationPendingRequest(
                action="malformed_revoke",
                exception_id=exception_id,
                comment_node_id=comment_node_id,
                raw_comment_digest=raw_digest,
            )
        raise SecurityExceptionValidationError(
            "Command does not match an exact public command grammar."
        )
    if action_token == "withdraw-invalid":
        grammar = grammars.get("withdraw_invalid")
        if not isinstance(grammar, list) or len(tokens) != len(grammar):
            raise SecurityExceptionValidationError(
                "Command does not match an exact public command grammar."
            )
        exception_id = _parse_uuid4_token(tokens[3], "exception_id")
        _require_known_public_exception(current_inventory, exception_id)
        if tokens[2] != "1.0":
            raise SecurityExceptionValidationError(
                "Command does not match an exact public command grammar."
            )
        for token, field_name in (
            (tokens[4], "pending_transition_digest"),
            (tokens[5], "predecessor_effective_event_digest"),
            (tokens[7], "malformed_raw_comment_digest"),
        ):
            _validate_digest(token, field_name)
        _validate_comment_node_id(tokens[6], "malformed_comment_node_id")
        return PublicCommandRequest(
            action="withdraw_invalid",
            exception_id=exception_id,
            comment_node_id=comment_node_id,
            raw_comment_digest=raw_digest,
            pending_transition_digest=tokens[4],
            predecessor_effective_event_digest=tokens[5],
            malformed_comment_node_id=tokens[6],
            malformed_raw_comment_digest=tokens[7],
        )
    raise SecurityExceptionValidationError(
        "Command does not match an exact public command grammar."
    )


def validate_public_transition_projection(
    request: PublicCommandRequest | RevocationPendingRequest,
    projection: Mapping[str, object],
    *,
    current_state: str,
    current_inventory: SecurityExceptionInventory,
    evaluated_at: str,
) -> StructuralTransitionProjection:
    """Structurally validate a transition projection without authenticating it."""
    contract = load_security_exception_contract()
    _validate_artifact(contract, "transition_projection", projection)
    if not isinstance(request, (PublicCommandRequest, RevocationPendingRequest)):
        raise SecurityExceptionValidationError(
            "A transition projection requires a valid exact public command request."
        )
    _validate_transition_inventory_binding(
        request,
        projection,
        current_state=current_state,
        current_inventory=current_inventory,
    )
    observed = _parse_datetime(projection.get("observed_at"), "observed_at")
    persisted = _parse_datetime(projection.get("persisted_at"), "persisted_at")
    evaluated = _parse_datetime(evaluated_at, "evaluated_at")
    if not (observed <= persisted <= evaluated):
        raise SecurityExceptionValidationError(
            "Transition observation or persistence time is from the future or non-monotonic."
        )
    transition_observation = contract.data.get("transition_observation")
    persistence_delay = (
        transition_observation.get("maximum_persistence_delay_seconds")
        if isinstance(transition_observation, Mapping)
        else None
    )
    maximum_age = (
        transition_observation.get("maximum_age_seconds")
        if isinstance(transition_observation, Mapping)
        else None
    )
    if any(
        not isinstance(value, int) or isinstance(value, bool)
        for value in (persistence_delay, maximum_age)
    ):
        raise SecurityExceptionContractError(
            "Security Exception transition-observation freshness policy is malformed."
        )
    assert isinstance(persistence_delay, int)
    assert isinstance(maximum_age, int)
    if persisted > observed + timedelta(seconds=persistence_delay):
        raise SecurityExceptionValidationError(
            "Transition persistence exceeds the 15-minute provenance window."
        )
    if evaluated - persisted >= timedelta(seconds=maximum_age):
        raise SecurityExceptionValidationError("Transition persistence evidence is stale.")
    authority = contract.authority
    if any(
        projection.get(field) != expected
        for field, expected in (
            ("authority_login", authority.login),
            ("authority_database_id", authority.database_id),
            ("authority_node_id", authority.node_id),
        )
    ):
        raise SecurityExceptionValidationError("Transition authority does not match contract 1.0.")
    if projection.get("visibility") != "public":
        raise SecurityExceptionValidationError("Public commands govern public records only.")
    bindings: dict[str, object] = {
        "action": request.action,
        "exception_id": request.exception_id,
        "request_comment_node_id": request.comment_node_id,
        "request_raw_comment_digest": request.raw_comment_digest,
    }
    if isinstance(request, RevocationPendingRequest):
        bindings.update(
            {
                "from_state": current_state,
                "to_state": "revocation_pending",
            }
        )
    elif request.action == "withdraw_invalid":
        bindings.update(
            {
                "pending_transition_digest": request.pending_transition_digest,
                "predecessor_effective_event_digest": (
                    request.predecessor_effective_event_digest
                ),
                "malformed_comment_node_id": request.malformed_comment_node_id,
                "malformed_raw_comment_digest": request.malformed_raw_comment_digest,
                "from_state": "revocation_pending",
                "to_state": "recomputation_required",
                "clears": "pending_transition_only",
                "restores_snapshot": False,
                "forces_fresh_recomputation": True,
            }
        )
    else:
        bindings.update(
            {
                "proposal_digest": request.proposal_digest,
                "predecessor_effective_event_digest": (
                    "none"
                    if request.action == "approve"
                    else request.predecessor_effective_event_digest
                ),
            }
        )
    mismatched = [
        field_name
        for field_name, expected in bindings.items()
        if projection.get(field_name) != expected
    ]
    if mismatched:
        raise SecurityExceptionValidationError(
            "Transition projection does not bind the request: "
            + ", ".join(sorted(mismatched))
            + "."
        )
    if projection.get("from_state") != current_state:
        raise SecurityExceptionValidationError(
            "Transition projection does not use the current state."
        )
    if projection.get("current_head_effective_event_digest") != projection.get(
        "predecessor_effective_event_digest"
    ):
        raise SecurityExceptionValidationError(
            "Transition projection does not require the current head."
        )
    state_machine = contract.data.get("state_machine")
    if not isinstance(state_machine, Mapping):
        raise SecurityExceptionContractError("Security Exception state machine is missing.")
    actions = state_machine.get("actions")
    if not isinstance(actions, Mapping):
        raise SecurityExceptionContractError(
            "Security Exception state-machine actions are missing."
        )
    action_contract = actions.get(request.action)
    if not isinstance(action_contract, Mapping):
        raise SecurityExceptionValidationError("Transition action is unsupported by contract 1.0.")
    from_states = action_contract.get("from")
    to_state = action_contract.get("to")
    if (
        not isinstance(from_states, list)
        or current_state not in from_states
        or projection.get("to_state") != to_state
    ):
        raise SecurityExceptionValidationError("Transition is forbidden by contract 1.0.")
    persisted_result_digest = _required_str(projection, "persisted_result_digest")
    if persisted_result_digest == "0" * 64:
        raise SecurityExceptionValidationError(
            "Persisted transition result digest cannot be the zero digest."
        )
    result_projection = {
        key: value for key, value in projection.items() if key != "persisted_result_digest"
    }
    expected_result_digest = _compute_contract_digest(
        contract,
        "result",
        result_projection,
    )
    if persisted_result_digest != expected_result_digest:
        raise SecurityExceptionValidationError(
            "persisted_result_digest does not equal the canonical transition result digest."
        )
    return StructuralTransitionProjection(
        action=request.action,
        from_state=current_state,
        to_state=_required_str(projection, "to_state"),
        persisted_result_digest=persisted_result_digest,
        trust_status="structural_unverified",
    )


def _validate_transition_inventory_binding(
    request: PublicCommandRequest | RevocationPendingRequest,
    projection: Mapping[str, object],
    *,
    current_state: str,
    current_inventory: SecurityExceptionInventory,
) -> None:
    if not is_structural_security_exception_inventory(current_inventory):
        raise SecurityExceptionValidationError(
            "Transition validation requires a structural current whole-ledger inventory."
        )
    historical_exception_ids = {
        record.exception_id for record in current_inventory.all_records
    } | {
        exception_id
        for entry in current_inventory.lineages
        if isinstance(exception_id := entry.data.get("exception_id"), str)
    }
    if request.action == "approve":
        if request.exception_id in historical_exception_ids:
            raise SecurityExceptionValidationError(
                "Approval requires a fresh globally history-unique exception ID."
            )
        return
    predecessor = (
        request.predecessor_effective_event_digest
        if isinstance(request, PublicCommandRequest)
        else projection.get("current_head_effective_event_digest")
    )
    matching_records: list[SecurityExceptionRecord] = []
    for record in current_inventory.public_records:
        if any(
            entry.data.get("lineage_id") == record.lineage_id
            and entry.data.get("sequence") == record.lineage_sequence
            and entry.data.get("event_digest") == predecessor
            for entry in current_inventory.lineages
        ):
            matching_records.append(record)
    if len(matching_records) != 1:
        raise SecurityExceptionValidationError(
            "Transition predecessor does not bind exactly one current public lineage head."
        )
    current_record = matching_records[0]
    if current_state != current_record.state:
        raise SecurityExceptionValidationError(
            "Transition current state does not equal the current public lineage head."
        )
    if request.action == "renew":
        if request.exception_id in historical_exception_ids:
            raise SecurityExceptionValidationError(
                "Renewal requires a fresh successor exception ID."
            )
    elif request.exception_id != current_record.exception_id:
        raise SecurityExceptionValidationError(
            "Non-renewal transition must retain the current exception ID."
        )


def validate_lineage_issuance_projection(
    projection: Mapping[str, object],
    *,
    current_inventory: SecurityExceptionInventory,
    evaluated_at: str,
) -> StructuralLineageIssuanceProjection:
    """Validate an unpersisted coordinator issuance projection without issuing it."""
    if not is_structural_security_exception_inventory(current_inventory):
        raise SecurityExceptionValidationError(
            "Lineage issuance requires a structural whole-ledger inventory."
        )
    contract = load_security_exception_contract()
    _validate_artifact(contract, "lineage_issuance_projection", projection)
    lineage_id = _parse_uuid4_token(_required_str(projection, "lineage_id"), "lineage_id")
    exception_id = _parse_uuid4_token(
        _required_str(projection, "exception_id"), "exception_id"
    )
    coordinator_id = _parse_uuid4_token(
        _required_str(projection, "coordinator_id"), "coordinator_id"
    )
    subject_identity = _validate_issuance_subject_identity(
        contract,
        _required_str(projection, "subject_identity"),
    )
    if any(
        entry.data.get("lineage_id") == lineage_id
        or entry.data.get("subject_identity") == subject_identity
        for entry in current_inventory.lineages
    ):
        raise SecurityExceptionValidationError(
            "Lineage issuance would reuse an existing lineage or subject identity."
        )
    if any(
        record.exception_id == exception_id for record in current_inventory.all_records
    ) or any(
        entry.data.get("exception_id") == exception_id
        for entry in current_inventory.lineages
    ):
        raise SecurityExceptionValidationError(
            "Lineage issuance would reuse an existing or historical exception identifier."
        )
    issued = _parse_datetime(projection.get("issued_at"), "issued_at")
    evaluated = _parse_datetime(evaluated_at, "evaluated_at")
    issuance_policy = contract.data.get("lineage_issuance")
    maximum_future_skew = (
        issuance_policy.get("maximum_future_skew_seconds")
        if isinstance(issuance_policy, Mapping)
        else None
    )
    if not isinstance(maximum_future_skew, int) or isinstance(maximum_future_skew, bool):
        raise SecurityExceptionContractError(
            "Security Exception lineage-issuance time policy is malformed."
        )
    if issued > evaluated + timedelta(seconds=maximum_future_skew):
        raise SecurityExceptionValidationError("Lineage issuance time is from the future.")
    return StructuralLineageIssuanceProjection(
        coordinator_id=coordinator_id,
        lineage_id=lineage_id,
        exception_id=exception_id,
        visibility=_required_str(projection, "visibility"),
        subject_identity=subject_identity,
        persisted=False,
    )


def validate_advisory_reconciliation_projection(
    projection: Mapping[str, object],
    *,
    current_inventory: SecurityExceptionInventory,
) -> StructuralAdvisoryReconciliationProjection:
    """Validate unpersisted alias/evidence revision reconciliation."""
    if not is_structural_security_exception_inventory(current_inventory):
        raise SecurityExceptionValidationError(
            "Advisory reconciliation requires a structural whole-ledger inventory."
        )
    contract = load_security_exception_contract()
    _validate_artifact(contract, "advisory_reconciliation_projection", projection)
    lineage_id = _parse_uuid4_token(_required_str(projection, "lineage_id"), "lineage_id")
    matching = [
        record for record in current_inventory.all_records if record.lineage_id == lineage_id
    ]
    if len(matching) != 1:
        raise SecurityExceptionValidationError(
            "Advisory reconciliation must bind exactly one current lineage record."
        )
    current = matching[0]
    if projection.get("current_record_digest") != current.record_digest:
        raise SecurityExceptionValidationError(
            "Advisory reconciliation does not bind the exact current lineage head."
        )
    prior_alias = _required_int(projection, "prior_alias_revision")
    alias_revision = _required_int(projection, "alias_revision")
    prior_evidence = _required_int(projection, "prior_evidence_revision")
    evidence_revision = _required_int(projection, "evidence_revision")
    if prior_alias != current.alias_revision or prior_evidence != current.evidence_revision:
        raise SecurityExceptionValidationError(
            "Advisory reconciliation prior revisions do not equal current revisions."
        )
    if alias_revision not in {prior_alias, prior_alias + 1} or evidence_revision not in {
        prior_evidence,
        prior_evidence + 1,
    }:
        raise SecurityExceptionValidationError(
            "Advisory reconciliation revisions may advance by exactly one."
        )
    if alias_revision == prior_alias and evidence_revision == prior_evidence:
        raise SecurityExceptionValidationError(
            "Advisory reconciliation must advance an alias or evidence revision."
        )
    aliases = _string_tuple(projection, "aliases")
    if aliases != tuple(sorted(set(aliases))):
        raise SecurityExceptionValidationError(
            "Advisory reconciliation aliases must be sorted and unique."
        )
    evidence_digest = _required_str(projection, "evidence_digest")
    if alias_revision == prior_alias and aliases != current.aliases:
        raise SecurityExceptionValidationError(
            "Aliases changed without an alias revision."
        )
    if evidence_revision == prior_evidence and evidence_digest != current.evidence_digest:
        raise SecurityExceptionValidationError(
            "Evidence digest changed without an evidence revision."
        )
    return StructuralAdvisoryReconciliationProjection(
        lineage_id=lineage_id,
        alias_revision=alias_revision,
        aliases=aliases,
        evidence_revision=evidence_revision,
        evidence_digest=evidence_digest,
        persisted=False,
    )


def validate_authority_migration_projection(projection: Mapping[str, object]) -> None:
    """Validate the explicit migration shape, then refuse it under contract 1.0."""
    contract = load_security_exception_contract()
    _validate_artifact(contract, "authority_migration_projection", projection)
    raise SecurityExceptionValidationError(
        "Authority migration requires unsupported Security Exception contract 2.0."
    )


def validate_provider_observation_envelope(
    envelope: Mapping[str, object],
    *,
    evaluated_at: str,
) -> StructuralProviderObservation:
    """Validate an offline provider shape without authenticating its producer."""
    contract = load_security_exception_contract()
    _validate_artifact(contract, "provider_observation", envelope)
    completed = _parse_datetime(
        envelope.get("observation_completed_at"), "observation_completed_at"
    )
    valid_until = _parse_datetime(envelope.get("valid_until"), "valid_until")
    provider_until = _parse_datetime(
        envelope.get("provider_valid_until"), "provider_valid_until"
    )
    auth_until = _parse_datetime(
        envelope.get("provider_auth_valid_until"), "provider_auth_valid_until"
    )
    evaluated = _parse_datetime(evaluated_at, "evaluated_at")
    if not (completed <= evaluated < valid_until):
        raise SecurityExceptionValidationError(
            "Provider evidence violates the strict observation window."
        )
    if valid_until > completed + timedelta(minutes=15):
        raise SecurityExceptionValidationError(
            "Provider observation validity exceeds the 15-minute bound."
        )
    if valid_until > provider_until or valid_until > auth_until:
        raise SecurityExceptionValidationError(
            "Provider observation validity exceeds the provider or authentication bound."
        )
    passes = envelope.get("passes")
    if not isinstance(passes, list) or len(passes) != 2:
        raise SecurityExceptionValidationError("Provider evidence requires exactly two passes.")
    expected_semantic = _required_str(envelope, "semantic_digest")
    epoch_id = _required_str(envelope, "epoch_id")
    required_sources = (
        "github_dependabot",
        "osv",
        "github_private_advisory",
        "first_party_validation",
    )
    source_queries = {
        "github_dependabot": "repository-vulnerability-alerts",
        "osv": "osv-locked-dependencies",
        "github_private_advisory": "private-security-advisories",
        "first_party_validation": "validated-first-party-findings",
    }
    if tuple(_string_tuple(envelope, "sources")) != required_sources:
        raise SecurityExceptionValidationError(
            "Provider evidence must contain every required source exactly once."
        )
    producer_provenance = envelope.get("producer_provenance")
    if not isinstance(producer_provenance, Mapping):
        raise SecurityExceptionValidationError(
            "Provider evidence requires structural producer provenance."
        )
    semantic_manifests: list[tuple[tuple[object, ...], ...]] = []
    aggregate_manifests: list[list[dict[str, object]]] = []
    projected_times: list[datetime] = []
    for pass_index, pass_value in enumerate(passes, start=1):
        if not isinstance(pass_value, Mapping):
            raise SecurityExceptionValidationError("Provider pass must be an object.")
        if (
            pass_value.get("pass_number") != pass_index
            or pass_value.get("complete") is not True
            or pass_value.get("semantic_digest") != expected_semantic
        ):
            raise SecurityExceptionValidationError(
                "Provider evidence requires two complete semantic-identical structural passes."
            )
        pages = pass_value.get("pages")
        if not isinstance(pages, list) or len(pages) != len(required_sources):
            raise SecurityExceptionValidationError(
                "Provider pass must contain every required source exactly once."
            )
        manifest: list[tuple[object, ...]] = []
        aggregate_manifest: list[dict[str, object]] = []
        pass_times: list[datetime] = []
        for page_index, page_value in enumerate(pages, start=1):
            if not isinstance(page_value, Mapping):
                raise SecurityExceptionValidationError("Provider page must be an object.")
            if page_value.get("page_number") != page_index:
                raise SecurityExceptionValidationError("Provider pages are not strictly ordered.")
            source = page_value.get("source")
            expected_source = required_sources[page_index - 1]
            expected_query = source_queries.get(source) if isinstance(source, str) else None
            if source != expected_source or page_value.get("query_id") != expected_query:
                raise SecurityExceptionValidationError(
                    "Provider source/query cardinality is incomplete or out of order."
                )
            cursor_in = page_value.get("cursor_in")
            if cursor_in != "":
                raise SecurityExceptionValidationError(
                    "Single-page provider source must start with an empty cursor."
                )
            next_cursor = page_value.get("next_cursor")
            next_fact = page_value.get("next_fact")
            if not isinstance(next_cursor, str):
                raise SecurityExceptionValidationError("Provider next cursor is malformed.")
            if next_fact != "terminal" or next_cursor:
                raise SecurityExceptionValidationError(
                    "Provider source pagination is not terminal and complete."
                )
            item_digests = _string_tuple(page_value, "item_digests")
            if item_digests != tuple(sorted(set(item_digests))):
                raise SecurityExceptionValidationError(
                    "Provider source item digests must be sorted and unique."
                )
            request_projection = {
                "epoch_id": epoch_id,
                "source": source,
                "query_id": page_value.get("query_id"),
                "page_number": page_index,
                "cursor_in": cursor_in,
            }
            _require_canonical_digest(
                contract,
                "provider_request",
                request_projection,
                page_value.get("request_digest"),
            )
            semantic_projection = {
                "source": source,
                "query_id": page_value.get("query_id"),
                "item_digests": list(item_digests),
            }
            _require_canonical_digest(
                contract,
                "provider_semantic",
                semantic_projection,
                page_value.get("semantic_digest"),
            )
            response_projection = {
                "request_digest": page_value.get("request_digest"),
                "semantic_digest": page_value.get("semantic_digest"),
                "status": page_value.get("status"),
                "validator": page_value.get("validator"),
                "next_cursor": next_cursor,
                "next_fact": next_fact,
            }
            _require_canonical_digest(
                contract,
                "provider_response",
                response_projection,
                page_value.get("response_digest"),
            )
            provider_date = _parse_datetime(page_value.get("provider_date"), "provider_date")
            if abs((provider_date - completed).total_seconds()) > 120:
                raise SecurityExceptionValidationError(
                    "Provider projected time exceeds the allowed 120 seconds of skew."
                )
            if pass_times and provider_date < pass_times[-1]:
                raise SecurityExceptionValidationError("Provider projected time is not monotonic.")
            pass_times.append(provider_date)
            receipt_projection = {
                "producer_provenance": producer_provenance,
                "response_digest": page_value.get("response_digest"),
                "provider_date": page_value.get("provider_date"),
            }
            _require_canonical_digest(
                contract,
                "provider_receipt",
                receipt_projection,
                page_value.get("receipt_digest"),
            )
            manifest.append(
                (
                    source,
                    page_value.get("query_id"),
                    page_value.get("semantic_digest"),
                    item_digests,
                )
            )
            aggregate_manifest.append(semantic_projection)
        semantic_manifests.append(tuple(manifest))
        aggregate_manifests.append(aggregate_manifest)
        projected_times.extend(pass_times)
    if semantic_manifests[0] != semantic_manifests[1]:
        raise SecurityExceptionValidationError(
            "Provider passes are not semantic-identical ordered page manifests."
        )
    aggregate_projection = {
        "epoch_id": epoch_id,
        "repository_full_name": envelope.get("repository_full_name"),
        "issue_number": envelope.get("issue_number"),
        "account_login": envelope.get("account_login"),
        "sources": aggregate_manifests[0],
    }
    _require_canonical_digest(
        contract,
        "provider_aggregate",
        aggregate_projection,
        expected_semantic,
    )
    if any(
        later < earlier
        for earlier, later in zip(projected_times, projected_times[1:], strict=False)
    ):
        raise SecurityExceptionValidationError(
            "Provider projected time is not monotonic across passes."
        )
    return StructuralProviderObservation(
        provider=_required_str(envelope, "provider"),
        observation_completed_at=_required_str(envelope, "observation_completed_at"),
        valid_until=_required_str(envelope, "valid_until"),
        semantic_digest=expected_semantic,
        trust_status="structural_unverified",
    )


def validate_response_clock_inventory(
    inventory: Mapping[str, object],
    *,
    structural_observations: tuple[StructuralProviderObservation, ...],
    current_inventory: SecurityExceptionInventory,
    evaluated_at: str,
) -> ResponseClockState:
    """Validate complete response-clock inventory and calculate contract deadlines."""
    contract = load_security_exception_contract()
    _validate_artifact(contract, "response_clock_inventory", inventory)
    evaluated = _parse_datetime(evaluated_at, "evaluated_at")
    if not is_structural_security_exception_inventory(current_inventory):
        raise SecurityExceptionValidationError(
            "Response clocks require a structural current whole-ledger inventory."
        )
    if not structural_observations:
        raise SecurityExceptionValidationError(
            "Response clocks require complete provider observations."
        )
    for observation in structural_observations:
        completed = _parse_datetime(
            observation.observation_completed_at,
            "observation_completed_at",
        )
        valid_until = _parse_datetime(observation.valid_until, "valid_until")
        if not (completed <= evaluated < valid_until):
            raise SecurityExceptionValidationError(
                "Provider evidence violates the strict observation window."
            )
    expected_digests = tuple(
        sorted(observation.semantic_digest for observation in structural_observations)
    )
    observed_digests = _string_tuple(inventory, "observation_semantic_digests")
    if tuple(sorted(observed_digests)) != expected_digests:
        raise SecurityExceptionValidationError(
            "Response-clock inventory does not bind every structural provider observation."
        )
    complete = all(
        inventory.get(field) is True
        for field in ("source_available", "pagination_complete", "reconciliation_complete")
    )
    if not complete:
        raise SecurityExceptionValidationError(
            "Response-clock inventory must be available, pagination-complete, and reconciled."
        )
    raw_entries = inventory.get("entries")
    if not isinstance(raw_entries, list):
        raise SecurityExceptionValidationError("Response-clock entries must be an array.")
    positive_zero = inventory.get("positive_zero") is True
    if positive_zero != (not raw_entries):
        raise SecurityExceptionValidationError(
            "Response-clock positive zero is valid only for a complete empty inventory."
        )
    clock_entries = tuple(_project_response_clock_entry(value, evaluated) for value in raw_entries)
    current_by_lineage = {
        record.lineage_id: record for record in current_inventory.all_records
    }
    for entry in clock_entries:
        current = current_by_lineage.get(entry.lineage_id)
        if current is None or (
            entry.exception_id != current.exception_id
            or entry.lineage_sequence != current.lineage_sequence
            or entry.exact_lineage_head_record_digest != current.record_digest
        ):
            raise SecurityExceptionValidationError(
                "Response-clock entry does not bind the exact current lineage head."
            )
        if (
            entry.response_started_at != current.response_started_at
            or entry.source_time_status != current.source_time_status
            or entry.severity != current.severity
        ):
            raise SecurityExceptionValidationError(
                "Response-clock timing and severity do not equal the current record."
            )
        if current.subject_kind == "dependency_advisory" and (
            entry.scope not in current.dependency_scopes
            or entry.python_versions != current.python_versions
            or entry.platforms != current.platforms
        ):
            raise SecurityExceptionValidationError(
                "Response-clock dependency identity does not equal the current record."
            )
    if {entry.lineage_id for entry in clock_entries} != set(current_by_lineage):
        raise SecurityExceptionValidationError(
            "Response-clock inventory does not reconcile all current whole-ledger lineages."
        )
    identities = [entry.source_item_identity for entry in clock_entries]
    if len(identities) != len(set(identities)):
        raise SecurityExceptionValidationError(
            "Response-clock inventory contains duplicate exact source identities."
        )
    raise SecurityExceptionValidationError(
        "Response clocks and positive-zero claims require an authenticated provider adapter; "
        "contract 1.0 exposes structural observations only."
    )


def compute_security_exception_lifecycle(
    record: SecurityExceptionRecord,
    *,
    evaluated_at: str,
) -> SecurityExceptionLifecycle:
    """Compute lifecycle validity without conferring any gate or product effect."""
    if not isinstance(record, SecurityExceptionRecord):
        raise SecurityExceptionValidationError(
            "Lifecycle computation requires a typed Security Exception record."
        )
    evaluated = _parse_datetime(evaluated_at, "evaluated_at")
    effective_at = _parse_datetime(
        record.last_approval_or_renewal,
        "last_approval_or_renewal",
    )
    review_after = _parse_datetime(record.review_after, "review_after")
    expires_at = _parse_datetime(record.expires_at, "expires_at")
    if evaluated < effective_at:
        return SecurityExceptionLifecycle(
            state=record.state,
            active=False,
            reason="not_effective",
            evaluated_at=evaluated_at,
            trust_status="structural_unverified",
        )
    if record.state in {"revoked", "resolved"}:
        return SecurityExceptionLifecycle(
            state=record.state,
            active=False,
            reason=f"{record.state}_terminal",
            evaluated_at=evaluated_at,
            trust_status="structural_unverified",
        )
    if record.state in {"revocation_pending", "recomputation_required"}:
        return SecurityExceptionLifecycle(
            state=record.state,
            active=False,
            reason=record.state,
            evaluated_at=evaluated_at,
            trust_status="structural_unverified",
        )
    if evaluated >= expires_at:
        reason = "expired"
        active = False
    elif evaluated >= review_after:
        reason = "review_due"
        active = False
    else:
        reason = "structurally_current"
        active = False
    return SecurityExceptionLifecycle(
        state=record.state,
        active=active,
        reason=reason,
        evaluated_at=evaluated_at,
        trust_status="structural_unverified",
    )


def _validate_lifecycle_values(
    record: Mapping[str, object],
    *,
    evaluated_at: str,
) -> None:
    response_started = _parse_datetime(record.get("response_started_at"), "response_started_at")
    last_approval = _parse_datetime(
        record.get("last_approval_or_renewal"), "last_approval_or_renewal"
    )
    review_after = _parse_datetime(record.get("review_after"), "review_after")
    expires_at = _parse_datetime(record.get("expires_at"), "expires_at")
    absolute_cap = _parse_datetime(record.get("absolute_cap"), "absolute_cap")
    evaluated = _parse_datetime(evaluated_at, "evaluated_at")
    if response_started > last_approval:
        raise SecurityExceptionValidationError(
            "last_approval_or_renewal cannot precede response_started_at."
        )
    if last_approval > evaluated:
        raise SecurityExceptionValidationError(
            "last_approval_or_renewal is from the future."
        )
    if not (
        last_approval < review_after
        and review_after <= min(last_approval + timedelta(days=30), expires_at)
    ):
        raise SecurityExceptionValidationError(
            "review_after must be after approval and no later than 30 days or expires_at."
        )
    if not review_after <= expires_at <= absolute_cap:
        raise SecurityExceptionValidationError(
            "Lifecycle requires review_after <= expires_at <= absolute_cap."
        )
    severity = _required_str(record, "severity")
    kind = _required_str(record, "kind")
    caps = [response_started + timedelta(days=90)]
    if kind in {"control_bypass", "control_unavailability"}:
        caps.append(response_started + timedelta(days=7))
    if severity == "critical":
        caps.append(response_started + timedelta(hours=72))
    elif severity == "high":
        caps.append(response_started + timedelta(days=14))
    if absolute_cap > min(caps):
        raise SecurityExceptionValidationError(
            "absolute_cap exceeds the response, severity, or exception-kind lifecycle cap."
        )


def _project_response_clock_entry(value: object, evaluated: datetime) -> ResponseClockEntry:
    if not isinstance(value, Mapping):
        raise SecurityExceptionValidationError("Response-clock entry must be an object.")
    source_query = {
        "github_dependabot": "repository-vulnerability-alerts",
        "osv": "osv-locked-dependencies",
        "github_private_advisory": "private-security-advisories",
        "first_party_validation": "validated-first-party-findings",
    }
    source = _required_str(value, "source")
    query_id = _required_str(value, "query_id")
    if source_query.get(source) != query_id:
        raise SecurityExceptionValidationError("Response-clock source/query pair is not closed.")
    authoritative = value.get("authoritative_source_published_at")
    first_observed = _parse_datetime(value.get("first_observed_at"), "first_observed_at")
    if authoritative is None:
        started = first_observed
        source_status = "first_observed_upper_bound"
        triage_state = "uncertain"
        disposition_state = "uncertain"
    else:
        started = _parse_datetime(authoritative, "authoritative_source_published_at")
        if started > first_observed:
            raise SecurityExceptionValidationError(
                "Authoritative source publication cannot follow retained first observation."
            )
        source_status = "authoritative"
        triage_state = "pending"
        disposition_state = "pending"
    severity = _required_str(value, "severity")
    credible_severities = _string_tuple(value, "credible_severities")
    severity_order = ("critical", "high", "medium", "low")
    ordered_credible = tuple(item for item in severity_order if item in credible_severities)
    if credible_severities != ordered_credible or not credible_severities:
        raise SecurityExceptionValidationError(
            "Credible severities must be unique and ordered highest-first."
        )
    if severity != credible_severities[0]:
        raise SecurityExceptionValidationError(
            "Response-clock severity must equal the highest credible severity."
        )
    triage_deadline = _triage_deadline(started, severity)
    disposition_deadline = _disposition_deadline(started, severity)
    if source_status == "authoritative":
        if triage_deadline is not None and evaluated >= triage_deadline:
            triage_state = "overdue"
        if evaluated >= disposition_deadline:
            disposition_state = "overdue"
    return ResponseClockEntry(
        lineage_id=_parse_uuid4_token(_required_str(value, "lineage_id"), "lineage_id"),
        exception_id=_parse_uuid4_token(_required_str(value, "exception_id"), "exception_id"),
        lineage_sequence=_required_int(value, "lineage_sequence"),
        exact_lineage_head_record_digest=_required_str(
            value, "exact_lineage_head_record_digest"
        ),
        source=source,
        query_id=query_id,
        scope=_required_str(value, "scope"),
        python_versions=_string_tuple(value, "python_versions"),
        platforms=_string_tuple(value, "platforms"),
        source_item_identity=_required_str(value, "source_item_identity"),
        severity=severity,
        credible_severities=credible_severities,
        response_started_at=_format_datetime(started),
        source_time_status=source_status,
        triage_deadline=None if triage_deadline is None else _format_datetime(triage_deadline),
        disposition_deadline=_format_datetime(disposition_deadline),
        triage_state=triage_state,
        disposition_state=disposition_state,
    )


def _triage_deadline(started: datetime, severity: str) -> datetime | None:
    if severity == "critical":
        return started + timedelta(hours=24)
    if severity == "high":
        return _add_weekdays_utc(started, 2)
    if severity in {"medium", "low"}:
        return None
    raise SecurityExceptionValidationError("Response-clock severity is unsupported.")


def _disposition_deadline(started: datetime, severity: str) -> datetime:
    durations = {
        "critical": timedelta(hours=72),
        "high": timedelta(days=14),
        "medium": timedelta(days=30),
        "low": timedelta(days=90),
    }
    duration = durations.get(severity)
    if duration is None:
        raise SecurityExceptionValidationError("Response-clock severity is unsupported.")
    return started + duration


def _add_weekdays_utc(started: datetime, days: int) -> datetime:
    result = started
    remaining = days
    while remaining:
        result += timedelta(days=1)
        if result.weekday() < 5:
            remaining -= 1
    return result


def _format_datetime(value: datetime) -> str:
    return value.isoformat(timespec="seconds").replace("+00:00", "Z")


def _parse_uuid4_token(value: str, field: str) -> str:
    try:
        parsed = uuid.UUID(value)
    except ValueError as error:
        raise SecurityExceptionValidationError(f"{field} must be a canonical UUIDv4.") from error
    if parsed.version != 4 or str(parsed) != value:
        raise SecurityExceptionValidationError(f"{field} must be a canonical UUIDv4.")
    return value


def _validate_comment_node_id(value: object, field_name: str) -> None:
    if (
        not isinstance(value, str)
        or not value
        or len(value) > 256
        or re.fullmatch(r"[A-Za-z0-9_=-]+", value) is None
    ):
        raise SecurityExceptionValidationError(
            f"{field_name} must be a bounded immutable provider node ID."
        )


def _require_known_public_exception(
    current_inventory: SecurityExceptionInventory | None,
    exception_id: str,
) -> None:
    if not isinstance(current_inventory, SecurityExceptionInventory) or not (
        is_structural_security_exception_inventory(current_inventory)
    ):
        raise SecurityExceptionValidationError(
            "Revoke and withdrawal commands require structural current public inventory."
        )
    if not any(
        record.exception_id == exception_id for record in current_inventory.public_records
    ):
        raise SecurityExceptionValidationError(
            "Revoke and withdrawal commands require a known public exception ID."
        )


def _normalize_canonical_value(value: object) -> object:
    if value is None or isinstance(value, bool) or isinstance(value, int):
        return value
    if isinstance(value, float):
        raise SecurityExceptionValidationError(
            "Security Exception canonicalization rejects floating-point numbers."
        )
    if isinstance(value, str):
        return unicodedata.normalize("NFC", value)
    if isinstance(value, (list, tuple)):
        return [_normalize_canonical_value(item) for item in value]
    if isinstance(value, Mapping):
        normalized: dict[str, object] = {}
        for key, item in value.items():
            if not isinstance(key, str):
                raise SecurityExceptionValidationError(
                    "Security Exception canonical objects require string keys."
                )
            normalized_key = unicodedata.normalize("NFC", key)
            if normalized_key in normalized:
                raise SecurityExceptionValidationError(
                    "Security Exception canonical object keys collide after NFC normalization."
                )
            normalized[normalized_key] = _normalize_canonical_value(item)
        return normalized
    raise SecurityExceptionValidationError(
        f"Security Exception canonicalization rejects {type(value).__name__}."
    )


def load_security_exception_contract(
    path: str | Path | None = None,
) -> SecurityExceptionContract:
    """Load contract 1.0 only after verifying its exact packaged bytes."""
    contract_path = Path(path) if path is not None else Path(__file__).with_name(CONTRACT_FILENAME)
    try:
        descriptor = os.open(
            contract_path,
            os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0),
        )
        try:
            before = os.fstat(descriptor)
            if not stat.S_ISREG(before.st_mode):
                raise OSError("contract is not a regular file")
            payload = os.read(descriptor, MAX_CONTRACT_BYTES + 1)
            if len(payload) > MAX_CONTRACT_BYTES or os.read(descriptor, 1):
                raise OSError("contract exceeds the byte limit")
            after = os.fstat(descriptor)
            if (
                before.st_dev,
                before.st_ino,
                before.st_size,
                before.st_mtime_ns,
                before.st_ctime_ns,
            ) != (
                after.st_dev,
                after.st_ino,
                after.st_size,
                after.st_mtime_ns,
                after.st_ctime_ns,
            ) or after.st_size != len(payload):
                raise OSError("contract changed while being read")
        finally:
            os.close(descriptor)
    except OSError as error:
        raise SecurityExceptionContractError(
            "Security Exception contract 1.0 is unavailable."
        ) from error
    digest = hashlib.sha256(payload).hexdigest()
    if digest != EXPECTED_CONTRACT_SHA256:
        raise SecurityExceptionContractError(
            "Security Exception contract 1.0 does not match the embedded SHA-256."
        )
    try:
        data = json.loads(payload)
    except json.JSONDecodeError as error:
        raise SecurityExceptionContractError(
            "Security Exception contract 1.0 is not valid JSON."
        ) from error
    if not isinstance(data, dict):
        raise SecurityExceptionContractError("Security Exception contract root must be an object.")
    if data.get("artifact_kind") != "security_exception_contract":
        raise SecurityExceptionContractError(
            "Unsupported Security Exception contract artifact kind."
        )
    if data.get("contract_version") != "1.0":
        raise SecurityExceptionContractError("Unsupported Security Exception contract version.")
    authority_container = data.get("authority")
    if not isinstance(authority_container, dict):
        raise SecurityExceptionContractError("Security Exception contract authority is missing.")
    authority_data = authority_container.get("risk_authority")
    if not isinstance(authority_data, dict):
        raise SecurityExceptionContractError("Security Exception risk authority is missing.")
    login = authority_data.get("login")
    database_id = authority_data.get("database_id")
    node_id = authority_data.get("node_id")
    if not (
        isinstance(login, str)
        and isinstance(database_id, int)
        and isinstance(node_id, str)
    ):
        raise SecurityExceptionContractError("Security Exception risk authority is malformed.")
    return SecurityExceptionContract(
        artifact_kind="security_exception_contract",
        contract_version="1.0",
        authority=RiskAuthority(login=login, database_id=database_id, node_id=node_id),
        data=data,
        sha256=digest,
    )


def validate_public_security_exception_ledger(
    public_ledger: Mapping[str, object],
    *,
    evaluated_at: str,
) -> None:
    """Validate standalone public fields; private lineage reconciliation is separate."""
    contract = load_security_exception_contract()
    _validate_artifact(contract, "public_ledger", public_ledger)
    public_values = public_ledger.get("exceptions", [])
    if not isinstance(public_values, list):
        raise SecurityExceptionValidationError(
            "Public Security Exception records must be an array."
        )
    _validate_projection_confidentiality(public_values, [])
    _validate_kind_subject_pairs(contract, public_values)
    records: list[Mapping[str, object]] = []
    for record in public_values:
        if not isinstance(record, Mapping):
            raise SecurityExceptionValidationError(
                "Public Security Exception record must be an object."
            )
        _validate_record_semantics(
            contract,
            record,
            visibility="public",
            evaluated_at=evaluated_at,
        )
        records.append(record)
    exception_ids = [_required_str(record, "exception_id") for record in records]
    lineage_ids = [_required_str(record, "lineage_id") for record in records]
    if len(exception_ids) != len(set(exception_ids)):
        raise SecurityExceptionValidationError(
            "Public Security Exception ledger contains exception identifier reuse."
        )
    if len(lineage_ids) != len(set(lineage_ids)):
        raise SecurityExceptionValidationError(
            "Public Security Exception ledger contains multiple current lineage records."
        )
    # Contract 1.0 keeps lineage entries out of the public schema. The private
    # projection binds and recomputes event and record digests for the whole ledger.
    _validate_canonical_digests(contract, records, [])


def validate_security_exception_inventory(
    public_ledger: Mapping[str, object],
    private_projection: Mapping[str, object] | None,
    authority_observation: Mapping[str, object],
    *,
    evaluated_at: str,
) -> SecurityExceptionInventory:
    """Validate public and sanitized private projections as one closed inventory."""
    contract = load_security_exception_contract()
    _validate_artifact(contract, "public_ledger", public_ledger)
    if private_projection is None:
        raise SecurityExceptionValidationError(
            "The required sanitized private projection is unavailable."
        )
    _validate_artifact(contract, "private_projection", private_projection)
    _validate_artifact(contract, "authority_observation", authority_observation)
    _validate_authority(contract, authority_observation, evaluated_at=evaluated_at)
    public_values = public_ledger.get("exceptions", [])
    private_values = private_projection["records"]
    lineage_projection = private_projection["lineage_index"]
    if not isinstance(public_values, list) or not isinstance(private_values, list):
        raise SecurityExceptionValidationError("Security Exception records must be arrays.")
    if not isinstance(lineage_projection, Mapping):
        raise SecurityExceptionValidationError("The lineage index projection is malformed.")
    lineage_values = lineage_projection["entries"]
    if not isinstance(lineage_values, list):
        raise SecurityExceptionValidationError("Lineage index entries must be an array.")
    _validate_projection_confidentiality(public_values, private_values)
    _validate_kind_subject_pairs(contract, [*public_values, *private_values])
    for record in public_values:
        _validate_record_semantics(
            contract, record, visibility="public", evaluated_at=evaluated_at
        )
    for record in private_values:
        _validate_record_semantics(
            contract, record, visibility="private", evaluated_at=evaluated_at
        )
    _validate_lineages(
        contract,
        [*public_values, *private_values],
        lineage_values,
        evaluated_at=evaluated_at,
    )
    public_records = tuple(_project_record(contract, value) for value in public_values)
    private_records = tuple(_project_record(contract, value) for value in private_values)
    inventory = object.__new__(SecurityExceptionInventory)
    object.__setattr__(inventory, "contract_version", contract.contract_version)
    object.__setattr__(inventory, "contract_sha256", contract.sha256)
    object.__setattr__(inventory, "public_records", public_records)
    object.__setattr__(inventory, "private_records", private_records)
    object.__setattr__(
        inventory,
        "lineages",
        tuple(
            LineageEntry(_freeze_projection_mapping(value))
            for value in lineage_values
            if isinstance(value, Mapping)
        ),
    )
    object.__setattr__(inventory, "authority_status", "structural_unverified")
    return inventory


def _validate_record_semantics(
    contract: SecurityExceptionContract,
    raw: object,
    *,
    visibility: str,
    evaluated_at: str,
) -> None:
    if not isinstance(raw, Mapping):
        raise SecurityExceptionValidationError("Security Exception record must be an object.")
    exception_id = _uuid4(raw, "exception_id")
    lineage_id = _uuid4(raw, "lineage_id")
    del exception_id
    if _required_int(raw, "lineage_sequence") < 1:
        raise SecurityExceptionValidationError("lineage_sequence must be positive.")
    for field_name in ("alias_revision", "evidence_revision"):
        if _required_int(raw, field_name) < 1:
            raise SecurityExceptionValidationError(f"{field_name} must be positive.")
    enums = contract.data.get("enums")
    if not isinstance(enums, Mapping):
        raise SecurityExceptionContractError("Security Exception enums are missing.")
    for field_name, enum_name in (
        ("kind", "exception_kinds"),
        ("subject_kind", "subject_kinds"),
        ("visibility", "visibility"),
        ("severity", "severity"),
        ("state", "record_states"),
        ("source_time_status", "source_time_status"),
        ("fix_availability", "fix_availability"),
    ):
        allowed = enums.get(enum_name)
        if not isinstance(allowed, list) or raw.get(field_name) not in allowed:
            raise SecurityExceptionValidationError(
                f"{field_name} is outside the closed contract enum."
            )
    authority = contract.authority
    for field_name, expected in (
        ("authority_login", authority.login),
        ("authority_database_id", authority.database_id),
        ("authority_node_id", authority.node_id),
    ):
        if raw.get(field_name) != expected:
            raise SecurityExceptionValidationError(
                f"Security Exception record {field_name} does not match the sole risk authority."
            )
    for field_name in (
        "proposal_digest",
        "event_digest",
        "record_digest",
        "result_digest",
        "predecessor_record_digest",
        "evidence_digest",
    ):
        _validate_digest(raw.get(field_name), field_name)
    for field_name in (
        "response_started_at",
        "last_approval_or_renewal",
        "review_after",
        "expires_at",
        "absolute_cap",
    ):
        _parse_datetime(raw.get(field_name), field_name)
    _validate_bounded_identifiers(raw, "compensating_control_ids")
    _validate_bounded_identifiers(raw, "aliases")
    references = _string_tuple(raw, "public_references")
    for reference in references:
        _validate_public_reference(contract, reference)
    if raw.get("subject_kind") == "dependency_advisory":
        package = _required_str(raw, "package")
        normalized = re.sub(r"[-_.]+", "-", package).lower()
        if package != normalized:
            raise SecurityExceptionValidationError("Dependency package must use normalized form.")
        locked_version = _required_str(raw, "locked_version")
        if len(locked_version) > 128 or any(character.isspace() for character in locked_version):
            raise SecurityExceptionValidationError("locked_version is not a bounded exact version.")
        scopes = _ordered_contract_subset(raw, "dependency_scopes", enums, allow_empty=False)
        python_versions = _ordered_contract_subset(raw, "python_versions", enums, allow_empty=False)
        platforms = _ordered_contract_subset(raw, "platforms", enums, allow_empty=False)
        if platforms != ("linux",):
            raise SecurityExceptionValidationError("Dependency platform must be exactly linux.")
        expected_key = (
            f"dependency:{lineage_id}:{package}@{locked_version}|scopes={','.join(scopes)}|"
            f"python={','.join(python_versions)}|platform=linux"
        )
        if raw.get("subject_key") != expected_key:
            raise SecurityExceptionValidationError(
                "Security Exception dependency subject_key is not the exact lineage-scoped key."
            )
    _validate_lifecycle_values(raw, evaluated_at=evaluated_at)


def _validate_lineages(
    contract: SecurityExceptionContract,
    records: list[object],
    raw_entries: list[object],
    *,
    evaluated_at: str,
) -> None:
    evaluated = _parse_datetime(evaluated_at, "evaluated_at")
    state_machine = contract.data.get("state_machine")
    if not isinstance(state_machine, Mapping):
        raise SecurityExceptionContractError("Security Exception state machine is missing.")
    terminal_values = state_machine.get("terminal_states")
    if not isinstance(terminal_values, list) or any(
        not isinstance(value, str) for value in terminal_values
    ):
        raise SecurityExceptionContractError(
            "Security Exception terminal states are malformed."
        )
    terminal_states = set(terminal_values)
    lineage_policy = contract.data.get("lineage")
    exception_id_policy = (
        lineage_policy.get("exception_id_policy")
        if isinstance(lineage_policy, Mapping)
        else None
    )
    if (
        not isinstance(lineage_policy, Mapping)
        or lineage_policy.get("initial_state") != "approved"
        or exception_id_policy
        != {
            "initial": "fresh_globally_history_unique",
            "renewal": "rotate_fresh_globally_history_unique",
            "other_transitions": "retain",
            "current_record": "equals_head",
        }
    ):
        raise SecurityExceptionContractError(
            "Security Exception lineage exception-ID policy is malformed."
        )
    record_state_values = state_machine.get("record_states")
    actions = state_machine.get("actions")
    if (
        not isinstance(record_state_values, list)
        or any(not isinstance(value, str) for value in record_state_values)
        or not isinstance(actions, Mapping)
    ):
        raise SecurityExceptionContractError(
            "Security Exception record states or actions are malformed."
        )
    record_states = set(record_state_values)
    allowed_transitions: set[tuple[str, str]] = set()
    for action in actions.values():
        if not isinstance(action, Mapping):
            raise SecurityExceptionContractError(
                "Security Exception state-machine action is malformed."
            )
        from_states = action.get("from")
        to_state = action.get("to")
        if (
            not isinstance(from_states, list)
            or not from_states
            or any(not isinstance(value, str) for value in from_states)
            or not isinstance(to_state, str)
            or to_state not in record_states
            or any(
                value != "proposal" and value not in record_states
                for value in from_states
            )
        ):
            raise SecurityExceptionContractError(
                "Security Exception state-machine action is malformed."
            )
        allowed_transitions.update(
            (from_state, to_state)
            for from_state in from_states
            if from_state != "proposal"
        )
    record_values: list[Mapping[str, object]] = []
    for value in records:
        if not isinstance(value, Mapping):
            raise SecurityExceptionValidationError(
                "Security Exception record must be an object."
            )
        record_values.append(value)
    exception_ids = [_required_str(record, "exception_id") for record in record_values]
    if len(exception_ids) != len(set(exception_ids)):
        raise SecurityExceptionValidationError(
            "Whole-ledger inventory contains exception identifier reuse."
        )
    subject_identities: dict[str, str] = {}
    dependency_records = [
        record
        for record in record_values
        if record.get("subject_kind") == "dependency_advisory"
    ]
    for record in record_values:
        lineage_id = _required_str(record, "lineage_id")
        subject_identities[lineage_id] = _canonical_subject_identity(contract, record)
    for index, first in enumerate(dependency_records):
        for second in dependency_records[index + 1 :]:
            if (
                first.get("package") == second.get("package")
                and first.get("locked_version") == second.get("locked_version")
                and set(_string_tuple(first, "dependency_scopes"))
                & set(_string_tuple(second, "dependency_scopes"))
                and set(_string_tuple(first, "python_versions"))
                & set(_string_tuple(second, "python_versions"))
                and set(_string_tuple(first, "platforms"))
                & set(_string_tuple(second, "platforms"))
            ):
                raise SecurityExceptionValidationError(
                    "Whole-ledger inventory contains dependency subject overlap."
                )
    entries: list[Mapping[str, object]] = []
    for value in raw_entries:
        if not isinstance(value, Mapping):
            raise SecurityExceptionValidationError("Lineage index entries must be objects.")
        entries.append(value)
    grouped: dict[str, list[Mapping[str, object]]] = {}
    identities: dict[str, str] = {}
    event_digests: set[str] = set()
    record_digests: set[str] = set()
    exception_id_lineages: dict[str, str] = {}
    for entry in entries:
        lineage_id = str(_uuid4(entry, "lineage_id"))
        exception_id = str(_uuid4(entry, "exception_id"))
        other_lineage = exception_id_lineages.get(exception_id)
        if other_lineage is not None and other_lineage != lineage_id:
            raise SecurityExceptionValidationError(
                "Lineage index contains a cross-lineage exception identifier collision."
            )
        exception_id_lineages[exception_id] = lineage_id
        _validate_digest(entry.get("event_digest"), "event_digest")
        _validate_digest(entry.get("result_digest"), "result_digest")
        _validate_digest(entry.get("record_digest"), "record_digest")
        _validate_digest(entry.get("predecessor_event_digest"), "predecessor_event_digest")
        event_digest = _required_str(entry, "event_digest")
        record_digest = _required_str(entry, "record_digest")
        if event_digest in event_digests or record_digest in record_digests:
            raise SecurityExceptionValidationError("Lineage index contains unlinked digest reuse.")
        event_digests.add(event_digest)
        record_digests.add(record_digest)
        grouped.setdefault(lineage_id, []).append(entry)
    for lineage_id, lineage in grouped.items():
        lineage.sort(key=_lineage_sequence)
        if [entry.get("sequence") for entry in lineage] != list(range(1, len(lineage) + 1)):
            raise SecurityExceptionValidationError(
                "Lineage index contains a branch or sequence gap."
            )
        first = lineage[0]
        if first.get("state") != "approved":
            raise SecurityExceptionValidationError(
                "Security Exception lineage must begin with approved."
            )
        identity = _required_str(first, "subject_identity")
        expected_identity = subject_identities.get(lineage_id)
        if identity != expected_identity:
            raise SecurityExceptionValidationError(
                "Lineage subject identity is not the exact canonical subject identity."
            )
        other_lineage = identities.get(identity)
        if other_lineage is not None and other_lineage != lineage_id:
            raise SecurityExceptionValidationError(
                "Lineage index contains subject identity reuse, split, merge, or overlap."
            )
        identities[identity] = lineage_id
        immutable = {
            field: first.get(field)
            for field in (
                "visibility",
                "subject_key",
                "subject_identity",
                "response_started_at",
                "absolute_cap",
            )
        }
        previous_event = "0" * 64
        previous_effective: datetime | None = None
        previous_state: str | None = None
        previous_alias_revision: int | None = None
        previous_evidence_revision: int | None = None
        last_approval_or_renewal: str | None = None
        previous_exception_id: str | None = None
        issued_exception_ids: set[str] = set()
        for entry in lineage:
            if previous_state in terminal_states:
                raise SecurityExceptionValidationError(
                    "Lineage index contains a successor after a terminal state."
                )
            current_state = _required_str(entry, "state")
            if (
                previous_state is not None
                and (previous_state, current_state) not in allowed_transitions
            ):
                raise SecurityExceptionValidationError(
                    "Lineage index contains a forbidden state transition."
                )
            current_exception_id = _required_str(entry, "exception_id")
            if previous_exception_id is None:
                issued_exception_ids.add(current_exception_id)
            elif current_state == "renewed":
                if current_exception_id == previous_exception_id:
                    raise SecurityExceptionValidationError(
                        "Lineage renewal must rotate to a fresh successor exception ID."
                    )
                if current_exception_id in issued_exception_ids:
                    raise SecurityExceptionValidationError(
                        "Lineage renewal exception ID must be globally history-unique."
                    )
                issued_exception_ids.add(current_exception_id)
            elif current_exception_id != previous_exception_id:
                raise SecurityExceptionValidationError(
                    "Lineage non-renewal transition must retain its current exception ID."
                )
            if any(entry.get(field) != expected for field, expected in immutable.items()):
                raise SecurityExceptionValidationError(
                    "Lineage index contains cross-visibility reuse or an anchor reset."
                )
            if entry.get("predecessor_event_digest") != previous_event:
                raise SecurityExceptionValidationError(
                    "Lineage index contains a branch or unlinked reuse."
                )
            current_effective = _parse_datetime(entry.get("effective_at"), "effective_at")
            if current_effective > evaluated:
                raise SecurityExceptionValidationError(
                    "Lineage effective_at is from the future."
                )
            if previous_effective is not None and current_effective <= previous_effective:
                raise SecurityExceptionValidationError(
                    "Lineage effective times must be strictly monotonic."
                )
            alias_revision = _required_int(entry, "alias_revision")
            evidence_revision = _required_int(entry, "evidence_revision")
            if (
                previous_alias_revision is not None
                and alias_revision
                not in {previous_alias_revision, previous_alias_revision + 1}
            ) or (
                previous_evidence_revision is not None
                and evidence_revision
                not in {previous_evidence_revision, previous_evidence_revision + 1}
            ):
                raise SecurityExceptionValidationError(
                    "Lineage index contains an alias or evidence revision reset or gap."
                )
            previous_effective = current_effective
            previous_event = _required_str(entry, "event_digest")
            previous_state = current_state
            previous_exception_id = current_exception_id
            if current_state in {"approved", "renewed"}:
                last_approval_or_renewal = _required_str(entry, "effective_at")
            previous_alias_revision = alias_revision
            previous_evidence_revision = evidence_revision
        matching = [
            record
            for record in records
            if isinstance(record, Mapping) and record.get("lineage_id") == lineage_id
        ]
        if len(matching) != 1:
            raise SecurityExceptionValidationError(
                "Every lineage must have exactly one current whole-ledger record."
            )
        record = matching[0]
        head = lineage[-1]
        comparisons = {
            "exception_id": "exception_id",
            "lineage_sequence": "sequence",
            "visibility": "visibility",
            "subject_key": "subject_key",
            "alias_revision": "alias_revision",
            "evidence_revision": "evidence_revision",
            "response_started_at": "response_started_at",
            "expires_at": "expires_at",
            "absolute_cap": "absolute_cap",
            "state": "state",
            "event_digest": "event_digest",
            "result_digest": "result_digest",
            "record_digest": "record_digest",
        }
        if any(
            record.get(record_field) != head.get(head_field)
            for record_field, head_field in comparisons.items()
        ):
            raise SecurityExceptionValidationError(
                "Current record does not exactly equal its lineage head and current revisions."
            )
        if record.get("last_approval_or_renewal") != last_approval_or_renewal:
            raise SecurityExceptionValidationError(
                "Current record last_approval_or_renewal does not equal the most recent "
                "approved or renewed lineage event."
            )
        expected_predecessor_record = (
            "0" * 64 if len(lineage) == 1 else lineage[-2]["record_digest"]
        )
        if record.get("predecessor_record_digest") != expected_predecessor_record:
            raise SecurityExceptionValidationError(
                "Current record predecessor does not link to the lineage head predecessor."
            )
    record_lineages = {
        record.get("lineage_id") for record in records if isinstance(record, Mapping)
    }
    if record_lineages != set(grouped):
        raise SecurityExceptionValidationError(
            "Whole-ledger records and lineage index are not linked."
        )
    _validate_canonical_digests(contract, record_values, entries)


def _validate_canonical_digests(
    contract: SecurityExceptionContract,
    records: list[Mapping[str, object]],
    entries: list[Mapping[str, object]],
) -> None:
    all_digest_fields = {
        "evidence_digest",
        "proposal_digest",
        "event_digest",
        "result_digest",
        "record_digest",
        "predecessor_record_digest",
    }
    for record in records:
        evidence_projection = {
            key: value for key, value in record.items() if key not in all_digest_fields
        }
        _require_canonical_digest(
            contract,
            "evidence",
            evidence_projection,
            record.get("evidence_digest"),
        )
        proposal_projection = {
            key: value
            for key, value in record.items()
            if key not in {"proposal_digest", "event_digest", "result_digest", "record_digest"}
        }
        _require_canonical_digest(
            contract,
            "proposal",
            proposal_projection,
            record.get("proposal_digest"),
        )
        result_projection = {
            key: value
            for key, value in record.items()
            if key not in {"result_digest", "record_digest"}
        }
        _require_canonical_digest(
            contract,
            "result",
            result_projection,
            record.get("result_digest"),
        )
    for entry in entries:
        event_projection = {
            key: value
            for key, value in entry.items()
            if key not in {"event_digest", "result_digest", "record_digest"}
        }
        _require_canonical_digest(
            contract,
            "event",
            event_projection,
            entry.get("event_digest"),
        )
    for entry in entries:
        record_projection = {
            key: value for key, value in entry.items() if key != "record_digest"
        }
        _require_canonical_digest(
            contract,
            "record",
            record_projection,
            entry.get("record_digest"),
        )


def _require_canonical_digest(
    contract: SecurityExceptionContract,
    domain: str,
    projection: Mapping[str, object],
    supplied: object,
) -> None:
    expected = _compute_contract_digest(contract, domain, projection)
    if supplied != expected:
        raise SecurityExceptionValidationError(
            f"{domain}_digest does not equal its canonical {domain} digest."
        )


def _lineage_sequence(entry: Mapping[str, object]) -> int:
    return _required_int(entry, "sequence")


def _uuid4(value: Mapping[str, object], field: str) -> uuid.UUID:
    raw = _required_str(value, field)
    try:
        parsed = uuid.UUID(raw)
    except ValueError as error:
        raise SecurityExceptionValidationError(f"{field} must be a canonical UUIDv4.") from error
    if parsed.version != 4 or str(parsed) != raw:
        raise SecurityExceptionValidationError(f"{field} must be a canonical UUIDv4.")
    return parsed


def _validate_digest(value: object, field: str) -> None:
    if not isinstance(value, str) or re.fullmatch(r"[0-9a-f]{64}", value) is None:
        raise SecurityExceptionValidationError(f"{field} must be a lowercase SHA-256 digest.")


def _validate_bounded_identifiers(value: Mapping[str, object], field: str) -> None:
    values = _string_tuple(value, field)
    if tuple(sorted(set(values))) != values:
        raise SecurityExceptionValidationError(f"{field} must be sorted and unique.")
    if any(
        len(identifier) > 160
        or re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:/@+-]*", identifier) is None
        for identifier in values
    ):
        raise SecurityExceptionValidationError(f"{field} contains an unbounded identifier.")


def _validate_public_reference(
    contract: SecurityExceptionContract,
    reference: str,
) -> None:
    policy = contract.data.get("public_reference_policy")
    approved_values = policy.get("approved_hosts") if isinstance(policy, Mapping) else None
    if not isinstance(approved_values, list) or any(
        not isinstance(value, str) for value in approved_values
    ):
        raise SecurityExceptionContractError(
            "Security Exception public reference policy is malformed."
        )
    approved_hosts = set(approved_values)
    path_patterns = policy.get("path_patterns") if isinstance(policy, Mapping) else None
    if not isinstance(path_patterns, Mapping) or set(path_patterns) != approved_hosts:
        raise SecurityExceptionContractError(
            "Security Exception public reference path policy is malformed."
        )
    forbidden_credential_patterns = (
        policy.get("forbidden_credential_patterns") if isinstance(policy, Mapping) else None
    )
    if not isinstance(forbidden_credential_patterns, list) or any(
        not isinstance(pattern, str) for pattern in forbidden_credential_patterns
    ):
        raise SecurityExceptionContractError(
            "Security Exception public reference credential policy is malformed."
        )
    try:
        parsed = urlsplit(reference)
        port = parsed.port
    except ValueError as error:
        raise SecurityExceptionValidationError(
            "public_references must contain bounded credential-free HTTPS URLs "
            "on approved hosts."
        ) from error
    if (
        len(reference) > 2048
        or parsed.scheme != "https"
        or parsed.hostname not in approved_hosts
        or parsed.username is not None
        or parsed.password is not None
        or port not in {None, 443}
        or not parsed.path.startswith("/")
        or parsed.query
        or parsed.fragment
        or any(ord(character) < 0x20 for character in reference)
        or any(
            re.search(pattern, parsed.path, flags=re.IGNORECASE) is not None
            for pattern in forbidden_credential_patterns
        )
    ):
        raise SecurityExceptionValidationError(
            "public_references must contain bounded credential-free HTTPS URLs "
            "on approved hosts."
        )
    hostname = parsed.hostname
    approved_patterns = path_patterns.get(hostname) if hostname is not None else None
    if not isinstance(approved_patterns, list) or any(
        not isinstance(pattern, str) for pattern in approved_patterns
    ):
        raise SecurityExceptionContractError(
            "Security Exception public reference path policy is malformed."
        )
    if not any(re.fullmatch(pattern, parsed.path) is not None for pattern in approved_patterns):
        raise SecurityExceptionValidationError(
            "public_references must contain bounded credential-free HTTPS URLs "
            "for approved public resource paths."
        )


def _dependency_subject_identity(record: Mapping[str, object]) -> str:
    package = _required_str(record, "package")
    locked_version = _required_str(record, "locked_version")
    scopes = _string_tuple(record, "dependency_scopes")
    python_versions = _string_tuple(record, "python_versions")
    platforms = _string_tuple(record, "platforms")
    return (
        f"dependency:{package}@{locked_version}|scopes={','.join(scopes)}|"
        f"python={','.join(python_versions)}|platform={','.join(platforms)}"
    )


def _canonical_subject_identity(
    contract: SecurityExceptionContract,
    record: Mapping[str, object],
) -> str:
    prefixes = _subject_identity_prefixes(contract)
    subject_kind = _required_str(record, "subject_kind")
    if subject_kind == "dependency_advisory":
        if prefixes.get(subject_kind) != "dependency":
            raise SecurityExceptionContractError(
                "Security Exception dependency subject-identity prefix is malformed."
            )
        return _dependency_subject_identity(record)
    subject_key = _required_str(record, "subject_key")
    if not subject_key.isascii():
        raise SecurityExceptionValidationError(
            "Security Exception subject_key must be exact ASCII."
        )
    prefix = prefixes.get(subject_kind)
    if not isinstance(prefix, str):
        raise SecurityExceptionValidationError(
            "Security Exception subject kind has no canonical identity."
        )
    return f"{prefix}:{subject_key}"


def _subject_identity_prefixes(
    contract: SecurityExceptionContract,
) -> Mapping[str, object]:
    policy = contract.data.get("subject_identity")
    prefixes = policy.get("prefixes") if isinstance(policy, Mapping) else None
    enums = contract.data.get("enums")
    subject_kinds = enums.get("subject_kinds") if isinstance(enums, Mapping) else None
    if (
        not isinstance(policy, Mapping)
        or policy.get("subject_key_normalization") != "ascii-exact"
        or policy.get("aliases_participate") is not False
        or policy.get("cross_lineage_uniqueness") is not True
        or not isinstance(prefixes, Mapping)
        or not isinstance(subject_kinds, list)
        or any(not isinstance(subject_kind, str) for subject_kind in subject_kinds)
        or set(prefixes) != set(subject_kinds)
        or any(not isinstance(prefix, str) or not prefix for prefix in prefixes.values())
        or len(set(prefixes.values())) != len(prefixes)
    ):
        raise SecurityExceptionContractError(
            "Security Exception subject-identity policy is malformed."
        )
    return prefixes


def _validate_issuance_subject_identity(
    contract: SecurityExceptionContract,
    subject_identity: str,
) -> str:
    prefixes = _subject_identity_prefixes(contract)
    matches = [
        (subject_kind, prefix)
        for subject_kind, prefix in prefixes.items()
        if isinstance(subject_kind, str)
        and isinstance(prefix, str)
        and subject_identity.startswith(f"{prefix}:")
    ]
    if len(matches) != 1 or not subject_identity.isascii():
        raise SecurityExceptionValidationError(
            "Lineage issuance requires an exact canonical subject identity."
        )
    subject_kind, prefix = matches[0]
    if subject_kind != "dependency_advisory":
        subject_key = subject_identity[len(prefix) + 1 :]
        if not subject_key or len(subject_key) > 512:
            raise SecurityExceptionValidationError(
                "Lineage issuance requires an exact canonical subject identity."
            )
        return subject_identity
    before_platform, platform_separator, platform = subject_identity.rpartition(
        "|platform="
    )
    before_python, python_separator, python_value = before_platform.rpartition(
        "|python="
    )
    before_scopes, scope_separator, scope_value = before_python.rpartition("|scopes=")
    package_and_version = before_scopes.removeprefix(f"{prefix}:")
    package, version_separator, locked_version = package_and_version.partition("@")
    scopes = scope_value.split(",")
    python_versions = python_value.split(",")
    enums = contract.data.get("enums")
    if (
        not all(
            (
                platform_separator,
                python_separator,
                scope_separator,
                version_separator,
            )
        )
        or platform != "linux"
        or re.fullmatch(r"[a-z0-9]+(?:-[a-z0-9]+)*", package) is None
        or not locked_version
        or len(locked_version) > 128
        or any(character.isspace() for character in locked_version)
        or not isinstance(enums, Mapping)
    ):
        raise SecurityExceptionValidationError(
            "Lineage issuance requires an exact canonical subject identity."
        )
    descriptor: dict[str, object] = {
        "dependency_scopes": scopes,
        "python_versions": python_versions,
    }
    try:
        _ordered_contract_subset(descriptor, "dependency_scopes", enums, allow_empty=False)
        _ordered_contract_subset(descriptor, "python_versions", enums, allow_empty=False)
    except SecurityExceptionValidationError as error:
        raise SecurityExceptionValidationError(
            "Lineage issuance requires an exact canonical subject identity."
        ) from error
    return subject_identity


def _ordered_contract_subset(
    value: Mapping[str, object],
    field: str,
    enums: Mapping[str, object],
    *,
    allow_empty: bool,
) -> tuple[str, ...]:
    selected = _string_tuple(value, field)
    allowed = enums.get(field)
    if not isinstance(allowed, list) or any(not isinstance(item, str) for item in allowed):
        raise SecurityExceptionContractError(f"Security Exception enum {field} is malformed.")
    canonical = tuple(item for item in allowed if item in selected)
    if selected != canonical or (not allow_empty and not selected):
        raise SecurityExceptionValidationError(
            f"{field} must be a nonempty exact subset in contract order."
        )
    return selected


def _project_record(
    contract: SecurityExceptionContract,
    raw: object,
) -> SecurityExceptionRecord:
    if not isinstance(raw, Mapping):
        raise SecurityExceptionValidationError("Security Exception record must be an object.")
    expected_effects = contract.data.get("v1_total_effects")
    raw_effects_value = raw.get("effects")
    if (
        not isinstance(expected_effects, Mapping)
        or not isinstance(raw_effects_value, Mapping)
        or raw_effects_value != expected_effects
    ):
        raise SecurityExceptionValidationError(
            "Security Exception record effects must equal the contract 1.0 total effects."
        )
    raw_effects: Mapping[str, object] = raw_effects_value
    effects = SecurityExceptionEffects(
        inventory_recorded=_required_bool(raw_effects, "inventory_recorded"),
        decision_recorded=_required_bool(raw_effects, "decision_recorded"),
        lifecycle_recorded=_required_bool(raw_effects, "lifecycle_recorded"),
        security_posture_green=_required_bool(raw_effects, "security_posture_green"),
        admission_or_merge_authorized=_required_bool(
            raw_effects, "admission_or_merge_authorized"
        ),
        repository_control_relaxed_disabled_or_mutated=_required_bool(
            raw_effects, "repository_control_relaxed_disabled_or_mutated"
        ),
        assurance_validated=_required_bool(raw_effects, "assurance_validated"),
        baseline_or_release_eligible=_required_bool(
            raw_effects, "baseline_or_release_eligible"
        ),
        product_or_dogfood_authorized=_required_bool(
            raw_effects, "product_or_dogfood_authorized"
        ),
        underlying_failure_cleared=_required_bool(raw_effects, "underlying_failure_cleared"),
        underlying_failure_remains_blocking=_required_bool(
            raw_effects, "underlying_failure_remains_blocking"
        ),
    )
    return SecurityExceptionRecord(
        exception_id=_required_str(raw, "exception_id"),
        lineage_id=_required_str(raw, "lineage_id"),
        lineage_sequence=_required_int(raw, "lineage_sequence"),
        visibility=_required_str(raw, "visibility"),
        kind=_required_str(raw, "kind"),
        subject_kind=_required_str(raw, "subject_kind"),
        subject_key=_required_str(raw, "subject_key"),
        severity=_required_str(raw, "severity"),
        state=_required_str(raw, "state"),
        package=_optional_str(raw, "package"),
        locked_version=_optional_str(raw, "locked_version"),
        dependency_scopes=_string_tuple(raw, "dependency_scopes"),
        python_versions=_string_tuple(raw, "python_versions"),
        platforms=_string_tuple(raw, "platforms"),
        aliases=_string_tuple(raw, "aliases"),
        alias_revision=_required_int(raw, "alias_revision"),
        evidence_revision=_required_int(raw, "evidence_revision"),
        evidence_digest=_required_str(raw, "evidence_digest"),
        response_started_at=_required_str(raw, "response_started_at"),
        source_time_status=_required_str(raw, "source_time_status"),
        last_approval_or_renewal=_required_str(raw, "last_approval_or_renewal"),
        review_after=_required_str(raw, "review_after"),
        expires_at=_required_str(raw, "expires_at"),
        absolute_cap=_required_str(raw, "absolute_cap"),
        event_digest=_required_str(raw, "event_digest"),
        record_digest=_required_str(raw, "record_digest"),
        predecessor_record_digest=_required_str(raw, "predecessor_record_digest"),
        effects=effects,
    )


def _required_str(value: Mapping[str, object], field: str) -> str:
    selected = value.get(field)
    if not isinstance(selected, str) or not selected:
        raise SecurityExceptionValidationError(f"{field} must be a nonempty string.")
    return selected


def _freeze_projection_mapping(value: Mapping[str, object]) -> Mapping[str, object]:
    return MappingProxyType(
        {key: _freeze_projection_value(item) for key, item in value.items()}
    )


def _freeze_projection_value(value: object) -> object:
    if isinstance(value, Mapping):
        frozen: dict[str, object] = {}
        for key, item in value.items():
            if not isinstance(key, str):
                raise SecurityExceptionValidationError(
                    "Validated projection mappings require string keys."
                )
            frozen[key] = _freeze_projection_value(item)
        return MappingProxyType(frozen)
    if isinstance(value, (list, tuple)):
        return tuple(_freeze_projection_value(item) for item in value)
    return value


def _optional_str(value: Mapping[str, object], field: str) -> str | None:
    selected = value.get(field)
    if selected is None:
        return None
    if not isinstance(selected, str) or not selected:
        raise SecurityExceptionValidationError(f"{field} must be a nonempty string when present.")
    return selected


def _required_int(value: Mapping[str, object], field: str) -> int:
    selected = value.get(field)
    if not isinstance(selected, int) or isinstance(selected, bool):
        raise SecurityExceptionValidationError(f"{field} must be an integer.")
    return selected


def _required_bool(value: Mapping[str, object], field: str) -> bool:
    selected = value.get(field)
    if not isinstance(selected, bool):
        raise SecurityExceptionValidationError(f"{field} must be a boolean.")
    return selected


def _string_tuple(value: Mapping[str, object], field: str) -> tuple[str, ...]:
    selected = value.get(field, [])
    if not isinstance(selected, list) or any(not isinstance(item, str) for item in selected):
        raise SecurityExceptionValidationError(f"{field} must be an array of strings.")
    return tuple(selected)


def _validate_projection_confidentiality(
    public_records: list[object],
    private_records: list[object],
) -> None:
    for visibility, records in (
        ("public", public_records),
        ("private", private_records),
    ):
        for index, record in enumerate(records):
            if not isinstance(record, Mapping):
                raise SecurityExceptionValidationError(
                    f"{visibility} Security Exception record {index} must be an object."
                )
            if record.get("visibility") != visibility:
                raise SecurityExceptionValidationError(
                    f"{visibility} Security Exception record {index} has crossed visibility."
                )


def _validate_kind_subject_pairs(
    contract: SecurityExceptionContract,
    records: list[object],
) -> None:
    matrix = contract.data.get("kind_subject_matrix")
    if not isinstance(matrix, Mapping):
        raise SecurityExceptionContractError("Security Exception kind/subject matrix is missing.")
    for index, record in enumerate(records):
        if not isinstance(record, Mapping):
            raise SecurityExceptionValidationError(
                f"Security Exception record {index} must be an object."
            )
        kind = record.get("kind")
        subject_kind = record.get("subject_kind")
        permitted = matrix.get(kind) if isinstance(kind, str) else None
        if not isinstance(permitted, list) or subject_kind not in permitted:
            raise SecurityExceptionValidationError(
                f"Security Exception record {index} has a forbidden kind/subject pair."
            )


def _validate_artifact(
    contract: SecurityExceptionContract,
    schema_name: str,
    artifact: Mapping[str, object],
) -> None:
    schemas = contract.data.get("artifact_schemas")
    definitions = contract.data.get("$defs")
    if not isinstance(schemas, dict) or not isinstance(definitions, dict):
        raise SecurityExceptionContractError("Security Exception artifact schemas are missing.")
    selected = schemas.get(schema_name)
    if not isinstance(selected, dict):
        raise SecurityExceptionContractError(
            f"Security Exception artifact schema {schema_name!r} is missing."
        )
    schema: dict[str, Any] = {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$defs": definitions,
        **selected,
    }
    errors = sorted(
        Draft202012Validator(schema, format_checker=FormatChecker()).iter_errors(artifact),
        key=_validation_error_path,
    )
    if errors:
        location = ".".join(str(part) for part in errors[0].absolute_path) or "<root>"
        raise SecurityExceptionValidationError(
            f"{schema_name} is invalid at {location}: {errors[0].message}"
        )


def _validation_error_path(error: ValidationError) -> tuple[str, ...]:
    return tuple(str(part) for part in error.absolute_path)


def _validate_authority(
    contract: SecurityExceptionContract,
    observation: Mapping[str, object],
    *,
    evaluated_at: str,
) -> None:
    authority_container = contract.data["authority"]
    if not isinstance(authority_container, Mapping):
        raise SecurityExceptionContractError("Security Exception authority contract is malformed.")
    repository = authority_container["repository"]
    if not isinstance(repository, Mapping):
        raise SecurityExceptionContractError("Security Exception repository identity is malformed.")
    expected = {
        "repository_full_name": repository["full_name"],
        "repository_database_id": repository["database_id"],
        "repository_node_id": repository["node_id"],
        "login": contract.authority.login,
        "account_database_id": contract.authority.database_id,
        "account_node_id": contract.authority.node_id,
    }
    mismatched = [name for name, value in expected.items() if observation.get(name) != value]
    if mismatched:
        raise SecurityExceptionValidationError(
            "Risk-authority observation mismatch: " + ", ".join(sorted(mismatched)) + "."
        )
    observed = _parse_datetime(observation["observed_at"], "observed_at")
    evaluated = _parse_datetime(evaluated_at, "evaluated_at")
    if observed > evaluated:
        raise SecurityExceptionValidationError("Risk-authority observation is from the future.")
    observation_contract = contract.data.get("authority_observation")
    maximum_age = (
        observation_contract.get("maximum_age_seconds")
        if isinstance(observation_contract, Mapping)
        else None
    )
    if not isinstance(maximum_age, int) or isinstance(maximum_age, bool):
        raise SecurityExceptionContractError(
            "Security Exception authority-observation freshness policy is malformed."
        )
    if evaluated - observed > timedelta(seconds=maximum_age):
        raise SecurityExceptionValidationError("Risk-authority observation is stale.")


def _parse_datetime(value: object, field: str) -> datetime:
    if not isinstance(value, str) or not value.endswith("Z"):
        raise SecurityExceptionValidationError(f"{field} must be an RFC 3339 UTC timestamp.")
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as error:
        raise SecurityExceptionValidationError(
            f"{field} must be an RFC 3339 UTC timestamp."
        ) from error
    return parsed
