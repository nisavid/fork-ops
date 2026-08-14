from __future__ import annotations

import re
from pathlib import Path

import pytest

REPOSITORY_ROOT = Path(__file__).resolve().parents[3]
DOCUMENT_PATH = REPOSITORY_ROOT / "docs" / "agents" / "merge-admission.md"
DOMAIN_DOCUMENT_PATH = REPOSITORY_ROOT / "docs" / "agents" / "domain.md"


def _document() -> str:
    return DOCUMENT_PATH.read_text(encoding="utf-8")


def _domain_document() -> str:
    return DOMAIN_DOCUMENT_PATH.read_text(encoding="utf-8")


def _contract_section() -> str:
    document = _document()
    match = re.search(
        r"^## Required admission contract\n(?P<body>.*?)(?=^## |\Z)",
        document,
        flags=re.MULTILINE | re.DOTALL,
    )
    assert match is not None, "missing Required admission contract section"
    return match.group("body")


def _normalized(value: str) -> str:
    return re.sub(r"\s+", " ", value)


def _canonical_block(name: str) -> str:
    blocks = re.findall(
        r"^```text\n(?P<body>.*?)^```$",
        _contract_section(),
        flags=re.MULTILINE | re.DOTALL,
    )
    marker = f"[{name}]"
    matches = [block for block in blocks if block.splitlines()[0] == marker]
    assert len(matches) == 1, f"expected one canonical block named {marker}"
    return matches[0].strip()


def _canonical_text(name: str) -> str:
    return _normalized("\n".join((f"[{name}]", *_canonical_lines(name))))


def _validated_block_lines(block: str) -> tuple[str, ...]:
    lines = tuple(line.strip() for line in block.splitlines()[1:] if line.strip())
    seen_lines: dict[str, None] = {}
    assignments: dict[str, str] = {}

    for line in lines:
        assert line not in seen_lines, f"duplicate canonical line: {line}"
        seen_lines[line] = None

        match = re.match(r"^(?P<key>[A-Za-z][A-Za-z0-9_.]*)\s*=\s*(?!=)", line)
        if match is None:
            continue

        key = match.group("key")
        assert key not in assignments, (
            f"conflicting canonical definitions for {key}: {assignments.get(key)!r} and {line!r}"
        )
        assignments[key] = line

    return lines


def _canonical_lines(name: str) -> tuple[str, ...]:
    return _validated_block_lines(_canonical_block(name))


def test_canonical_block_parser_preserves_order_and_rejects_duplicates() -> None:
    assert _validated_block_lines("[sample]\nfirst\nmode = one\nlast") == (
        "first",
        "mode = one",
        "last",
    )

    with pytest.raises(AssertionError, match="duplicate canonical line"):
        _validated_block_lines("[sample]\nfirst\nfirst")

    with pytest.raises(AssertionError, match="conflicting canonical definitions"):
        _validated_block_lines("[sample]\nmode = one\nmode = two")


def test_future_control_schema_and_pending_envelope_must_bind_topology() -> None:
    control_state = _canonical_lines("control_state_schema_requirements")
    pending_fields = _canonical_lines("pending_fields")

    for binding in (
        "repository_id",
        "repository_node_id",
        "default_branch_name",
        "default_branch_ref",
        "repository_full_name",
        "repository_owner_login",
        "repository_owner_type",
        "repository_owner_database_id",
        "repository_owner_node_id",
        "repository_visibility",
        "ruleset_id",
        "ruleset_node_id",
        "ruleset_source",
        "ruleset_source_type",
        "ruleset_target_type",
        "ruleset_target_include",
        "ruleset_target_exclude",
    ):
        assert binding in control_state
        assert binding in pending_fields

    assert "all_control_state_fields" in pending_fields


def test_control_schema_is_an_issue_71_handoff_without_present_authority() -> None:
    control_state = _canonical_text("control_state_schema_requirements")
    pending_fields = _canonical_lines("pending_fields")
    contract = _normalized(_contract_section())

    for rule in (
        "schema_authority = Issue #71",
        "current_schema_status = requirements only",
        "required_schema = closed and versioned",
        "required_encoding = canonical UTF-8 JSON",
        "required_object_key_order = lexicographic",
        "required_array_order = schema-defined, significant, and preserved",
        "required_absent_null_semantics = absent != null",
        "required_number_domain = base-10 integers only; floats forbidden",
        "required_digest = lowercase SHA-256",
        "ruleset_response_snapshot_digest != C",
        "canonical_C_bytes = unavailable from this record",
        "C_digest = unavailable from this record",
        "eligibility = blocked until Issue #71 implements, versions, and proves the schema",
    ):
        assert rule in control_state

    assert 'schema_version = "fork-ops.merge-admission-control/v1"' not in control_state
    assert "C = digest(canonical_control_state)" not in control_state
    for binding in (
        "C",
        "control_state_schema_identity",
        "control_state_schema_version",
        "control_state_digest_algorithm",
    ):
        assert binding in pending_fields

    assert "Issue #70 binds the future opaque `C`" in contract
    assert "Issue #70 does not define its mechanism-specific schema or canonicalization" in contract
    assert "No canonical `C` bytes or digest are producible from this record alone" in contract


def test_control_history_binding_rejects_digest_aba() -> None:
    pending_fields = _canonical_lines("pending_fields")
    predicates = _canonical_lines("admission_predicates")

    assert "control_state_generation = G_control" in pending_fields
    assert "control_state_event_high_water = E_control" in pending_fields
    assert "admission_control_state_digest == pending.C" in predicates
    assert "control_state.generation == pending.control_state_generation" in predicates
    assert "control_state.event_high_water == pending.control_state_event_high_water" in predicates
    assert "generation change => reject even if current digest == C" in predicates


def test_pull_request_context_is_bound_through_final_reread() -> None:
    control_state = _canonical_lines("control_state_schema_requirements")
    pending_fields = _canonical_lines("pending_fields")
    predicates = _canonical_lines("admission_predicates")

    assert "default_branch_ref_format = refs/heads/{default_branch_name}" in control_state
    assert "pull_request_base_ref_format = refs/heads/{base.ref}" in control_state
    assert "pull_request_head_ref_format = refs/heads/{head.ref}" in control_state

    for control_field, pending_field in (
        ("pull_request_id", "pull_request_id"),
        ("pull_request_node_id", "pull_request_node_id"),
        ("pull_request_number", "pull_request_number"),
        ("pull_request_state", "pull_request_state"),
        ("pull_request_base_repository_id", "pull_request_base_repository_id"),
        (
            "pull_request_base_repository_node_id",
            "pull_request_base_repository_node_id",
        ),
        ("pull_request_base_ref", "pull_request_base_ref"),
        ("pull_request_base_sha = B", "pull_request_base_sha"),
        ("pull_request_head_repository_id", "pull_request_head_repository_id"),
        (
            "pull_request_head_repository_node_id",
            "pull_request_head_repository_node_id",
        ),
        ("pull_request_head_ref", "pull_request_head_ref"),
        ("pull_request_head_sha = H", "pull_request_head_sha"),
    ):
        assert control_field in control_state
        assert pending_field in pending_fields

    for predicate in (
        "pull_request.id == pending.pull_request_id",
        "pull_request.node_id == pending.pull_request_node_id",
        "pull_request.number == pending.pull_request_number",
        "pull_request.state == open",
        "pull_request.state == pending.pull_request_state",
        "pull_request.base.repository_id == pending.pull_request_base_repository_id",
        "pull_request.base.repository_node_id == pending.pull_request_base_repository_node_id",
        "pull_request.base.ref == pending.pull_request_base_ref",
        "pull_request.base.ref == pending.default_branch_ref",
        "pull_request.base.sha == pending.B",
        "pull_request.head.repository_id == pending.pull_request_head_repository_id",
        "pull_request.head.repository_node_id == pending.pull_request_head_repository_node_id",
        "pull_request.head.ref == pending.pull_request_head_ref",
        "pull_request.head.sha == pending.H",
    ):
        assert predicate in predicates


def test_freshness_uses_bounded_independent_witness_time() -> None:
    predicates = _canonical_lines("time_predicates")

    for requirement in (
        "time_authority = independently administered witness clock",
        "timestamp_format = whole-second UTC RFC 3339",
        "U_max = 120 seconds",
        "O_upper <= D_lower",
        "D_upper <= A_lower",
        "A_upper - O_lower < 900 seconds",
        "O_lower <= security_posture.completed_at",
        "security_posture.completed_at <= O_upper",
        "T_valid_until == O_lower + 900 seconds",
        "A_upper < T_valid_until",
        "time_quality = Unknown, missing, or out-of-bound time quality fails closed",
    ):
        assert requirement in predicates


def test_final_result_reread_matches_pending_result_identity() -> None:
    pending_fields = _canonical_lines("pending_fields")
    predicates = _canonical_lines("admission_predicates")

    for field in (
        "result_type",
        "result_id",
        "check_run_id",
        "attempt",
        "result_event_generation = G_result",
        "result_event_high_water = E_result",
        "app_id",
        "installation_id",
        "completed_at",
        "T_observed",
        "result_digest",
    ):
        assert field in pending_fields

    for predicate in (
        "security_posture.head_sha == H",
        "security_posture.producer == pinned producer App",
        "security_posture.conclusion == success",
        "security_posture.result_type == pending.result_type",
        "security_posture.result_id == pending.result_id",
        "security_posture.check_run_id == pending.check_run_id",
        "security_posture.attempt == pending.attempt",
        "security_posture.app_id == pending.app_id",
        "security_posture.installation_id == pending.installation_id",
        "security_posture.completed_at == pending.completed_at",
        "security_posture.observed_at == pending.T_observed",
        "security_posture.result_digest == pending.result_digest",
    ):
        assert predicate in predicates


def test_result_event_state_is_bound_and_frozen_outside_control_state() -> None:
    pending_fields = _canonical_lines("pending_fields")
    result_identity = _canonical_lines("result_identity")
    predicates = _canonical_lines("admission_predicates")
    ref_constraints = _canonical_text("ref_update_constraints")
    contract = _normalized(_contract_section())

    for binding in (
        "result_event_generation = G_result",
        "result_event_high_water = E_result",
    ):
        assert binding in pending_fields
        assert binding in result_identity

    for predicate in (
        "result_witness.generation == pending.result_event_generation",
        "result_witness.event_high_water == pending.result_event_high_water",
        "result event change => reject even if pending result identity still matches",
    ):
        assert predicate in predicates

    assert "Security Posture result event generation and event high-water" in ref_constraints
    assert "#71 must reject the candidate if result mutation cannot be excluded" in ref_constraints
    assert "`G_result` and `E_result` are outside `C`" in contract
    assert (
        "active receipt must bind the pending digest, the final matched `G_result` and `E_result`"
        in contract
    )
    assert "high-water recovery resolves the exact ref and result-event state" in contract


def test_result_identity_defines_nullable_and_witnessed_fields() -> None:
    result_identity = _canonical_text("result_identity")

    for rule in (
        "result_type = check_run | commit_status",
        "check_run_id = result_id for check_run; null for commit_status",
        "attempt = signed nonnegative integer or null",
        "installation_id = authenticated witnessed installation ID",
        "missing installation_id => reject result type",
        "endpoint absence != inferred value",
        "canonical values are signed and included in result_digest",
    ):
        assert rule in result_identity


def test_ref_update_does_not_claim_unsupported_compare_and_swap() -> None:
    constraints = _canonical_text("ref_update_constraints")

    for limitation in (
        "no documented atomic compare-and-swap precondition",
        "`force=false` is not compare-and-swap",
        "broker-local serialization alone is insufficient",
        "equivalent exclusion, lease, or freeze",
        "spans `H`, `B`, and `C`",
        "control-state generation and event high-water",
        "#71 must reject the candidate",
    ):
        assert limitation in constraints


def test_candidate_broker_must_enforce_the_closed_token_protocol() -> None:
    constraints = _canonical_text("broker_token_constraints")

    for rule in (
        "scope_enforcement = broker, not GitHub installation token",
        "repository_ids = [repository_id]",
        "permissions = exact least-permission subset",
        "token_isolation = broker-only memory; never caller-visible",
        "revocation = after each attempt and on ambiguity",
        "negative_tests = other refs and all other permitted Contents endpoints",
        "github_token_capability != closed protocol",
    ):
        assert rule in constraints


def test_issue_references_do_not_parse_as_markdown_headings() -> None:
    document = _document()
    ambiguous_issue_heading = re.compile(
        r"^#{1,6}[ \t]*#?[ \t]*(?:70|71)\b",
        flags=re.MULTILINE,
    )

    for depth in range(1, 7):
        heading_marks = "#" * depth
        for example in (
            f"{heading_marks}70",
            f"{heading_marks} 70",
            f"{heading_marks} #71",
            f"{heading_marks} # 71",
        ):
            assert ambiguous_issue_heading.search(example) is not None

    assert ambiguous_issue_heading.search(document) is None
    assert ambiguous_issue_heading.search("### Issue #70") is None
    assert ambiguous_issue_heading.search("### Issue #71") is None
    assert "### Issue #70:" in document
    assert "### Issue #71:" in document


def test_domain_route_labels_use_ordinary_lowercase_prose() -> None:
    document = _domain_document()

    assert "- security exception governance:" in document
    assert "- fresh exact-candidate merge admission decision:" in document
    assert "- Security exception governance:" not in document
    assert "- Fresh exact-candidate merge admission decision:" not in document
