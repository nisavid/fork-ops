from __future__ import annotations

import json
from copy import deepcopy
from pathlib import Path
from typing import Any

import pytest

from fork_ops import core as core_module
from fork_ops import mcp_server
from fork_ops.cli import main as cli_main
from fork_ops.core import (
    CONFIG_RELATIVE_PATH,
    ForkOpsError,
    assess_migration,
    build_equipment_migration_preflight,
    build_plugin_health_report,
    build_status_report,
    build_workflow_migration_inventory,
    capability_report,
    create_initial_config_text,
    dry_run_migration_plan,
    execute_migration_plan,
    explain_migration_blocker,
    generate_migration_plan,
    initialize_config,
    load_config,
    parse_config_text,
    render_migration_narrative,
    schema_artifact_report,
    schema_json,
)
from fork_ops.workflow_catalog import workflow_catalog, workflow_contracts

_STATE_FIELDS = {
    "activation_readiness",
    "replacement_coverage",
    "operational_continuity",
}
_STATE_CONTAINERS = {
    "accounting",
    "capability",
    "equipment_migration_preflight",
    "equipment_review",
    "equipment_review_record",
    "migration_plan",
    "preview",
}


def _state_value_evidence_ids(value: object) -> set[str]:
    if isinstance(value, dict):
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
    if isinstance(value, list):
        return {
            evidence_id
            for nested in value
            for evidence_id in _state_value_evidence_ids(nested)
        }
    return set()


def _state_evidence_ids(value: object, *, state_container: bool = True) -> set[str]:
    if not isinstance(value, dict):
        return set()
    references: set[str] = set()
    for key, nested in value.items():
        if state_container and key in _STATE_FIELDS:
            references.update(_state_value_evidence_ids(nested))
        elif key in _STATE_CONTAINERS or (
            isinstance(nested, dict) and isinstance(nested.get("artifact_kind"), str)
        ):
            references.update(_state_evidence_ids(nested))
    return references


def _root_evidence_ids(payload: dict[str, Any]) -> set[str]:
    return {
        item["id"]
        for item in payload["evidence"]
        if isinstance(item, dict) and isinstance(item.get("id"), str)
    }


def test_workflow_catalog_uses_the_canonical_versioned_contract() -> None:
    catalog = workflow_catalog()

    assert catalog["artifact_kind"] == "workflow_catalog"
    assert catalog["schema_version"] == "1.0"
    assert catalog["outcome"] == "completed"
    assert catalog["plan_executability"] == "not_applicable"
    assert catalog["mutation_state"] == "not_requested"
    assert catalog["implementation_extent_values"] == [
        "implemented",
        "partial",
        "planned",
    ]
    assert catalog["operation_mode_values"] == [
        "diagnostic",
        "read_only",
        "guarded_mutation",
    ]
    assert "status_values" not in catalog

    workflows = {workflow["id"]: workflow for workflow in catalog["workflows"]}
    assert "blocker-resolution" not in workflows
    assert workflows["migration-blocker-explanation"]["implementation_extent"] == (
        "implemented"
    )
    assert workflows["migration-blocker-explanation"]["title"] == (
        "Migration blocker explanation"
    )
    assert workflows["fork-authority-migration"]["implementation_extent"] == "partial"
    assert workflows["upstream-sync-planning"]["implementation_extent"] == "planned"

    for workflow in workflows.values():
        assert "implementation_status" not in workflow
        assert "available" not in workflow
        assert workflow["operations"]
        assert all(
            operation["operation_mode"]
            in {"diagnostic", "read_only", "guarded_mutation"}
            for operation in workflow["operations"]
        )

    migration_operations = {
        operation["id"]: operation
        for operation in workflows["fork-authority-migration"]["operations"]
    }
    assert migration_operations["migration-assessment"] == {
        "id": "migration-assessment",
        "operation_mode": "read_only",
        "available": True,
    }
    assert migration_operations["initial-config-creation"] == {
        "id": "initial-config-creation",
        "operation_mode": "guarded_mutation",
        "available": True,
    }
    assert migration_operations["source-material-removal"] == {
        "id": "source-material-removal",
        "operation_mode": "guarded_mutation",
        "available": False,
    }


def test_capability_report_separates_authority_from_product_state() -> None:
    config = parse_config_text(
        create_initial_config_text(
            ".",
            repository_owner="OWNER",
            repository_name="REPO",
            upstream_owner="UPSTREAM",
            upstream_name="PROJECT",
            default_branch="main",
        )
    )

    report = capability_report(config)

    assert report["artifact_kind"] == "capability_report"
    assert report["schema_version"] == "1.0"
    assert report["outcome"] == "completed"
    assert report["plan_executability"] == "not_applicable"
    assert report["mutation_state"] == "not_requested"
    assert report["repository_identity"] == {"slug": "OWNER/REPO"}
    assert report["config_identity"] == {"schema_version": "0.1"}
    assert report["baseline_assurance"] == "unvalidated"
    assert "highest_available" not in report

    authority = report["authority_readiness"]
    assert authority["highest_authority_ready"] == "track-aware"
    assert authority["derivation_rule"] == (
        "authority.required_fields_and_blocking_diagnostics"
    )
    assert authority["evidence_ids"] == ["config.authority"]
    assert authority["levels"]["track-aware"]["ready"] is True
    assert "available" not in authority["levels"]["track-aware"]
    assert "freshness" not in authority["levels"]["track-aware"][
        "authority_enables"
    ].lower()

    workflow_refs = {item["workflow_id"]: item for item in report["workflow_availability"]}
    assert workflow_refs["fork-authority-migration"] == {
        "workflow_id": "fork-authority-migration",
        "implementation_extent": "partial",
        "available_operations": [
            "migration-assessment",
            "equipment-migration-preflight",
            "migration-config-proposal",
            "migration-plan",
            "migration-dry-run",
            "initial-config-creation",
        ],
    }

    for field, value in (
        ("activation_readiness", "unassessed"),
        ("replacement_coverage", "unassessed"),
        ("operational_continuity", "unassessed"),
    ):
        state = report[field]
        assert state["subject"] == "reported_workflows"
        assert state["value"] == value
        assert state["evidence_ids"]
        assert state["derivation_rule"]


def _write_initial_config(repo: Path, *, schema_version: str = "0.1") -> None:
    target = repo / CONFIG_RELATIVE_PATH
    target.parent.mkdir(parents=True)
    text = create_initial_config_text(
        repo,
        repository_owner="OWNER",
        repository_name="REPO",
        upstream_owner="UPSTREAM",
        upstream_name="PROJECT",
        default_branch="main",
    )
    target.write_text(
        text.replace('schema_version = "0.1"', f'schema_version = "{schema_version}"'),
        encoding="utf-8",
    )


def test_cli_and_mcp_share_config_status_and_capability_payloads(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    _write_initial_config(tmp_path)

    assert cli_main(["config", "show", "--repo", str(tmp_path), "--format", "json"]) == 0
    cli_config_read = json.loads(capsys.readouterr().out)
    mcp_config_read = mcp_server.fork_ops_config_read(str(tmp_path), normalized=True)
    assert cli_config_read == mcp_config_read
    assert cli_config_read["artifact_kind"] == "config_read_result"
    assert cli_config_read["schema_version"] == "1.0"
    assert cli_config_read["config"]["schema_version"] == "0.1"

    assert cli_main(["config", "validate", "--repo", str(tmp_path), "--json"]) == 0
    cli_status = json.loads(capsys.readouterr().out)
    mcp_status = mcp_server.fork_ops_config_validate(str(tmp_path))
    assert cli_status == mcp_status == build_status_report(tmp_path, include_config=True)
    assert cli_status["artifact_kind"] == "status_report"
    assert cli_status["schema_version"] == "1.0"

    assert cli_main(["capability", "report", "--repo", str(tmp_path), "--json"]) == 0
    cli_capability = json.loads(capsys.readouterr().out)
    mcp_capability = mcp_server.fork_ops_capability_report(str(tmp_path))
    assert cli_capability == mcp_capability == cli_status["capability"]
    assert cli_capability["artifact_kind"] == "capability_report"


def test_unsupported_config_version_is_identified_raw_and_refused_before_semantics(
    tmp_path: Path,
) -> None:
    _write_initial_config(tmp_path, schema_version="9.9")

    raw = mcp_server.fork_ops_config_read(str(tmp_path), normalized=False)
    assert raw["outcome"] == "completed"
    assert raw["format"] == "raw"
    assert raw["config_identity"] == {"schema_version": "9.9"}
    assert raw["diagnostics"][0]["code"] == "unsupported_schema_version"

    normalized = mcp_server.fork_ops_config_read(str(tmp_path), normalized=True)
    assert normalized["outcome"] == "refused"
    assert "config" not in normalized
    assert normalized["diagnostics"][0]["code"] == "unsupported_schema_version"

    status = build_status_report(tmp_path)
    assert status["outcome"] == "refused"
    assert status["capability"]["outcome"] == "refused"
    assert status["capability"]["authority_readiness"][
        "highest_authority_ready"
    ] is None
    assert all(
        level["ready"] is None
        for level in status["capability"]["authority_readiness"]["levels"].values()
    )
    with pytest.raises(ForkOpsError, match="supports config schema version 0.1"):
        load_config(tmp_path)


def test_unsupported_config_never_mints_identity_or_readiness_semantics(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    text = create_initial_config_text(tmp_path, discover_git_remotes=False)
    text = text.replace('schema_version = "0.1"', 'schema_version = "9.9"')
    text = text.replace('owner = "OWNER"', 'owner = "UNTRUSTED"')
    text = text.replace('name = "REPO"', 'name = "SEMANTICS"')
    path = tmp_path / CONFIG_RELATIVE_PATH
    path.parent.mkdir(parents=True)
    path.write_text(text)

    args = [
        "config",
        "validate",
        "--repo",
        str(tmp_path),
        "--required-level",
        "sync-ready",
        "--json",
    ]
    assert cli_main(args) == 1
    cli_result = json.loads(capsys.readouterr().out)
    mcp_result = mcp_server.fork_ops_config_validate(
        str(tmp_path), required_level="sync-ready"
    )

    assert cli_result == mcp_result
    assert cli_result["outcome"] == "refused"
    assert cli_result["capability"]["repository_identity"]["slug"] is None
    assert "UNTRUSTED" not in json.dumps(cli_result)
    assert cli_result["required_level"] == {
        "level": "sync-ready",
        "authority_ready": None,
        "missing": None,
    }


def test_missing_config_version_never_mints_identity_or_readiness_semantics(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    text = create_initial_config_text(tmp_path, discover_git_remotes=False)
    text = text.replace('schema_version = "0.1"\n\n', "")
    text = text.replace('owner = "OWNER"', 'owner = "UNTRUSTED"')
    text = text.replace('name = "REPO"', 'name = "SEMANTICS"')
    path = tmp_path / CONFIG_RELATIVE_PATH
    path.parent.mkdir(parents=True)
    path.write_text(text)

    args = [
        "config",
        "validate",
        "--repo",
        str(tmp_path),
        "--required-level",
        "sync-ready",
        "--json",
    ]
    assert cli_main(args) == 1
    cli_result = json.loads(capsys.readouterr().out)
    mcp_result = mcp_server.fork_ops_config_validate(
        str(tmp_path), required_level="sync-ready"
    )

    assert cli_result == mcp_result
    assert cli_result["outcome"] == "refused"
    assert cli_result["capability"]["outcome"] == "refused"
    assert cli_result["capability"]["repository_identity"]["slug"] is None
    assert "UNTRUSTED" not in json.dumps(cli_result)
    assert cli_result["required_level"] == {
        "level": "sync-ready",
        "authority_ready": None,
        "missing": None,
    }


def test_migration_plan_versions_nested_replay_contracts_and_refuses_legacy_input(
    tmp_path: Path,
) -> None:
    plan = generate_migration_plan(tmp_path)

    assert plan["artifact_kind"] == "migration_plan"
    assert plan["schema_version"] == "1.0"
    assert plan["outcome"] == "completed"
    assert plan["plan_executability"] == "blocked"
    assert plan["mutation_state"] == "not_requested"
    assert plan["proposed_config_patch"]["artifact_kind"] == "migration_config_patch"
    assert plan["proposed_config_patch"]["schema_version"] == "1.0"
    assert plan["equipment_migration_preflight"]["artifact_kind"] == (
        "embedded_equipment_migration_preflight"
    )
    assert plan["equipment_migration_preflight"]["schema_version"] == "1.0"
    assert plan["migration_review_artifact"]["artifact_kind"] == (
        "migration_review_artifact"
    )
    assert plan["migration_review_artifact"]["schema_version"] == "1.0"
    assert plan["equipment_review_record"]["artifact_kind"] == "equipment_review"
    assert plan["equipment_review_record"]["schema_version"] == "1.0"
    assert plan["narrative"]["artifact_kind"] == "migration_narrative"
    assert plan["narrative"]["schema_version"] == "1.0"
    assert plan["activation_readiness"] == {
        "subject": "workflow:fork-authority-migration",
        "value": "blocked",
        "evidence_ids": ["migration.blockers", "equipment.preflight"],
        "derivation_rule": "activation.named_operation_authority_equipment_and_blockers",
    }

    dry_run = dry_run_migration_plan(plan)
    assert dry_run["artifact_kind"] == "migration_dry_run"
    assert dry_run["schema_version"] == "1.0"
    assert dry_run["outcome"] == "completed"
    assert dry_run["plan_executability"] == "blocked"
    assert dry_run["mutation_state"] == "not_requested"

    legacy = deepcopy(plan)
    legacy.pop("artifact_kind")
    legacy.pop("schema_version")
    refused_dry_run = dry_run_migration_plan(legacy)
    assert refused_dry_run == {
        "artifact_kind": "migration_dry_run",
        "schema_version": "1.0",
        "operation": "migration-dry-run",
        "outcome": "refused",
        "plan_executability": "not_applicable",
        "mutation_state": "not_requested",
        "diagnostics": [
            {
                "severity": "error",
                "code": "unsupported_artifact_version",
                "message": "Migration plan uses an unsupported artifact identity or version.",
                "path": "migration_plan",
                "detail": {
                    "expected_artifact_kind": "migration_plan",
                    "supported_schema_versions": ["1.0"],
                    "observed_artifact_kind": None,
                    "observed_schema_version": None,
                    "regeneration": "Regenerate the migration plan with Fork Ops 1.0.",
                },
            }
        ],
        "evidence": [],
    }

    unknown = deepcopy(plan)
    unknown["schema_version"] = "2.0"
    refused_execution = execute_migration_plan(unknown, tmp_path)
    assert refused_execution["outcome"] == "refused"
    assert refused_execution["plan_executability"] == "not_applicable"
    assert refused_execution["mutation_state"] == "not_started"
    assert refused_execution["diagnostics"][0]["code"] == (
        "unsupported_artifact_version"
    )
    assert not (tmp_path / CONFIG_RELATIVE_PATH).exists()


def test_every_public_report_family_uses_the_common_contract_root(tmp_path: Path) -> None:
    plugin_root = Path(__file__).resolve().parents[1]
    repository_root = plugin_root.parents[1]
    plan = generate_migration_plan(tmp_path)
    reports = {
        "plugin_health_report": build_plugin_health_report(
            plugin_root,
            repo_root=repository_root,
        ),
        "migration_assessment": assess_migration(tmp_path),
        "equipment_migration_preflight": build_equipment_migration_preflight(tmp_path),
        "workflow_migration_inventory": build_workflow_migration_inventory((tmp_path,)),
        "migration_blocker_explanation": explain_migration_blocker(plan),
        "schema_artifact_report": schema_artifact_report(plugin_root),
        "mcp_healthcheck": mcp_server.mcp_healthcheck(),
        "migration_execution_result": execute_migration_plan(plan, tmp_path),
        "config_initialization_result": initialize_config(tmp_path),
    }

    for expected_kind, report in reports.items():
        assert report["artifact_kind"] == expected_kind
        assert report["schema_version"] == "1.0"
        assert report["operation"]
        assert report["outcome"] in {"completed", "blocked", "refused", "failed"}
        assert report["plan_executability"] in {
            "executable",
            "blocked",
            "not_applicable",
        }
        assert report["mutation_state"] in {
            "not_requested",
            "not_started",
            "applied",
            "rolled_back",
            "applied_unverified",
        }
        assert isinstance(report["diagnostics"], list)
        assert isinstance(report["evidence"], list)

    assert reports["migration_blocker_explanation"]["operation"] == (
        "migration-blocker-explanation"
    )
    assert "status" not in reports["migration_execution_result"]
    assert "status" not in reports["config_initialization_result"]

    config_schema = json.loads(schema_json())
    assert config_schema["artifact_kind"] == "fork_ops_config_schema"
    assert config_schema["schema_version"] == "1.0"
    assert config_schema["properties"]["schema_version"]["const"] == "0.1"


def test_plan_replay_refuses_unknown_nested_contracts_before_repository_access(
    tmp_path: Path,
) -> None:
    plan = generate_migration_plan(tmp_path)
    plan["proposed_config_patch"]["schema_version"] = "2.0"

    dry_run = dry_run_migration_plan(plan)
    execution = execute_migration_plan(plan, tmp_path / "does-not-exist")

    for result, mutation_state in (
        (dry_run, "not_requested"),
        (execution, "not_started"),
    ):
        assert result["outcome"] == "refused"
        assert result["plan_executability"] == "not_applicable"
        assert result["mutation_state"] == mutation_state
        assert result["diagnostics"][0]["code"] == "unsupported_artifact_version"
        assert result["diagnostics"][0]["path"] == (
            "migration_plan.proposed_config_patch"
        )


def test_unassessed_equipment_does_not_claim_activation_ready(tmp_path: Path) -> None:
    source = tmp_path / ".agents/skills/working-with-upstream-refs/SKILL.md"
    source.parent.mkdir(parents=True)
    source.write_text("Use `origin/upstream-stable` as the fork baseline ref.\n")
    preflight = build_equipment_migration_preflight(tmp_path)

    assert preflight["activation_blocked_by"] == []
    assert preflight["unassessed_equipment_areas"]
    assert preflight["activation_readiness"]["value"] == "unassessed"


def test_diagnostic_consumers_refuse_legacy_workflow_outputs(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    plan = generate_migration_plan(tmp_path)
    legacy = deepcopy(plan)
    legacy.pop("artifact_kind")
    legacy.pop("schema_version")

    explanation = explain_migration_blocker(legacy)
    assert explanation["outcome"] == "refused"
    assert explanation["diagnostics"][0]["code"] == "unsupported_artifact_version"

    input_path = tmp_path / "legacy-plan.json"
    input_path.write_text(json.dumps(legacy))
    assert cli_main(["migration", "explain-blocker", "--input", str(input_path)]) == 1
    cli_result = json.loads(capsys.readouterr().out)
    assert cli_result == mcp_server.fork_ops_migration_blocker_resolution(legacy)

    with pytest.raises(ForkOpsError, match="unsupported artifact identity or version"):
        render_migration_narrative(legacy)


def test_execution_preserves_independent_state_lists(tmp_path: Path) -> None:
    plan = generate_migration_plan(tmp_path)
    dry_run = dry_run_migration_plan(plan)
    execution = execute_migration_plan(plan, tmp_path)

    assert execution["replacement_coverage"] == dry_run["replacement_coverage"]
    assert execution["operational_continuity"] == dry_run["operational_continuity"]


def test_public_state_evidence_references_are_attached(tmp_path: Path) -> None:
    plan = generate_migration_plan(tmp_path)
    payloads = (
        build_equipment_migration_preflight(tmp_path),
        plan,
        dry_run_migration_plan(plan),
        execute_migration_plan(plan, tmp_path),
    )

    for payload in payloads:
        assert _state_evidence_ids(payload) <= _root_evidence_ids(payload)


def test_config_validation_exit_and_required_level_are_canonical(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    assert cli_main(["config", "validate", "--repo", str(tmp_path), "--json"]) == 1
    missing = json.loads(capsys.readouterr().out)
    assert missing["outcome"] == "blocked"

    _write_initial_config(tmp_path)
    args = [
        "config",
        "validate",
        "--repo",
        str(tmp_path),
        "--required-level",
        "sync-ready",
        "--json",
    ]
    assert cli_main(args) == 1
    cli_result = json.loads(capsys.readouterr().out)
    mcp_result = mcp_server.fork_ops_config_validate(
        str(tmp_path),
        required_level="sync-ready",
    )
    assert cli_result == mcp_result
    assert cli_result["outcome"] == "blocked"
    assert cli_result["required_level"]["authority_ready"] is False
    assert cli_result["required_level"]["missing"]


@pytest.mark.parametrize("schema_version", [None, "9.9"])
def test_text_config_validation_renders_unassessed_required_level(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    schema_version: str | None,
) -> None:
    _write_initial_config(tmp_path, schema_version=schema_version or "0.1")
    if schema_version is None:
        path = tmp_path / CONFIG_RELATIVE_PATH
        path.write_text(
            path.read_text().replace('schema_version = "0.1"\n\n', ""),
            encoding="utf-8",
        )

    assert cli_main(
        [
            "config",
            "validate",
            "--repo",
            str(tmp_path),
            "--required-level",
            "sync-ready",
        ]
    ) == 1
    stdout = capsys.readouterr().out
    assert "required_level=sync-ready: unassessed" in stdout
    assert "missing_for_required_level=" not in stdout


def test_cli_exit_status_matches_canonical_operation_outcome(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    exit_code = cli_main(
        ["schema", "check", "--plugin-root", str(tmp_path), "--json"]
    )
    report = json.loads(capsys.readouterr().out)
    assert exit_code == 1
    assert report["outcome"] == "failed"


def test_canonical_wrapper_rejects_reserved_field_collisions() -> None:
    with pytest.raises(ValueError, match="reserved canonical fields"):
        core_module._canonical_operation_result(
            core_module.ArtifactKind.MIGRATION_ASSESSMENT,
            {"operation": "migration-assessment", "outcome": "failed"},
        )

    for collision in (
        {"artifact_kind": "wrong_kind"},
        {"schema_version": "9.9"},
    ):
        with pytest.raises(ValueError, match="canonical root identity"):
            core_module._canonical_nested_artifact(
                core_module.ArtifactKind.MIGRATION_NARRATIVE,
                {**collision, "text": "x"},
            )

    with pytest.raises(ValueError, match="unattached evidence"):
        core_module._canonical_operation_result(
            core_module.ArtifactKind.MIGRATION_ASSESSMENT,
            {
                "operation": "migration-assessment",
                "activation_readiness": {
                    "value": "blocked",
                    "evidence_ids": ["missing-evidence"],
                },
            },
        )


def test_unknown_config_extensions_are_preserved_ignored_or_refused_by_dependency(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    config = parse_config_text(
        create_initial_config_text(tmp_path, discover_git_remotes=False)
    )
    config["x_vendor"] = {
        "guard": "opaque",
        "value": "ready",
        "evidence_ids": ["foreign-evidence"],
    }

    normalized = core_module.normalize_config(config)
    assert normalized["x_vendor"] == {
        "guard": "opaque",
        "value": "ready",
        "evidence_ids": ["foreign-evidence"],
    }

    target = tmp_path / CONFIG_RELATIVE_PATH
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(
        create_initial_config_text(tmp_path, discover_git_remotes=False)
        + '\n[x_vendor]\nvalue = "ready"\nevidence_ids = ["foreign-evidence"]\n',
        encoding="utf-8",
    )
    python_result = core_module.read_config_result(tmp_path, normalized=True)
    mcp_result = mcp_server.fork_ops_config_read(str(tmp_path), normalized=True)
    assert cli_main(
        ["config", "show", "--repo", str(tmp_path), "--format", "json"]
    ) == 0
    cli_result = json.loads(capsys.readouterr().out)
    assert cli_result == mcp_result == python_result
    assert cli_result["config"]["x_vendor"]["value"] == "ready"

    without_extension = deepcopy(config)
    without_extension.pop("x_vendor")
    assert capability_report(config)["authority_readiness"] == capability_report(
        without_extension
    )["authority_readiness"]

    refused = capability_report(
        config,
        extension_dependencies=("x_vendor.guard",),
    )
    assert refused["outcome"] == "refused"
    assert refused["diagnostics"][0]["code"] == "unsupported_extension_semantics"
    assert refused["diagnostics"][0]["detail"]["extension_paths"] == [
        "x_vendor.guard"
    ]


def test_internal_workflow_contract_set_has_exact_identity() -> None:
    contracts = workflow_contracts()

    assert contracts.artifact_kind == "workflow_contract_set"
    assert contracts.schema_version == "1.0"
    assert tuple(contracts)
