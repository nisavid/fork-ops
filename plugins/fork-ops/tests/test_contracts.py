from __future__ import annotations

import argparse
import ast
import asyncio
import hashlib
import importlib.util
import io
import json
import runpy
import shutil
import subprocess
import sys
import textwrap
import tomllib
import zipfile
from contextlib import redirect_stderr, redirect_stdout
from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

import fork_ops
from fork_ops import _payload_inventory as payload_inventory_module
from fork_ops import core as core_module
from fork_ops import mcp_server
from fork_ops._contracts import (
    ARTIFACT_CONTRACTS,
    ArtifactKind,
    Compatibility,
    CompatibilityState,
    Diagnostic,
    Evidence,
    LegacyPolicy,
    ObservedCompatibility,
    ObservedVersionHandling,
    ObservedVersionOutcome,
    Outcome,
    OutcomeValue,
    SchemaVersion,
    State,
    StateDimension,
    _validate_state_value_registry,
    artifact_contract,
    artifact_identity_diagnostic,
    operation_artifact,
)
from fork_ops._payload_inventory import (
    PAYLOAD_FAMILIES,
    ConsumerPurpose,
    EndpointRole,
    ExternalIdentity,
    PersistenceRole,
    Transport,
    payload_family,
)
from fork_ops.cli import build_parser
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
    dry_run_migration,
    dry_run_migration_plan,
    execute_migration,
    execute_migration_plan,
    explain_migration_blocker,
    generate_migration_plan,
    initialize_config,
    load_config,
    propose_migration_config_patch,
    schema_artifact_report,
    schema_json,
)
from fork_ops.dependency_security import collect_uv_audit_evidence, evaluate_dependency_security
from fork_ops.mcp_server import fork_ops_migration_dry_run, fork_ops_migration_execute
from fork_ops.schema import (
    CONFIG_SCHEMA_ARTIFACT_KIND,
    CONFIG_SCHEMA_VERSION,
    schema_diagnostics,
)
from fork_ops.schema import Diagnostic as SchemaDiagnostic
from fork_ops.security_exceptions import (
    SecurityExceptionValidationError,
    validate_authority_migration_projection,
    validate_security_exception_inventory,
)
from fork_ops.workflow_catalog import workflow_catalog, workflow_contracts

EndpointRow = tuple[
    ArtifactKind,
    EndpointRole,
    str,
    Transport,
    PersistenceRole | None,
]

_CANONICAL_STATE_FIELD_NAMES = frozenset(
    {
        "activation_readiness",
        "replacement_coverage",
        "operational_continuity",
    }
)
_CANONICAL_STATE_CONTAINER_NAMES = frozenset(
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
    path: tuple[str, ...] = (),
    *,
    state_container: bool = True,
) -> list[tuple[tuple[str, ...], dict[str, object]]]:
    states: list[tuple[tuple[str, ...], dict[str, object]]] = []
    if isinstance(value, dict):
        for key, nested in value.items():
            nested_path = (*path, str(key))
            if (
                state_container
                and key in _CANONICAL_STATE_FIELD_NAMES
            ):
                if isinstance(nested, dict):
                    states.append((nested_path, nested))
                elif isinstance(nested, list):
                    states.extend(
                        ((*nested_path, str(index)), item)
                        for index, item in enumerate(nested)
                        if isinstance(item, dict)
                    )
                continue
            if key in _CANONICAL_STATE_CONTAINER_NAMES:
                states.extend(
                    _canonical_state_payloads(
                        nested,
                        nested_path,
                        state_container=True,
                    )
                )
    return states


def _assert_human_state_coverage(text: str, payload: dict[str, object]) -> None:
    states = _canonical_state_payloads(payload)
    assert states
    for path, state in states:
        prefix = f"state.{'.'.join(path)}"
        assert f"{prefix}.value={state['value']}" in text
        evidence_ids = state["evidence_ids"]
        assert isinstance(evidence_ids, list)
        assert f"{prefix}.evidence_ids={','.join(evidence_ids) or 'none'}" in text
        for field in ("subject", "derivation_rule"):
            if field in state:
                assert f"{prefix}.{field}={state[field]}" in text


def _assert_exact_state_scalars(payload: dict[str, object]) -> None:
    states = _canonical_state_payloads(payload)
    assert states
    for _, state in states:
        assert type(state["value"]) is str
        evidence_ids = state["evidence_ids"]
        assert isinstance(evidence_ids, list)
        assert all(type(evidence_id) is str for evidence_id in evidence_ids)

_PYTHON_ENDPOINT_NODE = (
    "plugins/fork-ops/tests/test_contracts.py::"
    "test_python_payload_endpoints_execute_with_exact_role_attribution"
)
_PERSISTENCE_ENDPOINT_NODE = (
    "plugins/fork-ops/tests/test_contracts.py::"
    "test_canonical_replay_and_persisted_payloads_are_exact"
)
_SUBPROCESS_TIMEOUT_SECONDS = 30.0


def _producer_row(
    kind: ArtifactKind,
    id: str,
    transport: Transport,
) -> EndpointRow:
    return (kind, EndpointRole.PRODUCER, id, transport, None)


def _consumer_row(
    kind: ArtifactKind,
    id: str,
    transport: Transport,
) -> EndpointRow:
    return (kind, EndpointRole.CONSUMER, id, transport, None)


def _persistence_row(
    kind: ArtifactKind,
    path: str,
    transport: Transport,
    role: PersistenceRole,
) -> EndpointRow:
    return (kind, EndpointRole.PERSISTENCE, path, transport, role)


def _inventory_rows(*, transports: set[Transport]) -> set[EndpointRow]:
    rows: set[EndpointRow] = set()
    for family in PAYLOAD_FAMILIES:
        rows.update(
            _producer_row(family.kind, endpoint.id, endpoint.transport)
            for endpoint in family.producers
            if endpoint.transport in transports
        )
        rows.update(
            _consumer_row(family.kind, endpoint.id, endpoint.transport)
            for endpoint in family.consumers
            if endpoint.transport in transports
        )
        rows.update(
            _persistence_row(family.kind, endpoint.path, endpoint.transport, endpoint.role)
            for endpoint in family.persistence
            if endpoint.transport in transports
        )
    return rows


def _inventory_rows_characterized_by(node_id: str) -> set[EndpointRow]:
    rows: set[EndpointRow] = set()
    for family in PAYLOAD_FAMILIES:
        rows.update(
            _producer_row(family.kind, endpoint.id, endpoint.transport)
            for endpoint in family.producers
            if node_id in endpoint.characterized_by
        )
        rows.update(
            _consumer_row(family.kind, endpoint.id, endpoint.transport)
            for endpoint in family.consumers
            if node_id in endpoint.characterized_by
        )
        rows.update(
            _persistence_row(family.kind, endpoint.path, endpoint.transport, endpoint.role)
            for endpoint in family.persistence
            if node_id in endpoint.characterized_by
        )
    return rows


def test_contract_foundations_do_not_expand_the_installed_public_surface(
    tmp_path: Path,
) -> None:
    expected_exports = [
        "CONFIG_RELATIVE_PATH",
        "assess_migration",
        "build_plugin_health_report",
        "build_status_report",
        "build_workflow_migration_inventory",
        "create_initial_config_text",
        "explain_migration_blocker",
        "find_config_path",
        "generate_migration_plan",
        "load_config",
        "render_migration_narrative",
        "workflow_catalog",
    ]
    assert fork_ops.__all__ == expected_exports
    assert importlib.util.find_spec("fork_ops.contracts") is None
    assert importlib.util.find_spec("fork_ops.payload_inventory") is None

    plugin_root = Path(__file__).resolve().parents[1]
    source_copy = tmp_path / "package-source"
    shutil.copytree(
        plugin_root,
        source_copy,
        ignore=shutil.ignore_patterns(
            ".pytest_cache",
            "__pycache__",
            "*.egg-info",
            "build",
        ),
    )
    wheel_directory = tmp_path / "wheel"
    wheel_directory.mkdir()
    wheel_builder = textwrap.dedent(
        """\
        import base64
        import hashlib
        import sys
        import zipfile
        from pathlib import Path

        package_root = Path(sys.argv[1]) / "src" / "fork_ops"
        wheel_directory = Path(sys.argv[2])
        wheel = wheel_directory / "fork_ops-0.1.0-py3-none-any.whl"
        entries = {
            path.relative_to(package_root.parent).as_posix(): path.read_bytes()
            for path in sorted(package_root.rglob("*"))
            if path.is_file()
            and "__pycache__" not in path.parts
            and path.suffix != ".pyc"
        }
        dist_info = "fork_ops-0.1.0.dist-info"
        entries[f"{dist_info}/METADATA"] = (
            "Metadata-Version: 2.1\\n"
            "Name: fork-ops\\n"
            "Version: 0.1.0\\n"
            "Requires-Python: >=3.11\\n"
        ).encode()
        entries[f"{dist_info}/WHEEL"] = (
            "Wheel-Version: 1.0\\n"
            "Generator: fork-ops-contract-characterization\\n"
            "Root-Is-Purelib: true\\n"
            "Tag: py3-none-any\\n"
        ).encode()
        record_path = f"{dist_info}/RECORD"
        record_lines = []
        for name, content in sorted(entries.items()):
            digest = base64.urlsafe_b64encode(hashlib.sha256(content).digest()).rstrip(b"=")
            record_lines.append(f"{name},sha256={digest.decode()},{len(content)}")
        record_lines.append(f"{record_path},,")
        entries[record_path] = ("\\n".join(record_lines) + "\\n").encode()

        with zipfile.ZipFile(wheel, "w") as archive:
            for name, content in sorted(entries.items()):
                info = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
                info.compress_type = zipfile.ZIP_STORED
                info.external_attr = 0o100644 << 16
                archive.writestr(info, content)
        print(wheel)
        """
    )
    # This test characterizes the installed import surface, so it builds an exact,
    # deterministic purelib wheel with the standard library instead of resolving a
    # build backend or contacting a package index.
    built = subprocess.run(
        [
            sys.executable,
            "-I",
            "-c",
            wheel_builder,
            str(source_copy),
            str(wheel_directory),
        ],
        check=False,
        capture_output=True,
        text=True,
        env={},
        timeout=_SUBPROCESS_TIMEOUT_SECONDS,
    )
    assert built.returncode == 0, built.stdout + built.stderr
    wheel = Path(built.stdout.strip())
    assert wheel.parent == wheel_directory
    assert wheel.is_file()
    install_directory = tmp_path / "installed"
    # This synthetic wheel is purelib-only, so installation is exactly archive
    # extraction. Keep the characterization independent of optional installers:
    # the locked source-validation container intentionally exposes neither uv nor pip.
    with zipfile.ZipFile(wheel) as archive:
        assert all(
            not Path(member.filename).is_absolute()
            and ".." not in Path(member.filename).parts
            for member in archive.infolist()
        )
        archive.extractall(install_directory)
    probe = textwrap.dedent(
        """\
        import ast
        import json
        import sys
        from pathlib import Path

        package_directory = Path(sys.argv[1]) / "fork_ops"
        init_path = package_directory / "__init__.py"
        module = ast.parse(init_path.read_text())
        export_values = [
            node.value
            for node in module.body
            if isinstance(node, ast.Assign)
            and any(
                isinstance(target, ast.Name) and target.id == "__all__"
                for target in node.targets
            )
        ]
        if len(export_values) != 1:
            raise AssertionError("installed package must define exactly one __all__ assignment")
        exports = ast.literal_eval(export_values[0])

        print(json.dumps({
            "exports": exports,
            "origin": str(init_path),
            "public_contracts": (package_directory / "contracts.py").is_file(),
            "public_inventory": (package_directory / "payload_inventory.py").is_file(),
            "private_contracts": (package_directory / "_contracts.py").is_file(),
            "private_inventory": (package_directory / "_payload_inventory.py").is_file(),
        }))
        """
    )
    installed = subprocess.run(
        [sys.executable, "-I", "-S", "-c", probe, str(install_directory)],
        check=False,
        capture_output=True,
        text=True,
        env={},
        timeout=_SUBPROCESS_TIMEOUT_SECONDS,
    )
    assert installed.returncode == 0, installed.stderr
    installed_surface = json.loads(installed.stdout)
    assert installed_surface == {
        "exports": expected_exports,
        "origin": str(install_directory / "fork_ops/__init__.py"),
        "public_contracts": False,
        "public_inventory": False,
        "private_contracts": True,
        "private_inventory": True,
    }


def _cli_leaves(parser: argparse.ArgumentParser, prefix: tuple[str, ...] = ()) -> set[str]:
    actions = [
        action
        for action in parser._actions
        if isinstance(action, argparse._SubParsersAction)
    ]
    if not actions:
        return {"fork-ops " + " ".join(prefix)}
    return {
        leaf
        for action in actions
        for name, child in action.choices.items()
        for leaf in _cli_leaves(child, (*prefix, name))
    }


def test_schema_compatibility_distinguishes_current_supported_unsupported_and_legacy() -> None:
    compatibility = Compatibility(
        current=SchemaVersion.parse("2.1"),
        supported=(SchemaVersion.parse("2.0"), SchemaVersion.parse("2.1")),
        legacy_policy=LegacyPolicy.IDENTIFY_ONLY,
    )

    assert compatibility.classify("2.1") is CompatibilityState.CURRENT
    assert compatibility.classify("2.0") is CompatibilityState.SUPPORTED
    assert compatibility.classify("1.9") is CompatibilityState.UNSUPPORTED
    assert compatibility.classify(None) is CompatibilityState.LEGACY_UNVERSIONED

    observed = ObservedCompatibility(
        version_handling=ObservedVersionHandling.PERMISSIVE,
        missing_version=ObservedVersionOutcome.REPORTED,
        unknown_version=ObservedVersionOutcome.ACCEPTED,
        legacy_policy=LegacyPolicy.ACCEPT,
    )
    assert observed.version_handling is ObservedVersionHandling.PERMISSIVE
    assert observed.missing_version is ObservedVersionOutcome.REPORTED
    assert observed.unknown_version is ObservedVersionOutcome.ACCEPTED

    with pytest.raises(ValueError, match="major.minor"):
        SchemaVersion.parse("2")


def test_schema_compatibility_defaults_to_current_version_only() -> None:
    version = SchemaVersion.parse("1.0")

    compatibility = Compatibility(current=version)

    assert compatibility.supported == (version,)
    assert compatibility.classify(version) is CompatibilityState.CURRENT


@pytest.mark.parametrize(
    ("major", "minor"),
    (
        (True, 0),
        (0, False),
        (1.0, 0),
        (0, 1.0),
        ("1", 0),
        (0, "1"),
    ),
)
def test_schema_version_direct_construction_requires_exact_integer_components(
    major: object,
    minor: object,
) -> None:
    with pytest.raises(TypeError, match="exact integers"):
        SchemaVersion(major=major, minor=minor)  # type: ignore[arg-type]


def test_config_and_equipment_version_behavior_is_characterized_per_consumer(
    tmp_path: Path,
) -> None:
    observed_rows: set[EndpointRow] = set()
    config_family = payload_family(ArtifactKind.FORK_OPS_CONFIG)
    config_behavior = {
        (consumer.id, consumer.transport): (
            consumer.observed_compatibility.version_handling,
            consumer.observed_compatibility.missing_version,
            consumer.observed_compatibility.unknown_version,
            consumer.cutover_compatibility.current
            if consumer.cutover_compatibility is not None
            else None,
            consumer.cutover_compatibility.legacy_policy
            if consumer.cutover_compatibility is not None
            else None,
        )
        for consumer in config_family.consumers
    }
    enforced = (
        ObservedVersionHandling.ENFORCED,
        ObservedVersionOutcome.REFUSED,
        ObservedVersionOutcome.REFUSED,
        SchemaVersion.parse("0.1"),
        LegacyPolicy.REFUSE,
    )
    uninspected_identifying = (
        ObservedVersionHandling.UNINSPECTED,
        ObservedVersionOutcome.ACCEPTED,
        ObservedVersionOutcome.ACCEPTED,
        SchemaVersion.parse("0.1"),
        LegacyPolicy.IDENTIFY_ONLY,
    )
    permissive_identifying = (
        ObservedVersionHandling.PERMISSIVE,
        ObservedVersionOutcome.REPORTED,
        ObservedVersionOutcome.REPORTED,
        SchemaVersion.parse("0.1"),
        LegacyPolicy.IDENTIFY_ONLY,
    )
    assert config_behavior == {
        ("fork_ops.core:load_config", Transport.PYTHON): enforced,
        ("fork_ops.core:build_status_report", Transport.PYTHON): enforced,
        (
            "fork-ops config show [--format toml]",
            Transport.CLI_TEXT,
        ): uninspected_identifying,
        (
            "fork-ops config show --format json|--normalized",
            Transport.CLI_JSON,
        ): enforced,
        (
            "fork-ops config validate (without --json)",
            Transport.CLI_TEXT,
        ): enforced,
        (
            "fork-ops config validate --json",
            Transport.CLI_JSON,
        ): enforced,
        (
            "fork_ops_config_read(normalized=False)",
            Transport.MCP,
        ): permissive_identifying,
        (
            "fork_ops_config_read(normalized=True)",
            Transport.MCP,
        ): enforced,
        ("fork_ops_config_validate", Transport.MCP): enforced,
    }

    config_text = create_initial_config_text(tmp_path, discover_git_remotes=False)
    for label, version in (("missing", None), ("unknown", "9.9")):
        repo = tmp_path / f"config-{label}"
        repo.mkdir()
        raw = config_text
        if version is None:
            raw = raw.replace('schema_version = "0.1"\n\n', "")
        else:
            raw = raw.replace('schema_version = "0.1"', f'schema_version = "{version}"')
        path = repo / CONFIG_RELATIVE_PATH
        path.parent.mkdir()
        path.write_text(raw, encoding="utf-8")

        with pytest.raises(ForkOpsError, match="supports config schema version 0.1"):
            load_config(repo)
        report = build_status_report(repo)
        diagnostic_codes = {item["code"] for item in report["diagnostics"]}
        assert report["outcome"] == "refused"
        assert diagnostic_codes == {"unsupported_schema_version"}

        raw_exit, raw_stdout, _ = _invoke_cli(
            ["config", "show", "--repo", str(repo)]
        )
        normalized_exit, normalized_stdout, _ = _invoke_cli(
            ["config", "show", "--repo", str(repo), "--normalized"]
        )
        text_validate_exit, _, _ = _invoke_cli(
            ["config", "validate", "--repo", str(repo)]
        )
        json_validate_exit, json_validate_stdout, _ = _invoke_cli(
            ["config", "validate", "--repo", str(repo), "--json"]
        )
        assert raw_exit == 0
        assert normalized_exit == 1
        assert raw_stdout == raw
        assert json.loads(normalized_stdout)["outcome"] == "refused"
        assert text_validate_exit == json_validate_exit == 1
        assert {
            item["code"] for item in json.loads(json_validate_stdout)["diagnostics"]
        } == {"unsupported_schema_version"}

        raw_mcp = mcp_server.fork_ops_config_read(str(repo), normalized=False)
        normalized_mcp = mcp_server.fork_ops_config_read(str(repo), normalized=True)
        validated_mcp = mcp_server.fork_ops_config_validate(str(repo))
        assert raw_mcp["raw"] == raw
        assert raw_mcp["outcome"] == "completed"
        assert {item["code"] for item in raw_mcp["diagnostics"]} == {
            "unsupported_schema_version"
        }
        for mcp_report in (normalized_mcp, validated_mcp):
            assert mcp_report["outcome"] == "refused"
            assert {item["code"] for item in mcp_report["diagnostics"]} == {
                "unsupported_schema_version"
            }

    observed_rows.update(
        _consumer_row(config_family.kind, consumer.id, consumer.transport)
        for consumer in config_family.consumers
    )

    equipment_family = payload_family(ArtifactKind.EQUIPMENT_REVIEW)
    assert {
        (consumer.id, consumer.transport): (
            consumer.observed_compatibility.version_handling,
            consumer.observed_compatibility.missing_version,
            consumer.observed_compatibility.unknown_version,
            consumer.cutover_compatibility.current
            if consumer.cutover_compatibility is not None
            else None,
            consumer.cutover_compatibility.legacy_policy
            if consumer.cutover_compatibility is not None
            else None,
        )
        for consumer in equipment_family.consumers
    } == {
        (
            "fork_ops.core:_equipment_review_record_report",
            Transport.PYTHON,
        ): (
            ObservedVersionHandling.ENFORCED,
            ObservedVersionOutcome.REFUSED,
            ObservedVersionOutcome.REFUSED,
            SchemaVersion.parse("1.0"),
            LegacyPolicy.REFUSE,
        ),
        ("fork_ops.core:build_status_report", Transport.PYTHON): (
            ObservedVersionHandling.ENFORCED,
            ObservedVersionOutcome.REFUSED,
            ObservedVersionOutcome.REFUSED,
            SchemaVersion.parse("1.0"),
            LegacyPolicy.REFUSE,
        ),
        **{
            (consumer.id, consumer.transport): (
                ObservedVersionHandling.ENFORCED,
                ObservedVersionOutcome.REFUSED,
                ObservedVersionOutcome.REFUSED,
                SchemaVersion.parse("1.0"),
                LegacyPolicy.REFUSE,
            )
            for consumer in equipment_family.consumers
            if consumer.purpose in {ConsumerPurpose.REPLAY, ConsumerPurpose.EXECUTION}
        },
    }

    equipment_repo = tmp_path / "equipment"
    equipment_repo.mkdir()
    equipment_config = create_initial_config_text(
        equipment_repo,
        discover_git_remotes=False,
    )
    equipment_config_path = equipment_repo / CONFIG_RELATIVE_PATH
    equipment_config_path.parent.mkdir()
    equipment_config_path.write_text(equipment_config, encoding="utf-8")
    plan = generate_migration_plan(equipment_repo)
    review_path = equipment_repo / "docs/agents/fork-ops-equipment-review.toml"
    review_path.parent.mkdir(parents=True)
    for label, version in (("missing", None), ("unknown", "9.9")):
        review_toml = plan["equipment_review_record"]["toml"]
        if version is None:
            review_toml = review_toml.replace('schema_version = "1.0"\n', "")
        else:
            review_toml = review_toml.replace(
                'schema_version = "1.0"',
                f'schema_version = "{version}"',
            )
        review_path.write_text(review_toml, encoding="utf-8")
        direct_report = core_module._equipment_review_record_report(equipment_repo)
        status_report = build_status_report(equipment_repo)["capability"]["equipment_review"]
        assert direct_report["valid"] is status_report["valid"] is False
        assert direct_report["compatibility"] == "unsupported"
        assert status_report["compatibility"] == "unsupported"
        assert "activation_readiness" not in direct_report
        assert "replacement_coverage" not in status_report

        replay_plan = json.loads(json.dumps(plan))
        if version is None:
            replay_plan["equipment_review_record"].pop("schema_version")
        else:
            replay_plan["equipment_review_record"]["schema_version"] = version
        replay_plan["equipment_review_record"]["toml"] = review_toml
        plan_path = tmp_path / f"equipment-plan-{label}.json"
        plan_path.write_text(json.dumps(replay_plan), encoding="utf-8")

        assert dry_run_migration(equipment_repo, plan=replay_plan)["outcome"] == "refused"
        assert dry_run_migration_plan(replay_plan)["outcome"] == "refused"
        assert execute_migration(equipment_repo, plan=replay_plan)["outcome"] == "refused"
        assert execute_migration_plan(replay_plan, equipment_repo)["outcome"] == "refused"
        cli_dry_exit, _, _ = _invoke_cli(
            ["migration", "dry-run", "--plan", str(plan_path)]
        )
        cli_execute_exit, _, _ = _invoke_cli(
            [
                "migration",
                "execute",
                "--repo",
                str(equipment_repo),
                "--plan",
                str(plan_path),
            ]
        )
        assert cli_dry_exit == 1
        assert cli_execute_exit == 1
        assert fork_ops_migration_dry_run(
            str(equipment_repo), migration_plan=replay_plan
        )["outcome"] == "refused"
        assert fork_ops_migration_execute(
            str(equipment_repo), migration_plan=replay_plan
        )["outcome"] == "refused"

    observed_rows.update(
        _consumer_row(equipment_family.kind, consumer.id, consumer.transport)
        for consumer in equipment_family.consumers
    )
    version_node = (
        "plugins/fork-ops/tests/test_contracts.py::"
        "test_config_and_equipment_version_behavior_is_characterized_per_consumer"
    )
    assert observed_rows == _inventory_rows_characterized_by(version_node)


def test_shared_diagnostic_evidence_state_and_outcome_primitives_are_independent() -> None:
    evidence = Evidence(
        id="git:upstream-main",
        source="git",
        detail={"ref": "refs/remotes/upstream/main"},
    )
    state = State(
        dimension=StateDimension.PLAN_EXECUTABILITY,
        value="blocked",
        evidence_ids=(evidence.id,),
    )
    diagnostic = Diagnostic(
        severity="error",
        code="migration.blocked",
        message="The reviewed plan is blocked.",
        detail={"state": state.value},
    )
    outcome = Outcome(
        value=OutcomeValue.BLOCKED,
        states=(state,),
        diagnostics=(diagnostic,),
        evidence=(evidence,),
    )

    assert SchemaDiagnostic is Diagnostic
    assert diagnostic.to_dict() == {
        "severity": "error",
        "code": "migration.blocked",
        "message": "The reviewed plan is blocked.",
        "detail": {"state": "blocked"},
    }
    assert outcome.states[0].dimension is StateDimension.PLAN_EXECUTABILITY
    assert outcome.value is OutcomeValue.BLOCKED
    assert outcome.evidence[0].id == "git:upstream-main"


def test_artifact_identity_diagnostic_names_the_registered_version_field() -> None:
    schema_diagnostic = artifact_identity_diagnostic(
        {},
        expected_kind=ArtifactKind.MIGRATION_PLAN,
        path="migration_plan",
        label="Migration plan",
    )
    contract_diagnostic = artifact_identity_diagnostic(
        {},
        expected_kind=ArtifactKind.SECURITY_EXCEPTION_CONTRACT,
        path="security_exception_contract",
        label="Security exception contract",
    )

    assert schema_diagnostic is not None
    assert schema_diagnostic.detail is not None
    assert schema_diagnostic.detail["observed_schema_version"] is None
    assert schema_diagnostic.detail["supported_schema_versions"] == ["1.0"]
    assert "observed_contract_version" not in schema_diagnostic.detail
    assert contract_diagnostic is not None
    assert contract_diagnostic.detail is not None
    assert contract_diagnostic.detail["observed_contract_version"] is None
    assert contract_diagnostic.detail["supported_contract_versions"] == ["1.0"]
    assert "observed_schema_version" not in contract_diagnostic.detail


def test_unknown_migration_artifact_diagnostic_has_stable_expected_identity() -> None:
    diagnostic = core_module._migration_workflow_identity_diagnostic(
        {"artifact_kind": "unknown", "schema_version": "9.9"},
        allow_explanation=False,
    )

    assert diagnostic is not None
    assert diagnostic.detail is not None
    assert diagnostic.detail["expected_artifact_kind"] == sorted(
        artifact_kind
        for artifact_kind, kind in core_module._MIGRATION_ARTIFACT_KIND_BY_VALUE.items()
        if kind is not ArtifactKind.MIGRATION_BLOCKER_EXPLANATION
    )
    assert diagnostic.detail["supported_schema_versions"] == ["1.0"]


def test_versioned_inventory_distinguishes_omitted_and_explicit_artifact_kind() -> None:
    with pytest.raises(ValueError, match="inventory artifact kind differs"):
        payload_inventory_module._versioned(
            ArtifactKind.MIGRATION_PLAN,
            emitted_artifact_kind=None,
            producers=(),
            consumers=(),
            docs=(),
            tests=(),
        )


def test_config_schema_identity_constants_match_the_artifact_registry() -> None:
    contract = artifact_contract(ArtifactKind.FORK_OPS_CONFIG_SCHEMA)

    assert CONFIG_SCHEMA_ARTIFACT_KIND == contract.emitted_artifact_kind
    assert CONFIG_SCHEMA_VERSION == str(contract.current_version)


def test_state_values_are_scoped_to_their_dimension() -> None:
    with pytest.raises(ValueError, match="activation_readiness"):
        State(
            dimension=StateDimension.ACTIVATION_READINESS,
            value="continuous",
        )
    with pytest.raises(ValueError, match="operational_continuity"):
        State(
            dimension=StateDimension.OPERATIONAL_CONTINUITY,
            value="ready",
        )

    assert State(
        dimension=StateDimension.ACTIVATION_READINESS,
        value="ready",
    ).value == "ready"
    enum_backed_state = State(
        dimension=StateDimension.EXECUTION_OUTCOME,
        value=OutcomeValue.COMPLETED,
    )
    assert type(enum_backed_state.value) is str
    assert type(enum_backed_state.to_dict()["value"]) is str


def test_state_value_registry_requires_exact_dimension_coverage() -> None:
    with pytest.raises(
        RuntimeError,
        match="state value registry must explicitly cover every state dimension",
    ):
        _validate_state_value_registry({})


def test_sequence_backed_contract_primitives_detach_caller_owned_lists() -> None:
    version = SchemaVersion.parse("1.0")
    supported = [version]
    compatibility = Compatibility(current=version, supported=supported)  # type: ignore[arg-type]

    evidence_ids = ["git:upstream-main"]
    state = State(
        dimension=StateDimension.PLAN_EXECUTABILITY,
        value="blocked",
        evidence_ids=evidence_ids,  # type: ignore[arg-type]
    )
    diagnostic = Diagnostic(
        severity="error",
        code="migration.blocked",
        message="The reviewed plan is blocked.",
        detail={},
    )
    evidence = Evidence(id="git:upstream-main", source="git")
    states = [state]
    diagnostics = [diagnostic]
    evidence_items = [evidence]
    outcome = Outcome(
        value=OutcomeValue.BLOCKED,
        states=states,  # type: ignore[arg-type]
        diagnostics=diagnostics,  # type: ignore[arg-type]
        evidence=evidence_items,  # type: ignore[arg-type]
    )

    supported.clear()
    evidence_ids.clear()
    states.clear()
    diagnostics.clear()
    evidence_items.clear()

    assert compatibility.supported == (version,)
    assert state.evidence_ids == ("git:upstream-main",)
    assert outcome.states == (state,)
    assert outcome.diagnostics == (diagnostic,)
    assert outcome.evidence == (evidence,)


def test_public_state_payloads_use_exact_json_scalar_types(tmp_path: Path) -> None:
    review_policy = tmp_path / "docs/agents/review-policy.md"
    review_policy.parent.mkdir(parents=True)
    review_policy.write_text(
        "Review bot policy lives here. Before publication closeout, validate "
        "CodeQL code scanning and review threads.\n",
        encoding="utf-8",
    )
    plan = generate_migration_plan(tmp_path)
    assert plan["replacement_coverage"]
    assert plan["operational_continuity"]
    payloads = (
        build_status_report(tmp_path),
        plan,
        build_equipment_migration_preflight(tmp_path),
        dry_run_migration_plan(plan),
        execute_migration_plan(plan, tmp_path),
    )

    for payload in payloads:
        _assert_exact_state_scalars(payload)


def test_evidence_detail_is_a_detached_canonical_immutable_value() -> None:
    original = {
        "identity": {"ref": "refs/remotes/upstream/main"},
        "observations": ["present", {"sha": "a" * 40}],
    }

    evidence = Evidence(id="git:upstream-main", source="git", detail=original)
    original["identity"]["ref"] = "refs/remotes/upstream/changed"  # type: ignore[index]
    original["observations"].append("changed")  # type: ignore[union-attr]

    identity = evidence.detail["identity"]
    observations = evidence.detail["observations"]
    assert identity["ref"] == "refs/remotes/upstream/main"  # type: ignore[index]
    assert observations == ("present", {"sha": "a" * 40})
    with pytest.raises(TypeError):
        evidence.detail["changed"] = True  # type: ignore[index]
    with pytest.raises(ValueError, match="canonical"):
        Evidence(id="invalid", source="test", detail={"ratio": 0.5})


def test_evidence_detail_does_not_masquerade_as_canonical_state() -> None:
    payload = operation_artifact(
        ArtifactKind.MIGRATION_ASSESSMENT,
        "migration-assessment",
        {
            "evidence": [
                Evidence(
                    id="upstream:opaque",
                    source="upstream",
                    detail={
                        "value": "ready",
                        "evidence_ids": ["foreign-evidence"],
                    },
                ).to_dict()
            ]
        },
    )

    evidence = payload["evidence"]
    assert isinstance(evidence, list)
    first_evidence = evidence[0]
    assert isinstance(first_evidence, dict)
    assert first_evidence["detail"] == {
        "value": "ready",
        "evidence_ids": ["foreign-evidence"],
    }
    assert _canonical_state_payloads(payload) == []

    nested_artifact = {
        "preview": {
            "artifact_kind": "migration_dry_run",
            "activation_readiness": {
                "value": "unassessed",
                "evidence_ids": ["preview-evidence"],
            },
        }
    }
    assert [path for path, _ in _canonical_state_payloads(nested_artifact)] == [
        ("preview", "activation_readiness")
    ]


def test_payload_inventory_is_complete_for_current_legacy_and_versioned_families() -> None:
    expected_legacy = {ArtifactKind.SECURITY_EXCEPTION_GUIDE}
    expected_versioned = set(ArtifactKind) - expected_legacy

    assert len(PAYLOAD_FAMILIES) == len(ArtifactKind)
    assert {family.kind for family in PAYLOAD_FAMILIES} == set(ArtifactKind)
    assert set(ARTIFACT_CONTRACTS) == set(ArtifactKind)
    for family in PAYLOAD_FAMILIES:
        contract = artifact_contract(family.kind)
        assert family.emitted_artifact_kind == contract.emitted_artifact_kind
        assert family.emitted_version == contract.current_version
        assert family.version_field == contract.version_field
        assert all(
            consumer.cutover_compatibility is None
            or consumer.cutover_compatibility.current == contract.current_version
            for consumer in family.consumers
        )
    assert {
        family.kind
        for family in PAYLOAD_FAMILIES
        if family.external_identity is ExternalIdentity.LEGACY_UNVERSIONED
    } == expected_legacy
    assert {
        family.kind
        for family in PAYLOAD_FAMILIES
        if family.external_identity is not ExternalIdentity.LEGACY_UNVERSIONED
    } == expected_versioned
    assert all(family.producers or family.producer_gap for family in PAYLOAD_FAMILIES)
    assert all(family.consumers or family.consumer_gap for family in PAYLOAD_FAMILIES)
    with pytest.raises(ValueError, match="production cannot be both"):
        replace(PAYLOAD_FAMILIES[0], producer_gap="contradictory producer gap")
    with pytest.raises(ValueError, match="consumption cannot be both"):
        replace(PAYLOAD_FAMILIES[0], consumer_gap="contradictory consumer gap")
    assert all(family.documented_by for family in PAYLOAD_FAMILIES)
    assert all(family.characterized_by for family in PAYLOAD_FAMILIES)
    characterization_nodes = {
        node_id
        for family in PAYLOAD_FAMILIES
        for node_id in family.characterized_by
    }
    assert all("::" in node_id for node_id in characterization_nodes)
    assert all(
        endpoint.characterized_by
        and set(endpoint.characterized_by) <= characterization_nodes
        for family in PAYLOAD_FAMILIES
        for endpoint in (*family.producers, *family.consumers, *family.persistence)
    )

    repository_root = Path(__file__).resolve().parents[3]
    assert all(
        (repository_root / path).is_file()
        for family in PAYLOAD_FAMILIES
        for path in family.documented_by
    )
    collection = subprocess.run(
        [
            sys.executable,
            "-m",
            "pytest",
            "--collect-only",
            "-q",
            *sorted(characterization_nodes),
        ],
        cwd=repository_root,
        check=False,
        capture_output=True,
        text=True,
        env={"PYTHONHASHSEED": "0"},
        timeout=_SUBPROCESS_TIMEOUT_SECONDS,
    )
    assert collection.returncode == 0, collection.stdout + collection.stderr


def test_payload_families_reject_duplicate_boundary_identities() -> None:
    family = payload_family(ArtifactKind.FORK_OPS_CONFIG)
    producer = family.producers[0]
    consumer = family.consumers[0]
    persistence = family.persistence[0]

    with pytest.raises(ValueError, match="producer endpoints must not contain duplicates"):
        replace(
            family,
            producers=(
                producer,
                replace(producer, characterized_by=("tests::different-producer",)),
            ),
        )
    with pytest.raises(ValueError, match="consumer endpoints must not contain duplicates"):
        replace(
            family,
            consumers=(
                consumer,
                replace(consumer, characterized_by=("tests::different-consumer",)),
            ),
        )
    with pytest.raises(ValueError, match="persistence endpoints must not contain duplicates"):
        replace(
            family,
            persistence=(
                persistence,
                replace(persistence, characterized_by=("tests::different-persistence",)),
            ),
        )


def test_inventory_builders_explain_missing_characterization(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    producer_key = next(iter(payload_inventory_module._PRODUCER_CHARACTERIZATION))
    monkeypatch.delitem(payload_inventory_module._PRODUCER_CHARACTERIZATION, producer_key)
    with pytest.raises(RuntimeError, match="missing producer characterization"):
        payload_inventory_module._endpoint(*producer_key)

    replay_key = ("fork_ops.core:dry_run_migration(plan=)", Transport.PYTHON)
    consumer_key = next(
        key
        for key in payload_inventory_module._CONSUMER_CHARACTERIZATION
        if key != replay_key
    )
    monkeypatch.delitem(payload_inventory_module._CONSUMER_CHARACTERIZATION, consumer_key)
    with pytest.raises(RuntimeError, match="missing consumer characterization"):
        payload_inventory_module._consumer(consumer_key[0], transport=consumer_key[1])

    monkeypatch.delitem(payload_inventory_module._CONSUMER_CHARACTERIZATION, replay_key)
    with pytest.raises(RuntimeError, match="missing consumer characterization"):
        payload_inventory_module._plan_replay_and_execution()

    persistence_key = next(iter(payload_inventory_module._PERSISTENCE_CHARACTERIZATION))
    monkeypatch.delitem(payload_inventory_module._PERSISTENCE_CHARACTERIZATION, persistence_key)
    with pytest.raises(RuntimeError, match="missing persistence characterization"):
        payload_inventory_module._persistence(*persistence_key)


def test_payload_family_refuses_unsupported_artifact_kind() -> None:
    unsupported: Any = "unsupported-artifact-kind"
    with pytest.raises(ValueError, match="unsupported payload artifact kind"):
        payload_family(unsupported)


def _invoke_cli(argv: list[str]) -> tuple[int, str, str]:
    stdout = io.StringIO()
    stderr = io.StringIO()
    with redirect_stdout(stdout), redirect_stderr(stderr):
        exit_code = cli_main(argv)
    return exit_code, stdout.getvalue(), stderr.getvalue()


def test_cross_module_consumer_edges_name_the_live_callable_and_exact_test() -> None:
    catalog = payload_family(ArtifactKind.WORKFLOW_CATALOG)
    assert {consumer.id for consumer in catalog.consumers} == {
        "fork_ops.core:_cli_execution_check",
        "scripts/produce_validation_evidence.py:_workflow_catalog_check",
    }
    contracts = payload_family(ArtifactKind.WORKFLOW_CONTRACT_SET)
    assert {consumer.id for consumer in contracts.consumers} == {
        "fork_ops.core:build_workflow_migration_inventory",
        "fork_ops.core:explain_migration_blocker via _workflow_contract_dict",
    }
    validation = payload_family(ArtifactKind.VALIDATION_EVIDENCE_RESULT)
    assert {consumer.id for consumer in validation.consumers} == {
        "scripts/produce_validation_evidence.py:_candidate_identity_check",
        "scripts/produce_validation_evidence.py:_release_preflight_evidence_check",
        "scripts/produce_validation_evidence.py:_release_trust_check",
    }
    contract = payload_family(ArtifactKind.SECURITY_EXCEPTION_CONTRACT)
    assert {consumer.id for consumer in contract.consumers} == {
        "fork_ops.security_exceptions:load_security_exception_contract",
        "scripts/security_exception_projections.py:main",
    }

    security_inventory = payload_family(ArtifactKind.SECURITY_EXCEPTION_INVENTORY)
    expected_nodes = {
        (
            "fork_ops.security_exceptions:"
            "parse_public_security_exception_command(current_inventory=)"
        ): (
            "plugins/fork-ops/tests/test_security_exceptions.py::"
            "test_public_command_parser_enforces_exact_six_and_eight_token_grammars"
        ),
        "fork_ops.security_exceptions:validate_public_transition_projection(current_inventory=)": (
            "plugins/fork-ops/tests/test_security_exceptions.py::"
            "test_transition_projection_never_claims_authenticated_persistence"
        ),
        "fork_ops.security_exceptions:validate_lineage_issuance_projection(current_inventory=)": (
            "plugins/fork-ops/tests/test_security_exceptions.py::"
            "test_new_lineage_and_advisory_revision_projections_are_pure_and_exact"
        ),
        (
            "fork_ops.security_exceptions:"
            "validate_advisory_reconciliation_projection(current_inventory=)"
        ): (
            "plugins/fork-ops/tests/test_security_exceptions.py::"
            "test_new_lineage_and_advisory_revision_projections_are_pure_and_exact"
        ),
        "fork_ops.security_exceptions:validate_response_clock_inventory(current_inventory=)": (
            "plugins/fork-ops/tests/test_security_exceptions.py::"
            "test_response_clock_zero_is_positive_only_for_complete_empty_inventory"
        ),
        "fork_ops.dependency_security:evaluate_dependency_security": (
            "plugins/fork-ops/tests/test_contracts.py::"
            "test_typed_security_exception_inventory_roundtrips_to_dependency_evaluation"
        ),
        "fork_ops.security_exceptions:is_structural_security_exception_inventory": (
            "plugins/fork-ops/tests/test_security_exceptions.py::"
            "test_caller_asserted_authority_can_only_form_a_structural_inventory"
        ),
        "fork_ops.security_exceptions:is_validated_security_exception_inventory": (
            "plugins/fork-ops/tests/test_security_exceptions.py::"
            "test_caller_asserted_authority_can_only_form_a_structural_inventory"
        ),
        (
            "fork_ops.repository_controls:"
            "evaluate_first_party_security(security_exception_inventory=)"
        ): (
            "plugins/fork-ops/tests/test_repository_controls.py::"
            "test_complete_current_controls_produce_a_deterministic_first_party_pass"
        ),
    }
    assert {
        consumer.id: set(consumer.characterized_by)
        for consumer in security_inventory.consumers
    } == {
        id: {node} for id, node in expected_nodes.items()
    }

    dependency_evidence = payload_family(
        ArtifactKind.NORMALIZED_DEPENDENCY_VULNERABILITY_EVIDENCE
    )
    assert dependency_evidence.consumers[0].characterized_by == (
        "plugins/fork-ops/tests/test_dependency_security.py::"
        "DependencySecurityTests::"
        "test_exact_current_complete_observations_produce_canonical_pass",
    )

    ledger = payload_family(ArtifactKind.SECURITY_EXCEPTION_LEDGER)
    ledger_node = (
        "plugins/fork-ops/tests/test_security_exceptions.py::"
        "test_empty_checked_in_public_ledger_validates_with_no_bootstrap_path"
    )
    package_adapter_node = (
        "plugins/fork-ops/tests/test_repository_control_adapters.py::"
        "test_package_adapters_observe_dependency_workflow_and_public_ledger_state"
    )
    assert {consumer.id: consumer.characterized_by for consumer in ledger.consumers} == {
        "fork_ops.security_exceptions:validate_security_exception_inventory(public_ledger=)": (
            ledger_node,
        ),
        "fork_ops.security_exceptions:validate_public_security_exception_ledger": (
            package_adapter_node,
        ),
    }
    assert all(
        endpoint.characterized_by == (ledger_node,)
        for endpoint in (*ledger.producers, *ledger.persistence)
    )

    public_request = payload_family(
        ArtifactKind.SECURITY_EXCEPTION_PUBLIC_COMMAND_REQUEST
    )
    transition_node = (
        "plugins/fork-ops/tests/test_security_exceptions.py::"
        "test_transition_projection_never_claims_authenticated_persistence"
    )
    assert {endpoint.id for endpoint in public_request.producers} == {
        "fork_ops.security_exceptions:parse_public_security_exception_command"
    }
    assert {endpoint.id for endpoint in public_request.consumers} == {
        "fork_ops.security_exceptions:validate_public_transition_projection(request=)"
    }
    assert all(
        endpoint.characterized_by == (transition_node,)
        for endpoint in (*public_request.producers, *public_request.consumers)
    )

    structural_observation = payload_family(
        ArtifactKind.SECURITY_EXCEPTION_STRUCTURAL_PROVIDER_OBSERVATION
    )
    response_node = (
        "plugins/fork-ops/tests/test_security_exceptions.py::"
        "test_response_clock_zero_is_positive_only_for_complete_empty_inventory"
    )
    assert {endpoint.id for endpoint in structural_observation.producers} == {
        "fork_ops.security_exceptions:validate_provider_observation_envelope"
    }
    assert {endpoint.id for endpoint in structural_observation.consumers} == {
        "fork_ops.security_exceptions:validate_response_clock_inventory(structural_observations=)"
    }
    assert all(
        endpoint.characterized_by == (response_node,)
        for endpoint in (*structural_observation.producers, *structural_observation.consumers)
    )

    config_patch = payload_family(ArtifactKind.MIGRATION_CONFIG_PATCH)
    assert {
        consumer.id
        for consumer in config_patch.consumers
        if consumer.purpose is ConsumerPurpose.DERIVATION
    } == {
        "fork_ops.core:assess_migration(include_proposed_config_patch=True)",
        "fork_ops.core:build_equipment_migration_preflight(proposed_config_patch)",
        "fork_ops.core:generate_migration_plan",
    }
    workflow_inventory = payload_family(ArtifactKind.WORKFLOW_MIGRATION_INVENTORY)
    assert {consumer.id for consumer in workflow_inventory.consumers} == {
        "fork_ops.core:build_equipment_migration_preflight(workflow_inventory)",
        "fork_ops.core:generate_migration_plan",
    }


def test_repository_control_payload_edges_are_inventoried_from_live_modules() -> None:
    families = {family.kind.value: family for family in PAYLOAD_FAMILIES}
    expected_edges = {
        "repository_control_observation_contract": (
            {"canonical packaged repository-control observation contract"},
            {"fork_ops.repository_controls:load_repository_control_contract"},
        ),
        "repository_control_observation": (
            {
                "fork_ops.repository_control_adapters:"
                "collect_repository_control_observation"
            },
            {
                "fork_ops.repository_controls:parse_repository_control_observation",
                "fork_ops.repository_controls:evaluate_first_party_security",
            },
        ),
        "repository_control_projection": (
            {
                "fork_ops.repository_control_adapters:GitHubControlAdapter.observe",
                "fork_ops.repository_control_adapters:PackageControlAdapter.observe",
                "fork_ops.repository_control_adapters:_unavailable_projection",
            },
            {
                "fork_ops.repository_controls:validate_repository_control_projection",
                "fork_ops.repository_control_adapters:"
                "collect_repository_control_observation(control projections)",
            },
        ),
        "first_party_security_result": (
            {"fork_ops.repository_controls:evaluate_first_party_security"},
            set(),
        ),
    }

    assert set(expected_edges) <= set(families)
    for artifact_kind, (producer_ids, consumer_ids) in expected_edges.items():
        family = families[artifact_kind]
        assert {producer.id for producer in family.producers} == producer_ids
        assert {consumer.id for consumer in family.consumers} == consumer_ids
        assert all(
            endpoint.characterized_by
            for endpoint in (*family.producers, *family.consumers, *family.persistence)
        )

    contract = families["repository_control_observation_contract"]
    assert {(endpoint.path, endpoint.role) for endpoint in contract.persistence} == {
        (
            "plugins/fork-ops/src/fork_ops/"
            "repository-control-observation-contract-1.0.json",
            PersistenceRole.BOTH,
        )
    }
    assert families["first_party_security_result"].consumer_gap


def test_all_cli_payload_modes_execute_with_exact_family_attribution(
    tmp_path: Path,
) -> None:
    observed_rows: set[EndpointRow] = set()
    invoked_leaves: set[str] = set()

    def execute(
        argv: list[str],
        *,
        rows: set[EndpointRow],
        expected_exit: int,
    ) -> tuple[str, str]:
        exit_code, stdout, stderr = _invoke_cli(argv)
        assert exit_code == expected_exit, (argv, stdout, stderr)
        observed_rows.update(rows)
        invoked_leaves.add(f"fork-ops {argv[0]} {argv[1]}")
        return stdout, stderr

    config_repo = tmp_path / "configured"
    config_repo.mkdir()
    config_text = create_initial_config_text(config_repo, discover_git_remotes=False)
    config_path = config_repo / CONFIG_RELATIVE_PATH
    config_path.parent.mkdir()
    config_path.write_text(config_text, encoding="utf-8")

    config_row_text = {
        _producer_row(
            ArtifactKind.FORK_OPS_CONFIG,
            "fork-ops config init (without --write)",
            Transport.CLI_TEXT,
        )
    }
    init_stdout, _ = execute(
        ["config", "init", "--repo", str(tmp_path / "init-preview")],
        rows=config_row_text,
        expected_exit=0,
    )
    assert tomllib.loads(init_stdout)["schema_version"] == "0.1"

    init_write_repo = tmp_path / "init-write"
    init_write_repo.mkdir()
    _, init_stderr = execute(
        ["config", "init", "--repo", str(init_write_repo), "--write"],
        rows={
            _consumer_row(
                ArtifactKind.CONFIG_INITIALIZATION_RESULT,
                "fork_ops.cli:cmd_config_init(--write)",
                Transport.CLI_TEXT,
            )
        },
        expected_exit=1,
    )
    assert "must be rebound on a subsequent invocation" in init_stderr
    init_stdout, _ = execute(
        ["config", "init", "--repo", str(init_write_repo), "--write"],
        rows={
            _consumer_row(
                ArtifactKind.CONFIG_INITIALIZATION_RESULT,
                "fork_ops.cli:cmd_config_init(--write)",
                Transport.CLI_TEXT,
            )
        },
        expected_exit=0,
    )
    assert init_stdout.strip() == str(init_write_repo / CONFIG_RELATIVE_PATH)

    raw_show_rows = {
        _producer_row(
            ArtifactKind.FORK_OPS_CONFIG,
            "fork-ops config show [--format toml]",
            Transport.CLI_TEXT,
        ),
        _consumer_row(
            ArtifactKind.FORK_OPS_CONFIG,
            "fork-ops config show [--format toml]",
            Transport.CLI_TEXT,
        ),
    }
    show_suffixes: tuple[list[str], ...] = ([], ["--format", "toml"])
    for suffix in show_suffixes:
        stdout, _ = execute(
            ["config", "show", "--repo", str(config_repo), *suffix],
            rows=raw_show_rows,
            expected_exit=0,
        )
        assert stdout == config_text

    normalized_show_rows = {
        _producer_row(
            ArtifactKind.FORK_OPS_CONFIG,
            "fork-ops config show --format json|--normalized",
            Transport.CLI_JSON,
        ),
        _consumer_row(
            ArtifactKind.FORK_OPS_CONFIG,
            "fork-ops config show --format json|--normalized",
            Transport.CLI_JSON,
        ),
        _producer_row(
            ArtifactKind.CONFIG_READ_RESULT,
            "fork-ops config show --format json|--normalized",
            Transport.CLI_JSON,
        ),
    }
    for suffix in (["--format", "json"], ["--normalized"]):
        stdout, _ = execute(
            ["config", "show", "--repo", str(config_repo), *suffix],
            rows=normalized_show_rows,
            expected_exit=0,
        )
        normalized_config = json.loads(stdout)
        assert normalized_config["artifact_kind"] == "config_read_result"
        assert normalized_config["schema_version"] == "1.0"
        assert normalized_config["config"]["schema_version"] == "0.1"

    stdout, _ = execute(
        ["config", "validate", "--repo", str(config_repo)],
        rows={
            _consumer_row(
                ArtifactKind.FORK_OPS_CONFIG,
                "fork-ops config validate (without --json)",
                Transport.CLI_TEXT,
            )
        },
        expected_exit=0,
    )
    assert "highest_authority_ready=" in stdout
    status_text = stdout

    stdout, _ = execute(
        ["config", "validate", "--repo", str(config_repo), "--json"],
        rows={
            _consumer_row(
                ArtifactKind.FORK_OPS_CONFIG,
                "fork-ops config validate --json",
                Transport.CLI_JSON,
            ),
            _producer_row(
                ArtifactKind.STATUS_REPORT,
                "fork-ops config validate --json",
                Transport.CLI_JSON,
            ),
        },
        expected_exit=0,
    )
    status_report = json.loads(stdout)
    assert status_report["artifact_kind"] == "status_report"
    assert set(status_report) >= {"capability", "config", "diagnostics", "outcome"}
    _assert_human_state_coverage(status_text, status_report)
    for field in ("outcome", "plan_executability", "mutation_state"):
        assert f"{field}={status_report[field]}" in status_text
        assert (
            f"capability.{field}={status_report['capability'][field]}" in status_text
        )
    assert (
        "capability.baseline_assurance="
        f"{status_report['capability']['baseline_assurance']}"
    ) in status_text
    for workflow in status_report["capability"]["workflow_availability"]:
        workflow_id = workflow["workflow_id"]
        assert (
            f"capability.workflow.{workflow_id}.implementation_extent="
            f"{workflow['implementation_extent']}"
        ) in status_text
        assert (
            f"capability.workflow.{workflow_id}.available_operations="
            f"{','.join(workflow['available_operations']) or 'none'}"
        ) in status_text

    stdout, _ = execute(
        ["capability", "report", "--repo", str(config_repo)],
        rows={
            _producer_row(
                ArtifactKind.CAPABILITY_REPORT,
                "fork-ops capability report (without --json)",
                Transport.CLI_TEXT,
            )
        },
        expected_exit=0,
    )
    assert "highest_authority_ready=" in stdout
    capability_text = stdout

    stdout, _ = execute(
        ["capability", "report", "--repo", str(config_repo), "--json"],
        rows={
            _producer_row(
                ArtifactKind.CAPABILITY_REPORT,
                "fork-ops capability report --json",
                Transport.CLI_JSON,
            )
        },
        expected_exit=0,
    )
    capability_json = json.loads(stdout)
    assert capability_json["artifact_kind"] == "capability_report"
    assert "authority_readiness" in capability_json
    assert "highest_available" not in capability_json
    _assert_human_state_coverage(capability_text, capability_json)
    for field in (
        "outcome",
        "plan_executability",
        "mutation_state",
        "baseline_assurance",
    ):
        assert f"{field}={capability_json[field]}" in capability_text
    for workflow in capability_json["workflow_availability"]:
        workflow_id = workflow["workflow_id"]
        assert (
            f"workflow.{workflow_id}.implementation_extent="
            f"{workflow['implementation_extent']}"
        ) in capability_text
        assert (
            f"workflow.{workflow_id}.available_operations="
            f"{','.join(workflow['available_operations']) or 'none'}"
        ) in capability_text

    migration_repo = tmp_path / "migration"
    migration_repo.mkdir()
    stdout, _ = execute(
        ["migration", "assess", "--repo", str(migration_repo)],
        rows={
            _producer_row(
                ArtifactKind.MIGRATION_ASSESSMENT,
                "fork-ops migration assess (without --with-proposed-config)",
                Transport.CLI_JSON,
            )
        },
        expected_exit=0,
    )
    assessment = json.loads(stdout)
    assert assessment["operation"] == "migration-assessment"
    assert "proposed_config_patch" not in assessment

    stdout, _ = execute(
        [
            "migration",
            "assess",
            "--repo",
            str(migration_repo),
            "--with-proposed-config",
        ],
        rows={
            _producer_row(
                ArtifactKind.MIGRATION_ASSESSMENT,
                "fork-ops migration assess --with-proposed-config",
                Transport.CLI_JSON,
            )
        },
        expected_exit=0,
    )
    proposed_patch = json.loads(stdout)["proposed_config_patch"]
    assert proposed_patch["operation"] == "migration-config-patch"
    assert proposed_patch["action"] == "create"

    stdout, _ = execute(
        ["migration", "preflight", "--repo", str(migration_repo)],
        rows={
            _producer_row(
                ArtifactKind.EQUIPMENT_MIGRATION_PREFLIGHT,
                "fork-ops migration preflight",
                Transport.CLI_JSON,
            )
        },
        expected_exit=0,
    )
    assert json.loads(stdout)["operation"] == "equipment-migration-preflight"

    stdout, _ = execute(
        ["migration", "plan", "--repo", str(migration_repo)],
        rows={
            _producer_row(
                ArtifactKind.MIGRATION_PLAN,
                "fork-ops migration plan",
                Transport.CLI_JSON,
            )
        },
        expected_exit=0,
    )
    plan = json.loads(stdout)
    plan_path = tmp_path / "migration-plan.json"
    plan_path.write_text(json.dumps(plan), encoding="utf-8")
    embedded_plan_families = {
        ArtifactKind.EMBEDDED_EQUIPMENT_MIGRATION_PREFLIGHT,
        ArtifactKind.MIGRATION_CONFIG_PATCH,
        ArtifactKind.MIGRATION_REVIEW_ARTIFACT,
        ArtifactKind.EQUIPMENT_REVIEW,
    }

    stdout, _ = execute(
        ["migration", "dry-run", "--repo", str(migration_repo)],
        rows={
            _producer_row(
                ArtifactKind.MIGRATION_DRY_RUN,
                "fork-ops migration dry-run (without --plan)",
                Transport.CLI_JSON,
            )
        },
        expected_exit=0,
    )
    generated_dry_run = json.loads(stdout)
    assert generated_dry_run["operation"] == "migration-dry-run"

    stdout, _ = execute(
        ["migration", "dry-run", "--plan", str(plan_path)],
        rows={
            _consumer_row(
                ArtifactKind.MIGRATION_PLAN,
                "fork-ops migration dry-run --plan",
                Transport.CLI_JSON,
            ),
            _producer_row(
                ArtifactKind.MIGRATION_DRY_RUN,
                "fork-ops migration dry-run --plan",
                Transport.CLI_JSON,
            ),
        }
        | {
            _consumer_row(
                kind,
                "fork-ops migration dry-run --plan",
                Transport.CLI_JSON,
            )
            for kind in embedded_plan_families
        },
        expected_exit=0,
    )
    replayed_dry_run = json.loads(stdout)
    assert replayed_dry_run == dry_run_migration_plan(plan)

    execute_repo = tmp_path / "execute-generated"
    execute_repo.mkdir()
    stdout, _ = execute(
        ["migration", "execute", "--repo", str(execute_repo)],
        rows={
            _producer_row(
                ArtifactKind.MIGRATION_EXECUTION_RESULT,
                "fork-ops migration execute (without --plan)",
                Transport.CLI_JSON,
            )
        },
        expected_exit=1,
    )
    generated_execution = json.loads(stdout)
    assert generated_execution["operation"] == "migration-execution"

    execute_plan_repo = tmp_path / "execute-plan"
    execute_plan_repo.mkdir()
    execute_plan = generate_migration_plan(execute_plan_repo)
    execute_plan_path = tmp_path / "execute-plan.json"
    execute_plan_path.write_text(json.dumps(execute_plan), encoding="utf-8")
    stdout, _ = execute(
        [
            "migration",
            "execute",
            "--repo",
            str(execute_plan_repo),
            "--plan",
            str(execute_plan_path),
        ],
        rows={
            _consumer_row(
                ArtifactKind.MIGRATION_PLAN,
                "fork-ops migration execute --plan",
                Transport.CLI_JSON,
            ),
            _producer_row(
                ArtifactKind.MIGRATION_EXECUTION_RESULT,
                "fork-ops migration execute --plan",
                Transport.CLI_JSON,
            ),
        }
        | {
            _consumer_row(
                kind,
                "fork-ops migration execute --plan",
                Transport.CLI_JSON,
            )
            for kind in embedded_plan_families
        },
        expected_exit=1,
    )
    replayed_execution = json.loads(stdout)
    assert replayed_execution["plan_operation"] == "migration-plan"

    diagnostic_inputs = (
        (ArtifactKind.MIGRATION_ASSESSMENT, assessment),
        (ArtifactKind.MIGRATION_PLAN, plan),
        (ArtifactKind.MIGRATION_DRY_RUN, generated_dry_run),
        (ArtifactKind.MIGRATION_EXECUTION_RESULT, generated_execution),
    )
    for index, (kind, payload) in enumerate(diagnostic_inputs):
        input_path = tmp_path / f"workflow-{index}.json"
        input_path.write_text(json.dumps(payload), encoding="utf-8")
        rows = {
            _consumer_row(
                kind,
                "fork-ops migration explain-blocker --input",
                Transport.CLI_JSON,
            ),
            _producer_row(
                ArtifactKind.MIGRATION_BLOCKER_EXPLANATION,
                "fork-ops migration explain-blocker --input",
                Transport.CLI_JSON,
            ),
        }
        stdout, _ = execute(
            ["migration", "explain-blocker", "--input", str(input_path)],
            rows=rows,
            expected_exit=0,
        )
        assert json.loads(stdout)["source_operation"] == payload["operation"]

    stdout, _ = execute(
        ["migration", "propose-config", "--repo", str(migration_repo)],
        rows={
            _producer_row(
                ArtifactKind.MIGRATION_CONFIG_PATCH,
                "fork-ops migration propose-config --format json",
                Transport.CLI_JSON,
            )
        },
        expected_exit=0,
    )
    config_patch = json.loads(stdout)
    assert config_patch["operation"] == "migration-config-patch"
    assert config_patch["action"] == "create"

    stdout, _ = execute(
        [
            "migration",
            "propose-config",
            "--repo",
            str(migration_repo),
            "--format",
            "toml",
        ],
        rows={
            _producer_row(
                ArtifactKind.FORK_OPS_CONFIG,
                "fork-ops migration propose-config --format toml",
                Transport.CLI_TEXT,
            )
        },
        expected_exit=0,
    )
    assert tomllib.loads(stdout)["schema_version"] == "0.1"

    stdout, _ = execute(
        ["workflow", "catalog"],
        rows={
            _producer_row(
                ArtifactKind.WORKFLOW_CATALOG,
                "fork-ops workflow catalog",
                Transport.CLI_JSON,
            )
        },
        expected_exit=0,
    )
    assert json.loads(stdout)["operation"] == "workflow-catalog"

    stdout, _ = execute(
        ["workflow", "inventory"],
        rows={
            _producer_row(
                ArtifactKind.WORKFLOW_MIGRATION_INVENTORY,
                "fork-ops workflow inventory",
                Transport.CLI_JSON,
            )
        },
        expected_exit=0,
    )
    assert json.loads(stdout)["operation"] == "workflow-migration-inventory"

    plugin_root = Path(__file__).resolve().parents[1]
    repository_root = plugin_root.parents[1]
    stdout, _ = execute(
        [
            "plugin",
            "health",
            "--plugin-root",
            str(plugin_root),
            "--repo-root",
            str(repository_root),
            "--ui-visible",
        ],
        rows={
            _producer_row(
                ArtifactKind.PLUGIN_HEALTH_REPORT,
                "fork-ops plugin health",
                Transport.CLI_JSON,
            )
        },
        expected_exit=0,
    )
    assert json.loads(stdout)["operation"] == "plugin-health"

    stdout, _ = execute(
        ["schema", "print"],
        rows={
            _producer_row(
                ArtifactKind.FORK_OPS_CONFIG_SCHEMA,
                "fork-ops schema print",
                Transport.CLI_JSON,
            )
        },
        expected_exit=0,
    )
    schema = json.loads(stdout)
    assert schema["$schema"] == "https://json-schema.org/draft/2020-12/schema"
    assert schema["properties"]["schema_version"]["const"] == "0.1"

    stdout, _ = execute(
        ["schema", "check", "--plugin-root", str(plugin_root)],
        rows={
            _consumer_row(
                ArtifactKind.FORK_OPS_CONFIG_SCHEMA,
                "fork-ops schema check (without --json)",
                Transport.CLI_TEXT,
            )
        },
        expected_exit=0,
    )
    assert all(line.startswith("ok\t") for line in stdout.splitlines())

    stdout, _ = execute(
        ["schema", "check", "--plugin-root", str(plugin_root), "--json"],
        rows={
            _consumer_row(
                ArtifactKind.FORK_OPS_CONFIG_SCHEMA,
                "fork-ops schema check --json",
                Transport.CLI_JSON,
            ),
            _producer_row(
                ArtifactKind.SCHEMA_ARTIFACT_REPORT,
                "fork-ops schema check --json",
                Transport.CLI_JSON,
            ),
        },
        expected_exit=0,
    )
    assert json.loads(stdout)["ok"] is True

    stdout = io.StringIO()
    with redirect_stdout(stdout):
        assert mcp_server.main(["--health-check"]) == 0
    assert json.loads(stdout.getvalue())["tools"] == mcp_server._REGISTERED_TOOL_IDS
    observed_rows.add(
        _producer_row(
            ArtifactKind.MCP_HEALTHCHECK,
            "fork-ops-mcp --health-check",
            Transport.CLI_JSON,
        )
    )

    inventory_rows = _inventory_rows(
        transports={Transport.CLI_JSON, Transport.CLI_TEXT}
    )
    assert observed_rows == inventory_rows
    assert invoked_leaves == _cli_leaves(build_parser())


def test_real_mcp_stdio_executes_every_payload_tool_with_exact_family_attribution(
    tmp_path: Path,
) -> None:
    config_repo = tmp_path / "mcp-configured"
    config_repo.mkdir()
    config_path = config_repo / CONFIG_RELATIVE_PATH
    config_path.parent.mkdir()
    config_path.write_text(
        create_initial_config_text(config_repo, discover_git_remotes=False),
        encoding="utf-8",
    )

    async def exercise_server() -> tuple[set[EndpointRow], set[str]]:
        observed_rows: set[EndpointRow] = set()
        called_tools: set[str] = set()
        server = StdioServerParameters(
            command=sys.executable,
            args=["-m", "fork_ops.mcp_server"],
        )

        async with stdio_client(server) as (read, write):
            async with ClientSession(read, write) as session:
                await session.initialize()
                listing = await session.list_tools()
                assert {tool.name for tool in listing.tools} == set(
                    mcp_server._REGISTERED_TOOL_IDS
                )

                async def call(
                    name: str,
                    arguments: dict[str, object],
                    *,
                    rows: set[EndpointRow],
                ) -> Any:
                    result = await session.call_tool(name, arguments)
                    assert result.isError is False, (name, result.content)
                    called_tools.add(name)
                    observed_rows.update(rows)
                    assert result.structuredContent is not None
                    return result.structuredContent

                plugin_root = Path(__file__).resolve().parents[1]
                repository_root = plugin_root.parents[1]
                plugin_health = await call(
                    "fork_ops_plugin_health",
                    {
                        "plugin_root": str(plugin_root),
                        "repo_root": str(repository_root),
                        "ui_visible": True,
                    },
                    rows={
                        _producer_row(
                            ArtifactKind.PLUGIN_HEALTH_REPORT,
                            "fork_ops_plugin_health",
                            Transport.MCP,
                        )
                    },
                )
                assert plugin_health["operation"] == "plugin-health"

                raw_config = await call(
                    "fork_ops_config_read",
                    {"repo_path": str(config_repo), "normalized": False},
                    rows={
                        _consumer_row(
                            ArtifactKind.FORK_OPS_CONFIG,
                            "fork_ops_config_read(normalized=False)",
                            Transport.MCP,
                        ),
                        _producer_row(
                            ArtifactKind.CONFIG_READ_RESULT,
                            "fork_ops_config_read(normalized=False)",
                            Transport.MCP,
                        ),
                    },
                )
                assert tomllib.loads(raw_config["raw"])["schema_version"] == "0.1"

                normalized_config = await call(
                    "fork_ops_config_read",
                    {"repo_path": str(config_repo), "normalized": True},
                    rows={
                        _producer_row(
                            ArtifactKind.FORK_OPS_CONFIG,
                            "fork_ops_config_read(normalized=True)",
                            Transport.MCP,
                        ),
                        _consumer_row(
                            ArtifactKind.FORK_OPS_CONFIG,
                            "fork_ops_config_read(normalized=True)",
                            Transport.MCP,
                        ),
                        _producer_row(
                            ArtifactKind.CONFIG_READ_RESULT,
                            "fork_ops_config_read(normalized=True)",
                            Transport.MCP,
                        ),
                    },
                )
                assert normalized_config["artifact_kind"] == "config_read_result"
                assert set(normalized_config) >= {"config", "diagnostics", "outcome"}

                validated = await call(
                    "fork_ops_config_validate",
                    {"repo_path": str(config_repo)},
                    rows={
                        _consumer_row(
                            ArtifactKind.FORK_OPS_CONFIG,
                            "fork_ops_config_validate",
                            Transport.MCP,
                        ),
                        _producer_row(
                            ArtifactKind.STATUS_REPORT,
                            "fork_ops_config_validate",
                            Transport.MCP,
                        ),
                    },
                )
                assert set(validated) >= {"capability", "diagnostics"}
                assert validated["config"]["schema_version"] == "0.1"

                capability = await call(
                    "fork_ops_capability_report",
                    {"repo_path": str(config_repo)},
                    rows={
                        _producer_row(
                            ArtifactKind.CAPABILITY_REPORT,
                            "fork_ops_capability_report",
                            Transport.MCP,
                        )
                    },
                )
                assert capability["artifact_kind"] == "capability_report"
                assert capability["schema_version"] == "1.0"
                assert capability["authority_readiness"][
                    "highest_authority_ready"
                ] == "track-aware"
                assert "highest_available" not in capability

                migration_repo = tmp_path / "mcp-migration"
                migration_repo.mkdir()
                assessment = await call(
                    "fork_ops_migration_assessment",
                    {
                        "repo_path": str(migration_repo),
                        "include_proposed_config_patch": True,
                    },
                    rows={
                        _producer_row(
                            ArtifactKind.MIGRATION_ASSESSMENT,
                            "fork_ops_migration_assessment",
                            Transport.MCP,
                        )
                    },
                )
                assert assessment["operation"] == "migration-assessment"

                preflight = await call(
                    "fork_ops_equipment_migration_preflight",
                    {"repo_path": str(migration_repo)},
                    rows={
                        _producer_row(
                            ArtifactKind.EQUIPMENT_MIGRATION_PREFLIGHT,
                            "fork_ops_equipment_migration_preflight",
                            Transport.MCP,
                        )
                    },
                )
                assert preflight["operation"] == "equipment-migration-preflight"

                plan = await call(
                    "fork_ops_migration_plan",
                    {"repo_path": str(migration_repo)},
                    rows={
                        _producer_row(
                            ArtifactKind.MIGRATION_PLAN,
                            "fork_ops_migration_plan",
                            Transport.MCP,
                        )
                    },
                )
                assert plan["operation"] == "migration-plan"
                embedded_plan_families = {
                    ArtifactKind.EMBEDDED_EQUIPMENT_MIGRATION_PREFLIGHT,
                    ArtifactKind.MIGRATION_CONFIG_PATCH,
                    ArtifactKind.MIGRATION_REVIEW_ARTIFACT,
                    ArtifactKind.EQUIPMENT_REVIEW,
                }

                generated_dry_run = await call(
                    "fork_ops_migration_dry_run",
                    {"repo_path": str(migration_repo)},
                    rows={
                        _producer_row(
                            ArtifactKind.MIGRATION_DRY_RUN,
                            "fork_ops_migration_dry_run(migration_plan=None)",
                            Transport.MCP,
                        )
                    },
                )
                assert generated_dry_run["operation"] == "migration-dry-run"

                replayed_dry_run = await call(
                    "fork_ops_migration_dry_run",
                    {"repo_path": str(migration_repo), "migration_plan": plan},
                    rows={
                        _consumer_row(
                            ArtifactKind.MIGRATION_PLAN,
                            "fork_ops_migration_dry_run(migration_plan=)",
                            Transport.MCP,
                        ),
                        _producer_row(
                            ArtifactKind.MIGRATION_DRY_RUN,
                            "fork_ops_migration_dry_run(migration_plan=)",
                            Transport.MCP,
                        ),
                    }
                    | {
                        _consumer_row(
                            kind,
                            "fork_ops_migration_dry_run(migration_plan=)",
                            Transport.MCP,
                        )
                        for kind in embedded_plan_families
                    },
                )
                assert replayed_dry_run == generated_dry_run

                execute_repo = tmp_path / "mcp-execute-generated"
                execute_repo.mkdir()
                generated_execution = await call(
                    "fork_ops_migration_execute",
                    {"repo_path": str(execute_repo)},
                    rows={
                        _producer_row(
                            ArtifactKind.MIGRATION_EXECUTION_RESULT,
                            "fork_ops_migration_execute(migration_plan=None)",
                            Transport.MCP,
                        )
                    },
                )
                assert generated_execution["operation"] == "migration-execution"

                execute_plan_repo = tmp_path / "mcp-execute-plan"
                execute_plan_repo.mkdir()
                execute_plan = generate_migration_plan(execute_plan_repo)
                replayed_execution = await call(
                    "fork_ops_migration_execute",
                    {
                        "repo_path": str(execute_plan_repo),
                        "migration_plan": execute_plan,
                    },
                    rows={
                        _consumer_row(
                            ArtifactKind.MIGRATION_PLAN,
                            "fork_ops_migration_execute(migration_plan=)",
                            Transport.MCP,
                        ),
                        _producer_row(
                            ArtifactKind.MIGRATION_EXECUTION_RESULT,
                            "fork_ops_migration_execute(migration_plan=)",
                            Transport.MCP,
                        ),
                    }
                    | {
                        _consumer_row(
                            kind,
                            "fork_ops_migration_execute(migration_plan=)",
                            Transport.MCP,
                        )
                        for kind in embedded_plan_families
                    },
                )
                assert replayed_execution["plan_operation"] == "migration-plan"

                diagnostic_inputs = (
                    (ArtifactKind.MIGRATION_ASSESSMENT, assessment),
                    (ArtifactKind.MIGRATION_PLAN, plan),
                    (ArtifactKind.MIGRATION_DRY_RUN, generated_dry_run),
                    (ArtifactKind.MIGRATION_EXECUTION_RESULT, generated_execution),
                )
                for kind, payload in diagnostic_inputs:
                    explanation = await call(
                        "fork_ops_migration_blocker_resolution",
                        {"workflow_output": payload},
                        rows={
                            _consumer_row(
                                kind,
                                "fork_ops_migration_blocker_resolution(workflow_output=)",
                                Transport.MCP,
                            ),
                            _producer_row(
                                ArtifactKind.MIGRATION_BLOCKER_EXPLANATION,
                                "fork_ops_migration_blocker_resolution(workflow_output=)",
                                Transport.MCP,
                            ),
                        },
                    )
                    assert explanation["source_operation"] == payload["operation"]

                config_patch = await call(
                    "fork_ops_migration_config_patch",
                    {"repo_path": str(migration_repo)},
                    rows={
                        _producer_row(
                            ArtifactKind.MIGRATION_CONFIG_PATCH,
                            "fork_ops_migration_config_patch",
                            Transport.MCP,
                        )
                    },
                )
                assert config_patch["operation"] == "migration-config-patch"
                assert config_patch["action"] == "create"

                schema_result = await call(
                    "fork_ops_schema",
                    {},
                    rows={
                        _producer_row(
                            ArtifactKind.FORK_OPS_CONFIG_SCHEMA,
                            "fork_ops_schema",
                            Transport.MCP,
                        )
                    },
                )
                schema = json.loads(schema_result["result"])
                assert schema["$schema"] == "https://json-schema.org/draft/2020-12/schema"

                catalog = await call(
                    "fork_ops_workflow_catalog",
                    {},
                    rows={
                        _producer_row(
                            ArtifactKind.WORKFLOW_CATALOG,
                            "fork_ops_workflow_catalog",
                            Transport.MCP,
                        )
                    },
                )
                assert catalog["operation"] == "workflow-catalog"

                inventory = await call(
                    "fork_ops_workflow_migration_inventory",
                    {},
                    rows={
                        _producer_row(
                            ArtifactKind.WORKFLOW_MIGRATION_INVENTORY,
                            "fork_ops_workflow_migration_inventory",
                            Transport.MCP,
                        )
                    },
                )
                assert inventory["operation"] == "workflow-migration-inventory"

        return observed_rows, called_tools

    observed_rows, called_tools = asyncio.run(
        asyncio.wait_for(exercise_server(), timeout=30.0)
    )
    inventory_rows = _inventory_rows(transports={Transport.MCP})
    assert observed_rows == inventory_rows
    assert called_tools == set(mcp_server._REGISTERED_TOOL_IDS)


def test_plan_consumers_enforce_the_atomic_cutover_policy() -> None:
    plan = payload_family(ArtifactKind.MIGRATION_PLAN)
    assert not hasattr(plan, "compatibility")
    assert not hasattr(LegacyPolicy, "READ_ONLY")

    replay_consumers = {
        consumer.id: consumer
        for consumer in plan.consumers
        if consumer.purpose in {ConsumerPurpose.REPLAY, ConsumerPurpose.EXECUTION}
    }
    diagnostic_consumers = {
        consumer.id: consumer
        for consumer in plan.consumers
        if consumer.purpose is ConsumerPurpose.DIAGNOSTIC
    }

    replayed_families = {
        ArtifactKind.EMBEDDED_EQUIPMENT_MIGRATION_PREFLIGHT,
        ArtifactKind.MIGRATION_CONFIG_PATCH,
        ArtifactKind.MIGRATION_PLAN,
        ArtifactKind.MIGRATION_REVIEW_ARTIFACT,
        ArtifactKind.EQUIPMENT_REVIEW,
    }
    expected_replay_ids = {
        "fork_ops.core:dry_run_migration(plan=)",
        "fork_ops.core:dry_run_migration_plan(plan)",
        "fork-ops migration dry-run --plan",
        "fork_ops_migration_dry_run(migration_plan=)",
        "fork_ops.core:execute_migration(plan=)",
        "fork_ops.core:execute_migration_plan(plan)",
        "fork-ops migration execute --plan",
        "fork_ops_migration_execute(migration_plan=)",
    }
    assert set(replay_consumers) == expected_replay_ids
    assert all(
        consumer.observed_compatibility.version_handling
        is ObservedVersionHandling.ENFORCED
        and consumer.observed_compatibility.missing_version
        is ObservedVersionOutcome.REFUSED
        and consumer.observed_compatibility.unknown_version
        is ObservedVersionOutcome.REFUSED
        and consumer.observed_compatibility.legacy_policy is LegacyPolicy.REFUSE
        and consumer.cutover_compatibility is not None
        and consumer.cutover_compatibility.current == SchemaVersion.parse("1.0")
        and consumer.cutover_compatibility.legacy_policy is LegacyPolicy.REFUSE
        and consumer.legacy_regeneration
        for consumer in replay_consumers.values()
    )
    assert set(diagnostic_consumers) == {
        "fork_ops:explain_migration_blocker(workflow_output)",
        "fork-ops migration explain-blocker --input",
        "fork_ops_migration_blocker_resolution(workflow_output=)",
        "fork_ops:render_migration_narrative(workflow_output)",
    }
    assert all(
        consumer.observed_compatibility.version_handling
        is ObservedVersionHandling.ENFORCED
        and consumer.observed_compatibility.missing_version
        is ObservedVersionOutcome.REFUSED
        and consumer.observed_compatibility.unknown_version
        is ObservedVersionOutcome.REFUSED
        for consumer in diagnostic_consumers.values()
    )
    for kind in replayed_families:
        replay_consumers = {
            consumer.id: consumer
            for consumer in payload_family(kind).consumers
            if consumer.purpose in {ConsumerPurpose.REPLAY, ConsumerPurpose.EXECUTION}
        }
        assert set(replay_consumers) == expected_replay_ids
        assert all(
            consumer.cutover_compatibility is not None
            and consumer.cutover_compatibility.current == SchemaVersion.parse("1.0")
            and consumer.cutover_compatibility.legacy_policy is LegacyPolicy.REFUSE
            and consumer.legacy_regeneration
            for consumer in replay_consumers.values()
        )

    assert all(
        consumer.observed_compatibility.legacy_policy is LegacyPolicy.IDENTIFY_ONLY
        for family in PAYLOAD_FAMILIES
        if family.external_identity is ExternalIdentity.LEGACY_UNVERSIONED
        for consumer in family.consumers
        if consumer.purpose is ConsumerPurpose.DIAGNOSTIC
    )


def test_every_versioned_artifact_consumer_enforces_its_current_identity() -> None:
    consumers = [
        (family, consumer)
        for family in PAYLOAD_FAMILIES
        if family.external_identity is ExternalIdentity.VERSIONED_ARTIFACT
        for consumer in family.consumers
    ]

    assert consumers
    assert all(
        consumer.observed_compatibility.version_handling
        is ObservedVersionHandling.ENFORCED
        and consumer.observed_compatibility.missing_version
        is ObservedVersionOutcome.REFUSED
        and consumer.observed_compatibility.unknown_version
        is ObservedVersionOutcome.REFUSED
        and consumer.observed_compatibility.legacy_policy is LegacyPolicy.REFUSE
        and consumer.cutover_compatibility is not None
        and consumer.cutover_compatibility.current == family.emitted_version
        and consumer.cutover_compatibility.supported == (family.emitted_version,)
        for family, consumer in consumers
    )


def test_inventory_identifies_every_legacy_persistence_boundary() -> None:
    persistence_paths = {
        endpoint.path
        for family in PAYLOAD_FAMILIES
        for endpoint in family.persistence
    }

    assert {
        "<operator-path>/migration-plan.json",
        "<operator-path>/migration-output.json",
        ".agents/fork-ops.toml",
        "docs/agents/fork-ops-equipment-review.toml",
        "docs/agents/fork-ops-migration-review.md",
        "docs/agents/security-exceptions.md",
        "docs/agents/security-exceptions.toml",
        "plugins/fork-ops/schema/fork-ops.schema.json",
        "plugins/fork-ops/src/fork_ops/fork-ops.schema.json",
        "plugins/fork-ops/src/fork_ops/security-exception-contract-1.0.json",
        "<validation-evidence-output>.json",
    } <= persistence_paths
    assert "<private-security-adapter>" not in persistence_paths
    assert all(
        family.persistence_gap and not family.persistence
        for family in PAYLOAD_FAMILIES
        if "adapter is not implemented" in family.persistence_gap
    )
    assert all(family.persistence or family.persistence_gap for family in PAYLOAD_FAMILIES)
    with pytest.raises(ValueError, match="persistence endpoint or an explicit persistence gap"):
        replace(
            payload_family(ArtifactKind.PLUGIN_HEALTH_REPORT),
            persistence=(),
            persistence_gap="",
        )

    assert payload_family(ArtifactKind.MIGRATION_PLAN).external_identity is (
        ExternalIdentity.VERSIONED_ARTIFACT
    )
    assert payload_family(ArtifactKind.MIGRATION_PLAN).emitted_version == (
        SchemaVersion.parse("1.0")
    )


def test_workflow_aggregate_variants_remain_versioned_and_shape_compatible() -> None:
    repository_root = Path(__file__).resolve().parents[3]
    workflow_shapes = {
        ".github/workflows/validation.yml": (
            {
                "artifact_kind",
                "schema_version",
                "outcome",
                "required",
                "advisory",
            },
            {
                "SOURCE_RESULT": "success",
                "BUILD_RESULT": "success",
                "INSTALLED_RESULT": "success",
                "ADVISORY_LINUX_RESULT": "passed",
                "ADVISORY_MACOS_RESULT": "passed",
                "ADVISORY_WINDOWS_RESULT": "passed",
            },
            "SOURCE_RESULT",
        ),
        ".github/workflows/release-validation.yml": (
            {
                "artifact_kind",
                "schema_version",
                "outcome",
                "required",
            },
            {"INSTALLED_RESULT": "success"},
            "INSTALLED_RESULT",
        ),
    }

    for path, (
        expected_keys,
        success_environment,
        required_failure_result,
    ) in workflow_shapes.items():
        workflow = (repository_root / path).read_text(encoding="utf-8")
        lines = workflow.splitlines()
        start = next(index for index, line in enumerate(lines) if line.strip() == "python - <<'PY'")
        end = next(
            index
            for index, line in enumerate(lines[start + 1 :], start=start + 1)
            if line.strip() == "PY"
        )
        script_text = textwrap.dedent("\n".join(lines[start + 1 : end]))
        script = ast.parse(script_text)
        aggregate = next(
            node
            for node in ast.walk(script)
            if isinstance(node, ast.Dict)
            and any(
                isinstance(key, ast.Constant)
                and key.value == "artifact_kind"
                and isinstance(value, ast.Constant)
                and value.value == "validation_workflow_aggregate"
                for key, value in zip(node.keys, node.values, strict=True)
            )
        )
        keys = {
            key.value
            for key in aggregate.keys
            if isinstance(key, ast.Constant) and isinstance(key.value, str)
        }
        assert keys == expected_keys
        version = next(
            value
            for key, value in zip(aggregate.keys, aggregate.values, strict=True)
            if isinstance(key, ast.Constant) and key.value == "schema_version"
        )
        assert isinstance(version, ast.Constant)
        assert version.value == "1.0"

        succeeded = subprocess.run(
            [sys.executable, "-I", "-c", script_text],
            check=False,
            capture_output=True,
            text=True,
            env=success_environment,
            timeout=_SUBPROCESS_TIMEOUT_SECONDS,
        )
        assert succeeded.returncode == 0, succeeded.stderr
        success_payload = json.loads(succeeded.stdout)
        assert set(success_payload) == expected_keys
        assert success_payload["artifact_kind"] == "validation_workflow_aggregate"
        assert success_payload["schema_version"] == "1.0"
        assert success_payload["outcome"] == "passed"

        failure_environment = dict(success_environment)
        failure_environment[required_failure_result] = "failure"
        failed = subprocess.run(
            [sys.executable, "-I", "-c", script_text],
            check=False,
            capture_output=True,
            text=True,
            env=failure_environment,
            timeout=_SUBPROCESS_TIMEOUT_SECONDS,
        )
        assert failed.returncode == 1, failed.stderr
        assert json.loads(failed.stdout)["outcome"] == "failed"

    family = payload_family(ArtifactKind.VALIDATION_WORKFLOW_AGGREGATE)
    assert family.emitted_artifact_kind == "validation_workflow_aggregate"
    assert family.emitted_version == SchemaVersion.parse("1.0")


def test_typed_security_exception_inventory_roundtrips_to_dependency_evaluation() -> None:
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

    result = evaluate_dependency_security({}, {}, inventory)

    assert inventory.contract_version == "1.0"
    assert result["security_exception_inventory"] == {
        "contract_version": "1.0",
        "finding_effect": "inventory_only",
        "unmatched_dependency_record_ids": [],
    }
    family = payload_family(ArtifactKind.SECURITY_EXCEPTION_INVENTORY)
    assert family.emitted_artifact_kind is None
    assert family.emitted_version == SchemaVersion.parse("1.0")
    assert {
        endpoint.id for endpoint in family.consumers
    } >= {"fork_ops.dependency_security:evaluate_dependency_security"}


def test_both_normalized_dependency_evidence_producers_emit_the_same_family(
    tmp_path: Path,
) -> None:
    python_versions = ("3.11", "3.12", "3.13", "3.14")
    dependency_scopes = ["runtime", "optional", "build", "test", "development"]
    scopes = {version: {"demo": dependency_scopes} for version in python_versions}
    versions = {version: {"demo": "1.0.0"} for version in python_versions}
    package_tuples = [
        {
            "python_version": version,
            "package": "demo",
            "locked_version": "1.0.0",
            "dependency_scopes": dependency_scopes,
        }
        for version in python_versions
    ]
    inventory_digest = hashlib.sha256(
        json.dumps(
            {"package_tuples": package_tuples},
            sort_keys=True,
            separators=(",", ":"),
        ).encode()
    ).hexdigest()
    candidate = {
        "commit_sha": "a" * 40,
        "source_snapshot_sha256": "b" * 64,
        "uv_lock_sha256": "c" * 64,
        "package_scope_inventory_sha256": inventory_digest,
    }
    producer = {
        "integration": "github-actions",
        "repository": "nisavid/fork-ops",
        "workflow_ref": "nisavid/fork-ops/.github/workflows/validation.yml@refs/heads/main",
        "workflow_sha": "d" * 40,
        "run_id": 1,
        "run_attempt": 1,
        "conclusion": "success",
    }
    raw = json.dumps({"vulnerabilities": [], "adverse_statuses": []})

    def runner(command: list[str], cwd: Path) -> subprocess.CompletedProcess[str]:
        return subprocess.CompletedProcess(command, 0, raw, "")

    library_evidence = collect_uv_audit_evidence(
        tmp_path,
        package_scopes_by_python=scopes,
        package_versions_by_python=versions,
        candidate_identity=candidate,
        producer_identity=producer,
        observation_epoch="e" * 64,
        runner=runner,
    )

    repository_root = Path(__file__).resolve().parents[3]
    namespace = runpy.run_path(str(repository_root / "scripts/produce_validation_evidence.py"))
    fake_uv = tmp_path / "uv"
    fake_uv.write_text(
        textwrap.dedent(
            f"""\
            #!{sys.executable}
            import json

            print(json.dumps({{"vulnerabilities": [], "adverse_statuses": []}}))
            """
        ),
        encoding="utf-8",
    )
    fake_uv.chmod(0o755)
    audit_check = namespace["_dependency_audit_matrix_check"]
    audit_check.__globals__["_TRUSTED_UV_EXECUTABLE"] = fake_uv
    audit_check.__globals__["_TRUSTED_UV_SHA256"] = hashlib.sha256(
        fake_uv.read_bytes()
    ).hexdigest()
    script_evidence_check = audit_check(
        repository_root,
        sys.executable,
        scopes,
        versions,
        candidate,
        producer,
    )
    script_evidence = script_evidence_check["evidence"]

    for evidence in (library_evidence, script_evidence):
        assert evidence["artifact_kind"] == "normalized_dependency_vulnerability_evidence"
        assert evidence["schema_version"] == "2.0"
        assert evidence["source"] == "osv"
        assert evidence["status"] == "available"
        assert evidence["advisories"] == []
    producers = payload_family(
        ArtifactKind.NORMALIZED_DEPENDENCY_VULNERABILITY_EVIDENCE
    ).producers
    assert {endpoint.id for endpoint in producers} == {
        "fork_ops.dependency_security:collect_uv_audit_evidence",
        "scripts/produce_validation_evidence.py:_dependency_audit_matrix_check",
    }


def test_authority_migration_projection_is_shape_checked_then_refused() -> None:
    projection = {
        "artifact_kind": "security_exception_authority_migration",
        "schema_version": "1.0",
        "from_contract_version": "1.0",
        "target_contract_version": "2.0",
        "from_login": "nisavid",
        "from_database_id": 576874,
        "from_node_id": "MDQ6VXNlcjU3Njg3NA==",
        "to_login": "successor",
        "to_database_id": 1,
        "to_node_id": "U_successor",
        "status": "unsupported_by_contract_1.0",
    }

    with pytest.raises(SecurityExceptionValidationError, match="contract 2.0"):
        validate_authority_migration_projection(projection)

    family = payload_family(ArtifactKind.SECURITY_EXCEPTION_AUTHORITY_MIGRATION)
    assert family.emitted_artifact_kind == "security_exception_authority_migration"
    assert family.emitted_version == SchemaVersion.parse("1.0")


def test_python_payload_endpoints_execute_with_exact_role_attribution(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    plugin_root = Path(__file__).resolve().parents[1]
    repo_root = plugin_root.parents[1]
    plan = generate_migration_plan(tmp_path)
    dry_run = dry_run_migration_plan(plan)
    execution = execute_migration_plan(plan, tmp_path)
    assert dry_run_migration(tmp_path)["operation"] == "migration-dry-run"
    assert dry_run_migration(tmp_path, plan=plan) == dry_run
    assert execute_migration(tmp_path)["operation"] == "migration-execution"
    assert execute_migration(tmp_path, plan=plan) == execution
    init_repo = tmp_path / "config-init"
    init_repo.mkdir()
    config_repo = tmp_path / "configured"
    config_repo.mkdir()
    config_text = create_initial_config_text(config_repo, discover_git_remotes=False)
    config_path = config_repo / CONFIG_RELATIVE_PATH
    config_path.parent.mkdir()
    config_path.write_text(config_text, encoding="utf-8")
    config = load_config(config_repo)
    assert schema_diagnostics(config) == []
    assert json.loads(schema_json())["$schema"].endswith("2020-12/schema")
    assert build_status_report(config_repo)["config"]["schema_version"] == "0.1"
    contracts = workflow_contracts()
    assert contracts
    assert all(contract.id and contract.entrypoints for contract in contracts)
    preflight = build_equipment_migration_preflight(
        tmp_path,
        source_roots=(tmp_path,),
    )
    assert core_module._equipment_review_record(preflight)["artifact_kind"] == (
        "equipment_review"
    )
    assert core_module._migration_review_artifact(plan["migration_map"])["status"] == (
        "proposed"
    )
    assessment = assess_migration(tmp_path)
    assessment_with_patch = assess_migration(
        tmp_path,
        include_proposed_config_patch=True,
    )
    assert assessment_with_patch["proposed_config_patch"]["action"] == "create"
    monkeypatch.setattr(Path, "home", lambda: tmp_path)
    monkeypatch.setenv("FORK_OPS_FULL_BREADTH_REPO_BASE", str(tmp_path))
    monkeypatch.setenv("FORK_OPS_FULL_BREADTH_MAINTAINED_REPOS", "")
    monkeypatch.setenv("FORK_OPS_FULL_BREADTH_ADJACENT_REPOS", "")
    full_breadth_plan = generate_migration_plan(tmp_path, scan_profile="full-breadth")
    assert full_breadth_plan["scan_accounting"]["workflow_inventory"] is not None
    workflow_outputs = (assessment, plan, dry_run, execution)
    for workflow_output in workflow_outputs:
        assert explain_migration_blocker(workflow_output)["source_operation"] == (
            workflow_output["operation"]
        )
        assert fork_ops.render_migration_narrative(workflow_output)["kind"] == (
            "operator-readable-narrative"
        )
    blocker_explanation = explain_migration_blocker(plan)
    assert fork_ops.render_migration_narrative(blocker_explanation)["workflow_id"] == (
            "migration-blocker-explanation"
    )

    payloads = {
        ArtifactKind.PLUGIN_HEALTH_REPORT: build_plugin_health_report(
            plugin_root,
            repo_root=repo_root,
            ui_visible=True,
        ),
        ArtifactKind.CONFIG_READ_RESULT: mcp_server.fork_ops_config_read(
            str(tmp_path),
            normalized=False,
        ),
        ArtifactKind.STATUS_REPORT: build_status_report(tmp_path),
        ArtifactKind.CAPABILITY_REPORT: capability_report({}),
        ArtifactKind.CONFIG_INITIALIZATION_RESULT: initialize_config(init_repo),
        ArtifactKind.MIGRATION_ASSESSMENT: assessment,
        ArtifactKind.EQUIPMENT_MIGRATION_PREFLIGHT: (
            preflight
        ),
        ArtifactKind.EMBEDDED_EQUIPMENT_MIGRATION_PREFLIGHT: plan[
            "equipment_migration_preflight"
        ],
        ArtifactKind.MIGRATION_CONFIG_PATCH: propose_migration_config_patch(tmp_path),
        ArtifactKind.MIGRATION_PLAN: plan,
        ArtifactKind.MIGRATION_DRY_RUN: dry_run,
        ArtifactKind.MIGRATION_EXECUTION_RESULT: execution,
        ArtifactKind.MIGRATION_BLOCKER_EXPLANATION: blocker_explanation,
        ArtifactKind.MIGRATION_NARRATIVE: fork_ops.render_migration_narrative(plan),
        ArtifactKind.MIGRATION_REVIEW_ARTIFACT: plan["migration_review_artifact"],
        ArtifactKind.EQUIPMENT_REVIEW: plan["equipment_review_record"],
        ArtifactKind.WORKFLOW_CATALOG: workflow_catalog(),
        ArtifactKind.WORKFLOW_MIGRATION_INVENTORY: (
            build_workflow_migration_inventory([])
        ),
        ArtifactKind.SCHEMA_ARTIFACT_REPORT: schema_artifact_report(plugin_root),
        ArtifactKind.MCP_HEALTHCHECK: mcp_server.mcp_healthcheck(),
    }
    operation_root = {
        "artifact_kind",
        "schema_version",
        "operation",
        "outcome",
        "plan_executability",
        "mutation_state",
        "diagnostics",
        "evidence",
    }
    nested_artifact_kinds = {
        ArtifactKind.MIGRATION_NARRATIVE,
        ArtifactKind.MIGRATION_REVIEW_ARTIFACT,
        ArtifactKind.EQUIPMENT_REVIEW,
    }
    assert payloads.keys() == {
        ArtifactKind.PLUGIN_HEALTH_REPORT,
        ArtifactKind.CONFIG_READ_RESULT,
        ArtifactKind.STATUS_REPORT,
        ArtifactKind.CAPABILITY_REPORT,
        ArtifactKind.CONFIG_INITIALIZATION_RESULT,
        ArtifactKind.MIGRATION_ASSESSMENT,
        ArtifactKind.EQUIPMENT_MIGRATION_PREFLIGHT,
        ArtifactKind.EMBEDDED_EQUIPMENT_MIGRATION_PREFLIGHT,
        ArtifactKind.MIGRATION_CONFIG_PATCH,
        ArtifactKind.MIGRATION_PLAN,
        ArtifactKind.MIGRATION_DRY_RUN,
        ArtifactKind.MIGRATION_EXECUTION_RESULT,
        ArtifactKind.MIGRATION_BLOCKER_EXPLANATION,
        ArtifactKind.MIGRATION_NARRATIVE,
        ArtifactKind.MIGRATION_REVIEW_ARTIFACT,
        ArtifactKind.EQUIPMENT_REVIEW,
        ArtifactKind.WORKFLOW_CATALOG,
        ArtifactKind.WORKFLOW_MIGRATION_INVENTORY,
        ArtifactKind.SCHEMA_ARTIFACT_REPORT,
        ArtifactKind.MCP_HEALTHCHECK,
    }
    for kind, payload in payloads.items():
        assert payload["artifact_kind"] == kind.value
        assert payload["schema_version"] == "1.0"
        if kind not in nested_artifact_kinds:
            assert operation_root <= set(payload)

    producer_edges = (
        (ArtifactKind.FORK_OPS_CONFIG, "fork_ops.core:create_initial_config_text"),
        (ArtifactKind.FORK_OPS_CONFIG, "fork_ops.core:propose_migration_config_patch"),
        (ArtifactKind.FORK_OPS_CONFIG_SCHEMA, "fork_ops.core:schema_json"),
        (ArtifactKind.PLUGIN_HEALTH_REPORT, "fork_ops.core:build_plugin_health_report"),
        (ArtifactKind.STATUS_REPORT, "fork_ops.core:build_status_report"),
        (ArtifactKind.CAPABILITY_REPORT, "fork_ops.core:capability_report"),
        (ArtifactKind.CONFIG_INITIALIZATION_RESULT, "fork_ops.core:initialize_config"),
        (ArtifactKind.MIGRATION_ASSESSMENT, "fork_ops.core:assess_migration"),
        (
            ArtifactKind.EQUIPMENT_MIGRATION_PREFLIGHT,
            "fork_ops.core:build_equipment_migration_preflight",
        ),
        (
            ArtifactKind.EMBEDDED_EQUIPMENT_MIGRATION_PREFLIGHT,
            "fork_ops.core:_equipment_migration_preflight",
        ),
        (ArtifactKind.MIGRATION_CONFIG_PATCH, "fork_ops.core:propose_migration_config_patch"),
        (ArtifactKind.MIGRATION_PLAN, "fork_ops.core:generate_migration_plan"),
        (ArtifactKind.MIGRATION_DRY_RUN, "fork_ops.core:dry_run_migration(plan=None)"),
        (ArtifactKind.MIGRATION_DRY_RUN, "fork_ops.core:dry_run_migration(plan=)"),
        (ArtifactKind.MIGRATION_DRY_RUN, "fork_ops.core:dry_run_migration_plan"),
        (
            ArtifactKind.MIGRATION_EXECUTION_RESULT,
            "fork_ops.core:execute_migration(plan=None)",
        ),
        (
            ArtifactKind.MIGRATION_EXECUTION_RESULT,
            "fork_ops.core:execute_migration(plan=)",
        ),
        (
            ArtifactKind.MIGRATION_EXECUTION_RESULT,
            "fork_ops.core:execute_migration_plan",
        ),
        (
            ArtifactKind.MIGRATION_BLOCKER_EXPLANATION,
            "fork_ops.core:explain_migration_blocker",
        ),
        (
            ArtifactKind.MIGRATION_NARRATIVE,
            "fork_ops:render_migration_narrative(workflow_output)",
        ),
        (
            ArtifactKind.MIGRATION_REVIEW_ARTIFACT,
            "fork_ops.core:_migration_review_artifact",
        ),
        (ArtifactKind.EQUIPMENT_REVIEW, "fork_ops.core:_equipment_review_record"),
        (
            ArtifactKind.EQUIPMENT_REVIEW,
            "fork_ops.core:build_equipment_migration_preflight(equipment_review_record)",
        ),
        (ArtifactKind.WORKFLOW_CATALOG, "fork_ops.workflow_catalog:workflow_catalog"),
        (
            ArtifactKind.WORKFLOW_CONTRACT_SET,
            "fork_ops.workflow_catalog:workflow_contracts",
        ),
        (
            ArtifactKind.WORKFLOW_MIGRATION_INVENTORY,
            "fork_ops.core:build_workflow_migration_inventory",
        ),
        (ArtifactKind.SCHEMA_ARTIFACT_REPORT, "fork_ops.core:schema_artifact_report"),
        (ArtifactKind.MCP_HEALTHCHECK, "fork_ops.mcp_server:mcp_healthcheck"),
    )
    consumer_edges = (
        (ArtifactKind.FORK_OPS_CONFIG, "fork_ops.core:load_config"),
        (ArtifactKind.FORK_OPS_CONFIG, "fork_ops.core:build_status_report"),
        (ArtifactKind.FORK_OPS_CONFIG_SCHEMA, "fork_ops.schema:schema_diagnostics"),
        (ArtifactKind.FORK_OPS_CONFIG_SCHEMA, "fork_ops.core:schema_artifact_report"),
        (ArtifactKind.CAPABILITY_REPORT, "fork_ops.core:build_status_report"),
        (
            ArtifactKind.MIGRATION_ASSESSMENT,
            "fork_ops:explain_migration_blocker(workflow_output)",
        ),
        (
            ArtifactKind.MIGRATION_ASSESSMENT,
            "fork_ops:render_migration_narrative(workflow_output)",
        ),
        (
            ArtifactKind.EMBEDDED_EQUIPMENT_MIGRATION_PREFLIGHT,
            "fork_ops.core:build_equipment_migration_preflight(embedded_preflight)",
        ),
        (
            ArtifactKind.EMBEDDED_EQUIPMENT_MIGRATION_PREFLIGHT,
            "fork_ops.core:generate_migration_plan(embedded_preflight)",
        ),
        (ArtifactKind.MIGRATION_CONFIG_PATCH, "fork_ops.core:generate_migration_plan"),
        (
            ArtifactKind.MIGRATION_CONFIG_PATCH,
            "fork_ops.core:assess_migration(include_proposed_config_patch=True)",
        ),
        (
            ArtifactKind.MIGRATION_CONFIG_PATCH,
            "fork_ops.core:build_equipment_migration_preflight(proposed_config_patch)",
        ),
        (
            ArtifactKind.MIGRATION_PLAN,
            "fork_ops:explain_migration_blocker(workflow_output)",
        ),
        (
            ArtifactKind.MIGRATION_PLAN,
            "fork_ops:render_migration_narrative(workflow_output)",
        ),
        (
            ArtifactKind.MIGRATION_DRY_RUN,
            "fork_ops:explain_migration_blocker(workflow_output)",
        ),
        (
            ArtifactKind.MIGRATION_DRY_RUN,
            "fork_ops:render_migration_narrative(workflow_output)",
        ),
        (
            ArtifactKind.MIGRATION_EXECUTION_RESULT,
            "fork_ops:explain_migration_blocker(workflow_output)",
        ),
        (
            ArtifactKind.MIGRATION_EXECUTION_RESULT,
            "fork_ops:render_migration_narrative(workflow_output)",
        ),
        (
            ArtifactKind.MIGRATION_BLOCKER_EXPLANATION,
            "fork_ops:render_migration_narrative(workflow_output)",
        ),
        (ArtifactKind.EQUIPMENT_REVIEW, "fork_ops.core:_equipment_review_record_report"),
        (ArtifactKind.EQUIPMENT_REVIEW, "fork_ops.core:build_status_report"),
        (ArtifactKind.WORKFLOW_CATALOG, "fork_ops.core:_cli_execution_check"),
        (
            ArtifactKind.WORKFLOW_CONTRACT_SET,
            "fork_ops.core:build_workflow_migration_inventory",
        ),
        (
            ArtifactKind.WORKFLOW_CONTRACT_SET,
            "fork_ops.core:explain_migration_blocker via _workflow_contract_dict",
        ),
        (
            ArtifactKind.WORKFLOW_MIGRATION_INVENTORY,
            "fork_ops.core:generate_migration_plan",
        ),
        (
            ArtifactKind.WORKFLOW_MIGRATION_INVENTORY,
            "fork_ops.core:build_equipment_migration_preflight(workflow_inventory)",
        ),
        (ArtifactKind.MCP_HEALTHCHECK, "fork_ops.core:build_plugin_health_report"),
    )
    observed_rows = {
        _producer_row(kind, endpoint, Transport.PYTHON)
        for kind, endpoint in producer_edges
    } | {
        _consumer_row(kind, endpoint, Transport.PYTHON)
        for kind, endpoint in consumer_edges
    }
    assert observed_rows == _inventory_rows_characterized_by(_PYTHON_ENDPOINT_NODE)


def test_canonical_replay_and_persisted_payloads_are_exact(
    tmp_path: Path,
) -> None:
    plan = generate_migration_plan(tmp_path)
    assert plan["artifact_kind"] == "migration_plan"
    assert plan["schema_version"] == "1.0"

    plan_path = tmp_path / "migration-plan.json"
    plan_path.write_text(json.dumps(plan), encoding="utf-8")
    persisted_plan = json.loads(plan_path.read_text(encoding="utf-8"))
    assert persisted_plan == plan

    python_wrapper_dry_run = dry_run_migration(tmp_path, plan=persisted_plan)
    python_plan_dry_run = dry_run_migration_plan(persisted_plan)
    output = io.StringIO()
    with redirect_stdout(output):
        exit_code = cli_main(["migration", "dry-run", "--plan", str(plan_path)])
    cli_dry_run = json.loads(output.getvalue())
    mcp_dry_run = fork_ops_migration_dry_run(
        str(tmp_path),
        migration_plan=persisted_plan,
    )

    assert exit_code == 0
    assert cli_dry_run == mcp_dry_run == python_wrapper_dry_run == python_plan_dry_run

    python_plan_execution = execute_migration_plan(persisted_plan, tmp_path)
    python_wrapper_execution = execute_migration(tmp_path, plan=persisted_plan)
    output = io.StringIO()
    with redirect_stdout(output):
        execute_exit_code = cli_main(
            [
                "migration",
                "execute",
                "--repo",
                str(tmp_path),
                "--plan",
                str(plan_path),
            ]
        )
    cli_execution = json.loads(output.getvalue())
    mcp_execution = fork_ops_migration_execute(
        str(tmp_path),
        migration_plan=persisted_plan,
    )
    assert execute_exit_code == 1
    assert (
        cli_execution
        == mcp_execution
        == python_wrapper_execution
        == python_plan_execution
    )

    legacy_plan = json.loads(json.dumps(plan))
    legacy_plan.pop("artifact_kind")
    legacy_plan.pop("schema_version")
    legacy_results = (
        dry_run_migration(tmp_path, plan=legacy_plan),
        dry_run_migration_plan(legacy_plan),
        execute_migration(tmp_path, plan=legacy_plan),
        execute_migration_plan(legacy_plan, tmp_path),
    )
    assert all(result["outcome"] == "refused" for result in legacy_results)
    assert all(
        result["diagnostics"][0]["code"] == "unsupported_artifact_version"
        for result in legacy_results
    )

    workflow_outputs = (
        assess_migration(tmp_path),
        persisted_plan,
        python_plan_dry_run,
        python_plan_execution,
    )
    for index, workflow_output in enumerate(workflow_outputs):
        explanation = explain_migration_blocker(workflow_output)
        narrative = fork_ops.render_migration_narrative(workflow_output)
        assert explanation["source_operation"] == workflow_output["operation"]
        assert narrative["kind"] == "operator-readable-narrative"
        output_path = tmp_path / f"migration-output-{index}.json"
        output_path.write_text(json.dumps(workflow_output), encoding="utf-8")
        assert json.loads(output_path.read_text(encoding="utf-8")) == workflow_output

    config_text = create_initial_config_text(tmp_path, discover_git_remotes=False)
    config_path = tmp_path / CONFIG_RELATIVE_PATH
    config_path.parent.mkdir(exist_ok=True)
    config_path.write_text(config_text, encoding="utf-8")
    assert load_config(tmp_path)["schema_version"] == "0.1"

    equipment_toml = plan["equipment_review_record"]["toml"]
    equipment_path = tmp_path / "docs/agents/fork-ops-equipment-review.toml"
    equipment_path.parent.mkdir(parents=True)
    equipment_path.write_text(equipment_toml, encoding="utf-8")
    persisted_review = build_status_report(tmp_path)["capability"]["equipment_review"]
    assert persisted_review["artifact_kind"] == "equipment_review"
    assert persisted_review["schema_version"] == "1.0"

    review_artifact = plan["migration_review_artifact"]
    review_path = tmp_path / review_artifact["target_path"]
    review_path.parent.mkdir(parents=True, exist_ok=True)
    review_path.write_text(review_artifact["markdown"], encoding="utf-8")
    assert review_path.read_text(encoding="utf-8") == review_artifact["markdown"]

    repository_root = Path(__file__).resolve().parents[3]
    runtime_schema = json.loads(mcp_server.fork_ops_schema())
    assert json.loads(
        (repository_root / "plugins/fork-ops/schema/fork-ops.schema.json").read_text(
            encoding="utf-8"
        )
    ) == runtime_schema
    assert json.loads(
        (
            repository_root
            / "plugins/fork-ops/src/fork_ops/fork-ops.schema.json"
        ).read_text(encoding="utf-8")
    ) == runtime_schema
    ledger = tomllib.loads(
        (repository_root / "docs/agents/security-exceptions.toml").read_text(
            encoding="utf-8"
        )
    )
    contract = json.loads(
        (
            repository_root
            / "plugins/fork-ops/src/fork_ops/security-exception-contract-1.0.json"
        ).read_text(encoding="utf-8")
    )
    assert ledger["artifact_kind"] == "security_exception_ledger"
    assert ledger["schema_version"] == "1.0"
    assert contract["artifact_kind"] == "security_exception_contract"
    assert contract["contract_version"] == "1.0"

    replayed_families = {
        ArtifactKind.EMBEDDED_EQUIPMENT_MIGRATION_PREFLIGHT,
        ArtifactKind.MIGRATION_CONFIG_PATCH,
        ArtifactKind.MIGRATION_PLAN,
        ArtifactKind.MIGRATION_REVIEW_ARTIFACT,
        ArtifactKind.EQUIPMENT_REVIEW,
    }
    python_replay_consumers = {
        "fork_ops.core:dry_run_migration(plan=)",
        "fork_ops.core:dry_run_migration_plan(plan)",
        "fork_ops.core:execute_migration(plan=)",
        "fork_ops.core:execute_migration_plan(plan)",
    }
    observed_rows = {
        _consumer_row(kind, endpoint, Transport.PYTHON)
        for kind in replayed_families
        for endpoint in python_replay_consumers
    }
    observed_rows.update(
        {
            _persistence_row(
                ArtifactKind.FORK_OPS_CONFIG,
                ".agents/fork-ops.toml",
                Transport.TOML_FILE,
                PersistenceRole.BOTH,
            ),
            _persistence_row(
                ArtifactKind.FORK_OPS_CONFIG_SCHEMA,
                "plugins/fork-ops/schema/fork-ops.schema.json",
                Transport.JSON_FILE,
                PersistenceRole.BOTH,
            ),
            _persistence_row(
                ArtifactKind.FORK_OPS_CONFIG_SCHEMA,
                "plugins/fork-ops/src/fork_ops/fork-ops.schema.json",
                Transport.PACKAGE_RESOURCE,
                PersistenceRole.BOTH,
            ),
            _persistence_row(
                ArtifactKind.MIGRATION_ASSESSMENT,
                "<operator-path>/migration-output.json",
                Transport.JSON_FILE,
                PersistenceRole.CALLER_MANAGED,
            ),
            _persistence_row(
                ArtifactKind.MIGRATION_PLAN,
                "<operator-path>/migration-plan.json",
                Transport.JSON_FILE,
                PersistenceRole.CALLER_MANAGED,
            ),
            _persistence_row(
                ArtifactKind.MIGRATION_PLAN,
                "<operator-path>/migration-output.json",
                Transport.JSON_FILE,
                PersistenceRole.CALLER_MANAGED,
            ),
            _persistence_row(
                ArtifactKind.MIGRATION_DRY_RUN,
                "<operator-path>/migration-output.json",
                Transport.JSON_FILE,
                PersistenceRole.CALLER_MANAGED,
            ),
            _persistence_row(
                ArtifactKind.MIGRATION_EXECUTION_RESULT,
                "<operator-path>/migration-output.json",
                Transport.JSON_FILE,
                PersistenceRole.CALLER_MANAGED,
            ),
            _persistence_row(
                ArtifactKind.MIGRATION_REVIEW_ARTIFACT,
                "docs/agents/fork-ops-migration-review.md",
                Transport.MARKDOWN_FILE,
                PersistenceRole.PROPOSED,
            ),
            _persistence_row(
                ArtifactKind.EQUIPMENT_REVIEW,
                "docs/agents/fork-ops-equipment-review.toml",
                Transport.TOML_FILE,
                PersistenceRole.BOTH,
            ),
        }
    )
    assert observed_rows == _inventory_rows_characterized_by(_PERSISTENCE_ENDPOINT_NODE)
