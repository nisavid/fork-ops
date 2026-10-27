from __future__ import annotations

import copy
import importlib
import json
from pathlib import Path
from typing import Any

import pytest
from jsonschema import Draft202012Validator

from fork_ops import core
from fork_ops.schema import schema_diagnostics

fixtures = importlib.import_module("test_core")
TRACK_AWARE_CONFIG: str = fixtures.TRACK_AWARE_CONFIG
UPSTREAM_REF_PRESSURE_TEXT: str = fixtures.UPSTREAM_REF_PRESSURE_TEXT

FIELDS = {
    "repository": ("host", "owner", "name", "default_branch"),
    "fork_remotes": ("name",),
    "upstreams": ("id", "remote"),
    "release_channels": ("id", "upstream"),
    "upstream_tracks": (
        "id",
        "upstream",
        "ref",
        "source",
        "source_ref",
        "tracking_ref",
        "local_branch",
        "owner_remote",
    ),
    "local_surfaces": ("path",),
    "sync_policy": ("default_sync_baseline", "default_sync_ref", "fork_sync_start_ref"),
    "authority": ("source_order",),
}


@pytest.mark.parametrize("section,key", [(s, k) for s, keys in FIELDS.items() for k in keys])
@pytest.mark.parametrize("blank", ["", " \t\n", "\u2003\u00a0"])
def test_blank_authority_rejected_by_both_schemas_and_direct_capability(
    section: str,
    key: str,
    blank: str,
) -> None:
    config = core.normalize_config(core.parse_config_text(TRACK_AWARE_CONFIG))
    record = config[section]
    if isinstance(record, list):
        record = record[0]
    record[key] = [blank] if key == "source_order" else blank
    plugin = Path(__file__).resolve().parents[1]
    for path in ("schema/fork-ops.schema.json", "src/fork_ops/fork-ops.schema.json"):
        assert not Draft202012Validator(json.loads((plugin / path).read_text())).is_valid(config)
    diagnostics = schema_diagnostics(config)
    assert diagnostics
    for supplied in (None, diagnostics):
        result = core.capability_report(config, supplied)
        assert result["authority_readiness"]["levels"]["track-aware"]["ready"] is False
    result = core.capability_report(config, [])
    assert result["authority_readiness"]["levels"]["track-aware"]["ready"] is False


def test_manual_authority_and_extensions_remain_unchanged() -> None:
    config = core.normalize_config(core.parse_config_text(TRACK_AWARE_CONFIG))
    config["release_channels"][0].update(kind="manual", notes="")
    config["upstream_tracks"][0].update(source_type="manual", source="Reviewed manual policy")
    config["extension"] = {"id": "", "ref": "", "path": ""}
    original = copy.deepcopy(config)
    assert not schema_diagnostics(config)
    assert core.capability_report(config)["authority_readiness"]["levels"]["track-aware"]["ready"]
    assert config == original


@pytest.mark.parametrize("channel", [{}, {"id": "stable", "upstream": "unknown", "kind": "manual"}])
def test_direct_capability_checks_shapes_and_references(channel: dict[str, Any]) -> None:
    config = core.normalize_config(core.parse_config_text(TRACK_AWARE_CONFIG))
    config["release_channels"] = [channel]
    config["upstream_tracks"][0]["source_type"] = "manual"
    assert (
        core.capability_report(config)["authority_readiness"]["levels"]["track-aware"]["ready"]
        is False
    )


@pytest.mark.parametrize("blank", ["", " \t\n", "\u2003"])
def test_migration_refuses_blank_authority_before_write(tmp_path: Path, blank: str) -> None:
    source = tmp_path / ".agents/skills/working-with-upstream-refs/SKILL.md"
    source.parent.mkdir(parents=True)
    source.write_text(UPSTREAM_REF_PRESSURE_TEXT)
    plan = core.generate_migration_plan(tmp_path)
    config = core.parse_config_text(TRACK_AWARE_CONFIG)
    config["release_channels"][0]["id"] = blank
    config["upstream_tracks"][0].update(id=blank, ref=blank, source=blank, source_type="manual")
    plan["proposed_config_patch"].update(
        config=config, toml=core._toml_dumps(config), diagnostics=[]
    )
    assert not core.dry_run_migration_plan(plan)["can_execute"]
    result = core.execute_migration_plan(plan, tmp_path)
    assert result["mutation_state"] == "not_started"
    assert "migration_execution.config_diagnostics_failed" in {
        x["code"] for x in result["blockers"]
    }
    assert not (tmp_path / core.CONFIG_RELATIVE_PATH).exists()
    assert source.read_text() == UPSTREAM_REF_PRESSURE_TEXT


def test_post_write_verification_rejects_blank_authority(tmp_path: Path) -> None:
    source = tmp_path / ".agents/skills/working-with-upstream-refs/SKILL.md"
    source.parent.mkdir(parents=True)
    source.write_text(UPSTREAM_REF_PRESSURE_TEXT)
    preview = core.dry_run_migration_plan(core.generate_migration_plan(tmp_path))
    config = core.parse_config_text(TRACK_AWARE_CONFIG)
    config["upstream_tracks"][0]["ref"] = "\u2003"
    (tmp_path / core.CONFIG_RELATIVE_PATH).write_text(core._toml_dumps(config))
    bound = core._bind_repository(tmp_path)
    try:
        verification, blockers = core._verify_migration_execution(bound, preview, [])
    finally:
        bound.close()
    assert verification and all(x["status"] == "failed" for x in verification)
    assert "migration_execution.verification_failed" in {x["code"] for x in blockers}
