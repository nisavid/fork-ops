from __future__ import annotations

import hashlib
import io
import json
import os
import subprocess
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from typing import Any, get_args
from unittest.mock import patch

from fork_ops.cli import main as cli_main
from fork_ops.core import (
    CONFIG_RELATIVE_PATH,
    ForkOpsError,
    assess_migration,
    build_status_report,
    build_workflow_migration_inventory,
    dry_run_migration,
    dry_run_migration_plan,
    execute_migration,
    execute_migration_plan,
    generate_migration_plan,
    normalize_config,
    parse_config_text,
    propose_migration_config_patch,
    schema_artifact_report,
    schema_json,
)
from fork_ops.mcp_server import (
    fork_ops_capability_report,
    fork_ops_config_read,
    fork_ops_config_validate,
    fork_ops_migration_dry_run,
    fork_ops_migration_execute,
    fork_ops_schema,
    fork_ops_workflow_catalog,
    fork_ops_workflow_migration_inventory,
)
from fork_ops.schema import schema_diagnostics
from fork_ops.workflow_catalog import ImplementationStatus, WorkflowContract, workflow_catalog

TRACK_AWARE_CONFIG = """schema_version = "0.1"

[repository]
host = "github"
owner = "nisavid"
name = "lemonade"
default_branch = "main"

[authority]
source_order = ["fork-ops-config", "repo-docs", "upstream-docs", "live-state"]

[change_targets]
default = "fork"

[[fork_remotes]]
name = "origin"
url = "https://github.com/nisavid/lemonade.git"
push = true

[[upstreams]]
id = "lemonade"
remote = "upstream"
url = "https://github.com/lemonade-sdk/lemonade.git"
push = false

[[release_channels]]
id = "stable"
upstream = "lemonade"
kind = "github_latest_release"

[[upstream_tracks]]
id = "upstream-stable"
upstream = "lemonade"
ref = "refs/remotes/origin/upstream-stable"
source_type = "release_channel"
source = "stable"

[[local_surfaces]]
kind = "config"
path = ".agents/fork-ops.toml"
domain = "identity"
portability_hint = "fork-specific"
"""

IDENTIFIED_CONFIG = """schema_version = "0.1"

[repository]
host = "github"
owner = "nisavid"
name = "lemonade"
default_branch = "main"

[authority]
source_order = ["fork-ops-config"]

[change_targets]
default = "fork"

[[fork_remotes]]
name = "origin"
url = "https://github.com/nisavid/lemonade.git"
push = true

[[upstreams]]
id = "lemonade"
remote = "upstream"
url = "https://github.com/lemonade-sdk/lemonade.git"
push = false
"""


def _entrypoint_ids(workflow: dict[str, Any]) -> set[str]:
    return {entrypoint["id"] for entrypoint in workflow["entrypoints"]}


class ForkOpsCoreTests(unittest.TestCase):
    def test_workflow_catalog_defines_intent_level_contracts(self) -> None:
        catalog = workflow_catalog()

        self.assertEqual(catalog["operation"], "workflow-catalog")
        workflows = {workflow["id"]: workflow for workflow in catalog["workflows"]}
        expected_contracts = {
            "operator-onboarding": ("plugin-health", "next-slice", False),
            "fork-authority-migration": ("identified", "current", True),
            "workflow-migration-inventory": ("plugin-health", "diagnostic-only", True),
            "authority-source-routing": ("identified", "diagnostic-only", True),
            "upstream-status-assessment": ("track-aware", "diagnostic-only", True),
            "upstream-sync-planning": ("sync-ready", "next-slice", False),
            "guarded-sync-execution": ("sync-ready", "planned", False),
            "carried-divergence-review": ("sync-ready", "planned", False),
            "review-preparation": ("review-ready", "planned", False),
            "publication-closeout": ("review-ready", "planned", False),
            "blocker-resolution": ("identified", "next-slice", False),
        }
        self.assertEqual(set(workflows), set(expected_contracts))
        self.assertEqual(len(catalog["workflows"]), len(workflows))

        for workflow_id, (capability_gate, status, available) in expected_contracts.items():
            workflow = workflows[workflow_id]
            self.assertEqual(workflow["capability_gate"], capability_gate)
            self.assertEqual(workflow["implementation_status"], status)
            self.assertEqual(workflow["available"], available)
            self.assertTrue(workflow["operator_intent"])
            self.assertTrue(workflow["trigger_phrases"])
            self.assertTrue(workflow["evidence_expectations"])
            self.assertTrue(workflow["refusal_behavior"])
            self.assertTrue(workflow["handoff_expectations"])
            self.assertTrue(workflow["closeout_criteria"])
            if not available:
                self.assertIn("fork-ops workflow catalog", _entrypoint_ids(workflow))
                self.assertIn("fork_ops_workflow_catalog", _entrypoint_ids(workflow))

        migration = workflows["fork-authority-migration"]
        self.assertIn("map an existing maintained fork", migration["operator_intent"].lower())
        self.assertIn("fork authority migration", migration["trigger_phrases"])
        self.assertLessEqual(
            {
                "fork-ops migration assess",
                "fork-ops migration plan",
                "fork-ops migration dry-run",
                "fork-ops migration execute",
                "fork-ops migration propose-config",
                "fork_ops_migration_assessment",
                "fork_ops_migration_plan",
                "fork_ops_migration_dry_run",
                "fork_ops_migration_execute",
                "fork_ops_migration_config_patch",
            },
            _entrypoint_ids(migration),
        )
        self.assertIn("source material disposition", " ".join(migration["evidence_expectations"]))

        workflow_inventory = workflows["workflow-migration-inventory"]
        self.assertIn("workflow migration inventory", workflow_inventory["trigger_phrases"])
        self.assertIn("fork-ops workflow inventory", _entrypoint_ids(workflow_inventory))
        self.assertIn(
            "fork_ops_workflow_migration_inventory",
            _entrypoint_ids(workflow_inventory),
        )
        self.assertIn(
            "backlog candidates",
            " ".join(workflow_inventory["evidence_expectations"]),
        )

        guarded_sync = workflows["guarded-sync-execution"]
        self.assertIn("refuse", guarded_sync["refusal_behavior"].lower())
        self.assertIn("not implemented", guarded_sync["refusal_behavior"].lower())

    def test_workflow_contract_rejects_available_unimplemented_workflow(self) -> None:
        with self.assertRaisesRegex(ValueError, "available=True requires"):
            WorkflowContract(
                id="bad-workflow",
                title="Bad workflow",
                operator_intent="Expose an invalid workflow contract.",
                trigger_phrases=("bad workflow",),
                capability_gate="sync-ready",
                implementation_status="planned",
                available=True,
                authority_reads=("sync_policy",),
                preflight_checks=("Validate sync policy.",),
                mutation_gates=("No mutation.",),
                entrypoints=(),
                evidence_expectations=("Evidence.",),
                refusal_behavior="Refuse invalid contracts.",
                handoff_expectations=("Ask for correction.",),
                closeout_criteria=("Contract is valid.",),
            )

    def test_workflow_catalog_status_values_cover_status_type(self) -> None:
        catalog = workflow_catalog()

        self.assertEqual(set(catalog["status_values"]), set(get_args(ImplementationStatus)))

    def test_workflow_migration_inventory_classifies_representative_sources(self) -> None:
        with tempfile.TemporaryDirectory() as workspace:
            workspace_path = Path(workspace)
            source_roots = _write_workflow_inventory_fixture(workspace_path)

            with patch.object(Path, "home", return_value=workspace_path):
                inventory = build_workflow_migration_inventory(source_roots)

        self.assertEqual(inventory["operation"], "workflow-migration-inventory")
        self.assertEqual(inventory["mode"], "read-only")
        self.assertEqual(inventory["summary"]["entry_count"], 7)
        self.assertEqual(inventory["summary"]["source_root_count"], 3)
        self.assertEqual(inventory["summary"]["unresolvable_source_root_count"], 0)
        self.assertEqual(inventory["unresolvable_source_roots"], [])
        self.assertGreaterEqual(inventory["summary"]["backlog_candidate_count"], 1)
        self.assertEqual(inventory["mutation_policy"], "no source roots are modified")

        entries_by_kind: dict[str, list[dict[str, Any]]] = {}
        for entry in inventory["entries"]:
            entries_by_kind.setdefault(entry["source_kind"], []).append(entry)
        self.assertEqual(
            {kind: len(entries) for kind, entries in entries_by_kind.items()},
            {
                "global-skill": 1,
                "repo-local-skill": 1,
                "agent-instruction": 1,
                "policy": 1,
                "gate": 1,
                "procedure": 1,
                "handoff": 1,
            },
        )
        entries = {kind: matches[0] for kind, matches in entries_by_kind.items()}
        self.assertEqual(
            entries["global-skill"]["material_scope"],
            "reusable-workflow-material",
        )
        self.assertEqual(
            entries["global-skill"]["likely_workflow_catalog_target"],
            "upstream-sync-planning",
        )
        global_skill_evidence = {
            evidence["signal"]: evidence for evidence in entries["global-skill"]["evidence"]
        }
        self.assertIsNone(global_skill_evidence["global-skill"]["line"])
        self.assertEqual(
            entries["repo-local-skill"]["material_scope"],
            "fork-local-authority-material",
        )
        self.assertEqual(
            entries["agent-instruction"]["material_scope"],
            "fork-local-authority-material",
        )
        self.assertEqual(entries["gate"]["likely_workflow_catalog_target"], "review-preparation")
        self.assertEqual(entries["handoff"]["coverage_status"], "backlog-candidate")

        for entry in inventory["entries"]:
            self.assertTrue(entry["candidate_operator_intent"])
            self.assertTrue(entry["likely_workflow_catalog_target"])
            self.assertTrue(entry["evidence"])
            self.assertNotIn("source_text", entry)
            for evidence in entry["evidence"]:
                self.assertTrue(evidence["id"])
                self.assertTrue(evidence["signal"])
                if evidence["line"] is not None:
                    self.assertGreaterEqual(evidence["line"], 1)
                self.assertNotIn("source_text", evidence)

    def test_workflow_migration_inventory_avoids_path_substring_source_kinds(self) -> None:
        with tempfile.TemporaryDirectory() as workspace:
            docs = Path(workspace) / "docs"
            docs.mkdir()
            for filename in (
                "aggregate-stats.md",
                "privacy-policy.md",
                "backhandoff.md",
            ):
                (docs / filename).write_text(
                    "# Workflow Notes\n\n"
                    "This maintained fork records upstream sync evidence for operator review.\n"
                )

            inventory = build_workflow_migration_inventory([docs])

        entries_by_path = {entry["source_path"]: entry for entry in inventory["entries"]}
        self.assertEqual(
            set(entries_by_path),
            {"aggregate-stats.md", "privacy-policy.md", "backhandoff.md"},
        )
        for entry in entries_by_path.values():
            self.assertEqual(entry["source_kind"], "doc")

    def test_workflow_migration_inventory_reports_unresolvable_source_roots(self) -> None:
        with tempfile.TemporaryDirectory() as workspace:
            missing = Path(workspace) / "missing-source-root"

            inventory = build_workflow_migration_inventory([missing])

        self.assertEqual(inventory["entries"], [])
        self.assertEqual(inventory["summary"]["source_root_count"], 1)
        self.assertEqual(inventory["summary"]["unresolvable_source_root_count"], 1)
        self.assertEqual(inventory["unresolvable_source_roots"], [str(missing.resolve())])

    def test_workflow_migration_inventory_groups_catalog_evidence_by_reference(self) -> None:
        with tempfile.TemporaryDirectory() as workspace:
            workspace_path = Path(workspace)
            source_roots = _write_workflow_inventory_fixture(workspace_path)

            with patch.object(Path, "home", return_value=workspace_path):
                inventory = build_workflow_migration_inventory(source_roots)

        catalog_evidence = {
            group["workflow_id"]: group for group in inventory["catalog_evidence"]
        }
        sync_planning = catalog_evidence["upstream-sync-planning"]
        self.assertEqual(sync_planning["coverage_status"], "cataloged-not-implemented")
        self.assertFalse(sync_planning["available"])
        self.assertTrue(sync_planning["entry_refs"])
        self.assertNotIn("source_text", sync_planning)
        self.assertNotIn("source_text", sync_planning["entry_refs"][0])

        backlog_targets = {
            candidate["candidate_target"] for candidate in inventory["backlog_candidates"]
        }
        self.assertIn("human-handoff-contracts", backlog_targets)
        for candidate in inventory["backlog_candidates"]:
            self.assertEqual(candidate["coverage_status"], "backlog-candidate")
            self.assertTrue(candidate["entry_id"])

    def test_workflow_migration_inventory_classifies_repo_local_skill_root(self) -> None:
        with tempfile.TemporaryDirectory() as workspace:
            repo = Path(workspace) / "maintained-fork"
            skill_root = repo / ".agents" / "skills"
            skill = skill_root / "review-closeout" / "SKILL.md"
            skill.parent.mkdir(parents=True)
            skill.write_text(
                "# Review Closeout\n\n"
                "This fork-local authority uses review bot evidence before publication.\n"
            )

            inventory = build_workflow_migration_inventory([skill_root])

        [entry] = inventory["entries"]
        self.assertEqual(entry["source_kind"], "repo-local-skill")
        self.assertEqual(entry["material_scope"], "fork-local-authority-material")

    def test_cli_and_mcp_expose_workflow_migration_inventory(self) -> None:
        with tempfile.TemporaryDirectory() as workspace:
            workspace_path = Path(workspace)
            source_roots = _write_workflow_inventory_fixture(workspace_path)
            output = io.StringIO()

            with patch.object(Path, "home", return_value=workspace_path), redirect_stdout(output):
                exit_code = cli_main(
                    [
                        "workflow",
                        "inventory",
                        "--source-root",
                        str(source_roots[0]),
                        "--source-root",
                        str(source_roots[1]),
                        "--source-root",
                        str(source_roots[2]),
                    ]
                )
            cli_payload = json.loads(output.getvalue())
            with patch.object(Path, "home", return_value=workspace_path):
                mcp_payload = fork_ops_workflow_migration_inventory(
                    [str(source_root) for source_root in source_roots]
                )

        self.assertEqual(exit_code, 0)
        self.assertEqual(cli_payload, mcp_payload)
        self.assertEqual(cli_payload["operation"], "workflow-migration-inventory")

    def test_track_aware_config_satisfies_track_aware_level(self) -> None:
        with tempfile.TemporaryDirectory() as repo:
            path = Path(repo) / CONFIG_RELATIVE_PATH
            path.parent.mkdir(parents=True)
            path.write_text(TRACK_AWARE_CONFIG)

            report = build_status_report(repo)

        self.assertEqual(report["capability"]["highest_available"], "track-aware")
        self.assertTrue(report["capability"]["levels"]["track-aware"]["available"])
        self.assertFalse(report["capability"]["levels"]["sync-ready"]["available"])

    def test_sync_ready_requires_safe_boolean_policy_values(self) -> None:
        config = (
            TRACK_AWARE_CONFIG
            + """
[sync_policy]
default_sync_baseline = "upstream-stable"
preserve_commit_identity = false
forbid_history_rewrites = true
allowed_merge_methods = ["merge"]

[divergence_policy]
uncertainty_destination = "ask-human-operator"
"""
        )
        with tempfile.TemporaryDirectory() as repo:
            path = Path(repo) / CONFIG_RELATIVE_PATH
            path.parent.mkdir(parents=True)
            path.write_text(config)

            report = build_status_report(repo)

        self.assertFalse(report["capability"]["levels"]["sync-ready"]["available"])
        self.assertIn(
            "sync_policy.preserve_commit_identity",
            report["capability"]["levels"]["sync-ready"]["missing"],
        )

    def test_schema_rejects_missing_required_foundation_sections(self) -> None:
        config = parse_config_text('schema_version = "0.1"\n')

        diagnostics = schema_diagnostics(config)

        messages = [item.message for item in diagnostics]
        self.assertTrue(
            any("'repository' is a required property" in message for message in messages)
        )
        self.assertTrue(
            any("'fork_remotes' is a required property" in message for message in messages)
        )

    def test_schema_artifacts_match_runtime_schema(self) -> None:
        plugin_root = Path(__file__).resolve().parents[1]
        expected = schema_json()

        self.assertEqual((plugin_root / "schema/fork-ops.schema.json").read_text(), expected)
        self.assertEqual((plugin_root / "src/fork_ops/fork-ops.schema.json").read_text(), expected)

    def test_schema_artifact_report_flags_documented_schema_drift(self) -> None:
        with tempfile.TemporaryDirectory() as plugin:
            plugin_root = Path(plugin)
            docs_schema = plugin_root / "schema/fork-ops.schema.json"
            runtime_schema = plugin_root / "src/fork_ops/fork-ops.schema.json"
            docs_schema.parent.mkdir(parents=True)
            runtime_schema.parent.mkdir(parents=True)
            docs_schema.write_text('{"title": "drifted"}\n')
            runtime_schema.write_text(schema_json())

            report = schema_artifact_report(plugin_root)

        self.assertFalse(report["ok"])
        artifacts = {artifact["path"]: artifact for artifact in report["artifacts"]}
        self.assertFalse(artifacts["schema/fork-ops.schema.json"]["matches_runtime_schema"])
        self.assertTrue(artifacts["src/fork_ops/fork-ops.schema.json"]["matches_runtime_schema"])

    def test_schema_artifact_report_records_unreadable_artifact(self) -> None:
        with tempfile.TemporaryDirectory() as plugin:
            plugin_root = Path(plugin)
            docs_schema = plugin_root / "schema/fork-ops.schema.json"
            runtime_schema = plugin_root / "src/fork_ops/fork-ops.schema.json"
            docs_schema.parent.mkdir(parents=True)
            runtime_schema.parent.mkdir(parents=True)
            docs_schema.write_text(schema_json())
            runtime_schema.write_text(schema_json())
            original_read_bytes = Path.read_bytes

            def unreadable(path: Path) -> bytes:
                if path == docs_schema:
                    raise PermissionError("permission denied")
                return original_read_bytes(path)

            with patch.object(Path, "read_bytes", unreadable):
                report = schema_artifact_report(plugin_root)

        artifacts = {artifact["path"]: artifact for artifact in report["artifacts"]}
        self.assertFalse(report["ok"])
        self.assertFalse(artifacts["schema/fork-ops.schema.json"]["matches_runtime_schema"])
        self.assertEqual(artifacts["schema/fork-ops.schema.json"]["error"], "permission denied")
        self.assertTrue(artifacts["src/fork_ops/fork-ops.schema.json"]["matches_runtime_schema"])

    def test_normalize_config_accepts_toml_datetime_values(self) -> None:
        config = parse_config_text(
            'schema_version = "0.1"\n\n[repository]\ncreated_at = 2026-05-18T00:00:00Z\n'
        )

        normalized = normalize_config(config)

        self.assertEqual(normalized["repository"]["created_at"].year, 2026)

    def test_status_report_config_is_json_safe(self) -> None:
        config = TRACK_AWARE_CONFIG.replace(
            'default_branch = "main"',
            'default_branch = "main"\ncreated_at = 2026-05-18T00:00:00Z',
        )
        with tempfile.TemporaryDirectory() as repo:
            path = Path(repo) / CONFIG_RELATIVE_PATH
            path.parent.mkdir(parents=True)
            path.write_text(config)

            report = build_status_report(repo)

        self.assertEqual(report["config"]["repository"]["created_at"], "2026-05-18T00:00:00+00:00")
        json.dumps(report)

    def test_malformed_sections_do_not_crash_diagnostics(self) -> None:
        config = """schema_version = "0.1"
repository = "not-a-table"
fork_remotes = ["not-a-table"]
upstreams = ["not-a-table"]
release_channels = ["not-a-table"]
upstream_tracks = ["not-a-table"]
local_surfaces = ["not-a-table"]

[authority]
source_order = ["fork-ops-config"]

[change_targets]
default = "fork"

[sync_policy]
default_sync_baseline = "upstream-stable"
preserve_commit_identity = true
forbid_history_rewrites = true
allowed_merge_methods = ["merge"]

[divergence_policy]
uncertainty_destination = "ask-human-operator"
"""
        with tempfile.TemporaryDirectory() as repo:
            path = Path(repo) / CONFIG_RELATIVE_PATH
            path.parent.mkdir(parents=True)
            path.write_text(config)

            report = build_status_report(repo)

        self.assertEqual(report["config"]["repository"], "not-a-table")
        self.assertTrue(report["diagnostics"])

    def test_unknown_track_release_channel_is_reference_error(self) -> None:
        config = TRACK_AWARE_CONFIG.replace('source = "stable"', 'source = "preview"')
        with tempfile.TemporaryDirectory() as repo:
            path = Path(repo) / CONFIG_RELATIVE_PATH
            path.parent.mkdir(parents=True)
            path.write_text(config)

            report = build_status_report(repo)

        codes = [item["code"] for item in report["diagnostics"]]
        self.assertIn("reference.unknown_release_channel", codes)
        self.assertIsNone(report["capability"]["highest_available"])

    def test_git_missing_remote_diagnostics_point_to_config_key(self) -> None:
        config = TRACK_AWARE_CONFIG.replace('name = "origin"', 'name = "fork-origin"', 1)
        with tempfile.TemporaryDirectory() as repo:
            repo_path = Path(repo)
            _run_git(repo_path, "init")
            path = repo_path / CONFIG_RELATIVE_PATH
            path.parent.mkdir(parents=True)
            path.write_text(config)

            report = build_status_report(repo_path)

        missing_paths = {
            item["path"] for item in report["diagnostics"] if item["code"] == "git.remote_missing"
        }
        self.assertIn("fork_remotes.0.name", missing_paths)
        self.assertIn("upstreams.0.remote", missing_paths)

    def test_proposed_config_uses_upstream_head_default_branch(self) -> None:
        with tempfile.TemporaryDirectory() as repo:
            repo_path = Path(repo)
            _run_git(repo_path, "init")
            _run_git(repo_path, "remote", "add", "origin", "https://github.com/fork/repo.git")
            _run_git(repo_path, "remote", "add", "upstream", "https://github.com/up/repo.git")
            _run_git(
                repo_path,
                "symbolic-ref",
                "refs/remotes/upstream/HEAD",
                "refs/remotes/upstream/trunk",
            )

            patch = propose_migration_config_patch(repo_path)

        self.assertEqual(patch["config"]["upstreams"][0]["default_branch"], "trunk")

    def test_upstream_stable_track_does_not_require_release_channel_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as repo:
            repo_path = Path(repo)
            path = repo_path / ".agents/skills/working-with-upstream-refs/SKILL.md"
            path.parent.mkdir(parents=True)
            path.write_text("Use `origin/upstream-stable` as the fork baseline ref.\n")

            patch = propose_migration_config_patch(repo_path)

        self.assertEqual(patch["diagnostics"], [])
        self.assertEqual(patch["config"]["release_channels"], [])
        [track] = patch["config"]["upstream_tracks"]
        self.assertEqual(track["id"], "upstream-stable")
        self.assertEqual(track["source_type"], "upstream_ref")
        self.assertEqual(track["source"], "refs/remotes/origin/upstream-stable")

    def test_default_sync_baseline_uses_detected_origin_upstream_track(self) -> None:
        with tempfile.TemporaryDirectory() as repo:
            repo_path = Path(repo)
            path = repo_path / ".agents/skills/working-with-upstream-refs/SKILL.md"
            path.parent.mkdir(parents=True)
            path.write_text(
                "Use `origin/upstream-lts` as the default upstream baseline for sync work.\n"
            )

            patch = propose_migration_config_patch(repo_path)

        self.assertEqual(patch["diagnostics"], [])
        [track] = patch["config"]["upstream_tracks"]
        self.assertEqual(track["id"], "upstream-lts")
        self.assertEqual(track["ref"], "refs/remotes/origin/upstream-lts")
        self.assertEqual(track["source"], "refs/remotes/origin/upstream-lts")
        self.assertTrue(track["sync_eligible"])
        self.assertEqual(patch["config"]["sync_policy"]["default_sync_baseline"], "upstream-lts")
        self.assertEqual(patch["config"]["sync_policy"]["default_sync_ref"], "origin/upstream-lts")
        self.assertIn(
            "git merge-base --is-ancestor origin/upstream-lts HEAD",
            patch["config"]["sync_policy"]["ancestry_checks"],
        )

    def test_default_sync_baseline_accepts_nested_origin_upstream_ref(self) -> None:
        with tempfile.TemporaryDirectory() as repo:
            repo_path = Path(repo)
            path = repo_path / ".agents/skills/working-with-release-refs/SKILL.md"
            path.parent.mkdir(parents=True)
            path.write_text(
                "Use origin/upstream-release/v1 as the default upstream baseline for sync work.\n"
            )

            patch = propose_migration_config_patch(repo_path)

        self.assertEqual(patch["diagnostics"], [])
        [track] = patch["config"]["upstream_tracks"]
        self.assertEqual(track["id"], "upstream-release-v1")
        self.assertEqual(track["ref"], "refs/remotes/origin/upstream-release/v1")
        self.assertEqual(
            patch["config"]["sync_policy"]["default_sync_ref"],
            "origin/upstream-release/v1",
        )

    def test_default_sync_baseline_ignores_trailing_sentence_period(self) -> None:
        with tempfile.TemporaryDirectory() as repo:
            repo_path = Path(repo)
            path = repo_path / ".agents/skills/working-with-default-ref/SKILL.md"
            path.parent.mkdir(parents=True)
            path.write_text(
                "Use origin/upstream-stable. It is the default upstream baseline for sync work.\n"
            )

            patch = propose_migration_config_patch(repo_path)

        self.assertEqual(patch["diagnostics"], [])
        [track] = patch["config"]["upstream_tracks"]
        self.assertEqual(track["id"], "upstream-stable")
        self.assertEqual(track["ref"], "refs/remotes/origin/upstream-stable")
        self.assertEqual(
            patch["config"]["sync_policy"]["default_sync_ref"],
            "origin/upstream-stable",
        )

    def test_multiple_default_sync_baselines_require_review(self) -> None:
        with tempfile.TemporaryDirectory() as repo:
            repo_path = Path(repo)
            lts_path = repo_path / ".agents/skills/default-lts/SKILL.md"
            stable_path = repo_path / "docs/agents/default-stable.md"
            lts_path.parent.mkdir(parents=True)
            stable_path.parent.mkdir(parents=True)
            lts_path.write_text(
                "Use origin/upstream-lts as the default upstream baseline for sync work.\n"
            )
            stable_path.write_text(
                "Use origin/upstream-stable as the default upstream baseline for sync work.\n"
            )

            patch = propose_migration_config_patch(repo_path)
            plan = generate_migration_plan(repo_path)

        track_ids = {track["id"] for track in patch["config"]["upstream_tracks"]}
        diagnostic_codes = {item["code"] for item in patch["diagnostics"]}
        blocker_codes = {item["code"] for item in plan["blockers"]}
        self.assertEqual(track_ids, {"upstream-lts", "upstream-stable"})
        self.assertEqual(patch["config"]["sync_policy"], {})
        self.assertIn("migration.default_sync_baseline_ambiguous", diagnostic_codes)
        self.assertIn("proposed_config_patch.diagnostics_failed", blocker_codes)

    def test_migration_assessment_extracts_upstream_ref_pressure_case(self) -> None:
        skill_text = UPSTREAM_REF_PRESSURE_TEXT
        with tempfile.TemporaryDirectory() as repo:
            path = Path(repo) / ".agents/skills/working-with-upstream-refs/SKILL.md"
            path.parent.mkdir(parents=True)
            path.write_text(skill_text)

            assessment = assess_migration(repo)

        [candidate] = assessment["candidates"]
        self.assertNotIn("proposed_config_patch", assessment)
        facts = {
            (fact["kind"], fact["value"], fact["suggested_config"])
            for fact in candidate["extracted_facts"]
        }
        self.assertIn(("ref_role", "origin/upstream-stable", "upstream_tracks"), facts)
        self.assertIn(("ref_role", "upstream-main", "upstream_tracks"), facts)
        self.assertIn(("release_channel", "stable", "release_channels"), facts)
        self.assertIn(
            (
                "default_sync_baseline",
                "origin/upstream-stable",
                "sync_policy.default_sync_baseline",
            ),
            facts,
        )
        self.assertIn(("disabled_upstream_push", "upstream", "upstreams.push"), facts)
        self.assertIn(
            (
                "forbidden_history_rewrite",
                "force-push",
                "sync_policy.forbid_history_rewrites",
            ),
            facts,
        )
        self.assertIn(
            ("ancestry_check", "merge-base --is-ancestor", "sync_policy.ancestry_checks"),
            facts,
        )
        self.assertIn("upstream_intelligence", candidate["domains"])
        self.assertIn("sync", candidate["domains"])

    def test_proposed_config_patch_preserves_upstream_ref_semantics(self) -> None:
        with tempfile.TemporaryDirectory() as repo:
            repo_path = Path(repo)
            path = repo_path / ".agents/skills/working-with-upstream-refs/SKILL.md"
            path.parent.mkdir(parents=True)
            path.write_text(UPSTREAM_REF_PRESSURE_TEXT)
            for context_path in (
                "AGENTS.md",
                "CONTEXT.md",
                "docs/agents/domain.md",
                "docs/agents/research-map.md",
            ):
                destination = repo_path / context_path
                destination.parent.mkdir(parents=True, exist_ok=True)
                destination.write_text("Fork-local context.\n")
            issue_tracker = repo_path / "docs/agents/issue-tracker.md"
            issue_tracker.write_text(
                "This is the fork's issue tracker. Create upstream issues only when "
                "the user explicitly says upstream issue work is in scope. Pull "
                "request review automation belongs here.\n"
            )

            patch = propose_migration_config_patch(repo)

        self.assertEqual(patch["mode"], "non-mutating")
        self.assertEqual(patch["operation"], "create")
        self.assertEqual(patch["diagnostics"], [])
        config = patch["config"]
        self.assertEqual(config["repository"]["owner"], "nisavid")
        self.assertEqual(config["repository"]["name"], "lemonade")
        self.assertEqual(config["repository"]["product_site"], "https://lemonade-server.ai/")
        self.assertNotIn("protected_branches", config["repository"])
        self.assertEqual(
            config["authority"]["required_context_paths"],
            [
                "AGENTS.md",
                "CONTEXT.md",
                "docs/agents/domain.md",
                "docs/agents/research-map.md",
            ],
        )
        self.assertEqual(config["upstreams"][0]["owner"], "lemonade-sdk")
        self.assertEqual(config["upstreams"][0]["name"], "lemonade")
        self.assertFalse(config["upstreams"][0]["push"])
        self.assertEqual(config["upstreams"][0]["push_url"], "DISABLED")
        self.assertEqual(config["release_channels"][0]["id"], "stable")
        self.assertFalse(config["release_channels"][0]["include_drafts"])
        self.assertFalse(config["release_channels"][0]["include_prereleases"])
        tracks = {track["id"]: track for track in config["upstream_tracks"]}
        self.assertEqual(
            tracks["upstream-main"]["source"],
            "refs/remotes/upstream/main",
        )
        self.assertFalse(tracks["upstream-main"]["sync_eligible"])
        self.assertIn("PR descriptions", tracks["upstream-main"]["update_policy"])
        self.assertIn(
            "git rev-parse upstream/main upstream-main origin/upstream-main",
            tracks["upstream-main"]["evidence_checks"],
        )
        self.assertEqual(
            tracks["upstream-stable"]["source_type"],
            "release_channel",
        )
        self.assertTrue(tracks["upstream-stable"]["sync_eligible"])
        self.assertIn("fork release versioning", tracks["upstream-stable"]["notes"])
        self.assertIn(
            "local upstream-stable only",
            tracks["upstream-stable"]["local_branch_policy"],
        )
        self.assertIn("not a fast-forward", tracks["upstream-stable"]["non_fast_forward_policy"])
        self.assertIn(
            "git rev-parse <release-tag> upstream-stable origin/upstream-stable",
            tracks["upstream-stable"]["evidence_checks"],
        )
        self.assertEqual(config["sync_policy"]["default_sync_baseline"], "upstream-stable")
        self.assertEqual(
            config["divergence_policy"]["uncertainty_destination"],
            "ask-human-operator",
        )
        self.assertNotIn("uncertainty_destination", config["sync_policy"])
        self.assertEqual(config["sync_policy"]["default_sync_ref"], "origin/upstream-stable")
        self.assertEqual(config["sync_policy"]["fork_sync_start_ref"], "origin/main")
        self.assertTrue(config["sync_policy"]["preserve_commit_identity"])
        self.assertTrue(config["sync_policy"]["forbid_history_rewrites"])
        self.assertIn("ff-only", config["sync_policy"]["allowed_merge_methods"])
        self.assertEqual(config["sync_policy"]["fork_sync_methods"], ["merge"])
        self.assertEqual(config["sync_policy"]["track_update_methods"], ["ff-only"])
        self.assertIn(
            "git merge-base --is-ancestor origin/upstream-stable HEAD",
            config["sync_policy"]["ancestry_checks"],
        )
        self.assertIn(
            "user-requested upstream main sync: git merge-base --is-ancestor upstream/main HEAD",
            config["sync_policy"]["conditional_ancestry_checks"],
        )
        self.assertIn("git fetch origin", config["sync_policy"]["pre_sync_fetches"])
        self.assertIn(
            "git fetch upstream --prune --tags",
            config["sync_policy"]["pre_sync_fetches"],
        )
        self.assertIn(
            "force-push routine baseline updates",
            config["sync_policy"]["forbidden_flows"],
        )
        surfaces = {surface["path"]: surface for surface in config["local_surfaces"]}
        upstream_ref_surface = surfaces[".agents/skills/working-with-upstream-refs/SKILL.md"]
        self.assertEqual(upstream_ref_surface["domain"], "upstream_intelligence")
        self.assertIn("authority", upstream_ref_surface["domains"])
        self.assertIn("sync", upstream_ref_surface["domains"])
        issue_tracker_surface = surfaces["docs/agents/issue-tracker.md"]
        self.assertEqual(issue_tracker_surface["domain"], "review_publication")
        self.assertEqual(issue_tracker_surface["portability_hint"], "repo-ops-candidate")
        self.assertIn("repo-ops-candidate", issue_tracker_surface["portability_hints"])
        self.assertIn("fork-specific", issue_tracker_surface["portability_hints"])
        self.assertIn(
            "review/publication workflow",
            issue_tracker_surface["repo_ops_candidate_scope"],
        )
        remote_facts = [
            fact["value"]
            for item in patch["evidence"]
            for fact in item["facts"]
            if fact["kind"] == "remote_url"
        ]
        self.assertNotIn("upstream:https://github.com/lemonade-sdk/lemonade/releases", remote_facts)
        parsed = parse_config_text(patch["toml"])
        self.assertEqual(parsed["sync_policy"]["default_sync_baseline"], "upstream-stable")
        self.assertEqual(
            parsed["divergence_policy"]["uncertainty_destination"],
            "ask-human-operator",
        )
        self.assertIn("toml_renderer.flat_config_contract", patch["contract_tags"])
        self.assertNotIn("toml_renderer.flat_config_contract", patch["limitations"])

    def test_migration_plan_distinguishes_plan_sections_for_lemonade_pressure_case(self) -> None:
        with tempfile.TemporaryDirectory() as repo:
            repo_path = Path(repo)
            path = repo_path / ".agents/skills/working-with-upstream-refs/SKILL.md"
            path.parent.mkdir(parents=True)
            path.write_text(UPSTREAM_REF_PRESSURE_TEXT)

            plan = generate_migration_plan(repo)

        self.assertEqual(plan["mode"], "non-mutating")
        self.assertEqual(plan["operation"], "migration-plan")
        self.assertTrue(plan["requires_review"])
        self.assertEqual(plan["summary"]["candidate_count"], 1)
        self.assertEqual(plan["summary"]["retained_source_material_count"], 1)
        self.assertIn("proposed_config_patch", plan)
        self.assertEqual(plan["proposed_config_patch"]["operation"], "create")
        self.assertEqual(plan["proposed_config_patch"]["target_path"], ".agents/fork-ops.toml")
        self.assertEqual(plan["proposed_config_patch"]["diagnostics"], [])
        evidence = plan["evidence"]
        self.assertEqual(
            evidence[0]["source_path"],
            ".agents/skills/working-with-upstream-refs/SKILL.md",
        )
        self.assertIn("upstream_intelligence", evidence[0]["domains"])
        facts = {
            (fact["kind"], fact["value"], fact["suggested_config"])
            for fact in evidence[0]["facts"]
        }
        self.assertIn(
            (
                "default_sync_baseline",
                "origin/upstream-stable",
                "sync_policy.default_sync_baseline",
            ),
            facts,
        )
        [retained] = plan["retained_source_materials"]
        self.assertEqual(retained["path"], ".agents/skills/working-with-upstream-refs/SKILL.md")
        self.assertEqual(retained["replacement_status"], "deferred")
        self.assertEqual(plan["deferred_removals"][0]["path"], retained["path"])
        self.assertEqual(plan["blockers"], [])
        review_codes = {item["code"] for item in plan["required_review"]}
        self.assertIn("review.proposed_config_patch", review_codes)
        self.assertIn("review.retained_source_materials", review_codes)
        validation_codes = {item["code"] for item in plan["validation_requirements"]}
        self.assertIn("validation.config_validate", validation_codes)

    def test_migration_plan_records_semantic_coverage_blockers(self) -> None:
        with tempfile.TemporaryDirectory() as repo:
            repo_path = Path(repo)
            path = repo_path / "AGENTS.md"
            path.write_text("Review bot policy lives here, but no structured fork facts yet.\n")

            plan = generate_migration_plan(repo)

        self.assertEqual(plan["summary"]["semantic_coverage"], "incomplete")
        self.assertEqual(plan["blockers"][0]["code"], "semantic_coverage.incomplete")
        self.assertEqual(plan["blockers"][0]["paths"], ["AGENTS.md"])

    def test_migration_plan_accepts_default_baseline_without_separate_ref_role(self) -> None:
        with tempfile.TemporaryDirectory() as repo:
            repo_path = Path(repo)
            path = repo_path / ".agents/skills/default-baseline/SKILL.md"
            path.parent.mkdir(parents=True)
            path.write_text(
                "Use origin/upstream-stable as the default upstream baseline for sync work.\n"
            )

            plan = generate_migration_plan(repo)

        self.assertEqual(plan["summary"]["semantic_coverage"], "complete")
        self.assertEqual(plan["blockers"], [])
        patch_config = plan["proposed_config_patch"]["config"]
        self.assertEqual(patch_config["upstream_tracks"][0]["id"], "upstream-stable")
        self.assertEqual(patch_config["sync_policy"]["default_sync_baseline"], "upstream-stable")

    def test_migration_dry_run_previews_plan_without_mutating_repo(self) -> None:
        with tempfile.TemporaryDirectory() as repo:
            repo_path = Path(repo)
            source_path = repo_path / ".agents/skills/working-with-upstream-refs/SKILL.md"
            source_path.parent.mkdir(parents=True)
            source_path.write_text(UPSTREAM_REF_PRESSURE_TEXT)
            plan = generate_migration_plan(repo_path)

            dry_run = dry_run_migration_plan(plan)

            self.assertFalse((repo_path / CONFIG_RELATIVE_PATH).exists())
            self.assertEqual(source_path.read_text(), UPSTREAM_REF_PRESSURE_TEXT)

        self.assertEqual(dry_run["mode"], "non-mutating")
        self.assertEqual(dry_run["operation"], "migration-dry-run")
        self.assertTrue(dry_run["can_execute"])
        self.assertEqual(dry_run["summary"]["file_edit_count"], 1)
        self.assertEqual(dry_run["file_edits"][0]["path"], ".agents/fork-ops.toml")
        self.assertEqual(dry_run["file_edits"][0]["action"], "create")
        self.assertEqual(dry_run["config_changes"][0]["target_path"], ".agents/fork-ops.toml")
        self.assertEqual(
            dry_run["retained_materials"][0]["path"],
            ".agents/skills/working-with-upstream-refs/SKILL.md",
        )
        blocker_codes = {item["code"] for item in dry_run["blocked_steps"]}
        self.assertNotIn("migration_execution.unavailable", blocker_codes)
        verification_codes = {item["code"] for item in dry_run["expected_verification_commands"]}
        self.assertIn("validation.config_validate", verification_codes)

    def test_migration_dry_run_output_does_not_alias_input_plan(self) -> None:
        with tempfile.TemporaryDirectory() as repo:
            repo_path = Path(repo)
            source_path = repo_path / ".agents/skills/working-with-upstream-refs/SKILL.md"
            source_path.parent.mkdir(parents=True)
            source_path.write_text(UPSTREAM_REF_PRESSURE_TEXT)
            plan = generate_migration_plan(repo_path)

            dry_run = dry_run_migration_plan(plan)
            dry_run["retained_materials"][0]["path"] = "changed"
            dry_run["deferred_removals"][0]["path"] = "changed"
            dry_run["config_changes"][0]["config"]["repository"]["owner"] = "changed"

        self.assertEqual(
            plan["retained_source_materials"][0]["path"],
            ".agents/skills/working-with-upstream-refs/SKILL.md",
        )
        self.assertEqual(
            plan["deferred_removals"][0]["path"],
            ".agents/skills/working-with-upstream-refs/SKILL.md",
        )
        self.assertNotEqual(
            plan["proposed_config_patch"]["config"]["repository"]["owner"],
            "changed",
        )

    def test_migration_dry_run_rejects_malformed_plan_sections(self) -> None:
        with tempfile.TemporaryDirectory() as repo:
            repo_path = Path(repo)
            source_path = repo_path / ".agents/skills/working-with-upstream-refs/SKILL.md"
            source_path.parent.mkdir(parents=True)
            source_path.write_text(UPSTREAM_REF_PRESSURE_TEXT)
            plan = generate_migration_plan(repo_path)
            plan["blockers"] = ["not-a-table"]

            with self.assertRaisesRegex(ForkOpsError, "malformed blockers"):
                dry_run_migration_plan(plan)

    def test_migration_dry_run_uses_embedded_repo_path_for_supplied_plan(self) -> None:
        with tempfile.TemporaryDirectory() as repo:
            repo_path = Path(repo)
            source_path = repo_path / ".agents/skills/working-with-upstream-refs/SKILL.md"
            source_path.parent.mkdir(parents=True)
            source_path.write_text(UPSTREAM_REF_PRESSURE_TEXT)
            plan = generate_migration_plan(repo_path)

            dry_run = dry_run_migration(".", plan=plan)

        self.assertEqual(dry_run["repo_path"], str(repo_path.resolve()))

    def test_migration_dry_run_reports_plan_blockers_before_execution(self) -> None:
        with tempfile.TemporaryDirectory() as repo:
            repo_path = Path(repo)
            source_path = repo_path / "AGENTS.md"
            source_text = "Review bot policy lives here, but no structured fork facts yet.\n"
            source_path.write_text(source_text)

            dry_run = dry_run_migration(repo_path)

            self.assertFalse((repo_path / CONFIG_RELATIVE_PATH).exists())
            self.assertEqual(source_path.read_text(), source_text)

        blocker_codes = [item["code"] for item in dry_run["blocked_steps"]]
        self.assertIn("semantic_coverage.incomplete", blocker_codes)
        self.assertFalse(dry_run["can_execute"])

    def test_cli_exposes_migration_dry_run(self) -> None:
        with tempfile.TemporaryDirectory() as repo:
            repo_path = Path(repo)
            source_path = repo_path / ".agents/skills/working-with-upstream-refs/SKILL.md"
            source_path.parent.mkdir(parents=True)
            source_path.write_text(UPSTREAM_REF_PRESSURE_TEXT)
            output = io.StringIO()

            with redirect_stdout(output):
                exit_code = cli_main(["migration", "dry-run", "--repo", str(repo_path)])

        payload = json.loads(output.getvalue())
        self.assertEqual(exit_code, 0)
        self.assertEqual(payload["operation"], "migration-dry-run")
        self.assertTrue(payload["can_execute"])

    def test_cli_accepts_migration_plan_file_for_dry_run(self) -> None:
        with tempfile.TemporaryDirectory() as repo:
            repo_path = Path(repo)
            source_path = repo_path / ".agents/skills/working-with-upstream-refs/SKILL.md"
            plan_path = repo_path / "migration-plan.json"
            source_path.parent.mkdir(parents=True)
            source_path.write_text(UPSTREAM_REF_PRESSURE_TEXT)
            plan_path.write_text(json.dumps(generate_migration_plan(repo_path)))
            output = io.StringIO()

            with redirect_stdout(output):
                exit_code = cli_main(["migration", "dry-run", "--plan", str(plan_path)])

        payload = json.loads(output.getvalue())
        self.assertEqual(exit_code, 0)
        self.assertEqual(payload["operation"], "migration-dry-run")
        self.assertEqual(payload["plan_operation"], "migration-plan")

    def test_cli_rejects_ambiguous_migration_dry_run_inputs(self) -> None:
        with tempfile.TemporaryDirectory() as repo:
            repo_path = Path(repo)
            source_path = repo_path / ".agents/skills/working-with-upstream-refs/SKILL.md"
            plan_path = repo_path / "migration-plan.json"
            source_path.parent.mkdir(parents=True)
            source_path.write_text(UPSTREAM_REF_PRESSURE_TEXT)
            plan_path.write_text(json.dumps(generate_migration_plan(repo_path)))

            with self.assertRaises(SystemExit) as raised:
                cli_main(
                    [
                        "migration",
                        "dry-run",
                        "--repo",
                        str(repo_path),
                        "--plan",
                        str(plan_path),
                    ]
                )

        self.assertEqual(raised.exception.code, 2)

    def test_cli_plan_json_parse_error_names_source_path(self) -> None:
        with tempfile.TemporaryDirectory() as repo:
            plan_path = Path(repo) / "bad-plan.json"
            plan_path.write_text("{")
            error = io.StringIO()

            with redirect_stderr(error):
                exit_code = cli_main(["migration", "dry-run", "--plan", str(plan_path)])

        self.assertEqual(exit_code, 2)
        self.assertIn(str(plan_path), error.getvalue())

    def test_cli_smokes_config_init_show_validate(self) -> None:
        with tempfile.TemporaryDirectory() as repo:
            repo_path = Path(repo)
            init_output = io.StringIO()
            show_output = io.StringIO()
            validate_output = io.StringIO()

            with redirect_stdout(init_output):
                init_exit = cli_main(
                    [
                        "config",
                        "init",
                        "--repo",
                        str(repo_path),
                        "--repository-owner",
                        "nisavid",
                        "--repository-name",
                        "demo",
                        "--upstream-owner",
                        "upstream",
                        "--upstream-name",
                        "demo",
                        "--write",
                    ]
                )
            with redirect_stdout(show_output):
                show_exit = cli_main(
                    ["config", "show", "--repo", str(repo_path), "--format", "json"]
                )
            with redirect_stdout(validate_output):
                validate_exit = cli_main(
                    [
                        "config",
                        "validate",
                        "--repo",
                        str(repo_path),
                        "--required-level",
                        "track-aware",
                        "--json",
                    ]
                )

        shown = json.loads(show_output.getvalue())
        validated = json.loads(validate_output.getvalue())
        self.assertEqual(init_exit, 0)
        self.assertEqual(show_exit, 0)
        self.assertEqual(validate_exit, 0)
        self.assertEqual(Path(init_output.getvalue().strip()).name, "fork-ops.toml")
        self.assertEqual(shown["repository"]["owner"], "nisavid")
        self.assertTrue(validated["required_level"]["available"])

    def test_cli_schema_check_reports_drift(self) -> None:
        with tempfile.TemporaryDirectory() as plugin:
            plugin_root = Path(plugin)
            docs_schema = plugin_root / "schema/fork-ops.schema.json"
            runtime_schema = plugin_root / "src/fork_ops/fork-ops.schema.json"
            docs_schema.parent.mkdir(parents=True)
            runtime_schema.parent.mkdir(parents=True)
            docs_schema.write_text(schema_json())
            runtime_schema.write_text("{}\n")
            output = io.StringIO()

            with redirect_stdout(output):
                exit_code = cli_main(
                    ["schema", "check", "--plugin-root", str(plugin_root), "--json"]
                )

        payload = json.loads(output.getvalue())
        self.assertEqual(exit_code, 1)
        self.assertFalse(payload["ok"])
        artifacts = {artifact["path"]: artifact for artifact in payload["artifacts"]}
        self.assertFalse(artifacts["src/fork_ops/fork-ops.schema.json"]["matches_runtime_schema"])

    def test_cli_schema_check_plain_output_distinguishes_read_errors(self) -> None:
        with tempfile.TemporaryDirectory() as plugin:
            plugin_root = Path(plugin)
            docs_schema = plugin_root / "schema/fork-ops.schema.json"
            runtime_schema = plugin_root / "src/fork_ops/fork-ops.schema.json"
            docs_schema.parent.mkdir(parents=True)
            runtime_schema.parent.mkdir(parents=True)
            docs_schema.write_text(schema_json())
            runtime_schema.write_text(schema_json())
            original_read_bytes = Path.read_bytes
            output = io.StringIO()

            def unreadable(path: Path) -> bytes:
                if path == docs_schema:
                    raise PermissionError("permission denied")
                return original_read_bytes(path)

            with patch.object(Path, "read_bytes", unreadable), redirect_stdout(output):
                exit_code = cli_main(["schema", "check", "--plugin-root", str(plugin_root)])

        self.assertEqual(exit_code, 1)
        self.assertIn("error\tschema/fork-ops.schema.json", output.getvalue())
        self.assertIn("ok\tsrc/fork_ops/fork-ops.schema.json", output.getvalue())

    def test_cli_and_mcp_expose_shared_workflow_catalog(self) -> None:
        output = io.StringIO()

        with redirect_stdout(output):
            exit_code = cli_main(["workflow", "catalog"])
        cli_payload = json.loads(output.getvalue())
        mcp_payload = fork_ops_workflow_catalog()

        self.assertEqual(exit_code, 0)
        self.assertEqual(cli_payload, mcp_payload)
        workflows = {workflow["id"]: workflow for workflow in cli_payload["workflows"]}
        operator_onboarding = workflows["operator-onboarding"]
        self.assertIn("fork-ops workflow catalog", _entrypoint_ids(operator_onboarding))
        self.assertIn("fork_ops_workflow_catalog", _entrypoint_ids(operator_onboarding))

    def test_mcp_exposes_migration_dry_run(self) -> None:
        with tempfile.TemporaryDirectory() as repo:
            repo_path = Path(repo)
            source_path = repo_path / ".agents/skills/working-with-upstream-refs/SKILL.md"
            source_path.parent.mkdir(parents=True)
            source_path.write_text(UPSTREAM_REF_PRESSURE_TEXT)

            payload = fork_ops_migration_dry_run(str(repo_path))

        self.assertEqual(payload["operation"], "migration-dry-run")
        self.assertTrue(payload["can_execute"])

    def test_mcp_smokes_config_tools_and_schema(self) -> None:
        with tempfile.TemporaryDirectory() as repo:
            repo_path = Path(repo)
            config_path = repo_path / CONFIG_RELATIVE_PATH
            config_path.parent.mkdir(parents=True)
            config_path.write_text(TRACK_AWARE_CONFIG)

            raw = fork_ops_config_read(str(repo_path), normalized=False)
            normalized = fork_ops_config_read(str(repo_path), normalized=True)
            validation = fork_ops_config_validate(str(repo_path), required_level="track-aware")
            capability = fork_ops_capability_report(str(repo_path))
            schema = fork_ops_schema()

        self.assertEqual(raw["raw"], TRACK_AWARE_CONFIG)
        self.assertEqual(normalized["config"]["repository"]["owner"], "nisavid")
        self.assertTrue(validation["required_level"]["available"])
        self.assertTrue(capability["levels"]["track-aware"]["available"])
        self.assertEqual(schema, schema_json())

    def test_migration_execution_rejects_malformed_plan_before_mutating(self) -> None:
        with tempfile.TemporaryDirectory() as repo:
            repo_path = Path(repo)

            with self.assertRaisesRegex(ForkOpsError, "operation='migration-plan'"):
                execute_migration_plan({"operation": "not-a-migration-plan"}, repo_path=repo_path)

            self.assertFalse((repo_path / CONFIG_RELATIVE_PATH).exists())

    def test_migration_execution_refuses_plan_blockers_without_mutating_repo(self) -> None:
        with tempfile.TemporaryDirectory() as repo:
            repo_path = Path(repo)
            source_path = repo_path / "AGENTS.md"
            source_text = "Review bot policy lives here, but no structured fork facts yet.\n"
            source_path.write_text(source_text)
            plan = generate_migration_plan(repo_path)

            result = execute_migration_plan(plan)

            self.assertFalse((repo_path / CONFIG_RELATIVE_PATH).exists())
            self.assertEqual(source_path.read_text(), source_text)

        self.assertEqual(result["operation"], "migration-execution")
        self.assertEqual(result["status"], "blocked")
        self.assertEqual(result["applied_edits"], [])
        blocker_codes = {blocker["code"] for blocker in result["blockers"]}
        self.assertIn("semantic_coverage.incomplete", blocker_codes)
        self.assertEqual(result["skipped_edits"][0]["reason"], "blocked_steps_present")

    def test_migration_execution_applies_config_and_preserves_source_material(self) -> None:
        with tempfile.TemporaryDirectory() as repo:
            repo_path = Path(repo)
            source_path = repo_path / ".agents/skills/working-with-upstream-refs/SKILL.md"
            source_path.parent.mkdir(parents=True)
            source_path.write_text(UPSTREAM_REF_PRESSURE_TEXT)
            plan = generate_migration_plan(repo_path)

            result = execute_migration_plan(plan)

            config_path = repo_path / CONFIG_RELATIVE_PATH
            self.assertTrue(config_path.exists())
            self.assertEqual(source_path.read_text(), UPSTREAM_REF_PRESSURE_TEXT)
            parsed = parse_config_text(config_path.read_text())
            config_bytes = config_path.read_bytes()

        self.assertEqual(result["mode"], "mutating")
        self.assertEqual(result["operation"], "migration-execution")
        self.assertEqual(result["status"], "applied")
        self.assertEqual(result["summary"]["applied_edit_count"], 1)
        self.assertEqual(result["summary"]["blocker_count"], 0)
        self.assertEqual(result["applied_edits"][0]["path"], ".agents/fork-ops.toml")
        self.assertEqual(result["applied_edits"][0]["action"], "create")
        self.assertEqual(result["applied_edits"][0]["bytes"], len(config_bytes))
        self.assertEqual(
            result["applied_edits"][0]["content_sha256"],
            hashlib.sha256(config_bytes).hexdigest(),
        )
        self.assertEqual(result["skipped_edits"][0]["action"], "preserve")
        self.assertEqual(
            result["skipped_edits"][0]["path"],
            ".agents/skills/working-with-upstream-refs/SKILL.md",
        )
        self.assertEqual(result["verification_results"][0]["status"], "passed")
        self.assertEqual(
            result["verification_results"][0]["note"],
            "Status reflects Fork Ops capability verification; listed commands are not executed.",
        )
        self.assertTrue(result["verification_results"][0]["required_level_available"])
        self.assertEqual(parsed["sync_policy"]["default_sync_baseline"], "upstream-stable")

    def test_migration_plan_hashes_retained_source_bytes(self) -> None:
        with tempfile.TemporaryDirectory() as repo:
            repo_path = Path(repo)
            source_path = repo_path / ".agents/skills/working-with-upstream-refs/SKILL.md"
            source_path.parent.mkdir(parents=True)
            source_bytes = UPSTREAM_REF_PRESSURE_TEXT.encode() + b"\xff"
            source_path.write_bytes(source_bytes)

            plan = generate_migration_plan(repo_path)
            result = execute_migration_plan(plan)

            self.assertEqual(
                plan["retained_source_materials"][0]["content_sha256"],
                hashlib.sha256(source_bytes).hexdigest(),
            )

        self.assertEqual(result["status"], "applied")

    def test_migration_execution_rejects_existing_config_create(self) -> None:
        with tempfile.TemporaryDirectory() as repo:
            repo_path = Path(repo)
            source_path = repo_path / ".agents/skills/working-with-upstream-refs/SKILL.md"
            source_path.parent.mkdir(parents=True)
            source_path.write_text(UPSTREAM_REF_PRESSURE_TEXT)
            config_path = repo_path / CONFIG_RELATIVE_PATH
            config_path.write_text(TRACK_AWARE_CONFIG)
            plan = generate_migration_plan(repo_path)
            plan["proposed_config_patch"]["operation"] = "create"
            plan["blockers"] = []
            original_config = config_path.read_text()

            result = execute_migration_plan(plan)

            self.assertEqual(config_path.read_text(), original_config)

        self.assertEqual(result["status"], "blocked")
        self.assertEqual(result["blockers"][0]["code"], "migration_execution.target_exists")

    def test_migration_execution_rejects_noncanonical_config_target(self) -> None:
        with tempfile.TemporaryDirectory() as repo:
            repo_path = Path(repo)
            source_path = repo_path / ".agents/skills/working-with-upstream-refs/SKILL.md"
            source_path.parent.mkdir(parents=True)
            source_path.write_text(UPSTREAM_REF_PRESSURE_TEXT)
            plan = generate_migration_plan(repo_path)
            plan["proposed_config_patch"]["target_path"] = ".agents/not-fork-ops.toml"

            result = execute_migration_plan(plan)

            self.assertFalse((repo_path / ".agents/not-fork-ops.toml").exists())

        self.assertEqual(result["status"], "blocked")
        self.assertEqual(
            result["blockers"][0]["code"],
            "migration_execution.unsupported_target_path",
        )

    def test_migration_execution_accepts_platform_separator_target_path(self) -> None:
        with tempfile.TemporaryDirectory() as repo:
            repo_path = Path(repo)
            source_path = repo_path / ".agents/skills/working-with-upstream-refs/SKILL.md"
            source_path.parent.mkdir(parents=True)
            source_path.write_text(UPSTREAM_REF_PRESSURE_TEXT)
            plan = generate_migration_plan(repo_path)
            plan["proposed_config_patch"]["target_path"] = ".agents\\fork-ops.toml"

            result = execute_migration_plan(plan)

            self.assertTrue((repo_path / CONFIG_RELATIVE_PATH).exists())

        self.assertEqual(result["status"], "applied")

    def test_migration_execution_does_not_overwrite_target_created_during_write(self) -> None:
        with tempfile.TemporaryDirectory() as repo:
            repo_path = Path(repo)
            source_path = repo_path / ".agents/skills/working-with-upstream-refs/SKILL.md"
            source_path.parent.mkdir(parents=True)
            source_path.write_text(UPSTREAM_REF_PRESSURE_TEXT)
            plan = generate_migration_plan(repo_path)

            original_open = Path.open

            def late_target_create(path: Path, *args: Any, **kwargs: Any) -> Any:
                mode = str(args[0]) if args else str(kwargs.get("mode", "r"))
                if "x" in mode:
                    raise FileExistsError
                return original_open(path, *args, **kwargs)

            with patch.object(Path, "open", late_target_create):
                result = execute_migration_plan(plan)

            self.assertFalse((repo_path / CONFIG_RELATIVE_PATH).exists())

        self.assertEqual(result["status"], "blocked")
        self.assertEqual(result["applied_edits"], [])
        self.assertEqual(result["blockers"][0]["code"], "migration_execution.target_exists")

    def test_migration_execution_rejects_dangling_target_symlink(self) -> None:
        with tempfile.TemporaryDirectory() as repo:
            repo_path = Path(repo)
            source_path = repo_path / ".agents/skills/working-with-upstream-refs/SKILL.md"
            source_path.parent.mkdir(parents=True)
            source_path.write_text(UPSTREAM_REF_PRESSURE_TEXT)
            plan = generate_migration_plan(repo_path)
            target_path = repo_path / CONFIG_RELATIVE_PATH
            target_path.symlink_to(repo_path / "missing-target")

            dry_run = dry_run_migration_plan(plan)
            result = execute_migration_plan(plan)

        self.assertFalse(dry_run["can_execute"])
        self.assertEqual(result["status"], "blocked")
        self.assertEqual(result["blockers"][0]["code"], "migration_execution.target_exists")

    def test_migration_execution_rejects_target_parent_symlink_outside_repo(self) -> None:
        with tempfile.TemporaryDirectory() as repo, tempfile.TemporaryDirectory() as outside:
            repo_path = Path(repo)
            source_path = repo_path / "docs/agents/working-with-upstream-refs.md"
            source_path.parent.mkdir(parents=True)
            source_path.write_text(UPSTREAM_REF_PRESSURE_TEXT)
            plan = generate_migration_plan(repo_path)
            (repo_path / ".agents").symlink_to(outside, target_is_directory=True)

            result = execute_migration_plan(plan)

            self.assertFalse((Path(outside) / "fork-ops.toml").exists())

        self.assertEqual(result["status"], "blocked")
        self.assertEqual(result["blockers"][0]["code"], "migration_execution.unsafe_target_path")

    def test_migration_execution_rejects_target_parent_file(self) -> None:
        with tempfile.TemporaryDirectory() as repo:
            repo_path = Path(repo)
            source_path = repo_path / "docs/agents/working-with-upstream-refs.md"
            source_path.parent.mkdir(parents=True)
            source_path.write_text(UPSTREAM_REF_PRESSURE_TEXT)
            plan = generate_migration_plan(repo_path)
            (repo_path / ".agents").write_text("not a directory\n")

            result = execute_migration_plan(plan)

        self.assertEqual(result["status"], "blocked")
        self.assertEqual(
            result["blockers"][0]["code"],
            "migration_execution.target_parent_not_directory",
        )

    def test_migration_execution_reports_target_parent_write_race(self) -> None:
        with tempfile.TemporaryDirectory() as repo:
            repo_path = Path(repo)
            source_path = repo_path / ".agents/skills/working-with-upstream-refs/SKILL.md"
            source_path.parent.mkdir(parents=True)
            source_path.write_text(UPSTREAM_REF_PRESSURE_TEXT)
            plan = generate_migration_plan(repo_path)

            with patch.object(Path, "mkdir", side_effect=FileExistsError("late parent file")):
                result = execute_migration_plan(plan)

            self.assertFalse((repo_path / CONFIG_RELATIVE_PATH).exists())

        self.assertEqual(result["status"], "blocked")
        self.assertEqual(
            result["blockers"][0]["code"],
            "migration_execution.target_parent_unavailable",
        )

    def test_migration_execution_rejects_config_without_required_capability(self) -> None:
        with tempfile.TemporaryDirectory() as repo:
            repo_path = Path(repo)
            source_path = repo_path / ".agents/skills/working-with-upstream-refs/SKILL.md"
            source_path.parent.mkdir(parents=True)
            source_path.write_text(UPSTREAM_REF_PRESSURE_TEXT)
            plan = generate_migration_plan(repo_path)
            plan["proposed_config_patch"]["toml"] = IDENTIFIED_CONFIG
            plan["proposed_config_patch"]["config"] = parse_config_text(IDENTIFIED_CONFIG)

            dry_run = dry_run_migration_plan(plan)
            result = execute_migration_plan(plan)

            self.assertFalse((repo_path / CONFIG_RELATIVE_PATH).exists())

        self.assertFalse(dry_run["can_execute"])
        self.assertEqual(result["status"], "blocked")
        self.assertEqual(
            result["blockers"][0]["code"],
            "migration_execution.required_capability_unavailable",
        )

    def test_migration_execution_rejects_plan_without_validation_requirements(self) -> None:
        with tempfile.TemporaryDirectory() as repo:
            repo_path = Path(repo)
            source_path = repo_path / ".agents/skills/working-with-upstream-refs/SKILL.md"
            source_path.parent.mkdir(parents=True)
            source_path.write_text(UPSTREAM_REF_PRESSURE_TEXT)
            plan = generate_migration_plan(repo_path)
            plan["validation_requirements"] = []

            dry_run = dry_run_migration_plan(plan)
            result = execute_migration_plan(plan)

            self.assertFalse((repo_path / CONFIG_RELATIVE_PATH).exists())

        self.assertFalse(dry_run["can_execute"])
        self.assertEqual(result["status"], "blocked")
        self.assertEqual(
            result["blockers"][0]["code"],
            "migration_execution.validation_requirements_missing",
        )

    def test_migration_execution_rejects_unknown_validation_requirement(self) -> None:
        with tempfile.TemporaryDirectory() as repo:
            repo_path = Path(repo)
            source_path = repo_path / ".agents/skills/working-with-upstream-refs/SKILL.md"
            source_path.parent.mkdir(parents=True)
            source_path.write_text(UPSTREAM_REF_PRESSURE_TEXT)
            plan = generate_migration_plan(repo_path)
            plan["validation_requirements"].append(
                {
                    "code": "validation.external_command",
                    "command": "false",
                    "when": "after applying the proposed fork ops config",
                }
            )

            result = execute_migration_plan(plan)

            self.assertFalse((repo_path / CONFIG_RELATIVE_PATH).exists())

        self.assertEqual(result["status"], "blocked")
        self.assertEqual(
            result["blockers"][0]["code"],
            "migration_execution.validation_requirement_unsupported",
        )

    def test_migration_execution_rejects_missing_validation_requirement(self) -> None:
        with tempfile.TemporaryDirectory() as repo:
            repo_path = Path(repo)
            source_path = repo_path / ".agents/skills/working-with-upstream-refs/SKILL.md"
            source_path.parent.mkdir(parents=True)
            source_path.write_text(UPSTREAM_REF_PRESSURE_TEXT)
            plan = generate_migration_plan(repo_path)
            plan["validation_requirements"] = plan["validation_requirements"][:1]

            result = execute_migration_plan(plan)

            self.assertFalse((repo_path / CONFIG_RELATIVE_PATH).exists())

        self.assertEqual(result["status"], "blocked")
        self.assertEqual(
            result["blockers"][0]["code"],
            "migration_execution.validation_requirement_missing",
        )

    def test_migration_execution_rejects_config_toml_mismatch(self) -> None:
        with tempfile.TemporaryDirectory() as repo:
            repo_path = Path(repo)
            source_path = repo_path / ".agents/skills/working-with-upstream-refs/SKILL.md"
            source_path.parent.mkdir(parents=True)
            source_path.write_text(UPSTREAM_REF_PRESSURE_TEXT)
            plan = generate_migration_plan(repo_path)
            patch_config = plan["proposed_config_patch"]["config"]
            patch_config["repository"]["owner"] = "reviewed-owner"

            result = execute_migration_plan(plan)

            self.assertFalse((repo_path / CONFIG_RELATIVE_PATH).exists())

        self.assertEqual(result["status"], "blocked")
        self.assertEqual(
            result["blockers"][0]["code"],
            "migration_execution.proposed_config_patch_mismatch",
        )

    def test_migration_execution_rejects_changed_retained_source_material(self) -> None:
        with tempfile.TemporaryDirectory() as repo:
            repo_path = Path(repo)
            source_path = repo_path / ".agents/skills/working-with-upstream-refs/SKILL.md"
            source_path.parent.mkdir(parents=True)
            source_path.write_text(UPSTREAM_REF_PRESSURE_TEXT)
            plan = generate_migration_plan(repo_path)
            source_path.write_text(UPSTREAM_REF_PRESSURE_TEXT + "\nChanged after plan.\n")

            result = execute_migration_plan(plan)

            self.assertFalse((repo_path / CONFIG_RELATIVE_PATH).exists())

        self.assertEqual(result["status"], "blocked")
        self.assertEqual(
            result["blockers"][0]["code"],
            "migration_execution.retained_source_changed",
        )

    def test_migration_execution_rejects_unreadable_retained_source_material(self) -> None:
        with tempfile.TemporaryDirectory() as repo:
            repo_path = Path(repo)
            source_path = repo_path / ".agents/skills/working-with-upstream-refs/SKILL.md"
            source_path.parent.mkdir(parents=True)
            source_path.write_text(UPSTREAM_REF_PRESSURE_TEXT)
            plan = generate_migration_plan(repo_path)
            plan["retained_source_materials"][0]["content_sha256"] = hashlib.sha256(
                b""
            ).hexdigest()
            original_read_bytes = Path.read_bytes

            def unreadable(path: Path) -> bytes:
                if path == source_path:
                    raise OSError("unreadable")
                return original_read_bytes(path)

            with patch.object(Path, "read_bytes", unreadable):
                result = execute_migration_plan(plan)

            self.assertFalse((repo_path / CONFIG_RELATIVE_PATH).exists())

        self.assertEqual(result["status"], "blocked")
        self.assertEqual(
            result["blockers"][0]["code"],
            "migration_execution.retained_source_changed",
        )

    def test_migration_execution_rejects_missing_retained_source_hash(self) -> None:
        with tempfile.TemporaryDirectory() as repo:
            repo_path = Path(repo)
            source_path = repo_path / ".agents/skills/working-with-upstream-refs/SKILL.md"
            source_path.parent.mkdir(parents=True)
            source_path.write_text(UPSTREAM_REF_PRESSURE_TEXT)
            plan = generate_migration_plan(repo_path)
            del plan["retained_source_materials"][0]["content_sha256"]

            result = execute_migration_plan(plan)

            self.assertFalse((repo_path / CONFIG_RELATIVE_PATH).exists())

        self.assertEqual(result["status"], "blocked")
        self.assertEqual(
            result["blockers"][0]["code"],
            "migration_execution.retained_source_hash_missing",
        )

    def test_migration_execution_rejects_unsafe_retained_source_path(self) -> None:
        with tempfile.TemporaryDirectory() as repo:
            repo_path = Path(repo)
            source_path = repo_path / ".agents/skills/working-with-upstream-refs/SKILL.md"
            source_path.parent.mkdir(parents=True)
            source_path.write_text(UPSTREAM_REF_PRESSURE_TEXT)
            plan = generate_migration_plan(repo_path)
            plan["retained_source_materials"][0]["path"] = "../outside.md"

            result = execute_migration_plan(plan)

            self.assertFalse((repo_path / CONFIG_RELATIVE_PATH).exists())

        self.assertEqual(result["status"], "blocked")
        self.assertEqual(
            result["blockers"][0]["code"],
            "migration_execution.unsafe_retained_source_path",
        )

    def test_migration_execution_preserves_concurrent_target_on_write_failure(self) -> None:
        with tempfile.TemporaryDirectory() as repo:
            repo_path = Path(repo)
            source_path = repo_path / ".agents/skills/working-with-upstream-refs/SKILL.md"
            source_path.parent.mkdir(parents=True)
            source_path.write_text(UPSTREAM_REF_PRESSURE_TEXT)
            plan = generate_migration_plan(repo_path)
            target_path = repo_path / CONFIG_RELATIVE_PATH

            def concurrent_target_then_link_failure(src: Path, dst: Path) -> None:
                target_path.write_text("created by another process")
                raise OSError("link failed after concurrent target create")

            with patch("fork_ops.core.os.link", concurrent_target_then_link_failure):
                result = execute_migration_plan(plan)

            self.assertEqual(target_path.read_text(), "created by another process")

        self.assertEqual(result["status"], "blocked")
        self.assertEqual(result["blockers"][0]["code"], "migration_execution.write_failed")

    def test_migration_execution_removes_parent_created_for_blocked_write(self) -> None:
        with tempfile.TemporaryDirectory() as repo:
            repo_path = Path(repo)
            source_path = repo_path / "AGENTS.md"
            source_path.write_text(UPSTREAM_REF_PRESSURE_TEXT)
            plan = generate_migration_plan(repo_path)

            def target_appeared(*args: Any, **kwargs: Any) -> None:
                raise FileExistsError("target appeared")

            with patch("fork_ops.core.os.link", target_appeared):
                result = execute_migration_plan(plan)

            self.assertFalse((repo_path / CONFIG_RELATIVE_PATH).exists())
            self.assertFalse((repo_path / ".agents").exists())

        self.assertEqual(result["status"], "blocked")
        self.assertEqual(result["blockers"][0]["code"], "migration_execution.target_exists")

    def test_mcp_migration_execution_rejects_plan_repo_path_mismatch(self) -> None:
        with tempfile.TemporaryDirectory() as repo, tempfile.TemporaryDirectory() as other:
            repo_path = Path(repo)
            source_path = repo_path / ".agents/skills/working-with-upstream-refs/SKILL.md"
            source_path.parent.mkdir(parents=True)
            source_path.write_text(UPSTREAM_REF_PRESSURE_TEXT)
            plan = generate_migration_plan(repo_path)

            result = fork_ops_migration_execute(str(Path(other)), migration_plan=plan)

            self.assertFalse((repo_path / CONFIG_RELATIVE_PATH).exists())
            self.assertFalse((Path(other) / CONFIG_RELATIVE_PATH).exists())

        self.assertEqual(result["status"], "blocked")
        self.assertEqual(result["blockers"][0]["code"], "migration_execution.repo_path_mismatch")

    def test_execute_migration_uses_embedded_repo_path_for_supplied_plan(self) -> None:
        with tempfile.TemporaryDirectory() as repo:
            repo_path = Path(repo)
            source_path = repo_path / ".agents/skills/working-with-upstream-refs/SKILL.md"
            source_path.parent.mkdir(parents=True)
            source_path.write_text(UPSTREAM_REF_PRESSURE_TEXT)
            plan = generate_migration_plan(repo_path)

            result = execute_migration("", plan=plan)

            self.assertTrue((repo_path / CONFIG_RELATIVE_PATH).exists())

        self.assertEqual(result["repo_path"], str(repo_path.resolve()))

    def test_execute_migration_rejects_dot_repo_path_mismatch_for_supplied_plan(self) -> None:
        original_cwd = Path.cwd()
        with tempfile.TemporaryDirectory() as repo, tempfile.TemporaryDirectory() as other:
            repo_path = Path(repo)
            source_path = repo_path / ".agents/skills/working-with-upstream-refs/SKILL.md"
            source_path.parent.mkdir(parents=True)
            source_path.write_text(UPSTREAM_REF_PRESSURE_TEXT)
            plan = generate_migration_plan(repo_path)

            try:
                os.chdir(other)
                result = execute_migration(".", plan=plan)
            finally:
                os.chdir(original_cwd)

            self.assertFalse((repo_path / CONFIG_RELATIVE_PATH).exists())

        self.assertEqual(result["status"], "blocked")
        self.assertEqual(result["blockers"][0]["code"], "migration_execution.repo_path_mismatch")

    def test_execute_migration_plan_rejects_repo_path_mismatch(self) -> None:
        with tempfile.TemporaryDirectory() as repo, tempfile.TemporaryDirectory() as other:
            repo_path = Path(repo)
            source_path = repo_path / ".agents/skills/working-with-upstream-refs/SKILL.md"
            source_path.parent.mkdir(parents=True)
            source_path.write_text(UPSTREAM_REF_PRESSURE_TEXT)
            plan = generate_migration_plan(repo_path)

            result = execute_migration_plan(plan, repo_path=other)

            self.assertFalse((repo_path / CONFIG_RELATIVE_PATH).exists())
            self.assertFalse((Path(other) / CONFIG_RELATIVE_PATH).exists())

        self.assertEqual(result["status"], "blocked")
        self.assertEqual(result["blockers"][0]["code"], "migration_execution.repo_path_mismatch")

    def test_mcp_migration_execution_defaults_to_current_directory(self) -> None:
        original_cwd = Path.cwd()
        with tempfile.TemporaryDirectory() as repo:
            repo_path = Path(repo)
            source_path = repo_path / ".agents/skills/working-with-upstream-refs/SKILL.md"
            source_path.parent.mkdir(parents=True)
            source_path.write_text(UPSTREAM_REF_PRESSURE_TEXT)

            try:
                os.chdir(repo_path)
                result = fork_ops_migration_execute()
            finally:
                os.chdir(original_cwd)

            self.assertTrue((repo_path / CONFIG_RELATIVE_PATH).exists())

        self.assertEqual(result["status"], "applied")
        self.assertEqual(result["repo_path"], str(repo_path.resolve()))

    def test_cli_exposes_migration_execute(self) -> None:
        with tempfile.TemporaryDirectory() as repo:
            repo_path = Path(repo)
            source_path = repo_path / ".agents/skills/working-with-upstream-refs/SKILL.md"
            source_path.parent.mkdir(parents=True)
            source_path.write_text(UPSTREAM_REF_PRESSURE_TEXT)
            output = io.StringIO()

            with redirect_stdout(output):
                exit_code = cli_main(["migration", "execute", "--repo", str(repo_path)])

        payload = json.loads(output.getvalue())
        self.assertEqual(exit_code, 0)
        self.assertEqual(payload["operation"], "migration-execution")
        self.assertEqual(payload["status"], "applied")

    def test_cli_accepts_migration_plan_file_for_execute(self) -> None:
        with tempfile.TemporaryDirectory() as repo:
            repo_path = Path(repo)
            source_path = repo_path / ".agents/skills/working-with-upstream-refs/SKILL.md"
            plan_path = repo_path / "migration-plan.json"
            source_path.parent.mkdir(parents=True)
            source_path.write_text(UPSTREAM_REF_PRESSURE_TEXT)
            plan_path.write_text(json.dumps(generate_migration_plan(repo_path)))
            output = io.StringIO()

            with redirect_stdout(output):
                exit_code = cli_main(["migration", "execute", "--plan", str(plan_path)])

        payload = json.loads(output.getvalue())
        self.assertEqual(exit_code, 0)
        self.assertEqual(payload["operation"], "migration-execution")
        self.assertEqual(payload["status"], "applied")

    def test_cli_migration_execute_plan_rejects_repo_path_mismatch(self) -> None:
        with tempfile.TemporaryDirectory() as repo, tempfile.TemporaryDirectory() as other:
            repo_path = Path(repo)
            source_path = repo_path / ".agents/skills/working-with-upstream-refs/SKILL.md"
            plan_path = repo_path / "migration-plan.json"
            source_path.parent.mkdir(parents=True)
            source_path.write_text(UPSTREAM_REF_PRESSURE_TEXT)
            plan_path.write_text(json.dumps(generate_migration_plan(repo_path)))
            output = io.StringIO()

            with redirect_stdout(output):
                exit_code = cli_main(
                    [
                        "migration",
                        "execute",
                        "--repo",
                        str(Path(other)),
                        "--plan",
                        str(plan_path),
                    ]
                )

        payload = json.loads(output.getvalue())
        self.assertEqual(exit_code, 1)
        self.assertEqual(payload["status"], "blocked")
        self.assertEqual(payload["blockers"][0]["code"], "migration_execution.repo_path_mismatch")

    def test_mcp_exposes_migration_execute(self) -> None:
        with tempfile.TemporaryDirectory() as repo:
            repo_path = Path(repo)
            source_path = repo_path / ".agents/skills/working-with-upstream-refs/SKILL.md"
            source_path.parent.mkdir(parents=True)
            source_path.write_text(UPSTREAM_REF_PRESSURE_TEXT)

            payload = fork_ops_migration_execute(str(repo_path))

        self.assertEqual(payload["operation"], "migration-execution")
        self.assertEqual(payload["status"], "applied")


UPSTREAM_REF_PRESSURE_TEXT = """# Working With Upstream Refs

Upstream project: `lemonade-sdk/lemonade`
Fork origin: `nisavid/lemonade`
Product site: https://lemonade-server.ai/
Upstream docs: https://lemonade-server.ai/docs/
Release index: https://github.com/lemonade-sdk/lemonade/releases

Use before upstream Git-ref work. This fork separates live upstream development
from the stable release baseline.

`upstream` fetches from https://github.com/lemonade-sdk/lemonade.git and has
push URL `DISABLED`. Publish fork-local refs to `origin`, not upstream.

`origin` fetches from https://github.com/nisavid/lemonade.git.

| Ref | Owner | Role |
| --- | --- | --- |
| `upstream/main` | Git remote-tracking ref | Upstream main. |
| `upstream-main` | Local branch, mirrored to `origin/upstream-main` | Scouting branch. |
| `origin/upstream-stable` | Fork remote-tracking ref | Published stable baseline. |
| `upstream-stable` | Local branch | Stable-baseline maintenance branch. |

Choose the next stable baseline from live GitHub Releases, not tag sorting.
Ignore drafts and prereleases unless explicitly requested.
Update and push `upstream-main` when a task depends on a shared current view of
upstream `main`, such as an upstream commit investigation, proactive sync
estimate, handoff, issue, or PR description.
Use local `upstream-stable` only when maintaining that published baseline.
When using syncing-forks-with-upstream, use `origin/upstream-stable` as the
default upstream baseline.

The upstream remote push URL is disabled. Do not force-push this branch as
routine maintenance.
If `<release-tag>` is not a fast-forward, stop and ask whether to move the
baseline.

Run `git rev-parse upstream/main upstream-main origin/upstream-main` for current
upstream state closeout.
Run `git rev-parse <release-tag> upstream-stable origin/upstream-stable` for
baseline update closeout.
Run `git merge-base --is-ancestor origin/upstream-stable HEAD` for closeout.
"""


def _write_workflow_inventory_fixture(workspace: Path) -> list[Path]:
    global_skills = workspace / ".agents" / "skills"
    maintained_fork = workspace / "maintained-fork"
    handoffs = workspace / "handoffs"

    global_skill = global_skills / "sync-fork" / "SKILL.md"
    global_skill.parent.mkdir(parents=True)
    global_skill.write_text(
        "# Sync Fork\n\n"
        "Use when an operator asks to plan an upstream sync for a maintained fork. "
        "Read fork-local authority, check origin/upstream-stable before mutation, and "
        "record workflow catalog evidence.\n"
    )

    repo_skill = maintained_fork / ".agents" / "skills" / "review-closeout" / "SKILL.md"
    repo_skill.parent.mkdir(parents=True)
    repo_skill.write_text(
        "# Review Closeout\n\n"
        "This fork-local authority says pull request publication uses the review bot, "
        "CodeQL code scanning, and rebase merge after review threads are resolved.\n"
    )

    agents = maintained_fork / "AGENTS.md"
    agents.write_text(
        "# Agent Instructions\n\n"
        "Mutation gate: do not force-push routine baseline updates. Stop and ask a "
        "human operator when sync policy is ambiguous.\n"
    )

    docs_agents = maintained_fork / "docs" / "agents"
    docs_agents.mkdir(parents=True)
    (docs_agents / "pull-request-policy.md").write_text(
        "# Pull Request Policy\n\n"
        "Policy: required checks, code scanning, and unresolved review thread handling "
        "must be reported before publication closeout.\n"
    )
    (docs_agents / "local-gates.md").write_text(
        "# Local Gates\n\n"
        "Gate: run pytest and ruff before review preparation. If checks fail, no "
        "publication mutation is allowed.\n"
    )
    (docs_agents / "upstream-sync-procedure.md").write_text(
        "# Upstream Sync Procedure\n\n"
        "Procedure: upstream sync planning compares origin/upstream-stable with HEAD "
        "using merge-base --is-ancestor and records blockers.\n"
    )

    handoff = handoffs / "sync-handoff.md"
    handoff.parent.mkdir(parents=True)
    handoff.write_text(
        "# Sync Handoff\n\n"
        "Handoff contract: include the active blocker, current upstream refs, review "
        "thread state, next action, and return contract when an upstream sync pauses.\n"
    )

    return [global_skills, maintained_fork, handoffs]


def _run_git(repo_path: Path, *args: str) -> None:
    subprocess.run(
        ["git", "-C", str(repo_path), *args],
        check=True,
        text=True,
        capture_output=True,
    )


if __name__ == "__main__":
    unittest.main()
