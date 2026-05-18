from __future__ import annotations

import io
import json
import subprocess
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from typing import Any
from unittest.mock import patch

from fork_ops.cli import main as cli_main
from fork_ops.core import (
    CONFIG_RELATIVE_PATH,
    ForkOpsError,
    assess_migration,
    build_status_report,
    dry_run_migration,
    dry_run_migration_plan,
    execute_migration,
    execute_migration_plan,
    generate_migration_plan,
    normalize_config,
    parse_config_text,
    propose_migration_config_patch,
    schema_json,
)
from fork_ops.mcp_server import fork_ops_migration_dry_run, fork_ops_migration_execute
from fork_ops.schema import schema_diagnostics

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


class ForkOpsCoreTests(unittest.TestCase):
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

    def test_migration_plan_semantic_coverage_ignores_config_diagnostic_blockers(self) -> None:
        with tempfile.TemporaryDirectory() as repo:
            repo_path = Path(repo)
            path = repo_path / ".agents/skills/default-baseline/SKILL.md"
            path.parent.mkdir(parents=True)
            path.write_text(
                "Use origin/upstream-stable as the default upstream baseline for sync work.\n"
            )

            plan = generate_migration_plan(repo)

        self.assertEqual(plan["summary"]["semantic_coverage"], "complete")
        blocker_codes = {blocker["code"] for blocker in plan["blockers"]}
        self.assertIn("proposed_config_patch.diagnostics_failed", blocker_codes)
        self.assertNotIn("semantic_coverage.incomplete", blocker_codes)

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

    def test_mcp_exposes_migration_dry_run(self) -> None:
        with tempfile.TemporaryDirectory() as repo:
            repo_path = Path(repo)
            source_path = repo_path / ".agents/skills/working-with-upstream-refs/SKILL.md"
            source_path.parent.mkdir(parents=True)
            source_path.write_text(UPSTREAM_REF_PRESSURE_TEXT)

            payload = fork_ops_migration_dry_run(str(repo_path))

        self.assertEqual(payload["operation"], "migration-dry-run")
        self.assertTrue(payload["can_execute"])

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

        self.assertEqual(result["mode"], "mutating")
        self.assertEqual(result["operation"], "migration-execution")
        self.assertEqual(result["status"], "applied")
        self.assertEqual(result["summary"]["applied_edit_count"], 1)
        self.assertEqual(result["summary"]["blocker_count"], 0)
        self.assertEqual(result["applied_edits"][0]["path"], ".agents/fork-ops.toml")
        self.assertEqual(result["applied_edits"][0]["action"], "create")
        self.assertEqual(result["skipped_edits"][0]["action"], "preserve")
        self.assertEqual(
            result["skipped_edits"][0]["path"],
            ".agents/skills/working-with-upstream-refs/SKILL.md",
        )
        self.assertEqual(result["verification_results"][0]["status"], "passed")
        self.assertTrue(result["verification_results"][0]["required_level_available"])
        self.assertEqual(parsed["sync_policy"]["default_sync_baseline"], "upstream-stable")

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
                if mode == "x":
                    raise FileExistsError
                return original_open(path, *args, **kwargs)

            with patch.object(Path, "open", late_target_create):
                result = execute_migration_plan(plan)

            self.assertFalse((repo_path / CONFIG_RELATIVE_PATH).exists())

        self.assertEqual(result["status"], "blocked")
        self.assertEqual(result["applied_edits"], [])
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

    def test_execute_migration_uses_embedded_repo_path_for_supplied_plan(self) -> None:
        with tempfile.TemporaryDirectory() as repo:
            repo_path = Path(repo)
            source_path = repo_path / ".agents/skills/working-with-upstream-refs/SKILL.md"
            source_path.parent.mkdir(parents=True)
            source_path.write_text(UPSTREAM_REF_PRESSURE_TEXT)
            plan = generate_migration_plan(repo_path)

            result = execute_migration(".", plan=plan)

            self.assertTrue((repo_path / CONFIG_RELATIVE_PATH).exists())

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


def _run_git(repo_path: Path, *args: str) -> None:
    subprocess.run(
        ["git", "-C", str(repo_path), *args],
        check=True,
        text=True,
        capture_output=True,
    )


if __name__ == "__main__":
    unittest.main()
