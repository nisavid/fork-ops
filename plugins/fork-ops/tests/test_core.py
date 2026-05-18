from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from fork_ops.core import (
    CONFIG_RELATIVE_PATH,
    assess_migration,
    build_status_report,
    parse_config_text,
    propose_migration_config_patch,
)
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


if __name__ == "__main__":
    unittest.main()
