from __future__ import annotations

import json
from copy import deepcopy
from pathlib import Path
from typing import Any
from unittest.mock import patch

import pytest
from jsonschema import Draft202012Validator

from fork_ops import core
from fork_ops.schema import Diagnostic, schema_diagnostics


@pytest.fixture
def config() -> dict[str, Any]:
    return core.parse_config_text(core.create_initial_config_text(discover_git_remotes=False))


@pytest.mark.parametrize('blank', ['', ' ', '\t\r\n', '\u00a0\u2003'])
@pytest.mark.parametrize(('section', 'field'), [
    ('repository', 'host'), ('repository', 'owner'), ('repository', 'name'),
    ('repository', 'default_branch'), ('fork_remotes', 'name'), ('upstreams', 'id'),
    ('upstreams', 'remote'), ('release_channels', 'id'), ('release_channels', 'upstream'),
    ('upstream_tracks', 'id'), ('upstream_tracks', 'upstream'), ('upstream_tracks', 'ref'),
    ('upstream_tracks', 'source'), ('local_surfaces', 'path'), ('authority', 'source_order'),
])
def test_blank_authority(config: dict[str, Any], section: str, field: str, blank: str) -> None:
    record = config[section]
    if isinstance(record, list):
        record = record[0]
    record[field] = [blank] if field == 'source_order' else blank
    root = Path(__file__).resolve().parents[1]
    for path in ('schema/fork-ops.schema.json', 'src/fork_ops/fork-ops.schema.json'):
        assert not Draft202012Validator(json.loads((root / path).read_text())).is_valid(config)
    empty: list[Diagnostic] = []
    for candidate in (config, core.normalize_config(config)):
        for diagnostics in (None, empty):
            result = core.capability_report(candidate, diagnostics)
            assert result['authority_readiness']['levels']['track-aware']['ready'] is False
            assert any(d['code'] == 'schema.invalid' for d in result['diagnostics'])


@pytest.mark.parametrize('blank', ['', ' \t', '\u2003'])
def test_linked_blanks_and_status(config: dict[str, Any], tmp_path: Path, blank: str) -> None:
    config['upstreams'][0]['id'] = blank
    config['release_channels'][0].update(id=blank, upstream=blank)
    config['upstream_tracks'][0].update(id=blank, upstream=blank, ref=blank, source=blank)
    target = tmp_path / core.CONFIG_RELATIVE_PATH
    target.parent.mkdir()
    target.write_text(core._toml_dumps(config))
    result = core.build_status_report(tmp_path)
    assert result['outcome'] == 'blocked'
    assert result['capability']['authority_readiness']['highest_authority_ready'] is None
    assert core.read_config_result(tmp_path, normalized=True)['outcome'] == 'refused'


@pytest.mark.parametrize(('field', 'value'), [('upstream', []), ('source', {})])
def test_malformed_references(config: dict[str, Any], tmp_path: Path, field: str, value: Any):
    config['upstream_tracks'][0][field] = value
    assert core.capability_report(config)['outcome'] == 'blocked'
    target = tmp_path / core.CONFIG_RELATIVE_PATH
    target.parent.mkdir()
    if isinstance(value, dict):
        config['upstream_tracks'][0][field] = 'placeholder'
        text = core._toml_dumps(config).replace('source = \"placeholder\"', 'source = {}')
    else:
        text = core._toml_dumps(config)
    target.write_text(text)
    assert core.build_status_report(tmp_path)['outcome'] == 'blocked'


@pytest.mark.parametrize('source_type', ['manual', 'upstream_ref', 'release_channel'])
def test_valid_modes(config: dict[str, Any], source_type: str) -> None:
    config['release_channels'][0].update(kind='manual', notes='')
    config['upstream_tracks'][0].update(source_type=source_type, notes='')
    if source_type != 'release_channel':
        config['upstream_tracks'][0]['source'] = 'Operator selection'
    config['x_vendor'] = {'id': '', 'nested': {'ref': ' '}}
    before = deepcopy(config)
    assert core.capability_report(config)['authority_readiness']['highest_authority_ready'] == (
        'track-aware'
    )
    assert config == before


def test_references_and_deduplication(config: dict[str, Any]) -> None:
    config['release_channels'][0]['upstream'] = 'unknown'
    expected = core.reference_diagnostics(config)
    for diagnostics in (None, expected):
        result = core.capability_report(config, diagnostics)
        assert result['diagnostics'] == [d.to_dict() for d in expected]
        assert result['authority_readiness']['highest_authority_ready'] is None
    config['upstream_tracks'][0]['ref'] = ''
    expected = schema_diagnostics(config) + core.reference_diagnostics(config)
    assert core.capability_report(config, expected)['diagnostics'] == [
        d.to_dict() for d in expected
    ]


def test_invalid_sibling(config: dict[str, Any]) -> None:
    record = deepcopy(config['upstream_tracks'][0])
    record.update(id='', ref='')
    config['upstream_tracks'].append(record)
    assert core.capability_report(config)['outcome'] == 'blocked'


def test_lower_capability(config: dict[str, Any]) -> None:
    del config['release_channels']
    del config['upstream_tracks']
    assert core.capability_report(config)['authority_readiness']['highest_authority_ready'] == (
        'scoutable'
    )


@pytest.mark.parametrize('post_write', [False, True])
def test_migration_validation(config: dict[str, Any], tmp_path: Path, post_write: bool) -> None:
    pressure_text = """# Working With Upstream Refs

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

    source = tmp_path / '.agents/skills/working-with-upstream-refs/SKILL.md'
    source.parent.mkdir(parents=True)
    source.write_text(pressure_text)
    plan = core.generate_migration_plan(tmp_path)
    config['upstream_tracks'][0]['ref'] = ''
    plan['proposed_config_patch']['config'] = config
    plan['proposed_config_patch']['toml'] = core._toml_dumps(config)
    if post_write:
        with patch('fork_ops.core._migration_file_edit_blockers', return_value=[]):
            result = core.execute_migration_plan(plan, tmp_path)
        assert result['mutation_state'] == 'applied_unverified'
        assert result['verification_results'][0]['status'] == 'failed'
    else:
        assert not core.dry_run_migration_plan(plan)['can_execute']
        result = core.execute_migration_plan(plan, tmp_path)
        assert result['mutation_state'] == 'not_started'
        assert not (tmp_path / core.CONFIG_RELATIVE_PATH).exists()
