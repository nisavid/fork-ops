from __future__ import annotations

import hashlib
import json
import os
import shlex
import shutil
import subprocess
import sys
import textwrap
from collections.abc import Callable
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from threading import Event, Lock, current_thread, main_thread
from typing import cast

import pytest

from fork_ops import repository_control_adapters
from fork_ops.repository_control_adapters import (
    ControlReadContext,
    GitHubControlAdapter,
    PackageControlAdapter,
    ProducerIdentity,
    RepositoryControlAdapter,
    RepositoryControlReadError,
    RepositoryIdentity,
    RepositoryObservationCoordinationError,
    RepositoryObservationRequest,
    build_github_control_adapters,
    build_package_control_adapters,
    collect_repository_control_observation,
)
from fork_ops.repository_controls import CONTROL_SOURCES

_ISOLATED_GIT_ENV = {
    **{key: value for key, value in os.environ.items() if not key.upper().startswith("GIT_")},
    "GIT_CONFIG_GLOBAL": os.devnull,
    "GIT_CONFIG_NOSYSTEM": "1",
}
_ENFORCING_DEPENDENCY_REVIEW_INPUTS = (
    "          fail-on-severity: low\n"
    "          fail-on-scopes: runtime, development, unknown\n"
    "          warn-only: false\n"
    "          vulnerability-check: true\n"
)

requires_git = pytest.mark.skipif(
    shutil.which("git") is None,
    reason="Git is required for package-control materialization tests.",
)
requires_secure_package_platform = pytest.mark.skipif(
    sys.platform != "linux" or not Path("/proc/self/fd").is_dir(),
    reason="Package-control materialization requires Linux descriptor anchoring.",
)


@requires_git
def test_fixture_git_commands_do_not_spawn_detached_automatic_maintenance(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    trace = tmp_path / "git-trace.json"
    monkeypatch.setitem(_ISOLATED_GIT_ENV, "GIT_TRACE2_EVENT", str(trace))

    _commit_candidate(tmp_path / "candidate")

    events = [json.loads(line) for line in trace.read_text(encoding="utf-8").splitlines()]
    maintenance_commands = [
        event["argv"]
        for event in events
        if event.get("event") == "child_start"
        and isinstance(event.get("argv"), list)
        and event["argv"][:3] == ["git", "maintenance", "run"]
    ]
    assert maintenance_commands == []


def test_coordinator_binds_every_control_to_one_epoch_and_deadline() -> None:
    seen_contexts: list[tuple[str, str, float]] = []
    adapters: list[RepositoryControlAdapter] = []
    for control_id, source in CONTROL_SOURCES.items():
        reader = _passing_reader(control_id, seen_contexts)
        adapter: RepositoryControlAdapter
        if source == "github":
            adapter = GitHubControlAdapter(control_id, reader)
        else:
            adapter = PackageControlAdapter(control_id, reader)
        adapters.append(adapter)
    times = iter(
        (
            datetime(2026, 8, 14, 0, 0, 0, tzinfo=UTC),
            datetime(2026, 8, 14, 0, 0, 20, tzinfo=UTC),
        )
    )

    observation = collect_repository_control_observation(
        RepositoryObservationRequest(
            repository=RepositoryIdentity(
                full_name="nisavid/fork-ops",
                database_id=1_241_799_725,
                node_id="R_kgDOSgRcLQ",
                default_branch="main",
            ),
            candidate_sha="a" * 40,
            producer=ProducerIdentity(
                kind="github_app",
                opaque_id="github-app:1234",
                workflow_sha="b" * 40,
                evaluator_sha256="c" * 64,
            ),
            timeout_seconds=60,
        ),
        adapters,
        clock=lambda: next(times),
        monotonic=lambda: 100.0,
        epoch_factory=lambda: "e" * 64,
    )

    payload = observation.to_dict()
    assert payload["operation"] == {
        "epoch": "e" * 64,
        "started_at": "2026-08-14T00:00:00Z",
        "completed_at": "2026-08-14T00:00:20Z",
        "deadline_at": "2026-08-14T00:01:00Z",
    }
    assert payload["candidate_sha"] == "a" * 40
    controls = payload["controls"]
    assert isinstance(controls, list)
    assert [control["status"] for control in controls] == ["passed"] * len(CONTROL_SOURCES)
    assert sorted(seen_contexts) == sorted(
        (control_id, "e" * 64, 160.0) for control_id in CONTROL_SOURCES
    )


def test_default_clock_produces_a_whole_second_observation() -> None:
    adapters: list[RepositoryControlAdapter] = []
    for control_id, source in CONTROL_SOURCES.items():
        reader = _passing_reader(control_id, [])
        adapter: RepositoryControlAdapter
        if source == "github":
            adapter = GitHubControlAdapter(control_id, reader)
        else:
            adapter = PackageControlAdapter(control_id, reader)
        adapters.append(adapter)

    payload = collect_repository_control_observation(
        _request(timeout_seconds=60),
        adapters,
    ).to_dict()

    controls = payload["controls"]
    assert isinstance(controls, list)
    assert [control["status"] for control in controls] == ["passed"] * len(CONTROL_SOURCES)


def test_coordinator_clamps_a_backward_wall_clock_to_the_operation_start() -> None:
    adapters: list[RepositoryControlAdapter] = [
        _ProtocolPassingAdapter(control_id, source)
        for control_id, source in CONTROL_SOURCES.items()
    ]
    times = iter(
        (
            datetime(2026, 8, 14, 0, 0, 20, tzinfo=UTC),
            datetime(2026, 8, 14, 0, 0, 0, tzinfo=UTC),
        )
    )

    payload = collect_repository_control_observation(
        _request(),
        adapters,
        clock=lambda: next(times),
        monotonic=lambda: 100.0,
        epoch_factory=lambda: "e" * 64,
    ).to_dict()

    operation = payload["operation"]
    assert isinstance(operation, dict)
    assert operation["completed_at"] == "2026-08-14T00:00:20Z"


def test_request_identity_is_refused_before_any_provider_read() -> None:
    with pytest.raises(RepositoryObservationCoordinationError, match="identity"):
        RepositoryIdentity(
            full_name="not-a-repository",
            database_id=1,
            node_id="node:1",
            default_branch="main",
        )
    with pytest.raises(RepositoryObservationCoordinationError, match="producer"):
        ProducerIdentity(
            kind="github_app",
            opaque_id="app:1",
            workflow_sha="main",
            evaluator_sha256="c" * 64,
        )
    with pytest.raises(RepositoryObservationCoordinationError, match="candidate"):
        RepositoryObservationRequest(
            repository=_request().repository,
            candidate_sha="main",
            producer=_request().producer,
        )

    seen_contexts: list[tuple[str, str, float]] = []
    adapters: list[RepositoryControlAdapter] = []
    for control_id, source in CONTROL_SOURCES.items():
        reader = _passing_reader(control_id, seen_contexts)
        if source == "github":
            adapters.append(GitHubControlAdapter(control_id, reader))
        else:
            adapters.append(PackageControlAdapter(control_id, reader))
    with pytest.raises(RepositoryObservationCoordinationError, match="epoch"):
        collect_repository_control_observation(
            _request(),
            adapters,
            clock=lambda: datetime(2026, 8, 14, 0, 0, 0, tzinfo=UTC),
            monotonic=lambda: 100.0,
            epoch_factory=lambda: "not-an-epoch",
        )
    assert seen_contexts == []


@pytest.mark.parametrize("timeout_seconds", (True, 1.5, "60"))
def test_request_timeout_is_an_exact_integer(timeout_seconds: object) -> None:
    with pytest.raises(
        RepositoryObservationCoordinationError,
        match="between 1 and 900 seconds",
    ):
        RepositoryObservationRequest(
            repository=_request().repository,
            candidate_sha="a" * 40,
            producer=_request().producer,
            timeout_seconds=timeout_seconds,  # type: ignore[arg-type]
        )


def test_github_adapter_set_is_closed_and_complete() -> None:
    readers = {
        control_id: _passing_reader(control_id, [])
        for control_id, source in CONTROL_SOURCES.items()
        if source == "github"
    }

    adapters = build_github_control_adapters(readers)

    assert {adapter.control_id for adapter in adapters} == set(readers)
    readers.pop("main_ruleset")
    with pytest.raises(
        RepositoryObservationCoordinationError,
        match="exactly one reader for every GitHub control",
    ):
        build_github_control_adapters(readers)


def test_alert_and_private_state_require_complete_provider_evidence() -> None:
    context = _context()
    alert_reader = _passing_reader("codeql_alerts", [])

    def incomplete_alert(read_context: ControlReadContext) -> dict[str, object]:
        result = alert_reader(read_context)
        result["pagination_complete"] = False
        return result

    def mismatched_private(read_context: ControlReadContext) -> dict[str, object]:
        result = _passing_reader("private_security_exception_state", [])(read_context)
        result["semantically_identical"] = False
        return result

    alert = GitHubControlAdapter("codeql_alerts", incomplete_alert).observe(context)
    private = GitHubControlAdapter(
        "private_security_exception_state",
        mismatched_private,
    ).observe(context)

    assert alert["status"] == "unavailable"
    assert alert["failure_class"] == "pagination_incomplete"
    assert private["status"] == "failed"


def test_custom_adapter_exception_is_projected_without_private_method_coupling() -> None:
    adapters: list[RepositoryControlAdapter] = []
    for control_id, source in CONTROL_SOURCES.items():
        if control_id == "main_ruleset":
            adapters.append(_ExplodingAdapter())
        elif source == "github":
            adapters.append(GitHubControlAdapter(control_id, _passing_reader(control_id, [])))
        else:
            adapters.append(PackageControlAdapter(control_id, _passing_reader(control_id, [])))
    times = iter(
        (
            datetime(2026, 8, 14, 0, 0, 0, tzinfo=UTC),
            datetime(2026, 8, 14, 0, 0, 20, tzinfo=UTC),
        )
    )

    payload = collect_repository_control_observation(
        _request(),
        adapters,
        clock=lambda: next(times),
        monotonic=lambda: 100.0,
        epoch_factory=lambda: "e" * 64,
    ).to_dict()

    controls = payload["controls"]
    assert isinstance(controls, list)
    controls_by_id = {control["control_id"]: control for control in controls}
    assert controls_by_id["main_ruleset"]["status"] == "unavailable"
    assert controls_by_id["main_ruleset"]["failure_class"] == "adapter_error"


@pytest.mark.parametrize(
    ("field", "unsafe_value"),
    (
        ("opaque_ids", ["private body must not survive"]),
        ("observed_at", "private body must not survive"),
    ),
)
def test_adapter_rejects_unsafe_provider_data_before_projection(
    field: str,
    unsafe_value: object,
) -> None:
    private_sentinel = "private body must not survive"

    def unsafe_reader(context: ControlReadContext) -> dict[str, object]:
        result = _passing_reader("main_ruleset", [])(context)
        result[field] = unsafe_value
        return result

    result = GitHubControlAdapter("main_ruleset", unsafe_reader).observe(_context())

    assert result["status"] == "unavailable"
    assert result["failure_class"] == "malformed"
    assert private_sentinel not in str(result)


def test_adapter_discards_a_reader_result_that_reaches_the_deadline() -> None:
    remaining = iter((1.0, 0.0))
    context = replace(
        _context(),
        deadline_remaining=lambda: next(remaining),
    )

    result = GitHubControlAdapter(
        "main_ruleset",
        _passing_reader("main_ruleset", []),
    ).observe(context)

    assert result["status"] == "unavailable"
    assert result["failure_class"] == "timeout"


def test_coordinator_closes_the_snapshot_at_the_shared_deadline() -> None:
    release = Event()
    fast_readers = _FastReaderCompletion(expected=len(CONTROL_SOURCES) - 1)
    adapters: list[RepositoryControlAdapter] = []
    for control_id, source in CONTROL_SOURCES.items():
        reader = _passing_reader(control_id, [])
        if control_id == "main_ruleset":
            reader = _blocked_reader(release, control_id="main_ruleset")
        else:
            reader = fast_readers.wrap(reader)
        if source == "github":
            adapters.append(GitHubControlAdapter(control_id, reader))
        else:
            adapters.append(PackageControlAdapter(control_id, reader))
    times = iter(
        (
            datetime(2026, 8, 14, 0, 0, 0, tzinfo=UTC),
            datetime(2026, 8, 14, 0, 2, 0, tzinfo=UTC),
        )
    )
    monotonic = _CompletionDeadlineClock(
        start=100.0,
        after_start=159.5,
        fast_readers=fast_readers,
    )

    observation = collect_repository_control_observation(
        _request(),
        adapters,
        clock=lambda: next(times),
        monotonic=monotonic,
        epoch_factory=lambda: "e" * 64,
    )
    release.set()

    payload = observation.to_dict()
    operation = payload["operation"]
    assert isinstance(operation, dict)
    assert operation["completed_at"] == "2026-08-14T00:01:00Z"
    controls = payload["controls"]
    assert isinstance(controls, list)
    controls_by_id = {control["control_id"]: control for control in controls}
    assert controls_by_id["main_ruleset"]["failure_class"] == "timeout"


def test_coordinator_timeout_does_not_keep_a_child_interpreter_alive() -> None:
    script = textwrap.dedent(
        """
        from datetime import UTC, datetime, timedelta
        from threading import Event

        from fork_ops.repository_control_adapters import (
            GitHubControlAdapter,
            PackageControlAdapter,
            ProducerIdentity,
            RepositoryIdentity,
            RepositoryObservationRequest,
            collect_repository_control_observation,
        )
        from fork_ops.repository_controls import CONTROL_SOURCES

        blocked = Event()

        def reader_for(control_id):
            def read(context):
                if control_id == "main_ruleset":
                    blocked.wait()
                result = {
                    "repository_full_name": context.repository.full_name,
                    "repository_database_id": context.repository.database_id,
                    "repository_node_id": context.repository.node_id,
                    "candidate_sha": context.candidate_sha,
                    "operation_epoch": context.operation_epoch,
                    "status": "passed",
                    "observed_at": context.started_at.isoformat(timespec="seconds").replace(
                        "+00:00", "Z"
                    ),
                    "valid_until": (context.started_at + timedelta(minutes=10))
                    .isoformat(timespec="seconds")
                    .replace("+00:00", "Z"),
                    "opaque_ids": [],
                }
                if control_id in {
                    "codeql_alerts",
                    "dependabot_alerts",
                    "secret_scanning_alerts",
                }:
                    result.update(pagination_complete=True, open_count=0)
                if control_id == "private_security_exception_state":
                    result.update(
                        pagination_complete=True,
                        semantic_pass_count=2,
                        semantically_identical=True,
                    )
                return result
            return read

        adapters = []
        for control_id, source in CONTROL_SOURCES.items():
            adapter_type = GitHubControlAdapter if source == "github" else PackageControlAdapter
            adapters.append(adapter_type(control_id, reader_for(control_id)))
        request = RepositoryObservationRequest(
            repository=RepositoryIdentity(
                full_name="example/repository",
                database_id=1,
                node_id="R_example",
                default_branch="main",
            ),
            candidate_sha="a" * 40,
            producer=ProducerIdentity(
                kind="github_app",
                opaque_id="github-app:1",
                workflow_sha="b" * 40,
                evaluator_sha256="c" * 64,
            ),
            timeout_seconds=1,
        )
        observation = collect_repository_control_observation(request, adapters)
        payload = observation.to_dict()
        controls = {control["control_id"]: control for control in payload["controls"]}
        print(controls["main_ruleset"]["failure_class"], flush=True)
        """
    )

    try:
        completed = subprocess.run(
            (sys.executable, "-c", script),
            check=False,
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            timeout=30,
        )
    except subprocess.TimeoutExpired as error:
        pytest.fail(
            "child interpreter remained alive after emitting its timeout projection: "
            + str(error.stdout)
        )

    assert completed.returncode == 0, completed.stderr
    assert completed.stdout == "timeout\n"


def test_adapter_failures_are_closed_and_confidentiality_safe() -> None:
    private_sentinel = "private-advisory-body-DO-NOT-PROJECT"
    release_slow_reader = Event()
    fast_readers = _FastReaderCompletion(expected=len(CONTROL_SOURCES) - 1)
    adapters: list[RepositoryControlAdapter] = []
    for control_id, source in CONTROL_SOURCES.items():
        reader = _passing_reader(control_id, [])
        if control_id == "main_ruleset":
            reader = _mismatched_reader
        elif control_id == "human_review":
            reader = _error_reader(private_sentinel)
        elif control_id == "codeql_alerts":
            reader = _blocked_reader(release_slow_reader)
        elif control_id == "private_security_exception_state":
            reader = _private_reader(private_sentinel)
        if control_id != "codeql_alerts":
            reader = fast_readers.wrap(reader)
        if source == "github":
            adapter = GitHubControlAdapter(control_id, reader)
        else:
            adapter = PackageControlAdapter(control_id, reader)
        adapters.append(adapter)
    times = iter(
        (
            datetime(2026, 8, 14, 0, 0, 0, tzinfo=UTC),
            datetime(2026, 8, 14, 0, 0, 20, tzinfo=UTC),
        )
    )
    monotonic = _CompletionDeadlineClock(
        start=100.0,
        after_start=159.5,
        fast_readers=fast_readers,
    )

    observation = collect_repository_control_observation(
        _request(),
        adapters,
        clock=lambda: next(times),
        monotonic=monotonic,
        epoch_factory=lambda: "e" * 64,
    )
    release_slow_reader.set()

    payload = observation.to_dict()
    serialized = str(payload)
    assert private_sentinel not in serialized
    control_values = payload["controls"]
    assert isinstance(control_values, list)
    controls = {control["control_id"]: control for control in control_values}
    assert controls["main_ruleset"]["failure_class"] == "identity_mismatch"
    assert controls["human_review"]["failure_class"] == "adapter_error"
    assert controls["codeql_alerts"]["failure_class"] == "timeout"
    assert controls["private_security_exception_state"]["status"] == "passed"


def test_coordinator_rejects_custom_adapter_results_completed_after_deadline() -> None:
    adapters: list[RepositoryControlAdapter] = [
        _ProtocolPassingAdapter(control_id, source)
        for control_id, source in CONTROL_SOURCES.items()
    ]
    times = iter(
        (
            datetime(2026, 8, 14, 0, 0, 0, tzinfo=UTC),
            datetime(2026, 8, 14, 0, 0, 0, tzinfo=UTC),
        )
    )

    payload = collect_repository_control_observation(
        _request(timeout_seconds=1),
        adapters,
        clock=lambda: next(times),
        monotonic=_PostDeadlineMonotonic(),
        epoch_factory=lambda: "e" * 64,
    ).to_dict()

    controls = payload["controls"]
    assert isinstance(controls, list)
    assert [control["status"] for control in controls] == ["unavailable"] * len(CONTROL_SOURCES)
    assert {control["failure_class"] for control in controls} == {"timeout"}


def test_coordinator_isolates_a_malformed_custom_adapter_projection() -> None:
    adapters: list[RepositoryControlAdapter] = [
        _ProtocolPassingAdapter(control_id, source)
        for control_id, source in CONTROL_SOURCES.items()
    ]
    malformed_index = next(
        index
        for index, adapter in enumerate(adapters)
        if adapter.control_id == _MalformedProjectionAdapter.control_id
    )
    adapters[malformed_index] = _MalformedProjectionAdapter()
    times = iter(
        (
            datetime(2026, 8, 14, 0, 0, 0, tzinfo=UTC),
            datetime(2026, 8, 14, 0, 0, 0, tzinfo=UTC),
        )
    )

    payload = collect_repository_control_observation(
        _request(),
        adapters,
        clock=lambda: next(times),
        monotonic=lambda: 100.0,
        epoch_factory=lambda: "e" * 64,
    ).to_dict()

    controls = payload["controls"]
    assert isinstance(controls, list)
    assert controls[malformed_index]["status"] == "unavailable"
    assert controls[malformed_index]["failure_class"] == "adapter_error"
    assert [
        control["status"] for index, control in enumerate(controls) if index != malformed_index
    ] == ["passed"] * (len(CONTROL_SOURCES) - 1)


@requires_git
@requires_secure_package_platform
def test_package_adapters_observe_dependency_workflow_and_public_ledger_state(
    tmp_path: Path,
) -> None:
    workflows = tmp_path / ".github" / "workflows"
    workflows.mkdir(parents=True)
    (workflows / "security.yml").write_text(
        """\
on:
  pull_request:
permissions:
  contents: read
jobs:
  dependency-review:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@1111111111111111111111111111111111111111
      - uses: actions/dependency-review-action@2222222222222222222222222222222222222222
        with:
          fail-on-severity: low
          fail-on-scopes: runtime, development, unknown
          warn-only: false
          vulnerability-check: true
      - name: Literal marker is not an action reference
        run: 'echo "uses: example/unpinned@main"'
""",
        encoding="utf-8",
    )
    dependabot = tmp_path / ".github" / "dependabot.yml"
    dependabot.write_text(
        """\
version: 2
updates:
  - package-ecosystem: uv
    directory: /
    schedule:
      interval: weekly
    groups:
      security-only:
        applies-to: security-updates
        patterns: ["*"]
      compatible:
        patterns: ["*"]
        update-types: ["minor", "patch"]
""",
        encoding="utf-8",
    )
    _write_uv_lock(tmp_path)
    ledger = tmp_path / "docs" / "agents" / "security-exceptions.toml"
    ledger.parent.mkdir(parents=True)
    ledger.write_text(
        'artifact_kind = "security_exception_ledger"\nschema_version = "1.0"\n',
        encoding="utf-8",
    )
    candidate_sha = _commit_candidate(tmp_path)
    adapters: list[RepositoryControlAdapter] = list(build_package_control_adapters(tmp_path))
    package_ids = set(CONTROL_SOURCES) - {
        control_id for control_id, source in CONTROL_SOURCES.items() if source == "github"
    }
    assert {adapter.control_id for adapter in adapters} == package_ids
    for control_id, source in CONTROL_SOURCES.items():
        if source == "github":
            adapters.append(GitHubControlAdapter(control_id, _passing_reader(control_id, [])))
    times = iter(
        (
            datetime(2026, 8, 14, 0, 0, 0, tzinfo=UTC),
            datetime(2026, 8, 14, 0, 0, 20, tzinfo=UTC),
        )
    )

    payload = collect_repository_control_observation(
        _request(candidate_sha=candidate_sha),
        adapters,
        clock=lambda: next(times),
        monotonic=lambda: 100.0,
        epoch_factory=lambda: "e" * 64,
    ).to_dict()

    control_values = payload["controls"]
    assert isinstance(control_values, list)
    controls = {control["control_id"]: control for control in control_values}
    for control_id in package_ids:
        assert controls[control_id]["status"] == "passed", (
            control_id,
            controls[control_id],
        )


def test_package_adapter_builder_fails_closed_without_linux_descriptor_anchor(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        repository_control_adapters,
        "_secure_package_platform_available",
        lambda: False,
    )

    with pytest.raises(RepositoryObservationCoordinationError, match="Linux"):
        build_package_control_adapters(tmp_path)


@requires_git
@requires_secure_package_platform
def test_package_git_discovery_cannot_escape_the_anchored_candidate_root(
    tmp_path: Path,
) -> None:
    outer = tmp_path / "outer"
    candidate = outer / "candidate"
    root_dependabot = outer / ".github" / "dependabot.yml"
    candidate_dependabot = candidate / ".github" / "dependabot.yml"
    policy = """\
version: 2
updates:
  - package-ecosystem: uv
    directory: /
    schedule:
      interval: weekly
    groups:
      compatible:
        patterns: ["*"]
        update-types: ["minor", "patch"]
"""
    root_dependabot.parent.mkdir(parents=True)
    candidate_dependabot.parent.mkdir(parents=True)
    root_dependabot.write_text(policy, encoding="utf-8")
    candidate_dependabot.write_text(policy, encoding="utf-8")
    _write_uv_lock(outer)
    _write_uv_lock(candidate)
    candidate_sha = _commit_candidate(outer)
    adapter = {value.control_id: value for value in build_package_control_adapters(candidate)}[
        "dependabot_grouped_updates"
    ]

    observation = adapter.observe(_context(candidate_sha=candidate_sha))

    assert observation["status"] == "unavailable"
    assert observation["failure_class"] == "identity_mismatch"


@requires_secure_package_platform
def test_package_git_output_limit_interrupts_the_producer_before_timeout(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    (tmp_path / ".git").mkdir()
    fake_git = tmp_path / "git"
    fake_git.write_text(
        (
            "#!/bin/sh\n"
            "printf '%s' \"$$\" > git.pid\n"
            'cat "/proc/$$/stat" > git.stat\n'
            "head -c 1024 /dev/zero\n"
            "sleep 2\n"
        ),
        encoding="utf-8",
    )
    os.chmod(fake_git, 0o700)
    monkeypatch.setattr(repository_control_adapters, "_trusted_git_executable", lambda: fake_git)
    context = replace(_context(), deadline_remaining=lambda: 0.25)
    root_descriptor = os.open(tmp_path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        with pytest.raises(RepositoryControlReadError, match="malformed"):
            repository_control_adapters._run_git(
                root_descriptor,
                context,
                ("status",),
                maximum_output_bytes=8,
            )
        process_id = int((tmp_path / "git.pid").read_text(encoding="utf-8"))
        recorded_start_time = _proc_stat_start_time(
            (tmp_path / "git.stat").read_text(encoding="utf-8")
        )
        current_start_time = _linux_process_start_time(process_id)
        assert current_start_time is None or current_start_time != recorded_start_time
    finally:
        os.close(root_descriptor)


@requires_git
@requires_secure_package_platform
def test_package_git_checks_do_not_execute_candidate_fsmonitor(
    tmp_path: Path,
) -> None:
    workflow = tmp_path / ".github" / "workflows" / "validation.yml"
    workflow.parent.mkdir(parents=True)
    workflow.write_text(
        """\
on: push
jobs:
  validation:
    steps:
      - uses: actions/checkout@1111111111111111111111111111111111111111
""",
        encoding="utf-8",
    )
    candidate_sha = _commit_candidate(tmp_path)
    sentinel = tmp_path.parent / f"{tmp_path.name} fsmonitor executed"
    monitor = tmp_path.parent / f"{tmp_path.name}-fsmonitor"
    monitor.write_text(
        "#!/bin/sh\nprintf executed > " + shlex.quote(str(sentinel)) + "\nprintf '0\\n'\n",
        encoding="utf-8",
    )
    os.chmod(monitor, 0o700)
    subprocess.run(
        ("git", "-C", str(tmp_path), "config", "core.fsmonitor", str(monitor)),
        check=True,
        env=_ISOLATED_GIT_ENV,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    subprocess.run(
        ("git", "-C", str(tmp_path), "status", "--short"),
        check=True,
        env=_ISOLATED_GIT_ENV,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    assert sentinel.read_text(encoding="utf-8") == "executed"
    sentinel.unlink()
    adapter = {value.control_id: value for value in build_package_control_adapters(tmp_path)}[
        "immutable_action_pins"
    ]

    observation = adapter.observe(_context(candidate_sha=candidate_sha))

    assert observation["status"] == "passed"
    assert not sentinel.exists()


@requires_git
@requires_secure_package_platform
def test_package_git_checks_do_not_execute_candidate_clean_filters(
    tmp_path: Path,
) -> None:
    workflow = tmp_path / ".github" / "workflows" / "validation.yml"
    workflow.parent.mkdir(parents=True)
    workflow.write_text(
        """\
on: push
jobs:
  validation:
    steps:
      - uses: actions/checkout@1111111111111111111111111111111111111111
""",
        encoding="utf-8",
    )
    (tmp_path / ".gitattributes").write_text(
        ".github/workflows/*.yml filter=candidate-sentinel\n",
        encoding="utf-8",
    )
    candidate_sha = _commit_candidate(tmp_path)
    sentinel = tmp_path.parent / f"{tmp_path.name}-clean-filter-executed"
    filter_program = tmp_path.parent / f"{tmp_path.name}-clean-filter"
    filter_program.write_text(
        "#!/bin/sh\nprintf executed > " + shlex.quote(str(sentinel)) + "\ncat\n",
        encoding="utf-8",
    )
    os.chmod(filter_program, 0o700)
    subprocess.run(
        (
            "git",
            "-C",
            str(tmp_path),
            "config",
            "filter.candidate-sentinel.clean",
            str(filter_program),
        ),
        check=True,
        env=_ISOLATED_GIT_ENV,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    subprocess.run(
        (
            "git",
            "-C",
            str(tmp_path),
            "add",
            "--renormalize",
            "--",
            ".github/workflows",
        ),
        check=True,
        env=_ISOLATED_GIT_ENV,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    assert sentinel.read_text(encoding="utf-8") == "executed"
    sentinel.unlink()
    adapter = {value.control_id: value for value in build_package_control_adapters(tmp_path)}[
        "immutable_action_pins"
    ]

    observation = adapter.observe(_context(candidate_sha=candidate_sha))

    assert observation["status"] == "passed"
    assert not sentinel.exists()


@requires_git
@requires_secure_package_platform
def test_action_pins_include_transitive_local_composite_action_references(
    tmp_path: Path,
) -> None:
    workflow = tmp_path / ".github" / "workflows" / "validation.yml"
    workflow.parent.mkdir(parents=True)
    workflow.write_text(
        """\
on: push
jobs:
  validation:
    steps:
      - uses: ./.github/actions/local
""",
        encoding="utf-8",
    )
    action = tmp_path / ".github" / "actions" / "local" / "action.yml"
    action.parent.mkdir(parents=True)
    action.write_text(
        """\
name: Local composite
runs:
  using: composite
  steps:
    - uses: actions/checkout@main
""",
        encoding="utf-8",
    )
    candidate_sha = _commit_candidate(tmp_path)
    adapter = {value.control_id: value for value in build_package_control_adapters(tmp_path)}[
        "immutable_action_pins"
    ]

    observation = adapter.observe(_context(candidate_sha=candidate_sha))

    assert observation["status"] == "failed"


@requires_git
@requires_secure_package_platform
def test_action_pins_reject_a_mutable_local_docker_action_base(tmp_path: Path) -> None:
    workflow = tmp_path / ".github" / "workflows" / "validation.yml"
    workflow.parent.mkdir(parents=True)
    workflow.write_text(
        """\
on: push
jobs:
  validation:
    steps:
      - uses: ./.github/actions/local-docker
""",
        encoding="utf-8",
    )
    action_directory = tmp_path / ".github" / "actions" / "local-docker"
    action_directory.mkdir(parents=True)
    (action_directory / "action.yml").write_text(
        """\
name: Local Docker action
runs:
  using: docker
  image: Dockerfile
""",
        encoding="utf-8",
    )
    (action_directory / "Dockerfile").write_text(
        "FROM alpine:latest\n",
        encoding="utf-8",
    )
    candidate_sha = _commit_candidate(tmp_path)
    adapter = {value.control_id: value for value in build_package_control_adapters(tmp_path)}[
        "immutable_action_pins"
    ]

    observation = adapter.observe(_context(candidate_sha=candidate_sha))

    assert observation["status"] == "failed"


@requires_git
@requires_secure_package_platform
def test_action_pins_accept_a_digest_pinned_local_docker_action_base(tmp_path: Path) -> None:
    observation = _observe_local_docker_action(
        tmp_path,
        dockerfile="FROM alpine@sha256:" + "1" * 64 + "\n",
    )

    assert observation["status"] == "passed"


@requires_git
@requires_secure_package_platform
@pytest.mark.parametrize(
    "copy_instruction",
    (
        "COPY --from=registry.example.invalid/tool:latest /tool /tool",
        ('COPY --chown=0:0 --from=registry.example.invalid/tool:latest ["/tool", "/tool"]'),
    ),
    ids=("shell-form", "json-form-after-flag"),
)
def test_action_pins_reject_a_mutable_external_copy_source(
    tmp_path: Path,
    copy_instruction: str,
) -> None:
    observation = _observe_local_docker_action(
        tmp_path,
        dockerfile=("FROM alpine@sha256:" + "1" * 64 + f"\n{copy_instruction}\n"),
    )

    assert observation["status"] == "failed"


@pytest.mark.parametrize(
    "dockerfile",
    (
        (
            "FROM alpine@sha256:"
            + "1" * 64
            + "\nCOPY --from=registry.example.invalid/tool@sha256:"
            + "2" * 64
            + " /tool /tool\n"
        ),
        (
            "FROM alpine@sha256:"
            + "1" * 64
            + "\ncOpY --link --from=registry.example.invalid/tool@sha256:"
            + "2" * 64
            + ' ["/tool", "/tool"]\n'
        ),
        ("FROM alpine@sha256:" + "1" * 64 + "\nCOPY --from=ScRaTcH /tool /tool\n"),
        (
            "FROM alpine@sha256:"
            + "1" * 64
            + " AS Tool\nFROM alpine@sha256:"
            + "2" * 64
            + "\nCOPY --from=tOoL /tool /tool\n"
        ),
        (
            "FROM alpine@sha256:"
            + "1" * 64
            + " AS Tool\nFROM alpine@sha256:"
            + "2" * 64
            + "\nCOPY --from=0 /tool /tool\n"
        ),
        (
            "FROM alpine@sha256:"
            + "1" * 64
            + "\nCOPY source /destination\n"
            + 'COPY ["source", "/destination"]\n'
        ),
    ),
    ids=(
        "digest-pinned-shell",
        "digest-pinned-json-after-flag",
        "scratch",
        "prior-named-stage-case-insensitive",
        "prior-numeric-stage",
        "copy-without-external-source",
    ),
)
@requires_git
@requires_secure_package_platform
def test_action_pins_accept_immutable_or_local_copy_sources(
    tmp_path: Path,
    dockerfile: str,
) -> None:
    observation = _observe_local_docker_action(tmp_path, dockerfile=dockerfile)

    assert observation["status"] == "passed"


@pytest.mark.parametrize(
    "copy_source",
    (
        "$TOOL_IMAGE",
        "${TOOL_IMAGE}",
        "${TOOL_IMAGE}@sha256:" + "2" * 64,
    ),
    ids=("short-variable", "braced-variable", "variable-with-digest"),
)
@requires_git
@requires_secure_package_platform
def test_action_pins_reject_variable_external_copy_sources(
    tmp_path: Path,
    copy_source: str,
) -> None:
    observation = _observe_local_docker_action(
        tmp_path,
        dockerfile=(
            "FROM alpine@sha256:" + "1" * 64 + f"\nCOPY --from={copy_source} /tool /tool\n"
        ),
    )

    assert observation["status"] == "failed"


@pytest.mark.parametrize(
    "copy_instruction",
    (
        "CoPy --from=registry.example.invalid/tool:latest /tool /tool",
        (
            "COPY --from=registry.example.invalid/tool@sha256:"
            + "2" * 64
            + " --from=registry.example.invalid/tool:latest /tool /tool"
        ),
    ),
    ids=("mixed-case-instruction", "duplicate-from-flags"),
)
@requires_git
@requires_secure_package_platform
def test_action_pins_reject_alternate_mutable_copy_source_forms(
    tmp_path: Path,
    copy_instruction: str,
) -> None:
    observation = _observe_local_docker_action(
        tmp_path,
        dockerfile=("FROM alpine@sha256:" + "1" * 64 + f"\n{copy_instruction}\n"),
    )

    assert observation["status"] == "failed"


@requires_git
@requires_secure_package_platform
def test_action_pins_reject_a_forward_copy_stage_alias_collision(tmp_path: Path) -> None:
    observation = _observe_local_docker_action(
        tmp_path,
        dockerfile=(
            "FROM alpine@sha256:"
            + "1" * 64
            + " AS initial\nCOPY --from=Builder /tool /tool\n"
            + "FROM alpine@sha256:"
            + "2" * 64
            + " AS builder\n"
        ),
    )

    assert observation["status"] == "failed"


@pytest.mark.parametrize(
    "copy_source",
    ("Tool", "0"),
    ids=("current-stage-alias", "current-stage-index"),
)
@requires_git
@requires_secure_package_platform
def test_action_pins_reject_copy_sources_from_the_current_stage(
    tmp_path: Path,
    copy_source: str,
) -> None:
    observation = _observe_local_docker_action(
        tmp_path,
        dockerfile=(
            "FROM alpine@sha256:" + "1" * 64 + f" AS Tool\nCOPY --from={copy_source} /tool /tool\n"
        ),
    )

    assert observation["status"] == "failed"


@requires_git
@requires_secure_package_platform
@pytest.mark.parametrize(
    "run_instruction",
    (
        ("RUN --mount=type=bind,from=registry.example.invalid/tool:latest,target=/tool true"),
        (
            "rUn --network=none "
            '--mount="type=bind,from=registry.example.invalid/tool:latest,target=/tool" '
            '["true"]'
        ),
    ),
    ids=("shell-form", "json-form-after-flag"),
)
def test_action_pins_reject_a_mutable_external_run_mount_source(
    tmp_path: Path,
    run_instruction: str,
) -> None:
    observation = _observe_local_docker_action(
        tmp_path,
        dockerfile=("FROM alpine@sha256:" + "1" * 64 + f"\n{run_instruction}\n"),
    )

    assert observation["status"] == "failed"


@pytest.mark.parametrize(
    "dockerfile",
    (
        (
            "FROM alpine@sha256:"
            + "1" * 64
            + "\nRUN --mount=type=bind,from=registry.example.invalid/tool@sha256:"
            + "2" * 64
            + ",target=/tool true\n"
        ),
        (
            "FROM alpine@sha256:"
            + "1" * 64
            + " AS Tool\nFROM alpine@sha256:"
            + "2" * 64
            + "\nRUN --mount=from=tOoL,type=bind,target=/tool true\n"
        ),
        ("FROM alpine@sha256:" + "1" * 64 + "\nRUN --mount=type=cache,target=/cache true\n"),
    ),
    ids=(
        "digest-pinned-external",
        "prior-named-stage-case-insensitive",
        "mount-without-source",
    ),
)
@requires_git
@requires_secure_package_platform
def test_action_pins_accept_immutable_or_local_run_mount_sources(
    tmp_path: Path,
    dockerfile: str,
) -> None:
    observation = _observe_local_docker_action(tmp_path, dockerfile=dockerfile)

    assert observation["status"] == "passed"


@pytest.mark.parametrize(
    "dockerfile",
    (
        (
            "FROM alpine@sha256:"
            + "1" * 64
            + "\nRUN --mount=type=bind,from=${TOOL_IMAGE},target=/tool true\n"
        ),
        (
            "FROM alpine@sha256:"
            + "1" * 64
            + "\nRUN --mount=type=bind,from=scratch,target=/tool true\n"
        ),
        (
            "FROM alpine@sha256:"
            + "1" * 64
            + " AS Tool\nRUN --mount=from=0,type=bind,target=/tool true\n"
        ),
        (
            "FROM alpine@sha256:"
            + "1" * 64
            + " AS initial\nRUN --mount=from=Builder,type=bind,target=/tool true\n"
            + "FROM alpine@sha256:"
            + "2" * 64
            + " AS builder\n"
        ),
        (
            "FROM alpine@sha256:"
            + "1" * 64
            + " AS Tool\nRUN --mount=from=tOoL,type=bind,target=/tool true\n"
        ),
        (
            "FROM alpine@sha256:"
            + "1" * 64
            + " AS 0\nFROM alpine@sha256:"
            + "2" * 64
            + "\nRUN --mount=from=0,type=bind,target=/tool true\n"
        ),
        (
            "FROM alpine@sha256:"
            + "1" * 64
            + "\nRUN --mount=from=registry.example.invalid/tool@sha256:"
            + "2" * 64
            + ",from=registry.example.invalid/tool:latest,target=/tool true\n"
        ),
    ),
    ids=(
        "variable",
        "scratch",
        "numeric-stage-index",
        "forward-stage-alias",
        "current-stage-alias",
        "numeric-stage-alias",
        "duplicate-from-fields",
    ),
)
@requires_git
@requires_secure_package_platform
def test_action_pins_reject_ambiguous_run_mount_sources(
    tmp_path: Path,
    dockerfile: str,
) -> None:
    observation = _observe_local_docker_action(tmp_path, dockerfile=dockerfile)

    assert observation["status"] == "failed"


@pytest.mark.parametrize(
    "onbuild_instruction",
    (
        "ONBUILD COPY --from=registry.example.invalid/tool:latest /tool /tool",
        (
            "ONBUILD RUN --mount=type=bind,from=registry.example.invalid/tool:latest,"
            "target=/tool true"
        ),
    ),
    ids=("copy", "run-mount"),
)
@requires_git
@requires_secure_package_platform
def test_action_pins_reject_repository_visible_onbuild_instructions(
    tmp_path: Path,
    onbuild_instruction: str,
) -> None:
    observation = _observe_local_docker_action(
        tmp_path,
        dockerfile=("FROM alpine@sha256:" + "1" * 64 + f"\n{onbuild_instruction}\n"),
    )

    assert observation["status"] == "failed"


@pytest.mark.parametrize(
    "add_instructions",
    (
        "ADD https://downloads.example.invalid/tool.tar /opt/tool/",
        'ADD ["https://downloads.example.invalid/tool.tar", "/opt/tool/"]',
        "ADD git://github.example.invalid/team/tool.git /src/tool/",
        "ADD ssh://git@github.example.invalid/team/tool.git /src/tool/",
        (
            "ADD --checksum=sha256:"
            + "2" * 64
            + " https://downloads.example.invalid/tool.tar /opt/tool/"
        ),
        "ARG TOOL_SOURCE\nADD ${TOOL_SOURCE} /opt/tool/",
        "aDd local.tar /opt/tool/",
        'ADD ["local.tar", "/opt/tool/"]',
    ),
    ids=(
        "https-shell",
        "https-json",
        "git",
        "ssh",
        "checksum-https",
        "arg-expanded",
        "local-shell",
        "local-json",
    ),
)
@requires_git
@requires_secure_package_platform
def test_action_pins_reject_all_repository_visible_add_instructions(
    tmp_path: Path,
    add_instructions: str,
) -> None:
    observation = _observe_local_docker_action(
        tmp_path,
        dockerfile=("FROM alpine@sha256:" + "1" * 64 + f"\n{add_instructions}\n"),
    )

    assert observation["status"] == "failed"


@pytest.mark.parametrize(
    "copy_instructions",
    (
        'COPY --from="registry.example.invalid/tool:latest" /tool /tool',
        ('COPY --from="registry.example.invalid/tool@sha256:' + "2" * 64 + '" /tool /tool'),
        (
            "COPY --from=registry.example.invalid/tool@sha256:"
            + "2" * 64
            + " /tool /tool\n"
            + "COPY --from=registry.example.invalid/other:latest /other /other"
        ),
        "COPY --from= /tool /tool",
        "COPY --from /tool /tool",
        ('COPY --from="registry.example.invalid/tool@sha256:' + "2" * 64 + " /tool /tool"),
    ),
    ids=(
        "quoted-mutable",
        "quoted-pinned",
        "second-copy-mutable",
        "empty-source",
        "missing-equals",
        "unterminated-quote",
    ),
)
@requires_git
@requires_secure_package_platform
def test_action_pins_reject_copy_source_grammar_bypasses(
    tmp_path: Path,
    copy_instructions: str,
) -> None:
    observation = _observe_local_docker_action(
        tmp_path,
        dockerfile=("FROM alpine@sha256:" + "1" * 64 + f"\n{copy_instructions}\n"),
    )

    assert observation["status"] == "failed"


@pytest.mark.parametrize(
    "run_instruction",
    (
        (
            "RUN --mount=type=bind,from=registry.example.invalid/tool@sha256:"
            + "2" * 64
            + ",target=/tool "
            + "--mount=type=bind,from=registry.example.invalid/other:latest,target=/other "
            + "true"
        ),
        "RUN --mount= true",
        "RUN --mount=type=bind,from=,target=/tool true",
        "RUN --mount type=bind,from=registry.example.invalid/tool:latest true",
        (
            'RUN --mount="type=bind,from=registry.example.invalid/tool@sha256:'
            + "2" * 64
            + ',target=/tool" ["true"]'
        ),
        (
            'RUN --mount="type=bind,from=registry.example.invalid/tool@sha256:'
            + "2" * 64
            + ",target=/tool' true"
        ),
    ),
    ids=(
        "second-mount-mutable",
        "empty-mount",
        "empty-source",
        "missing-equals",
        "quoted-pinned",
        "mismatched-quotes",
    ),
)
@requires_git
@requires_secure_package_platform
def test_action_pins_reject_run_mount_source_grammar_bypasses(
    tmp_path: Path,
    run_instruction: str,
) -> None:
    observation = _observe_local_docker_action(
        tmp_path,
        dockerfile=("FROM alpine@sha256:" + "1" * 64 + f"\n{run_instruction}\n"),
    )

    assert observation["status"] == "failed"


@pytest.mark.parametrize(
    "dockerfile",
    (
        (
            "FROM alpine@sha256:"
            + "1" * 64
            + '\nCOPY --fr"om"=registry.example.invalid/tool:latest /tool /tool\n'
        ),
        (
            "FROM alpine@sha256:"
            + "1" * 64
            + "\nCOPY --fro\\m=registry.example.invalid/tool:latest /tool /tool\n"
        ),
        (
            "FROM alpine@sha256:"
            + "1" * 64
            + '\nCOPY --from"="registry.example.invalid/tool:latest /tool /tool\n'
        ),
        (
            "FROM alpine@sha256:"
            + "1" * 64
            + "\nCOPY --from\\=registry.example.invalid/tool:latest /tool /tool\n"
        ),
        (
            "FROM alpine@sha256:"
            + "1" * 64
            + '\nRUN --mo"unt"=type=bind,from=registry.example.invalid/tool:latest,'
            + "target=/tool true\n"
        ),
        (
            "FROM alpine@sha256:"
            + "1" * 64
            + "\nRUN --mo\\unt=type=bind,from=registry.example.invalid/tool:latest,"
            + "target=/tool true\n"
        ),
        (
            "FROM alpine@sha256:"
            + "1" * 64
            + '\nRUN --mount"="type=bind,from=registry.example.invalid/tool:latest,'
            + "target=/tool true\n"
        ),
        (
            "FROM alpine@sha256:"
            + "1" * 64
            + '\nRUN --mount=type=bind,fr"om"=registry.example.invalid/tool:latest,'
            + "target=/tool true\n"
        ),
        (
            "FROM alpine@sha256:"
            + "1" * 64
            + "\nRUN --mount=type=bind,fro\\m=registry.example.invalid/tool:latest,"
            + "target=/tool true\n"
        ),
        (
            "FROM alpine@sha256:"
            + "1" * 64
            + '\nRUN --mount=type=bind,from"="registry.example.invalid/tool:latest,'
            + "target=/tool true\n"
        ),
        (
            "# escape=`\nFROM alpine@sha256:"
            + "1" * 64
            + "\nCOPY --fro`m=registry.example.invalid/tool:latest /tool /tool\n"
        ),
        (
            "# escape=`\nFROM alpine@sha256:"
            + "1" * 64
            + "\nRUN --mo`unt=type=bind,from=registry.example.invalid/tool:latest,"
            + "target=/tool true\n"
        ),
        (
            "# escape=`\nFROM alpine@sha256:"
            + "1" * 64
            + "\nRUN --mount=type=bind,fro`m=registry.example.invalid/tool:latest,"
            + "target=/tool true\n"
        ),
    ),
    ids=(
        "copy-quoted-flag-name",
        "copy-escaped-flag-name",
        "copy-quoted-equals",
        "copy-escaped-equals",
        "run-quoted-mount-flag-name",
        "run-escaped-mount-flag-name",
        "run-quoted-mount-equals",
        "run-quoted-from-key",
        "run-escaped-from-key",
        "run-quoted-from-equals",
        "copy-configured-escape-flag-name",
        "run-configured-escape-mount-flag-name",
        "run-configured-escape-from-key",
    ),
)
@requires_git
@requires_secure_package_platform
def test_action_pins_reject_buildkit_flag_lexing_bypasses(
    tmp_path: Path,
    dockerfile: str,
) -> None:
    observation = _observe_local_docker_action(tmp_path, dockerfile=dockerfile)

    assert observation["status"] == "failed"


@pytest.mark.parametrize(
    "dockerfile",
    (
        ("F\\\nROM registry.example.invalid/base:latest\nFROM alpine@sha256:" + "1" * 64 + "\n"),
        (
            "FROM alpine@sha256:"
            + "1" * 64
            + "\nONB\\\nUILD COPY --from=registry.example.invalid/tool:latest /tool /tool\n"
        ),
        (
            "FROM alpine@sha256:"
            + "1" * 64
            + "\nC\\\nOPY --from=registry.example.invalid/tool:latest /tool /tool\n"
        ),
        (
            "FROM alpine@sha256:"
            + "1" * 64
            + "\nCOPY --fr\\\nom=registry.example.invalid/tool:latest /tool /tool\n"
        ),
        (
            "FROM alpine@sha256:"
            + "1" * 64
            + "\nRUN --mo\\\nunt=type=bind,from=registry.example.invalid/tool:latest,"
            + "target=/tool true\n"
        ),
        (
            "# escape=`\nF`\nROM registry.example.invalid/base:latest\nFROM alpine@sha256:"
            + "1" * 64
            + "\n"
        ),
        (
            "# escape=`\nFROM alpine@sha256:"
            + "1" * 64
            + "\nONB`\nUILD COPY --from=registry.example.invalid/tool:latest /tool /tool\n"
        ),
        (
            "# escape=`\nFROM alpine@sha256:"
            + "1" * 64
            + "\nC`\nOPY --from=registry.example.invalid/tool:latest /tool /tool\n"
        ),
        (
            "# escape=`\nFROM alpine@sha256:"
            + "1" * 64
            + "\nCOPY --fr`\nom=registry.example.invalid/tool:latest /tool /tool\n"
        ),
        (
            "# escape=`\nFROM alpine@sha256:"
            + "1" * 64
            + "\nRUN --mo`\nunt=type=bind,from=registry.example.invalid/tool:latest,"
            + "target=/tool true\n"
        ),
    ),
    ids=(
        "backslash-from-instruction",
        "backslash-onbuild-instruction",
        "backslash-copy-instruction",
        "backslash-copy-flag",
        "backslash-run-mount-flag",
        "backtick-from-instruction",
        "backtick-onbuild-instruction",
        "backtick-copy-instruction",
        "backtick-copy-flag",
        "backtick-run-mount-flag",
    ),
)
@requires_git
@requires_secure_package_platform
def test_action_pins_reject_buildkit_continuation_token_bypasses(
    tmp_path: Path,
    dockerfile: str,
) -> None:
    observation = _observe_local_docker_action(tmp_path, dockerfile=dockerfile)

    assert observation["status"] == "unavailable"
    assert observation["failure_class"] == "malformed"


@pytest.mark.parametrize(
    "continued_instruction",
    (
        ("COPY --chown=0:0 \\\n  --from=registry.example.invalid/tool:latest \\\n  /tool /tool"),
        (
            "RUN --network=none \\\n"
            "  --mount=type=bind,from=registry.example.invalid/tool:latest,target=/tool \\\n"
            "  true"
        ),
    ),
    ids=("copy", "run-mount"),
)
@requires_git
@requires_secure_package_platform
def test_action_pins_reject_separated_token_dockerfile_continuations(
    tmp_path: Path,
    continued_instruction: str,
) -> None:
    observation = _observe_local_docker_action(
        tmp_path,
        dockerfile=("FROM alpine@sha256:" + "1" * 64 + f"\n{continued_instruction}\n"),
    )

    assert observation["status"] == "unavailable"
    assert observation["failure_class"] == "malformed"


@pytest.mark.parametrize(
    ("parser_directive", "escape_sequence"),
    (
        ("", "\\" * 2),
        ("", "\\" * 3),
        ("# escape=`\n", "`" * 2),
        ("# escape=`\n", "`" * 3),
    ),
    ids=(
        "backslash-even",
        "backslash-odd-repeated",
        "backtick-even",
        "backtick-odd-repeated",
    ),
)
@requires_git
@requires_secure_package_platform
def test_action_pins_reject_repeated_terminal_dockerfile_escapes(
    tmp_path: Path,
    parser_directive: str,
    escape_sequence: str,
) -> None:
    observation = _observe_local_docker_action(
        tmp_path,
        dockerfile=(
            parser_directive
            + "FROM alpine@sha256:"
            + "1" * 64
            + "\nLABEL key=value"
            + escape_sequence
            + "\nCOPY --from=registry.example.invalid/tool:latest /x /x\n"
        ),
    )

    assert observation["status"] == "unavailable"
    assert observation["failure_class"] == "malformed"


@requires_git
@requires_secure_package_platform
def test_action_pin_evidence_binds_the_local_dockerfile_path_and_content(
    tmp_path: Path,
) -> None:
    observation = _observe_local_docker_action(
        tmp_path,
        dockerfile="FROM alpine@sha256:" + "1" * 64 + "\n",
    )

    evidence_paths = (
        Path(".github/actions/local-docker/Dockerfile"),
        Path(".github/actions/local-docker/action.yml"),
        Path(".github/workflows/validation.yml"),
    )
    document_identities = [
        {
            "path": path.as_posix(),
            "sha256": hashlib.sha256((tmp_path / path).read_bytes()).hexdigest(),
        }
        for path in sorted(evidence_paths)
    ]
    fixture_provenance_opaque_id = (
        "workflow-set:"
        + hashlib.sha256(
            json.dumps(
                document_identities,
                ensure_ascii=False,
                allow_nan=False,
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8")
        ).hexdigest()
    )
    expected_opaque_id = (
        "workflow-set:a84b3809d795c09891a5c50520224675636c2ca8982deccb204f520d23648ef1"
    )

    assert fixture_provenance_opaque_id == expected_opaque_id, (
        "local Docker evidence fixture changed; review its path-and-hash provenance "
        f"before updating the compatibility golden: {document_identities!r}"
    )
    assert observation["opaque_ids"] == [expected_opaque_id]


@pytest.mark.parametrize(
    "instruction_template",
    (
        "COPY --from=registry.example.invalid/tool@sha256:{digest} /tool /tool",
        (
            "RUN --mount=type=bind,from=registry.example.invalid/tool@sha256:{digest},"
            "target=/tool true"
        ),
    ),
    ids=("copy-source", "run-mount-source"),
)
@requires_git
@requires_secure_package_platform
def test_action_pin_evidence_binds_external_dockerfile_materialization_sources(
    tmp_path: Path,
    instruction_template: str,
) -> None:
    base = "FROM alpine@sha256:" + "1" * 64 + "\n"
    first = _observe_local_docker_action(
        tmp_path / "first",
        dockerfile=base + instruction_template.format(digest="2" * 64) + "\n",
    )
    second = _observe_local_docker_action(
        tmp_path / "second",
        dockerfile=base + instruction_template.format(digest="3" * 64) + "\n",
    )

    assert first["status"] == "passed"
    assert second["status"] == "passed"
    assert first["opaque_ids"] != second["opaque_ids"]


@requires_git
@requires_secure_package_platform
def test_action_pins_accept_scratch_as_a_local_docker_action_base(tmp_path: Path) -> None:
    observation = _observe_local_docker_action(
        tmp_path,
        dockerfile="FROM ScRaTcH\n",
    )

    assert observation["status"] == "passed"


@requires_git
@requires_secure_package_platform
def test_action_pins_accept_prior_named_local_docker_stages_case_insensitively(
    tmp_path: Path,
) -> None:
    observation = _observe_local_docker_action(
        tmp_path,
        dockerfile=(
            "FROM alpine@sha256:"
            + "1" * 64
            + " AS Builder\n"
            + "FROM bUiLdEr AS packaged\n"
            + "FROM PACKAGED\n"
        ),
    )

    assert observation["status"] == "passed"


@requires_git
@requires_secure_package_platform
def test_action_pins_resolve_a_relative_local_action_dockerfile(tmp_path: Path) -> None:
    observation = _observe_local_docker_action(
        tmp_path,
        image="./container/Dockerfile",
        dockerfile="FROM alpine@sha256:" + "1" * 64 + "\n",
    )

    assert observation["status"] == "passed"


@pytest.mark.parametrize(
    "dockerfile",
    (
        "FROM alpine\n",
        "ARG BASE\nFROM ${BASE}\n",
        "ARG BASE\nFROM ${BASE}@sha256:" + "1" * 64 + "\n",
        "FROM https://registry.example.invalid/base@sha256:" + "1" * 64 + "\n",
        "FROM --platform=linux/amd64 alpine@sha256:" + "1" * 64 + "\n",
        ("FROM later AS initial\nFROM alpine@sha256:" + "1" * 64 + " AS later\n"),
    ),
)
@requires_git
@requires_secure_package_platform
def test_action_pins_reject_ambiguous_local_docker_stage_bases(
    tmp_path: Path,
    dockerfile: str,
) -> None:
    observation = _observe_local_docker_action(tmp_path, dockerfile=dockerfile)

    assert observation["status"] == "failed"


@requires_git
@requires_secure_package_platform
def test_action_pins_reject_every_ambiguous_local_docker_stage(
    tmp_path: Path,
) -> None:
    observation = _observe_local_docker_action(
        tmp_path,
        dockerfile=(
            "FROM alpine@sha256:" + "1" * 64 + " AS safe\nFROM --platform=linux/amd64 safe\n"
        ),
    )

    assert observation["status"] == "failed"


@requires_git
@requires_secure_package_platform
def test_action_pins_reject_continued_local_docker_stages(tmp_path: Path) -> None:
    observation = _observe_local_docker_action(
        tmp_path,
        dockerfile=(
            "FROM alpine@sha256:"
            + "1" * 64
            + " \\\n"
            + "  AS Builder\n"
            + "FROM builder \\\n"
            + "  AS final\n"
        ),
    )

    assert observation["status"] == "unavailable"
    assert observation["failure_class"] == "malformed"


@requires_git
@requires_secure_package_platform
def test_action_pins_reject_a_mutable_local_dockerfile_syntax_frontend(
    tmp_path: Path,
) -> None:
    observation = _observe_local_docker_action(
        tmp_path,
        dockerfile=("# syntax=docker/dockerfile:1\nFROM alpine@sha256:" + "1" * 64 + "\n"),
    )

    assert observation["status"] == "failed"


@pytest.mark.parametrize(
    "dockerfile",
    (
        ("\ufeff# syntax=docker/dockerfile:1\nFROM alpine@sha256:" + "1" * 64 + "\n"),
        ("# check=skip=all\n# syntax=docker/dockerfile:1\nFROM alpine@sha256:" + "1" * 64 + "\n"),
        (
            "# check=skip=all\n"
            "# escape=`\n"
            "FROM alpine@sha256:" + "1" * 64 + "\nENV VALUE=\\\nFROM mutable:latest\n"
        ),
        ("   # escape=`\nFROM alpine@sha256:" + "1" * 64 + "\nENV VALUE=\\\nFROM mutable:latest\n"),
        (
            "#!/usr/bin/env dockerfile\n"
            "# syntax=docker/dockerfile:1\n"
            "FROM alpine@sha256:" + "1" * 64 + "\n"
        ),
        ("// syntax=docker/dockerfile:1\nFROM alpine@sha256:" + "1" * 64 + "\n"),
        ('{"syntax":"docker/dockerfile:1"}\nFROM alpine@sha256:' + "1" * 64 + "\n"),
        ("# syntax=docker/dockerfile:1 ignored-option\nFROM alpine@sha256:" + "1" * 64 + "\n"),
        ("# syntax=docker/dockerfile:1 # ignored\nFROM alpine@sha256:" + "1" * 64 + "\n"),
        ("# syntax = docker/dockerfile:1 // opts\nFROM alpine@sha256:" + "1" * 64 + "\n"),
        (
            "# check=skip=all // opts\n"
            "# syntax=docker/dockerfile:1\n"
            "FROM alpine@sha256:" + "1" * 64 + "\n"
        ),
    ),
    ids=(
        "utf8-bom",
        "check-before-syntax",
        "check-before-escape",
        "leading-whitespace-escape",
        "shebang-before-syntax",
        "slash-comment-syntax",
        "json-syntax",
        "syntax-command-line",
        "syntax-inline-comment",
        "syntax-slash-options",
        "check-command-line-before-syntax",
    ),
)
@requires_git
@requires_secure_package_platform
def test_action_pins_enforce_all_active_dockerfile_parser_directives(
    tmp_path: Path,
    dockerfile: str,
) -> None:
    observation = _observe_local_docker_action(
        tmp_path,
        dockerfile=dockerfile,
    )

    assert observation["status"] == "failed"


@requires_git
@requires_secure_package_platform
def test_action_pins_accept_a_pinned_syntax_frontend_with_a_command_line(
    tmp_path: Path,
) -> None:
    observation = _observe_local_docker_action(
        tmp_path,
        dockerfile=(
            "# syntax=docker/dockerfile:1@sha256:"
            + "2" * 64
            + " // opts\nFROM alpine@sha256:"
            + "1" * 64
            + "\n"
        ),
    )

    assert observation["status"] == "passed"


@requires_git
@requires_secure_package_platform
def test_action_pins_accept_pinned_syntax_and_declared_escape_directives(
    tmp_path: Path,
) -> None:
    observation = _observe_local_docker_action(
        tmp_path,
        dockerfile=(
            "# syntax=docker/dockerfile:1@sha256:"
            + "2" * 64
            + "\n# escape=`\n\n"
            + "FROM alpine@sha256:"
            + "1" * 64
            + " AS Builder\n"
            + "FROM builder\n"
        ),
    )

    assert observation["status"] == "passed"


@requires_git
@requires_secure_package_platform
def test_action_pins_reject_an_even_escaped_backslash_line_ending(
    tmp_path: Path,
) -> None:
    observation = _observe_local_docker_action(
        tmp_path,
        dockerfile=("FROM alpine@sha256:" + "1" * 64 + " \\\\\n  AS builder\n"),
    )

    assert observation["status"] == "unavailable"
    assert observation["failure_class"] == "malformed"


@pytest.mark.parametrize(
    "heredoc_instruction",
    (
        "RUN <<'SCRIPT'\nFROM mutable:latest\n# syntax=docker/dockerfile:latest\nSCRIPT",
        "RUN <<SCRIPT\nFROM mutable:latest\nSCRIPT",
        "COPY --from=registry.example.invalid/tool:latest <<EOF /tool\npayload\nEOF",
        (
            "RUN --mount=type=bind,from=registry.example.invalid/tool:latest,target=/tool "
            "<<EOF\ntrue\nEOF"
        ),
    ),
    ids=("quoted-run", "unquoted-run", "copy", "run-mount"),
)
@requires_git
@requires_secure_package_platform
def test_action_pins_reject_all_local_dockerfile_heredocs(
    tmp_path: Path,
    heredoc_instruction: str,
) -> None:
    observation = _observe_local_docker_action(
        tmp_path,
        dockerfile=("FROM alpine@sha256:" + "1" * 64 + f"\n{heredoc_instruction}\n"),
    )

    assert observation["status"] == "unavailable"
    assert observation["failure_class"] == "malformed"


@requires_git
@requires_secure_package_platform
def test_action_pins_fail_closed_before_an_ambiguous_heredoc_can_hide_copy(
    tmp_path: Path,
) -> None:
    observation = _observe_local_docker_action(
        tmp_path,
        dockerfile=(
            "FROM alpine@sha256:"
            + "1" * 64
            + "\nRUN echo ' <<EOF '\n"
            + "COPY --from=alpine:latest <<EOF /x\n"
            + "payload\n"
            + "EOF\n"
        ),
    )

    assert observation["status"] == "unavailable"
    assert observation["failure_class"] == "malformed"


@pytest.mark.parametrize(
    "dockerfile_suffix",
    (
        "RUN <<EOF\nFROM mutable:latest\n",
        "RUN <<$DYNAMIC\nDYNAMIC\n",
        "RUN echo continued \\\n",
        "RUN echo continued \\\n\nRUN true\n",
        "RUN echo '<<SCRIPT'\nFROM mutable:latest\nSCRIPT\n",
    ),
)
@requires_git
@requires_secure_package_platform
def test_action_pins_fail_closed_on_malformed_local_dockerfile_boundaries(
    tmp_path: Path,
    dockerfile_suffix: str,
) -> None:
    observation = _observe_local_docker_action(
        tmp_path,
        dockerfile="FROM alpine@sha256:" + "1" * 64 + "\n" + dockerfile_suffix,
    )

    assert observation["status"] == "unavailable"
    assert observation["failure_class"] == "malformed"


@requires_git
@requires_secure_package_platform
def test_action_pins_bound_the_cumulative_local_dockerfile_stage_count(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        repository_control_adapters,
        "MAX_DOCKERFILE_STAGES",
        1,
    )
    observation = _observe_local_docker_action(
        tmp_path,
        dockerfile=("FROM alpine@sha256:" + "1" * 64 + " AS builder\nFROM builder\n"),
    )

    assert observation["status"] == "unavailable"
    assert observation["failure_class"] == "malformed"


@pytest.mark.parametrize(
    ("bound_name", "expected_status", "expected_failure_class"),
    (
        ("MAX_LOCAL_DOCKERFILES", "unavailable", "malformed"),
        ("MAX_LOCAL_ACTIONS", "failed", None),
    ),
)
@requires_git
@requires_secure_package_platform
def test_action_pins_bound_local_action_and_dockerfile_traversal(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    bound_name: str,
    expected_status: str,
    expected_failure_class: str | None,
) -> None:
    workflow = tmp_path / ".github" / "workflows" / "validation.yml"
    workflow.parent.mkdir(parents=True)
    workflow.write_text(
        """\
on: push
jobs:
  validation:
    steps:
      - uses: ./.github/actions/first
      - uses: ./.github/actions/second
""",
        encoding="utf-8",
    )
    for action_name in ("first", "second"):
        action_directory = tmp_path / ".github" / "actions" / action_name
        action_directory.mkdir(parents=True)
        (action_directory / "action.yml").write_text(
            "name: Local Docker action\nruns:\n  using: docker\n  image: Dockerfile\n",
            encoding="utf-8",
        )
        (action_directory / "Dockerfile").write_text(
            "FROM alpine@sha256:" + "1" * 64 + "\n",
            encoding="utf-8",
        )
    candidate_sha = _commit_candidate(tmp_path)
    monkeypatch.setattr(
        repository_control_adapters,
        bound_name,
        1,
    )
    adapter = {value.control_id: value for value in build_package_control_adapters(tmp_path)}[
        "immutable_action_pins"
    ]

    observation = adapter.observe(_context(candidate_sha=candidate_sha))

    assert observation["status"] == expected_status
    assert observation.get("failure_class") == expected_failure_class


@pytest.mark.parametrize("image", ("./missing/Dockerfile", "./../Dockerfile"))
@requires_git
@requires_secure_package_platform
def test_action_pins_reject_missing_or_escaping_local_dockerfiles(
    tmp_path: Path,
    image: str,
) -> None:
    observation = _observe_local_docker_action(
        tmp_path,
        image=image,
        dockerfile=None,
    )

    assert observation["status"] == "failed"


@requires_git
@requires_secure_package_platform
def test_action_pins_fail_closed_without_reading_a_symlinked_local_dockerfile(
    tmp_path: Path,
) -> None:
    private_sentinel = "private-dockerfile-content-DO-NOT-PROJECT"
    workflow = tmp_path / ".github" / "workflows" / "validation.yml"
    workflow.parent.mkdir(parents=True)
    workflow.write_text(
        "on: push\njobs:\n  validation:\n    steps:\n"
        "      - uses: ./.github/actions/local-docker\n",
        encoding="utf-8",
    )
    action_directory = tmp_path / ".github" / "actions" / "local-docker"
    action_directory.mkdir(parents=True)
    (action_directory / "action.yml").write_text(
        "name: Local Docker action\nruns:\n  using: docker\n  image: Dockerfile\n",
        encoding="utf-8",
    )
    private_target = tmp_path / "private-target"
    private_target.write_text(private_sentinel, encoding="utf-8")
    (action_directory / "Dockerfile").symlink_to(private_target)
    candidate_sha = _commit_candidate(tmp_path)
    adapter = {value.control_id: value for value in build_package_control_adapters(tmp_path)}[
        "immutable_action_pins"
    ]

    observation = adapter.observe(_context(candidate_sha=candidate_sha))

    assert observation["status"] == "unavailable"
    assert observation["failure_class"] == "not_found_or_inaccessible"
    assert private_sentinel not in str(observation)


@requires_git
@requires_secure_package_platform
@pytest.mark.parametrize(
    ("initial_instruction", "mutated_instruction"),
    (
        (
            "COPY --from=registry.example.invalid/tool@sha256:" + "2" * 64 + " /tool /tool",
            "COPY --from=registry.example.invalid/tool:latest /tool /tool",
        ),
        (
            "RUN --mount=type=bind,from=registry.example.invalid/tool@sha256:"
            + "2" * 64
            + ",target=/tool true",
            ("RUN --mount=type=bind,from=registry.example.invalid/tool:latest,target=/tool true"),
        ),
    ),
    ids=("copy-source", "run-mount-source"),
)
def test_action_pins_reject_local_dockerfile_source_mutation_after_observation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    initial_instruction: str,
    mutated_instruction: str,
) -> None:
    workflow = tmp_path / ".github" / "workflows" / "validation.yml"
    workflow.parent.mkdir(parents=True)
    workflow.write_text(
        "on: push\njobs:\n  validation:\n    steps:\n"
        "      - uses: ./.github/actions/local-docker\n",
        encoding="utf-8",
    )
    action_directory = tmp_path / ".github" / "actions" / "local-docker"
    action_directory.mkdir(parents=True)
    (action_directory / "action.yml").write_text(
        "name: Local Docker action\nruns:\n  using: docker\n  image: Dockerfile\n",
        encoding="utf-8",
    )
    dockerfile = action_directory / "Dockerfile"
    dockerfile.write_text(
        "FROM alpine@sha256:" + "1" * 64 + f"\n{initial_instruction}\n",
        encoding="utf-8",
    )
    candidate_sha = _commit_candidate(tmp_path)
    original_observe = repository_control_adapters._observe_action_pins

    def observe_then_mutate(
        root_descriptor: int,
        context: ControlReadContext,
    ) -> tuple[bool, list[str], tuple[str, ...]]:
        result = original_observe(root_descriptor, context)
        dockerfile.write_text(
            "FROM alpine@sha256:" + "1" * 64 + f"\n{mutated_instruction}\n",
            encoding="utf-8",
        )
        return result

    monkeypatch.setattr(
        repository_control_adapters,
        "_observe_action_pins",
        observe_then_mutate,
    )
    adapter = {value.control_id: value for value in build_package_control_adapters(tmp_path)}[
        "immutable_action_pins"
    ]

    observation = adapter.observe(_context(candidate_sha=candidate_sha))

    assert observation["status"] == "unavailable"
    assert observation["failure_class"] == "identity_mismatch"


@requires_git
@requires_secure_package_platform
def test_action_pin_documents_include_dockerfiles_in_the_cumulative_byte_budget(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    workflow_payload = b"""\
on: push
jobs:
  validation:
    steps:
      - uses: ./.github/actions/local-docker
"""
    action_payload = b"""\
name: Local Docker action
runs:
  using: docker
  image: Dockerfile
"""
    dockerfile_payload = b"FROM alpine@sha256:" + b"1" * 64 + b"\n"
    workflow = tmp_path / ".github" / "workflows" / "validation.yml"
    workflow.parent.mkdir(parents=True)
    workflow.write_bytes(workflow_payload)
    action_directory = tmp_path / ".github" / "actions" / "local-docker"
    action_directory.mkdir(parents=True)
    (action_directory / "action.yml").write_bytes(action_payload)
    (action_directory / "Dockerfile").write_bytes(dockerfile_payload)
    candidate_sha = _commit_candidate(tmp_path)
    monkeypatch.setattr(
        repository_control_adapters,
        "MAX_POLICY_DOCUMENT_BYTES",
        len(workflow_payload) + len(action_payload) + len(dockerfile_payload) - 1,
    )
    adapter = {value.control_id: value for value in build_package_control_adapters(tmp_path)}[
        "immutable_action_pins"
    ]

    observation = adapter.observe(_context(candidate_sha=candidate_sha))

    assert observation["status"] == "unavailable"
    assert observation["failure_class"] == "malformed"


@requires_git
@requires_secure_package_platform
def test_action_pin_documents_share_one_cumulative_byte_budget(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    workflow_payload = b"""\
on: push
jobs:
  validation:
    steps:
      - uses: ./.github/actions/local
"""
    action_payload = b"""\
name: Local composite
runs:
  using: composite
  steps:
    - uses: actions/checkout@1111111111111111111111111111111111111111
"""
    workflow = tmp_path / ".github" / "workflows" / "validation.yml"
    workflow.parent.mkdir(parents=True)
    workflow.write_bytes(workflow_payload)
    action = tmp_path / ".github" / "actions" / "local" / "action.yml"
    action.parent.mkdir(parents=True)
    action.write_bytes(action_payload)
    candidate_sha = _commit_candidate(tmp_path)
    monkeypatch.setattr(
        repository_control_adapters,
        "MAX_POLICY_DOCUMENT_BYTES",
        max(len(workflow_payload), len(action_payload)),
    )
    adapter = {value.control_id: value for value in build_package_control_adapters(tmp_path)}[
        "immutable_action_pins"
    ]

    observation = adapter.observe(_context(candidate_sha=candidate_sha))

    assert observation["status"] == "unavailable"
    assert observation["failure_class"] == "malformed"


@requires_git
@requires_secure_package_platform
def test_workflow_set_remains_bound_when_a_tracked_file_disappears_after_preflight(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    workflow = tmp_path / ".github" / "workflows" / "validation.yml"
    workflow.parent.mkdir(parents=True)
    workflow.write_text(
        """\
on: push
jobs:
  validation:
    steps:
      - uses: actions/checkout@main
""",
        encoding="utf-8",
    )
    candidate_sha = _commit_candidate(tmp_path)
    original_verify = repository_control_adapters._verify_candidate_materialization
    removed = False

    def verify_then_remove(
        root_descriptor: int,
        context: ControlReadContext,
        paths: tuple[str, ...],
    ) -> None:
        nonlocal removed
        original_verify(root_descriptor, context, paths)
        if not removed:
            workflow.unlink()
            removed = True

    monkeypatch.setattr(
        repository_control_adapters,
        "_verify_candidate_materialization",
        verify_then_remove,
    )
    adapter = {value.control_id: value for value in build_package_control_adapters(tmp_path)}[
        "immutable_action_pins"
    ]

    observation = adapter.observe(_context(candidate_sha=candidate_sha))

    assert observation["status"] == "unavailable"
    assert observation["failure_class"] == "identity_mismatch"


@requires_git
@requires_secure_package_platform
def test_package_scope_rejects_worktree_mutation_after_the_control_read(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    dependabot = tmp_path / ".github" / "dependabot.yml"
    dependabot.parent.mkdir(parents=True)
    dependabot.write_text(
        """\
version: 2
updates:
  - package-ecosystem: uv
    directory: /
    schedule:
      interval: weekly
    groups:
      compatible:
        patterns: ["*"]
        update-types: ["minor", "patch"]
""",
        encoding="utf-8",
    )
    _write_uv_lock(tmp_path)
    candidate_sha = _commit_candidate(tmp_path)
    original_observe = repository_control_adapters._observe_dependabot_grouping

    def observe_then_mutate(
        root_descriptor: int,
        context: ControlReadContext,
    ) -> tuple[bool, list[str]]:
        result = original_observe(root_descriptor, context)
        dependabot.write_text("version: 2\nupdates: []\n", encoding="utf-8")
        return result

    monkeypatch.setattr(
        repository_control_adapters,
        "_observe_dependabot_grouping",
        observe_then_mutate,
    )
    adapter = {value.control_id: value for value in build_package_control_adapters(tmp_path)}[
        "dependabot_grouped_updates"
    ]

    observation = adapter.observe(_context(candidate_sha=candidate_sha))

    assert observation["status"] == "unavailable"
    assert observation["failure_class"] == "identity_mismatch"


@requires_git
@requires_secure_package_platform
def test_workflow_set_rejects_a_skip_worktree_candidate_omission(tmp_path: Path) -> None:
    workflows = tmp_path / ".github" / "workflows"
    workflows.mkdir(parents=True)
    (workflows / "good.yml").write_text(
        """\
on: push
jobs:
  validation:
    steps:
      - uses: actions/checkout@1111111111111111111111111111111111111111
""",
        encoding="utf-8",
    )
    hidden = workflows / "hidden.yml"
    hidden.write_text(
        """\
on: push
jobs:
  validation:
    steps:
      - uses: actions/checkout@main
""",
        encoding="utf-8",
    )
    candidate_sha = _commit_candidate(tmp_path)
    subprocess.run(
        (
            "git",
            "-C",
            str(tmp_path),
            "update-index",
            "--skip-worktree",
            ".github/workflows/hidden.yml",
        ),
        check=True,
        env=_ISOLATED_GIT_ENV,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    hidden.unlink()
    adapter = {value.control_id: value for value in build_package_control_adapters(tmp_path)}[
        "immutable_action_pins"
    ]

    observation = adapter.observe(_context(candidate_sha=candidate_sha))

    assert observation["status"] == "unavailable"
    assert observation["failure_class"] == "identity_mismatch"


@requires_git
@requires_secure_package_platform
def test_local_action_paths_are_literal_when_checking_index_materialization(
    tmp_path: Path,
) -> None:
    workflow = tmp_path / ".github" / "workflows" / "validation.yml"
    workflow.parent.mkdir(parents=True)
    workflow.write_text(
        "on: push\njobs:\n  validation:\n    steps:\n      - uses: ./:(literal)hidden\n",
        encoding="utf-8",
    )
    action = tmp_path / ":(literal)hidden" / "action.yml"
    action.parent.mkdir(parents=True)
    action.write_text(
        "name: Literal path action\nruns:\n  using: node20\n  main: index.js\n",
        encoding="utf-8",
    )
    candidate_sha = _commit_candidate(tmp_path)
    subprocess.run(
        (
            "git",
            "-C",
            str(tmp_path),
            "update-index",
            "--skip-worktree",
            "--",
            ":(literal)hidden/action.yml",
        ),
        check=True,
        env={**_ISOLATED_GIT_ENV, "GIT_LITERAL_PATHSPECS": "1"},
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    adapter = {value.control_id: value for value in build_package_control_adapters(tmp_path)}[
        "immutable_action_pins"
    ]

    observation = adapter.observe(_context(candidate_sha=candidate_sha))

    assert observation["status"] == "unavailable"
    assert observation["failure_class"] == "identity_mismatch"


@requires_git
@requires_secure_package_platform
def test_package_adapters_fail_closed_for_missing_or_symlinked_authority(tmp_path: Path) -> None:
    private_sentinel = "private-file-content-DO-NOT-PROJECT"
    workflows = tmp_path / ".github" / "workflows"
    workflows.mkdir(parents=True)
    target = tmp_path / "private-workflow.yml"
    target.write_text(private_sentinel, encoding="utf-8")
    (workflows / "security.yml").symlink_to(target)
    candidate_sha = _commit_candidate(tmp_path)
    adapters: list[RepositoryControlAdapter] = list(build_package_control_adapters(tmp_path))
    for control_id, source in CONTROL_SOURCES.items():
        if source == "github":
            adapters.append(GitHubControlAdapter(control_id, _passing_reader(control_id, [])))
    times = iter(
        (
            datetime(2026, 8, 14, 0, 0, 0, tzinfo=UTC),
            datetime(2026, 8, 14, 0, 0, 20, tzinfo=UTC),
        )
    )

    payload = collect_repository_control_observation(
        _request(candidate_sha=candidate_sha),
        adapters,
        clock=lambda: next(times),
        monotonic=lambda: 100.0,
        epoch_factory=lambda: "e" * 64,
    ).to_dict()

    control_values = payload["controls"]
    assert isinstance(control_values, list)
    controls = {control["control_id"]: control for control in control_values}
    assert controls["immutable_action_pins"]["failure_class"] == ("not_found_or_inaccessible")
    assert controls["dependency_review"]["failure_class"] == "not_found_or_inaccessible"
    assert controls["dependabot_grouped_updates"]["status"] == "failed"
    assert controls["public_security_exception_state"]["status"] == "failed"
    assert private_sentinel not in str(payload)


@requires_git
@requires_secure_package_platform
def test_package_policy_evidence_must_be_bound_to_the_matching_yaml_record(
    tmp_path: Path,
) -> None:
    workflows = tmp_path / ".github" / "workflows"
    workflows.mkdir(parents=True)
    (workflows / "security.yml").write_text(
        """\
on:
  pull_request:
permissions:
  contents: read
jobs:
  dependency-review:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/dependency-review-action@2222222222222222222222222222222222222222
      - name: Unrelated step
        with:
          fail-on-severity: low
          fail-on-scopes: runtime, development, unknown
          warn-only: false
          vulnerability-check: true
""",
        encoding="utf-8",
    )
    (tmp_path / ".github" / "dependabot.yml").write_text(
        """\
version: 2
updates:
  - package-ecosystem: uv
    directory: /
    schedule:
      interval: monthly
  - package-ecosystem: npm
    directory: /
    schedule:
      interval: weekly
    groups:
      compatible:
        patterns: ["*"]
        update-types: ["minor", "patch"]
""",
        encoding="utf-8",
    )
    _write_uv_lock(tmp_path)
    candidate_sha = _commit_candidate(tmp_path)
    adapters = {adapter.control_id: adapter for adapter in build_package_control_adapters(tmp_path)}

    dependency_review = adapters["dependency_review"].observe(_context(candidate_sha=candidate_sha))
    dependabot = adapters["dependabot_grouped_updates"].observe(
        _context(candidate_sha=candidate_sha)
    )

    assert dependency_review["status"] == "failed"
    assert dependabot["status"] == "failed"


@requires_git
@requires_secure_package_platform
def test_dependabot_compatible_fields_must_belong_to_the_same_group(
    tmp_path: Path,
) -> None:
    dependabot = tmp_path / ".github" / "dependabot.yml"
    dependabot.parent.mkdir(parents=True)
    dependabot.write_text(
        """\
version: 2
updates:
  - package-ecosystem: uv
    directory: /
    schedule:
      interval: weekly
    groups:
      broad-pattern:
        patterns: ["*"]
      compatible-types:
        update-types: ["minor", "patch"]
""",
        encoding="utf-8",
    )
    _write_uv_lock(tmp_path)
    candidate_sha = _commit_candidate(tmp_path)
    adapters = {adapter.control_id: adapter for adapter in build_package_control_adapters(tmp_path)}

    observation = adapters["dependabot_grouped_updates"].observe(
        _context(candidate_sha=candidate_sha)
    )

    assert observation["status"] == "failed"


@pytest.mark.parametrize(
    ("ecosystem", "include_lock"),
    (("pip", True), ("uv", False)),
)
@requires_git
@requires_secure_package_platform
def test_dependabot_grouping_binds_the_authoritative_uv_lock_graph(
    tmp_path: Path,
    ecosystem: str,
    include_lock: bool,
) -> None:
    dependabot = tmp_path / ".github" / "dependabot.yml"
    dependabot.parent.mkdir(parents=True)
    dependabot.write_text(
        "version: 2\nupdates:\n"
        + f"  - package-ecosystem: {ecosystem}\n"
        + "    directory: /\n"
        + "    schedule:\n      interval: weekly\n"
        + "    groups:\n      compatible:\n"
        + '        patterns: ["*"]\n'
        + '        update-types: ["minor", "patch"]\n',
        encoding="utf-8",
    )
    if include_lock:
        _write_uv_lock(tmp_path)
    candidate_sha = _commit_candidate(tmp_path)
    adapter = {value.control_id: value for value in build_package_control_adapters(tmp_path)}[
        "dependabot_grouped_updates"
    ]

    observation = adapter.observe(_context(candidate_sha=candidate_sha))

    assert observation["status"] == "failed"


@requires_git
@requires_secure_package_platform
def test_package_evidence_is_bound_to_the_claimed_candidate_commit(
    tmp_path: Path,
) -> None:
    dependabot = tmp_path / ".github" / "dependabot.yml"
    dependabot.parent.mkdir(parents=True)
    dependabot.write_text(
        "version: 2\nupdates: []\n",
        encoding="utf-8",
    )
    _write_uv_lock(tmp_path)
    first_sha = _commit_candidate(tmp_path)
    dependabot.write_text(
        "version: 2\nupdates:\n  - package-ecosystem: uv\n",
        encoding="utf-8",
    )
    second_sha = _commit_candidate(tmp_path)
    assert second_sha != first_sha
    adapter = {value.control_id: value for value in build_package_control_adapters(tmp_path)}[
        "dependabot_grouped_updates"
    ]

    observation = adapter.observe(_context(candidate_sha=first_sha))

    assert observation["status"] == "unavailable"
    assert observation["failure_class"] == "identity_mismatch"


@requires_git
@requires_secure_package_platform
def test_public_exception_control_rejects_malformed_or_confidential_records(
    tmp_path: Path,
) -> None:
    private_sentinel = "private-advisory-body-DO-NOT-PROJECT"
    ledger = tmp_path / "docs" / "agents" / "security-exceptions.toml"
    ledger.parent.mkdir(parents=True)
    ledger.write_text(
        "\n".join(
            (
                'artifact_kind = "security_exception_ledger"',
                'schema_version = "1.0"',
                "[[exceptions]]",
                f'secret = "{private_sentinel}"',
            )
        )
        + "\n",
        encoding="utf-8",
    )
    candidate_sha = _commit_candidate(tmp_path)
    adapter = {value.control_id: value for value in build_package_control_adapters(tmp_path)}[
        "public_security_exception_state"
    ]

    observation = adapter.observe(_context(candidate_sha=candidate_sha))

    assert observation["status"] == "failed"
    assert private_sentinel not in str(observation)


@requires_git
@requires_secure_package_platform
def test_dependency_review_requires_a_pr_triggered_enforcing_step(
    tmp_path: Path,
) -> None:
    workflow = tmp_path / ".github" / "workflows" / "security.yml"
    workflow.parent.mkdir(parents=True)
    workflow.write_text(
        """\
on: workflow_dispatch
true:
  pull_request: decoy
permissions:
  contents: read
env:
  pull_request: never
jobs:
  dependency-review:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/dependency-review-action@2222222222222222222222222222222222222222
        with:
          fail-on-severity: low
          fail-on-scopes: runtime, development, unknown
          warn-only: false
          vulnerability-check: true
""",
        encoding="utf-8",
    )
    candidate_sha = _commit_candidate(tmp_path)
    adapter = {value.control_id: value for value in build_package_control_adapters(tmp_path)}[
        "dependency_review"
    ]

    observation = adapter.observe(_context(candidate_sha=candidate_sha))

    assert observation["status"] == "failed"


@pytest.mark.parametrize(
    ("workflow_permissions", "job_permissions", "expected_status"),
    (
        ("permissions:\n  contents: read\n", "", "passed"),
        ("permissions: read-all\n", "", "passed"),
        ("permissions: {}\n", "    permissions:\n      contents: read\n", "passed"),
        ("", "", "failed"),
        ("permissions: {}\n", "", "failed"),
        ("permissions: write-all\n", "", "failed"),
        ("permissions:\n  pull-requests: write\n", "", "failed"),
        (
            "permissions:\n  contents: read\n",
            "    permissions: {}\n",
            "failed",
        ),
        (
            "permissions:\n  contents: read\n",
            "    permissions:\n      contents: write\n",
            "failed",
        ),
        (
            "permissions:\n  contents: read\n",
            "    permissions:\n      pull-requests: write\n",
            "failed",
        ),
    ),
)
@requires_git
@requires_secure_package_platform
def test_dependency_review_requires_effective_read_only_contents_permission(
    tmp_path: Path,
    workflow_permissions: str,
    job_permissions: str,
    expected_status: str,
) -> None:
    workflow = tmp_path / ".github" / "workflows" / "security.yml"
    workflow.parent.mkdir(parents=True)
    workflow.write_text(
        "on:\n  pull_request:\n"
        + workflow_permissions
        + "jobs:\n  dependency-review:\n    runs-on: ubuntu-latest\n"
        + job_permissions
        + "    steps:\n"
        + "      - uses: actions/dependency-review-action@"
        + "2222222222222222222222222222222222222222\n"
        + "        with:\n"
        + "          fail-on-severity: low\n"
        + "          fail-on-scopes: runtime, development, unknown\n"
        + "          warn-only: false\n"
        + "          vulnerability-check: true\n",
        encoding="utf-8",
    )
    candidate_sha = _commit_candidate(tmp_path)
    adapter = {value.control_id: value for value in build_package_control_adapters(tmp_path)}[
        "dependency_review"
    ]

    observation = adapter.observe(_context(candidate_sha=candidate_sha))

    assert observation["status"] == expected_status


@pytest.mark.parametrize(
    "disabled_setting",
    ("        if: false\n", "        continue-on-error: true\n"),
)
@requires_git
@requires_secure_package_platform
def test_dependency_review_rejects_non_enforcing_steps(
    tmp_path: Path,
    disabled_setting: str,
) -> None:
    workflow = tmp_path / ".github" / "workflows" / "security.yml"
    workflow.parent.mkdir(parents=True)
    workflow.write_text(
        """\
on:
  pull_request:
permissions:
  contents: read
jobs:
  dependency-review:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/dependency-review-action@2222222222222222222222222222222222222222
"""
        + disabled_setting
        + """\
        with:
          fail-on-severity: low
          fail-on-scopes: runtime, development, unknown
          warn-only: false
          vulnerability-check: true
""",
        encoding="utf-8",
    )
    candidate_sha = _commit_candidate(tmp_path)
    adapter = {value.control_id: value for value in build_package_control_adapters(tmp_path)}[
        "dependency_review"
    ]

    observation = adapter.observe(_context(candidate_sha=candidate_sha))

    assert observation["status"] == "failed"


@pytest.mark.parametrize(
    ("pull_request_configuration", "job_configuration"),
    (
        ("    types: [closed]\n", "    runs-on: ubuntu-latest\n"),
        ("", "    runs-on: ubuntu-latest\n    continue-on-error: true\n"),
        ("", ""),
    ),
)
@requires_git
@requires_secure_package_platform
def test_dependency_review_requires_an_applicable_failure_enforcing_job(
    tmp_path: Path,
    pull_request_configuration: str,
    job_configuration: str,
) -> None:
    workflow = tmp_path / ".github" / "workflows" / "security.yml"
    workflow.parent.mkdir(parents=True)
    workflow.write_text(
        "on:\n  pull_request:\n"
        + pull_request_configuration
        + "permissions:\n  contents: read\n"
        + "jobs:\n  dependency-review:\n"
        + job_configuration
        + "    steps:\n"
        + "      - uses: actions/dependency-review-action@"
        + "2222222222222222222222222222222222222222\n"
        + "        with:\n          fail-on-severity: low\n"
        + "          fail-on-scopes: runtime, development, unknown\n"
        + "          warn-only: false\n"
        + "          vulnerability-check: true\n",
        encoding="utf-8",
    )
    candidate_sha = _commit_candidate(tmp_path)
    adapter = {value.control_id: value for value in build_package_control_adapters(tmp_path)}[
        "dependency_review"
    ]

    observation = adapter.observe(_context(candidate_sha=candidate_sha))

    assert observation["status"] == "failed"


@requires_git
@requires_secure_package_platform
def test_dependency_review_rejects_a_job_skippable_through_needs(
    tmp_path: Path,
) -> None:
    workflow = tmp_path / ".github" / "workflows" / "security.yml"
    workflow.parent.mkdir(parents=True)
    workflow.write_text(
        """\
on:
  pull_request:
permissions:
  contents: read
jobs:
  preflight:
    runs-on: ubuntu-latest
    steps:
      - run: exit 1
  dependency-review:
    needs: preflight
    runs-on: ubuntu-latest
    steps:
      - uses: actions/dependency-review-action@2222222222222222222222222222222222222222
        with:
          fail-on-severity: low
          fail-on-scopes: runtime, development, unknown
          warn-only: false
          vulnerability-check: true
""",
        encoding="utf-8",
    )
    candidate_sha = _commit_candidate(tmp_path)
    adapter = {value.control_id: value for value in build_package_control_adapters(tmp_path)}[
        "dependency_review"
    ]

    observation = adapter.observe(_context(candidate_sha=candidate_sha))

    assert observation["status"] == "failed"


@pytest.mark.parametrize(
    "dependency_review_inputs",
    (
        _ENFORCING_DEPENDENCY_REVIEW_INPUTS.replace("          warn-only: false\n", ""),
        _ENFORCING_DEPENDENCY_REVIEW_INPUTS.replace("          vulnerability-check: true\n", ""),
        _ENFORCING_DEPENDENCY_REVIEW_INPUTS.replace("warn-only: false", "warn-only: true"),
        _ENFORCING_DEPENDENCY_REVIEW_INPUTS.replace("warn-only: false", "WARN-ONLY: true"),
        _ENFORCING_DEPENDENCY_REVIEW_INPUTS + "          WARN-ONLY: true\n",
        _ENFORCING_DEPENDENCY_REVIEW_INPUTS.replace(
            "vulnerability-check: true", "vulnerability-check: false"
        ),
        _ENFORCING_DEPENDENCY_REVIEW_INPUTS + "          allow-ghsas: GHSA-1111-2222-3333\n",
        _ENFORCING_DEPENDENCY_REVIEW_INPUTS
        + "          config-file: .github/dependency-review-config.yml\n",
        _ENFORCING_DEPENDENCY_REVIEW_INPUTS.replace(
            "runtime, development, unknown", "runtime, development"
        ),
        _ENFORCING_DEPENDENCY_REVIEW_INPUTS + "          base-ref: refs/heads/main\n",
        _ENFORCING_DEPENDENCY_REVIEW_INPUTS + "          head-ref: refs/heads/topic\n",
    ),
)
@requires_git
@requires_secure_package_platform
def test_dependency_review_rejects_inputs_that_weaken_vulnerability_enforcement(
    tmp_path: Path,
    dependency_review_inputs: str,
) -> None:
    workflow = tmp_path / ".github" / "workflows" / "security.yml"
    workflow.parent.mkdir(parents=True)
    workflow.write_text(
        "on:\n  pull_request:\n"
        + "permissions:\n  contents: read\n"
        + "jobs:\n  dependency-review:\n    runs-on: ubuntu-latest\n    steps:\n"
        + "      - uses: actions/dependency-review-action@"
        + "2222222222222222222222222222222222222222\n"
        + "        with:\n"
        + dependency_review_inputs,
        encoding="utf-8",
    )
    candidate_sha = _commit_candidate(tmp_path)
    adapter = {value.control_id: value for value in build_package_control_adapters(tmp_path)}[
        "dependency_review"
    ]

    observation = adapter.observe(_context(candidate_sha=candidate_sha))

    assert observation["status"] == "failed"


@requires_git
@requires_secure_package_platform
def test_workflow_yaml_duplicate_keys_fail_closed(tmp_path: Path) -> None:
    workflow = tmp_path / ".github" / "workflows" / "security.yml"
    workflow.parent.mkdir(parents=True)
    workflow.write_text(
        """\
on: workflow_dispatch
on:
  pull_request:
jobs:
  dependency-review:
    steps:
      - uses: actions/dependency-review-action@2222222222222222222222222222222222222222
        with:
          fail-on-severity: low
""",
        encoding="utf-8",
    )
    candidate_sha = _commit_candidate(tmp_path)
    adapter = {value.control_id: value for value in build_package_control_adapters(tmp_path)}[
        "dependency_review"
    ]

    observation = adapter.observe(_context(candidate_sha=candidate_sha))

    assert observation["status"] == "unavailable"
    assert observation["failure_class"] == "malformed"


@requires_git
@requires_secure_package_platform
def test_dependabot_grouping_requires_a_top_level_update_record(
    tmp_path: Path,
) -> None:
    dependabot = tmp_path / ".github" / "dependabot.yml"
    dependabot.parent.mkdir(parents=True)
    dependabot.write_text(
        """\
version: 2
not_updates:
  - package-ecosystem: uv
    schedule:
      interval: weekly
    groups:
      compatible:
        patterns: ["*"]
        update-types: ["minor", "patch"]
""",
        encoding="utf-8",
    )
    _write_uv_lock(tmp_path)
    candidate_sha = _commit_candidate(tmp_path)
    adapter = {value.control_id: value for value in build_package_control_adapters(tmp_path)}[
        "dependabot_grouped_updates"
    ]

    observation = adapter.observe(_context(candidate_sha=candidate_sha))

    assert observation["status"] == "failed"


@pytest.mark.parametrize(
    ("directory", "pull_request_limit"),
    (("/unused", ""), ("/", "    open-pull-requests-limit: 0\n")),
)
@requires_git
@requires_secure_package_platform
def test_dependabot_grouping_requires_enabled_root_updates(
    tmp_path: Path,
    directory: str,
    pull_request_limit: str,
) -> None:
    dependabot = tmp_path / ".github" / "dependabot.yml"
    dependabot.parent.mkdir(parents=True)
    dependabot.write_text(
        "version: 2\nupdates:\n"
        + "  - package-ecosystem: uv\n"
        + f"    directory: {directory}\n"
        + pull_request_limit
        + "    schedule:\n      interval: weekly\n"
        + "    groups:\n      compatible:\n"
        + '        patterns: ["*"]\n'
        + '        update-types: ["minor", "patch"]\n',
        encoding="utf-8",
    )
    _write_uv_lock(tmp_path)
    candidate_sha = _commit_candidate(tmp_path)
    adapter = {value.control_id: value for value in build_package_control_adapters(tmp_path)}[
        "dependabot_grouped_updates"
    ]

    observation = adapter.observe(_context(candidate_sha=candidate_sha))

    assert observation["status"] == "failed"


@pytest.mark.parametrize(
    ("update_configuration", "group_configuration"),
    (
        ("    target-branch: maintenance\n", ""),
        ("    allow:\n      - dependency-name: only-this-package\n", ""),
        ('    ignore:\n      - dependency-name: "*"\n', ""),
        ('    exclude-paths: ["**"]\n', ""),
        ("    cooldown:\n      default-days: 365\n", ""),
        ("", "        applies-to: security-updates\n"),
        ("", "        dependency-type: development\n"),
        ("", '        exclude-patterns: ["*"]\n'),
    ),
)
@requires_git
@requires_secure_package_platform
def test_dependabot_grouping_covers_default_branch_version_updates(
    tmp_path: Path,
    update_configuration: str,
    group_configuration: str,
) -> None:
    dependabot = tmp_path / ".github" / "dependabot.yml"
    dependabot.parent.mkdir(parents=True)
    dependabot.write_text(
        "version: 2\nupdates:\n"
        + "  - package-ecosystem: uv\n"
        + "    directory: /\n"
        + update_configuration
        + "    schedule:\n      interval: weekly\n"
        + "    groups:\n      compatible:\n"
        + group_configuration
        + '        patterns: ["*"]\n'
        + '        update-types: ["minor", "patch"]\n',
        encoding="utf-8",
    )
    _write_uv_lock(tmp_path)
    candidate_sha = _commit_candidate(tmp_path)
    adapter = {value.control_id: value for value in build_package_control_adapters(tmp_path)}[
        "dependabot_grouped_updates"
    ]

    observation = adapter.observe(_context(candidate_sha=candidate_sha))

    assert observation["status"] == "failed"


@pytest.mark.parametrize(
    "dependabot_policy",
    (
        pytest.param(
            """\
version: 2
updates:
  - package-ecosystem: uv
    directory: /
    versioning-strategy: lockfile-only
    schedule:
      interval: weekly
    groups:
      compatible:
        patterns: ["*"]
        update-types: ["minor", "patch"]
""",
            id="lockfile-only",
        ),
        pytest.param(
            """\
version: 2
updates:
  - package-ecosystem: uv
    directory: /
    schedule:
      interval: weekly
    groups:
      compatible:
        patterns: ["*"]
        update-types: ["minor", "patch", "major"]
""",
            id="major-in-compatible-group",
        ),
        pytest.param(
            """\
version: 2
updates:
  - package-ecosystem: uv
    directory: /
    schedule:
      interval: weekly
    groups:
      earlier-catch-all:
        patterns: ["*"]
      compatible:
        patterns: ["*"]
        update-types: ["minor", "patch"]
""",
            id="shadowed-compatible-group",
        ),
        pytest.param(
            """\
version: 2
multi-ecosystem-groups:
  all-dependencies:
    schedule:
      interval: monthly
updates:
  - package-ecosystem: uv
    directory: /
    multi-ecosystem-group: all-dependencies
    schedule:
      interval: weekly
    groups:
      compatible:
        patterns: ["*"]
        update-types: ["minor", "patch"]
""",
            id="multi-ecosystem-schedule-override",
        ),
        pytest.param(
            """\
version: 2
updates:
  - package-ecosystem: uv
    directory: /
    schedule:
      interval: monthly
  - package-ecosystem: uv
    directory: /
    schedule:
      interval: weekly
    groups:
      compatible:
        patterns: ["*"]
        update-types: ["minor", "patch"]
""",
            id="overlapping-root-update",
        ),
    ),
)
@requires_git
@requires_secure_package_platform
def test_dependabot_grouping_rejects_ambiguous_or_narrowed_effective_policy(
    tmp_path: Path,
    dependabot_policy: str,
) -> None:
    dependabot = tmp_path / ".github" / "dependabot.yml"
    dependabot.parent.mkdir(parents=True)
    dependabot.write_text(dependabot_policy, encoding="utf-8")
    _write_uv_lock(tmp_path)
    candidate_sha = _commit_candidate(tmp_path)
    adapter = {value.control_id: value for value in build_package_control_adapters(tmp_path)}[
        "dependabot_grouped_updates"
    ]

    observation = adapter.observe(_context(candidate_sha=candidate_sha))

    assert observation["status"] == "failed"


@requires_git
@requires_secure_package_platform
def test_workflow_evidence_aggregates_more_than_thirty_two_structural_documents(
    tmp_path: Path,
) -> None:
    workflows = tmp_path / ".github" / "workflows"
    workflows.mkdir(parents=True)
    for index in range(33):
        (workflows / f"workflow-{index:02}.yml").write_text(
            """\
on: push
jobs:
  check:
    steps: [{uses: "actions/checkout@1111111111111111111111111111111111111111"}]
""",
            encoding="utf-8",
        )
    candidate_sha = _commit_candidate(tmp_path)
    adapter = {value.control_id: value for value in build_package_control_adapters(tmp_path)}[
        "immutable_action_pins"
    ]

    observation = adapter.observe(_context(candidate_sha=candidate_sha))

    assert observation["status"] == "passed"
    opaque_ids = observation["opaque_ids"]
    assert isinstance(opaque_ids, list)
    assert len(opaque_ids) == 1
    assert isinstance(opaque_ids[0], str)
    assert opaque_ids[0].startswith("workflow-set:")


def test_coordinator_projects_passed_evidence_expired_at_completion_as_stale() -> None:
    adapters: list[RepositoryControlAdapter] = []
    for control_id, source in CONTROL_SOURCES.items():
        reader = _passing_reader(control_id, [])
        if control_id == "main_ruleset":

            def stale_reader(context: ControlReadContext) -> dict[str, object]:
                result = _passing_reader("main_ruleset", [])(context)
                result["valid_until"] = "2026-08-14T00:00:15Z"
                return result

            reader = stale_reader
        if source == "github":
            adapters.append(GitHubControlAdapter(control_id, reader))
        else:
            adapters.append(PackageControlAdapter(control_id, reader))
    times = iter(
        (
            datetime(2026, 8, 14, 0, 0, 0, tzinfo=UTC),
            datetime(2026, 8, 14, 0, 0, 20, tzinfo=UTC),
        )
    )

    payload = collect_repository_control_observation(
        _request(),
        adapters,
        clock=lambda: next(times),
        monotonic=lambda: 100.0,
        epoch_factory=lambda: "e" * 64,
    ).to_dict()

    controls = payload["controls"]
    assert isinstance(controls, list)
    controls_by_id = {control["control_id"]: control for control in controls}
    assert controls_by_id["main_ruleset"]["status"] == "unavailable"
    assert controls_by_id["main_ruleset"]["failure_class"] == "stale"


def _passing_reader(
    control_id: str,
    seen_contexts: list[tuple[str, str, float]],
) -> Callable[[ControlReadContext], dict[str, object]]:
    def read(context: ControlReadContext) -> dict[str, object]:
        epoch = context.operation_epoch
        monotonic_deadline = context.monotonic_deadline
        repository = context.repository
        candidate_sha = context.candidate_sha
        seen_contexts.append((control_id, epoch, monotonic_deadline))
        result: dict[str, object] = {
            "repository_full_name": repository.full_name,
            "repository_database_id": repository.database_id,
            "repository_node_id": repository.node_id,
            "candidate_sha": candidate_sha,
            "operation_epoch": epoch,
            "status": "passed",
            "observed_at": _format_time(context.started_at),
            "valid_until": _format_time(context.started_at + timedelta(minutes=10)),
            "opaque_ids": [],
        }
        if control_id in {"codeql_alerts", "dependabot_alerts", "secret_scanning_alerts"}:
            result.update(pagination_complete=True, open_count=0)
        if control_id == "private_security_exception_state":
            result.update(
                pagination_complete=True,
                semantic_pass_count=2,
                semantically_identical=True,
            )
        return result

    return read


def _request(
    *,
    timeout_seconds: int = 60,
    candidate_sha: str = "a" * 40,
) -> RepositoryObservationRequest:
    return RepositoryObservationRequest(
        repository=RepositoryIdentity(
            full_name="nisavid/fork-ops",
            database_id=1_241_799_725,
            node_id="R_kgDOSgRcLQ",
            default_branch="main",
        ),
        candidate_sha=candidate_sha,
        producer=ProducerIdentity(
            kind="github_app",
            opaque_id="github-app:1234",
            workflow_sha="b" * 40,
            evaluator_sha256="c" * 64,
        ),
        timeout_seconds=timeout_seconds,
    )


def _context(*, candidate_sha: str = "a" * 40) -> ControlReadContext:
    request = _request(candidate_sha=candidate_sha)
    return ControlReadContext(
        repository=request.repository,
        candidate_sha=request.candidate_sha,
        producer=request.producer,
        operation_epoch="e" * 64,
        started_at=datetime(2026, 8, 14, 0, 0, 0, tzinfo=UTC),
        deadline_at=datetime(2026, 8, 14, 0, 1, 0, tzinfo=UTC),
        monotonic_deadline=160.0,
        deadline_remaining=lambda: 60.0,
    )


def _mismatched_reader(context: ControlReadContext) -> dict[str, object]:
    result = _passing_reader("main_ruleset", [])(context)
    result["candidate_sha"] = "f" * 40
    return result


def _private_reader(
    private_sentinel: str,
) -> Callable[[ControlReadContext], dict[str, object]]:
    def read(context: ControlReadContext) -> dict[str, object]:
        result = _passing_reader("private_security_exception_state", [])(context)
        result["raw_private_response"] = private_sentinel
        return result

    return read


def _error_reader(
    private_sentinel: str,
) -> Callable[[ControlReadContext], dict[str, object]]:
    def read(_context: ControlReadContext) -> dict[str, object]:
        raise RuntimeError(private_sentinel)

    return read


def _blocked_reader(
    release: Event,
    *,
    control_id: str = "codeql_alerts",
) -> Callable[[ControlReadContext], dict[str, object]]:
    def read(context: ControlReadContext) -> dict[str, object]:
        release.wait(timeout=30)
        return _passing_reader(control_id, [])(context)

    return read


class _ExplodingAdapter:
    control_id = "main_ruleset"
    source = "github"

    def observe(self, context: ControlReadContext) -> dict[str, object]:
        del context
        raise RuntimeError("private adapter exception")


class _ProtocolPassingAdapter:
    def __init__(self, control_id: str, source: str) -> None:
        self.control_id = control_id
        self.source = source

    def observe(self, context: ControlReadContext) -> dict[str, object]:
        projection: dict[str, object] = {
            "control_id": self.control_id,
            "source": self.source,
            "status": "passed",
            "observed_at": _format_time(context.started_at),
            "valid_until": _format_time(context.started_at + timedelta(minutes=15)),
            "opaque_ids": [],
        }
        projection["projection_sha256"] = repository_control_adapters._projection_digest(projection)
        return projection


class _MalformedProjectionAdapter:
    control_id = "main_ruleset"
    source = "github"

    def observe(self, context: ControlReadContext) -> dict[str, object]:
        del context
        return cast(dict[str, object], [])


def _linux_process_start_time(process_id: int) -> str | None:
    try:
        payload = Path(f"/proc/{process_id}/stat").read_text(encoding="utf-8")
    except FileNotFoundError:
        return None
    return _proc_stat_start_time(payload)


def _proc_stat_start_time(payload: str) -> str:
    _identity, separator, remaining_fields = payload.rpartition(") ")
    if not separator:
        raise AssertionError("Linux process stat is missing the command boundary")
    fields = remaining_fields.split()
    if len(fields) <= 19:
        raise AssertionError("Linux process stat is missing the start-time field")
    return fields[19]


def _commit_candidate(root: Path) -> str:
    subprocess.run(
        ("git", "init", "--quiet", str(root)),
        check=True,
        env=_ISOLATED_GIT_ENV,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    base = (
        "git",
        "-c",
        "commit.gpgsign=false",
        "-c",
        "maintenance.auto=false",
        "-c",
        "core.hooksPath=/dev/null",
        "-c",
        "user.email=fixture@example.invalid",
        "-c",
        "user.name=Fixture",
        "-C",
        str(root),
    )
    subprocess.run(
        (*base, "add", "--all"),
        check=True,
        env=_ISOLATED_GIT_ENV,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    subprocess.run(
        (*base, "commit", "--quiet", "--allow-empty", "-m", "test fixture"),
        check=True,
        env=_ISOLATED_GIT_ENV,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    return subprocess.run(
        (*base, "rev-parse", "HEAD"),
        check=True,
        env=_ISOLATED_GIT_ENV,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True,
    ).stdout.strip()


def _observe_local_docker_action(
    root: Path,
    *,
    dockerfile: str | None,
    image: str = "Dockerfile",
) -> dict[str, object]:
    workflow = root / ".github" / "workflows" / "validation.yml"
    workflow.parent.mkdir(parents=True)
    workflow.write_text(
        """\
on: push
jobs:
  validation:
    steps:
      - uses: ./.github/actions/local-docker
""",
        encoding="utf-8",
    )
    action_directory = root / ".github" / "actions" / "local-docker"
    action_directory.mkdir(parents=True)
    (action_directory / "action.yml").write_text(
        """\
name: Local Docker action
runs:
  using: docker
  image: """
        + image
        + "\n",
        encoding="utf-8",
    )
    if dockerfile is not None:
        dockerfile_path = action_directory / image.removeprefix("./")
        dockerfile_path.parent.mkdir(parents=True, exist_ok=True)
        dockerfile_path.write_text(dockerfile, encoding="utf-8")
    candidate_sha = _commit_candidate(root)
    adapter = {value.control_id: value for value in build_package_control_adapters(root)}[
        "immutable_action_pins"
    ]
    return adapter.observe(_context(candidate_sha=candidate_sha))


def _write_uv_lock(root: Path) -> None:
    (root / "uv.lock").write_text(
        'version = 1\nrevision = 3\nrequires-python = ">=3.11"\n',
        encoding="utf-8",
    )


def _format_time(value: datetime) -> str:
    return value.isoformat(timespec="seconds").replace("+00:00", "Z")


class _FastReaderCompletion:
    def __init__(self, *, expected: int) -> None:
        self._expected = expected
        self._completed = 0
        self._lock = Lock()
        self.done = Event()

    def wrap(
        self,
        reader: Callable[[ControlReadContext], dict[str, object]],
    ) -> Callable[[ControlReadContext], dict[str, object]]:
        def read(context: ControlReadContext) -> dict[str, object]:
            try:
                return reader(context)
            finally:
                with self._lock:
                    self._completed += 1
                    if self._completed == self._expected:
                        self.done.set()

        return read


class _CompletionDeadlineClock:
    def __init__(
        self,
        *,
        start: float,
        after_start: float,
        fast_readers: _FastReaderCompletion,
    ) -> None:
        self._start = start
        self._after_start = after_start
        self._fast_readers = fast_readers
        self._started = False

    def __call__(self) -> float:
        if not self._started:
            self._started = True
            return self._start
        if current_thread() is main_thread():
            if not self._fast_readers.done.wait(timeout=30):
                raise AssertionError("fast repository-control readers did not complete")
            return self._after_start
        return self._start


class _PostDeadlineMonotonic:
    def __init__(self) -> None:
        self._started = False
        self._lock = Lock()

    def __call__(self) -> float:
        with self._lock:
            if current_thread() is main_thread() and not self._started:
                self._started = True
                return 100.0
        return 101.0
