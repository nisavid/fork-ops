from __future__ import annotations

import re
import shlex
from collections.abc import Mapping, Sequence
from copy import deepcopy
from pathlib import Path

import pytest
import yaml

REPOSITORY_ROOT = Path(__file__).resolve().parents[3]
REPOSITORY_TEST_ROOT = REPOSITORY_ROOT / "plugins" / "fork-ops" / "tests"
VALIDATION_WORKFLOW = REPOSITORY_ROOT / ".github" / "workflows" / "validation.yml"
RELEASE_WORKFLOW = REPOSITORY_ROOT / ".github" / "workflows" / "release-validation.yml"
TRUSTED_PRODUCER = "python trusted-verifier/scripts/produce_validation_evidence.py"
_TRUSTED_PRODUCER_COMMAND = tuple(TRUSTED_PRODUCER.split())
_SHELL_COMMAND_BOUNDARY_CHARACTERS = frozenset("();<>|&")
_IMMUTABLE_ACTION_REF = re.compile(r"[0-9a-f]{40}", re.IGNORECASE)
_CANDIDATE_REFERENCE = re.compile(
    r"(?<![A-Za-z0-9])candidate(?![A-Za-z0-9])",
    re.IGNORECASE,
)
_CANDIDATE_PATH_SEGMENT = re.compile(
    r"(?:^|[\\/])candidate(?:[\\/]|$)",
    re.IGNORECASE,
)
_GITHUB_TOKEN_REFERENCE = re.compile(
    r"(?:github\s*(?:\.\s*token|\[\s*['\"]token['\"]\s*\])|"
    r"secrets\s*(?:\.\s*GITHUB_TOKEN|\[\s*['\"]GITHUB_TOKEN['\"]\s*\])|"
    r"toJSON\s*\(\s*(?:github|secrets)\s*\))",
    re.IGNORECASE,
)
_MISSING_PERMISSIONS = object()
_INVALID_PERMISSION_DECLARATIONS = (
    pytest.param(None, id="null"),
    pytest.param("read-all", id="read-all"),
    pytest.param({"contents": "write"}, id="write"),
)
_INVALID_WORKFLOW_PERMISSION_DECLARATIONS = (
    pytest.param(_MISSING_PERMISSIONS, id="missing"),
    *_INVALID_PERMISSION_DECLARATIONS,
)
_CANDIDATE_INTERPRETER_TARGET = re.compile(
    r"(?:^|[;&|])\s*\(?\s*(?:env\s+)?"
    r"(?:python(?:\d+(?:\.\d+)*)?|bash|sh|zsh|node|ruby|perl)"
    r"(?:\s+-[^\s;&|]+)*\s+[\"']?(?:\./)?candidate(?:[\\/])",
    re.IGNORECASE | re.MULTILINE,
)
_SHELL_CD = re.compile(
    r"(?:^|[;&|])\s*\(?\s*cd\s+(?:--\s+)?"
    r"(?P<target>\"[^\"]*\"|'[^']*'|[^\s;&|]+)",
    re.IGNORECASE | re.MULTILINE,
)
_UV_RUN = re.compile(
    r"(?:^|[;&|])\s*uv\s+run(?:\s|$)(?P<arguments>[^\n;&|]*)",
    re.IGNORECASE | re.MULTILINE,
)
_CANDIDATE_CHECKOUT = "pinned checkout"
_CANDIDATE_ARTIFACT_TRANSFER = "pinned artifact transfer"
_CANDIDATE_TRUSTED_PRODUCER = "trusted producer invocation"
_CANDIDATE_STEP_KINDS = {
    _CANDIDATE_CHECKOUT,
    _CANDIDATE_ARTIFACT_TRANSFER,
    _CANDIDATE_TRUSTED_PRODUCER,
}
_ARTIFACT_TRANSFER_REPOSITORIES = {
    "actions/download-artifact",
    "actions/upload-artifact",
}
_CANDIDATE_JOB_ACTION_REPOSITORIES = {
    "actions/checkout",
    "actions/download-artifact",
    "actions/setup-python",
    "actions/upload-artifact",
    "astral-sh/setup-uv",
}
_ADVISORY_OUTCOME_COMMAND = 'echo "outcome=$ADVISORY_STEP_OUTCOME" >> "$GITHUB_OUTPUT"'
_ADVISORY_RUN_PREFIX = (
    "python trusted-verifier/scripts/produce_validation_evidence.py "
    "--mode fresh-source --interpreter python --repo candidate "
    "--execution-boundary local-observational --overall-timeout-seconds 1500 "
    "--output "
)
_SOURCE_EVIDENCE_COMMAND = (
    "python trusted-verifier/scripts/produce_validation_evidence.py "
    '--mode "$VALIDATION_MODE" --interpreter python --repo candidate '
    '--diff-base "$DIFF_BASE" --execution-boundary container '
    "--overall-timeout-seconds 1500 "
    '--output "${{ runner.temp }}/validation-evidence-source-${{ matrix.python }}.json"'
)
_BUILD_EVIDENCE_COMMAND = (
    "python trusted-verifier/scripts/produce_validation_evidence.py "
    "--mode build --interpreter python --repo candidate "
    '--artifact-dir "${{ runner.temp }}/candidate" '
    "--execution-boundary container --overall-timeout-seconds 600 "
    '--output "${{ runner.temp }}/validation-evidence-build.json"'
)
_INSTALLED_EVIDENCE_COMMAND = (
    "python trusted-verifier/scripts/produce_validation_evidence.py "
    "--mode installed --interpreter python --repo candidate "
    '--artifact-dir "${{ runner.temp }}/candidate" '
    '--build-evidence "${{ runner.temp }}/candidate-evidence/'
    'validation-evidence-build.json" --execution-boundary container '
    "--overall-timeout-seconds 900 "
    '--output "${{ runner.temp }}/validation-evidence-installed-'
    '${{ matrix.python }}.json"'
)
_ADVISORY_EVIDENCE_COMMANDS = {
    "advisory_macos": _ADVISORY_RUN_PREFIX
    + '"${{ runner.temp }}/validation-evidence-advisory-macos-3.11.json"',
    "advisory_windows": _ADVISORY_RUN_PREFIX
    + '"${{ runner.temp }}/validation-evidence-advisory-windows-3.11.json"',
    "advisory": _ADVISORY_RUN_PREFIX
    + '"${{ runner.temp }}/validation-evidence-advisory-linux-3.15.json"',
}
_RELEASE_PREFLIGHT_COMMAND = (
    "python trusted-verifier/scripts/produce_validation_evidence.py "
    "--mode release-preflight --interpreter python --repo candidate "
    '--artifact-dir "${{ runner.temp }}/candidate" '
    '--build-evidence "${{ runner.temp }}/candidate-evidence/'
    'validation-evidence-build.json" --trusted-main-run-id "$TRUSTED_MAIN_RUN_ID" '
    '--trusted-main-run-attempt "$TRUSTED_MAIN_RUN_ATTEMPT" '
    "--trusted-workflow-path .github/workflows/validation.yml "
    "--trusted-event push --trusted-artifact-name \"$TRUSTED_ARTIFACT_NAME\" "
    '--trusted-release-workflow-ref "$TRUSTED_RELEASE_WORKFLOW_REF" '
    '--trusted-release-workflow-sha "$TRUSTED_RELEASE_WORKFLOW_SHA" '
    '--trusted-release-workflow-path "$TRUSTED_RELEASE_WORKFLOW_PATH" '
    '--trusted-verifier-repository "$TRUSTED_VERIFIER_REPOSITORY" '
    '--trusted-verifier-sha "$TRUSTED_VERIFIER_SHA" '
    '--release-preflight-key-file "$RELEASE_PREFLIGHT_KEY_FILE" '
    "--overall-timeout-seconds 180 "
    '--output "${{ runner.temp }}/trusted-state/release-preflight-'
    '${{ matrix.python }}.json"'
)
_RELEASE_INSTALLED_COMMAND = (
    "python trusted-verifier/scripts/produce_validation_evidence.py "
    "--mode installed --interpreter python --repo candidate "
    '--artifact-dir "${{ runner.temp }}/candidate" '
    '--build-evidence "${{ runner.temp }}/candidate-evidence/'
    'validation-evidence-build.json" '
    '--release-preflight-evidence "${{ runner.temp }}/trusted-state/'
    'release-preflight-${{ matrix.python }}.json" '
    '--trusted-release-workflow-ref "$TRUSTED_RELEASE_WORKFLOW_REF" '
    '--trusted-release-workflow-sha "$TRUSTED_RELEASE_WORKFLOW_SHA" '
    '--trusted-release-workflow-path "$TRUSTED_RELEASE_WORKFLOW_PATH" '
    '--trusted-verifier-repository "$TRUSTED_VERIFIER_REPOSITORY" '
    '--trusted-verifier-sha "$TRUSTED_VERIFIER_SHA" '
    '--release-preflight-key-file "$RELEASE_PREFLIGHT_KEY_FILE" '
    "--execution-boundary container --overall-timeout-seconds 780 "
    '--output "${{ runner.temp }}/validation-evidence-release-'
    '${{ matrix.python }}.json"'
)
_APPROVED_CANDIDATE_JOB_RUNS = {
    ("validation", "source"): (_SOURCE_EVIDENCE_COMMAND,),
    ("validation", "build"): (_BUILD_EVIDENCE_COMMAND,),
    ("validation", "installed"): (_INSTALLED_EVIDENCE_COMMAND,),
    **{
        ("validation", job_name): (command, _ADVISORY_OUTCOME_COMMAND)
        for job_name, command in _ADVISORY_EVIDENCE_COMMANDS.items()
    },
    ("release", "installed"): (
        _RELEASE_PREFLIGHT_COMMAND,
        _RELEASE_INSTALLED_COMMAND,
    ),
}
_APPROVED_RUN_EXECUTION: dict[
    str, tuple[str | None, Mapping[str, object]]
] = {
    _SOURCE_EVIDENCE_COMMAND: (
        None,
        {
            "DIFF_BASE": "${{ github.event.pull_request.base.sha || "
            "(github.event_name == 'push' && "
            "github.event.before != '0000000000000000000000000000000000000000' "
            "&& github.event.before) || '' }}",
            "VALIDATION_MODE": "${{ github.event_name == 'schedule' && "
            "'fresh-source' || 'locked-source' }}",
        },
    ),
    _BUILD_EVIDENCE_COMMAND: (None, {}),
    _INSTALLED_EVIDENCE_COMMAND: (None, {}),
    **{
        command: ("bash", {})
        for command in _ADVISORY_EVIDENCE_COMMANDS.values()
    },
    _ADVISORY_OUTCOME_COMMAND: (
        "bash",
        {"ADVISORY_STEP_OUTCOME": "${{ steps.advisory_run.outcome }}"},
    ),
    _RELEASE_PREFLIGHT_COMMAND: (
        None,
        {
            "GITHUB_TOKEN": "${{ github.token }}",
            "TRUSTED_MAIN_RUN_ID": "${{ inputs.artifact_run_id }}",
            "TRUSTED_MAIN_RUN_ATTEMPT": "${{ inputs.artifact_run_attempt }}",
            "TRUSTED_ARTIFACT_NAME": "${{ inputs.artifact_name }}",
            "TRUSTED_RELEASE_WORKFLOW_REF": "${{ job.workflow_ref }}",
            "TRUSTED_RELEASE_WORKFLOW_SHA": "${{ job.workflow_sha }}",
            "TRUSTED_RELEASE_WORKFLOW_PATH": "${{ job.workflow_file_path }}",
            "TRUSTED_VERIFIER_REPOSITORY": "${{ job.workflow_repository }}",
            "TRUSTED_VERIFIER_SHA": "${{ job.workflow_sha }}",
            "RELEASE_PREFLIGHT_KEY_FILE": "${{ runner.temp }}/trusted-state/"
            "release-preflight-${{ matrix.python }}.key",
        },
    ),
    _RELEASE_INSTALLED_COMMAND: (
        None,
        {
            "TRUSTED_RELEASE_WORKFLOW_REF": "${{ job.workflow_ref }}",
            "TRUSTED_RELEASE_WORKFLOW_SHA": "${{ job.workflow_sha }}",
            "TRUSTED_RELEASE_WORKFLOW_PATH": "${{ job.workflow_file_path }}",
            "TRUSTED_VERIFIER_REPOSITORY": "${{ job.workflow_repository }}",
            "TRUSTED_VERIFIER_SHA": "${{ job.workflow_sha }}",
            "RELEASE_PREFLIGHT_KEY_FILE": "${{ runner.temp }}/trusted-state/"
            "release-preflight-${{ matrix.python }}.key",
        },
    ),
}


def _approved_run_step_metadata(
    name: str,
    command: str,
    *,
    step_id: str | None = None,
    condition: object | None = None,
) -> dict[str, object]:
    shell, environment = _APPROVED_RUN_EXECUTION[command]
    metadata: dict[str, object] = {"name": name}
    if step_id is not None:
        metadata["id"] = step_id
    if condition is not None:
        metadata["if"] = condition
    if shell is not None:
        metadata["shell"] = shell
    if environment:
        metadata["env"] = dict(environment)
    return metadata


_APPROVED_RUN_STEP_METADATA = {
    _SOURCE_EVIDENCE_COMMAND: _approved_run_step_metadata(
        "Produce source validation evidence",
        _SOURCE_EVIDENCE_COMMAND,
    ),
    _BUILD_EVIDENCE_COMMAND: _approved_run_step_metadata(
        "Build candidate distributions",
        _BUILD_EVIDENCE_COMMAND,
    ),
    _INSTALLED_EVIDENCE_COMMAND: _approved_run_step_metadata(
        "Validate installed candidate",
        _INSTALLED_EVIDENCE_COMMAND,
    ),
    **{
        command: _approved_run_step_metadata(
            "Produce advisory fresh-resolution evidence",
            command,
            step_id="advisory_run",
        )
        for command in _ADVISORY_EVIDENCE_COMMANDS.values()
    },
    _ADVISORY_OUTCOME_COMMAND: _approved_run_step_metadata(
        "Observe advisory outcome",
        _ADVISORY_OUTCOME_COMMAND,
        step_id="observe",
        condition="${{ always() }}",
    ),
    _RELEASE_PREFLIGHT_COMMAND: _approved_run_step_metadata(
        "Verify release provenance without executing candidate code",
        _RELEASE_PREFLIGHT_COMMAND,
    ),
    _RELEASE_INSTALLED_COMMAND: _approved_run_step_metadata(
        "Validate exact release candidate inside the isolated container",
        _RELEASE_INSTALLED_COMMAND,
    ),
}
_APPROVED_CANDIDATE_JOB_CONTROLS = {
    ("validation", "source"): (None, None),
    ("validation", "build"): (None, None),
    ("validation", "installed"): (None, None),
    **{
        ("validation", job_name): (
            "${{ github.event_name == 'schedule' }}",
            True,
        )
        for job_name in _ADVISORY_EVIDENCE_COMMANDS
    },
    ("release", "installed"): (None, None),
}


def _artifact_transfer_signature(
    name: object,
    repository: str,
    condition: object,
    inputs: Mapping[str, object],
) -> tuple[object, str, object, tuple[tuple[str, object], ...]]:
    return name, repository, condition, tuple(sorted(inputs.items()))


_APPROVED_ARTIFACT_TRANSFERS = {
    ("validation", "source"): (
        _artifact_transfer_signature(
            "Upload source evidence",
            "actions/upload-artifact",
            "${{ always() }}",
            {
                "name": "validation-evidence-source-${{ matrix.python }}",
                "path": "${{ runner.temp }}/validation-evidence-source-"
                "${{ matrix.python }}.json",
                "if-no-files-found": "warn",
                "retention-days": 30,
            },
        ),
    ),
    ("validation", "build"): (
        _artifact_transfer_signature(
            "Upload candidate distributions",
            "actions/upload-artifact",
            "${{ always() }}",
            {
                "name": "candidate-dist",
                "path": "${{ runner.temp }}/candidate/*.whl\n"
                "${{ runner.temp }}/candidate/*.tar.gz\n",
                "if-no-files-found": "error",
                "retention-days": 30,
            },
        ),
        _artifact_transfer_signature(
            "Upload build evidence",
            "actions/upload-artifact",
            "${{ always() }}",
            {
                "name": "validation-evidence-build",
                "path": "${{ runner.temp }}/validation-evidence-build.json",
                "if-no-files-found": "warn",
                "retention-days": 30,
            },
        ),
    ),
    ("validation", "installed"): (
        _artifact_transfer_signature(
            None,
            "actions/download-artifact",
            None,
            {
                "name": "candidate-dist",
                "path": "${{ runner.temp }}/candidate",
            },
        ),
        _artifact_transfer_signature(
            None,
            "actions/download-artifact",
            None,
            {
                "name": "validation-evidence-build",
                "path": "${{ runner.temp }}/candidate-evidence",
            },
        ),
        _artifact_transfer_signature(
            "Upload installed evidence",
            "actions/upload-artifact",
            "${{ always() }}",
            {
                "name": "validation-evidence-installed-${{ matrix.python }}",
                "path": "${{ runner.temp }}/validation-evidence-installed-"
                "${{ matrix.python }}.json",
                "if-no-files-found": "warn",
                "retention-days": 30,
            },
        ),
    ),
    **{
        ("validation", job_name): (
            _artifact_transfer_signature(
                "Upload advisory evidence",
                "actions/upload-artifact",
                "${{ always() }}",
                {
                    "name": f"validation-evidence-advisory-{suffix}",
                    "path": "${{ runner.temp }}/validation-evidence-advisory-"
                    f"{suffix}.json",
                    "if-no-files-found": "warn",
                    "retention-days": 30,
                },
            ),
        )
        for job_name, suffix in {
            "advisory_macos": "macos-3.11",
            "advisory_windows": "windows-3.11",
            "advisory": "linux-3.15",
        }.items()
    },
    ("release", "installed"): (
        _artifact_transfer_signature(
            None,
            "actions/download-artifact",
            None,
            {
                "name": "${{ inputs.artifact_name }}",
                "path": "${{ runner.temp }}/candidate",
                "run-id": "${{ inputs.artifact_run_id }}",
                "github-token": "${{ github.token }}",
            },
        ),
        _artifact_transfer_signature(
            None,
            "actions/download-artifact",
            None,
            {
                "name": "validation-evidence-build",
                "path": "${{ runner.temp }}/candidate-evidence",
                "run-id": "${{ inputs.artifact_run_id }}",
                "github-token": "${{ github.token }}",
            },
        ),
        _artifact_transfer_signature(
            "Upload release evidence",
            "actions/upload-artifact",
            "${{ always() }}",
            {
                "name": "validation-evidence-release-${{ matrix.python }}",
                "path": "${{ runner.temp }}/trusted-state/release-preflight-"
                "${{ matrix.python }}.json\n"
                "${{ runner.temp }}/validation-evidence-release-"
                "${{ matrix.python }}.json\n",
                "if-no-files-found": "warn",
                "retention-days": 90,
            },
        ),
    ),
}
_TRUSTED_VERIFIER_CHECKOUT_INPUTS = {
    (
        "${{ github.repository }}",
        "${{ github.event.pull_request.base.sha || github.sha }}",
        "trusted-verifier",
    ),
    (
        "${{ job.workflow_repository }}",
        "${{ job.workflow_sha }}",
        "trusted-verifier",
    ),
    (
        "${{ github.repository }}",
        "${{ github.sha }}",
        "trusted-verifier",
    ),
}

WorkflowStep = dict[str, object]
WorkflowJob = tuple[WorkflowStep, ...]
WorkflowDocument = Mapping[str, object]
WorkflowSource = str | WorkflowDocument


def test_repository_checkout_contains_workflow_security_sources() -> None:
    if Path(__file__).resolve().parent != REPOSITORY_TEST_ROOT:
        pytest.skip("The package source archive does not include repository workflows.")
    assert VALIDATION_WORKFLOW.is_file(), VALIDATION_WORKFLOW
    assert RELEASE_WORKFLOW.is_file(), RELEASE_WORKFLOW


def test_candidate_workflows_disable_shared_dependency_caches() -> None:
    steps = _all_workflow_steps()
    _assert_candidate_cache_boundary(steps)


@pytest.mark.parametrize(
    "uses",
    (
        "actions/cache@0123456789abcdef0123456789abcdef01234567",
        "Actions/Cache/restore@0123456789abcdef0123456789abcdef01234567",
        "ACTIONS/CACHE/save@0123456789abcdef0123456789abcdef01234567",
    ),
)
def test_candidate_cache_boundary_rejects_cache_repository_and_subactions(
    uses: str,
) -> None:
    steps = _mutable_all_workflow_steps()
    steps.append({"uses": uses})

    with pytest.raises(AssertionError, match="actions/cache"):
        _assert_candidate_cache_boundary(steps)


def test_candidate_cache_boundary_allows_unrelated_cache_helper_action() -> None:
    steps = _mutable_all_workflow_steps()
    steps.append(
        {
            "uses": (
                "actions/cache-helper@0123456789abcdef0123456789abcdef01234567"
            )
        }
    )

    _assert_candidate_cache_boundary(steps)


def test_candidate_cache_boundary_rejects_setup_python_dependency_cache() -> None:
    steps = _mutable_all_workflow_steps()
    setup_python = next(
        step
        for step in steps
        if _action_repository(_step_uses(step)) == "actions/setup-python"
    )
    _mutable_step_inputs(setup_python)["cache"] = "pip"

    with pytest.raises(AssertionError, match="setup-python.*cache"):
        _assert_candidate_cache_boundary(steps)


def test_candidate_cache_boundary_rejects_enabled_setup_uv_cache() -> None:
    steps = _mutable_all_workflow_steps()
    setup_uv = next(
        step
        for step in steps
        if _action_repository(_step_uses(step)) == "astral-sh/setup-uv"
    )
    _mutable_step_inputs(setup_uv)["enable-cache"] = True

    with pytest.raises(AssertionError, match="setup-uv.*enable-cache"):
        _assert_candidate_cache_boundary(steps)


def _mutable_all_workflow_steps() -> list[dict[str, object]]:
    return [deepcopy(dict(step)) for step in _all_workflow_steps()]


def _mutable_step_inputs(step: dict[str, object]) -> dict[str, object]:
    inputs = step.get("with")
    if inputs is None:
        result: dict[str, object] = {}
        step["with"] = result
        return result
    if not isinstance(inputs, dict):
        raise AssertionError("workflow step inputs are not a mapping")
    return inputs


def _action_repository(uses: str) -> str | None:
    reference = _action_reference(uses)
    return reference[0] if reference is not None else None


def _action_reference(uses: str) -> tuple[str, str] | None:
    action_path, separator, ref = uses.rpartition("@")
    if not separator:
        return None
    parts = action_path.split("/")
    if len(parts) < 2 or not all(parts[:2]) or not ref:
        return None
    return "/".join(parts[:2]).casefold(), ref


def _action_is_pinned_to_commit(uses: str) -> bool:
    reference = _action_reference(uses)
    return reference is not None and _IMMUTABLE_ACTION_REF.fullmatch(reference[1]) is not None


def _assert_candidate_cache_boundary(steps: Sequence[WorkflowStep]) -> None:
    cache_actions = [
        _step_uses(step)
        for step in steps
        if _action_repository(_step_uses(step)) == "actions/cache"
    ]
    assert not cache_actions, f"actions/cache variants are forbidden: {cache_actions!r}"

    setup_python_steps = [
        step
        for step in steps
        if _action_repository(_step_uses(step)) == "actions/setup-python"
    ]
    assert setup_python_steps
    for step in setup_python_steps:
        inputs = _step_mapping(step, "with")
        assert all(str(key).casefold() != "cache" for key in inputs), (
            "actions/setup-python must omit the dependency cache input"
        )

    setup_uv_steps = [
        step
        for step in steps
        if _action_repository(_step_uses(step)) == "astral-sh/setup-uv"
    ]
    assert setup_uv_steps
    assert all(_step_with_value(step, "enable-cache") is False for step in setup_uv_steps), (
        "astral-sh/setup-uv must set enable-cache to false"
    )


def test_trusted_producer_checkouts_are_immutable_and_separate_from_candidate_data() -> None:
    producer_jobs = _trusted_producer_jobs()
    assert producer_jobs
    for workflow_name, job in producer_jobs:
        producer_positions = [
            index
            for index, step in enumerate(job)
            if _is_trusted_producer_invocation(_step_run(step))
        ]
        trusted_checkouts = [
            (index, step)
            for index, step in enumerate(job)
            if _step_with_value(step, "path") == "trusted-verifier"
        ]
        candidate_checkouts = [
            (index, step)
            for index, step in enumerate(job)
            if _step_with_value(step, "path") == "candidate"
        ]
        assert len(trusted_checkouts) == 1
        assert len(candidate_checkouts) == 1
        assert trusted_checkouts[0][0] < min(producer_positions)
        assert candidate_checkouts[0][0] < min(producer_positions)
        for _index, checkout in (*trusted_checkouts, *candidate_checkouts):
            assert _action_repository(_step_uses(checkout)) == "actions/checkout"
            assert _action_is_pinned_to_commit(_step_uses(checkout))
            assert _step_with_value(checkout, "persist-credentials") is False
        trusted_checkout = trusted_checkouts[0][1]
        candidate_checkout = candidate_checkouts[0][1]
        if workflow_name == "validation":
            assert _step_with_value(trusted_checkout, "repository") == "${{ github.repository }}"
            assert _step_with_value(trusted_checkout, "ref") in {
                "${{ github.event.pull_request.base.sha || github.sha }}",
                "${{ github.sha }}",
            }
            assert _step_with_value(candidate_checkout, "repository") in {
                "${{ github.event.pull_request.head.repo.full_name || github.repository }}",
                "${{ github.repository }}",
            }
            assert _step_with_value(candidate_checkout, "ref") in {
                "${{ github.event.pull_request.head.sha || github.sha }}",
                "${{ github.sha }}",
            }
        else:
            assert _step_with_value(trusted_checkout, "repository") == (
                "${{ job.workflow_repository }}"
            )
            assert _step_with_value(trusted_checkout, "ref") == "${{ job.workflow_sha }}"
            assert _step_with_value(candidate_checkout, "repository") is None
            assert _step_with_value(candidate_checkout, "ref") == ("${{ inputs.candidate_commit }}")


def test_candidate_execution_stays_inside_the_trusted_producer_boundary() -> None:
    workflows = dict(_workflow_sources())
    producer_jobs = _trusted_producer_jobs()
    for _workflow_name, job in producer_jobs:
        assert any(_step_uses(step).startswith("actions/setup-python@") for step in job)
        assert any(_step_uses(step).startswith("astral-sh/setup-uv@") for step in job)

    _assert_candidate_execution_boundary(workflows)

    for step_name in (
        "Produce source validation evidence",
        "Build candidate distributions",
        "Validate installed candidate",
    ):
        run = _step_run(_workflow_step(workflows["validation"], step_name))
        assert _is_trusted_producer_invocation(run)
        assert "--execution-boundary container" in run

    preflight = _workflow_step(
        workflows["release"],
        "Verify release provenance without executing candidate code",
    )
    installed = _workflow_step(
        workflows["release"],
        "Validate exact release candidate inside the isolated container",
    )
    preflight_run = _step_run(preflight)
    installed_run = _step_run(installed)
    assert _is_trusted_producer_invocation(preflight_run)
    assert "--mode release-preflight" in preflight_run
    assert "--execution-boundary" not in preflight_run
    assert _is_trusted_producer_invocation(installed_run)
    assert "--mode installed" in installed_run
    assert "--execution-boundary container" in installed_run


@pytest.mark.parametrize(
    ("run", "message"),
    (
        (
            f"echo {TRUSTED_PRODUCER}; bash candidate/scripts/check.sh",
            "direct candidate execution is forbidden",
        ),
        (
            "cd candidate && uv run pytest",
            "direct candidate execution is forbidden",
        ),
        (
            "(cd candidate && uv run pytest)",
            "direct candidate execution is forbidden",
        ),
        (
            "env python candidate/script.py",
            "direct candidate execution is forbidden",
        ),
        (
            "uv run --project candidate pytest",
            "direct candidate execution is forbidden",
        ),
        (
            "python candidate/scripts/check.py",
            "direct candidate execution is forbidden",
        ),
    ),
)
def test_candidate_execution_boundary_rejects_direct_candidate_commands(
    run: str,
    message: str,
) -> None:
    workflows = _mutable_workflow_documents()
    producer = _workflow_step(
        workflows["validation"],
        "Produce source validation evidence",
    )
    producer["run"] = run

    with pytest.raises(AssertionError, match=message):
        _assert_candidate_execution_boundary(workflows)


@pytest.mark.parametrize(
    "run",
    (
        (f"{TRUSTED_PRODUCER} --mode build --repo candidate && ./candidate/script.sh"),
        (f"{TRUSTED_PRODUCER} --mode build --repo candidate && $(candidate/script.sh)"),
    ),
)
def test_candidate_execution_boundary_rejects_untrusted_candidate_commands(
    run: str,
) -> None:
    workflows = _mutable_workflow_documents()
    producer = _workflow_step(
        workflows["validation"],
        "Produce source validation evidence",
    )
    producer["run"] = run

    with pytest.raises(AssertionError, match="candidate-bearing step"):
        _assert_candidate_execution_boundary(workflows)


def test_candidate_execution_boundary_rejects_local_action_under_candidate() -> None:
    workflows = _mutable_workflow_documents()
    _prepend_workflow_step(
        workflows["validation"],
        {
            "name": "Invoke candidate local action",
            "uses": "./candidate/.github/actions/unsafe",
        },
    )

    with pytest.raises(AssertionError, match="local action.*candidate"):
        _assert_candidate_execution_boundary(workflows)


@pytest.mark.parametrize("scope", ("workflow", "job", "step"))
def test_candidate_execution_boundary_rejects_candidate_working_directory(
    scope: str,
) -> None:
    workflows = _mutable_workflow_documents()
    validation = workflows["validation"]
    if scope == "workflow":
        validation["defaults"] = {"run": {"working-directory": "candidate"}}
    elif scope == "job":
        _workflow_job_documents(validation)[0]["defaults"] = {
            "run": {"working-directory": "${{ github.workspace }}/candidate"}
        }
    else:
        producer = _workflow_step(
            validation,
            "Produce source validation evidence",
        )
        producer["working-directory"] = "./candidate"

    with pytest.raises(AssertionError, match=f"{scope}.*working-directory"):
        _assert_candidate_execution_boundary(workflows)


@pytest.mark.parametrize(
    ("step_name", "unpinned_uses"),
    (
        ("Check out candidate as data", "actions/checkout@v5"),
        ("Upload candidate distributions", "actions/upload-artifact@v5"),
    ),
)
def test_candidate_execution_boundary_rejects_unpinned_candidate_transfers(
    step_name: str,
    unpinned_uses: str,
) -> None:
    workflows = _mutable_workflow_documents()
    step = _workflow_step(workflows["validation"], step_name)
    step["uses"] = unpinned_uses

    with pytest.raises(AssertionError, match="immutable commit"):
        _assert_candidate_execution_boundary(workflows)


@pytest.mark.parametrize(
    "uses",
    ("actions/checkout@v5", "actions/download-artifact@v5", "actions/upload-artifact@v5"),
)
def test_candidate_execution_boundary_rejects_every_unpinned_transfer(
    uses: str,
) -> None:
    workflows = _mutable_workflow_documents()
    _prepend_workflow_step(
        workflows["validation"],
        {"name": "Transfer source data", "uses": uses},
    )

    with pytest.raises(AssertionError, match="immutable commit"):
        _assert_candidate_execution_boundary(workflows)


@pytest.mark.parametrize(
    ("workflow_name", "step_name", "expected_count"),
    (
        ("validation", "Check out immutable trusted verifier", 6),
        ("release", "Check out immutable repository verifier", 1),
    ),
)
def test_candidate_execution_boundary_does_not_classify_trusted_verifier_checkout(
    workflow_name: str,
    step_name: str,
    expected_count: int,
) -> None:
    workflows = dict(_workflow_sources())
    trusted_checkouts = [
        step
        for job in _workflow_jobs(workflows[workflow_name])
        for step in job
        if step.get("name") == step_name
    ]

    assert len(trusted_checkouts) == expected_count
    assert all(_classify_candidate_step(step) is None for step in trusted_checkouts)


@pytest.mark.parametrize("mutation", ("unpinned", "persisted_credentials"))
def test_candidate_execution_boundary_rejects_weakened_trusted_verifier_checkout(
    mutation: str,
) -> None:
    workflows = _mutable_workflow_documents()
    trusted_checkout = _workflow_step(
        workflows["validation"],
        "Check out immutable trusted verifier",
    )
    if mutation == "unpinned":
        trusted_checkout["uses"] = "actions/checkout@v5"
    else:
        inputs = trusted_checkout.get("with")
        assert isinstance(inputs, dict)
        inputs["persist-credentials"] = True

    with pytest.raises(AssertionError, match="trusted verifier checkout"):
        _assert_candidate_execution_boundary(workflows)


def test_candidate_execution_boundary_rejects_renamed_candidate_checkout_path() -> None:
    workflows = _mutable_workflow_documents()
    candidate_checkout = _workflow_step(
        workflows["validation"],
        "Check out candidate as data",
    )
    inputs = candidate_checkout.get("with")
    assert isinstance(inputs, dict)
    inputs["path"] = "head"
    producer = _workflow_step(
        workflows["validation"],
        "Produce source validation evidence",
    )
    producer["run"] = "python head/scripts/check.py"

    with pytest.raises(AssertionError, match="candidate checkout path"):
        _assert_candidate_execution_boundary(workflows)


@pytest.mark.parametrize(
    "carrier",
    ("step_shell", "step_environment", "workflow_shell", "job_environment"),
)
def test_candidate_execution_boundary_rejects_candidate_execution_carriers(
    carrier: str,
) -> None:
    workflows = _mutable_workflow_documents()
    validation = workflows["validation"]
    producer = _workflow_step(
        validation,
        "Produce source validation evidence",
    )
    if carrier == "step_shell":
        producer["shell"] = "python candidate/shell.py {0}"
    elif carrier == "step_environment":
        producer["env"] = {"BASH_ENV": "candidate/bootstrap.sh"}
    elif carrier == "workflow_shell":
        validation["defaults"] = {
            "run": {"shell": "python candidate/shell.py {0}"}
        }
    else:
        _workflow_job_documents(validation)[0]["env"] = {
            "BASH_ENV": "candidate/bootstrap.sh"
        }

    with pytest.raises(AssertionError, match="candidate.*(?:shell|environment)"):
        _assert_candidate_execution_boundary(workflows)


@pytest.mark.parametrize(
    "carrier",
    ("step_shell", "step_environment", "workflow_shell", "job_environment"),
)
def test_candidate_execution_boundary_rejects_unapproved_execution_carriers(
    carrier: str,
) -> None:
    workflows = _mutable_workflow_documents()
    validation = workflows["validation"]
    producer = _workflow_step(
        validation,
        "Produce source validation evidence",
    )
    if carrier == "step_shell":
        producer["shell"] = 'python -c "print(1)" {0}'
    elif carrier == "step_environment":
        producer["env"] = {"BASH_ENV": "/tmp/bootstrap.sh"}
    elif carrier == "workflow_shell":
        validation["defaults"] = {"run": {"shell": 'python -c "print(1)" {0}'}}
    else:
        _workflow_job_documents(validation)[0]["env"] = {
            "BASH_ENV": "/tmp/bootstrap.sh"
        }

    with pytest.raises(AssertionError, match="candidate-bearing.*not approved"):
        _assert_candidate_execution_boundary(workflows)


@pytest.mark.parametrize(
    "container",
    (
        {"image": "python:3.13"},
        {
            "image": "python:3.13",
            "env": {"BASH_ENV": "candidate/bootstrap.sh"},
        },
    ),
)
def test_candidate_execution_boundary_rejects_candidate_job_container(
    container: dict[str, object],
) -> None:
    workflows = _mutable_workflow_documents()
    validation_job = _workflow_job_documents(workflows["validation"])[0]
    validation_job["container"] = container

    with pytest.raises(AssertionError, match="candidate.*container"):
        _assert_candidate_execution_boundary(workflows)


def test_candidate_execution_boundary_rejects_job_services() -> None:
    workflows = _mutable_workflow_documents()
    validation_job = _workflow_job_documents(workflows["validation"])[0]
    validation_job["services"] = {"helper": {"image": "python:3.13"}}

    with pytest.raises(AssertionError, match="candidate.*services"):
        _assert_candidate_execution_boundary(workflows)


def test_candidate_execution_boundary_rejects_reusable_workflow_job() -> None:
    workflows = _mutable_workflow_documents()
    jobs = workflows["validation"].get("jobs")
    assert isinstance(jobs, dict)
    jobs["delegated-candidate"] = {
        "uses": (
            "owner/repository/.github/workflows/validate.yml@"
            "0123456789abcdef0123456789abcdef01234567"
        ),
        "with": {"candidate_path": "candidate"},
    }

    with pytest.raises(AssertionError, match="reusable workflow"):
        _assert_candidate_execution_boundary(workflows)


@pytest.mark.parametrize(
    "step",
    (
        {
            "uses": "example/opaque-action@0123456789abcdef0123456789abcdef01234567"
        },
        {
            "run": (
                "python -c \"import pathlib; "
                "exec(next(pathlib.Path().glob('*/payload.py')).read_text())\""
            )
        },
    ),
)
def test_candidate_execution_boundary_rejects_unapproved_host_steps(
    step: dict[str, object],
) -> None:
    workflows = _mutable_workflow_documents()
    _prepend_workflow_step(workflows["validation"], step)

    with pytest.raises(AssertionError, match="candidate-bearing job"):
        _assert_candidate_execution_boundary(workflows)


def test_candidate_execution_boundary_rejects_unapproved_host_step_after_download() -> None:
    workflows = _mutable_workflow_documents()
    installed_jobs = dict(_workflow_named_jobs(workflows["validation"]))
    installed = installed_jobs["installed"]
    steps = installed.get("steps")
    assert isinstance(steps, list)
    steps[:] = [
        step
        for step in steps
        if not (
            isinstance(step, dict)
            and step.get("name") == "Check out candidate as data"
        )
    ]
    steps.append({"run": 'python -c "print(1)"'})

    with pytest.raises(AssertionError, match="candidate-bearing job"):
        _assert_candidate_execution_boundary(workflows)


def test_candidate_execution_boundary_rejects_artifact_overlay() -> None:
    workflows = _mutable_workflow_documents()
    upload = _workflow_step(
        workflows["validation"],
        "Upload candidate distributions",
    )
    upload_inputs = upload.get("with")
    assert isinstance(upload_inputs, dict)
    upload_inputs["path"] = "candidate"
    installed = dict(_workflow_named_jobs(workflows["validation"]))["installed"]
    steps = _job_steps(installed)
    assert steps is not None
    download = next(
        step
        for step in steps
        if _action_repository(_step_uses(step)) == "actions/download-artifact"
        and _step_with_value(step, "name") == "candidate-dist"
    )
    download_inputs = download.get("with")
    assert isinstance(download_inputs, dict)
    download_inputs["path"] = "trusted-verifier"

    with pytest.raises(AssertionError, match="artifact transfers"):
        _assert_candidate_execution_boundary(workflows)


def test_candidate_execution_boundary_rejects_changed_producer_directives() -> None:
    workflows = _mutable_workflow_documents()
    producer = _workflow_step(
        workflows["validation"],
        "Produce source validation evidence",
    )
    run = producer.get("run")
    assert isinstance(run, str)
    producer["run"] = run + " --execution-boundary=local-observational"

    with pytest.raises(AssertionError, match="candidate-bearing job"):
        _assert_candidate_execution_boundary(workflows)


def test_candidate_execution_boundary_rejects_skipped_required_run() -> None:
    workflows = _mutable_workflow_documents()
    installed = _workflow_step(
        workflows["release"],
        "Validate exact release candidate inside the isolated container",
    )
    installed["if"] = False

    with pytest.raises(AssertionError, match="run step is not approved"):
        _assert_candidate_execution_boundary(workflows)


def test_candidate_execution_boundary_rejects_non_enforcing_required_job() -> None:
    workflows = _mutable_workflow_documents()
    release_jobs = dict(_workflow_named_jobs(workflows["release"]))
    release_jobs["installed"]["continue-on-error"] = True

    with pytest.raises(AssertionError, match="job controls are not approved"):
        _assert_candidate_execution_boundary(workflows)


def test_candidate_execution_boundary_rejects_cross_lane_host_command() -> None:
    workflows = _mutable_workflow_documents()
    source_job = dict(_workflow_named_jobs(workflows["validation"]))["source"]
    source_steps = source_job.get("steps")
    assert isinstance(source_steps, list)
    advisory = _workflow_step(
        workflows["validation"],
        "Produce advisory fresh-resolution evidence",
    )
    advisory_run = advisory.get("run")
    assert isinstance(advisory_run, str)
    source_steps.append({"run": advisory_run})

    with pytest.raises(AssertionError, match="candidate-bearing job"):
        _assert_candidate_execution_boundary(workflows)


def test_candidate_execution_boundary_rejects_missing_candidate_lane() -> None:
    workflows = _mutable_workflow_documents()
    jobs = workflows["validation"].get("jobs")
    assert isinstance(jobs, dict)
    jobs.pop("advisory_macos")

    with pytest.raises(AssertionError, match="candidate-bearing lanes"):
        _assert_candidate_execution_boundary(workflows)


@pytest.mark.parametrize(
    "steps",
    (
        (
            {"run": 'python -c "print(1)"'},
            {"run": _SOURCE_EVIDENCE_COMMAND},
        ),
        (
            {"run": "echo opaque"},
            {
                "uses": (
                    "actions/upload-artifact@"
                    "0123456789abcdef0123456789abcdef01234567"
                )
            },
        ),
    ),
)
def test_candidate_execution_boundary_rejects_unapproved_candidate_lane(
    steps: tuple[dict[str, object], ...],
) -> None:
    workflows = _mutable_workflow_documents()
    jobs = workflows["validation"].get("jobs")
    assert isinstance(jobs, dict)
    jobs["unapproved-candidate"] = {"runs-on": "ubuntu-latest", "steps": list(steps)}

    with pytest.raises(AssertionError, match="candidate-bearing job"):
        _assert_candidate_execution_boundary(workflows)


def test_workflow_token_scope_excludes_candidate_execution() -> None:
    workflows = dict(_workflow_sources())
    _assert_workflow_token_scope(workflows)


@pytest.mark.parametrize(
    "permissions",
    _INVALID_WORKFLOW_PERMISSION_DECLARATIONS,
)
def test_workflow_token_scope_rejects_invalid_workflow_permissions(
    permissions: object,
) -> None:
    workflows = _mutable_workflow_documents()
    validation = workflows["validation"]
    if permissions is _MISSING_PERMISSIONS:
        validation.pop("permissions")
    else:
        validation["permissions"] = permissions
    assert ("permissions" not in validation) == (
        permissions is _MISSING_PERMISSIONS
    ), "missing permissions must be distinct from an explicit null value"

    with pytest.raises(AssertionError, match="workflow validation permissions"):
        _assert_workflow_token_scope(workflows)


@pytest.mark.parametrize(
    "permissions",
    _INVALID_PERMISSION_DECLARATIONS,
)
def test_workflow_token_scope_rejects_invalid_job_permission_override(
    permissions: object,
) -> None:
    workflows = _mutable_workflow_documents()
    jobs = workflows["validation"].get("jobs")
    assert isinstance(jobs, dict)
    source = jobs.get("source")
    assert isinstance(source, dict)
    source["permissions"] = permissions

    with pytest.raises(AssertionError, match=r"job validation\.source permissions"):
        _assert_workflow_token_scope(workflows)


def test_workflow_token_scope_allows_absent_job_permissions_to_inherit() -> None:
    workflows = _mutable_workflow_documents()
    jobs = workflows["validation"].get("jobs")
    assert isinstance(jobs, dict)
    source = jobs.get("source")
    assert isinstance(source, dict)
    source.pop("permissions", None)
    assert "permissions" not in source

    _assert_workflow_token_scope(workflows)


@pytest.mark.parametrize(
    ("carrier", "key", "value"),
    (
        ("env", "GH_TOKEN", "${{ github.token }}"),
        ("with", "token", "${{ secrets.GITHUB_TOKEN }}"),
        ("env", "TOKEN", "${{ github['token'] }}"),
        ("with", "token", "${{ secrets['GITHUB_TOKEN'] }}"),
        ("env", "CONTEXT", "${{ toJSON(github) }}"),
        ("with", "context", "${{ toJSON(secrets) }}"),
    ),
)
def test_workflow_token_scope_rejects_aliased_candidate_tokens(
    carrier: str,
    key: str,
    value: str,
) -> None:
    workflows = _mutable_workflow_documents()
    installed = _workflow_step(
        workflows["release"],
        "Validate exact release candidate inside the isolated container",
    )
    mapping = installed.setdefault(carrier, {})
    assert isinstance(mapping, dict)
    mapping[key] = value

    with pytest.raises(AssertionError, match="token"):
        _assert_workflow_token_scope(workflows)


@pytest.mark.parametrize(
    "token_reference",
    ("${{ github.token }}", "${{ toJSON(secrets) }}"),
)
def test_workflow_token_scope_rejects_token_in_candidate_run(
    token_reference: str,
) -> None:
    workflows = _mutable_workflow_documents()
    installed = _workflow_step(
        workflows["release"],
        "Validate exact release candidate inside the isolated container",
    )
    installed["run"] = f"python candidate/check.py --token '{token_reference}'"

    with pytest.raises(AssertionError, match="token"):
        _assert_workflow_token_scope(workflows)


def test_workflow_token_scope_rejects_token_in_candidate_shell() -> None:
    workflows = _mutable_workflow_documents()
    installed = _workflow_step(
        workflows["release"],
        "Validate exact release candidate inside the isolated container",
    )
    installed["shell"] = (
        "bash -c 'echo ${{ github.token }} >/dev/null; exec bash {0}'"
    )

    with pytest.raises(AssertionError, match="token"):
        _assert_workflow_token_scope(workflows)


@pytest.mark.parametrize(
    ("scope", "key", "value"),
    (
        ("workflow", "GH_TOKEN", "${{ github.token }}"),
        ("job", "TOKEN", "${{ secrets.GITHUB_TOKEN }}"),
        ("workflow", "GITHUB_TOKEN", "opaque"),
        ("job", "GITHUB_TOKEN", "opaque"),
    ),
)
def test_workflow_token_scope_rejects_inherited_token_environment(
    scope: str,
    key: str,
    value: str,
) -> None:
    workflows = _mutable_workflow_documents()
    validation = workflows["validation"]
    environment = {key: value}
    if scope == "workflow":
        validation["env"] = environment
    else:
        jobs = validation.get("jobs")
        assert isinstance(jobs, dict)
        job = next(iter(jobs.values()))
        assert isinstance(job, dict)
        job["env"] = environment

    with pytest.raises(AssertionError, match=f"{scope}.*token"):
        _assert_workflow_token_scope(workflows)


def test_workflow_token_scope_rejects_job_container_token() -> None:
    workflows = _mutable_workflow_documents()
    validation_job = _workflow_job_documents(workflows["validation"])[0]
    validation_job["container"] = {
        "image": "python:3.13",
        "env": {"GH_TOKEN": "${{ github.token }}"},
    }

    with pytest.raises(AssertionError, match="container.*token"):
        _assert_workflow_token_scope(workflows)


def test_workflow_token_scope_rejects_job_service_token() -> None:
    workflows = _mutable_workflow_documents()
    validation_job = _workflow_job_documents(workflows["validation"])[0]
    validation_job["services"] = {
        "helper": {
            "image": "python:3.13",
            "env": {"GH_TOKEN": "${{ github.token }}"},
        }
    }

    with pytest.raises(AssertionError, match="services.*token"):
        _assert_workflow_token_scope(workflows)


def test_workflow_token_scope_rejects_reusable_workflow_job() -> None:
    workflows = _mutable_workflow_documents()
    jobs = workflows["validation"].get("jobs")
    assert isinstance(jobs, dict)
    jobs["delegated-candidate"] = {
        "uses": (
            "owner/repository/.github/workflows/validate.yml@"
            "0123456789abcdef0123456789abcdef01234567"
        ),
        "secrets": {"token": "${{ github.token }}"},
    }

    with pytest.raises(AssertionError, match="reusable workflow"):
        _assert_workflow_token_scope(workflows)


@pytest.mark.parametrize(
    ("field", "value"),
    (
        ("name", "unrelated-bundle"),
        ("path", "${{ runner.temp }}/unrelated"),
        ("run-id", "${{ inputs.other_run_id }}"),
        ("repository", "other/repository"),
    ),
)
def test_workflow_token_scope_rejects_drifted_download_grants(
    field: str,
    value: str,
) -> None:
    workflows = _mutable_workflow_documents()
    release_steps = [
        step
        for job in _workflow_jobs(workflows["release"])
        for step in job
    ]
    first_download = next(
        step
        for step in release_steps
        if _action_repository(_step_uses(step)) == "actions/download-artifact"
    )
    inputs = first_download.get("with")
    assert isinstance(inputs, dict)
    inputs[field] = value

    with pytest.raises(AssertionError, match="download"):
        _assert_workflow_token_scope(workflows)


def test_workflow_token_scope_rejects_reassigned_download_grant() -> None:
    workflows = _mutable_workflow_documents()
    release = workflows["release"]
    release_steps = [step for job in _workflow_jobs(release) for step in job]
    first_download = next(
        step
        for step in release_steps
        if _action_repository(_step_uses(step)) == "actions/download-artifact"
    )
    inputs = first_download.get("with")
    assert isinstance(inputs, dict)
    inputs.pop("github-token")
    _prepend_workflow_step(
        release,
        {
            "uses": _step_uses(first_download),
            "with": {
                "name": "unrelated-bundle",
                "path": "${{ runner.temp }}/unrelated",
                "run-id": "${{ inputs.artifact_run_id }}",
                "github-token": "${{ github.token }}",
            },
        },
    )

    with pytest.raises(AssertionError, match="download"):
        _assert_workflow_token_scope(workflows)


def _assert_read_only_permissions(subject: str, permissions: object) -> None:
    assert isinstance(permissions, dict), (
        f"{subject} permissions must be an explicit mapping"
    )
    assert all(
        isinstance(permission, str)
        and isinstance(access, str)
        and access in {"read", "none"}
        for permission, access in permissions.items()
    ), f"{subject} permissions must contain only read or none grants"


def _assert_workflow_token_scope(
    workflows: Mapping[str, WorkflowSource],
) -> None:
    for workflow_name, workflow in workflows.items():
        document = _workflow_document(workflow)
        _assert_read_only_permissions(
            f"workflow {workflow_name}",
            document.get("permissions"),
        )
        workflow_env = document.get("env")
        assert not isinstance(workflow_env, dict) or "GITHUB_TOKEN" not in workflow_env, (
            f"workflow {workflow_name} token environment keys are forbidden"
        )
        assert not _contains_github_token_reference(workflow_env), (
            f"workflow {workflow_name} token values are forbidden"
        )
        assert not _contains_github_token_reference(_default_run_value(document, "shell")), (
            f"workflow {workflow_name} default shell token values are forbidden"
        )
        jobs = document.get("jobs")
        assert isinstance(jobs, dict)
        for job_name, job in jobs.items():
            assert isinstance(job, dict)
            if "permissions" in job:
                _assert_read_only_permissions(
                    f"job {workflow_name}.{job_name}",
                    job["permissions"],
                )
            assert job.get("uses") is None, (
                f"job {job_name} reusable workflow calls are forbidden by token boundary"
            )
            job_env = job.get("env")
            assert not isinstance(job_env, dict) or "GITHUB_TOKEN" not in job_env, (
                f"job {job_name} token environment keys are forbidden"
            )
            assert not _contains_github_token_reference(job_env), (
                f"job {job_name} token values are forbidden"
            )
            assert not _contains_github_token_reference(job.get("container")), (
                f"job {job_name} container token values are forbidden"
            )
            assert job.get("services") is None, (
                f"job {job_name} services token values are forbidden"
            )
            assert not _contains_github_token_reference(_default_run_value(job, "shell")), (
                f"job {job_name} default shell token values are forbidden"
            )
    steps = _all_workflow_steps(workflows)
    preflight = _workflow_step(
        workflows["release"],
        "Verify release provenance without executing candidate code",
    )
    installed = _workflow_step(
        workflows["release"],
        "Validate exact release candidate inside the isolated container",
    )
    release_steps = [step for job in _workflow_jobs(workflows["release"]) for step in job]
    token_downloads = [
        step
        for step in release_steps
        if _action_repository(_step_uses(step)) == "actions/download-artifact"
        and _step_with_value(step, "github-token") == "${{ github.token }}"
    ]
    assert len(token_downloads) == 2
    for download in token_downloads:
        assert _action_is_pinned_to_commit(_step_uses(download))
        assert not _step_exposes_github_token(download, include_inputs=False)
        token_inputs = {
            key: value
            for key, value in _step_mapping(download, "with").items()
            if _contains_github_token_reference(value)
        }
        assert token_inputs == {"github-token": "${{ github.token }}"}
    assert [_step_mapping(download, "with") for download in token_downloads] == [
        {
            "name": "${{ inputs.artifact_name }}",
            "path": "${{ runner.temp }}/candidate",
            "run-id": "${{ inputs.artifact_run_id }}",
            "github-token": "${{ github.token }}",
        },
        {
            "name": "validation-evidence-build",
            "path": "${{ runner.temp }}/candidate-evidence",
            "run-id": "${{ inputs.artifact_run_id }}",
            "github-token": "${{ github.token }}",
        },
    ], "release token downloads must retain their exact trusted inputs"

    token_steps = [step for step in steps if _step_exposes_github_token(step)]
    assert token_steps == [*token_downloads, preflight], (
        "token values are restricted to pinned release artifact downloads and preflight"
    )
    preflight_env = _step_mapping(preflight, "env")
    token_environment = {
        key: value
        for key, value in preflight_env.items()
        if key == "GITHUB_TOKEN" or _contains_github_token_reference(value)
    }
    assert token_environment == {"GITHUB_TOKEN": "${{ github.token }}"}
    assert not _contains_github_token_reference(_step_mapping(preflight, "with"))
    assert not _step_exposes_github_token(installed)


def _workflow_sources() -> tuple[tuple[str, str], ...]:
    if not VALIDATION_WORKFLOW.is_file() or not RELEASE_WORKFLOW.is_file():
        pytest.skip("Static workflow boundary evidence requires repository workflow sources.")
    return (
        ("validation", VALIDATION_WORKFLOW.read_text(encoding="utf-8")),
        ("release", RELEASE_WORKFLOW.read_text(encoding="utf-8")),
    )


def _mutable_workflow_documents() -> dict[str, dict[str, object]]:
    documents: dict[str, dict[str, object]] = {}
    for name, source in _workflow_sources():
        document = yaml.safe_load(source)
        if not isinstance(document, dict):
            raise AssertionError(f"{name} workflow root is not a mapping")
        documents[name] = deepcopy(document)
    return documents


def _prepend_workflow_step(
    workflow: dict[str, object],
    step: dict[str, object],
) -> None:
    for job in _workflow_job_documents(workflow):
        steps = job.get("steps")
        if isinstance(steps, list):
            steps.insert(0, step)
            return
    raise AssertionError("workflow has no mutable steps")


def _all_workflow_steps(
    workflows: Mapping[str, WorkflowSource] | None = None,
) -> list[WorkflowStep]:
    sources = workflows.items() if workflows is not None else _workflow_sources()
    return [
        step
        for _workflow_name, workflow in sources
        for job in _workflow_jobs(workflow)
        for step in job
    ]


def _trusted_producer_jobs() -> list[tuple[str, WorkflowJob]]:
    return [
        (workflow_name, job)
        for workflow_name, workflow in _workflow_sources()
        for job in _workflow_jobs(workflow)
        if any(_is_trusted_producer_invocation(_step_run(step)) for step in job)
    ]


def _workflow_step(workflow: WorkflowSource, name: str) -> WorkflowStep:
    for job in _workflow_jobs(workflow):
        for step in job:
            if step.get("name") == name:
                return step
    raise AssertionError(f"workflow step {name!r} is missing")


def _workflow_jobs(workflow: WorkflowSource) -> list[tuple[WorkflowStep, ...]]:
    result: list[tuple[WorkflowStep, ...]] = []
    for job in _workflow_job_documents(workflow):
        steps = _job_steps(job)
        if steps is None:
            continue
        result.append(steps)
    return result


def _workflow_job_documents(workflow: WorkflowSource) -> list[dict[str, object]]:
    return [job for _name, job in _workflow_named_jobs(workflow)]


def _workflow_named_jobs(
    workflow: WorkflowSource,
) -> list[tuple[str, dict[str, object]]]:
    document = _workflow_document(workflow)
    jobs = document.get("jobs")
    if not isinstance(jobs, dict):
        raise AssertionError("workflow jobs are not a mapping")
    result: list[tuple[str, dict[str, object]]] = []
    for name, job in jobs.items():
        if not isinstance(job, dict):
            raise AssertionError("workflow job is not a mapping")
        result.append((str(name), job))
    return result


def _job_steps(job: WorkflowDocument) -> tuple[WorkflowStep, ...] | None:
    steps = job.get("steps")
    if steps is None:
        return None
    if not isinstance(steps, list) or not all(isinstance(step, dict) for step in steps):
        raise AssertionError("workflow steps are not mappings")
    return tuple(step for step in steps if isinstance(step, dict))


def _workflow_document(workflow: WorkflowSource) -> WorkflowDocument:
    document = yaml.safe_load(workflow) if isinstance(workflow, str) else workflow
    if not isinstance(document, dict):
        raise AssertionError("workflow root is not a mapping")
    return document


def _step_uses(step: WorkflowStep) -> str:
    value = step.get("uses")
    return value if isinstance(value, str) else ""


def _step_run(step: WorkflowStep) -> str:
    value = step.get("run")
    return value if isinstance(value, str) else ""


def _step_mapping(step: WorkflowStep, key: str) -> Mapping[str, object]:
    value = step.get(key)
    return value if isinstance(value, dict) else {}


def _step_with_value(step: WorkflowStep, key: str) -> object:
    return _step_mapping(step, "with").get(key)


def _assert_candidate_execution_boundary(
    workflows: Mapping[str, WorkflowSource],
) -> None:
    _assert_no_candidate_working_directories(workflows)
    steps = _all_workflow_steps(workflows)
    candidate_step_kinds = {
        kind
        for step in steps
        if (kind := _classify_candidate_step(step)) is not None
    }
    assert candidate_step_kinds == _CANDIDATE_STEP_KINDS
    _assert_candidate_job_topologies(workflows)


def _assert_no_candidate_working_directories(
    workflows: Mapping[str, WorkflowSource],
) -> None:
    for workflow_name, source in workflows.items():
        document = _workflow_document(source)
        _assert_execution_defaults(document, f"workflow {workflow_name}")
        jobs = document.get("jobs")
        if not isinstance(jobs, dict):
            raise AssertionError("workflow jobs are not a mapping")
        for job_name, job in jobs.items():
            if not isinstance(job, dict):
                raise AssertionError("workflow job is not a mapping")
            assert job.get("uses") is None, (
                f"candidate reusable workflow job {job_name} is forbidden"
            )
            assert job.get("container") is None, (
                f"candidate job {job_name} container configuration is forbidden"
            )
            assert job.get("services") is None, (
                f"candidate job {job_name} services are forbidden"
            )
            _assert_execution_defaults(job, f"job {job_name}")
            steps = _job_steps(job)
            if steps is None:
                continue
            for step in steps:
                working_directory = step.get("working-directory")
                assert not _is_candidate_path(working_directory), (
                    "step working-directory must not target candidate"
                )
                assert not _contains_candidate_reference(step.get("shell")), (
                    "candidate step shell is forbidden"
                )
                assert not _contains_candidate_reference(step.get("env")), (
                    "candidate step environment is forbidden"
                )


def _assert_execution_defaults(
    owner: WorkflowDocument,
    scope: str,
) -> None:
    assert not _contains_candidate_reference(owner.get("env")), (
        f"{scope} candidate environment is forbidden"
    )
    working_directory = _default_run_value(owner, "working-directory")
    assert not _is_candidate_path(working_directory), (
        f"{scope} working-directory must not target candidate"
    )
    assert not _contains_candidate_reference(_default_run_value(owner, "shell")), (
        f"{scope} candidate shell is forbidden"
    )


def _default_run_value(owner: WorkflowDocument, key: str) -> object:
    defaults = owner.get("defaults")
    if not isinstance(defaults, dict):
        return None
    run_defaults = defaults.get("run")
    if not isinstance(run_defaults, dict):
        return None
    return run_defaults.get(key)


def _assert_candidate_job_topologies(
    workflows: Mapping[str, WorkflowSource],
) -> None:
    assert set(_APPROVED_ARTIFACT_TRANSFERS) == set(_APPROVED_CANDIDATE_JOB_RUNS)
    assert set(_APPROVED_CANDIDATE_JOB_CONTROLS) == set(
        _APPROVED_CANDIDATE_JOB_RUNS
    )
    observed_lane_keys: set[tuple[str, str]] = set()
    for workflow_name, source in workflows.items():
        document = _workflow_document(source)
        for job_name, job in _workflow_named_jobs(source):
            steps = _job_steps(job)
            if steps is None or not any(
                _classify_candidate_step(step) is not None
                for step in steps
            ):
                continue
            assert document.get("env") is None, (
                f"candidate-bearing workflow {workflow_name} environment is not approved"
            )
            assert _default_run_value(document, "shell") is None, (
                f"candidate-bearing workflow {workflow_name} shell is not approved"
            )
            assert job.get("env") is None, (
                f"candidate-bearing job {workflow_name}/{job_name} environment is not approved"
            )
            assert _default_run_value(job, "shell") is None, (
                f"candidate-bearing job {workflow_name}/{job_name} shell is not approved"
            )
            approved_runs = _APPROVED_CANDIDATE_JOB_RUNS.get(
                (workflow_name, job_name)
            )
            assert approved_runs is not None, (
                f"candidate-bearing job {workflow_name}/{job_name} is not approved"
            )
            approved_transfers = _APPROVED_ARTIFACT_TRANSFERS[
                (workflow_name, job_name)
            ]
            assert (
                job.get("if"),
                job.get("continue-on-error"),
            ) == _APPROVED_CANDIDATE_JOB_CONTROLS[(workflow_name, job_name)], (
                f"candidate-bearing job {workflow_name}/{job_name} "
                "job controls are not approved"
            )
            observed_lane_keys.add((workflow_name, job_name))
            observed_runs: list[str] = []
            observed_transfers: list[
                tuple[object, str, object, tuple[tuple[str, object], ...]]
            ] = []
            for step in steps:
                uses = _step_uses(step)
                run = _step_run(step)
                assert not (uses and run), (
                    f"candidate-bearing job {workflow_name}/{job_name} step mixes uses and run"
                )
                if uses:
                    repository = _action_repository(uses)
                    assert repository is not None
                    assert repository in _CANDIDATE_JOB_ACTION_REPOSITORIES, (
                        f"candidate-bearing job {workflow_name}/{job_name} action is not approved"
                    )
                    assert _action_is_pinned_to_commit(uses), (
                        f"candidate-bearing job {workflow_name}/{job_name} action is not immutable"
                    )
                    assert step.get("shell") is None and step.get("env") is None, (
                        f"candidate-bearing job {workflow_name}/{job_name} "
                        "action execution is not approved"
                    )
                    if repository in _ARTIFACT_TRANSFER_REPOSITORIES:
                        assert set(step) <= {"name", "if", "uses", "with"}, (
                            f"candidate-bearing job {workflow_name}/{job_name} "
                            "artifact transfer shape is not approved"
                        )
                        observed_transfers.append(
                            _artifact_transfer_signature(
                                step.get("name"),
                                repository,
                                step.get("if"),
                                _step_mapping(step, "with"),
                            )
                        )
                if run:
                    observed_runs.append(run)
                    assert run in approved_runs, (
                        f"candidate-bearing job {workflow_name}/{job_name} "
                        "host command is not approved"
                    )
                    expected_shell, expected_env = _APPROVED_RUN_EXECUTION[run]
                    actual_env = step.get("env")
                    assert actual_env is None or isinstance(actual_env, dict), (
                        f"candidate-bearing job {workflow_name}/{job_name} "
                        "environment is not a mapping"
                    )
                    assert step.get("shell") == expected_shell, (
                        f"candidate-bearing job {workflow_name}/{job_name} shell is not approved"
                    )
                    assert (actual_env or {}) == expected_env, (
                        f"candidate-bearing job {workflow_name}/{job_name} "
                        "environment is not approved"
                    )
                    actual_metadata = {
                        key: value for key, value in step.items() if key != "run"
                    }
                    assert actual_metadata == _APPROVED_RUN_STEP_METADATA[run], (
                        f"candidate-bearing job {workflow_name}/{job_name} "
                        "run step is not approved"
                    )
            assert tuple(observed_runs) == approved_runs, (
                f"candidate-bearing job {workflow_name}/{job_name} commands are incomplete"
            )
            assert tuple(observed_transfers) == approved_transfers, (
                f"candidate-bearing job {workflow_name}/{job_name} "
                "artifact transfers are not approved"
            )
    assert observed_lane_keys == set(_APPROVED_CANDIDATE_JOB_RUNS), (
        "candidate-bearing lanes do not match the approved topology"
    )


def _classify_candidate_step(step: WorkflowStep) -> str | None:
    uses = _step_uses(step)
    repository = _action_repository(uses)
    if repository == "actions/checkout":
        if _is_trusted_verifier_checkout(step):
            assert _action_is_pinned_to_commit(uses), (
                "trusted verifier checkout must use an immutable commit"
            )
            assert _step_with_value(step, "persist-credentials") is False, (
                "trusted verifier checkout must disable persisted credentials"
            )
            return None
        assert _action_is_pinned_to_commit(uses), (
            "candidate checkout must use an immutable commit"
        )
        assert _step_with_value(step, "path") == "candidate", (
            "candidate checkout path must remain candidate"
        )
        assert _step_with_value(step, "persist-credentials") is False, (
            "candidate checkout must disable persisted credentials"
        )
        return _CANDIDATE_CHECKOUT
    if repository in _ARTIFACT_TRANSFER_REPOSITORIES:
        assert _action_is_pinned_to_commit(uses), (
            "candidate artifact transfer must use an immutable commit"
        )
        return _CANDIDATE_ARTIFACT_TRANSFER
    if not _contains_candidate_reference(step):
        return None
    if _local_action_uses_candidate(uses):
        raise AssertionError("local action under candidate is forbidden")

    run = _step_run(step)
    if _run_directly_executes_candidate(run):
        raise AssertionError("direct candidate execution is forbidden")
    if _is_trusted_producer_invocation(run):
        return _CANDIDATE_TRUSTED_PRODUCER
    raise AssertionError(
        "candidate-bearing step must be a pinned checkout, pinned artifact transfer, "
        "or exact trusted producer invocation"
    )


def _is_trusted_producer_invocation(run: str) -> bool:
    if any(character in run for character in "\r\n`#"):
        return False
    lexer = shlex.shlex(run, posix=True, punctuation_chars=True)
    lexer.commenters = ""
    lexer.whitespace_split = True
    try:
        tokens = tuple(lexer)
    except ValueError:
        return False
    return tokens[: len(_TRUSTED_PRODUCER_COMMAND)] == _TRUSTED_PRODUCER_COMMAND and all(
        not _SHELL_COMMAND_BOUNDARY_CHARACTERS.intersection(token) for token in tokens
    )


def _run_directly_executes_candidate(run: str) -> bool:
    if _CANDIDATE_INTERPRETER_TARGET.search(run) is not None:
        return True
    if any(
        _contains_candidate_reference(match.group("arguments"))
        for match in _UV_RUN.finditer(run)
    ):
        return True
    return any(
        _is_candidate_path(match.group("target").strip("\"'"))
        for match in _SHELL_CD.finditer(run)
    )


def _local_action_uses_candidate(uses: str) -> bool:
    return bool(uses) and "@" not in uses and _is_candidate_path(uses)


def _is_trusted_verifier_checkout(step: WorkflowStep) -> bool:
    inputs = _step_mapping(step, "with")
    return (
        inputs.get("repository"),
        inputs.get("ref"),
        inputs.get("path"),
    ) in _TRUSTED_VERIFIER_CHECKOUT_INPUTS


def _is_candidate_path(value: object) -> bool:
    return isinstance(value, str) and _CANDIDATE_PATH_SEGMENT.search(
        value.strip().strip("\"'")
    ) is not None


def _contains_candidate_reference(value: object) -> bool:
    if isinstance(value, str):
        return _CANDIDATE_REFERENCE.search(value) is not None
    if isinstance(value, Mapping):
        return any(
            _contains_candidate_reference(key) or _contains_candidate_reference(item)
            for key, item in value.items()
        )
    if isinstance(value, (list, tuple)):
        return any(_contains_candidate_reference(item) for item in value)
    return False


def _step_exposes_github_token(
    step: WorkflowStep,
    *,
    include_inputs: bool = True,
) -> bool:
    environment = _step_mapping(step, "env")
    if "GITHUB_TOKEN" in environment or _contains_github_token_reference(environment):
        return True
    if _contains_github_token_reference(_step_run(step)):
        return True
    if _contains_github_token_reference(step.get("shell")):
        return True
    return include_inputs and _contains_github_token_reference(
        _step_mapping(step, "with")
    )


def _contains_github_token_reference(value: object) -> bool:
    if isinstance(value, str):
        return _GITHUB_TOKEN_REFERENCE.search(value) is not None
    if isinstance(value, Mapping):
        return any(_contains_github_token_reference(item) for item in value.values())
    if isinstance(value, (list, tuple)):
        return any(_contains_github_token_reference(item) for item in value)
    return False
