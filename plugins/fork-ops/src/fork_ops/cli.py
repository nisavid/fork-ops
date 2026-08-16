"""Command-line adapter for Fork Ops."""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Callable
from pathlib import Path
from typing import Any, cast

from ._contracts import ArtifactKind, _canonical_state_payloads
from .core import (
    MAX_FILE_BYTES,
    SCAN_PROFILES,
    ForkOpsError,
    _read_absolute_regular_file,
    _require_current_artifact,
    _validate_bounded_object,
    assess_migration,
    build_equipment_migration_preflight,
    build_plugin_health_report,
    build_status_report,
    build_workflow_migration_inventory,
    create_initial_config_text,
    dry_run_migration,
    dry_run_migration_plan,
    execute_migration,
    explain_migration_blocker,
    generate_migration_plan,
    initialize_config,
    propose_migration_config_patch,
    read_config_result,
    schema_artifact_report,
    schema_json,
)
from .schema import CAPABILITY_LEVELS
from .workflow_catalog import workflow_catalog


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    func = cast(Callable[[argparse.Namespace], int], args.func)
    try:
        return func(args)
    except ForkOpsError as exc:
        print(str(exc), file=sys.stderr)
        return 2


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="fork-ops",
        description="Operate maintained repository forks.",
    )

    subcommands = parser.add_subparsers(dest="command", required=True)

    config = subcommands.add_parser("config", help="Read or create Fork Ops config.")
    config_subcommands = config.add_subparsers(dest="config_command", required=True)

    show = config_subcommands.add_parser("show", help="Show Fork Ops config.")
    _add_repo_arg(show)
    show.add_argument("--format", choices=["toml", "json"])
    show.add_argument("--normalized", action="store_true", help="Show normalized JSON config.")
    show.set_defaults(func=cmd_config_show)

    validate = config_subcommands.add_parser("validate", help="Validate Fork Ops config.")
    _add_repo_arg(validate)
    validate.add_argument(
        "--required-level",
        choices=CAPABILITY_LEVELS,
    )
    validate.add_argument("--json", action="store_true", help="Print full JSON report.")
    validate.set_defaults(func=cmd_config_validate)

    init = config_subcommands.add_parser("init", help="Generate a starter Fork Ops config.")
    init.add_argument("--repo", help="Repository root to inspect or mutate.")
    init.add_argument("--repository-owner", default="OWNER")
    init.add_argument("--repository-name", default="REPO")
    init.add_argument("--upstream-owner", default="UPSTREAM_OWNER")
    init.add_argument("--upstream-name", default="UPSTREAM_REPO")
    init.add_argument("--default-branch", default="main")
    init.add_argument(
        "--write",
        action="store_true",
        help="Write .agents/fork-ops.toml instead of printing.",
    )
    init.set_defaults(func=cmd_config_init)

    capability = subcommands.add_parser("capability", help="Report Fork Ops capability levels.")
    capability_subcommands = capability.add_subparsers(dest="capability_command", required=True)
    report = capability_subcommands.add_parser("report", help="Report capability levels.")
    _add_repo_arg(report)
    report.add_argument("--json", action="store_true", help="Print full JSON report.")
    report.set_defaults(func=cmd_capability_report)

    migration = subcommands.add_parser(
        "migration",
        help="Assess migration from existing fork materials.",
    )
    migration_subcommands = migration.add_subparsers(dest="migration_command", required=True)
    assess = migration_subcommands.add_parser("assess", help="Run read-only migration assessment.")
    _add_repo_arg(assess)
    assess.add_argument(
        "--with-proposed-config",
        action="store_true",
        help="Include the non-mutating proposed config patch in the assessment output.",
    )
    assess.set_defaults(func=cmd_migration_assess)
    preflight = migration_subcommands.add_parser(
        "preflight",
        help="Build a read-only equipment migration preflight.",
    )
    _add_repo_arg(preflight)
    preflight.add_argument(
        "--source-root",
        action="append",
        dest="source_roots",
        help="Additional global or local equipment root to scan. May be provided more than once.",
    )
    _add_scan_profile_arg(preflight)
    preflight.set_defaults(func=cmd_migration_preflight)
    plan = migration_subcommands.add_parser(
        "plan",
        help="Generate a non-mutating migration plan.",
    )
    _add_repo_arg(plan)
    _add_scan_profile_arg(plan)
    plan.set_defaults(func=cmd_migration_plan)
    dry_run = migration_subcommands.add_parser(
        "dry-run",
        help="Preview a migration plan without mutating the repository.",
    )
    dry_run_source = dry_run.add_mutually_exclusive_group()
    dry_run_source.add_argument("--repo", default=".", help="Repository root to inspect.")
    dry_run_source.add_argument(
        "--plan",
        help="Read an existing migration plan JSON file instead of generating one from --repo.",
    )
    _add_scan_profile_arg(dry_run)
    dry_run.set_defaults(func=cmd_migration_dry_run)
    execute = migration_subcommands.add_parser(
        "execute",
        help="Apply a validated migration plan through guarded operations.",
    )
    execute.add_argument(
        "--repo",
        required=True,
        help="Explicit repository root to mutate and confirm against the plan.",
    )
    execute.add_argument(
        "--plan",
        help="Read an existing migration plan JSON file instead of generating one from --repo.",
    )
    execute.set_defaults(func=cmd_migration_execute)
    explain_blocker = migration_subcommands.add_parser(
        "explain-blocker",
        help="Explain a migration blocker from workflow output JSON.",
    )
    explain_blocker.add_argument(
        "--input",
        required=True,
        help="Read workflow output JSON from a file, or '-' for stdin.",
    )
    explain_blocker.add_argument(
        "--blocker-code",
        help="Explain a specific blocker code from the workflow output.",
    )
    explain_blocker.set_defaults(func=cmd_migration_explain_blocker)
    propose = migration_subcommands.add_parser(
        "propose-config",
        help="Generate a non-mutating Fork Ops config proposal.",
    )
    _add_repo_arg(propose)
    propose.add_argument("--format", choices=["json", "toml"], default="json")
    propose.set_defaults(func=cmd_migration_propose_config)

    workflow = subcommands.add_parser("workflow", help="Inspect Fork Ops workflow contracts.")
    workflow_subcommands = workflow.add_subparsers(dest="workflow_command", required=True)
    workflow_catalog_parser = workflow_subcommands.add_parser(
        "catalog",
        help="Print the Fork Ops workflow catalog.",
    )
    workflow_catalog_parser.set_defaults(func=cmd_workflow_catalog)
    workflow_inventory_parser = workflow_subcommands.add_parser(
        "inventory",
        help="Build a read-only workflow migration inventory.",
    )
    workflow_inventory_parser.add_argument(
        "--source-root",
        action="append",
        dest="source_roots",
        help="Source file or directory to scan. May be provided more than once.",
    )
    _add_scan_profile_arg(workflow_inventory_parser)
    workflow_inventory_parser.set_defaults(func=cmd_workflow_inventory)

    plugin = subcommands.add_parser("plugin", help="Inspect Fork Ops plugin package state.")
    plugin_subcommands = plugin.add_subparsers(dest="plugin_command", required=True)
    plugin_health = plugin_subcommands.add_parser(
        "health",
        help="Report Fork Ops plugin health diagnostics.",
    )
    plugin_health.add_argument(
        "--plugin-root",
        help="Fork Ops plugin root to inspect. Defaults to the installed package root.",
    )
    plugin_health.add_argument(
        "--repo-root",
        help="Repository root containing plugin marketplace metadata.",
    )
    ui_visibility = plugin_health.add_mutually_exclusive_group()
    ui_visibility.add_argument(
        "--ui-visible",
        action="store_true",
        help="Report UI visibility as ready from an external UI inspection.",
    )
    ui_visibility.add_argument(
        "--ui-hidden",
        action="store_true",
        help="Report UI visibility as failed from an external UI inspection.",
    )
    plugin_health.set_defaults(func=cmd_plugin_health)

    schema = subcommands.add_parser("schema", help="Print schema information.")
    schema_subcommands = schema.add_subparsers(dest="schema_command", required=True)
    schema_print = schema_subcommands.add_parser("print", help="Print Fork Ops JSON Schema.")
    schema_print.set_defaults(func=cmd_schema_print)
    schema_check = schema_subcommands.add_parser(
        "check",
        help="Check checked-in schema artifacts against the runtime schema.",
    )
    schema_check.add_argument(
        "--plugin-root",
        default=str(Path(__file__).resolve().parents[2]),
        help="Fork Ops plugin root containing schema/ and src/fork_ops/.",
    )
    schema_check.add_argument("--json", action="store_true", help="Print full JSON report.")
    schema_check.set_defaults(func=cmd_schema_check)

    return parser


def _add_repo_arg(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--repo", default=".", help="Repository root to inspect.")


def _add_scan_profile_arg(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--scan-profile",
        choices=SCAN_PROFILES,
        default="custom",
        help="Source-root expansion profile to use for migration accounting.",
    )


def cmd_config_show(args: argparse.Namespace) -> int:
    output_format = args.format or ("json" if args.normalized else "toml")
    if args.normalized and output_format == "toml":
        raise ForkOpsError("--normalized requires JSON output; use --format json or omit --format.")
    if output_format == "json":
        result = read_config_result(args.repo, normalized=True)
        print(json.dumps(result, indent=2, sort_keys=True))
        return _domain_exit(result)
    result = read_config_result(args.repo, normalized=False)
    raw = result.get("raw")
    if isinstance(raw, str):
        print(raw, end="")
    if result.get("diagnostics"):
        _print_diagnostics(result, file=sys.stderr)
    return _domain_exit(result)


def cmd_config_validate(args: argparse.Namespace) -> int:
    report = build_status_report(
        args.repo,
        include_config=args.json,
        required_level=args.required_level or "",
    )
    if args.json:
        print(json.dumps(report, indent=2, sort_keys=True))
    else:
        _print_diagnostics(report)
        _print_operation_status(report)
        _print_capability_status(report["capability"], prefix="capability.")
    if args.required_level and report["required_level"]["authority_ready"] is not True:
        if not args.json:
            authority_ready = report["required_level"]["authority_ready"]
            missing = report["required_level"]["missing"]
            status = "not_ready" if authority_ready is False else "unassessed"
            print(f"required_level={args.required_level}: {status}")
            if isinstance(missing, list):
                print(f"missing_for_required_level={', '.join(missing) or 'none'}")
    return _domain_exit(report)


def cmd_config_init(args: argparse.Namespace) -> int:
    if not args.write:
        text = create_initial_config_text(
            args.repo or ".",
            repository_owner=args.repository_owner,
            repository_name=args.repository_name,
            upstream_owner=args.upstream_owner,
            upstream_name=args.upstream_name,
            default_branch=args.default_branch,
        )
        print(text, end="")
        return 0
    result = initialize_config(
        args.repo or "",
        repository_owner=args.repository_owner,
        repository_name=args.repository_name,
        upstream_owner=args.upstream_owner,
        upstream_name=args.upstream_name,
        default_branch=args.default_branch,
    )
    _require_current_artifact(
        result,
        ArtifactKind.CONFIG_INITIALIZATION_RESULT,
        "Config initialization result",
    )
    if result["outcome"] != "completed" or result["mutation_state"] != "applied":
        print(_config_initialization_failure_message(result), file=sys.stderr)
        return _domain_exit(result)
    print(result["target_path"])
    return 0


def _config_initialization_failure_message(result: dict[str, Any]) -> str:
    blockers = result.get("blockers", [])
    detail = (
        str(blockers[0].get("message", "Config initialization failed."))
        if isinstance(blockers, list) and blockers and isinstance(blockers[0], dict)
        else "Config initialization failed."
    )
    mutation_state = result.get("mutation_state")
    if mutation_state == "rolled_back":
        return f"Config initialization failed and the task-created config was rolled back: {detail}"
    if mutation_state == "applied_unverified":
        mutation = result.get("mutation")
        applied_edits = result.get("applied_edits")
        parent_only = (
            isinstance(mutation, dict)
            and mutation.get("target_state") == "not-created"
            and isinstance(applied_edits, list)
            and any(
                isinstance(edit, dict)
                and edit.get("target_created") is False
                and isinstance(edit.get("created_parent"), str)
                for edit in applied_edits
            )
        )
        if parent_only:
            return (
                "Config initialization created the .agents directory without creating "
                f"the config; rerun the command to bind that directory safely: {detail}"
            )
        return (
            f"Config initialization changed {result.get('target_path')}, but the target remains "
            f"unverified and could not be safely rolled back: {detail}"
        )
    return detail


def cmd_capability_report(args: argparse.Namespace) -> int:
    report = build_status_report(args.repo, include_config=True)
    capability = report["capability"]
    if args.json:
        print(json.dumps(capability, indent=2, sort_keys=True))
    else:
        _print_capability_status(capability)
        if capability.get("diagnostics"):
            _print_diagnostics(capability)
    return _domain_exit(capability)


def _print_operation_status(payload: dict[str, Any], *, prefix: str = "") -> None:
    for field in ("outcome", "plan_executability", "mutation_state"):
        print(f"{prefix}{field}={payload[field]}")


def _print_capability_status(
    capability: dict[str, Any],
    *,
    prefix: str = "",
) -> None:
    authority = capability["authority_readiness"]
    _print_operation_status(capability, prefix=prefix)
    print(f"{prefix}baseline_assurance={capability['baseline_assurance']}")
    _print_canonical_states(
        capability,
        path_prefix=tuple(part for part in prefix.rstrip(".").split(".") if part),
    )
    print(
        f"{prefix}highest_authority_ready="
        f"{authority['highest_authority_ready'] or 'none'}"
    )
    for level, details in authority["levels"].items():
        status = (
            "ready"
            if details["ready"] is True
            else "not_ready"
            if details["ready"] is False
            else "unassessed"
        )
        print(f"{prefix}authority.{level}={status}")
        if details["missing"]:
            print(f"{prefix}authority.{level}.missing={','.join(details['missing'])}")
    for workflow in capability["workflow_availability"]:
        workflow_id = workflow["workflow_id"]
        print(
            f"{prefix}workflow.{workflow_id}.implementation_extent="
            f"{workflow['implementation_extent']}"
        )
        available_operations = workflow["available_operations"]
        print(
            f"{prefix}workflow.{workflow_id}.available_operations="
            f"{','.join(available_operations) or 'none'}"
        )


def _print_canonical_states(
    payload: dict[str, Any],
    *,
    path_prefix: tuple[str, ...] = (),
) -> None:
    for path, state in _canonical_state_payloads(payload):
        prefix = f"state.{'.'.join((*path_prefix, *path))}"
        print(f"{prefix}.value={state['value']}")
        evidence_ids = state.get("evidence_ids")
        rendered_evidence = (
            ",".join(str(item) for item in evidence_ids)
            if isinstance(evidence_ids, list) and evidence_ids
            else "none"
        )
        print(f"{prefix}.evidence_ids={rendered_evidence}")
        for field in ("subject", "derivation_rule"):
            if field in state:
                print(f"{prefix}.{field}={state[field]}")


def cmd_migration_assess(args: argparse.Namespace) -> int:
    print(
        json.dumps(
            assess_migration(
                args.repo,
                include_proposed_config_patch=args.with_proposed_config,
            ),
            indent=2,
            sort_keys=True,
        )
    )
    return 0


def cmd_migration_preflight(args: argparse.Namespace) -> int:
    print(
        json.dumps(
            build_equipment_migration_preflight(
                args.repo,
                args.source_roots,
                scan_profile=args.scan_profile,
            ),
            indent=2,
            sort_keys=True,
        )
    )
    return 0


def cmd_migration_plan(args: argparse.Namespace) -> int:
    print(
        json.dumps(
            generate_migration_plan(args.repo, scan_profile=args.scan_profile),
            indent=2,
            sort_keys=True,
        )
    )
    return 0


def cmd_migration_dry_run(args: argparse.Namespace) -> int:
    if args.plan:
        if args.scan_profile != "custom":
            raise ForkOpsError("--scan-profile cannot be used with --plan.")
        result = dry_run_migration_plan(_read_json_plan(args.plan))
    else:
        result = dry_run_migration(args.repo, scan_profile=args.scan_profile)
    print(json.dumps(result, indent=2, sort_keys=True))
    return _domain_exit(result)


def cmd_migration_execute(args: argparse.Namespace) -> int:
    if args.plan:
        result = execute_migration(args.repo, plan=_read_json_plan(args.plan))
    else:
        result = execute_migration(args.repo)
    print(json.dumps(result, indent=2, sort_keys=True))
    return _domain_exit(result)


def cmd_migration_explain_blocker(args: argparse.Namespace) -> int:
    result = explain_migration_blocker(
        _read_json_workflow_output(args.input),
        args.blocker_code,
    )
    print(json.dumps(result, indent=2, sort_keys=True))
    return _domain_exit(result)


def cmd_migration_propose_config(args: argparse.Namespace) -> int:
    patch = propose_migration_config_patch(args.repo)
    if args.format == "toml":
        print(patch["toml"], end="")
        if patch["diagnostics"]:
            print(json.dumps(patch["diagnostics"], indent=2, sort_keys=True), file=sys.stderr)
    else:
        print(json.dumps(patch, indent=2, sort_keys=True))
    return _domain_exit(patch)


def cmd_workflow_catalog(args: argparse.Namespace) -> int:
    print(json.dumps(workflow_catalog(), indent=2, sort_keys=True))
    return 0


def cmd_workflow_inventory(args: argparse.Namespace) -> int:
    print(
        json.dumps(
            build_workflow_migration_inventory(
                args.source_roots,
                scan_profile=args.scan_profile,
            ),
            indent=2,
            sort_keys=True,
        )
    )
    return 0


def cmd_plugin_health(args: argparse.Namespace) -> int:
    ui_visible: bool | None
    if args.ui_visible:
        ui_visible = True
    elif args.ui_hidden:
        ui_visible = False
    else:
        ui_visible = None
    report = build_plugin_health_report(
        args.plugin_root,
        repo_root=args.repo_root,
        ui_visible=ui_visible,
    )
    print(json.dumps(report, indent=2, sort_keys=True))
    return _domain_exit(report)


def cmd_schema_print(args: argparse.Namespace) -> int:
    print(schema_json(), end="")
    return 0


def cmd_schema_check(args: argparse.Namespace) -> int:
    report = schema_artifact_report(args.plugin_root)
    if args.json:
        print(json.dumps(report, indent=2, sort_keys=True))
    else:
        for artifact in report["artifacts"]:
            if artifact.get("error"):
                status = "error"
            elif artifact["matches_runtime_schema"]:
                status = "ok"
            else:
                status = "drift"
            print(f"{status}\t{artifact['path']}")
    return _domain_exit(report)


def _print_diagnostics(report: dict[str, Any], *, file: Any = None) -> None:
    destination = sys.stdout if file is None else file
    diagnostics = report.get("diagnostics", [])
    if not diagnostics:
        print("diagnostics=none", file=destination)
        return
    for item in diagnostics:
        path = f" {item['path']}" if item.get("path") else ""
        print(
            f"{item['severity']} {item['code']}{path}: {item['message']}",
            file=destination,
        )


def _domain_exit(payload: dict[str, Any]) -> int:
    return 0 if payload.get("outcome") == "completed" else 1


def _has_errors(report: dict[str, Any]) -> bool:
    return _diagnostics_have_errors(report.get("diagnostics", []))


def _diagnostics_have_errors(diagnostics: list[dict[str, Any]]) -> bool:
    return any(item.get("severity") == "error" for item in diagnostics)


def _read_json_plan(path: str) -> dict[str, Any]:
    return _read_json_object(path, "Migration plan")


def _read_json_workflow_output(path: str) -> dict[str, Any]:
    return _read_json_object(path, "Workflow output")


def _read_json_object(path: str, label: str) -> dict[str, Any]:
    try:
        if path == "-":
            raw_bytes = sys.stdin.buffer.read(MAX_FILE_BYTES + 1)
            if len(raw_bytes) > MAX_FILE_BYTES:
                raise ForkOpsError(f"{label} exceeds the file byte limit.")
            raw = raw_bytes.decode("utf-8")
        else:
            raw = _read_absolute_regular_file(path).decode("utf-8")
        parsed = json.loads(raw)
    except UnicodeDecodeError as exc:
        raise ForkOpsError(f"{label} is not valid UTF-8 text.") from exc
    except OSError as exc:
        raise ForkOpsError(f"{label} read failed: {path}: {exc}") from exc
    except json.JSONDecodeError as exc:
        raise ForkOpsError(f"{label} JSON parse failed for {path}: {exc}") from exc
    if not isinstance(parsed, dict):
        raise ForkOpsError(f"{label} JSON must parse to an object.")
    _validate_bounded_object(parsed, label=label)
    return parsed


if __name__ == "__main__":
    raise SystemExit(main())
