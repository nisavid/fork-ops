"""Command-line adapter for Fork Ops."""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Callable
from pathlib import Path
from typing import Any, cast

from .core import (
    CONFIG_RELATIVE_PATH,
    ForkOpsError,
    assess_migration,
    build_status_report,
    create_initial_config_text,
    dry_run_migration,
    dry_run_migration_plan,
    execute_migration,
    execute_migration_plan,
    generate_migration_plan,
    load_raw_config,
    propose_migration_config_patch,
    schema_json,
)
from .schema import CAPABILITY_LEVELS


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
    _add_repo_arg(init)
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
    plan = migration_subcommands.add_parser(
        "plan",
        help="Generate a non-mutating migration plan.",
    )
    _add_repo_arg(plan)
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
    dry_run.set_defaults(func=cmd_migration_dry_run)
    execute = migration_subcommands.add_parser(
        "execute",
        help="Apply a validated migration plan through guarded operations.",
    )
    execute_source = execute.add_mutually_exclusive_group()
    execute_source.add_argument("--repo", default=".", help="Repository root to inspect.")
    execute_source.add_argument(
        "--plan",
        help="Read an existing migration plan JSON file instead of generating one from --repo.",
    )
    execute.set_defaults(func=cmd_migration_execute)
    propose = migration_subcommands.add_parser(
        "propose-config",
        help="Generate a non-mutating Fork Ops config proposal.",
    )
    _add_repo_arg(propose)
    propose.add_argument("--format", choices=["json", "toml"], default="json")
    propose.set_defaults(func=cmd_migration_propose_config)

    schema = subcommands.add_parser("schema", help="Print schema information.")
    schema_subcommands = schema.add_subparsers(dest="schema_command", required=True)
    schema_print = schema_subcommands.add_parser("print", help="Print Fork Ops JSON Schema.")
    schema_print.set_defaults(func=cmd_schema_print)

    return parser


def _add_repo_arg(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--repo", default=".", help="Repository root to inspect.")


def cmd_config_show(args: argparse.Namespace) -> int:
    output_format = args.format or ("json" if args.normalized else "toml")
    if args.normalized and output_format == "toml":
        raise ForkOpsError("--normalized requires JSON output; use --format json or omit --format.")
    if output_format == "json":
        report = build_status_report(args.repo, include_config=True)
        if "config" not in report:
            print(json.dumps(report, indent=2, sort_keys=True), file=sys.stderr)
            return 1
        print(json.dumps(report["config"], indent=2, sort_keys=True))
        return 0
    print(load_raw_config(args.repo), end="")
    return 0


def cmd_config_validate(args: argparse.Namespace) -> int:
    report = build_status_report(args.repo, include_config=args.json)
    required_available = True
    if args.required_level:
        level = report["capability"]["levels"][args.required_level]
        required_available = bool(level["available"])
        report["required_level"] = {
            "level": args.required_level,
            "available": required_available,
            "missing": level["missing"],
        }
    if args.json:
        print(json.dumps(report, indent=2, sort_keys=True))
    else:
        _print_diagnostics(report)
        highest = report["capability"]["highest_available"] or "none"
        print(f"highest_available={highest}")
    if args.required_level:
        if not required_available:
            if not args.json:
                missing = report["required_level"]["missing"]
                print(f"required_level={args.required_level}: unavailable")
                print(f"missing_for_required_level={', '.join(missing) or 'none'}")
    if _has_errors(report):
        return 1
    if args.required_level:
        if not required_available:
            return 1
    return 0


def cmd_config_init(args: argparse.Namespace) -> int:
    text = create_initial_config_text(
        args.repo,
        repository_owner=args.repository_owner,
        repository_name=args.repository_name,
        upstream_owner=args.upstream_owner,
        upstream_name=args.upstream_name,
        default_branch=args.default_branch,
    )
    if not args.write:
        print(text, end="")
        return 0
    repo = Path(args.repo).expanduser().resolve()
    path = repo / CONFIG_RELATIVE_PATH
    if path.exists():
        raise ForkOpsError(f"Refusing to overwrite existing config: {path}")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text)
    print(str(path))
    return 0


def cmd_capability_report(args: argparse.Namespace) -> int:
    report = build_status_report(args.repo, include_config=args.json)
    if args.json:
        print(json.dumps(report, indent=2, sort_keys=True))
    else:
        capability = report["capability"]
        print(f"highest_available={capability['highest_available'] or 'none'}")
        for level, details in capability["levels"].items():
            status = "available" if details["available"] else "unavailable"
            print(f"{level}: {status}")
            if details["missing"]:
                print(f"  missing: {', '.join(details['missing'])}")
        if report.get("diagnostics"):
            _print_diagnostics(report)
    return 1 if _has_errors(report) else 0


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


def cmd_migration_plan(args: argparse.Namespace) -> int:
    print(json.dumps(generate_migration_plan(args.repo), indent=2, sort_keys=True))
    return 0


def cmd_migration_dry_run(args: argparse.Namespace) -> int:
    if args.plan:
        print(
            json.dumps(
                dry_run_migration_plan(_read_json_plan(args.plan)),
                indent=2,
                sort_keys=True,
            )
        )
    else:
        print(json.dumps(dry_run_migration(args.repo), indent=2, sort_keys=True))
    return 0


def cmd_migration_execute(args: argparse.Namespace) -> int:
    if args.plan:
        result = execute_migration_plan(_read_json_plan(args.plan))
    else:
        result = execute_migration(args.repo)
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result["status"] == "applied" else 1


def cmd_migration_propose_config(args: argparse.Namespace) -> int:
    patch = propose_migration_config_patch(args.repo)
    if args.format == "toml":
        print(patch["toml"], end="")
        if patch["diagnostics"]:
            print(json.dumps(patch["diagnostics"], indent=2, sort_keys=True), file=sys.stderr)
    else:
        print(json.dumps(patch, indent=2, sort_keys=True))
    return 1 if _diagnostics_have_errors(patch["diagnostics"]) else 0


def cmd_schema_print(args: argparse.Namespace) -> int:
    print(schema_json(), end="")
    return 0


def _print_diagnostics(report: dict[str, Any]) -> None:
    diagnostics = report.get("diagnostics", [])
    if not diagnostics:
        print("diagnostics=none")
        return
    for item in diagnostics:
        path = f" {item['path']}" if item.get("path") else ""
        print(f"{item['severity']} {item['code']}{path}: {item['message']}")


def _has_errors(report: dict[str, Any]) -> bool:
    return _diagnostics_have_errors(report.get("diagnostics", []))


def _diagnostics_have_errors(diagnostics: list[dict[str, Any]]) -> bool:
    return any(item.get("severity") == "error" for item in diagnostics)


def _read_json_plan(path: str) -> dict[str, Any]:
    try:
        raw = sys.stdin.read() if path == "-" else Path(path).expanduser().read_text()
        parsed = json.loads(raw)
    except OSError as exc:
        raise ForkOpsError(f"Migration plan read failed: {path}: {exc}") from exc
    except json.JSONDecodeError as exc:
        raise ForkOpsError(f"Migration plan JSON parse failed for {path}: {exc}") from exc
    if not isinstance(parsed, dict):
        raise ForkOpsError("Migration plan JSON must parse to an object.")
    return parsed


if __name__ == "__main__":
    raise SystemExit(main())
