#!/usr/bin/env python3
"""Generate or verify human projections of Security Exception contract 1.0."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import secrets
import stat
import sys
from pathlib import Path
from typing import Any

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
CONTRACT_PATH = (
    REPOSITORY_ROOT
    / "plugins"
    / "fork-ops"
    / "src"
    / "fork_ops"
    / "security-exception-contract-1.0.json"
)
GUIDE_PATH = REPOSITORY_ROOT / "docs" / "agents" / "security-exceptions.md"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true", help="fail when projections drift")
    arguments = parser.parse_args(argv)
    contract_bytes = CONTRACT_PATH.read_bytes()
    contract = json.loads(contract_bytes)
    if not isinstance(contract, dict):
        raise ValueError("canonical contract must be an object")
    _check_golden_vectors(contract)
    rendered = _render_guide(contract, hashlib.sha256(contract_bytes).hexdigest())
    if arguments.check:
        try:
            current = _read_projection()
        except FileNotFoundError:
            print(f"missing projection: {GUIDE_PATH.relative_to(REPOSITORY_ROOT)}", file=sys.stderr)
            return 1
        if current != rendered:
            print(
                f"projection drift: run {Path(__file__).relative_to(REPOSITORY_ROOT)}",
                file=sys.stderr,
            )
            return 1
        return 0
    _write_projection(rendered)
    return 0


def _projection_directory_fd() -> int:
    root = REPOSITORY_ROOT.resolve(strict=True)
    try:
        relative = GUIDE_PATH.relative_to(REPOSITORY_ROOT)
    except ValueError as error:
        raise ValueError("projection destination must be a regular in-tree file") from error
    if relative.is_absolute() or ".." in relative.parts or relative.name != GUIDE_PATH.name:
        raise ValueError("projection destination must be a regular in-tree file")
    descriptor = os.open(
        root,
        os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
    )
    try:
        for component in relative.parent.parts:
            next_descriptor = os.open(
                component,
                os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
                dir_fd=descriptor,
            )
            os.close(descriptor)
            descriptor = next_descriptor
        return descriptor
    except OSError as error:
        os.close(descriptor)
        raise ValueError(
            "projection destination must be a regular in-tree file"
        ) from error


def _reject_unsafe_projection_target(directory_fd: int) -> None:
    try:
        metadata = os.stat(GUIDE_PATH.name, dir_fd=directory_fd, follow_symlinks=False)
    except FileNotFoundError:
        return
    if not stat.S_ISREG(metadata.st_mode):
        raise ValueError("projection destination must not be a symlink or non-regular file")


def _read_projection() -> str:
    directory_fd = _projection_directory_fd()
    try:
        _reject_unsafe_projection_target(directory_fd)
        descriptor = os.open(
            GUIDE_PATH.name,
            os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW,
            dir_fd=directory_fd,
        )
        with os.fdopen(descriptor, "r", encoding="utf-8") as stream:
            return stream.read()
    finally:
        os.close(directory_fd)


def _write_projection(rendered: str) -> None:
    directory_fd = _projection_directory_fd()
    temporary_name = f".{GUIDE_PATH.name}.tmp-{secrets.token_hex(12)}"
    temporary_exists = False
    try:
        _reject_unsafe_projection_target(directory_fd)
        descriptor = os.open(
            temporary_name,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW,
            0o644,
            dir_fd=directory_fd,
        )
        temporary_exists = True
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="") as stream:
            stream.write(rendered)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(
            temporary_name,
            GUIDE_PATH.name,
            src_dir_fd=directory_fd,
            dst_dir_fd=directory_fd,
        )
        temporary_exists = False
        os.fsync(directory_fd)
    finally:
        if temporary_exists:
            try:
                os.unlink(temporary_name, dir_fd=directory_fd)
            except FileNotFoundError:
                pass
        os.close(directory_fd)


def _check_golden_vectors(contract: dict[str, Any]) -> None:
    canonicalization = contract["canonicalization"]
    domains = canonicalization["digest_domains"]
    for vector in canonicalization["golden_vectors"]:
        canonical = json.dumps(
            vector["projection"],
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        if canonical.decode("utf-8") != vector["canonical_utf8"]:
            raise ValueError("canonicalization golden vector drifted")
        for domain, expected in vector["digests"].items():
            actual = hashlib.sha256(domains[domain].encode("utf-8") + canonical).hexdigest()
            if actual != expected:
                raise ValueError(f"{domain} digest golden vector drifted")


def _render_guide(contract: dict[str, Any], digest: str) -> str:
    matrix = contract["kind_subject_matrix"]
    effects = contract["v1_total_effects"]
    commands = contract["public_command_grammars"]
    lifecycle = contract["lifecycle"]
    response = contract["response_clock"]
    provider = contract["provider_observation"]
    authority_observation = contract["authority_observation"]
    transition_observation = contract["transition_observation"]
    lineage_issuance = contract["lineage_issuance"]
    subject_identity = contract["subject_identity"]
    required_passes = provider["required_passes"]
    validity_minutes = provider["maximum_validity_seconds"] // 60
    skew_seconds = provider["maximum_trusted_time_skew_seconds"]
    validity_window = f"{validity_minutes} minutes"
    skew_window = f"{skew_seconds} seconds"
    authority_window = f"{authority_observation['maximum_age_seconds'] // 60} minutes"
    transition_window = f"{transition_observation['maximum_age_seconds'] // 60} minutes"
    review_days = lifecycle["review_max_days"]
    expiry_days = lifecycle["expiry_max_days"]
    control_days = lifecycle["control_bypass_or_unavailability_max_days"]
    critical_triage = response["triage"]["critical"]["value"]
    high_triage = response["triage"]["high"]["value"]
    critical_disposition = response["disposition"]["critical"]["value"]
    high_disposition = response["disposition"]["high"]["value"]
    medium_disposition = response["disposition"]["medium"]["value"]
    low_disposition = response["disposition"]["low"]["value"]
    critical_triage_window = f"{critical_triage} elapsed hours"
    high_triage_window = f"{high_triage} Monday-Friday UTC weekdays"
    critical_disposition_window = f"{critical_disposition} elapsed hours"
    high_disposition_window = f"{high_disposition} calendar days"
    medium_disposition_window = f"{medium_disposition} calendar days"
    low_disposition_window = f"{low_disposition} calendar days"
    critical_response_line = (
        f"- Critical: triage in {critical_triage_window}; "
        f"disposition in {critical_disposition_window}."
    )
    high_triage_line = (
        f"- High: triage in {high_triage_window} with no holiday calendar;"
    )
    high_disposition_line = f"  disposition in {high_disposition_window}."
    non_dependency_identities = "\n".join(
        f"- `{subject_kind}`: `{prefix}:{{subject_key}}`"
        for subject_kind, prefix in subject_identity["prefixes"].items()
        if subject_kind != "dependency_advisory"
    )
    matrix_rows = "\n".join(
        f"| `{kind}` | {', '.join(f'`{subject}`' for subject in subjects)} |"
        for kind, subjects in matrix.items()
    )
    command_rows = "\n".join(
        f"| `{name.replace('_', '-')}` | `{' '.join(tokens)}` |"
        for name, tokens in commands.items()
        if isinstance(tokens, list)
    )
    false_effects = [name for name, value in effects.items() if value is False]
    true_effects = [name for name, value in effects.items() if value is True]
    return f"""# Security Exceptions

This guide is generated from the package-owned canonical contract. Edit
`plugins/fork-ops/src/fork_ops/security-exception-contract-1.0.json`, then run:

```bash
uv run --package fork-ops python scripts/security_exception_projections.py
uv run --package fork-ops python scripts/security_exception_projections.py --check
```

Contract version: `{contract['contract_version']}`

Contract SHA-256: `{digest}`

## Purpose and boundary

Contract 1.0 records exception inventory, decisions, lineage, and lifecycle.
It is pure governance evidence. It has no gate, merge, repository-control,
assurance, baseline, release, product, or dogfood effect, and it never clears
the underlying failure. Future effects require an unsupported contract 2.0.

The public ledger is `docs/agents/security-exceptions.toml`. It contains flat
`[[exceptions]]` records and starts empty. Public records contain bounded,
structured, confidentiality-safe metadata and credential-free HTTPS references
using the contract's closed per-host public resource paths only.
Private proposals, commands, and evidence remain in a private advisory adapter;
the validator accepts only its versioned sanitized projection and fails the
whole ledger when that projection is unavailable.

An Unscanned Equipment Exception is separate equipment governance. It is not a
Security Exception and cannot affect Security Posture without a separate record
under this contract.

## Closed kind and subject matrix

| Kind | Permitted subjects |
| --- | --- |
{matrix_rows}

## Total effects

Always true: {', '.join(f'`{name}`' for name in true_effects)}.

Always false: {', '.join(f'`{name}`' for name in false_effects)}.

## Authority and lineage

The sole authority is GitHub login `{contract['authority']['risk_authority']['login']}`,
database ID `{contract['authority']['risk_authority']['database_id']}`, node ID
`{contract['authority']['risk_authority']['node_id']}`. Login and immutable IDs
must all match the structural observation. Contract 1.0 refuses an authority
mismatch or an observation older than {authority_window}; explicit migration
requires a future contract. The pure validator
cannot authenticate a caller mapping: it returns only an inventory with
`authority_status = "structural_unverified"`, and its authenticated-inventory
predicate remains false until a live verification adapter exists.

Lineage uses a coordinator-issued random UUIDv4 and an append-only index across
current and terminal states. Every lineage starts in `approved`; later entries
must follow a closed state-machine action and cannot be future-dated. The
`last_approval_or_renewal` anchor remains the most recent `approved` or
`renewed` event. The initial record gets a fresh globally history-unique
exception ID. Each renewal rotates to another fresh ID; every other transition
retains the current ID, and the current record ID equals the lineage head.
Dependency identity includes lineage, normalized package,
locked version, exact scopes, an exact nonempty Python 3.11-3.14 subset, and
Linux. Alias and evidence revisions are separate. The current record must equal
the lineage head and current revisions exactly. Branch,
overlap, split, merge, cross-visibility reuse, unlinked reuse, and anchor reset
are rejected. Evidence, proposal, event, result, and record digests are
recomputed from domain-separated canonical projections. Each lineage head binds
the record's canonical result digest so the head identity changes with any
security-relevant record content. Subject identity is derived rather than
caller-selected. Dependency identity remains package, locked version, exact
scopes, exact Python subset, and Linux. Other identities bind the exact ASCII
subject key under the closed subject kind:

{non_dependency_identities}

Aliases do not participate in identity, so alias revisions remain in the same
lineage. Lineage issuance accepts only the closed canonical identity grammar,
refuses current or historical exception-ID reuse, and requires
`{lineage_issuance['time_window']}`. Collection and persistence are adapter
responsibilities; this implementation validates projections only.

## Public request commands

Commands use the exact ASCII whitespace-separated tokens below, lowercase
literals, and no extra text. They are requests only. Transition projections
bind immutable authority IDs, the exact request, producer and persistence
receipts, a canonical result digest, and monotonic timestamps, but remain
`structural_unverified`. Contract 1.0 has no authenticated command or
persistence adapter, so no transition projection takes authoritative effect.
Transition persistence evidence must be less than {transition_window} old at
evaluation. Public commands govern public records only, and edited comments are
rejected. Every transition binds a structural current whole-ledger inventory.
Approval requires a globally history-unique exception ID; renewal requires a
fresh successor ID; other transitions retain the current ID.

| Action | Exact grammar |
| --- | --- |
{command_rows}

A malformed command with the exact revoke prefix can only request a
`revocation_pending` transition. `withdraw-invalid` binds that pending
transition, predecessor effective-event digest, malformed comment node ID, and
raw comment digest. It requires the current head, clears only the pending
transition, never restores a snapshot, and forces fresh recomputation.

## Provider and response clocks

Provider projections require {required_passes} complete, semantic-identical
structural passes with one terminal manifest for every required source.
Request, semantic, response, receipt, and aggregate digests are recomputed;
producer provenance remains `unverified_projection`. The strict window is
`{provider['time_window']}`.
Validity is at most {validity_window} and ends earlier when the provider or
authentication bound does. Projected provider time is monotonic with at most
{skew_window} of skew. Repository, governance issue, and account identities are
pinned.

A positive zero response-clock inventory is structurally complete only when
every required source is present in one epoch, pagination is terminal,
reconciliation is complete, and entries are empty. It cannot become an
authoritative positive-zero claim until a live authenticated provider adapter
exists. The earliest authenticated source publication or private validation
would start the clock. If source time is missing, retain the first-observed upper
bound, but triage and disposition remain `uncertain` and do not prove an SLA.
The highest credible severity only tightens deadlines.

{critical_response_line}
{high_triage_line}
{high_disposition_line}
- Medium: disposition in {medium_disposition_window}.
- Low: disposition in {low_disposition_window}.

## Record lifecycle

Review is due within {review_days} days; expiry is due within {expiry_days} days.
Control bypass and control unavailability records expire within {control_days} days.
Critical and high records cannot pass their response disposition cap.

`{lifecycle['review_formula']}`

`{lifecycle['expiry_formula']}`

Anchors never reset. Equality at review or expiry is inactive. Revoked and
resolved states are terminal. Lifecycle projections remain
`{lifecycle['trust_status']}` and cannot report `active = true` without an
authenticated authority adapter. Lifecycle validity records state only and
never changes the contract's total effects.
"""


if __name__ == "__main__":
    raise SystemExit(main())
