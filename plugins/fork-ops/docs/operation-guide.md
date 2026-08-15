# Fork Ops Operation Guide

Start configured-fork operations by locating fork-local authority.

```bash
uv run --package fork-ops fork-ops plugin health
uv run --package fork-ops fork-ops workflow catalog
uv run --package fork-ops fork-ops capability report --repo /path/to/configured-fork
```

For an unconfigured fork, start with migration assessment instead.

```bash
uv run --package fork-ops fork-ops migration assess --repo /path/to/fork
uv run --package fork-ops fork-ops migration preflight --repo /path/to/fork --source-root /path/to/global-skills
uv run --package fork-ops fork-ops migration preflight --repo /path/to/fork --scan-profile full-breadth
uv run --package fork-ops fork-ops migration plan --repo /path/to/fork
uv run --package fork-ops fork-ops migration dry-run --repo /path/to/fork
uv run --package fork-ops fork-ops migration execute --repo /path/to/fork
uv run --package fork-ops fork-ops migration propose-config --repo /path/to/fork --format toml
```

## Config Access

Use the CLI or MCP tools instead of ad hoc TOML parsing when an operation depends on fork ops config.

```bash
uv run --package fork-ops fork-ops config show --repo /path/to/configured-fork --format json
uv run --package fork-ops fork-ops config validate --repo /path/to/configured-fork --required-level track-aware
```

Create a starter config when fork-local authority already identifies the fork
and upstream repository:

```bash
uv run --package fork-ops fork-ops config init --repo /path/to/fork --repository-owner OWNER --repository-name REPO --upstream-owner UPSTREAM_OWNER --upstream-name UPSTREAM_REPO --write
```

`--write` uses the same guarded config-creation mechanics as migration
execution. It validates track-aware content, refuses existing or unsafe targets,
writes without overwriting a concurrent target, and verifies the resulting
file identity, exact bytes, and capability. If `.agents` does not exist, the
first invocation creates only that directory and reports `applied_unverified`;
run the command again to bind the existing directory and create the config.
If post-create verification fails,
the command preserves any extant target because portable filesystems do not
provide an atomic identity-conditioned delete. It reports `applied_unverified`
for operator review and never infers rollback from pathname absence.
The mutating path requires the explicit `--repo` selection and does not derive
authored remote URLs from mutable Git metadata. Generate-only config output may
show credential-free projected remotes, but `--write` uses the supplied owner
and repository arguments as its authority input.

MCP tools expose the same surface for agents:

- `fork_ops_plugin_health`
- `fork_ops_config_read`
- `fork_ops_config_validate`
- `fork_ops_capability_report`
- `fork_ops_workflow_catalog`
- `fork_ops_workflow_migration_inventory`
- `fork_ops_migration_assessment`
- `fork_ops_equipment_migration_preflight`
- `fork_ops_migration_plan`
- `fork_ops_migration_dry_run`
- `fork_ops_migration_execute`
- `fork_ops_migration_blocker_resolution`
- `fork_ops_migration_config_patch`
- `fork_ops_schema`

## Machine Contract

Fork Ops machine artifacts identify themselves at the root with
`artifact_kind` and `schema_version`. Public operation results use schema 1.0
and also carry `operation`, `outcome`, `plan_executability`, `mutation_state`,
`diagnostics`, and `evidence`. The authored Fork Ops config remains schema 0.1;
the JSON Schema document that describes it is a separate, versioned machine
artifact.

Persisted and replayed artifacts must match their exact supported kind and
version before Fork Ops interprets domain fields or performs a mutation. A
missing or unsupported identity is refused and directs the caller to regenerate
the artifact. There are no legacy field aliases at the corrected boundary.
Internal typed values inherit the identity of their enclosing artifact, and
human-readable text or Markdown is a projection rather than a separate machine
contract.

CLI JSON and MCP tools return the same canonical domain object for the same
operation and inputs. Protocol envelopes and human CLI rendering may differ,
but they do not redefine fields. CLI exit status is 0 for a completed domain
request, including a completed report whose plan is blocked; 1 for a trustworthy
blocked, refused, or failed domain result; and 2 for invalid CLI input or when no
trustworthy domain result can be formed.

State dimensions remain independent. Activation readiness is `unassessed`,
`blocked`, `ready`, or `not_applicable`; replacement coverage is `unassessed`,
`blocked`, `covered`, or `not_applicable`; operational continuity is
`unassessed`, `at_risk`, `continuous`, or `not_applicable`. Each state records a
subject, evidence identifiers, and a named derivation rule when available.
Workflow implementation extent is `implemented`, `partial`, or `planned`, and
each operation mode is `diagnostic`, `read_only`, or `guarded_mutation`.

## Plugin Health

Use plugin health when first bringing Fork Ops online or when one control
surface works while another is missing. The report checks plugin registration,
skill discovery, CLI execution, MCP config, MCP startup, MCP tool listing, and
UI visibility when inspectable.

```bash
uv run --package fork-ops fork-ops plugin health
```

Registration, skill, and MCP config checks are observational. MCP config must
exactly match the reviewed plugin registration before the MCP runtime probe
starts. The independent CLI probe still runs when MCP config is absent, malformed,
or changed. Both runtime probes use the current Python interpreter in isolated
mode to run the installed `fork_ops.cli` and `fork_ops.mcp_server` modules; they
never run a wrapper script or command metadata from the inspected plugin root.

Each readiness path reports one status: `ready`, `failed`, `unavailable`, or
`uninspectable`. MCP failures include next paths, and the report provides CLI
fallback guidance when CLI execution is ready.

## Workflow Migration Inventory

Use workflow inventory for product-surface workflow migration, not for replacing
a maintained fork's authority. It scans operator-provided roots or the
full-breadth profile and reports source kind, source scope, material scope,
candidate operator intent, likely workflow catalog target, coverage status,
accounting records, follow-up candidates, and evidence references.

```bash
uv run --package fork-ops fork-ops workflow inventory --source-root /path/to/global-skills --source-root /path/to/fork
uv run --package fork-ops fork-ops workflow inventory --scan-profile full-breadth
```

Backlog candidates in this report are evidence for future catalog work. They do
not mean the workflow is available.

The `full-breadth` profile scans known user-global roots, the maintained-fork
repository set, and adjacent roots. It records the visited roots in
`source_root_records`, preserves each root's scope, and accounts for each
discovered workflow entry exactly once. Planned workflows, reusable Repo Ops
candidates, and unassessed roots receive follow-up candidates. Repository roots
are included only when `FORK_OPS_FULL_BREADTH_REPO_BASE` is set. Use
`FORK_OPS_FULL_BREADTH_MAINTAINED_REPOS` and
`FORK_OPS_FULL_BREADTH_ADJACENT_REPOS` to run the same profile against another
layout.

## Equipment Migration Preflight

Use equipment preflight before treating existing skills, configs, docs, hooks,
or other equipment as replaced. The preflight is read-only. It reports assessed
discovery scopes, proposed onboarding intent, equipment groups, proposed
dispositions, unassessed areas, compatibility entries when detected, activation
impact, and a proposed TOML equipment review record.

```bash
uv run --package fork-ops fork-ops migration preflight --repo /path/to/fork --source-root /path/to/global-skills
uv run --package fork-ops fork-ops migration preflight --repo /path/to/fork --scan-profile full-breadth
```

When no extra source root is supplied, preflight scans repo-local material and
names user-global equipment as unassessed. Unassessed areas limit activation
readiness and replacement coverage for overlapping behavior. Reviewed
`retain_authoritative_owner` entries in the equipment review record can support
guarded config creation while source-material replacement and removal remain
unavailable.

Each discovery scope binds its equipment count and content snapshot. A
persisted reviewed record supports readiness or continuity only when every
scope is scanned, the complete repo-local snapshot can be reproduced within
the scan bounds, and every reviewed decision still matches its attached
evidence and source bytes. External scopes cannot be revalidated from the
selected repository, so a record that marks them reviewed is invalid rather
than a basis for readiness or continuity. Repo-only discovery keeps the
user-global unassessed area and its accounting record. Plan replay rebuilds the
repo-local snapshot, and guarded execution checks it again before writing.

Superseded decisions remain linked audit history. Current capability and replay
state uses the single non-superseded decision for each equipment identity and
source.

Use `--scan-profile full-breadth` when full-breadth accounting is required. The
full-breadth preflight adds accounting records and follow-up candidates from the
known user-global, maintained-fork, and adjacent-root surfaces to the repo-local
equipment review record. Replacement coverage remains false until equivalent
Fork Ops-owned behavior exists, validates, and is reported as covered behavior.

## Schema Artifacts

The documented schema copy and packaged runtime schema copy should stay aligned
with the runtime schema printer.

```bash
uv run --package fork-ops fork-ops schema check --plugin-root plugins/fork-ops
```

## Capability Routing

Use `identified` for basic fork recognition and authority discovery.

Use `scoutable` for upstream and fork research where source order matters.

Use `track-aware` for release-channel and upstream track reasoning, freshness reports, and baseline comparison.

Use `sync-ready` only for sync planning and validation when sync policy and divergence policy are present.

Use `review-ready` only when PR, review, publication, and local gate policy are present.

Use `provenance-ready` only when source, artifact, package, runtime, or install-state verification surfaces are configured.

Capability reports include a summary of
`docs/agents/fork-ops-equipment-review.toml` when that record exists. The
summary identifies whether the record is valid, how many equipment decisions
are pending or reviewed, which reviewed paths remain retained authority, and
whether unassessed equipment areas still limit activation readiness. When the
record contains accounting records, the capability summary reports accounting
record counts, verified status counts, follow-up candidate counts, and whether
the accounting claims were verified. A proposed review retains its record and
follow-up counts but reports zero verified status counts. The summary does not
treat a proposed choice as reviewed authority. Reviewed repo-local decisions
must still match their attached source identity and current content digest, and
the discovery scope snapshot must still cover the current equipment set. The
summary does not by itself authorize equipment edits, disabling, redirects,
replacement coverage claims, or source-material removal.

## Mutation Policy

The foundation implementation supports guarded migration execution for
plans whose dry-run blockers are resolved for config creation. It creates
`.agents/fork-ops.toml`, preserves retained source materials, reports migration
map dispositions, equipment preflight findings, review artifact decisions,
activation-readiness limits, replayable wet-run evidence, operator-readable
narratives, migration blockers, and resulting capability verification. A
`semantic_coverage.incomplete` path only stops blocking guarded config creation
when the migration review artifact records a reviewed `retain` decision or the
equipment review record records a reviewed `retain_authoritative_owner`
disposition for that path. Retained authority remains checked-in source
material and still blocks source-material replacement or removal. The
implementation does not run broad sync mutations, PR publication closeout,
arbitrary migration edits, equipment edits, equipment disabling, or
source-material removal. Agents should report missing capabilities and provide
the smallest safe next step.

When mutation surfaces exist, they should share core mutation gate logic:

- Validate config before acting.
- Verify descriptive fork facts against live state when possible.
- Respect prescriptive fork policies.
- Produce structured evidence.
- Fail closed when mutation gates fail.

Semantic tools should call mutation gates before side effects because they know the typed operation intent. Hooks should enforce harness boundaries for lifecycle events and manual mutation paths.
