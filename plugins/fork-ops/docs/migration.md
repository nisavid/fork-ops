# Fork Ops Migration

Migration starts with read-only migration assessment.

```bash
uv run --package fork-ops fork-ops migration assess --repo /path/to/fork
```

Assessment scans likely fork-related agent materials and reports candidate docs, skills, scripts, configs, and instructions. It starts with agent-facing locations such as `AGENTS.md`, `CLAUDE.md`, `.agents/`, `.codex/`, `docs/agents/`, `docs/adr/`, and `docs/maintainers/`. It does not edit files.

For each candidate, assessment should preserve enough structure to support a later migration plan. In particular, upstream-ref materials should expose:

- ref roles that likely become `upstream_tracks`
- release-channel hints that likely become `release_channels`
- default baseline hints that likely become `sync_policy.default_sync_baseline`
- detected `origin/upstream-*` default baseline refs that become matching
  `upstream_tracks` entries
- disabled upstream push policy that likely becomes `upstreams.push = false`
- ancestry checks and forbidden history rewrites that likely become sync Mutation Gates

Equipment migration preflight is also read-only. It groups discovered equipment
before detailed migration decisions, recommends `migrate_toward_fork_ops` as
the default onboarding intent, names assessed discovery scopes, records
unassessed areas, proposes equipment dispositions, and emits a proposed TOML
equipment review record.

```bash
uv run --package fork-ops fork-ops migration preflight --repo /path/to/fork
uv run --package fork-ops fork-ops migration preflight --repo /path/to/fork --source-root /path/to/global-skills
```

The proposed equipment review record targets
`docs/agents/fork-ops-equipment-review.toml` and uses
`artifact_kind = "equipment_review"`. It can carry reviewed equipment
dispositions such as `retain_authoritative_owner`, but activation, disable, and
redirect effects still require projection into config or another explicit
control surface before behavior changes.

The foundation also exposes a non-mutating proposed config patch. It converts
migration assessment candidates into a draft `.agents/fork-ops.toml` payload for
review.

```bash
uv run --package fork-ops fork-ops migration assess --repo /path/to/fork --with-proposed-config
uv run --package fork-ops fork-ops migration propose-config --repo /path/to/fork --format toml
```

The proposed config patch is not a migration plan or migration execution. It
must be scrutinized against source materials before application. If important
source semantics are not represented, improve the deterministic generator or
switch that migration slice to an LLM-guided planner with a rubric and a
structured config patch output contract.

The proposal TOML renderer intentionally supports top-level scalar fields,
top-level tables, and arrays of flat tables. Config proposal output should stay
inside that flat contract; introduce a TOML writer library or expand the
renderer before nested config output is emitted.

A migration plan combines the assessment and proposed config patch into a
reviewable non-mutating plan.

```bash
uv run --package fork-ops fork-ops migration plan --repo /path/to/fork
```

The plan output separates:

- source evidence and extracted facts
- a migration map entry for each candidate source material item
- typed source material dispositions and target surfaces
- equipment migration preflight findings and activation-readiness limits
- a proposed TOML equipment review record for existing equipment dispositions
- a proposed migration review artifact for durable decisions outside config
- review decision choices for retain, exclude, defer, needs-human-decision, and
  unsupported-extractor outcomes
- the proposed config patch
- retained source materials that remain preserved
- retained authority that agents still need to read after config creation
- deferred removals
- blockers such as incomplete semantic coverage or config diagnostics
- required review and validation requirements
- an operator-readable narrative generated from the same structured evidence

The plan does not edit `.agents/fork-ops.toml` and does not remove source
materials. It is an input to migration dry run.

Migration plans are dry-run-default. Their run-mode metadata requires a reviewed
dry run before a replayable wet run, fails closed by default when drift is
detected, and does not let operator overrides bypass mutation gates, authority
checks, or unresolved human decisions.

Migration map dispositions use these initial values:

- `extracted_into_config`: machine-actionable facts are represented in the proposed fork ops config.
- `retained_as_fork_local_authority`: the source remains checked-in fork-local authority.
- `mapped_to_workflow_backlog`: the source belongs in workflow catalog follow-up work.
- `irrelevant_to_fork_ops`: a broad scan signal matched material that does not describe fork ops authority.
- `unsupported_extractor_shape`: the source appears relevant, but deterministic extraction did not produce structured facts.
- `needs_human_decision`: the source contributes an ambiguous choice that needs an operator decision.
- `deferred_with_rationale`: the source has extractable facts, but the current guarded execution slice cannot apply the needed merge.

The migration review artifact is proposed as
`docs/agents/fork-ops-migration-review.md`. It records each migration map entry,
including its disposition rationale, target-surface details, and review decision
state. Review decisions use `retain`, `exclude`, `defer`,
`needs-human-decision`, and `unsupported-extractor` choices. A reviewed
`retain` decision records that the source remains fork-local authority for
guarded config creation. Other choices remain durable review decisions, but they
do not authorize source-material replacement or removal. Review rationale
belongs in the review artifact, not in `.agents/fork-ops.toml`.

The equipment review record is proposed as
`docs/agents/fork-ops-equipment-review.toml`. It records discovery scopes,
unassessed equipment areas, evidence entries, equipment identifiers,
classifications, dispositions, decision status, and activation impact. A
reviewed `retain_authoritative_owner` equipment disposition records that the
source remains authoritative for guarded config creation. Proposed dispositions
guide review only; they do not establish replacement coverage or authorize
equipment edits.

Migration dry run previews a migration plan without mutating the repository.
When no plan file is supplied, the CLI generates the current plan internally.

```bash
uv run --package fork-ops fork-ops migration dry-run --repo /path/to/fork
uv run --package fork-ops fork-ops migration dry-run --plan /path/to/migration-plan.json
```

The dry-run output reports planned file edits, config changes, migration map
entries, the proposed review artifact, the proposed equipment review record,
activation readiness, replayable wet-run metadata, retained source materials,
blocked steps, expected verification commands, retained authority that agents
still need to read, unavailable migration work, and an operator-readable
narrative. If all `semantic_coverage.incomplete` paths have reviewed `retain`
decisions in the migration review artifact or reviewed
`retain_authoritative_owner` dispositions in the equipment review record,
guarded config creation can proceed while source-material replacement and
removal stay unavailable. It does not edit config, source material, equipment,
or branch state.

Migration execution applies a migration plan through guarded operations when
the dry-run preview has no blockers. When no plan file is supplied, the CLI
generates the current plan internally.

```bash
uv run --package fork-ops fork-ops migration execute --repo /path/to/fork
uv run --package fork-ops fork-ops migration execute --plan /path/to/migration-plan.json
```

The current execution slice supports creating `.agents/fork-ops.toml` from the
validated config proposal, preserving retained source materials, reporting the
migration map, proposed review artifact, equipment review record,
activation-readiness limits, replay metadata, and resulting Fork Ops capability
verification. It returns structured evidence for applied edits, skipped
preservation steps, retained authority, deferred removals, blockers,
verification results, and narrative refusal context. It refuses malformed plans,
plans with unresolved dry-run blockers, unsupported edit actions, unsafe target
paths, and config content that fails parse or validation checks.

Migration outputs include a `narrative` object. The narrative is rendered from
the structured output and names source paths, dispositions, blockers, retained
authority, safe continuations, and unavailable work. Treat the structured fields
as authoritative when writing automation; use the narrative to orient operators.

Use blocker explanation for an existing migration output JSON object:

```bash
uv run --package fork-ops fork-ops migration explain-blocker --input /path/to/migration-output.json --blocker-code semantic_coverage.incomplete
```

For `semantic_coverage.incomplete`, blocker-resolution output lists the affected
source material paths, links them back to migration map entries when present,
explains that deterministic extraction did not produce structured facts, and
keeps source-material replacement/removal unavailable until coverage is
reviewed.

## Migration Lifecycle

1. Migration assessment maps existing material to proposed Fork Ops config sections, docs, skills, tools, hooks, and portability hints.
2. Equipment migration preflight groups existing equipment and proposes reviewed-record entries for operator intent and disposition decisions.
3. Migration plan defines the migration map, review artifact proposal, equipment review record proposal, specific edits, blockers, run mode, and verification steps.
4. Migration dry run previews the migration plan without mutating the repo.
5. Migration execution applies a validated plan and verifies the resulting Fork Ops capability level.

The implementation supports migration assessment, non-mutating proposed config
patch generation, non-mutating equipment migration preflight, non-mutating
migration plan generation, non-mutating migration dry run, operator-readable
migration narratives, and blocker explanations. Migration execution supports
guarded config creation and capability verification for plans whose dry-run
blockers are resolved for config creation. Retained authority remains checked-in
source material and remains a blocker for replacement or removal.

## Migration Boundaries

Do not delete the last copy of fork policy until the Fork Ops replacement exists and validates.

Do not migrate generic repository behavior into Fork Ops without a Portability Hint. Portability Hints are non-normative and are subject to future Repo Ops migration design.

## Workflow Migration Inventory

Workflow migration inventory is separate from fork authority migration. It
scouts reusable fork-workflow materials from operator-provided source roots and
maps them to workflow catalog targets or backlog candidates without mutating the
sources.

```bash
uv run --package fork-ops fork-ops workflow inventory --source-root /path/to/source-root
```

Inventory evidence uses references, source kinds, material scope, coverage
status, and line numbers when in-file evidence exists. Path-only evidence uses a
null line value. The report also lists source roots that cannot be resolved. It
does not duplicate source text or make backlog candidates available as
implemented workflows.
