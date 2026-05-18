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
- disabled upstream push policy that likely becomes `upstreams.push = false`
- ancestry checks and forbidden history rewrites that likely become sync Mutation Gates

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

A migration plan combines the assessment and proposed config patch into a
reviewable non-mutating plan.

```bash
uv run --package fork-ops fork-ops migration plan --repo /path/to/fork
```

The plan output separates:

- source evidence and extracted facts
- the proposed config patch
- retained source materials that remain fork-local authority
- deferred removals
- blockers such as incomplete semantic coverage or config diagnostics
- required review and validation requirements

The plan does not edit `.agents/fork-ops.toml` and does not remove source
materials. It is an input to migration dry run.

Migration dry run previews a migration plan without mutating the repository.
When no plan file is supplied, the CLI generates the current plan internally.

```bash
uv run --package fork-ops fork-ops migration dry-run --repo /path/to/fork
uv run --package fork-ops fork-ops migration dry-run --plan /path/to/migration-plan.json
```

The dry-run output reports planned file edits, config changes, retained source
materials, blocked steps, and expected verification commands. It fails closed
while migration execution is unavailable: blockers remain explicit and no
config, source material, or branch state is changed.

## Migration Lifecycle

1. Migration assessment maps existing material to proposed Fork Ops config sections, docs, skills, tools, hooks, and portability hints.
2. Migration plan defines the specific edits, removals, replacements, blockers, and verification steps.
3. Migration dry run previews the migration plan without mutating the repo.
4. Migration execution applies a validated plan and verifies the resulting Fork Ops capability level.

The implementation supports migration assessment, non-mutating proposed config
patch generation, non-mutating migration plan generation, and non-mutating
migration dry run. Execution is unavailable until target functionality exists
for the material being migrated.

## Migration Boundaries

Do not delete the last copy of fork policy until the Fork Ops replacement exists and validates.

Do not migrate generic repository behavior into Fork Ops without a Portability Hint. Portability Hints are non-normative and are subject to future Repo Ops migration design.
