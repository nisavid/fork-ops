# Fork Ops Migration

Migration starts with read-only Migration Assessment.

```bash
uv run --package fork-ops fork-ops migration assess --repo /path/to/fork
```

Assessment scans likely fork-related agent materials and reports candidate docs, skills, scripts, configs, and instructions. It starts with agent-facing locations such as `AGENTS.md`, `CLAUDE.md`, `.agents/`, `.codex/`, `docs/agents/`, `docs/adr/`, and `docs/maintainers/`. It does not edit files.

For each candidate, assessment should preserve enough structure to support a later Migration Plan. In particular, upstream-ref materials should expose:

- ref roles that likely become `upstream_tracks`
- release-channel hints that likely become `release_channels`
- default baseline hints that likely become `sync_policy.default_sync_baseline`
- disabled upstream push policy that likely becomes `upstreams.push = false`
- ancestry checks and forbidden history rewrites that likely become sync Mutation Gates

The foundation also exposes a non-mutating proposed config patch. It converts
Migration Assessment candidates into a draft `.agents/fork-ops.toml` payload for
review.

```bash
uv run --package fork-ops fork-ops migration assess --repo /path/to/fork --with-proposed-config
uv run --package fork-ops fork-ops migration propose-config --repo /path/to/fork --format toml
```

The proposed config patch is not a Migration Plan or Migration Execution. It
must be scrutinized against source materials before application. If important
source semantics are not represented, improve the deterministic generator or
switch that migration slice to an LLM-guided planner with a rubric and a
structured config patch output contract.

## Migration Lifecycle

1. Migration Assessment maps existing material to proposed Fork Ops config sections, docs, skills, tools, hooks, and portability hints.
2. Migration Plan defines the specific edits, removals, replacements, and verification steps.
3. Migration Dry Run previews the Migration Plan without mutating the repo.
4. Migration Execution applies a validated plan and verifies the resulting Fork Ops capability level.

The foundation implementation supports Migration Assessment and non-mutating proposed config patch generation. Plan, dry run, and execution are unavailable until target functionality exists for the material being migrated.

## Migration Boundaries

Do not delete the last copy of fork policy until the Fork Ops replacement exists and validates.

Do not migrate generic repository behavior into Fork Ops without a Portability Hint. Portability Hints are non-normative and are subject to future Repo Ops migration design.
