# Capability Card: Fork Ops Foundation

Status: Draft
Promotion state: specified

## Purpose

Provide reusable agentic operations for Maintained Forks while keeping each fork's operating truth in checked-in fork-local authority.

## Initial Operational Target

The first implementation should fully support the `track-aware` Fork Ops Capability Level. It should design for `sync-ready` without implementing every sync mutation in the first release.

The first implementation should include read-only migration assessment,
non-mutating config proposal generation, and non-mutating migration plan
generation for existing fork-related materials. Migration dry run and migration
execution support should follow after the target config, docs, and component
surfaces exist.

## Users

- Human operator: initiates work, owns stakeholder policy, and decides exceptions.
- Root agent: reads fork-local authority, performs fork ops, verifies evidence, and escalates at policy or control-surface boundaries.
- Specialist agent: handles bounded review, sync, validation, or migration tasks under root-agent accountability.
- External system: Git, GitHub, local package managers, CI, code-scanning, release feeds, and future Repo Ops equipment.

## Target Harnesses

- Codex: required for the initial version.
- Other agent harnesses: deferred.
- Future Repo Ops equipment: deferred dependency and migration destination.

## Risks

- Security: mutation-capable tools may push branches, edit tracked config, resolve review threads, or trigger external services.
- Privacy: review and CI tooling can disclose repository content or metadata to external systems.
- Reliability: stale upstream refs, stale GitHub state, or incomplete local gates can produce false readiness.
- Context budget: fork policy can sprawl if deterministic checks and schema details remain in model-facing instructions.
- Human workflow: unclear upstreaming or sync policy can create unwanted upstream PRs, history rewrites, or misplaced responsibility.

## External Systems

- Local Git repository and remotes.
- GitHub repositories, pull requests, issues, reviews, checks, code scanning, releases, and branch rules.
- Local filesystem paths for checked-in config, docs, scripts, and plugin components.
- Optional package/runtime probes for provenance validation.

## Side Effects

- Read-only: inspect config, docs, Git state, GitHub state, release channels, and local artifacts.
- Local write: edit fork-ops config, generated reports, branch state, and tracked docs.
- Network write: push refs, create or update PRs/issues/comments, trigger workflows, and update GitHub review state.
- External disclosure: call hosted review, code-scanning, CI, or documentation services when configured.
- Irreversible mutation: merge PRs, delete branches, resolve review threads, and publish baseline refs.

## Needed Harness Components

- Skills: procedural judgment for onboarding, syncing, reviewing, contributor PR repair, and config migration.
- MCP/tools: typed config, Git/GitHub state, validation, and mutation operations.
- Hooks: optional lifecycle checks for configured forks and risky mutation gates.
- Agent Profiles: deferred; use only when specialized authority or tool access becomes clear.
- Plugins: Codex plugin packaging for initial distribution.
- Scripts: deterministic TOML parsing, schema validation, state inspection, and report generation.
- Config: `.agents/fork-ops.toml`.
- Docs: glossary, domain map, config schema, operation runbooks, and migration notes.

## Initial Implementation Shape

- Python core library for schema, parsing, normalization, diagnostics, Git/GitHub inspectors, release-channel resolution, migration assessment, config proposals, and migration plans.
- `fork-ops` CLI as a thin adapter over the core library.
- Stdio MCP server as a thin adapter over the core library.
- Codex plugin packaging for skills, MCP config, scripts, docs, and assets.

## Hard Rules

- Fork-local authority is the source of project truth for a maintained fork.
- The Fork Ops plugin supplies reusable operations but does not replace fork-local authority.
- Default upstream contribution intent is fork-local unless fork-local authority or the user says otherwise.
- Upstream release channels are live selectors, not durable baseline refs.
- Durable upstream baseline state belongs in upstream tracks.
- Upstream commit identity must be preserved when a sync claims to include upstream commits.
- Portability hints are non-normative and do not decide future Repo Ops migration.

## Deterministic Checks

- TOML parses and conforms to the fork-ops schema.
- Descriptive fork facts match live Git/GitHub state where control surfaces are available.
- Configured upstream tracks resolve to existing refs.
- Release channels resolve to expected upstream release metadata when the operation requires fresh upstream data.
- Sync baseline checks use merge-base ancestry, not patch equivalence alone.
- Mutation tools produce structured evidence and respect configured gates.

## Mutation Gate Model

Mutation Gate logic belongs in the core Fork Ops library so the same policy rules can be tested and reused across CLI, MCP, hooks, and future harnesses.

Semantic mutation tools must call the core gate before mutating because they know the operation intent, typed inputs, target capability level, and evidence contract.

Codex hooks should enforce the harness boundary for lifecycle events and manual or non-semantic mutation paths, such as raw Git commands. Hooks are defense in depth and an important enforcement adapter; they should not be the only place where domain gate rules exist.

## Output Contract

Fork Ops equipment should produce structured status, evidence, and next-action reports that distinguish verified facts, fork policy, inferred conclusions, blockers, and required human decisions.

Migration assessment output should map existing fork-related material to
proposed fork ops config sections, docs, skills, scripts, tools, hooks, and
portability hints without mutating the repository.

For upstream-ref materials, migration assessment should expose candidate facts
such as ref roles, release-channel sources, default sync baselines, disabled
upstream push policy, ancestry checks, and forbidden history rewrites. These
facts are pressure-case inputs for the migration plan; they are not applied
automatically.

The proposed config patch surface should convert assessment output into a non-mutating `.agents/fork-ops.toml` draft with review-required metadata, source evidence, schema diagnostics, and limitations. It should not infer repository protection policy that was not present in the source material or verified from live state.

Config-management output should distinguish raw TOML, parsed config, normalized config, diagnostics, capability levels, proposed diffs, and applied semantic operations.

## Failure Modes

- Missing config: report unconfigured status and offer onboarding steps.
- Descriptive fact mismatch: report diagnostics before applying dependent operations.
- Policy ambiguity: escalate with concrete options and a return contract.
- Missing control surface: provide the smallest actionable human handoff.
- Mutation gate failure: fail closed and preserve evidence.

## Open Questions

- Which current global and repo-local fork skills should be migrated first?

## First MCP Tools

- `fork_ops_config_read`: read raw or normalized Fork Ops Config.
- `fork_ops_config_validate`: validate config and optionally check a required capability level.
- `fork_ops_capability_report`: report Fork Ops Capability Levels.
- `fork_ops_migration_assessment`: run read-only Migration Assessment.
- `fork_ops_migration_plan`: generate a non-mutating migration plan for review.
- `fork_ops_migration_config_patch`: generate a non-mutating proposed config patch for review.
- `fork_ops_schema`: return the config schema.
