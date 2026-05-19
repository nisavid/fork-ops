# Domain Documentation

Use this page to choose the right source before making fork-ops claims or edits.

## Required Vocabulary

Read `CONTEXT.md` before naming domain concepts in docs, issues, tests, or code.
Use the project terms there, especially:

- maintained fork
- fork-local authority
- fork ops config
- upstream release channel
- upstream track
- default sync baseline
- migration assessment
- migration plan
- migration dry run
- migration execution
- portability hint

If a needed concept is missing, note the vocabulary gap instead of inventing a
near-synonym.

In prose docs, render these concepts as ordinary lowercase language unless a
heading, proper noun, acronym, or quoted source title requires capitalization.

## Source Routing

Use the narrowest source that answers the question:

- Human project status and entry points: `README.md`
- Plugin package surfaces and local checks: `plugins/fork-ops/README.md`
- Operation behavior: `plugins/fork-ops/docs/operation-guide.md`
- Config shape and capability sections: `plugins/fork-ops/docs/config-schema.md`
- Migration lifecycle and boundaries: `plugins/fork-ops/docs/migration.md`
- Design rationale and pressure cases: `specs/fork-ops-foundation/`
- Issue workflow and triage vocabulary: `docs/agents/issue-tracker.md` and
  `docs/agents/triage-labels.md`
- Current implementation: `plugins/fork-ops/src/fork_ops/`

## Current Implementation Boundary

The foundation implementation is `track-aware`. It supports config discovery,
schema validation, capability reporting, local Git diagnostics, workflow
migration inventory reporting, migration assessment, proposed config patch
generation, migration plan generation, migration dry run, and guarded migration
execution for blocker-free config creation plans.

Treat these as planned, not implemented:

- Broad upstream sync mutation
- PR publication closeout
- source-material removal during migration execution
- arbitrary migration edits beyond guarded fork ops config creation
- General Repo Ops extraction

## Documentation Placement

Put durable facts where future readers will look first:

- Root `README.md`: user-facing orientation, current status, and links.
- Plugin docs: how to use the current plugin surfaces.
- Specs: rationale, domain design, pressure cases, and implementation contracts.
- `AGENTS.md`: always-loaded operating law and validation expectations.
- Issues: next work, follow-up hardening, and unresolved design decisions.

Do not put long maintainer process or agent-only policy in the root README.
