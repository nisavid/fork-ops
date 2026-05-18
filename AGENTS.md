# Agent Instructions

## Project Role

Fork Ops builds agentic operations for maintained repository forks. The current
deliverable is the Codex plugin under `plugins/fork-ops/`.

Keep the distinction clear:

- The plugin supplies reusable operations.
- Each maintained fork owns its checked-in fork-local authority.
- `.agents/fork-ops.toml` is the authored fork config path in a target fork.
- Portability hints are non-normative notes for future Repo Ops migration, not
  authoritative classification.

## Agent skills

### Issue tracker

Issues and PRDs are tracked in GitHub Issues for `nisavid/fork-ops`. See `docs/agents/issue-tracker.md`.

### Triage labels

Use the default five-label triage vocabulary. See `docs/agents/triage-labels.md`.

### Domain docs

This is a single-context repo. Read `CONTEXT.md` for vocabulary and
`docs/agents/domain.md` for source routing.

## Current Foundation

The merged foundation supports:

- TOML config schema and schema printing.
- Python core library, CLI, and MCP adapter.
- Capability reporting for all defined levels, with implemented operations
  centered on `track-aware`.
- Local Git diagnostics for configured remotes and upstream track refs.
- Read-only migration assessment, non-mutating config proposal generation, and
  non-mutating migration plan generation.

Do not describe broad upstream sync, publication closeout, migration dry run, or
migration execution as implemented. They are planned follow-up work.

## Source Map

- `README.md`: human landing page and current project status.
- `plugins/fork-ops/README.md`: plugin package reference and development checks.
- `plugins/fork-ops/docs/`: operation, config schema, and migration guides.
- `plugins/fork-ops/src/fork_ops/`: core library, CLI, and MCP adapter.
- `plugins/fork-ops/schema/fork-ops.schema.json`: discoverable schema copy.
- `plugins/fork-ops/src/fork_ops/fork-ops.schema.json`: packaged runtime schema.
- `specs/fork-ops-foundation/`: foundation design records and pressure cases.
- `CONTEXT.md`: domain vocabulary and relationships.

## Validation

Use `uv` for Python tooling. Before claiming docs or code are ready, run the
smallest relevant checks. For broad plugin changes, run:

```bash
export UV_CACHE_DIR=/tmp/fork-ops-uv-cache
uv run --package fork-ops ruff check --cache-dir .ruff_cache
uv run --package fork-ops pytest plugins/fork-ops/tests -q
uv run --package fork-ops mypy --cache-dir .mypy_cache
uv run --package fork-ops fork-ops schema print | cmp -s - plugins/fork-ops/schema/fork-ops.schema.json
git diff --check
```

For documentation-only changes, at minimum run `git diff --check` and verify
all edited links, commands, paths, and status claims against the repository.

## Operating Policy

- This repository uses agentic engineering and operations. Agents should perform assigned tasks autonomously until they reach a boundary that requires stakeholder policy or an unavailable control surface.
- The user reserves authority over project initiatives and over initiation or continuation of work sessions. Within an active user-directed session, agents should drive execution, review loops, commits, publication steps, and cleanup unless escalation is required.
- Escalate when a decision or action impacts stakeholder concerns and the stakeholder's policy is unknown or uncertain.
- Escalate when an action must be taken but the agent lacks an autonomous control surface for it.
- When escalating a decision and a set of plausible, distinct choices is known, use a multiple-choice input tool if one is available in the interactive context. Include a way for the human operator to provide custom input.
- When escalating an action with a known prescribed path, present the steps clearly for the human operator to perform. Prefer fewer steps; present commands in easily copyable blocks, and prefer a single one-line command when practical.
- For every escalation, make the return contract clear: state exactly what result, confirmation, artifact, or output is needed to hand control back to the agent, and make it easy to validate.
- Prefer verified repository facts over guesses or aspirational guidance.
- When adding new agent-facing instructions, ask whether the information is durable, non-obvious, and useful before scouting a task.
- Remove guidance that becomes redundant with ordinary file discovery.
- Keep human-facing docs user-first. Put maintainer process, agent policy, and
  long rationale in `AGENTS.md`, `docs/agents/`, plugin docs, specs, or issues
  rather than in the landing page.
- In prose docs, render domain vocabulary as ordinary prose. Do not capitalize
  ubiquitous-language terms only because they are defined in `CONTEXT.md`;
  reserve capitalization for proper nouns, acronyms, headings, and quoted source
  titles.
