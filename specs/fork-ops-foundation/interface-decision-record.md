# Interface Decision Record: Fork Ops Foundation

Status: Draft

## Requirement

Fork Ops must provide reusable operations for Maintained Forks while keeping fork-specific facts and policies in checked-in repo-local config and docs.

## Decision

Use a Codex plugin for the initial portable bundle, with a design bundle before scaffolding implementation files.

The first fully operational target is the `track-aware` capability level. The config schema should include the shape needed for `sync-ready`, but broad sync mutations can follow after config access, validation, and upstream-track reporting are solid.

The first migration surface includes read-only migration assessment,
non-mutating config proposal generation, and non-mutating migration plan
generation. Full migration must later support dry-run preview, mutation, and
verification.

Use Python for the initial core library, CLI, and MCP server implementation.

## Chosen Surface

- Skill: procedural workflows and judgment-heavy operation routing.
- MCP/tool: typed config access, validation, live-state reads, semantic config mutations, and other gated mutations.
- Hook: deferred; use only for narrow lifecycle checks or mutation gates.
- Agent Profile: deferred until a specialized worker role needs distinct authority or tool access.
- Plugin: initial Codex distribution boundary.
- Script: deterministic parsing, validation, inspection, formatting, and report generation.
- Config: `.agents/fork-ops.toml` as the checked-in fork-local config path.
- Local docs: glossary, schema docs, domain map, runbooks, and migration guidance.

## Implementation Projection

- Core package: `plugins/fork-ops/src/fork_ops/` for schema, parsing, normalization, diagnostics, Git/GitHub inspectors, release-channel resolution, migration assessment, config proposals, and migration plans.
- CLI adapter: a `fork-ops` console entry point over the core package.
- MCP adapter: a stdio MCP server over the core package.

## Config API Shape

Read surfaces should expose raw TOML, parsed config, normalized config, capability-level reports, and diagnostics. Write surfaces should default to semantic operations such as adding an upstream, adding a release channel, adding an upstream track, setting the default sync baseline, adding a local surface, or setting a portability hint.

Raw TOML writes are an advanced escape hatch. They should validate parse and schema results and show a diff before writing.

## Mutation Gate Placement

Mutation Gate policy logic belongs in the core library, not only in a harness-specific hook. Semantic tools should call the same gate logic before side effects and return structured evidence. Codex hooks should call or mirror that same gate logic at harness boundaries for lifecycle events and manual mutation paths.

This makes hooks the authoritative Codex interception surface without making hook scripts the only source of gate semantics.

## Rationale

The plugin boundary makes the equipment discoverable and installable in Codex. The config path keeps fork-specific authority in each Maintained Fork. MCP/tools provide a stable structured surface for agents and future clients. Skills remain thin and route judgment-heavy work to deterministic scripts and typed tools.

Python is the initial implementation language because the same package can own TOML parsing, schema validation, deterministic inspections, CLI commands, and the MCP stdio server without duplicating config logic.

The Codex plugin marketplace entry is a packaging step. The repo registers this plugin in `.agents/plugins/marketplace.json`, pointing to `./plugins/fork-ops`.

## Evidence Category

Current source and documentation evidence:

- Existing Lemonade and codex-app-linux fork guidance shows fork-local policy belongs in checked-in docs and config.
- Current Codex plugin docs support packaging skills, hooks, MCP servers, apps, and assets in one plugin.
- Current MCP Python SDK docs support typed tools, structured output, prompts, and resources over stdio.
- Agent Armory component guidance favors docs for truth, config for durable choices, scripts for deterministic work, MCP/tools for typed operations, and plugins for distribution.
- Accepted Fork Ops gate design puts policy semantics in core code, semantic enforcement in typed tools, and harness-boundary enforcement in hooks.

## Harness-Specific Projection

- Codex: required target for the initial version.
- Other agent harnesses: out of scope for the initial version.
- Future Repo Ops: portability hints should make extraction easier, but Fork Ops does not depend on Repo Ops existing.

## Alternatives Rejected

- Repo-local skills only: not generic or discoverable enough for repeated fork operations.
- Home-global skills only: cannot carry fork-specific checked-in authority.
- MCP server only: lacks procedural guidance, docs, and plugin distribution.
- Plugin scaffold first: risks creating component structure before the domains and interface split are clear.
- Separate implementations for CLI and MCP: duplicates schema and validation logic.

## Risks

- The plugin may absorb generic repository operations that should later move into Repo Ops.
- Mutation-capable tools need clear side-effect classification and gates.
- Overloaded config can become a second documentation system if schema boundaries are loose.
- Hooks can become hidden workflows if used too broadly.
- Designing `sync-ready` too early may overfit to the current complex forks; implementation should stop at `track-aware` until pressure scenarios justify the next workflow layer.
- Python packaging inside the Codex plugin needs explicit path and dependency handling before publication.

## Maintenance Notes

Review this decision when Codex plugin capabilities change, when Repo Ops design starts, when mutation gates are implemented, or when pressure scenarios show repeated ambiguity.
