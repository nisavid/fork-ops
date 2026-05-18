# Fork Ops Context

This context defines the core language for agentic operations on repository forks. It keeps fork-ops vocabulary separate from implementation specs, tool contracts, and workflow runbooks.

## Language

**Maintained Fork**:
A downstream repository operated with an explicit upstream source, local contracts, checked-in fork-ops config, and repo-owned agent guidance.
_Avoid_: Plain fork, clone, downstream repo when the local operating contracts matter.

**Fork Ops Plugin**:
The portable Codex bundle that provides reusable fork-operation tooling for Maintained Forks.
_Avoid_: Source of project truth, repo policy.

**Fork-local Authority**:
The checked-in config and docs that define how a specific Maintained Fork should be operated.
_Avoid_: Plugin defaults, chat memory, global skill policy.

**Authority Surface**:
A source where fork-ops decisions or fork-local operating rules live, such as fork-ops config, fork-local docs, repo-local skills, or policy docs.
_Avoid_: Tool interface, implementation surface.

**Equipment Surface**:
A fork-ops plugin surface that performs, routes, validates, or explains workflows, such as plugin skills, CLI commands, MCP tools, hooks, schemas, prompts, or narrative renderers.
_Avoid_: Source of fork-local authority.

**Fork Ops Config**:
The `.agents/fork-ops.toml` file checked into a Maintained Fork to define its fork-ops settings.
_Avoid_: Plugin config, global config, runtime state.

**Fork Ops Workflow**:
A named intent-level workflow supplied by the Fork Ops plugin.
_Avoid_: Raw CLI command, MCP tool, skill paragraph.

**Workflow Contract**:
The standard definition of a fork-ops workflow, including operator intent, trigger phrases, fork-ops capability level, authority reads, preflight checks, mutation gates, workflow entrypoints, structured evidence, operator-readable narrative, refusal behavior, closeout criteria, and implementation status.
_Avoid_: Loose workflow idea, implementation-only command spec.

**Human Handoff Contract**:
The part of a workflow contract that defines when autonomous work stops, what decision or artifact is needed from the operator, how the request is presented, and how the workflow resumes after the operator responds.
_Avoid_: Vague needs review note, open-ended escalation.

**Workflow Catalog**:
The product-level inventory of workflows that the Fork Ops plugin is designed to support, including workflows that are not yet implemented.
_Avoid_: Current CLI subcommand list, promise that every cataloged workflow is implemented.

**Operator Intent**:
The natural-language goal an operator asks Fork Ops to accomplish. Operator intents organize the workflow catalog before CLI, MCP, skills, or documentation entrypoints are selected.
_Avoid_: Raw function name, subcommand name, implementation entrypoint.

**Workflow Entrypoint**:
A skill, CLI command, MCP tool, prompt, or document path that routes an operator intent into a fork-ops workflow.
_Avoid_: The workflow contract itself, complete product surface.

**Operator Onboarding Workflow**:
A fork-ops workflow that verifies plugin installation, CLI access, MCP registration or diagnostics, skill discoverability, and workflow catalog visibility before work begins in a maintained fork.
_Avoid_: Fork authority migration, target fork assessment.

**Plugin Health**:
The readiness state of Fork Ops plugin surfaces, including plugin registration, skill discovery, CLI execution, MCP config resolution, MCP process startup, MCP tool listing, and Codex UI visibility where a control surface exists.
_Avoid_: Plugin installed flag, single all-or-nothing readiness status.

**Dogfood Target**:
A maintained fork selected to validate fork-ops workflows end-to-end against real fork-local authority, source materials, blockers, and operator workflows.
_Avoid_: Synthetic fixture, proof that every planned workflow is implemented.

**Upstream Release Channel**:
A live upstream selector such as latest stable, latest preview, latest prerelease, or latest LTS.
_Avoid_: Branch, baseline ref, fork-owned ref.

**Upstream Track**:
A named upstream-related ref role maintained or consumed by a Maintained Fork.
_Avoid_: Release channel, arbitrary branch.

**Default Sync Baseline**:
The Upstream Track a Maintained Fork uses for ordinary upstream sync work unless the user chooses another track.
_Avoid_: Always upstream main, latest release channel.

**Descriptive Fork Fact**:
A configured fact about a Maintained Fork that fork-ops tooling should verify against live repository state when possible.
_Avoid_: Policy choice, unchecked assumption.

**Prescriptive Fork Policy**:
A configured rule that expresses how agents should operate a Maintained Fork.
_Avoid_: Discovered fact, tool default.

**Mutation Gate**:
A configured precondition that must pass before a side-effecting fork-ops workflow proceeds.
_Avoid_: Reminder, suggestion, best-effort check.

**Refusal Behavior**:
The workflow contract for declining an unsafe, unsupported, underspecified, or policy-blocked action. It explains the refusal, cites evidence, identifies safe work that can continue, and offers explicit next paths.
_Avoid_: Generic failure, unexplained blocker code.

**Blocker Resolution Workflow**:
A fork-ops workflow that explains a blocker or failed workflow output, traces the evidence that produced it, and guides the operator through safe resolution paths.
_Avoid_: Replacing every workflow's refusal behavior, generic troubleshooting.

**Operator-readable Narrative**:
Plain-language output generated from structured fork-ops evidence that explains what was found, why it matters, what is blocked, and which next safe choices are available.
_Avoid_: Freeform prose detached from evidence, JSON-only result.

**Repo Ops Candidate**:
A Fork Ops capability or domain that could later move wholly or partly into generic repository-operations equipment.
_Avoid_: Fork-specific contract, immediate extraction requirement.

**Fork Ops Add-on**:
The future role of Fork Ops when generic Repo Ops equipment owns shared repository-operation behavior.
_Avoid_: Standalone replacement for Repo Ops.

**Fork-specific**:
A portability classification for behavior that belongs in Fork Ops long term.
_Avoid_: Generic repository operation.

**Shared with Fork Policy**:
A portability classification for generic repository behavior that needs fork-specific policy overlays.
_Avoid_: Pure Fork Ops behavior, pure Repo Ops behavior.

**Repo-ops Candidate**:
A portability classification for behavior likely to move into future generic Repo Ops equipment.
_Avoid_: Immediate dependency on Repo Ops.

**Portability Hint**:
A non-normative classification that suggests how a Fork Ops domain or component might relate to future Repo Ops equipment.
_Avoid_: Authoritative migration decision.

**Fork Ops Capability Level**:
A named workflow readiness gate that describes which fork-ops workflows a maintained fork's config and authority support, and which workflows should be refused until more authority exists.
_Avoid_: Maturity score, quality ranking.

**Workflow Migration**:
The consolidation of reusable fork-operation skills, policies, procedures, gates, handoff contracts, and tool interfaces into Fork Ops plugin surfaces.
_Avoid_: Per-fork config onboarding, replacement of fork-local authority.

**Workflow Migration Inventory**:
The source inventory used during workflow migration, including existing global fork-related skills, repo-local skills, agent instructions, prior fork-ops chat summaries, policies, gates, procedures, and handoff patterns.
_Avoid_: Per-fork config field extraction only, casual brainstorming list.

**Fork Authority Migration**:
The process of mapping a maintained fork's existing fork-local guidance, config, docs, skills, and operating rules into the established fork-ops workflow model.
_Avoid_: Plugin product design, reusable workflow migration.

**Migration Assessment**:
A read-only analysis that maps existing fork-related materials to proposed Fork Ops config, docs, and components.
_Avoid_: Automatic migration.

**Source Material Disposition**:
A reviewed outcome assigned to candidate fork-related source material during fork authority migration. Dispositions can include extracted into config, retained as fork-local authority, mapped to fork-ops workflow backlog, irrelevant to Fork Ops, unsupported extractor shape, needs human decision, or deferred with rationale.
_Avoid_: Unresolved semantic coverage, automatic replacement decision.

**Migration Map**:
The plan section that lists each source material item, its source material disposition, and its target surface such as fork-ops config, retained fork-local authority, workflow catalog backlog, or deferred review.
_Avoid_: Implicit migration scope, unexplained file list.

**Migration Review Artifact**:
A checked-in fork-local artifact that records durable operator decisions from fork authority migration, such as retained authority, exclusions, deferred mappings, and rationale that should remain auditable but does not need to live in fork-ops config.
_Avoid_: Machine-actionable config field, chat-only decision.

**Migration Plan**:
A designed sequence for moving existing fork-related materials into Fork Ops after prerequisite functionality exists.
_Avoid_: Scan report, implementation guess.

**Migration Dry Run**:
A non-mutating execution of a Migration Plan that previews edits, removals, replacements, and validation effects.
_Avoid_: Actual migration.

**Migration Execution**:
A mutating application of a validated Migration Plan.
_Avoid_: Dry run, assessment.

## Relationships

- A **Maintained Fork** has exactly one **Fork-local Authority**.
- The **Fork Ops Plugin** reads, validates, and acts on **Fork-local Authority**.
- The **Fork Ops Plugin** supplies shared workflows but does not replace a **Maintained Fork**'s **Fork-local Authority**.
- Authority surface entries define decisions and operating rules; equipment surface entries expose or perform fork-ops behavior.
- **Fork Ops Config** is part of a **Maintained Fork**'s **Fork-local Authority**.
- **Fork Ops Config** determines one or more **Fork Ops Capability Levels**.
- **Fork Ops Config** contains **Descriptive Fork Facts** and **Prescriptive Fork Policies**.
- The plugin exposes fork-ops workflows through CLI, MCP, skills, and agent-facing documentation surfaces.
- A fork-ops workflow is defined by a workflow contract.
- A workflow contract includes a human handoff contract when operator input may be required.
- A workflow catalog can include planned workflows when each workflow's implementation status is recorded in that catalog.
- Operator intents organize the workflow catalog before implementation entrypoints are selected.
- Workflow entrypoints expose fork-ops workflows without replacing the workflow contracts.
- The operator onboarding workflow reports plugin health before directing work into a maintained fork.
- **Descriptive Fork Facts** are verified against live state when a control surface is available.
- **Prescriptive Fork Policies** guide agent behavior unless the user explicitly changes them.
- **Mutation Gates** enforce **Prescriptive Fork Policies** for side-effecting workflows.
- Refusal behavior is part of a fork-ops workflow contract, not only an error-reporting detail.
- A blocker resolution workflow can continue from another workflow's refusal behavior.
- Operator-readable narratives should be generated from structured evidence.
- A dogfood target validates fork-ops workflows against real fork-local authority, source materials, blockers, and operator workflows.
- A **Maintained Fork** may define multiple **Upstream Tracks**.
- An **Upstream Track** may be updated from an **Upstream Release Channel** or from another upstream Git ref.
- A **Maintained Fork** may mark one **Upstream Track** as its **Default Sync Baseline**.
- A **Repo Ops Candidate** remains in Fork Ops until generic Repo Ops equipment exists.
- A **Fork Ops Add-on** depends on generic Repo Ops for shared repository-operation behavior.
- **Fork-specific**, **Shared with Fork Policy**, and **Repo-ops Candidate** are **Portability Hints** for Fork Ops domains and components.
- Repo Ops migration design owns the authoritative classification for future extraction.
- A **Migration Assessment** can inform a **Migration Plan**.
- A **Migration Plan** should assign a source material disposition before replacing, removing, or relying on candidate source material.
- A **Migration Plan** should include a migration map.
- A migration review artifact can preserve durable migration decisions that are not machine-actionable config.
- A **Migration Plan** should support a **Migration Dry Run** before **Migration Execution**.
- Fork authority migration may create fork-ops config while some source materials remain retained authority, but retained authority should not be replaced or removed until the relevant fork-ops workflows and extraction coverage exist.

## Example dialogue

> **Dev:** "Should this rule live in the Fork Ops Plugin?"
> **Domain expert:** "Only if it is reusable across Maintained Forks. If it defines how this fork operates, it belongs in Fork-local Authority."
> **Dev:** "Is latest stable the sync branch?"
> **Domain expert:** "No. Latest stable is an Upstream Release Channel. The fork may publish an Upstream Track from it, then use that track as the Default Sync Baseline."
> **Dev:** "The config says main is protected, but GitHub says it is not."
> **Domain expert:** "That is a Descriptive Fork Fact mismatch. Report it as diagnostics before applying Prescriptive Fork Policy."
> **Dev:** "Can I push this sync branch even though checks are stale?"
> **Domain expert:** "Only if the relevant Mutation Gate allows it or the human operator explicitly grants an exception."
> **Dev:** "PR closeout is not fork-specific. Should we omit it?"
> **Domain expert:** "No. Mark it as a Repo Ops Candidate, implement only the fork-specific needs here, and keep it easy to migrate later."
> **Dev:** "External-contributor PR repair feels generic."
> **Domain expert:** "Classify it as Shared with Fork Policy when fork branch protections, code scanning, or upstreaming rules change the workflow."
> **Dev:** "Can Fork Ops decide this component definitely belongs in Repo Ops later?"
> **Domain expert:** "No. Fork Ops can leave a Portability Hint, but Repo Ops migration design will make that decision."
> **Dev:** "Does every Maintained Fork need package provenance rules?"
> **Domain expert:** "No. That belongs to a later Fork Ops Capability Level; a simple fork can still be identified, scoutable, and sync-ready."
> **Dev:** "Can the first plugin rewrite existing repo-local fork skills?"
> **Domain expert:** "No. Start with Migration Assessment. Design, dry-run, and execute the full migration after the target functionality exists."

## Flagged ambiguities

- "fork" can mean any GitHub fork or a **Maintained Fork** with explicit operating contracts. Use **Maintained Fork** when fork-ops tooling should treat the repo as managed.
- "upstream stable" can mean either an **Upstream Release Channel** or a fork-owned **Upstream Track** derived from that channel. Name the channel and the track separately.
- "config" can mean verified repository facts or operating policy. Use **Descriptive Fork Fact** for the former and **Prescriptive Fork Policy** for the latter.
- "generic repo ops" is future equipment, not a current dependency. Mark reusable surfaces as **Repo Ops Candidates** without blocking Fork Ops foundation work.
- "repo-ops candidate" appears both as a concept and as a classification. Use **Repo Ops Candidate** for the concept and **Repo-ops Candidate** for the classification value.
- **Portability Hints** are not normative. Do not use them to block implementation or override current Fork Ops requirements.
- Capability levels describe workflow readiness and refusal boundaries, not whether a fork is well maintained.
- Workflow migration defines reusable Fork Ops plugin behavior before fork authority migration maps a specific maintained fork into that behavior.
- A workflow migration inventory informs the workflow catalog.
- **Migration Assessment** is not a promise that Fork Ops can safely migrate the material yet.
- Incomplete semantic coverage is a review state that should be resolved through source material disposition, not a hard dead end by itself.
- Incomplete semantic coverage should block replacement or deletion of source material, not safe config creation that explicitly preserves the source material as retained authority.
- **Mutation Gates** are policy preconditions. Their implementation surface can vary by harness.
