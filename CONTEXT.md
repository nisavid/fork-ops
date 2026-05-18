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

**Fork Ops Config**:
The `.agents/fork-ops.toml` file checked into a Maintained Fork to define its fork-ops settings.
_Avoid_: Plugin config, global config, runtime state.

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
A configured precondition that must pass before a Fork Ops operation performs a side-effecting action.
_Avoid_: Reminder, suggestion, best-effort check.

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
A named readiness level that describes which Fork Ops operations a Maintained Fork's config and authority support.
_Avoid_: Maturity score, quality ranking.

**Migration Assessment**:
A read-only analysis that maps existing fork-related materials to proposed Fork Ops config, docs, and components.
_Avoid_: Automatic migration.

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
- The **Fork Ops Plugin** supplies shared operations but does not replace a **Maintained Fork**'s **Fork-local Authority**.
- **Fork Ops Config** is part of a **Maintained Fork**'s **Fork-local Authority**.
- **Fork Ops Config** determines one or more **Fork Ops Capability Levels**.
- **Fork Ops Config** contains **Descriptive Fork Facts** and **Prescriptive Fork Policies**.
- **Descriptive Fork Facts** are verified against live state when a control surface is available.
- **Prescriptive Fork Policies** guide agent behavior unless the user explicitly changes them.
- **Mutation Gates** enforce **Prescriptive Fork Policies** for side-effecting operations.
- A **Maintained Fork** may define multiple **Upstream Tracks**.
- An **Upstream Track** may be updated from an **Upstream Release Channel** or from another upstream Git ref.
- A **Maintained Fork** may mark one **Upstream Track** as its **Default Sync Baseline**.
- A **Repo Ops Candidate** remains in Fork Ops until generic Repo Ops equipment exists.
- A **Fork Ops Add-on** depends on generic Repo Ops for shared repository-operation behavior.
- **Fork-specific**, **Shared with Fork Policy**, and **Repo-ops Candidate** are **Portability Hints** for Fork Ops domains and components.
- Repo Ops migration design owns the authoritative classification for future extraction.
- A **Migration Assessment** can inform a **Migration Plan**.
- A **Migration Plan** should support a **Migration Dry Run** before **Migration Execution**.

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
- **Fork Ops Capability Levels** describe supported operations, not whether a fork is well maintained.
- **Migration Assessment** is not a promise that Fork Ops can safely migrate the material yet.
- **Mutation Gates** are policy preconditions. Their implementation surface can vary by harness.
