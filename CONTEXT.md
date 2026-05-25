# Fork Ops Context

This context defines the core language for agentic operations on repository forks. It keeps fork-ops vocabulary separate from implementation specs, tool contracts, and workflow runbooks.

## Language

**Maintained Fork**:
A downstream repository operated with an explicit upstream source, local contracts, checked-in fork-ops config, and repo-owned agent guidance.
_Avoid_: Plain fork, clone, downstream repo when the local operating contracts matter.

**Fork Ops Plugin**:
The portable Codex bundle that provides reusable fork-operation tooling for Maintained Forks.
_Avoid_: Source of project truth, repo policy.

**Agentically Operated**:
Run through supported agent workflows that can read, write, and execute fork-ops state under explicit authority, validation, and mutation gates.
_Avoid_: Manual one-off maintenance, unrestricted agent mutation, agentically managed.

**Workflow Run Mode**:
The dry-run or wet-run mode used to preview or execute a mutating fork-ops workflow.
_Avoid_: Capability level, validation status.

**Replayable Wet Run**:
A wet run that applies the exact reviewed dry-run plan without replanning the outcome.
_Avoid_: Fresh migration plan, best-effort repeat.

**Workflow State Surface**:
A durable state category used by a fork-ops workflow according to the state purpose and lifecycle it preserves.
_Avoid_: File path choice, chat-only state.

**Fork-local Authority**:
The checked-in config and docs that define how a specific Maintained Fork should be operated.
_Avoid_: Plugin defaults, chat memory, global skill policy.

**Authority Surface**:
A source where fork-ops decisions or fork-local operating rules live, such as fork-ops config, fork-local docs, repo-local skills, or policy docs.
_Avoid_: Tool interface, implementation surface.

**Equipment Surface**:
A fork-ops plugin surface that performs, routes, validates, or explains workflows, such as plugin skills, CLI commands, MCP tools, hooks, schemas, prompts, or narrative renderers.
_Avoid_: Source of fork-local authority.

**Existing Fork Ops Equipment**:
A skill, plugin, tool, config, hook, or instruction surface that exists before Fork Ops onboarding and may own, consume, integrate with, or ignore fork-operation behavior.
_Avoid_: Installed skill, active dependency, retained authority by default.

**Equipment Facet**:
A separable behavior, policy, route, or integration within existing fork-ops equipment that may need its own equipment disposition.
_Avoid_: Whole equipment item, source file.

**Equipment Disposition**:
A reviewed operator decision for existing fork-ops equipment, equipment components, or equipment facets during onboarding.
_Avoid_: Installed state, inferred user intent, source-material disposition.

**Equipment Decision Status**:
The review state of an equipment review record entry's disposition value.
_Avoid_: Equipment disposition value, risk acceptance, classification confidence, activation state.

**Equipment Risk Acceptance**:
An explicit operator acceptance of disclosed risk attached to an equipment review record decision.
_Avoid_: Decision status, implied consent, hidden warning.

**Fork Ops Consumer**:
Existing equipment that consumes, integrates with, or depends on Fork Ops behavior or policy output without owning that fork-operation behavior.
_Avoid_: Fork Ops owner, conflicting equipment.

**Consumer Compatibility Entry**:
A durable equipment review record entry that records a consumer integration contract or output shape that Fork Ops should preserve.
_Avoid_: Equipment disposition, behavior ownership decision, retained owner.

**Equipment Migration**:
The onboarding process for handling existing fork-ops equipment through migration, retention, compatibility preservation, redirection, disabling, splitting, discarding, or deferment.
_Avoid_: Source material extraction only, automatic replacement.

**Equipment Migration Preflight**:
A non-mutating equipment migration report that groups discovered existing equipment, proposes candidate facets and dispositions, identifies conflicts, and names activation-readiness impact.
_Avoid_: Equipment migration execution, uninstall plan.

**Equipment Discovery Scope**:
A named boundary for where equipment migration scans for prior equipment during onboarding.
_Avoid_: Scanner implementation detail, implicit global search.

**Unassessed Equipment Area**:
A named discovery scope, equipment group, or capability overlap that equipment migration has not scanned or classified enough to support activation-readiness claims.
_Avoid_: Warning-only note, scan failure, accepted risk.

**Equipment Review Artifact**:
A durable equipment migration artifact, usually an equipment review record, that preserves equipment decisions and supporting evidence once equipment migration proceeds beyond discovery.
_Avoid_: Fork authority migration review artifact, machine-actionable activation state.

**Equipment Review Record**:
A structured TOML equipment review artifact that records operator intent, unassessed areas, equipment dispositions, conflict decisions, shadow-mode or advisory-mode choices, review freshness policy, and supporting evidence references.
_Default path_: `docs/agents/fork-ops-equipment-review.toml` for repo-local records.
_Avoid_: Active Fork Ops config, `.agents/fork-ops.toml` schema family, prose-only narrative, migration execution artifact.

**Equipment Evidence Entry**:
A structured evidence item in an equipment review record that supports equipment dispositions, risk acceptances, or derived capability claims.
_Avoid_: Free-form rationale, chat transcript, untraceable observation.

**Equipment Identifier**:
A stable, visible, namespaced identifier for existing fork-ops equipment or a reviewed equipment facet, derived from discovery scope and source identity when possible.
_Avoid_: Operator-facing display label, mutable nickname, classification confidence.

**Follow-up Candidate**:
Actionable work discovered by Fork Ops that should be tracked but has not yet been projected into an issue tracker or in-repo tracker.
_Avoid_: Chat-only TODO, implemented work.

**Follow-up Record**:
A durable record of follow-up candidates that persists until each candidate is projected into an issue tracker or in-repo tracker.
_Avoid_: Reminder text, temporary scratch note.

**Follow-up Audience Scope**:
The ownership audience for a follow-up candidate, such as team-wide equipment activation or user-specific activation.
_Avoid_: Storage location, urgency, blocker status.

**User Follow-up Registry**:
A user-scoped durable home for user-specific follow-up candidates across agent-operated equipment.
_Avoid_: Team issue tracker, repo issue tracker, Fork Ops-only follow-up store.

**Follow-up Reminder Surface**:
A harness-dependent surface that brings unresolved follow-up candidates into relevant agent sessions without requiring the operator to ask Fork Ops directly.
_Avoid_: Capability report only, chat memory.

**Reminder Overhead Constraint**:
A provisional constraint that follow-up reminders should avoid prompt or session overhead when no unresolved candidates exist and minimize overhead when candidates do exist.
_Avoid_: Proven guarantee, global reminder policy.

**Onboarding Intent**:
The operator's session-level direction for Fork Ops onboarding before equipment groups and facets receive detailed dispositions.
_Avoid_: Installed state, per-facet disposition, inferred final decision.

**Fork Ops Capability Conflict**:
An overlap where Fork Ops and existing equipment can both route, own, or mutate the same fork-operation behavior in ways that may produce inconsistent policy or effects.
_Avoid_: Harmless duplicate, user preference note.

**Equipment Classification Confidence**:
A short operator-facing confidence tier for an equipment group or facet classification during equipment migration.
_Avoid_: Quality score, implementation certainty.

**Unscanned Equipment Exception**:
An operator-approved exception that lets Fork Ops proceed despite unscanned equipment in a defined scope, with explicit risk disclosure and capability limits.
_Avoid_: Scan success, activation readiness, hidden risk acceptance.

**Review Freshness Policy**:
A declared set of conditions that require a persistent exception or long-lived review artifact to be revalidated before future agents rely on it for activation-readiness or Replacement Coverage claims.
_Avoid_: Time-based expiry by default, session-local evidence, execution drift check.

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

**Activation Readiness**:
The readiness of a Fork Ops capability to be active after considering equipment dispositions and capability conflicts.
_Avoid_: Config validity, capability level.

**Operational Continuity**:
A state where a maintained fork can keep operating safely for a behavior because Fork Ops is active or a retained owner remains authoritative.
_Avoid_: Replacement coverage, migration completion.

**Shadow Mode**:
A non-authoritative state where Fork Ops runs beside retained authoritative equipment to compare behavior, build confidence, or prepare migration without taking over the workflow.
_Avoid_: Generic advisory output, Replacement Coverage, active ownership.

**Advisory Mode**:
A non-authoritative state where Fork Ops provides guidance, diagnostics, plans, or warnings without mutating, routing, or shadowing an authoritative equipment owner.
_Avoid_: Shadow Mode, active ownership, Replacement Coverage.

**Capability Report**:
A live Fork Ops output that states which capability levels, workflows, covered behaviors, and retained-authority requirements apply to a configured maintained fork.
_Avoid_: Migration plan, static schema validation, workflow catalog.

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

**Replacement Coverage**:
Verified and activation-ready Fork Ops workflow or config behavior that can safely stand in for a source material item while preserving any retained authority that remains outside the replacement.
_Avoid_: Catalog evidence, config creation, retained-owner redirection, inferred equivalence.

**Covered Behavior**:
A specific source-material behavior that has Replacement Coverage.
_Avoid_: Covered file, covered workflow, covered source.

**Migration Map**:
The plan section that lists each source material item, its source material disposition, and its target surface such as fork-ops config, retained fork-local authority, workflow catalog backlog, or deferred review.
_Avoid_: Implicit migration scope, unexplained file list.

**Migration Review Artifact**:
A checked-in fork-local artifact that records durable operator decisions from fork authority migration, such as retained authority, exclusions, deferred mappings, and rationale that should remain auditable but does not need to live in fork-ops config.
_Avoid_: Machine-actionable config field, execution replay state, generic coordination state.

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
- Fork Ops aims to make maintained-fork operation **Agentically Operated**, not manually maintained through one-off edits.
- Every mutating Fork Ops workflow should make dry-run mode available.
- Mutating workflows with hard-to-reverse, varied, or highly situational outcomes should default to dry-run mode and offer a replayable wet run after review.
- Replayable wet run support is required for dry-run-default workflows and optional for workflows that default to gated wet runs.
- Replayable wet runs for hard-to-reverse or high-variability workflows require a persisted dry-run artifact or equivalent durable plan token.
- Replayable wet runs should revalidate preconditions and fail closed by default when drift is detected.
- When a workflow defines safe drift handling, a replayable wet run may offer operator-approved continuation by adjusting for drift, replaying unaffected parts, or resuming with a fresh partial dry run.
- Mutating workflows with predictable steps, staged or versioned effects, easy reversal, or independently previewable risky steps may default to wet-run mode when gates keep the operation controlled.
- Fork Ops workflows should be designed toward safe, controlled, predictable wet runs where the domain allows it.
- For wet-run-default workflows, an imperative operator request implies wet-run execution when the workflow is implemented, gates pass, and no human decision is unresolved.
- For dry-run-default workflows, an imperative operator request starts the dry-run or plan first and then offers replayable wet-run execution after review.
- Operators may request dry-run mode for any mutating workflow.
- Operators may request wet-run mode for a dry-run-default workflow only when the workflow defines a safe bypass policy or can use an existing reviewed dry-run artifact.
- Workflow run-mode overrides do not bypass mutation gates, authority checks, or human decision blockers.
- Multi-step mutating workflows should persist enough state for a fresh agent to resume safely after handoff, compaction, operator review, external checks, or wet-run replay.
- Workflow state surfaces are selected by purpose and lifecycle rather than by defaulting to a single artifact path.
- Authority state preserves current machine-actionable policy, activation, redirect, disable, and ownership state.
- Decision state preserves reviewed operator choices, dispositions, risk acceptances, retained-authority rationale, and deferments.
- Execution state preserves dry-run artifacts, replay tokens, preconditions, drift checks, and partial-resume state.
- Replayable wet runs should use workflow-specific execution artifacts for replay state; review artifacts may reference those execution artifacts but should not replace them.
- Dry-run artifacts for replayable wet runs should embed enough evidence snapshot to make replay drift-checkable.
- Replay evidence snapshots should include the reviewed dispositions, evidence IDs, source hashes or timestamps, and derived blocker-clearance facts the dry run relied on.
- Replay evidence snapshots may reference current records or reports, but wet-run replay should not trust mutable current files without drift checks.
- Evidence state preserves validation, scan, capability, and coverage evidence needed to justify reports and future decisions.
- Evidence state may be embedded in reports or artifacts, but claims about Replacement Coverage, Activation Readiness, and Operational Continuity should remain traceable to evidence.
- Coordination state preserves issue-tracker projections, follow-up records, blockers, and work routing.
- Coordination state may carry full follow-up candidate content before tracker projection and should prefer tracker references after projection.
- Handoff state preserves return contracts and enough context for a fresh agent to resume without becoming authority.
- Handoff state may summarize decisions and point to authoritative artifacts, but should not be the durable authority for decisions.
- External equipment state preserves user-global or cross-repo equipment decisions that cannot be owned by the maintained fork.
- Fork-local config may reference external equipment state as external authority but should not claim ownership over that state.
- Authority surface entries define decisions and operating rules; equipment surface entries expose or perform fork-ops behavior.
- Existing equipment can be irrelevant to Fork Ops, a Fork Ops consumer or integration surface, a mixed surface with some fork-ops-owning behavior, or wholly fork-ops-owning equipment.
- Existing equipment can include documents, config, skills, plugins, tools, hooks, prompts, and other components that shape agent behavior.
- Installed existing equipment does not prove current use or operator intent to retain it.
- Installing Fork Ops is a prior signal that the default **Onboarding Intent** is migration toward Fork Ops, but it does not decide detailed equipment dispositions by itself.
- Fork Ops onboarding should ask for operator intent when migration, retention, disabling, removal, or compatibility work depends on ambiguous use or retention intent.
- A **Fork Ops Consumer** needs compatibility preservation when the operator values that consumer facet.
- Existing equipment that owns fork-operation behavior requires an **Equipment Disposition** before overlapping Fork Ops behavior is treated as active.
- Retaining fork-ops-owning existing equipment means Fork Ops must not also own the overlapping behavior.
- Retain and redirected are separate decisions: retain keeps the existing equipment authoritative, while redirected means Fork Ops routes an overlapping surface to that retained owner.
- A retained existing owner should cause overlapping Fork Ops behavior to be disabled, redirected to the retained owner, or refused as unavailable according to the available harness controls.
- Migrating fork-ops-owning existing equipment means Fork Ops should become the owner after Replacement Coverage exists, activation changes are verified, and the operator approves any final edit or removal of prior equipment.
- Discarding existing equipment means the operator does not want that equipment or facet preserved or migrated, but cleanup still requires scope, permission, and affected-repo checks.
- For mixed existing equipment, prefer redirection before selective disable, prefer scoped edit or removal before splitting, and reserve splitting for cases where architectural clarity justifies the heavier cleanup.
- Equipment migration should produce reviewed plans before mutating existing equipment.
- Fork Ops may later execute repo-local equipment mutations under normal migration gates, but global equipment mutations belong to global equipment migration.
- Equipment migration may ignore irrelevant existing equipment without operator input.
- Equipment migration may preserve clearly used consumer or integration facets without operator input, but should ask when valued use is ambiguous.
- Equipment migration should ask for operator intent before assigning a disposition to fork-ops-owning equipment or facets unless explicit policy already gives the disposition.
- Low-risk default dispositions for irrelevant, non-owning, or clearly used consumer equipment should remain proposed unless explicit policy allows auto-review.
- Fork-ops-owning, conflicting, mutating, or risk-bearing equipment dispositions require operator review before becoming reviewed dispositions.
- Auto-reviewed equipment dispositions should be limited to explicit policy cases and should record the policy evidence that authorized auto-review.
- The first equipment migration implementation should not auto-review dispositions; it may propose defaults, but reviewed dispositions require explicit operator review.
- Checked-in policy, config, lockfiles, and discovered equipment state are inputs for an in-session operator intent check, not sufficient current intent by themselves.
- Equipment migration should run an intent preflight for discovered prior equipment before drilling into detailed source-material or equipment-item decisions.
- Equipment migration preflight should establish the **Onboarding Intent** before presenting group-level or facet-level disposition choices.
- Common onboarding intents include migration toward Fork Ops, coexistence with existing equipment, evaluation only, targeted migration, and custom operator direction.
- Under migration-toward-Fork-Ops intent, covered facets may migrate while uncovered facets remain retained, shadowed, or advisory and missing equipment becomes follow-up work.
- Equipment migration intent preflight should group discovered equipment by meaningful operator-facing role before asking for detailed item-level disposition.
- Equipment migration preflight should turn findings into concise operator questions with recommended defaults and consequence summaries.
- Equipment migration preflight should prefer deterministic scan, parsed source, and command-output evidence before asking for operator statements.
- Equipment migration preflight should ask narrow operator questions when scan evidence is unavailable, inconclusive, or insufficient for intent and risk decisions.
- Equipment migration preflight should name the active **Equipment Discovery Scopes** before asking the operator to accept, skip, or expand scanning.
- Common **Equipment Discovery Scopes** are repo-local, user-global, explicit-source-root, and known-plugin-cache.
- Repo-local discovery should be included by default during repo onboarding.
- Equipment migration preflight should recommend broad user-global equipment scanning when relevant, but make that scan an explicit skippable choice.
- Skipped discovery scopes should be recorded as **Unassessed Equipment Areas** rather than hidden in warning prose.
- An **Unassessed Equipment Area** should name the skipped or incomplete scope, the reason it remains unassessed, affected capabilities, default activation limits, and any accepted **Unscanned Equipment Exception**.
- Common unassessed-area reasons include skipped when the operator chose not to scan, and inconclusive when Fork Ops attempted discovery or classification but could not establish enough confidence.
- Skipped and inconclusive unassessed areas should drive different risk disclosures, retry guidance, and exception handling.
- Inconclusive unassessed areas should be retryable without changing the operator's onboarding intent.
- Inconclusive retry paths may include adding source roots, raising diagnostic detail, inspecting named files, or asking a narrow operator question.
- Skipped unassessed areas should offer scanning the scope now or accepting the scoped risk.
- Skipping recommended broad user-global equipment scanning limits activation-readiness and Replacement Coverage claims for capabilities that may overlap unscanned global equipment.
- By default, skipped user-global scanning blocks mutating or auto-triggered activation for plausible overlaps, while diagnostic or advisory behavior may proceed with an unassessed-risk warning.
- An **Unscanned Equipment Exception** can apply to any recommended equipment scan scope, not only user-global equipment.
- Operators may grant an **Unscanned Equipment Exception** per invocation, per session, or persistently in config.
- A persistent **Unscanned Equipment Exception** supports Replacement Coverage only when config records the affected scope, affected capabilities, explicit risk disclosure, operator acceptance, and **Review Freshness Policy**.
- Long-lived review artifacts and persistent exceptions should use a **Review Freshness Policy** when future agents may rely on them without asking the operator again.
- Review freshness policies may be event-based rather than time-based.
- Review freshness events can include Fork Ops upgrades, harness trigger-mode changes, newly discovered equipment, changed retained equipment, new overlapping capabilities, operator intent changes, or maintained-fork scope changes.
- Session-local preflight findings do not need expiry because they support only the current session or artifact.
- Execution artifacts rely on drift checks rather than review freshness policy.
- Operator acceptance of any unscanned-equipment risk must immediately follow the agent's best available disclosure of the known risks.
- Per-invocation and per-session **Unscanned Equipment Exceptions** may allow a workflow run to proceed but do not establish durable Replacement Coverage.
- Discovery-only equipment migration preflight may produce a report without writing an equipment review record.
- A missing equipment review record should not block discovery-only equipment migration preflight.
- A missing equipment review record should block onboarding steps that rely on reviewed equipment dispositions or risk acceptances.
- When a required equipment review record is missing, the workflow should stop before activation or migration and ask for review.
- Equipment migration preflight should not create a blank equipment review record when no prior equipment or durable decisions are found.
- When no equipment review record is needed, the preflight report may state that outcome without creating durable record churn.
- A clean equipment migration preflight may clear equipment-conflict blockers for the assessed discovery scopes and affected capabilities.
- A clean preflight should not clear blockers for unassessed equipment areas, skipped scopes, or capabilities outside the assessed scope.
- A clean preflight result that later workflows rely on should persist as evidence state even when no equipment review record is needed.
- Durable clean-preflight evidence should record assessed discovery scopes, source snapshot or timestamp, affected capabilities, and any unassessed equipment areas.
- Clean-preflight evidence should live in the capability report, migration artifact, or other artifact that relies on it to clear a blocker.
- Clean-preflight evidence should not force an equipment review record unless there are actual equipment decisions to preserve.
- Equipment migration preflight should emit proposed findings and proposed equipment review record entries without recording reviewed dispositions or risk acceptances.
- Equipment migration preflight should emit one combined proposed equipment review record by default, grouped internally by discovery scope or operator-facing equipment group.
- Separate proposed record fragments may be useful for advanced review but should not be the default preflight shape.
- Proposed equipment review records should omit irrelevant equipment by default after reporting it.
- Irrelevant-equipment evidence should be included in durable artifacts only when needed to clear a blocker, explain assessed scope, or support a future claim.
- Consumer-only equipment should get durable equipment review record entries only when compatibility preservation matters.
- Unaffected or irrelevant consumer-only equipment may be reported and omitted from durable records.
- Consumer compatibility entries should record the integration contract or output shape that Fork Ops must preserve.
- Consumer compatibility entries should be separate from equipment disposition entries.
- Consumer compatibility entries should reference the consumer equipment identifier and the compatibility contract to preserve.
- Consumer compatibility entries should declare their compatibility impact for each affected capability or workflow.
- Compatibility impact values commonly include required, optional, and advisory.
- Compatibility impact determines whether verification failure blocks activation or creates follow-up.
- Required compatibility impact blocks activation only for the affected capability or workflow scope named by the entry.
- Required compatibility impact should not block unrelated capabilities or workflows unless the entry explicitly scopes them.
- Capability reports should evaluate consumer compatibility impact per capability or workflow scope.
- Consumer compatibility entries may scope impact to affected Fork Ops workflows, affected Fork Ops capability levels, or both.
- Affected workflow names are preferred when the compatibility constraint is workflow-specific.
- Affected capability levels are useful for broad gates.
- Capability reports should use the narrower applicable compatibility scope when both workflow and capability-level scopes are present.
- Reviewed consumer compatibility entries should fail validation when compatibility impact is missing.
- Reviewed consumer compatibility entries should fail validation when they reference unknown Fork Ops workflow names.
- Reviewed consumer compatibility entries should fail validation when they reference unknown Fork Ops capability levels.
- Proposed consumer compatibility entries may carry unknown workflow names as discovery output.
- Proposed consumer compatibility entries may carry unknown capability levels as discovery output.
- Compatibility constraints for future or unknown workflows or capability levels should be explicitly marked as follow-up rather than reviewed current scope.
- Follow-up candidates for future or unknown compatibility scopes should preserve the original proposed workflow or capability-level string as evidence.
- Proposed consumer compatibility entries may omit compatibility impact while preflight is still gathering information.
- Consumer compatibility entries may reference verification commands or checks that validate the preserved contract.
- Equipment migration preflight may run compatibility checks to discover current compatibility state and propose compatibility entries.
- Activation should run or verify required compatibility checks again because activation gates current behavior.
- Dry-run artifacts should snapshot compatibility-check evidence they rely on, and replayable wet runs should revalidate required compatibility checks.
- Compatibility verification commands should be non-mutating by default.
- Mutating compatibility checks require explicit metadata and should be gated like mutating workflow steps.
- Mutating compatibility checks should not run automatically during preflight.
- The first equipment migration implementation should support only non-mutating compatibility verification checks.
- Compatibility contracts that require mutating verification should be recorded as unsupported or follow-up work rather than run by the first implementation.
- Unsupported mutating compatibility verification should block activation when the compatibility contract is required for that activation.
- Unsupported mutating compatibility verification should create follow-up without blocking when the compatibility contract is optional or advisory for the activation being attempted.
- When a reviewed consumer compatibility entry has a verification check, activation should prefer running or requiring that check over relying only on static review.
- Failure of a verification check tied to a reviewed consumer compatibility entry should block activation by default.
- An unavailable or unable-to-run compatibility verification check should also block activation by default when the check is required for a reviewed consumer compatibility entry.
- Capability reports should distinguish compatibility verification failure from an unavailable compatibility verification check because remediation differs.
- When a required compatibility verification check is unavailable, workflows should offer retry or refinement before offering scoped risk acceptance.
- Compatibility verification failure or an unavailable required compatibility check may be overridden only by explicit scoped risk acceptance.
- The first equipment migration implementation should treat consumer compatibility entries as proposed by preflight and reviewed by the operator before becoming durable authority.
- Later auto-review may be appropriate for deterministic consumer compatibility contracts, but should require explicit policy and validation support.
- Reviewed consumer compatibility entries should be changed through append-and-supersede rather than silent in-place editing.
- Capability reports should use non-superseded reviewed consumer compatibility entries by default.
- Consumer compatibility should be reported as part of capability reporting at first.
- A dedicated compatibility report can be added later if consumer compatibility output outgrows the capability report.
- A reviewed consumer compatibility entry can block Fork Ops activation when activation would violate the preserved compatibility contract.
- Compatibility-driven activation blocks should be reported separately from equipment ownership conflicts and missing Replacement Coverage.
- A compatibility-driven activation block may be overridden only by explicit operator risk acceptance after disclosing the affected consumer contract and likely breakage.
- Compatibility override risk acceptance should be scoped to the affected consumer contract and activation decision.
- Compatibility override risk acceptance should be per-run by default.
- Persistent compatibility override risk acceptance should require explicit scope, disclosure summary, operator acceptance, and review freshness policy.
- A compatibility override should not delete or supersede the consumer compatibility entry unless the operator also reviews a replacement or removal of that compatibility contract.
- Equipment disposition entries handle owner, activation, migration, retention, discard, shadow, advisory, or defer decisions.
- A separate review or apply step should record reviewed equipment dispositions, risk acceptances, and durable equipment review record entries.
- A review or apply step that writes equipment review records or control-surface projections should be dry-run-default and offer replayable wet-run execution after review.
- A non-mutating review step may return proposed TOML without creating a replayable wet-run artifact.
- Equipment migration should write an equipment review record once the operator sets onboarding intent, accepts skipped or inconclusive consequences, accepts an unscanned-equipment exception, or assigns group or facet dispositions.
- The first durable equipment review record should use structured TOML and may be accompanied by generated narrative output for operator review.
- Repo-local equipment review records should default to `docs/agents/fork-ops-equipment-review.toml`.
- Equipment review records should require `artifact_kind = "equipment_review"` as a TOML discriminator.
- Equipment review records should use `schema_version` for their own schema family, independent from the `.agents/fork-ops.toml` config schema family.
- Equipment review record schema changes should not imply active Fork Ops config migrations.
- Equipment review records may be authoritative for reviewed equipment dispositions and risk acceptances.
- Machine-actionable equipment activation, disable, or redirect behavior requires projection into Fork Ops config or another explicit control surface before behavior changes.
- Equipment review records should store both an operator-facing display label and an **Equipment Identifier** for each reviewed equipment item or facet when a stable identifier can be derived.
- Equipment identifiers should prefer discovery scope plus path, source URI, plugin or skill identity, command name, config key, or other stable source identity over mutable display text.
- Equipment identifiers should be visible namespaced strings rather than opaque generated IDs.
- Example equipment identifier shapes include `repo-local:path:.agents/foo.md`, `user-global:skill:grill-with-docs`, and `known-plugin-cache:plugin:fork-ops`.
- Equipment review records should preserve previous equipment identifiers as aliases when Fork Ops has evidence that moved or renamed equipment is the same equipment.
- Previous equipment identifiers support traceability and should not be used to infer identity without supporting evidence.
- Discovery-only findings become durable decisions only when captured in the relevant review artifact, follow-up record, config, or tracker.
- An equipment intent preflight may assign a group-level disposition or defer a group to item-by-item disposition.
- Decide-later and item-by-item are distinct equipment intent outcomes: decide-later defers activation or replacement, while item-by-item continues detailed classification.
- Equipment review records may record dispositions at equipment-item level and equipment-facet level.
- Proposed equipment disposition entries may be edited during preflight before review.
- Reviewed equipment disposition entries should be changed through append-and-supersede rather than silent in-place editing.
- Superseded equipment disposition entries should remain traceable when activation, risk acceptance, retained ownership, or conflict resolution depended on them.
- New entries that supersede reviewed disposition, consumer compatibility, follow-up blocker relationship, or evidence entries should identify the old entries with a `supersedes` field when practical.
- Superseded reviewed disposition, consumer compatibility, follow-up blocker relationship, or evidence entries should identify the newer entries with a `superseded_by` field when practical.
- Updating `superseded_by` on an old reviewed entry is a lifecycle metadata update, not an in-place edit to the reviewed decision or evidence content.
- Capability reports should derive current activation, continuity, conflict, and coverage claims from non-superseded reviewed entries by default.
- Superseded entries should be used for audit history or change explanations, not current-state derivation, unless a workflow explicitly asks for historical analysis.
- Supersede fields and validation should be available for the first equipment migration that writes reviewed entries.
- Automated supersede maintenance should be picked up shortly after the first equipment migration, but should not gate that first migration.
- Equipment review records should distinguish the disposition value from the **Equipment Decision Status**.
- A disposition value names the intended equipment handling, such as migrate, retain, discard, shadow, advisory, or defer.
- A shadow disposition means the operator wants Fork Ops to run beside retained authoritative equipment for comparison or confidence-building.
- An advisory disposition means the operator wants Fork Ops to provide non-authoritative guidance, diagnostics, plans, or warnings without shadowing retained authoritative equipment.
- A shadow activation state means a Fork Ops capability is currently running in parallel confidence-building mode beside retained authoritative equipment.
- An advisory activation state means a Fork Ops capability is currently non-authoritative and non-mutating without parallel shadowing.
- Equipment review records should store dispositions, projection targets, and evidence references rather than manual activation-state decisions.
- Equipment review records may store intended projection targets before those projections exist.
- Projection targets can include Fork Ops config, hook config, retained equipment config, global skill config, another explicit control surface, or no projection.
- A projection target in an equipment review record records intended projection, not verified activation.
- `projection_target = "none"` means the reviewed disposition is intentionally durable decision state without a corresponding control-surface projection.
- Dispositions such as discard, defer, and advisory may use no projection when the decision itself is the intended durable outcome.
- A no-projection decision is not a missing implementation by itself, but capability reports should still derive activation limits from it.
- Equipment review record entries should include evidence references when the disposition affects activation, conflict resolution, Replacement Coverage, Operational Continuity, or risk acceptance.
- Evidence references in equipment review record entries should point to structured **Equipment Evidence Entries**, not free-form evidence strings.
- Equipment evidence entries should have stable IDs and record source type, source path or URI, fact type, optional summary, and freshness or invalidation information when needed.
- Equipment evidence source types should be controlled and extensible.
- Built-in equipment evidence source types may include file, skill, plugin, command_output, config, and operator_statement.
- Custom or extension equipment evidence source types should use an extension namespace and should not carry special semantics unless Fork Ops understands them.
- Operator-statement evidence can support operator intent and explicit risk acceptance.
- Operator-statement evidence should not by itself support factual claims about equipment behavior, such as trigger mode or capability ownership.
- Factual equipment-behavior claims should use scan evidence, parsed source evidence, command output, or an explicit accepted-risk path when only operator statement is available.
- Equipment evidence entries should use controlled fact types for tool reasoning and optional prose summaries for operator readability.
- Equipment evidence fact types should be extensible but validated.
- Known equipment evidence fact types may carry first-class semantics for activation, coverage, continuity, conflict, and risk claims.
- Built-in Fork Ops equipment evidence fact types may use plain controlled names.
- Custom or extension equipment evidence fact types should use an extension namespace to avoid collisions with future built-in names.
- Unknown or extension equipment evidence fact types may be preserved for readability and future use, but should not support activation, Replacement Coverage, Operational Continuity, conflict resolution, or risk-acceptance claims until Fork Ops understands their semantics.
- Reviewed low-impact advisory or defer dispositions may reference unknown extension fact types when those facts are not used for activation, coverage, continuity, conflict, or risk claims.
- Validation should warn when unknown extension fact types are preserved but ignored for semantic claims.
- Source hashes, timestamps, and similar source snapshot fields should live in equipment evidence entries and replay evidence snapshots, not duplicated across disposition entries.
- Proposed equipment evidence entries may be edited during preflight before they support reviewed decisions.
- Equipment evidence entries referenced by reviewed dispositions or risk acceptances should be corrected through append-and-supersede rather than in-place editing.
- Superseded or invalid equipment evidence entries should remain traceable for auditability.
- Validation should fail closed when a current reviewed disposition that affects activation, conflict resolution, Replacement Coverage, Operational Continuity, or risk acceptance references missing, superseded, or invalid evidence.
- Validation should warn, not block, when low-impact advisory or defer entries omit optional evidence.
- Free-form strings may appear in rationale fields but should not be the primary evidence link for activation, coverage, continuity, conflict, or risk claims.
- Evidence references are optional but recommended for low-impact advisory or defer decisions that do not affect activation, coverage, continuity, conflict resolution, or risk acceptance claims.
- Capability reports should derive activation state from reviewed dispositions, config or control-surface projection, retained-owner evidence, and unassessed areas.
- Reports should keep derived activation state separate from disposition, such as `disposition = "shadow"` and `activation_state = "shadow"`.
- Equipment decision statuses commonly include proposed, reviewed, blocked, and superseded.
- Equipment risk acceptance should be recorded separately from equipment decision status.
- Risk-dependent reviewed decisions should include the accepted risk scope, disclosure summary, operator acceptance, and review freshness policy when future agents may rely on them.
- Proposed dispositions may guide preflight but should not authorize activation, conflict resolution, or Replacement Coverage claims.
- Reviewed dispositions may authorize later projection into config or another explicit control surface when normal gates pass and any required risk acceptance is recorded.
- A reviewed defer disposition blocks overlapping Fork Ops activation by default because replacement, retention, or discard has not been decided.
- Deferred overlapping behavior may remain available only in Shadow Mode, Advisory Mode, or another non-mutating state until resolved.
- Defer dispositions block the overlapping Fork Ops capability, not unrelated Fork Ops capabilities.
- Item-level equipment dispositions apply to homogeneous equipment and provide defaults for facets without a more specific disposition.
- Facet-level equipment dispositions override item-level dispositions for mixed equipment.
- Activation, conflict resolution, and Replacement Coverage should use the most specific applicable reviewed equipment disposition.
- Group-level equipment disposition guides migration preflight, but **Equipment Facet** disposition controls activation, conflict resolution, and Replacement Coverage unless the group is homogeneous.
- Group-level equipment dispositions should be written to an equipment review record only when they are reviewed operator decisions for a homogeneous group or a deliberate group default.
- Presentation-only equipment groups should remain report structure, with durable authority recorded in the resulting item-level or facet-level dispositions.
- Discovered equipment facets are candidate facets until reviewed by the operator or validated by deterministic structure.
- Deterministic facet validation requires explicit structure such as a config key, single-purpose trigger, named command, labeled section, or machine-readable activation control.
- Plain prose can suggest candidate facets but should not validate facet boundaries by itself.
- Equipment classification confidence commonly distinguishes clear, likely, unclear, and conflicting classifications.
- Equipment classification confidence should support progressive disclosure, with unclear and conflicting classifications expanded before clear groups.
- **Source Material Disposition** feeds lower-level material findings into **Equipment Migration**.
- **Equipment Disposition** decides how prior equipment or equipment facets are handled during **Equipment Migration**.
- Machine-actionable equipment activation, disable, or redirect decisions belong in Fork Ops config or another explicit control surface.
- Equipment disposition rationale, deferred choices, item-by-item decisions, and operator review notes belong in an equipment review record when they are substantial or cross-cutting.
- User-global equipment decisions may need a global equipment migration record outside the maintained fork.
- Equipment review records may be repo-local or global according to the scope of the equipment decisions.
- Repo-local equipment review records may reference global equipment decisions but should not duplicate or own them.
- Fork Ops config may reference user-global equipment as an external owner, redirect target, compatibility dependency, or retained risk, but does not own or mutate that global equipment.
- Shadow Mode can coexist with retained ownership only when the retained owner remains authoritative and Fork Ops output is comparative, non-mutating, and unable to activate replacement.
- Advisory Mode can coexist with retained ownership when Fork Ops output is non-authoritative, non-mutating, and not presented as parallel behavior verification.
- Shadow Mode requires a retained authoritative owner for Fork Ops to compare against.
- Advisory Mode does not require a retained authoritative owner.
- Equipment migration should be exposed as a distinct Fork Ops workflow and may be a prerequisite for fork authority migration when existing equipment overlaps Fork Ops capabilities.
- Migration closeout should offer to project discovered follow-up candidates into the issue tracker immediately after migration completes.
- Migration closeout should offer both required or blocking and optional team-wide follow-ups for issue projection, grouped by impact.
- Required or blocking follow-up projection should be emphasized; optional follow-up projection should be easy to skip.
- Skipped optional team-wide follow-up projection should keep the follow-up candidate durable until the operator explicitly discards it.
- Skipping issue projection should mean not now, not forget this, unless the operator chooses discard.
- Migration closeout may offer explicit discard for optional follow-up candidates, but discard should not be the default option.
- Discarding an optional follow-up candidate should recommend a short reason, especially when the candidate came from reviewed evidence, but the reason should not be required.
- Discarded follow-up candidates should remain minimally traceable when they came from reviewed evidence or were blockers.
- Minimal discard traceability should include follow-up ID, title, discard time, optional reason, and source references when already reviewed.
- Purely session-local optional suggestions do not need full discard retention.
- User-specific durable follow-ups in a **User Follow-up Registry** should follow the same discard traceability rule.
- Optional user-specific suggestions can disappear when they were never written to durable user follow-up storage.
- The first Fork Ops equipment migration slice should specify the **User Follow-up Registry** contract without building full generic registry tooling unless required user-specific follow-ups are in scope.
- If required user-specific follow-ups are in scope, the first slice needs at least a minimal fallback **User Follow-up Registry** writer.
- Full generic **User Follow-up Registry** tooling belongs in later Agent Armory or Repo Ops work.
- Migration closeout should distinguish Replacement Coverage, Operational Continuity, and follow-up candidates.
- If issue-tracker equipment is unavailable, migration closeout should offer to set it up when an appropriate Agent Armory Issue Tracker Ops path exists.
- Fork Ops should route issue-tracker setup to Agent Armory Issue Tracker Ops rather than owning generic issue-tracker onboarding.
- Follow-up candidates should remain in a durable follow-up record until they are projected into the appropriate tracker or durable follow-up home.
- Follow-up candidates should declare their **Follow-up Audience Scope**.
- Team-wide equipment activation follow-ups should be offered for projection into the team or repo issue tracker.
- User-specific activation follow-ups should not pollute team or repo trackers by default.
- User-specific activation follow-ups need a durable and discoverable user-specific home.
- A centralized user-specific tracker is preferred when configured.
- User-specific activation follow-ups should prefer a generic **User Follow-up Registry** over a Fork Ops-specific user store.
- Fork Ops follow-ups in a generic **User Follow-up Registry** should be namespaced to Fork Ops.
- When no user-specific tracker preference is configured, Fork Ops should fall back to the well-known user-global agents-subpath follow-up home as a generic **User Follow-up Registry** location.
- The operator may configure a preferred user-specific follow-up home or abort the process, but should not be offered a non-durable decline path for required user-specific follow-up tracking.
- When fallback to the well-known **User Follow-up Registry** is used, Fork Ops may initialize its namespace automatically as part of writing a required user-specific follow-up.
- Optional user-specific follow-ups should be offered for durable tracking but should not be written automatically to the fallback **User Follow-up Registry**.
- Optional user-specific follow-ups may remain in the session closeout summary when the operator does not opt into durable tracking during that flow.
- Workflow-scoped follow-up candidates should be recorded in the relevant review artifact or follow-up record; broader follow-up records may use a separate in-repo tracker file.
- Equipment review records may reference follow-up candidates by ID or tracker reference.
- Equipment review records should not store full follow-up bodies unless they are the only durable home for those candidates.
- Follow-up records own follow-up candidate body and general status.
- Equipment review records own relationships between referenced follow-up candidates and equipment decisions, capabilities, workflows, or blocker scope.
- Reviewed follow-up blocker relationships should fail validation when the referenced follow-up candidate or tracker item cannot be resolved.
- Follow-up validation should distinguish a missing referenced follow-up from unavailable tracker connectivity.
- Unavailable tracker connectivity should produce an unavailable or inconclusive reference state rather than treating the follow-up as missing.
- Activation may still fail closed when an unavailable referenced follow-up affects a current blocker claim, but remediation should be reconnect or retry rather than recreating the follow-up.
- Referenced follow-up candidates are blockers only when the referencing entry explicitly marks a capability or workflow blocker relationship.
- Follow-up blocker relationships should name affected workflows, affected capability levels, or both.
- Follow-up blocker relationships block only the named workflow or capability scope.
- Follow-up blocker relationships should declare whether scoped risk-acceptance override is allowed.
- Risk-based follow-up blockers may allow scoped risk-acceptance override after explicit disclosure.
- Follow-up blockers for missing required implementation, missing authority, or absent capability should not be overrideable by risk acceptance.
- Override eligibility for durable reviewed blocker relationships should itself be reviewed by the operator or backed by explicit policy.
- Proposed blocker relationships may suggest override eligibility, but should not authorize risk acceptance until reviewed or policy-backed.
- Reviewed follow-up blocker relationships should be changed through append-and-supersede rather than silent in-place editing.
- Capability reports should use non-superseded reviewed follow-up blocker relationships by default.
- Follow-up candidates may be informational, optional, or required; blocker status should not be inferred from the mere existence of a follow-up reference.
- Fork Ops config may reference a follow-up record but should not store the follow-up body.
- Untracked follow-up reminders should appear only when unresolved follow-up candidates exist and should use terse summaries plus the benefit of tracking or resolving them.
- Follow-up reminder surfaces may include workflow preambles, hooks, capability report pointers, plugin health pointers, or a separate follow-up report depending on harness support.
- Follow-up reminders should be relevance-gated to workflow boundaries where the unresolved candidates matter, unless the harness cannot implement that within the token-overhead constraint.
- Proactive follow-up reminders are later harness-dependent work; durable follow-up records and migration closeout offers come first.
- Unresolved auto-triggerable **Fork Ops Capability Conflict** blocks safe onboarding.
- Explicit-only conflicting equipment can remain as an operator-discretion path when the harness enforces explicit-only activation, but it should be reported as a warning or retained risk rather than treated as absent.
- Unknown trigger mode should be treated as potentially auto-triggerable and should block overlapping activation until clarified.
- User-global existing equipment needs a scope decision before repo-local Fork Ops onboarding treats it as safe to edit, remove, or ignore.
- User-global existing equipment used by multiple repos should not be globally edited, removed, or disabled during repo-local onboarding; overlapping behavior needs repo-local avoidance, redirection, guardrails, deferment, or a separate global equipment migration.
- Repo-local onboarding should not change user-global trigger behavior unless the operator explicitly authorizes that global equipment migration in-session.
- An unresolved equipment conflict blocks the overlapping Fork Ops capability, not unrelated Fork Ops capabilities.
- **Fork Ops Config** is part of a **Maintained Fork**'s **Fork-local Authority**.
- **Fork Ops Config** determines one or more **Fork Ops Capability Levels**.
- A **Capability Report** owns the current coverage status for a configured **Maintained Fork**.
- Capability reports may remain command output by default.
- Capability report content should persist as durable evidence when another workflow relies on it for blocker clearance, replay, reviewed claims, or traceability.
- Durable capability-report evidence should live in the relying artifact rather than forcing report-file churn by default.
- A **Capability Report** should distinguish authority/config readiness from **Activation Readiness**.
- **Activation Readiness** is reported per Fork Ops capability, with workflow and equipment-facet evidence behind the capability status.
- Activation readiness commonly distinguishes active, shadow, advisory, redirected, disabled, blocked, unassessed, and not-implemented capability states.
- Capability reports should surface relevant **Unassessed Equipment Areas** when they limit activation-readiness or Replacement Coverage claims.
- Capability reports should surface reviewed consumer compatibility entries that constrain current or future Fork Ops behavior.
- A **Capability Report** may report Shadow Mode for a capability whose Fork Ops workflow can compare against retained authoritative equipment.
- A **Capability Report** may report Advisory Mode for a capability whose Fork Ops workflow can advise but not own activation.
- A **Migration Plan** consumes **Capability Report** coverage status when deciding whether source-material behavior is replaceable.
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
- A **Migration Plan** should claim **Replacement Coverage** only when equivalent Fork Ops behavior exists, validates at the required capability level, and reports any retained authority that remains.
- **Replacement Coverage** requires a named current **Fork Ops Workflow** or config policy shape, a satisfied **Fork Ops Capability Level**, **Activation Readiness**, and output that distinguishes covered behavior from retained authority.
- **Replacement Coverage** requires Fork Ops-owned active behavior; redirected retained-owner behavior can make operation safe but does not establish Fork Ops Replacement Coverage.
- **Operational Continuity** can be satisfied by Fork Ops active behavior or a retained authoritative owner.
- Redirected retained-owner behavior can satisfy **Operational Continuity** when the retained owner is verified and the redirect is active.
- Redirected retained-owner continuity should be attributed to the retained authoritative owner and active redirect, not to Fork Ops Replacement Coverage.
- When Shadow Mode coexists with **Operational Continuity**, the continuity should be attributed to the retained authoritative owner rather than to Fork Ops shadow output.
- Advisory Mode output does not satisfy **Operational Continuity** by itself.
- **Operational Continuity** does not authorize source-material removal.
- **Replacement Coverage** applies to source-material behavior, not to entire files or whole workflows.
- Config representation preserves authority in machine-readable form but does not establish **Replacement Coverage** until current Fork Ops behavior consumes and validates it.
- Planned and next-slice workflows do not establish **Replacement Coverage**.
- Diagnostic-only workflows establish **Replacement Coverage** only for diagnostic behavior, not for mutation or repair behavior.
- Shadow Mode and Advisory Mode output do not establish **Replacement Coverage** by themselves.
- Source material with both covered and uncovered behavior remains retained authority until every behavior is covered, excluded, or deferred through reviewed disposition.
- A **Migration Plan** should include a migration map.
- A migration review artifact can preserve durable fork authority migration decisions that are not machine-actionable config.
- A migration review artifact primarily carries decision state and supporting evidence state for fork authority migration.
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
- "installed skill" does not say whether the skill is used, intended to remain in use, or safe to remove. Treat those as separate questions about **Existing Fork Ops Equipment**.
- "compatibility" can mean preserving a consumer integration, retaining a foreign owner, or redirecting one equipment surface to another. Name the specific relationship before claiming compatibility.
- "generic repo ops" is future equipment, not a current dependency. Mark reusable surfaces as **Repo Ops Candidates** without blocking Fork Ops foundation work.
- "repo-ops candidate" appears both as a concept and as a classification. Use **Repo Ops Candidate** for the concept and **Repo-ops Candidate** for the classification value.
- **Portability Hints** are not normative. Do not use them to block implementation or override current Fork Ops requirements.
- Capability levels describe workflow readiness and refusal boundaries, not whether a fork is well maintained.
- Workflow migration defines reusable Fork Ops plugin behavior before fork authority migration maps a specific maintained fork into that behavior.
- A workflow migration inventory informs the workflow catalog.
- Equipment migration handles prior operational equipment during onboarding after reusable behavior and fork-local authority are understood.
- Equipment migration is the next workflow slice after the foundation migration work because production onboarding should not activate overlapping behavior before prior equipment conflicts are resolved.
- The first equipment migration slice should be an equipment migration preflight without equipment edits, disabling, or removal.
- Equipment migration is dry-run-default because equipment ownership and activation changes are situational and can affect future auto-trigger behavior.
- Fork authority migration is dry-run-default because source-material and authority changes are varied and can be hard to reverse.
- Upstream sync execution should be wet-run-default once implemented, with dry-run mode available and mutation gates controlling the predictable sync sequence.
- Publication closeout should be wet-run-default once implemented, with readiness preview available and policy gates controlling push, review, merge, and cleanup steps.
- Workflow migration, fork authority migration, and equipment migration are distinct tracks; do not use one track's evidence as automatic completion for another.
- **Migration Assessment** is not a promise that Fork Ops can safely migrate the material yet.
- **Replacement Coverage** is not established by workflow catalog evidence, config creation, or a retained source material decision by itself.
- A source material item can contain both **Covered Behavior** and retained authority; do not classify the whole item as replaceable from partial coverage.
- Incomplete semantic coverage is a review state that should be resolved through source material disposition, not a hard dead end by itself.
- Incomplete semantic coverage should block replacement or deletion of source material, not safe config creation that explicitly preserves the source material as retained authority.
- **Mutation Gates** are policy preconditions. Their implementation surface can vary by harness.
