"""Intent-level Fork Ops workflow catalog."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Literal

ImplementationStatus = Literal["current", "diagnostic-only", "next-slice", "planned"]
_AVAILABLE_STATUSES: frozenset[ImplementationStatus] = frozenset(
    {"current", "diagnostic-only"}
)


@dataclass(frozen=True)
class WorkflowEntrypoint:
    kind: str
    id: str
    label: str
    surface: str

    def to_dict(self) -> dict[str, str]:
        return {
            "kind": self.kind,
            "id": self.id,
            "label": self.label,
            "surface": self.surface,
        }


@dataclass(frozen=True)
class WorkflowContract:
    id: str
    title: str
    operator_intent: str
    trigger_phrases: tuple[str, ...]
    capability_gate: str
    implementation_status: ImplementationStatus
    available: bool
    authority_reads: tuple[str, ...]
    preflight_checks: tuple[str, ...]
    mutation_gates: tuple[str, ...]
    entrypoints: tuple[WorkflowEntrypoint, ...]
    evidence_expectations: tuple[str, ...]
    refusal_behavior: str
    handoff_expectations: tuple[str, ...]
    closeout_criteria: tuple[str, ...]

    def __post_init__(self) -> None:
        if self.available and self.implementation_status not in _AVAILABLE_STATUSES:
            raise ValueError(
                f"Workflow {self.id!r}: available=True requires implementation_status in "
                f"{_AVAILABLE_STATUSES!r}, got {self.implementation_status!r}"
            )

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "title": self.title,
            "operator_intent": self.operator_intent,
            "trigger_phrases": list(self.trigger_phrases),
            "capability_gate": self.capability_gate,
            "implementation_status": self.implementation_status,
            "available": self.available,
            "authority_reads": list(self.authority_reads),
            "preflight_checks": list(self.preflight_checks),
            "mutation_gates": list(self.mutation_gates),
            "entrypoints": [entrypoint.to_dict() for entrypoint in self.entrypoints],
            "evidence_expectations": list(self.evidence_expectations),
            "refusal_behavior": self.refusal_behavior,
            "handoff_expectations": list(self.handoff_expectations),
            "closeout_criteria": list(self.closeout_criteria),
        }


_CATALOG_ENTRYPOINT = WorkflowEntrypoint(
    kind="cli",
    id="fork-ops workflow catalog",
    label="Print the Fork Ops workflow catalog.",
    surface="fork-ops workflow catalog",
)

_MCP_CATALOG_ENTRYPOINT = WorkflowEntrypoint(
    kind="mcp",
    id="fork_ops_workflow_catalog",
    label="Return the Fork Ops workflow catalog to MCP clients.",
    surface="MCP tool",
)

_CATALOG_ENTRYPOINTS = (_CATALOG_ENTRYPOINT, _MCP_CATALOG_ENTRYPOINT)


WORKFLOW_CONTRACTS: tuple[WorkflowContract, ...] = (
    WorkflowContract(
        id="operator-onboarding",
        title="Operator onboarding",
        operator_intent=(
            "Verify Fork Ops plugin health and catalog visibility before using the plugin "
            "on a maintained fork."
        ),
        trigger_phrases=(
            "show me what fork ops can do",
            "verify fork ops is installed",
            "operator onboarding",
        ),
        capability_gate="plugin-health",
        implementation_status="current",
        available=True,
        authority_reads=("plugin registration", "skill discovery", "CLI and MCP surfaces"),
        preflight_checks=(
            "Check plugin registration.",
            "Check skill discovery.",
            "Check CLI execution.",
            "Check MCP config, startup, and tool listing.",
            "Report UI visibility only when an inspection surface exists.",
        ),
        mutation_gates=("No repository mutation is allowed during onboarding diagnostics.",),
        entrypoints=(
            WorkflowEntrypoint(
                kind="cli",
                id="fork-ops plugin health",
                label="Report independent Fork Ops plugin readiness paths.",
                surface="fork-ops plugin health",
            ),
            WorkflowEntrypoint(
                kind="mcp",
                id="fork_ops_plugin_health",
                label="Return Fork Ops plugin health diagnostics to MCP clients.",
                surface="MCP tool",
            ),
            _CATALOG_ENTRYPOINT,
            _MCP_CATALOG_ENTRYPOINT,
            WorkflowEntrypoint(
                kind="skill",
                id="fork-ops",
                label="Route natural-language fork operation requests.",
                surface="plugins/fork-ops/skills/fork-ops/SKILL.md",
            ),
        ),
        evidence_expectations=(
            "Independent readiness paths for plugin registration, skill discovery, CLI, "
            "MCP, and UI visibility.",
            "Actionable MCP failure output and CLI fallback guidance when CLI execution works.",
        ),
        refusal_behavior=(
            "Refuse repository mutation during onboarding diagnostics; report unavailable "
            "or uninspectable paths without failing unrelated ready paths."
        ),
        handoff_expectations=(
            "Ask the operator for any missing plugin registration or UI state that the "
            "agent cannot inspect.",
        ),
        closeout_criteria=(
            "Each plugin readiness path is ready, failed, unavailable, or uninspectable.",
            "CLI fallback guidance is reported when MCP or UI surfaces are not usable.",
        ),
    ),
    WorkflowContract(
        id="fork-authority-migration",
        title="Fork authority migration",
        operator_intent=(
            "Map an existing maintained fork's local guidance, config, docs, and skills "
            "into fork-local authority that Fork Ops can read."
        ),
        trigger_phrases=(
            "fork authority migration",
            "migrate this fork into fork ops",
            "generate a fork ops config",
        ),
        capability_gate="identified",
        implementation_status="current",
        available=True,
        authority_reads=(
            ".agents/fork-ops.toml when present",
            "candidate fork-local agent docs and skills",
            "Git remotes and configured upstream tracks",
        ),
        preflight_checks=("Assess candidate source materials.", "Validate generated config."),
        mutation_gates=(
            "Migration execution only creates .agents/fork-ops.toml when the dry-run "
            "preview has no blockers.",
            "Retained source material must remain present and unchanged.",
        ),
        entrypoints=(
            WorkflowEntrypoint(
                kind="cli",
                id="fork-ops migration assess",
                label="Assess existing fork-related source materials.",
                surface="fork-ops migration assess",
            ),
            WorkflowEntrypoint(
                kind="cli",
                id="fork-ops migration preflight",
                label="Build a read-only equipment migration preflight.",
                surface="fork-ops migration preflight",
            ),
            WorkflowEntrypoint(
                kind="cli",
                id="fork-ops migration plan",
                label="Generate a non-mutating migration plan.",
                surface="fork-ops migration plan",
            ),
            WorkflowEntrypoint(
                kind="cli",
                id="fork-ops migration dry-run",
                label="Preview migration plan effects without edits.",
                surface="fork-ops migration dry-run",
            ),
            WorkflowEntrypoint(
                kind="cli",
                id="fork-ops migration execute",
                label="Apply guarded config creation when the dry-run preview has no blockers.",
                surface="fork-ops migration execute",
            ),
            WorkflowEntrypoint(
                kind="cli",
                id="fork-ops migration propose-config",
                label="Generate a non-mutating Fork Ops config proposal.",
                surface="fork-ops migration propose-config",
            ),
            WorkflowEntrypoint(
                kind="mcp",
                id="fork_ops_migration_assessment",
                label="Assess existing fork-related source materials for MCP clients.",
                surface="MCP tool",
            ),
            WorkflowEntrypoint(
                kind="mcp",
                id="fork_ops_equipment_migration_preflight",
                label="Return an equipment migration preflight to MCP clients.",
                surface="MCP tool",
            ),
            WorkflowEntrypoint(
                kind="mcp",
                id="fork_ops_migration_plan",
                label="Return a non-mutating migration plan to MCP clients.",
                surface="MCP tool",
            ),
            WorkflowEntrypoint(
                kind="mcp",
                id="fork_ops_migration_dry_run",
                label="Preview migration plan effects for MCP clients.",
                surface="MCP tool",
            ),
            WorkflowEntrypoint(
                kind="mcp",
                id="fork_ops_migration_execute",
                label="Apply guarded config creation for MCP clients.",
                surface="MCP tool",
            ),
            WorkflowEntrypoint(
                kind="mcp",
                id="fork_ops_migration_config_patch",
                label="Generate a non-mutating config proposal for MCP clients.",
                surface="MCP tool",
            ),
        ),
        evidence_expectations=(
            "source material disposition and retained-authority evidence",
            "proposed config diagnostics and capability evidence",
            "dry-run file edit preview before mutation",
        ),
        refusal_behavior=(
            "Refuse replacement, deletion, or arbitrary migration edits; explain blockers "
            "and retain source material until replacement coverage exists."
        ),
        handoff_expectations=(
            "Request a concrete retain, exclude, defer, needs-human-decision, or "
            "unsupported-extractor decision when source material disposition is ambiguous.",
        ),
        closeout_criteria=(
            "Config creation is applied only when the dry-run preview has no blockers.",
            "Reviewed retain decisions can resolve semantic coverage for config creation.",
            "Retained authority remains preserved and validation evidence is reported.",
        ),
    ),
    WorkflowContract(
        id="workflow-migration-inventory",
        title="Workflow migration inventory",
        operator_intent=(
            "Scout reusable fork-workflow materials and map them to workflow catalog "
            "coverage evidence without changing source roots."
        ),
        trigger_phrases=(
            "workflow migration inventory",
            "inventory fork workflow materials",
            "map skills to the workflow catalog",
        ),
        capability_gate="plugin-health",
        implementation_status="diagnostic-only",
        available=True,
        authority_reads=("operator-provided source roots", "workflow catalog contracts"),
        preflight_checks=("Confirm source roots are readable.", "Classify source material."),
        mutation_gates=("No source root mutation is allowed during inventory reporting.",),
        entrypoints=(
            WorkflowEntrypoint(
                kind="cli",
                id="fork-ops workflow inventory",
                label="Build a read-only workflow migration inventory.",
                surface="fork-ops workflow inventory",
            ),
            WorkflowEntrypoint(
                kind="mcp",
                id="fork_ops_workflow_migration_inventory",
                label="Return workflow migration inventory evidence to MCP clients.",
                surface="MCP tool",
            ),
        ),
        evidence_expectations=(
            "source kind, material scope, candidate operator intent, and coverage status",
            "line-level evidence references that do not duplicate source text",
            "backlog candidates separated from implemented workflow availability",
        ),
        refusal_behavior=(
            "Refuse to treat backlog candidates as available workflows or to replace "
            "fork-local authority based on inventory reporting alone."
        ),
        handoff_expectations=(
            "Ask for additional source roots when the inventory scope is incomplete.",
            "Ask for product-owner review before converting backlog candidates into catalog work.",
        ),
        closeout_criteria=(
            "Inventory entries are grouped by catalog target or backlog candidate.",
            "No source root was modified.",
        ),
    ),
    WorkflowContract(
        id="authority-source-routing",
        title="Authority and source routing explanation",
        operator_intent="Explain where fork-local authority comes from before selecting tools.",
        trigger_phrases=("where should fork ops read from", "explain authority routing"),
        capability_gate="identified",
        implementation_status="diagnostic-only",
        available=True,
        authority_reads=(".agents/fork-ops.toml", "local_surfaces", "repo docs"),
        preflight_checks=("Read config when present.", "List required local surfaces."),
        mutation_gates=("No mutation is allowed for authority explanation.",),
        entrypoints=(
            WorkflowEntrypoint(
                kind="cli",
                id="fork-ops config show",
                label="Show normalized fork-local config.",
                surface="fork-ops config show --format json",
            ),
            WorkflowEntrypoint(
                kind="doc",
                id="operation-guide",
                label="Document authority-first operation routing.",
                surface="plugins/fork-ops/docs/operation-guide.md",
            ),
        ),
        evidence_expectations=("Config path, local surfaces, and diagnostics.",),
        refusal_behavior=(
            "Refuse to infer fork policy from plugin defaults when authority is missing."
        ),
        handoff_expectations=("Ask for the missing fork-local authority surface when required.",),
        closeout_criteria=("Authority order and missing surfaces are named.",),
    ),
    WorkflowContract(
        id="upstream-status-assessment",
        title="Upstream status assessment",
        operator_intent="Assess configured remotes and upstream tracks without changing refs.",
        trigger_phrases=("assess upstream status", "check upstream tracks"),
        capability_gate="track-aware",
        implementation_status="diagnostic-only",
        available=True,
        authority_reads=("configured remotes", "release channels", "upstream tracks"),
        preflight_checks=("Validate config.", "Inspect local Git remotes and refs."),
        mutation_gates=("No fetch, push, merge, or ref update is performed.",),
        entrypoints=(
            WorkflowEntrypoint(
                kind="cli",
                id="fork-ops capability report",
                label="Report capability and local Git diagnostics.",
                surface="fork-ops capability report",
            ),
            WorkflowEntrypoint(
                kind="mcp",
                id="fork_ops_capability_report",
                label="Return capability evidence to MCP clients.",
                surface="MCP tool",
            ),
        ),
        evidence_expectations=("Capability levels, diagnostics, and configured track refs.",),
        refusal_behavior=(
            "Refuse sync conclusions when track-aware authority or Git evidence is missing."
        ),
        handoff_expectations=(
            "Ask the operator which upstream track to inspect when config is ambiguous.",
        ),
        closeout_criteria=("Highest available capability and blocking diagnostics are reported.",),
    ),
    WorkflowContract(
        id="upstream-sync-planning",
        title="Upstream sync planning",
        operator_intent="Plan a safe upstream sync path without executing it.",
        trigger_phrases=("plan an upstream sync", "prepare sync plan"),
        capability_gate="sync-ready",
        implementation_status="next-slice",
        available=False,
        authority_reads=("sync_policy", "divergence_policy", "upstream tracks"),
        preflight_checks=("Validate sync-ready authority.", "Compare configured baseline refs."),
        mutation_gates=("Planning is non-mutating; execution remains separate.",),
        entrypoints=_CATALOG_ENTRYPOINTS,
        evidence_expectations=("Baseline comparison evidence and required mutation gates.",),
        refusal_behavior=(
            "Refuse to present a sync plan as implemented until sync planning has a "
            "contract-backed planner."
        ),
        handoff_expectations=("Ask for the intended baseline or policy exception when missing.",),
        closeout_criteria=("A non-mutating plan names gates, blockers, and safe next paths.",),
    ),
    WorkflowContract(
        id="guarded-sync-execution",
        title="Guarded sync execution",
        operator_intent="Execute an upstream sync only after configured mutation gates pass.",
        trigger_phrases=("execute upstream sync", "sync this fork"),
        capability_gate="sync-ready",
        implementation_status="planned",
        available=False,
        authority_reads=("sync_policy", "divergence_policy", "review policy"),
        preflight_checks=("Validate sync-ready authority.", "Verify ancestry and mutation gates."),
        mutation_gates=("History rewrite policy", "allowed merge methods", "required checks"),
        entrypoints=_CATALOG_ENTRYPOINTS,
        evidence_expectations=("Gate results, refs before and after, and merge evidence.",),
        refusal_behavior=(
            "Refuse guarded sync execution because broad upstream sync mutation is not "
            "implemented in the current plugin."
        ),
        handoff_expectations=(
            "Request explicit operator direction for unsupported mutation paths.",
        ),
        closeout_criteria=(
            "Executed refs and validation evidence are reported after implementation exists.",
        ),
    ),
    WorkflowContract(
        id="carried-divergence-review",
        title="Carried divergence review",
        operator_intent="Review fork-carried divergence before a sync or publication decision.",
        trigger_phrases=("review carried divergence", "what does this fork carry"),
        capability_gate="sync-ready",
        implementation_status="planned",
        available=False,
        authority_reads=("divergence_policy", "change targets", "upstream baseline"),
        preflight_checks=("Identify fork-only commits.", "Classify divergence policy."),
        mutation_gates=("No mutation is allowed during divergence review.",),
        entrypoints=_CATALOG_ENTRYPOINTS,
        evidence_expectations=(
            "Commit ranges, classified divergence, and unresolved policy gaps.",
        ),
        refusal_behavior="Refuse to classify carried divergence without an implemented analyzer.",
        handoff_expectations=(
            "Ask for operator classification when divergence policy is insufficient.",
        ),
        closeout_criteria=("Each carried item has a disposition or a named blocker.",),
    ),
    WorkflowContract(
        id="review-preparation",
        title="Review preparation",
        operator_intent="Prepare a fork-local change for review using configured review policy.",
        trigger_phrases=("prepare this for review", "review prep"),
        capability_gate="review-ready",
        implementation_status="planned",
        available=False,
        authority_reads=("review_policy", "local_gates", "publication_policy"),
        preflight_checks=("Run configured local gates.", "Summarize evidence for reviewers."),
        mutation_gates=("No publication mutation occurs during review preparation.",),
        entrypoints=_CATALOG_ENTRYPOINTS,
        evidence_expectations=("Diff summary, validation evidence, and review gate status.",),
        refusal_behavior="Refuse to claim review preparation automation is implemented.",
        handoff_expectations=("Ask for missing review policy or reviewer decision when required.",),
        closeout_criteria=("Validation evidence and review handoff are ready.",),
    ),
    WorkflowContract(
        id="publication-closeout",
        title="Publication closeout",
        operator_intent="Publish or close out fork-local changes after review gates pass.",
        trigger_phrases=("publish this fork change", "close out publication"),
        capability_gate="review-ready",
        implementation_status="planned",
        available=False,
        authority_reads=("publication_policy", "review_policy", "local_gates"),
        preflight_checks=("Verify review state.", "Verify publication target and merge policy."),
        mutation_gates=("Review approval", "CI state", "allowed merge methods"),
        entrypoints=_CATALOG_ENTRYPOINTS,
        evidence_expectations=("Review state, publication target, and final merge/push evidence.",),
        refusal_behavior=(
            "Refuse publication closeout automation because PR publication and closeout are "
            "not implemented in the current plugin."
        ),
        handoff_expectations=(
            "Ask for operator approval when publication policy is absent or blocked.",
        ),
        closeout_criteria=("Published ref, PR, or explicit blocker is recorded.",),
    ),
    WorkflowContract(
        id="blocker-resolution",
        title="Blocker explanation or resolution",
        operator_intent="Explain a Fork Ops blocker and route the smallest safe continuation.",
        trigger_phrases=("explain this blocker", "resolve fork ops blocker"),
        capability_gate="identified",
        implementation_status="diagnostic-only",
        available=True,
        authority_reads=("workflow output", "diagnostics", "fork-local authority"),
        preflight_checks=("Identify blocker code.", "Trace evidence that produced the blocker."),
        mutation_gates=("Resolution mutations use the originating workflow's gates.",),
        entrypoints=(
            WorkflowEntrypoint(
                kind="cli",
                id="fork-ops migration explain-blocker",
                label="Explain a migration blocker from workflow output JSON.",
                surface="fork-ops migration explain-blocker",
            ),
            WorkflowEntrypoint(
                kind="mcp",
                id="fork_ops_migration_blocker_resolution",
                label="Return blocker-resolution output to MCP clients.",
                surface="MCP tool",
            ),
            _CATALOG_ENTRYPOINT,
            _MCP_CATALOG_ENTRYPOINT,
        ),
        evidence_expectations=(
            "Blocker code, source evidence, safe continuations, and next paths.",
        ),
        refusal_behavior=(
            "Refuse unsupported fixes while still explaining evidence and safe next paths."
        ),
        handoff_expectations=(
            "Ask for a concrete operator decision when multiple safe paths exist.",
        ),
        closeout_criteria=("Blocker is resolved, deferred, or routed to a named follow-up.",),
    ),
)


def workflow_contracts() -> tuple[WorkflowContract, ...]:
    return WORKFLOW_CONTRACTS


def workflow_catalog() -> dict[str, Any]:
    workflows = [workflow.to_dict() for workflow in WORKFLOW_CONTRACTS]
    return {
        "operation": "workflow-catalog",
        "model": "intent-led-workflow-contracts",
        # Keep these keys in sync with the ImplementationStatus Literal type.
        "status_values": {
            "current": "Implemented in the plugin's current controlled surfaces.",
            "diagnostic-only": "Implemented only for read-only diagnostics or explanation.",
            "next-slice": "Visible contract for the next implementation slice.",
            "planned": "Planned workflow; visible with refusal boundaries.",
        },
        "workflows": workflows,
    }


__all__ = ["WorkflowContract", "WorkflowEntrypoint", "workflow_catalog", "workflow_contracts"]
