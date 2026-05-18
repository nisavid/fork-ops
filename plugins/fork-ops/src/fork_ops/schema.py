"""Fork Ops config schema and schema validation helpers."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from jsonschema import Draft202012Validator

CAPABILITY_LEVELS = [
    "identified",
    "scoutable",
    "track-aware",
    "sync-ready",
    "review-ready",
    "provenance-ready",
]


CONFIG_SCHEMA: dict[str, Any] = {
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "$id": "https://github.com/nisavid/fork-ops/plugins/fork-ops/schema/fork-ops.schema.json",
    "title": "Fork Ops Config",
    "type": "object",
    "additionalProperties": True,
    "required": [
        "schema_version",
        "repository",
        "fork_remotes",
        "upstreams",
        "authority",
        "change_targets",
    ],
    "properties": {
        "schema_version": {"type": "string", "pattern": r"^[0-9]+\.[0-9]+$"},
        "repository": {
            "type": "object",
            "additionalProperties": True,
            "required": ["host", "owner", "name", "default_branch"],
            "properties": {
                "host": {"type": "string"},
                "owner": {"type": "string"},
                "name": {"type": "string"},
                "default_branch": {"type": "string"},
                "product_site": {"type": "string"},
                "protected_branches": {
                    "type": "array",
                    "items": {"type": "string"},
                    "uniqueItems": True,
                },
            },
        },
        "fork_remotes": {
            "type": "array",
            "minItems": 1,
            "items": {
                "type": "object",
                "additionalProperties": True,
                "required": ["name"],
                "properties": {
                    "name": {"type": "string"},
                    "url": {"type": "string"},
                    "push": {"type": "boolean"},
                    "owner": {"type": "string"},
                    "purpose": {"type": "string"},
                },
            },
        },
        "upstreams": {
            "type": "array",
            "minItems": 1,
            "items": {
                "type": "object",
                "additionalProperties": True,
                "required": ["id", "remote"],
                "properties": {
                    "id": {"type": "string"},
                    "name": {"type": "string"},
                    "owner": {"type": "string"},
                    "remote": {"type": "string"},
                    "url": {"type": "string"},
                    "push_url": {"type": "string"},
                    "docs_url": {"type": "string"},
                    "site_url": {"type": "string"},
                    "default_branch": {"type": "string"},
                    "push": {"type": "boolean"},
                },
            },
        },
        "authority": {
            "type": "object",
            "additionalProperties": True,
            "required": ["source_order"],
            "properties": {
                "source_order": {
                    "type": "array",
                    "minItems": 1,
                    "items": {"type": "string"},
                },
                "upstream_canon": {"type": "string"},
                "inference_labeling": {"type": "string"},
                "escalation_policy": {"type": "string"},
                "required_context_paths": {
                    "type": "array",
                    "items": {"type": "string"},
                    "uniqueItems": True,
                },
                "pre_change_requirements": {
                    "type": "array",
                    "items": {"type": "string"},
                    "uniqueItems": True,
                },
                "durable_discovery_destinations": {
                    "type": "array",
                    "items": {"type": "string"},
                    "uniqueItems": True,
                },
            },
        },
        "change_targets": {
            "type": "object",
            "additionalProperties": True,
            "required": ["default"],
            "properties": {
                "default": {"type": "string", "enum": ["fork", "upstream", "ask"]},
                "upstream_contribution": {"type": "string"},
                "upstream_issues": {"type": "string"},
                "replacement_prs": {"type": "string"},
                "selective_upstreaming": {"type": "string"},
            },
        },
        "release_channels": {
            "type": "array",
            "items": {
                "type": "object",
                "additionalProperties": True,
                "required": ["id", "upstream", "kind"],
                "properties": {
                    "id": {"type": "string"},
                    "upstream": {"type": "string"},
                    "kind": {
                        "type": "string",
                        "enum": [
                            "github_latest_release",
                            "github_latest_prerelease",
                            "github_tag_pattern",
                            "manual",
                        ],
                    },
                    "include_drafts": {"type": "boolean"},
                    "include_prereleases": {"type": "boolean"},
                    "selection_source": {"type": "string"},
                    "tag_pattern": {"type": "string"},
                    "notes": {"type": "string"},
                },
            },
        },
        "upstream_tracks": {
            "type": "array",
            "items": {
                "type": "object",
                "additionalProperties": True,
                "required": ["id", "upstream", "ref", "source_type", "source"],
                "properties": {
                    "id": {"type": "string"},
                    "upstream": {"type": "string"},
                    "ref": {"type": "string"},
                    "role": {"type": "string"},
                    "source_ref": {"type": "string"},
                    "local_branch": {"type": "string"},
                    "tracking_ref": {"type": "string"},
                    "source_type": {
                        "type": "string",
                        "enum": ["release_channel", "upstream_ref", "manual"],
                    },
                    "source": {"type": "string"},
                    "owner_remote": {"type": "string"},
                    "update_policy": {"type": "string"},
                    "local_branch_policy": {"type": "string"},
                    "non_fast_forward_policy": {"type": "string"},
                    "evidence_checks": {
                        "type": "array",
                        "items": {"type": "string"},
                        "uniqueItems": True,
                    },
                    "sync_eligible": {"type": "boolean"},
                    "notes": {"type": "string"},
                },
            },
        },
        "local_surfaces": {
            "type": "array",
            "items": {
                "type": "object",
                "additionalProperties": True,
                "required": ["kind", "path"],
                "properties": {
                    "kind": {
                        "type": "string",
                        "enum": [
                            "config",
                            "doc",
                            "skill",
                            "script",
                            "hook",
                            "agent_instruction",
                            "migration_input",
                            "other",
                        ],
                    },
                    "path": {"type": "string"},
                    "domain": {"type": "string"},
                    "domains": {
                        "type": "array",
                        "items": {"type": "string"},
                        "uniqueItems": True,
                    },
                    "portability_hint": {
                        "type": "string",
                        "enum": [
                            "fork-specific",
                            "shared-with-fork-policy",
                            "repo-ops-candidate",
                        ],
                    },
                    "portability_hints": {
                        "type": "array",
                        "items": {
                            "type": "string",
                            "enum": [
                                "fork-specific",
                                "shared-with-fork-policy",
                                "repo-ops-candidate",
                            ],
                        },
                        "uniqueItems": True,
                    },
                    "repo_ops_candidate_scope": {"type": "string"},
                    "notes": {"type": "string"},
                },
            },
        },
        "sync_policy": {
            "type": "object",
            "additionalProperties": True,
            "properties": {
                "default_sync_baseline": {"type": "string"},
                "default_sync_ref": {"type": "string"},
                "fork_sync_start_ref": {"type": "string"},
                "preserve_commit_identity": {"type": "boolean"},
                "forbid_history_rewrites": {"type": "boolean"},
                "allowed_merge_methods": {
                    "type": "array",
                    "items": {"type": "string"},
                    "uniqueItems": True,
                },
                "fork_sync_methods": {
                    "type": "array",
                    "items": {"type": "string"},
                    "uniqueItems": True,
                },
                "track_update_methods": {
                    "type": "array",
                    "items": {"type": "string"},
                    "uniqueItems": True,
                },
                "ancestry_checks": {
                    "type": "array",
                    "items": {"type": "string"},
                    "uniqueItems": True,
                },
                "conditional_ancestry_checks": {
                    "type": "array",
                    "items": {"type": "string"},
                    "uniqueItems": True,
                },
                "pre_sync_fetches": {
                    "type": "array",
                    "items": {"type": "string"},
                    "uniqueItems": True,
                },
                "forbidden_flows": {
                    "type": "array",
                    "items": {"type": "string"},
                    "uniqueItems": True,
                },
                "unreleased_upstream_main": {"type": "string"},
                "uncertainty_destination": {"type": "string"},
            },
        },
        "divergence_policy": {
            "type": "object",
            "additionalProperties": True,
            "properties": {
                "inventory_paths": {
                    "type": "array",
                    "items": {"type": "string"},
                    "uniqueItems": True,
                },
                "preservation_checks": {
                    "type": "array",
                    "items": {"type": "string"},
                    "uniqueItems": True,
                },
                "uncertainty_destination": {"type": "string"},
            },
        },
        "review_policy": {"type": "object", "additionalProperties": True},
        "publication_policy": {"type": "object", "additionalProperties": True},
        "local_gates": {"type": "object", "additionalProperties": True},
        "portability": {"type": "object", "additionalProperties": True},
    },
}


@dataclass(frozen=True)
class Diagnostic:
    severity: str
    code: str
    message: str
    path: str = ""
    detail: dict[str, Any] | None = None

    def to_dict(self) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "severity": self.severity,
            "code": self.code,
            "message": self.message,
        }
        if self.path:
            payload["path"] = self.path
        if self.detail:
            payload["detail"] = self.detail
        return payload


def schema_diagnostics(config: dict[str, Any]) -> list[Diagnostic]:
    """Return JSON Schema diagnostics for a parsed Fork Ops config."""
    validator = Draft202012Validator(CONFIG_SCHEMA)
    diagnostics: list[Diagnostic] = []
    for error in sorted(validator.iter_errors(config), key=lambda item: list(item.path)):
        path = _format_path(error.path)
        diagnostics.append(
            Diagnostic(
                severity="error",
                code="schema.invalid",
                message=error.message,
                path=path,
            )
        )
    return diagnostics


def _format_path(parts: Any) -> str:
    return ".".join(str(part) for part in parts)
