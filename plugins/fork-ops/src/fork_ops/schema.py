"""Fork Ops config schema and schema validation helpers."""

from __future__ import annotations

import json
from dataclasses import dataclass
from importlib import resources
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

SCHEMA_RESOURCE = "fork-ops.schema.json"


def _load_config_schema() -> dict[str, Any]:
    schema_text = resources.files(__package__).joinpath(SCHEMA_RESOURCE).read_text()
    schema = json.loads(schema_text)
    if not isinstance(schema, dict):
        raise TypeError(f"{SCHEMA_RESOURCE} must contain a JSON object")
    return schema


CONFIG_SCHEMA: dict[str, Any] = _load_config_schema()


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
