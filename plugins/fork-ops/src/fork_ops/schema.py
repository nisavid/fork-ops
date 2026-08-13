"""Fork Ops config schema and schema validation helpers."""

from __future__ import annotations

import json
import os
import stat
from dataclasses import dataclass
from importlib import resources
from typing import Any

from jsonschema import Draft202012Validator
from jsonschema.exceptions import ValidationError

CAPABILITY_LEVELS = [
    "identified",
    "scoutable",
    "track-aware",
    "sync-ready",
    "review-ready",
    "provenance-ready",
]

SCHEMA_RESOURCE = "fork-ops.schema.json"
MAX_SCHEMA_BYTES = 1_048_576


def _load_config_schema() -> dict[str, Any]:
    schema_path = resources.files("fork_ops").joinpath(SCHEMA_RESOURCE)
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    descriptor = os.open(str(schema_path), flags)
    try:
        schema_stat = os.fstat(descriptor)
        if not stat.S_ISREG(schema_stat.st_mode):
            raise TypeError(f"{SCHEMA_RESOURCE} must be a regular file")
        payload = os.read(descriptor, MAX_SCHEMA_BYTES + 1)
        if len(payload) > MAX_SCHEMA_BYTES or os.read(descriptor, 1):
            raise TypeError(f"{SCHEMA_RESOURCE} exceeds the schema byte limit")
    finally:
        os.close(descriptor)
    schema_text = payload.decode("utf-8")
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
    for error in sorted(validator.iter_errors(config), key=_validation_error_path):
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


def _validation_error_path(error: ValidationError) -> list[str | int]:
    return list(error.path)


def _format_path(parts: Any) -> str:
    return ".".join(str(part) for part in parts)
