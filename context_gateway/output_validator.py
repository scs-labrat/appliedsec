"""Output validator — Story 5.4.

Validates LLM responses against:
1. A JSON schema (if provided in the ``GatewayRequest``).
2. The ``taxonomy_ids`` Postgres table (technique IDs).

Unknown / hallucinated technique IDs are quarantined and returned in
``validation_errors``.
"""

from __future__ import annotations

import json
import logging
import re
from typing import Any

logger = logging.getLogger(__name__)

# Regex to find ATT&CK / ATLAS technique IDs in text
_TECHNIQUE_RE = re.compile(r"\b(T\d{4}(?:\.\d{3})?|AML\.T\d{4})\b")


def validate_output(
    content: str,
    *,
    known_technique_ids: set[str] | None = None,
    output_schema: dict[str, Any] | None = None,
) -> tuple[bool, list[str], list[str]]:
    """Validate an LLM response.

    Parameters
    ----------
    content:
        Raw LLM response text.
    known_technique_ids:
        Set of valid technique IDs from the ``taxonomy_ids`` table.
        If ``None``, technique validation is skipped.
    output_schema:
        JSON Schema dict to validate against.  If ``None``, schema
        validation is skipped.

    Returns
    -------
    (valid, validation_errors, quarantined_ids)
    """
    errors: list[str] = []
    quarantined: list[str] = []

    # --- technique ID validation -----------------------------------------
    if known_technique_ids is not None:
        found_ids = set(_TECHNIQUE_RE.findall(content))
        for tid in sorted(found_ids):
            if tid not in known_technique_ids:
                quarantined.append(tid)
                errors.append(f"Unknown technique ID: {tid}")

    # --- JSON schema validation ------------------------------------------
    if output_schema is not None:
        try:
            parsed = json.loads(content)
            schema_errors = _validate_schema(parsed, output_schema)
            errors.extend(schema_errors)
        except json.JSONDecodeError as exc:
            errors.append(f"Response is not valid JSON: {exc}")

    valid = len(errors) == 0
    return valid, errors, quarantined


def _validate_schema(data: Any, schema: dict[str, Any]) -> list[str]:
    """Lightweight JSON schema validation (required fields + type checks).

    This is intentionally simple — for full JSON Schema validation,
    swap in ``jsonschema.validate()`` if the dependency is available.
    """
    errors: list[str] = []
    expected_type = schema.get("type")

    if expected_type == "object" and not isinstance(data, dict):
        errors.append(f"Expected object, got {type(data).__name__}")
        return errors

    if expected_type == "array" and not isinstance(data, list):
        errors.append(f"Expected array, got {type(data).__name__}")
        return errors

    if expected_type == "object" and isinstance(data, dict):
        for field in schema.get("required", []):
            if field not in data:
                errors.append(f"Missing required field: {field}")

        properties = schema.get("properties", {})
        for key, prop_schema in properties.items():
            if key in data:
                prop_type = prop_schema.get("type")
                actual = data[key]
                if prop_type == "string" and not isinstance(actual, str):
                    errors.append(f"Field '{key}' expected string, got {type(actual).__name__}")
                elif prop_type == "number" and not isinstance(actual, (int, float)):
                    errors.append(f"Field '{key}' expected number, got {type(actual).__name__}")
                elif prop_type == "array" and not isinstance(actual, list):
                    errors.append(f"Field '{key}' expected array, got {type(actual).__name__}")
                elif prop_type == "boolean" and not isinstance(actual, bool):
                    errors.append(f"Field '{key}' expected boolean, got {type(actual).__name__}")

    return errors
