"""PII redaction with reversible mapping — Story 5.2.

Replaces real entity values with placeholders (``USER_001``,
``IP_SRC_001``, ``HOST_001``, …) before sending content to the LLM,
and restores them after the response is received.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

# Regex patterns to detect PII in free text
_IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_EMAIL_RE = re.compile(r"\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b")
_UPN_RE = _EMAIL_RE  # UPNs look like emails
_HOSTNAME_RE = re.compile(r"\b[A-Z][A-Z0-9_-]{2,15}(?:\.[a-zA-Z0-9.-]+)?\b")


@dataclass
class RedactionMap:
    """Bidirectional mapping between real values and placeholders."""

    _forward: dict[str, str] = field(default_factory=dict)  # real → placeholder
    _reverse: dict[str, str] = field(default_factory=dict)  # placeholder → real
    _counters: dict[str, int] = field(default_factory=dict)

    def get_or_create(self, real_value: str, prefix: str) -> str:
        """Return the existing placeholder or create a new one."""
        if real_value in self._forward:
            return self._forward[real_value]
        count = self._counters.get(prefix, 0) + 1
        self._counters[prefix] = count
        placeholder = f"{prefix}_{count:03d}"
        self._forward[real_value] = placeholder
        self._reverse[placeholder] = real_value
        return placeholder

    def restore(self, placeholder: str) -> str | None:
        """Look up the real value for a placeholder."""
        return self._reverse.get(placeholder)

    @property
    def mappings(self) -> dict[str, str]:
        """Return a copy of the forward (real → placeholder) map."""
        return dict(self._forward)

    @property
    def reverse_mappings(self) -> dict[str, str]:
        """Return a copy of the reverse (placeholder → real) map."""
        return dict(self._reverse)


def redact_pii(
    text: str,
    redaction_map: RedactionMap | None = None,
    *,
    extra_values: dict[str, str] | None = None,
) -> tuple[str, RedactionMap]:
    """Replace PII in *text* with stable placeholders.

    Parameters
    ----------
    text:
        Free-text content (alert description, LLM prompt, etc.).
    redaction_map:
        Existing map to reuse (ensures same entity → same placeholder
        across calls within one investigation).  Created if ``None``.
    extra_values:
        Explicit ``{real_value: prefix}`` pairs to redact (e.g. from
        parsed entities).

    Returns
    -------
    (redacted_text, redaction_map)
    """
    if redaction_map is None:
        redaction_map = RedactionMap()

    # --- explicit values first (highest priority) -------------------------
    if extra_values:
        for value, prefix in extra_values.items():
            placeholder = redaction_map.get_or_create(value, prefix)
            text = text.replace(value, placeholder)

    # --- regex-based detection -------------------------------------------
    for match in _IP_RE.findall(text):
        placeholder = redaction_map.get_or_create(match, "IP_SRC")
        text = text.replace(match, placeholder)

    for match in _EMAIL_RE.findall(text):
        placeholder = redaction_map.get_or_create(match, "USER")
        text = text.replace(match, placeholder)

    return text, redaction_map


def deanonymise_text(text: str, redaction_map: RedactionMap) -> str:
    """Restore original values in *text* using the *redaction_map*.

    Replaces longest placeholders first to avoid partial replacements.
    """
    for placeholder in sorted(
        redaction_map.reverse_mappings, key=len, reverse=True
    ):
        real = redaction_map.reverse_mappings[placeholder]
        text = text.replace(placeholder, real)
    return text
