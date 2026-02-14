"""Injection detection engine — Story 5.1.

Regex-based detection and redaction of prompt-injection patterns
in LLM input.  All user-supplied strings (alert descriptions, entity
fields, log entries) pass through ``sanitise_input()`` before reaching
the Anthropic API.
"""

from __future__ import annotations

import re

REDACTED_INJECTION = "[REDACTED_INJECTION_ATTEMPT]"
REDACTED_MARKUP = "[REDACTED_MARKUP]"

# --------------------------------------------------------------------------
# 14+ injection patterns — order matters (longer / more specific first)
# --------------------------------------------------------------------------
INJECTION_PATTERNS: list[re.Pattern[str]] = [
    # Role-change / impersonation
    re.compile(r"you\s+are\s+now\b", re.IGNORECASE),
    re.compile(r"pretend\s+you\s+are\b", re.IGNORECASE),
    re.compile(r"role[\s-]?play\s+as\b", re.IGNORECASE),
    re.compile(r"act\s+as\s+(?:a|an|if)\b", re.IGNORECASE),
    # Instruction override
    re.compile(r"ignore\s+(?:previous|all|your|the\s+above)\s+instructions?\b", re.IGNORECASE),
    re.compile(r"disregard\s+(?:your|all|the|previous)\s+(?:instructions?|rules?|prompt)\b", re.IGNORECASE),
    re.compile(r"override\s+your\s+(?:instructions?|rules?|guidelines?)\b", re.IGNORECASE),
    re.compile(r"forget\s+(?:everything|all|your)\s+(?:instructions?|rules?)?\b", re.IGNORECASE),
    # Jailbreak / DAN
    re.compile(r"\bDAN\b.*Do\s+Anything\s+Now", re.IGNORECASE),
    re.compile(r"\bjailbreak\b", re.IGNORECASE),
    re.compile(r"\bDo\s+Anything\s+Now\b", re.IGNORECASE),
    # System prompt extraction
    re.compile(r"(?:print|show|reveal|repeat|output)\s+(?:your\s+)?system\s+prompt\b", re.IGNORECASE),
    re.compile(r"what\s+(?:is|are)\s+your\s+(?:system\s+)?instructions?\b", re.IGNORECASE),
    # Developer mode
    re.compile(r"(?:enter|enable|activate)\s+developer\s+mode\b", re.IGNORECASE),
]

# Markup patterns — fenced code blocks pretending to be system/tool messages
_MARKUP_PATTERN = re.compile(
    r"```\s*(?:system|tool|assistant|human)\b.*?```",
    re.IGNORECASE | re.DOTALL,
)


def sanitise_input(text: str) -> tuple[str, list[str]]:
    """Sanitise *text* by redacting injection patterns and dangerous markup.

    Returns ``(sanitised_text, detections)`` where *detections* is a list
    of human-readable descriptions of what was redacted.
    """
    detections: list[str] = []

    # --- markup first (may span multiple lines) --------------------------
    if _MARKUP_PATTERN.search(text):
        text = _MARKUP_PATTERN.sub(REDACTED_MARKUP, text)
        detections.append("embedded_markup")

    # --- injection patterns -----------------------------------------------
    for pattern in INJECTION_PATTERNS:
        if pattern.search(text):
            text = pattern.sub(REDACTED_INJECTION, text)
            detections.append(f"injection:{pattern.pattern[:40]}")

    return text, detections
