"""PII redaction with reversible mapping — Stories 5.2, 15.4.

Replaces real entity values with placeholders (``USER_001``,
``IP_SRC_001``, ``HOST_001``, …) before sending content to the LLM,
and restores them after the response is received.

Story 15.4 extends detection to usernames in hostnames, file paths,
and chat handles, and adds encrypted redaction map storage.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field

# Regex patterns to detect PII in free text
_IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_EMAIL_RE = re.compile(r"\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b")
_UPN_RE = _EMAIL_RE  # UPNs look like emails
_HOSTNAME_RE = re.compile(r"\b[A-Z][A-Z0-9_-]{2,15}(?:\.[a-zA-Z0-9.-]+)?\b")

# Story 15.4: Extended PII patterns
_USERNAME_IN_HOSTNAME_RE = re.compile(
    r"\b[A-Za-z][A-Za-z0-9]{1,19}[-_][A-Za-z]{2,15}(?:\d{1,3})?\b"
)
_FILE_PATH_USERNAME_RE = re.compile(
    r"(?:/home/|/Users/|[A-Za-z]:\\Users\\)([a-zA-Z][a-zA-Z0-9._-]{1,20})"
)
_CHAT_HANDLE_RE = re.compile(r"@[a-zA-Z][a-zA-Z0-9._-]{1,20}\b")

# F3: Common infrastructure words that should not trigger hostname-username redaction
_HOSTNAME_EXCLUSIONS = frozenset({
    "SERVER", "ROUTER", "SWITCH", "PRINTER", "BUILD", "TEST",
    "PROD", "DEV", "STAGE", "STAGING", "BACKUP", "PROXY",
    "GATEWAY", "MONITOR", "ADMIN", "NODE", "WORKER", "MASTER",
    "SLAVE", "PRIMARY", "SECONDARY", "REPLICA", "CLUSTER",
})

# F4: ECS/Elastic field names that should not trigger chat handle redaction
_ECS_FIELD_EXCLUSIONS = frozenset({
    "@timestamp", "@version", "@metadata",
    "@message", "@fields", "@source",
    "@tags", "@type",
})


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

    # Story 15.4: hostname-with-username (e.g. JSMITH-LAPTOP)
    # F3: skip matches where second segment is a common infra word
    for match in _USERNAME_IN_HOSTNAME_RE.findall(text):
        parts = re.split(r"[-_]", match, maxsplit=1)
        if len(parts) == 2 and parts[1].upper().rstrip("0123456789") in _HOSTNAME_EXCLUSIONS:
            continue
        placeholder = redaction_map.get_or_create(match, "HOST")
        text = text.replace(match, placeholder)

    # Story 15.4: file path usernames (e.g. /home/jsmith/)
    for m in list(_FILE_PATH_USERNAME_RE.finditer(text)):
        full_match = m.group(0)
        username = m.group(1)
        placeholder = redaction_map.get_or_create(username, "USER")
        replacement = full_match.replace(username, placeholder, 1)
        text = text.replace(full_match, replacement, 1)

    # Story 15.4: chat handles (e.g. @jsmith)
    # F4: skip ECS field names like @timestamp, @version
    for match in _CHAT_HANDLE_RE.findall(text):
        if match.lower() in _ECS_FIELD_EXCLUSIONS:
            continue
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


# ---- Secure redaction map storage (Story 15.4) --------------------------------

def encrypt_redaction_map(redaction_map: RedactionMap, key: bytes) -> bytes:
    """Encrypt a redaction map using Fernet symmetric encryption.

    The key should come from ``PII_REDACTION_KEY`` env var or a KMS.
    """
    from cryptography.fernet import Fernet

    fernet = Fernet(key)
    payload = json.dumps({
        "forward": redaction_map.mappings,
        "reverse": redaction_map.reverse_mappings,
        "counters": dict(redaction_map._counters),
    }).encode("utf-8")
    return fernet.encrypt(payload)


def decrypt_redaction_map(encrypted: bytes, key: bytes) -> RedactionMap:
    """Decrypt a redaction map for audit re-identification.

    Raises ``cryptography.fernet.InvalidToken`` if the key is wrong.
    """
    from cryptography.fernet import Fernet

    fernet = Fernet(key)
    payload = fernet.decrypt(encrypted)
    data = json.loads(payload.decode("utf-8"))

    rm = RedactionMap()
    rm._forward = data["forward"]
    rm._reverse = data["reverse"]
    # F10: restore counters directly if present, else reconstruct from forward map
    if "counters" in data:
        rm._counters = data["counters"]
    else:
        for placeholder in rm._forward.values():
            parts = placeholder.rsplit("_", 1)
            if len(parts) == 2:
                prefix, num = parts
                try:
                    count = int(num)
                    rm._counters[prefix] = max(rm._counters.get(prefix, 0), count)
                except ValueError:
                    pass
    return rm
