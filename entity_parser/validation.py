"""Input validation and sanitisation for extracted entity values — Story 3.4."""

from __future__ import annotations

import logging
import re

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Validation patterns — reject values that don't match expected formats
# ---------------------------------------------------------------------------
VALIDATION_PATTERNS: dict[str, re.Pattern[str]] = {
    "ipv4": re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$"),
    "ipv6": re.compile(r"^[0-9a-fA-F:]+$"),
    "sha256": re.compile(r"^[a-fA-F0-9]{64}$"),
    "sha1": re.compile(r"^[a-fA-F0-9]{40}$"),
    "md5": re.compile(r"^[a-fA-F0-9]{32}$"),
    "domain": re.compile(
        r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$"
    ),
    "upn": re.compile(r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"),
    "hostname": re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9._-]{0,63}$"),
}

# Characters that should never appear in IOC values (query injection vectors)
DANGEROUS_CHARS = re.compile(r"""[;|&`$(){}\[\]<>'"]""")

# Maximum field length to prevent memory abuse
MAX_FIELD_LENGTH = 2048


def sanitize_value(value: str, field_name: str = "") -> str | None:
    """Sanitize an extracted entity value.

    Returns the cleaned string or *None* if the input is not usable.
    """
    if not isinstance(value, str):
        return str(value) if value is not None else None

    # Truncate oversized values
    if len(value) > MAX_FIELD_LENGTH:
        logger.warning("Truncated oversized field '%s': %d chars", field_name, len(value))
        value = value[:MAX_FIELD_LENGTH]

    # Check for query-injection patterns
    if DANGEROUS_CHARS.search(value):
        # Allow semicolons / special chars inside CommandLine fields
        if field_name.lower() not in ("commandline", "command_line"):
            logger.warning("Dangerous characters in field '%s': %s", field_name, value[:100])
            value = DANGEROUS_CHARS.sub("", value)

    return value.strip() or None


def validate_ip(address: str) -> bool:
    """Return *True* if *address* looks like a valid IPv4 or IPv6 address."""
    address = address.strip()
    if VALIDATION_PATTERNS["ipv4"].match(address):
        parts = address.split(".")
        return all(0 <= int(p) <= 255 for p in parts)
    if VALIDATION_PATTERNS["ipv6"].match(address) and ":" in address:
        return True
    return False


def validate_hash(value: str, algorithm: str | None = None) -> bool:
    """Validate a file hash against known length/format rules.

    If *algorithm* is provided it must match one of SHA256 / SHA1 / MD5.
    Otherwise the function tries all three lengths.
    """
    value = value.strip().lower()
    if algorithm:
        key = algorithm.lower().replace("-", "")
        pattern = VALIDATION_PATTERNS.get(key)
        if pattern is None:
            return False
        return bool(pattern.match(value))
    # Auto-detect by length
    for key in ("sha256", "sha1", "md5"):
        if VALIDATION_PATTERNS[key].match(value):
            return True
    return False
