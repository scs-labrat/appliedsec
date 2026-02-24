"""XML-delimited evidence block builder — Story 12.6.

Wraps untrusted alert data in ``<evidence>`` XML tags with proper
escaping to prevent breakout from the data section.
"""

from __future__ import annotations

import re

_EVIDENCE_TAG_RE = re.compile(r"</?evidence>", re.IGNORECASE)


def escape_xml_tags(text: str) -> str:
    """Escape XML angle brackets and strip ``<evidence>`` tags from *text*.

    This prevents untrusted content from:
    1. Injecting arbitrary XML tags (angle bracket escaping)
    2. Breaking out of the ``<evidence>`` block (tag stripping)
    """
    # Strip evidence tags first (before escaping angle brackets)
    text = _EVIDENCE_TAG_RE.sub("", text)
    # Escape remaining angle brackets
    text = text.replace("&", "&amp;")
    text = text.replace("<", "&lt;")
    text = text.replace(">", "&gt;")
    return text


class EvidenceBlock:
    """Builds XML-delimited evidence blocks for structured prompts."""

    @staticmethod
    def wrap_evidence(
        alert_title: str,
        alert_description: str,
        entities_json: str,
    ) -> str:
        """Wrap untrusted alert data in escaped ``<evidence>`` XML tags."""
        escaped_title = escape_xml_tags(alert_title)
        escaped_description = escape_xml_tags(alert_description)
        escaped_entities = escape_xml_tags(entities_json)

        return (
            "<evidence>\n"
            f"<alert_title>{escaped_title}</alert_title>\n"
            f"<alert_description>{escaped_description}</alert_description>\n"
            f"<entities>{escaped_entities}</entities>\n"
            "</evidence>"
        )
