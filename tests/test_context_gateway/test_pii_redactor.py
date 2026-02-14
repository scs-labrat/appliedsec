"""Tests for PII redaction — Story 5.2."""

from __future__ import annotations

from context_gateway.pii_redactor import RedactionMap, deanonymise_text, redact_pii


class TestRedactionMap:
    def test_creates_placeholder(self):
        rm = RedactionMap()
        p = rm.get_or_create("10.0.0.1", "IP_SRC")
        assert p == "IP_SRC_001"

    def test_same_value_same_placeholder(self):
        rm = RedactionMap()
        p1 = rm.get_or_create("10.0.0.1", "IP_SRC")
        p2 = rm.get_or_create("10.0.0.1", "IP_SRC")
        assert p1 == p2

    def test_different_values_different_placeholders(self):
        rm = RedactionMap()
        p1 = rm.get_or_create("10.0.0.1", "IP_SRC")
        p2 = rm.get_or_create("10.0.0.2", "IP_SRC")
        assert p1 != p2
        assert p1 == "IP_SRC_001"
        assert p2 == "IP_SRC_002"

    def test_restore(self):
        rm = RedactionMap()
        rm.get_or_create("admin@contoso.com", "USER")
        assert rm.restore("USER_001") == "admin@contoso.com"

    def test_restore_unknown(self):
        rm = RedactionMap()
        assert rm.restore("UNKNOWN_001") is None

    def test_mappings_property(self):
        rm = RedactionMap()
        rm.get_or_create("10.0.0.1", "IP_SRC")
        assert "10.0.0.1" in rm.mappings
        assert "IP_SRC_001" in rm.reverse_mappings


class TestRedactPii:
    def test_redacts_ip(self):
        text, rm = redact_pii("Connection from 192.168.1.100 detected")
        assert "192.168.1.100" not in text
        assert "IP_SRC_001" in text

    def test_redacts_email(self):
        text, rm = redact_pii("User john@example.com logged in")
        assert "john@example.com" not in text
        assert "USER_001" in text

    def test_consistent_across_calls(self):
        rm = RedactionMap()
        text1, rm = redact_pii("IP 10.0.0.1 seen", rm)
        text2, rm = redact_pii("Same IP 10.0.0.1 again", rm)
        assert "IP_SRC_001" in text1
        assert "IP_SRC_001" in text2

    def test_extra_values(self):
        text, rm = redact_pii(
            "Host WORKSTATION-42 is compromised",
            extra_values={"WORKSTATION-42": "HOST"},
        )
        assert "WORKSTATION-42" not in text
        assert "HOST_001" in text

    def test_creates_new_map_if_none(self):
        text, rm = redact_pii("10.0.0.1")
        assert isinstance(rm, RedactionMap)

    def test_no_pii_unchanged(self):
        text, rm = redact_pii("Normal text with no PII")
        assert text == "Normal text with no PII"


class TestDeanonymise:
    def test_restores_values(self):
        original = "Alert from 10.0.0.1 by admin@corp.com"
        redacted, rm = redact_pii(original)
        restored = deanonymise_text(redacted, rm)
        assert "10.0.0.1" in restored
        assert "admin@corp.com" in restored

    def test_handles_empty_map(self):
        rm = RedactionMap()
        assert deanonymise_text("no placeholders here", rm) == "no placeholders here"

    def test_handles_multiple_ips(self):
        text = "Source 10.0.0.1, dest 10.0.0.2"
        redacted, rm = redact_pii(text)
        restored = deanonymise_text(redacted, rm)
        assert "10.0.0.1" in restored
        assert "10.0.0.2" in restored
