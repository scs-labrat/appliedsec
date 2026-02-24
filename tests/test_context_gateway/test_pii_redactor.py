"""Tests for PII redaction — Story 5.2, Sprint 2 fixes."""

from __future__ import annotations

from context_gateway.pii_redactor import (
    RedactionMap,
    deanonymise_text,
    encrypt_redaction_map,
    decrypt_redaction_map,
    redact_pii,
)
from cryptography.fernet import Fernet


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


# ---------- F3: Hostname regex false positives --------------------------------

class TestHostnameExclusions:
    def test_infra_hostnames_preserved(self):
        """Common infra hostnames like WEB-SERVER should NOT be redacted."""
        text = "Alert from WEB-SERVER and DB-ROUTER and APP-SWITCH"
        redacted, rm = redact_pii(text)
        assert "WEB-SERVER" in redacted
        assert "DB-ROUTER" in redacted
        assert "APP-SWITCH" in redacted

    def test_real_user_hostnames_still_redacted(self):
        """User hostnames like JSMITH-LAPTOP should still be redacted."""
        text = "JSMITH-WORKSTATION connected to the VPN"
        redacted, rm = redact_pii(text)
        assert "JSMITH-WORKSTATION" not in redacted
        assert "HOST_001" in redacted


# ---------- F4: Chat handle regex hits ECS field names ------------------------

class TestChatHandleEcsExclusions:
    def test_ecs_fields_preserved(self):
        """ECS fields like @timestamp should NOT be redacted."""
        text = "Log entry: @timestamp=2024-01-01 @version=1 @metadata"
        redacted, rm = redact_pii(text)
        assert "@timestamp" in redacted
        assert "@version" in redacted
        assert "@metadata" in redacted

    def test_real_chat_handles_still_redacted(self):
        """Real chat handles like @jsmith should still be redacted."""
        text = "Message from @jsmith.ops in the channel"
        redacted, rm = redact_pii(text)
        assert "@jsmith.ops" not in redacted
        assert "USER_001" in redacted


# ---------- F9: File path regex only matches C:\Users\ -----------------------

class TestFilePathDriveLetter:
    def test_non_c_drive_redacted(self):
        """File paths on D:\\ or E:\\ should also be redacted."""
        text = r"Found file at D:\Users\jsmith\docs\secrets.txt"
        redacted, rm = redact_pii(text)
        assert "jsmith" not in redacted


# ---------- F10: Encrypted redaction map loses counters -----------------------

class TestEncryptedRedactionMapCounters:
    def test_round_trip_preserves_counters(self):
        """encrypt → decrypt round-trip should preserve counter state."""
        key = Fernet.generate_key()
        rm = RedactionMap()
        rm.get_or_create("10.0.0.1", "IP_SRC")
        rm.get_or_create("10.0.0.2", "IP_SRC")
        assert rm._counters["IP_SRC"] == 2

        encrypted = encrypt_redaction_map(rm, key)
        restored = decrypt_redaction_map(encrypted, key)
        assert restored._counters["IP_SRC"] == 2

    def test_continued_redaction_after_decrypt_uses_correct_counter(self):
        """After decrypt, new redactions should continue from the right counter."""
        key = Fernet.generate_key()
        rm = RedactionMap()
        rm.get_or_create("10.0.0.1", "IP_SRC")
        rm.get_or_create("10.0.0.2", "IP_SRC")

        encrypted = encrypt_redaction_map(rm, key)
        restored = decrypt_redaction_map(encrypted, key)

        # Next IP should be IP_SRC_003, not IP_SRC_001
        p = restored.get_or_create("10.0.0.3", "IP_SRC")
        assert p == "IP_SRC_003"
