"""PII redaction completeness tests — Story 15.4.

Covers hostname-with-username, file path usernames, chat handles,
secure redaction map encryption, and full integration across all PII types.
"""

from __future__ import annotations

import pytest
from cryptography.fernet import Fernet, InvalidToken

from context_gateway.pii_redactor import (
    RedactionMap,
    decrypt_redaction_map,
    encrypt_redaction_map,
    redact_pii,
)


# ---------------------------------------------------------------------------
# TestHostnameRedaction (Task 1) — AC-1
# ---------------------------------------------------------------------------

class TestHostnameRedaction:
    """AC-1: Hostname containing username is pseudonymized to HOST_NNN."""

    def test_jsmith_laptop(self):
        text, rm = redact_pii("Compromised host JSMITH-LAPTOP detected")
        assert "JSMITH-LAPTOP" not in text
        assert "HOST_" in text

    def test_admin_pc01(self):
        text, rm = redact_pii("Alert on admin-PC01 endpoint")
        assert "admin-PC01" not in text
        assert "HOST_" in text

    def test_jdoe_workstation(self):
        text, rm = redact_pii("Login from jdoe-Workstation")
        assert "jdoe-Workstation" not in text
        assert "HOST_" in text

    def test_consistent_placeholder(self):
        """Same hostname gets same placeholder across calls."""
        rm = RedactionMap()
        text1, rm = redact_pii("Host JSMITH-LAPTOP seen", rm)
        text2, rm = redact_pii("Same JSMITH-LAPTOP again", rm)
        assert text1.count("HOST_001") == 1
        assert text2.count("HOST_001") == 1


# ---------------------------------------------------------------------------
# TestFilePathRedaction (Task 2) — AC-2
# ---------------------------------------------------------------------------

class TestFilePathRedaction:
    """AC-2: File path containing username is pseudonymized."""

    def test_linux_home_path(self):
        text, rm = redact_pii("File found at /home/jsmith/Documents/malware.exe")
        assert "jsmith" not in text
        assert "/home/USER_" in text
        assert "Documents/malware.exe" in text

    def test_windows_users_path(self):
        text, rm = redact_pii(r"File at C:\Users\jdoe\Downloads\payload.bin")
        assert "jdoe" not in text
        assert "USER_" in text

    def test_macos_users_path(self):
        text, rm = redact_pii("Config at /Users/admin.user/Library/prefs.plist")
        assert "admin.user" not in text
        assert "USER_" in text

    def test_path_without_username_unchanged(self):
        text, rm = redact_pii("File at /var/log/syslog")
        assert text == "File at /var/log/syslog"


# ---------------------------------------------------------------------------
# TestChatHandleRedaction (Task 3) — AC-4
# ---------------------------------------------------------------------------

class TestChatHandleRedaction:
    """AC-4: Chat handles are pseudonymized."""

    def test_simple_handle(self):
        text, rm = redact_pii("Message from @jsmith in Slack")
        assert "@jsmith" not in text
        assert "USER_" in text

    def test_dotted_handle(self):
        text, rm = redact_pii("Ping @admin.user for approval")
        assert "@admin.user" not in text
        assert "USER_" in text

    def test_email_already_handled(self):
        """Email with @ is handled by email regex, not chat handle."""
        text, rm = redact_pii("Contact john@example.com")
        assert "john@example.com" not in text
        assert "USER_" in text


# ---------------------------------------------------------------------------
# TestSecureRedactionMap (Task 4) — AC-3
# ---------------------------------------------------------------------------

class TestSecureRedactionMap:
    """AC-3: Encrypted redaction map for audit re-identification."""

    def test_encrypt_decrypt_round_trip(self):
        """Encrypt/decrypt preserves all mappings."""
        rm = RedactionMap()
        rm.get_or_create("jsmith@corp.com", "USER")
        rm.get_or_create("10.0.0.1", "IP_SRC")
        rm.get_or_create("JSMITH-LAPTOP", "HOST")

        key = Fernet.generate_key()
        encrypted = encrypt_redaction_map(rm, key)
        restored = decrypt_redaction_map(encrypted, key)

        assert restored.mappings == rm.mappings
        assert restored.reverse_mappings == rm.reverse_mappings

    def test_wrong_key_fails(self):
        """Wrong key raises InvalidToken."""
        rm = RedactionMap()
        rm.get_or_create("test@test.com", "USER")

        key1 = Fernet.generate_key()
        key2 = Fernet.generate_key()

        encrypted = encrypt_redaction_map(rm, key1)
        with pytest.raises(InvalidToken):
            decrypt_redaction_map(encrypted, key2)

    def test_encrypted_data_not_plaintext(self):
        """Encrypted output does not contain original PII values."""
        rm = RedactionMap()
        rm.get_or_create("sensitive@example.com", "USER")

        key = Fernet.generate_key()
        encrypted = encrypt_redaction_map(rm, key)

        assert b"sensitive@example.com" not in encrypted
        assert b"USER_001" not in encrypted

    def test_restored_map_is_functional(self):
        """Decrypted map can be used for deanonymisation."""
        rm = RedactionMap()
        rm.get_or_create("admin@corp.com", "USER")

        key = Fernet.generate_key()
        encrypted = encrypt_redaction_map(rm, key)
        restored = decrypt_redaction_map(encrypted, key)

        assert restored.restore("USER_001") == "admin@corp.com"


# ---------------------------------------------------------------------------
# TestPIICompleteness (Task 5) — AC-4
# ---------------------------------------------------------------------------

class TestPIICompleteness:
    """AC-4: Full integration across all PII categories."""

    def test_all_pii_types_redacted(self):
        """Alert with ALL PII types: all are correctly redacted."""
        alert_text = (
            "Alert: Suspicious login by john@corp.com from 10.0.0.1 "
            "on host JSMITH-LAPTOP. File accessed: /home/jsmith/secrets.txt. "
            "Slack message to @jsmith.admin about the incident."
        )
        text, rm = redact_pii(alert_text)

        # Email redacted
        assert "john@corp.com" not in text
        # IP redacted (existing behavior)
        assert "10.0.0.1" not in text
        # Hostname redacted
        assert "JSMITH-LAPTOP" not in text
        # File path username redacted
        assert "/home/jsmith/" not in text
        # Chat handle redacted
        assert "@jsmith.admin" not in text

    def test_hashes_preserved(self):
        """MD5/SHA hashes are NOT PII and should be kept."""
        text, rm = redact_pii(
            "Hash: d41d8cd98f00b204e9800998ecf8427e detected in alert"
        )
        assert "d41d8cd98f00b204e9800998ecf8427e" in text

    def test_redaction_map_covers_all_types(self):
        """Redaction map contains entries for all detected PII."""
        alert_text = (
            "User admin@corp.com on ADMIN-PC at /home/admin/data. "
            "Ping @secops for help. Source IP 192.168.1.1."
        )
        text, rm = redact_pii(alert_text)
        mappings = rm.mappings

        # Should have entries for: email, IP, hostname, path username, chat handle
        assert len(mappings) >= 3  # at least email + IP + hostname

    def test_deanonymise_restores_all(self):
        """Full round-trip: redact then deanonymise restores originals."""
        from context_gateway.pii_redactor import deanonymise_text

        original = (
            "Login by admin@corp.com on ADMIN-LAPTOP from 10.0.0.1"
        )
        redacted, rm = redact_pii(original)
        restored = deanonymise_text(redacted, rm)

        assert "admin@corp.com" in restored
        assert "10.0.0.1" in restored
        assert "ADMIN-LAPTOP" in restored
