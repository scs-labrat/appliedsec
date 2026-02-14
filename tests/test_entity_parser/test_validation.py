"""Tests for entity validation and sanitisation — Story 3.4."""

from __future__ import annotations

from entity_parser.validation import (
    DANGEROUS_CHARS,
    MAX_FIELD_LENGTH,
    VALIDATION_PATTERNS,
    sanitize_value,
    validate_hash,
    validate_ip,
)


class TestValidateIp:
    def test_valid_ipv4(self):
        assert validate_ip("192.168.1.1") is True

    def test_valid_ipv4_zeroes(self):
        assert validate_ip("0.0.0.0") is True

    def test_valid_ipv4_max(self):
        assert validate_ip("255.255.255.255") is True

    def test_invalid_ipv4_octet_too_high(self):
        assert validate_ip("256.1.1.1") is False

    def test_invalid_ipv4_letters(self):
        assert validate_ip("abc.def.ghi.jkl") is False

    def test_valid_ipv6(self):
        assert validate_ip("2001:0db8:85a3:0000:0000:8a2e:0370:7334") is True

    def test_valid_ipv6_short(self):
        assert validate_ip("::1") is True

    def test_invalid_ip_empty(self):
        assert validate_ip("") is False

    def test_invalid_ip_garbage(self):
        assert validate_ip("not-an-ip") is False

    def test_strips_whitespace(self):
        assert validate_ip("  10.0.0.1  ") is True


class TestValidateHash:
    def test_valid_sha256(self):
        h = "a" * 64
        assert validate_hash(h, "SHA256") is True

    def test_valid_sha1(self):
        h = "b" * 40
        assert validate_hash(h, "SHA1") is True

    def test_valid_md5(self):
        h = "c" * 32
        assert validate_hash(h, "MD5") is True

    def test_wrong_length_for_algorithm(self):
        h = "a" * 64
        assert validate_hash(h, "MD5") is False

    def test_non_hex_chars(self):
        h = "g" * 64
        assert validate_hash(h, "SHA256") is False

    def test_auto_detect_sha256(self):
        assert validate_hash("a" * 64) is True

    def test_auto_detect_sha1(self):
        assert validate_hash("b" * 40) is True

    def test_auto_detect_md5(self):
        assert validate_hash("c" * 32) is True

    def test_unknown_algorithm(self):
        assert validate_hash("abc123", "RIPEMD") is False

    def test_case_insensitive(self):
        h = "AABBCCDD" * 8  # 64 chars
        assert validate_hash(h, "sha256") is True


class TestSanitizeValue:
    def test_normal_string(self):
        assert sanitize_value("hello") == "hello"

    def test_strips_whitespace(self):
        assert sanitize_value("  hello  ") == "hello"

    def test_truncates_oversized(self):
        long_str = "x" * 3000
        result = sanitize_value(long_str, "test")
        assert result is not None
        assert len(result) == MAX_FIELD_LENGTH

    def test_strips_dangerous_chars(self):
        result = sanitize_value("drop;table|users", "field")
        assert result is not None
        assert ";" not in result
        assert "|" not in result

    def test_allows_special_chars_in_commandline(self):
        result = sanitize_value("cmd.exe /c dir & echo hello", "CommandLine")
        assert result is not None
        assert "&" in result

    def test_allows_special_chars_in_command_line(self):
        result = sanitize_value("bash -c 'ls'", "command_line")
        assert result is not None
        assert "'" in result

    def test_none_input(self):
        assert sanitize_value(None) is None  # type: ignore[arg-type]

    def test_non_string_coerced(self):
        assert sanitize_value(12345) == "12345"  # type: ignore[arg-type]

    def test_empty_string_returns_none(self):
        assert sanitize_value("   ") is None


class TestValidationPatterns:
    def test_all_expected_patterns_present(self):
        expected = {"ipv4", "ipv6", "sha256", "sha1", "md5", "domain", "upn", "hostname"}
        assert set(VALIDATION_PATTERNS.keys()) == expected

    def test_domain_pattern(self):
        assert VALIDATION_PATTERNS["domain"].match("example.com")
        assert not VALIDATION_PATTERNS["domain"].match("-invalid.com")

    def test_upn_pattern(self):
        assert VALIDATION_PATTERNS["upn"].match("user@example.com")
        assert not VALIDATION_PATTERNS["upn"].match("noatsign")

    def test_hostname_pattern(self):
        assert VALIDATION_PATTERNS["hostname"].match("server-01")
        assert not VALIDATION_PATTERNS["hostname"].match("-invalid")

    def test_dangerous_chars_regex(self):
        assert DANGEROUS_CHARS.search(";")
        assert DANGEROUS_CHARS.search("|")
        assert DANGEROUS_CHARS.search("$(cmd)")
        assert not DANGEROUS_CHARS.search("safe_value")
