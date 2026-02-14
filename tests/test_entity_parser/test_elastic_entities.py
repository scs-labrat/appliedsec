"""Tests for Elastic / regex fallback entity extraction — Story 3.5."""

from __future__ import annotations

from entity_parser.parser import parse_alert_entities


class TestRegexFallbackIps:
    def test_extracts_ipv4_from_raw_payload(self):
        result = parse_alert_entities(
            "",
            raw_payload={"message": "Connection from 192.168.1.100 to 10.0.0.5"},
        )
        ips = {e.primary_value for e in result.ips}
        assert "192.168.1.100" in ips
        assert "10.0.0.5" in ips

    def test_invalid_ip_skipped(self):
        result = parse_alert_entities(
            "",
            raw_payload={"message": "Version 999.999.999.999 detected"},
        )
        assert len(result.ips) == 0

    def test_ip_confidence_is_reduced(self):
        result = parse_alert_entities(
            "",
            raw_payload={"message": "Source: 8.8.8.8"},
        )
        assert result.ips[0].confidence < 1.0


class TestRegexFallbackHashes:
    def test_extracts_sha256(self):
        sha256 = "a" * 64
        result = parse_alert_entities(
            "",
            raw_payload={"message": f"File hash: {sha256}"},
        )
        hashes = {e.primary_value for e in result.file_hashes}
        assert sha256 in hashes

    def test_extracts_sha1(self):
        sha1 = "b" * 40
        result = parse_alert_entities(
            "",
            raw_payload={"message": f"Hash: {sha1}"},
        )
        hashes = {e.primary_value for e in result.file_hashes}
        assert sha1 in hashes

    def test_hash_confidence_below_one(self):
        result = parse_alert_entities(
            "",
            raw_payload={"message": f"Hash: {'f' * 64}"},
        )
        assert result.file_hashes[0].confidence < 1.0


class TestRegexFallbackDomains:
    def test_extracts_domains(self):
        result = parse_alert_entities(
            "",
            raw_payload={"message": "DNS query to evil.example.com seen"},
        )
        domains = {e.primary_value for e in result.dns_records}
        assert "evil.example.com" in domains

    def test_domain_confidence_reduced(self):
        result = parse_alert_entities(
            "",
            raw_payload={"message": "Contacted malware.io"},
        )
        if result.dns_records:
            assert result.dns_records[0].confidence < 1.0


class TestFallbackFromBadJson:
    def test_malformed_json_falls_back_to_regex(self):
        result = parse_alert_entities("not valid json {192.168.1.1}")
        assert len(result.parse_errors) > 0
        ips = {e.primary_value for e in result.ips}
        assert "192.168.1.1" in ips

    def test_non_array_json_falls_back(self):
        result = parse_alert_entities('{"type": "ip", "addr": "10.0.0.1"}')
        assert len(result.parse_errors) > 0
        ips = {e.primary_value for e in result.ips}
        assert "10.0.0.1" in ips


class TestRawIocsFromFallback:
    def test_raw_iocs_populated_from_regex(self):
        result = parse_alert_entities(
            "",
            raw_payload={"message": "8.8.8.8 with hash " + "d" * 64},
        )
        assert len(result.raw_iocs) > 0

    def test_deduplicates_iocs(self):
        result = parse_alert_entities(
            "",
            raw_payload={"message": "IP 1.2.3.4 appeared again 1.2.3.4"},
        )
        ip_count = sum(1 for i in result.raw_iocs if i == "1.2.3.4")
        assert ip_count == 1
