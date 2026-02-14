"""Tests for Sentinel structured entity parsing — Story 3.5."""

from __future__ import annotations

import json

from shared.schemas.entity import EntityType

from entity_parser.parser import parse_alert_entities

# ---- sample Sentinel entity payloads ----------------------------------------

SENTINEL_ENTITIES = json.dumps([
    {
        "$id": "1",
        "Type": "account",
        "Name": "john.doe",
        "UPNSuffix": "contoso.com",
        "AadUserId": "aad-123",
        "Sid": "S-1-5-21-1234",
        "IsDomainJoined": True,
        "DnsDomain": "contoso.com",
    },
    {
        "$id": "2",
        "Type": "host",
        "HostName": "WORKSTATION01",
        "DnsDomain": "contoso.local",
        "OSFamily": "Windows",
        "OSVersion": "10.0.19045",
    },
    {
        "$id": "3",
        "Type": "ip",
        "Address": "10.0.0.42",
        "Location": {
            "CountryCode": "US",
            "City": "Redmond",
            "Asn": 8075,
        },
    },
    {
        "$id": "4",
        "Type": "file",
        "Name": "malware.exe",
        "Directory": "C:\\Windows\\Temp",
        "SizeInBytes": 12345,
        "FileHashes": [
            {"Algorithm": "SHA256", "Value": "a" * 64},
            {"Algorithm": "MD5", "Value": "b" * 32},
        ],
    },
    {
        "$id": "5",
        "Type": "process",
        "ProcessId": 4567,
        "CommandLine": "cmd.exe /c whoami & net user",
        "ImageFile": {"$ref": "6"},
        "ParentProcessId": 1234,
    },
    {
        "$id": "6",
        "Type": "file",
        "Name": "cmd.exe",
        "Directory": "C:\\Windows\\System32",
    },
    {
        "$id": "7",
        "Type": "url",
        "Url": "https://evil.example.com/payload",
    },
    {
        "$id": "8",
        "Type": "dns",
        "DomainName": "c2.malware.io",
        "IpAddresses": ["203.0.113.5"],
    },
    {
        "$id": "9",
        "Type": "filehash",
        "Algorithm": "SHA256",
        "Value": "c" * 64,
    },
    {
        "$id": "10",
        "Type": "mailbox",
        "MailboxPrimaryAddress": "ceo@contoso.com",
        "DisplayName": "CEO",
        "Upn": "ceo@contoso.com",
    },
])


class TestSentinelAccountParsing:
    def test_account_extracted(self):
        result = parse_alert_entities(SENTINEL_ENTITIES)
        assert len(result.accounts) == 1

    def test_account_upn(self):
        result = parse_alert_entities(SENTINEL_ENTITIES)
        assert result.accounts[0].primary_value == "john.doe@contoso.com"

    def test_account_properties(self):
        result = parse_alert_entities(SENTINEL_ENTITIES)
        props = result.accounts[0].properties
        assert props["name"] == "john.doe"
        assert props["aad_user_id"] == "aad-123"
        assert props["sid"] == "S-1-5-21-1234"
        assert props["is_domain_joined"] is True

    def test_account_source_id(self):
        result = parse_alert_entities(SENTINEL_ENTITIES)
        assert result.accounts[0].source_id == "1"


class TestSentinelHostParsing:
    def test_host_extracted(self):
        result = parse_alert_entities(SENTINEL_ENTITIES)
        assert len(result.hosts) == 1

    def test_host_fqdn(self):
        result = parse_alert_entities(SENTINEL_ENTITIES)
        assert result.hosts[0].primary_value == "WORKSTATION01.contoso.local"

    def test_host_properties(self):
        result = parse_alert_entities(SENTINEL_ENTITIES)
        props = result.hosts[0].properties
        assert props["hostname"] == "WORKSTATION01"
        assert props["os_family"] == "Windows"


class TestSentinelIpParsing:
    def test_ip_extracted(self):
        result = parse_alert_entities(SENTINEL_ENTITIES)
        assert len(result.ips) == 1

    def test_ip_value(self):
        result = parse_alert_entities(SENTINEL_ENTITIES)
        assert result.ips[0].primary_value == "10.0.0.42"

    def test_ip_geo_properties(self):
        result = parse_alert_entities(SENTINEL_ENTITIES)
        props = result.ips[0].properties
        assert props["geo_country"] == "US"
        assert props["geo_city"] == "Redmond"
        assert props["asn"] == 8075


class TestSentinelFileParsing:
    def test_files_extracted(self):
        result = parse_alert_entities(SENTINEL_ENTITIES)
        # Two file entities: malware.exe and cmd.exe
        assert len(result.files) == 2

    def test_file_name(self):
        result = parse_alert_entities(SENTINEL_ENTITIES)
        names = {f.primary_value for f in result.files}
        assert "malware.exe" in names
        assert "cmd.exe" in names

    def test_file_hashes_from_file(self):
        result = parse_alert_entities(SENTINEL_ENTITIES)
        # 2 hashes from malware.exe FileHashes + 1 standalone filehash entity
        sha_values = {h.primary_value for h in result.file_hashes}
        assert "a" * 64 in sha_values
        assert "b" * 32 in sha_values
        assert "c" * 64 in sha_values


class TestSentinelProcessParsing:
    def test_process_extracted(self):
        result = parse_alert_entities(SENTINEL_ENTITIES)
        assert len(result.processes) == 1

    def test_process_resolves_image_ref(self):
        result = parse_alert_entities(SENTINEL_ENTITIES)
        assert result.processes[0].primary_value == "cmd.exe"

    def test_process_preserves_command_line(self):
        result = parse_alert_entities(SENTINEL_ENTITIES)
        cmd = result.processes[0].properties["command_line"]
        # CommandLine should preserve special chars
        assert "&" in cmd


class TestSentinelUrlAndDns:
    def test_url_extracted(self):
        result = parse_alert_entities(SENTINEL_ENTITIES)
        assert len(result.urls) == 1
        assert result.urls[0].primary_value == "https://evil.example.com/payload"

    def test_dns_extracted(self):
        result = parse_alert_entities(SENTINEL_ENTITIES)
        assert len(result.dns_records) == 1
        assert result.dns_records[0].primary_value == "c2.malware.io"
        assert result.dns_records[0].properties["resolved_ips"] == ["203.0.113.5"]


class TestSentinelMailbox:
    def test_mailbox_extracted(self):
        result = parse_alert_entities(SENTINEL_ENTITIES)
        assert len(result.mailboxes) == 1
        assert result.mailboxes[0].primary_value == "ceo@contoso.com"
        assert result.mailboxes[0].properties["display_name"] == "CEO"


class TestSentinelRawIocs:
    def test_raw_iocs_populated(self):
        result = parse_alert_entities(SENTINEL_ENTITIES)
        iocs = result.raw_iocs
        assert "john.doe@contoso.com" in iocs
        assert "10.0.0.42" in iocs
        assert "a" * 64 in iocs
        assert "c2.malware.io" in iocs

    def test_no_parse_errors(self):
        result = parse_alert_entities(SENTINEL_ENTITIES)
        assert len(result.parse_errors) == 0
