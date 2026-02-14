"""Tests for EntityType, NormalizedEntity, AlertEntities — AC-1.1.8."""

from shared.schemas.entity import AlertEntities, EntityType, NormalizedEntity


class TestEntityTypeEnum:
    """Test EntityType has all 15 members."""

    def test_enum_has_fifteen_members(self):
        assert len(list(EntityType)) == 15

    def test_all_expected_members_present(self):
        expected = {
            "ACCOUNT",
            "HOST",
            "IP",
            "FILE",
            "PROCESS",
            "URL",
            "DNS",
            "FILEHASH",
            "MAILBOX",
            "MAILMESSAGE",
            "REGISTRY_KEY",
            "REGISTRY_VALUE",
            "SECURITY_GROUP",
            "CLOUD_APPLICATION",
            "MALWARE",
        }
        assert {m.name for m in EntityType} == expected

    def test_entity_type_values(self):
        assert EntityType.ACCOUNT.value == "account"
        assert EntityType.REGISTRY_KEY.value == "registry-key"
        assert EntityType.CLOUD_APPLICATION.value == "cloud-application"


class TestNormalizedEntity:
    """AC-1.1.8: NormalizedEntity defaults confidence to 1.0."""

    def test_default_confidence(self):
        entity = NormalizedEntity(
            entity_type=EntityType.IP,
            primary_value="10.0.0.1",
        )
        assert entity.confidence == 1.0

    def test_default_properties_empty(self):
        entity = NormalizedEntity(
            entity_type=EntityType.HOST,
            primary_value="WKSTN-042",
        )
        assert entity.properties == {}

    def test_default_source_id_none(self):
        entity = NormalizedEntity(
            entity_type=EntityType.ACCOUNT,
            primary_value="admin@contoso.com",
        )
        assert entity.source_id is None

    def test_custom_confidence(self):
        entity = NormalizedEntity(
            entity_type=EntityType.URL,
            primary_value="http://evil.example.com",
            confidence=0.75,
            source_id="parser-v2",
        )
        assert entity.confidence == 0.75
        assert entity.source_id == "parser-v2"


class TestAlertEntities:
    """AlertEntities defaults all lists to empty."""

    def test_defaults_all_empty(self):
        ae = AlertEntities()
        assert ae.accounts == []
        assert ae.hosts == []
        assert ae.ips == []
        assert ae.files == []
        assert ae.processes == []
        assert ae.urls == []
        assert ae.dns_records == []
        assert ae.file_hashes == []
        assert ae.mailboxes == []
        assert ae.other == []
        assert ae.raw_iocs == []
        assert ae.parse_errors == []

    def test_add_entity(self):
        entity = NormalizedEntity(
            entity_type=EntityType.IP,
            primary_value="192.168.1.1",
        )
        ae = AlertEntities(ips=[entity])
        assert len(ae.ips) == 1
        assert ae.ips[0].primary_value == "192.168.1.1"
