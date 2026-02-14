"""Tests for EntityParserService Kafka consumer/producer — Stories 3.2 & 3.3."""

from __future__ import annotations

import json
from unittest.mock import MagicMock, patch

import pytest

from entity_parser.service import (
    DEFAULT_GROUP,
    TOPIC_DLQ,
    TOPIC_NORMALIZED,
    TOPIC_RAW,
    EntityParserService,
    _entity_to_dict,
)
from shared.schemas.entity import EntityType, NormalizedEntity


# ---- helpers ----------------------------------------------------------------

def _make_alert(**overrides) -> dict:
    base = {
        "alert_id": "alert-001",
        "source": "sentinel",
        "timestamp": "2025-01-15T10:00:00Z",
        "title": "Test Alert",
        "description": "A test alert",
        "severity": "high",
        "tactics": ["InitialAccess"],
        "techniques": ["T1190"],
        "entities_raw": json.dumps([
            {"$id": "1", "Type": "ip", "Address": "10.0.0.1"},
        ]),
        "product": "Sentinel",
        "tenant_id": "t-001",
        "raw_payload": {},
    }
    base.update(overrides)
    return base


# ---- test entity serialization ---------------------------------------------

class TestEntityToDict:
    def test_serializes_entity(self):
        entity = NormalizedEntity(
            entity_type=EntityType.IP,
            primary_value="10.0.0.1",
            properties={"geo_country": "US"},
            confidence=0.9,
            source_id="1",
        )
        d = _entity_to_dict(entity)
        assert d["entity_type"] == "ip"
        assert d["primary_value"] == "10.0.0.1"
        assert d["properties"]["geo_country"] == "US"
        assert d["confidence"] == 0.9
        assert d["source_id"] == "1"


# ---- test service construction ---------------------------------------------

class TestServiceConstruction:
    @patch("entity_parser.service.Producer")
    @patch("entity_parser.service.Consumer")
    def test_creates_consumer_with_correct_config(self, mock_consumer_cls, mock_producer_cls):
        svc = EntityParserService("localhost:9092")
        call_args = mock_consumer_cls.call_args[0][0]
        assert call_args["bootstrap.servers"] == "localhost:9092"
        assert call_args["group.id"] == DEFAULT_GROUP
        assert call_args["enable.auto.commit"] is False
        assert call_args["auto.offset.reset"] == "earliest"

    @patch("entity_parser.service.Producer")
    @patch("entity_parser.service.Consumer")
    def test_custom_consumer_group(self, mock_consumer_cls, mock_producer_cls):
        svc = EntityParserService("localhost:9092", consumer_group="custom-group")
        call_args = mock_consumer_cls.call_args[0][0]
        assert call_args["group.id"] == "custom-group"


# ---- test process_message --------------------------------------------------

class TestProcessMessage:
    @patch("entity_parser.service.Producer")
    @patch("entity_parser.service.Consumer")
    def test_parses_valid_alert(self, mock_consumer_cls, mock_producer_cls):
        svc = EntityParserService("localhost:9092")
        alert = _make_alert()
        raw = json.dumps(alert).encode("utf-8")

        enriched = svc.process_message(raw)

        assert "parsed_entities" in enriched
        pe = enriched["parsed_entities"]
        assert len(pe["ips"]) == 1
        assert pe["ips"][0]["primary_value"] == "10.0.0.1"

    @patch("entity_parser.service.Producer")
    @patch("entity_parser.service.Consumer")
    def test_rejects_invalid_alert(self, mock_consumer_cls, mock_producer_cls):
        svc = EntityParserService("localhost:9092")
        bad_data = json.dumps({"not": "an alert"}).encode("utf-8")

        with pytest.raises(Exception):
            svc.process_message(bad_data)

    @patch("entity_parser.service.Producer")
    @patch("entity_parser.service.Consumer")
    def test_raw_iocs_in_output(self, mock_consumer_cls, mock_producer_cls):
        svc = EntityParserService("localhost:9092")
        alert = _make_alert()
        enriched = svc.process_message(json.dumps(alert).encode("utf-8"))

        assert "10.0.0.1" in enriched["parsed_entities"]["raw_iocs"]

    @patch("entity_parser.service.Producer")
    @patch("entity_parser.service.Consumer")
    def test_alert_id_preserved(self, mock_consumer_cls, mock_producer_cls):
        svc = EntityParserService("localhost:9092")
        alert = _make_alert(alert_id="unique-123")
        enriched = svc.process_message(json.dumps(alert).encode("utf-8"))

        assert enriched["alert_id"] == "unique-123"


# ---- test DLQ routing ------------------------------------------------------

class TestDlqRouting:
    @patch("entity_parser.service.Producer")
    @patch("entity_parser.service.Consumer")
    def test_sends_bad_message_to_dlq(self, mock_consumer_cls, mock_producer_cls):
        mock_producer = MagicMock()
        mock_producer_cls.return_value = mock_producer

        svc = EntityParserService("localhost:9092")
        bad_value = b"not json at all"

        svc._send_to_dlq(bad_value, "JSON decode error")

        mock_producer.produce.assert_called_once()
        call_kwargs = mock_producer.produce.call_args[1]
        assert call_kwargs["topic"] == TOPIC_DLQ

        payload = json.loads(call_kwargs["value"])
        assert "not json at all" in payload["original"]
        assert "JSON decode error" in payload["error"]


# ---- test start / stop / close ---------------------------------------------

class TestServiceLifecycle:
    @patch("entity_parser.service.Producer")
    @patch("entity_parser.service.Consumer")
    def test_start_subscribes(self, mock_consumer_cls, mock_producer_cls):
        mock_consumer = MagicMock()
        mock_consumer_cls.return_value = mock_consumer

        svc = EntityParserService("localhost:9092")
        svc.start()

        mock_consumer.subscribe.assert_called_once_with([TOPIC_RAW])
        assert svc._running is True

    @patch("entity_parser.service.Producer")
    @patch("entity_parser.service.Consumer")
    def test_stop_sets_flag(self, mock_consumer_cls, mock_producer_cls):
        svc = EntityParserService("localhost:9092")
        svc.start()
        svc.stop()

        assert svc._running is False

    @patch("entity_parser.service.Producer")
    @patch("entity_parser.service.Consumer")
    def test_close_flushes_and_closes(self, mock_consumer_cls, mock_producer_cls):
        mock_consumer = MagicMock()
        mock_producer = MagicMock()
        mock_consumer_cls.return_value = mock_consumer
        mock_producer_cls.return_value = mock_producer

        svc = EntityParserService("localhost:9092")
        svc.close()

        mock_producer.flush.assert_called_once()
        mock_consumer.close.assert_called_once()


# ---- test constants ---------------------------------------------------------

class TestConstants:
    def test_topic_names(self):
        assert TOPIC_RAW == "alerts.raw"
        assert TOPIC_NORMALIZED == "alerts.normalized"
        assert TOPIC_DLQ == "alerts.raw.dlq"

    def test_default_group(self):
        assert DEFAULT_GROUP == "aluskort.entity-parser"
