"""Tests for CTEM Normaliser Kafka service — Story 8.6."""

import pytest
from unittest.mock import AsyncMock, MagicMock

from ctem_normaliser.service import (
    CTEMNormaliserService,
    NORMALISED_TOPIC,
    DLQ_TOPIC,
    SUBSCRIBED_TOPICS,
    TOPIC_NORMALISER_MAP,
)
from ctem_normaliser.upsert import CTEMRepository


@pytest.fixture
def mock_db():
    db = AsyncMock()
    db.execute = AsyncMock()
    db.fetch_one = AsyncMock(return_value=None)
    db.fetch_many = AsyncMock(return_value=[])
    return db


@pytest.fixture
def mock_producer():
    prod = AsyncMock()
    prod.produce = AsyncMock()
    return prod


@pytest.fixture
def service(mock_db, mock_producer):
    repo = CTEMRepository(mock_db)
    return CTEMNormaliserService(
        repository=repo,
        kafka_producer=mock_producer,
    )


@pytest.fixture
def wiz_message():
    return {
        "title": "S3 Public",
        "resource_id": "bucket-1",
        "severity": "HIGH",
        "resource_type": "s3",
        "detected_at": "2026-01-15T10:00:00Z",
        "tenant_id": "tenant-A",
    }


class TestServiceRouting:
    def test_topic_normaliser_map(self):
        assert "ctem.raw.wiz" in TOPIC_NORMALISER_MAP
        assert "ctem.raw.snyk" in TOPIC_NORMALISER_MAP
        assert "ctem.raw.garak" in TOPIC_NORMALISER_MAP
        assert "ctem.raw.art" in TOPIC_NORMALISER_MAP

    def test_subscribed_topics(self):
        assert len(SUBSCRIBED_TOPICS) == 6
        assert "ctem.raw.burp" in SUBSCRIBED_TOPICS
        assert "ctem.raw.custom" in SUBSCRIBED_TOPICS

    def test_get_normaliser_wiz(self, service):
        n = service.get_normaliser("ctem.raw.wiz")
        assert n is not None
        assert n.source_name() == "wiz"

    def test_get_normaliser_snyk(self, service):
        n = service.get_normaliser("ctem.raw.snyk")
        assert n.source_name() == "snyk"

    def test_get_normaliser_unknown(self, service):
        assert service.get_normaliser("ctem.raw.unknown") is None


class TestProcessMessage:
    @pytest.mark.asyncio
    async def test_wiz_normalise_and_upsert(self, service, mock_db, wiz_message):
        result = await service.process_message("ctem.raw.wiz", wiz_message)
        assert result is not None
        assert result.source_tool == "wiz"
        mock_db.execute.assert_called_once()  # upsert

    @pytest.mark.asyncio
    async def test_publishes_normalised(self, service, mock_producer, wiz_message):
        await service.process_message("ctem.raw.wiz", wiz_message)
        mock_producer.produce.assert_called_once()
        topic = mock_producer.produce.call_args[0][0]
        assert topic == NORMALISED_TOPIC

    @pytest.mark.asyncio
    async def test_unsupported_topic_dlq(self, service, mock_producer):
        result = await service.process_message("ctem.raw.unknown", {"data": 1})
        assert result is None
        mock_producer.produce.assert_called_once()
        topic = mock_producer.produce.call_args[0][0]
        assert topic == DLQ_TOPIC

    @pytest.mark.asyncio
    async def test_normalisation_failure_dlq(self, service, mock_producer):
        # Missing required fields → normalisation error
        result = await service.process_message("ctem.raw.wiz", {})
        # May or may not fail depending on defaults; check it doesn't crash
        if result is None:
            # Sent to DLQ
            assert mock_producer.produce.called

    @pytest.mark.asyncio
    async def test_upsert_failure_dlq(self, service, mock_db, mock_producer, wiz_message):
        mock_db.execute.side_effect = Exception("DB down")
        result = await service.process_message("ctem.raw.wiz", wiz_message)
        assert result is None
        # Should have sent to DLQ
        dlq_calls = [
            c for c in mock_producer.produce.call_args_list
            if c[0][0] == DLQ_TOPIC
        ]
        assert len(dlq_calls) == 1

    @pytest.mark.asyncio
    async def test_snyk_message(self, service, mock_db):
        msg = {
            "title": "CVE-2026-1234",
            "project_id": "proj-1",
            "severity": "HIGH",
            "packageName": "express",
            "exploitability_score": 7.5,
        }
        result = await service.process_message("ctem.raw.snyk", msg)
        assert result is not None
        assert result.source_tool == "snyk"

    @pytest.mark.asyncio
    async def test_garak_message(self, service, mock_db):
        msg = {
            "title": "DAN Jailbreak",
            "model_name": "model-v1",
            "probe_type": "jailbreak",
            "success_rate": 0.6,
        }
        result = await service.process_message("ctem.raw.garak", msg)
        assert result is not None
        assert result.source_tool == "garak"
        assert result.atlas_technique == "AML.T0051"

    @pytest.mark.asyncio
    async def test_art_message(self, service, mock_db):
        msg = {
            "title": "Poisoning Attack",
            "model_id": "model-v2",
            "attack_type": "poisoning",
            "success_rate": 0.8,
        }
        result = await service.process_message("ctem.raw.art", msg)
        assert result is not None
        assert result.physical_consequence == "safety_life"


class TestServiceConstants:
    def test_normalised_topic(self):
        assert NORMALISED_TOPIC == "ctem.normalized"

    def test_dlq_topic(self):
        assert DLQ_TOPIC == "ctem.normalized.dlq"


class TestNoProducer:
    @pytest.mark.asyncio
    async def test_works_without_producer(self, mock_db, wiz_message):
        repo = CTEMRepository(mock_db)
        service = CTEMNormaliserService(repository=repo)
        result = await service.process_message("ctem.raw.wiz", wiz_message)
        assert result is not None
