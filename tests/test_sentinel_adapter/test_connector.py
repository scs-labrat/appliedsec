"""Tests for Sentinel connectors and retry logic — Story 4.2."""

from __future__ import annotations

import json
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from sentinel_adapter.connector import (
    BASE_DELAY,
    DEFAULT_POLL_INTERVAL,
    MAX_RETRIES,
    SentinelEventHubConnector,
    SentinelLogAnalyticsConnector,
    _canonical_to_bytes,
    retry_with_backoff,
)
from sentinel_adapter.adapter import SentinelAdapter


# ---- retry_with_backoff ----------------------------------------------------

class TestRetryWithBackoff:
    @pytest.mark.asyncio
    async def test_succeeds_first_try(self):
        func = AsyncMock(return_value="ok")
        result = await retry_with_backoff(func)
        assert result == "ok"
        assert func.call_count == 1

    @pytest.mark.asyncio
    async def test_retries_on_failure(self):
        func = AsyncMock(side_effect=[Exception("fail"), "ok"])
        with patch("sentinel_adapter.connector.asyncio.sleep", new_callable=AsyncMock):
            result = await retry_with_backoff(func, max_retries=2, base_delay=0)
        assert result == "ok"
        assert func.call_count == 2

    @pytest.mark.asyncio
    async def test_raises_after_max_retries(self):
        func = AsyncMock(side_effect=Exception("always fails"))
        with patch("sentinel_adapter.connector.asyncio.sleep", new_callable=AsyncMock):
            with pytest.raises(Exception, match="always fails"):
                await retry_with_backoff(func, max_retries=3, base_delay=0)
        assert func.call_count == 3

    def test_constants(self):
        assert MAX_RETRIES == 3
        assert BASE_DELAY == 1


# ---- _canonical_to_bytes --------------------------------------------------

class TestCanonicalToBytes:
    def test_valid_event(self):
        adapter = SentinelAdapter()
        event = {
            "SystemAlertId": "test-001",
            "TimeGenerated": "2026-02-14T10:00:00Z",
            "AlertName": "Test",
            "Description": "desc",
            "Severity": "High",
            "Entities": "[]",
        }
        result = _canonical_to_bytes(adapter, event)
        assert result is not None
        key, value = result
        assert key == b"test-001"
        data = json.loads(value)
        assert data["alert_id"] == "test-001"
        assert data["severity"] == "high"

    def test_heartbeat_returns_none(self):
        adapter = SentinelAdapter()
        event = {
            "SystemAlertId": "hb-001",
            "AlertName": "Heartbeat",
            "TimeGenerated": "2026-02-14T10:00:00Z",
        }
        assert _canonical_to_bytes(adapter, event) is None


# ---- SentinelEventHubConnector construction --------------------------------

class TestEventHubConnectorConstruction:
    @patch("sentinel_adapter.connector.Producer")
    def test_creates_with_connection_string(self, mock_producer_cls):
        conn = SentinelEventHubConnector(
            event_hub_connection_string="Endpoint=sb://test.servicebus.windows.net/",
            kafka_bootstrap="localhost:9092",
        )
        assert conn.connection_string == "Endpoint=sb://test.servicebus.windows.net/"
        assert conn.consumer_group == "$Default"
        assert isinstance(conn.adapter, SentinelAdapter)

    @patch("sentinel_adapter.connector.Producer")
    def test_custom_consumer_group(self, mock_producer_cls):
        conn = SentinelEventHubConnector(
            event_hub_connection_string="Endpoint=...",
            kafka_bootstrap="localhost:9092",
            consumer_group="custom-cg",
        )
        assert conn.consumer_group == "custom-cg"

    @patch("sentinel_adapter.connector.Producer")
    def test_stop_and_close(self, mock_producer_cls):
        mock_producer = MagicMock()
        mock_producer_cls.return_value = mock_producer

        conn = SentinelEventHubConnector(
            event_hub_connection_string="Endpoint=...",
            kafka_bootstrap="localhost:9092",
        )
        conn.close()
        mock_producer.flush.assert_called()
        assert conn._running is False


# ---- SentinelLogAnalyticsConnector construction ----------------------------

class TestLogAnalyticsConnectorConstruction:
    @patch("sentinel_adapter.connector.Producer")
    def test_creates_with_workspace_id(self, mock_producer_cls):
        cred = MagicMock()
        conn = SentinelLogAnalyticsConnector(
            workspace_id="ws-123",
            credential=cred,
            kafka_bootstrap="localhost:9092",
        )
        assert conn.workspace_id == "ws-123"
        assert conn.poll_interval == DEFAULT_POLL_INTERVAL

    @patch("sentinel_adapter.connector.Producer")
    def test_custom_poll_interval(self, mock_producer_cls):
        conn = SentinelLogAnalyticsConnector(
            workspace_id="ws-123",
            credential=MagicMock(),
            kafka_bootstrap="localhost:9092",
            poll_interval=60,
        )
        assert conn.poll_interval == 60

    @patch("sentinel_adapter.connector.Producer")
    def test_stop_and_close(self, mock_producer_cls):
        mock_producer = MagicMock()
        mock_producer_cls.return_value = mock_producer

        conn = SentinelLogAnalyticsConnector(
            workspace_id="ws-123",
            credential=MagicMock(),
            kafka_bootstrap="localhost:9092",
        )
        conn.close()
        mock_producer.flush.assert_called()
        assert conn._running is False

    def test_default_poll_interval(self):
        assert DEFAULT_POLL_INTERVAL == 30
