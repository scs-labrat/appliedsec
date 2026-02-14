"""Sentinel connectors — Story 4.2.

Two connection modes:
* **Event Hub** — near-real-time via Azure Event Hubs SDK
* **Log Analytics API** — polling via REST (30 s default interval)

Both connectors publish :class:`CanonicalAlert` JSON to the ``alerts.raw``
Kafka topic.
"""

from __future__ import annotations

import asyncio
import json
import logging
from typing import Any

from confluent_kafka import Producer

from sentinel_adapter.adapter import SentinelAdapter

logger = logging.getLogger(__name__)

DEFAULT_POLL_INTERVAL = 30  # seconds
MAX_RETRIES = 3
BASE_DELAY = 1  # seconds


async def retry_with_backoff(
    coro_func: Any,
    *args: Any,
    max_retries: int = MAX_RETRIES,
    base_delay: float = BASE_DELAY,
    **kwargs: Any,
) -> Any:
    """Exponential-backoff wrapper: 1 s → 2 s → 4 s."""
    for attempt in range(max_retries):
        try:
            return await coro_func(*args, **kwargs)
        except Exception as exc:
            if attempt < max_retries - 1:
                delay = base_delay * (2 ** attempt)
                logger.warning(
                    "Attempt %d/%d failed, retrying in %.1fs: %s",
                    attempt + 1, max_retries, delay, exc,
                )
                await asyncio.sleep(delay)
            else:
                logger.error("All %d attempts failed: %s", max_retries, exc)
                raise


def _canonical_to_bytes(adapter: SentinelAdapter, raw_event: dict[str, Any]) -> tuple[bytes | None, bytes] | None:
    """Map a raw event through the adapter and serialise.

    Returns ``(key_bytes, value_bytes)`` or ``None`` if the event is
    dropped (heartbeat).
    """
    canonical = adapter.to_canonical(raw_event)
    if canonical is None:
        return None

    key = canonical.alert_id.encode("utf-8") if canonical.alert_id else None
    value = json.dumps(canonical.model_dump(), default=str).encode("utf-8")
    return key, value


class SentinelEventHubConnector:
    """Near-real-time Sentinel ingestion via Azure Event Hubs.

    Requires the ``azure-eventhub`` package (optional dependency).
    """

    TOPIC = "alerts.raw"

    def __init__(
        self,
        event_hub_connection_string: str,
        kafka_bootstrap: str,
        consumer_group: str = "$Default",
    ) -> None:
        self.connection_string = event_hub_connection_string
        self.consumer_group = consumer_group
        self.adapter = SentinelAdapter()
        self.producer = Producer({"bootstrap.servers": kafka_bootstrap})
        self._running = False

    async def subscribe(self) -> None:
        """Connect to Event Hub and begin forwarding events."""
        # Import lazily so the rest of the codebase doesn't require azure-eventhub
        from azure.eventhub.aio import EventHubConsumerClient  # type: ignore[import-untyped]

        client = EventHubConsumerClient.from_connection_string(
            self.connection_string,
            consumer_group=self.consumer_group,
        )
        self._running = True

        async with client:
            await client.receive_batch(
                on_event_batch=self._on_event_batch,
                starting_position="-1",
            )

    async def _on_event_batch(self, partition_context: Any, events: list[Any]) -> None:
        for event in events:
            try:
                raw_event = json.loads(event.body_as_str())
                pair = _canonical_to_bytes(self.adapter, raw_event)
                if pair is None:
                    continue
                key, value = pair
                self.producer.produce(topic=self.TOPIC, key=key, value=value)
            except Exception as exc:
                logger.error("Error processing Event Hub event: %s", exc, exc_info=True)

        self.producer.flush(timeout=5)
        await partition_context.update_checkpoint()

    def stop(self) -> None:
        self._running = False

    def close(self) -> None:
        self.stop()
        self.producer.flush(timeout=5)


class SentinelLogAnalyticsConnector:
    """Polling-based Sentinel ingestion via Log Analytics REST API.

    Requires the ``aiohttp`` package (optional dependency).
    """

    TOPIC = "alerts.raw"

    def __init__(
        self,
        workspace_id: str,
        credential: Any,
        kafka_bootstrap: str,
        poll_interval: int = DEFAULT_POLL_INTERVAL,
    ) -> None:
        self.workspace_id = workspace_id
        self.credential = credential  # Azure TokenCredential
        self.poll_interval = poll_interval
        self.adapter = SentinelAdapter()
        self.producer = Producer({"bootstrap.servers": kafka_bootstrap})
        self._running = False
        self._last_poll_ts: str | None = None

    async def subscribe(self) -> None:
        """Begin polling loop."""
        self._running = True
        logger.info(
            "Log Analytics connector started (workspace=%s, interval=%ds)",
            self.workspace_id, self.poll_interval,
        )
        while self._running:
            try:
                await retry_with_backoff(self._poll_once)
            except Exception as exc:
                logger.error("Polling failed after retries: %s", exc)
            await asyncio.sleep(self.poll_interval)

    async def _poll_once(self) -> None:
        import aiohttp  # type: ignore[import-untyped]

        token = self.credential.get_token("https://api.loganalytics.io/.default")
        headers = {
            "Authorization": f"Bearer {token.token}",
            "Content-Type": "application/json",
        }

        time_filter = (
            f"| where TimeGenerated > datetime({self._last_poll_ts})"
            if self._last_poll_ts
            else "| where TimeGenerated > ago(5m)"
        )

        body = {
            "query": (
                "SecurityAlert "
                + time_filter
                + " | project SystemAlertId, TimeGenerated, AlertName, "
                "Description, Severity, Tactics, Techniques, Entities, "
                "ProductName, TenantId"
            ),
        }

        async with aiohttp.ClientSession() as session:
            url = f"https://api.loganalytics.io/v1/workspaces/{self.workspace_id}/query"
            async with session.post(url, json=body, headers=headers) as resp:
                resp.raise_for_status()
                result = await resp.json()

        tables = result.get("tables", [])
        if not tables:
            return

        columns = [c["name"] for c in tables[0].get("columns", [])]
        latest_ts = self._last_poll_ts

        for row in tables[0].get("rows", []):
            raw_event = dict(zip(columns, row))
            pair = _canonical_to_bytes(self.adapter, raw_event)
            if pair is None:
                continue
            key, value = pair
            self.producer.produce(topic=self.TOPIC, key=key, value=value)

            ts = raw_event.get("TimeGenerated", "")
            if ts and (latest_ts is None or ts > latest_ts):
                latest_ts = ts

        self.producer.flush(timeout=5)
        if latest_ts:
            self._last_poll_ts = latest_ts

    def stop(self) -> None:
        self._running = False

    def close(self) -> None:
        self.stop()
        self.producer.flush(timeout=5)
