"""Elastic connector — Story 16-2.

Polls Elasticsearch ``.siem-signals-*`` index for new detection signals
and publishes :class:`CanonicalAlert` JSON to the ``alerts.raw`` Kafka topic.
"""

from __future__ import annotations

import asyncio
import json
import logging
from typing import Any

from confluent_kafka import Producer

from elastic_adapter.adapter import ElasticAdapter
from sentinel_adapter.connector import retry_with_backoff

logger = logging.getLogger(__name__)

DEFAULT_POLL_INTERVAL = 30  # seconds
SIGNALS_INDEX = ".siem-signals-*"


def _canonical_to_bytes(
    adapter: ElasticAdapter, raw_event: dict[str, Any]
) -> tuple[bytes | None, bytes] | None:
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


class ElasticConnector:
    """Polling-based Elastic SIEM ingestion via Elasticsearch REST API.

    Queries the ``.siem-signals-*`` index for new signals using a
    ``range`` filter on ``@timestamp``.
    """

    TOPIC = "alerts.raw"

    def __init__(
        self,
        es_host: str,
        es_api_key: str,
        kafka_bootstrap: str,
        poll_interval: int = DEFAULT_POLL_INTERVAL,
    ) -> None:
        self.es_host = es_host.rstrip("/")
        self.es_api_key = es_api_key
        self.poll_interval = poll_interval
        self.adapter = ElasticAdapter()
        self.producer = Producer({"bootstrap.servers": kafka_bootstrap})
        self._running = False
        self._last_poll_ts: str | None = None

    async def subscribe(self) -> None:
        """Begin polling loop."""
        self._running = True
        logger.info(
            "Elastic connector started (host=%s, interval=%ds)",
            self.es_host, self.poll_interval,
        )
        while self._running:
            try:
                await retry_with_backoff(self._poll_once)
            except Exception as exc:
                logger.error("Polling failed after retries: %s", exc)
            await asyncio.sleep(self.poll_interval)

    async def _poll_once(self) -> None:
        """Query .siem-signals-* with range filter on @timestamp."""
        import aiohttp  # type: ignore[import-untyped]

        headers = {
            "Authorization": f"ApiKey {self.es_api_key}",
            "Content-Type": "application/json",
        }

        # Build range filter
        if self._last_poll_ts:
            range_filter = {"range": {"@timestamp": {"gt": self._last_poll_ts}}}
        else:
            range_filter = {"range": {"@timestamp": {"gte": "now-5m"}}}

        body = {
            "query": {"bool": {"filter": [range_filter]}},
            "sort": [{"@timestamp": "asc"}],
            "size": 100,
        }

        url = f"{self.es_host}/{SIGNALS_INDEX}/_search"

        async with aiohttp.ClientSession() as session:
            async with session.post(url, json=body, headers=headers) as resp:
                resp.raise_for_status()
                result = await resp.json()

        hits = result.get("hits", {}).get("hits", [])
        if not hits:
            return

        latest_ts = self._last_poll_ts
        for hit in hits:
            raw_event = hit.get("_source", {})
            pair = _canonical_to_bytes(self.adapter, raw_event)
            if pair is None:
                continue
            key, value = pair
            self.producer.produce(topic=self.TOPIC, key=key, value=value)

            ts = raw_event.get("@timestamp", "")
            if ts and (latest_ts is None or ts > latest_ts):
                latest_ts = ts

        self.producer.flush(timeout=5)
        if latest_ts:
            self._last_poll_ts = latest_ts

    def stop(self) -> None:
        """Signal the polling loop to stop."""
        self._running = False

    def close(self) -> None:
        """Stop and flush any pending Kafka messages."""
        self.stop()
        self.producer.flush(timeout=5)
