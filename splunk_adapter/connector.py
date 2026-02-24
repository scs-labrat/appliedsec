"""Splunk connectors — Stories 16-5 & 16-6.

Two connection modes:

* **HEC (HTTP Event Collector)** — webhook-style: Splunk pushes events via POST
* **Saved-Search** — polling: connector pulls saved-search results via REST

Both connectors publish :class:`CanonicalAlert` JSON to the ``alerts.raw``
Kafka topic.
"""

from __future__ import annotations

import asyncio
import json
import logging
from typing import Any

from confluent_kafka import Producer

from sentinel_adapter.connector import retry_with_backoff
from splunk_adapter.adapter import SplunkAdapter

logger = logging.getLogger(__name__)

DEFAULT_POLL_INTERVAL = 60  # seconds


def _canonical_to_bytes(
    adapter: SplunkAdapter, raw_event: dict[str, Any]
) -> tuple[bytes | None, bytes] | None:
    """Map a raw event through the adapter and serialise.

    Returns ``(key_bytes, value_bytes)`` or ``None`` if the event is
    dropped (health-check).
    """
    canonical = adapter.to_canonical(raw_event)
    if canonical is None:
        return None

    key = canonical.alert_id.encode("utf-8") if canonical.alert_id else None
    value = json.dumps(canonical.model_dump(), default=str).encode("utf-8")
    return key, value


# =====================================================================
# Story 16-5: Splunk HEC Connector (HTTP Event Collector webhook)
# =====================================================================


def _create_hec_app(connector: Any) -> Any:
    """Build a FastAPI app for HEC webhook ingestion.

    Defined at module level to work around ``from __future__ import annotations``
    preventing FastAPI from resolving Request type hints inside closures.
    """
    from fastapi import FastAPI, HTTPException
    from starlette.requests import Request

    app = FastAPI(title="Splunk HEC Receiver", version="1.0.0")

    # Define handler without decorator first so we can fix annotations
    async def receive_event(request: Request) -> dict:
        auth = request.headers.get("Authorization", "")
        if auth != f"Splunk {connector.hec_token}":
            raise HTTPException(status_code=403, detail="Invalid HEC token")

        body = await request.json()
        events = body if isinstance(body, list) else [body]

        for event_wrapper in events:
            raw_event = event_wrapper.get("event", event_wrapper)
            pair = _canonical_to_bytes(connector.adapter, raw_event)
            if pair is None:
                continue
            key, value = pair
            connector.producer.produce(topic=connector.TOPIC, key=key, value=value)

        connector.producer.flush(timeout=5)
        return {"text": "Success", "code": "0"}

    # Fix deferred annotation from `from __future__ import annotations`
    receive_event.__annotations__ = {"request": Request, "return": dict}
    app.post("/services/collector/event")(receive_event)

    async def health() -> dict:
        return {"status": "ok"}

    health.__annotations__ = {"return": dict}
    app.get("/health")(health)

    return app


class SplunkHECConnector:
    """Lightweight FastAPI endpoint that receives Splunk HEC webhook POSTs.

    Validates ``Authorization: Splunk <token>``, maps events through
    :class:`SplunkAdapter`, and publishes to Kafka.
    """

    TOPIC = "alerts.raw"

    def __init__(
        self,
        kafka_bootstrap: str,
        hec_token: str,
        port: int = 8088,
    ) -> None:
        self.kafka_bootstrap = kafka_bootstrap
        self.hec_token = hec_token
        self.port = port
        self.adapter = SplunkAdapter()
        self.producer = Producer({"bootstrap.servers": kafka_bootstrap})
        self._app: Any = None

    def _build_app(self) -> Any:
        """Build the FastAPI app with HEC endpoint."""
        app = _create_hec_app(self)
        self._app = app
        return app

    async def subscribe(self) -> None:
        """Start the FastAPI/uvicorn server on the configured port."""
        import uvicorn  # type: ignore[import-untyped]

        app = self._build_app()
        config = uvicorn.Config(app, host="0.0.0.0", port=self.port, log_level="info")
        server = uvicorn.Server(config)
        await server.serve()

    def get_app(self) -> Any:
        """Return the FastAPI app (for testing with TestClient)."""
        if self._app is None:
            self._build_app()
        return self._app

    def stop(self) -> None:
        """No-op — uvicorn handles shutdown."""

    def close(self) -> None:
        self.producer.flush(timeout=5)


# =====================================================================
# Story 16-6: Splunk Saved-Search Connector (polling)
# =====================================================================


class SplunkSavedSearchConnector:
    """Polling-based Splunk ingestion via Splunk REST API saved searches.

    Periodically queries ``/services/saved/searches`` for dispatched
    results and publishes new events to Kafka.
    """

    TOPIC = "alerts.raw"

    def __init__(
        self,
        splunk_host: str,
        splunk_token: str,
        kafka_bootstrap: str,
        poll_interval: int = DEFAULT_POLL_INTERVAL,
    ) -> None:
        self.splunk_host = splunk_host.rstrip("/")
        self.splunk_token = splunk_token
        self.poll_interval = poll_interval
        self.adapter = SplunkAdapter()
        self.producer = Producer({"bootstrap.servers": kafka_bootstrap})
        self._running = False
        self._last_dispatch_time: str | None = None

    async def subscribe(self) -> None:
        """Begin polling loop."""
        self._running = True
        logger.info(
            "Splunk Saved-Search connector started (host=%s, interval=%ds)",
            self.splunk_host, self.poll_interval,
        )
        while self._running:
            try:
                await retry_with_backoff(self._poll_once)
            except Exception as exc:
                logger.error("Polling failed after retries: %s", exc)
            await asyncio.sleep(self.poll_interval)

    async def _poll_once(self) -> None:
        """Query Splunk REST API for saved-search results."""
        import aiohttp  # type: ignore[import-untyped]

        headers = {
            "Authorization": f"Bearer {self.splunk_token}",
            "Content-Type": "application/json",
        }

        url = f"{self.splunk_host}/services/saved/searches"
        params = {"output_mode": "json", "count": "100"}

        async with aiohttp.ClientSession() as session:
            async with session.get(url, params=params, headers=headers, ssl=False) as resp:
                resp.raise_for_status()
                result = await resp.json()

        entries = result.get("entry", [])
        latest_dispatch = self._last_dispatch_time

        for entry in entries:
            content = entry.get("content", {})
            dispatch_time = content.get("dispatch.latest_time", "")

            # Filter by last dispatch time
            if self._last_dispatch_time and dispatch_time <= self._last_dispatch_time:
                continue

            # Process the notable event
            raw_event = content
            raw_event["search_name"] = entry.get("name", "")
            pair = _canonical_to_bytes(self.adapter, raw_event)
            if pair is None:
                continue
            key, value = pair
            self.producer.produce(topic=self.TOPIC, key=key, value=value)

            if dispatch_time and (
                latest_dispatch is None or dispatch_time > latest_dispatch
            ):
                latest_dispatch = dispatch_time

        self.producer.flush(timeout=5)
        if latest_dispatch:
            self._last_dispatch_time = latest_dispatch

    def stop(self) -> None:
        """Signal the polling loop to stop."""
        self._running = False

    def close(self) -> None:
        """Stop and flush any pending Kafka messages."""
        self.stop()
        self.producer.flush(timeout=5)
