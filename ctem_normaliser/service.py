"""CTEM Normaliser Kafka service — Story 8.6.

Consumes from per-source ctem.raw.* topics, routes to the correct
normaliser, upserts to Postgres, and publishes to ctem.normalized.
"""

from __future__ import annotations

import json
import logging
from typing import Any

from ctem_normaliser.base import BaseNormaliser
from ctem_normaliser.models import CTEMExposure
from ctem_normaliser.upsert import CTEMRepository
from ctem_normaliser.wiz import WizNormaliser
from ctem_normaliser.snyk import SnykNormaliser
from ctem_normaliser.garak import GarakNormaliser
from ctem_normaliser.art import ARTNormaliser

logger = logging.getLogger(__name__)

# Topic → normaliser mapping
TOPIC_NORMALISER_MAP: dict[str, type[BaseNormaliser]] = {
    "ctem.raw.wiz": WizNormaliser,
    "ctem.raw.snyk": SnykNormaliser,
    "ctem.raw.garak": GarakNormaliser,
    "ctem.raw.art": ARTNormaliser,
}

NORMALISED_TOPIC = "ctem.normalized"
DLQ_TOPIC = "ctem.normalized.dlq"

SUBSCRIBED_TOPICS = [
    "ctem.raw.wiz",
    "ctem.raw.snyk",
    "ctem.raw.garak",
    "ctem.raw.art",
    "ctem.raw.burp",
    "ctem.raw.custom",
]


class CTEMNormaliserService:
    """Kafka consumer service that normalises CTEM findings."""

    def __init__(
        self,
        repository: CTEMRepository,
        kafka_consumer: Any | None = None,
        kafka_producer: Any | None = None,
        neo4j_client: Any | None = None,
    ) -> None:
        self._repo = repository
        self._consumer = kafka_consumer
        self._producer = kafka_producer
        self._neo4j = neo4j_client
        self._normalisers: dict[str, BaseNormaliser] = {}
        self._init_normalisers()

    def _init_normalisers(self) -> None:
        """Instantiate normalisers with optional dependencies."""
        self._normalisers = {
            "ctem.raw.wiz": WizNormaliser(neo4j_client=self._neo4j),
            "ctem.raw.snyk": SnykNormaliser(),
            "ctem.raw.garak": GarakNormaliser(),
            "ctem.raw.art": ARTNormaliser(),
        }

    def get_normaliser(self, topic: str) -> BaseNormaliser | None:
        """Get the normaliser for a given topic."""
        return self._normalisers.get(topic)

    async def process_message(
        self,
        topic: str,
        raw_data: dict[str, Any],
    ) -> CTEMExposure | None:
        """Normalise a single message, upsert, and publish.

        Returns the normalised exposure, or None on failure.
        """
        normaliser = self.get_normaliser(topic)
        if normaliser is None:
            # Unsupported tool — route to generic handling or DLQ
            logger.warning("No normaliser for topic %s", topic)
            await self._send_to_dlq(topic, raw_data, "unsupported_topic")
            return None

        try:
            exposure = normaliser.normalise(raw_data)
        except Exception as exc:
            logger.error(
                "Normalisation failed for %s: %s", topic, exc,
                exc_info=True,
            )
            await self._send_to_dlq(topic, raw_data, str(exc))
            return None

        # Upsert to Postgres
        try:
            await self._repo.upsert(exposure)
        except Exception as exc:
            logger.error(
                "Upsert failed for %s: %s", exposure.exposure_key, exc,
                exc_info=True,
            )
            await self._send_to_dlq(topic, raw_data, f"upsert_failed: {exc}")
            return None

        # Publish to normalised topic
        await self._publish_normalised(exposure)

        return exposure

    async def _publish_normalised(self, exposure: CTEMExposure) -> None:
        """Publish normalised exposure to ctem.normalized topic."""
        if self._producer is None:
            return
        from dataclasses import asdict
        try:
            await self._producer.produce(
                NORMALISED_TOPIC, asdict(exposure)
            )
        except Exception:
            logger.warning(
                "Failed to publish normalised exposure %s",
                exposure.exposure_key, exc_info=True,
            )

    async def _send_to_dlq(
        self,
        topic: str,
        raw_data: dict[str, Any],
        error: str,
    ) -> None:
        """Send failed message to dead letter queue."""
        if self._producer is None:
            return
        try:
            await self._producer.produce(
                DLQ_TOPIC,
                {
                    "source_topic": topic,
                    "raw_data": raw_data,
                    "error": error,
                },
            )
        except Exception:
            logger.warning("Failed to send to DLQ", exc_info=True)
