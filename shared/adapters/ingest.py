"""IngestAdapter abstract base class — Story 4.1.

All SIEM adapters (Sentinel, Elastic, Splunk, Wiz) inherit from this ABC.
Vendor-specific SDKs are confined to adapter modules only.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any, Optional

from shared.schemas.alert import CanonicalAlert


class IngestAdapter(ABC):
    """Base class for SIEM/XDR ingest adapters."""

    @abstractmethod
    def source_name(self) -> str:
        """Return the adapter's source identifier (e.g. ``"sentinel"``)."""
        ...

    @abstractmethod
    async def subscribe(self) -> None:
        """Start consuming events from the source.

        This method is adapter-internal — the pipeline only ever sees
        ``CanonicalAlert`` objects on the ``alerts.raw`` Kafka topic.
        """
        ...

    @abstractmethod
    def to_canonical(self, raw_event: dict[str, Any]) -> Optional[CanonicalAlert]:
        """Convert a raw source event to a :class:`CanonicalAlert`.

        Returns ``None`` if the event should be dropped (e.g. heartbeat).
        """
        ...
