"""Adapter registry — Story 16-8.

Central registry for all SIEM ingest adapters.  Provides factory lookup
so the pipeline can instantiate adapters by source name string.
"""

from __future__ import annotations

from shared.adapters.ingest import IngestAdapter
from elastic_adapter.adapter import ElasticAdapter
from sentinel_adapter.adapter import SentinelAdapter
from splunk_adapter.adapter import SplunkAdapter

ADAPTER_REGISTRY: dict[str, type[IngestAdapter]] = {
    "sentinel": SentinelAdapter,
    "elastic": ElasticAdapter,
    "splunk": SplunkAdapter,
}


def get_adapter(source: str) -> IngestAdapter:
    """Instantiate and return an adapter for *source*.

    Raises :class:`ValueError` if the source name is not registered.
    """
    cls = ADAPTER_REGISTRY.get(source)
    if cls is None:
        raise ValueError(
            f"Unknown adapter source {source!r}. "
            f"Available: {list(ADAPTER_REGISTRY)}"
        )
    return cls()


def list_adapters() -> list[str]:
    """Return registered source names."""
    return list(ADAPTER_REGISTRY)
