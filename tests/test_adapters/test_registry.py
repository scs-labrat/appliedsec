"""Unit tests for adapter registry — Story 16-8."""

from __future__ import annotations

import pytest

from shared.adapters.registry import (
    ADAPTER_REGISTRY,
    get_adapter,
    list_adapters,
)
from elastic_adapter.adapter import ElasticAdapter
from sentinel_adapter.adapter import SentinelAdapter
from splunk_adapter.adapter import SplunkAdapter


class TestAdapterRegistry:
    """Registry has 3 entries, factory returns correct types."""

    def test_registry_has_three_entries(self):
        assert len(ADAPTER_REGISTRY) == 3
        assert set(ADAPTER_REGISTRY) == {"sentinel", "elastic", "splunk"}

    def test_get_adapter_sentinel(self):
        adapter = get_adapter("sentinel")
        assert isinstance(adapter, SentinelAdapter)
        assert adapter.source_name() == "sentinel"

    def test_get_adapter_elastic(self):
        adapter = get_adapter("elastic")
        assert isinstance(adapter, ElasticAdapter)
        assert adapter.source_name() == "elastic"

    def test_get_adapter_splunk(self):
        adapter = get_adapter("splunk")
        assert isinstance(adapter, SplunkAdapter)
        assert adapter.source_name() == "splunk"

    def test_unknown_source_raises_value_error(self):
        with pytest.raises(ValueError, match="Unknown adapter source"):
            get_adapter("unknown_siem")

    def test_list_adapters_returns_all_names(self):
        names = list_adapters()
        assert sorted(names) == ["elastic", "sentinel", "splunk"]
