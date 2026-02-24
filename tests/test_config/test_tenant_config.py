"""Tests for tenant configuration — Story 14.8."""

from __future__ import annotations

import json
from unittest.mock import AsyncMock

import pytest

from shared.config.tenant_config import TenantConfig, TenantConfigStore


# ---------------------------------------------------------------------------
# TestTenantConfig (Task 1)
# ---------------------------------------------------------------------------

class TestTenantConfig:
    """AC-1,4: Tenant config with shadow mode defaults."""

    def test_default_shadow_mode_true(self):
        """New tenants default to shadow_mode=True."""
        config = TenantConfig(tenant_id="t-new")
        assert config.shadow_mode is True
        assert config.go_live_signed_off is False
        assert config.shadow_rule_families == []

    def test_cannot_disable_shadow_without_signoff(self):
        """Cannot disable shadow mode without go_live_signed_off."""
        config = TenantConfig(tenant_id="t-001")
        with pytest.raises(ValueError, match="go_live_signed_off"):
            config.disable_shadow()

    def test_disable_shadow_with_signoff(self):
        """Can disable shadow mode after go_live sign-off."""
        config = TenantConfig(
            tenant_id="t-001",
            go_live_signed_off=True,
            go_live_signed_off_by="admin@example.com",
        )
        config.disable_shadow()
        assert config.shadow_mode is False

    def test_round_trip_dict(self):
        """Config round-trips through to_dict/from_dict."""
        config = TenantConfig(
            tenant_id="t-001",
            shadow_mode=True,
            shadow_rule_families=["phishing", "malware"],
            go_live_signed_off=True,
            go_live_signed_off_by="admin",
            go_live_date="2026-03-01",
            approval_timeout_overrides={"critical": 300},
        )
        restored = TenantConfig.from_dict(config.to_dict())
        assert restored.tenant_id == "t-001"
        assert restored.shadow_rule_families == ["phishing", "malware"]
        assert restored.go_live_signed_off_by == "admin"
        assert restored.approval_timeout_overrides == {"critical": 300}


# ---------------------------------------------------------------------------
# TestTenantConfigStore (Task 1)
# ---------------------------------------------------------------------------

class TestTenantConfigStore:
    """AC-1,4: Redis-backed config store."""

    @staticmethod
    def _make_redis():
        """Create a plain async Redis mock without _client attribute.

        TenantConfigStore._get_client() checks hasattr(_, '_client').
        AsyncMock responds True to all hasattr, so we use a simple class.
        """
        class _FakeRedis:
            async def get(self, key):
                return None
            async def set(self, key, value):
                pass
        return _FakeRedis()

    @pytest.mark.asyncio
    async def test_get_config_returns_default_when_missing(self):
        """Missing tenant returns default config (shadow=True)."""
        redis = self._make_redis()
        store = TenantConfigStore(redis)
        config = await store.get_config("t-new")
        assert config.tenant_id == "t-new"
        assert config.shadow_mode is True

    @pytest.mark.asyncio
    async def test_set_and_get_config(self):
        """Config round-trips through Redis."""
        stored: dict[str, str] = {}

        class _FakeRedisStore:
            async def get(self, key):
                return stored.get(key)
            async def set(self, key, value):
                stored[key] = value

        store = TenantConfigStore(_FakeRedisStore())

        config = TenantConfig(
            tenant_id="t-001",
            shadow_mode=True,
            go_live_signed_off=True,
        )
        await store.set_config(config)
        loaded = await store.get_config("t-001")
        assert loaded.tenant_id == "t-001"
        assert loaded.shadow_mode is True

    @pytest.mark.asyncio
    async def test_set_config_rejects_shadow_false_without_signoff(self):
        """Cannot persist config with shadow=False without sign-off."""
        store = TenantConfigStore(self._make_redis())
        config = TenantConfig(tenant_id="t-001", shadow_mode=False)
        with pytest.raises(ValueError, match="go_live_signed_off"):
            await store.set_config(config)
