"""YAML-driven zone consequence configuration — Story 14.1.

Loads zone-to-consequence-to-severity mapping from YAML, replacing
the hardcoded ZONE_CONSEQUENCE_FALLBACK dicts.
"""

from __future__ import annotations

import os
import time
from typing import Any

import yaml

_DEFAULT_PATH = os.path.join(os.path.dirname(__file__), "zone_consequences.yaml")

# Module-level cache with TTL
_config: dict[str, Any] | None = None
_config_loaded_at: float = 0.0
_CACHE_TTL_SECONDS: float = 300.0  # 5 minutes


def load_zone_consequences(path: str | None = None) -> dict[str, Any]:
    """Load zone consequences from YAML. Caches for 5 minutes after first load."""
    global _config, _config_loaded_at
    if (
        _config is not None
        and path is None
        and (time.monotonic() - _config_loaded_at) < _CACHE_TTL_SECONDS
    ):
        return _config

    config_path = path or _DEFAULT_PATH
    with open(config_path) as f:
        data = yaml.safe_load(f)

    if path is None:
        _config = data
        _config_loaded_at = time.monotonic()
    return data


def get_consequence_class(asset_zone: str) -> str:
    """Return consequence class for a zone, defaulting to 'data_loss'."""
    cfg = load_zone_consequences()
    zone_map = cfg.get("zone_consequence", {})
    entry = zone_map.get(asset_zone)
    if entry:
        return entry.get("consequence_class", cfg.get("default_consequence_class", "data_loss"))
    return cfg.get("default_consequence_class", "data_loss")


def get_severity(asset_zone: str) -> str:
    """Return severity string for a zone, defaulting to 'LOW'."""
    cfg = load_zone_consequences()
    zone_map = cfg.get("zone_consequence", {})
    entry = zone_map.get(asset_zone)
    if entry:
        return entry.get("severity", cfg.get("default_severity", "LOW"))
    return cfg.get("default_severity", "LOW")


def get_consequence_for_zone(asset_zone: str) -> tuple[str, str]:
    """Return (consequence_class, severity) tuple for a zone."""
    return get_consequence_class(asset_zone), get_severity(asset_zone)


def _reset_cache() -> None:
    """Reset the module cache (for testing)."""
    global _config, _config_loaded_at
    _config = None
    _config_loaded_at = 0.0
