"""Kill switch manager for FP auto-close — Story 14.3.

Provides 4-dimension emergency kill switches (tenant, pattern, technique,
datasource) backed by Redis.  Any active kill switch in any dimension
blocks FP auto-close for matching alerts.
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from typing import Any, Optional

logger = logging.getLogger(__name__)

KILL_SWITCH_DIMENSIONS = ("tenant", "pattern", "technique", "datasource")


class KillSwitchManager:
    """Manages kill switches across four dimensions via Redis keys.

    Redis key pattern:
        kill_switch:{dimension}:{value}  →  JSON metadata
    """

    def __init__(
        self,
        redis_client: Any,
        audit_producer: Any | None = None,
    ) -> None:
        self._redis = redis_client
        self._audit = audit_producer

    def _get_client(self) -> Any:
        """Return the underlying async Redis client."""
        if hasattr(self._redis, "_client") and self._redis._client is not None:
            return self._redis._client
        return self._redis

    async def activate(
        self,
        dimension: str,
        value: str,
        activated_by: str,
        reason: str = "",
    ) -> None:
        """Activate a kill switch for the given dimension/value.

        Stores metadata in Redis and emits an audit event.
        """
        if dimension not in KILL_SWITCH_DIMENSIONS:
            raise ValueError(
                f"Invalid dimension '{dimension}'. "
                f"Must be one of {KILL_SWITCH_DIMENSIONS}"
            )

        key = f"kill_switch:{dimension}:{value}"
        metadata = {
            "activated_by": activated_by,
            "activated_at": datetime.now(timezone.utc).isoformat(),
            "reason": reason,
            "dimension": dimension,
            "value": value,
        }

        client = self._get_client()
        await client.set(key, json.dumps(metadata))
        logger.info("Kill switch activated: %s", key)

        if self._audit is not None:
            try:
                await self._audit.emit(
                    event_type="kill_switch.activated",
                    tenant_id=value if dimension == "tenant" else "",
                    data={
                        "dimension": dimension,
                        "value": value,
                        "activated_by": activated_by,
                        "reason": reason,
                    },
                )
            except Exception:
                logger.warning("Failed to emit kill_switch.activated audit event", exc_info=True)

    async def deactivate(
        self,
        dimension: str,
        value: str,
        deactivated_by: str,
        reason: str = "",
    ) -> None:
        """Deactivate a kill switch for the given dimension/value."""
        if dimension not in KILL_SWITCH_DIMENSIONS:
            raise ValueError(
                f"Invalid dimension '{dimension}'. "
                f"Must be one of {KILL_SWITCH_DIMENSIONS}"
            )

        key = f"kill_switch:{dimension}:{value}"
        client = self._get_client()
        await client.delete(key)
        logger.info("Kill switch deactivated: %s", key)

        if self._audit is not None:
            try:
                await self._audit.emit(
                    event_type="kill_switch.deactivated",
                    tenant_id=value if dimension == "tenant" else "",
                    data={
                        "dimension": dimension,
                        "value": value,
                        "deactivated_by": deactivated_by,
                        "reason": reason,
                    },
                )
            except Exception:
                logger.warning("Failed to emit kill_switch.deactivated audit event", exc_info=True)

    async def is_killed(
        self,
        tenant_id: str,
        pattern_id: str = "",
        technique_id: str = "",
        data_source: str = "",
    ) -> bool:
        """Check whether ANY kill switch blocks auto-close for this alert.

        Checks all four dimensions.  Returns True if any is active.
        """
        checks: list[tuple[str, str]] = [("tenant", tenant_id)]
        if pattern_id:
            checks.append(("pattern", pattern_id))
        if technique_id:
            checks.append(("technique", technique_id))
        if data_source:
            checks.append(("datasource", data_source))

        client = self._get_client()
        for dimension, value in checks:
            if not value:
                continue
            key = f"kill_switch:{dimension}:{value}"
            try:
                result = await client.get(key)
                if result is not None:
                    return True
            except Exception:
                logger.warning("Redis check failed for %s — fail-open", key, exc_info=True)

        return False
