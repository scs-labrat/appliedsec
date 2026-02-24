"""Shadow mode manager — Story 14.8.

Manages shadow mode execution: full pipeline runs but decisions are
logged without execution. Tracks agreement rate with analyst decisions.
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from typing import Any

from shared.config.tenant_config import TenantConfigStore


@dataclass
class GoLiveCriteria:
    """Criteria that must be met before shadow mode can be disabled."""

    min_agreement_rate: float = 0.95
    min_window_days: int = 14
    max_missed_critical_tp: int = 0
    min_fp_precision: float = 0.98

    def check(
        self,
        agreement_rate: float,
        missed_critical_tps: int,
        fp_precision: float,
    ) -> tuple[bool, list[str]]:
        """Check whether go-live criteria are met.

        Returns ``(met, [list of unmet criteria descriptions])``.
        """
        unmet: list[str] = []
        if agreement_rate < self.min_agreement_rate:
            unmet.append(
                f"agreement_rate {agreement_rate:.3f} < {self.min_agreement_rate}"
            )
        if missed_critical_tps > self.max_missed_critical_tp:
            unmet.append(
                f"missed_critical_tps {missed_critical_tps} > {self.max_missed_critical_tp}"
            )
        if fp_precision < self.min_fp_precision:
            unmet.append(
                f"fp_precision {fp_precision:.3f} < {self.min_fp_precision}"
            )
        return (len(unmet) == 0, unmet)


class ShadowModeManager:
    """Orchestrates shadow mode execution and agreement tracking.

    Shadow decisions are stored in Redis lists keyed by tenant+rule_family.
    Each entry is a JSON object: ``{shadow_decision, shadow_confidence,
    analyst_decision, investigation_id, ts}``.
    """

    SHADOW_LOG_PREFIX = "shadow_log:"

    def __init__(
        self,
        tenant_config_store: TenantConfigStore,
        audit_producer: Any | None = None,
    ) -> None:
        self._store = tenant_config_store
        self._audit = audit_producer

    async def is_shadow_active(
        self, tenant_id: str, rule_family: str = "",
    ) -> bool:
        """Check if shadow mode is active for this tenant/rule_family."""
        config = await self._store.get_config(tenant_id)
        if not config.shadow_mode:
            return False
        # If shadow_rule_families is empty, ALL families are in shadow
        if not config.shadow_rule_families:
            return True
        return rule_family in config.shadow_rule_families

    async def record_shadow_decision(
        self,
        tenant_id: str,
        rule_family: str,
        shadow_decision: str,
        shadow_confidence: float,
        investigation_id: str,
    ) -> None:
        """Log what the system WOULD have done (without executing)."""
        client = self._store._get_client()
        key = f"{self.SHADOW_LOG_PREFIX}{tenant_id}:{rule_family}"
        entry = json.dumps({
            "type": "shadow",
            "shadow_decision": shadow_decision,
            "shadow_confidence": shadow_confidence,
            "investigation_id": investigation_id,
            "ts": time.time(),
        })
        await client.rpush(key, entry)

        if self._audit is not None:
            try:
                self._audit.emit(
                    tenant_id=tenant_id,
                    event_type="shadow.decision_logged",
                    event_category="decision",
                    actor_type="agent",
                    actor_id="shadow_mode_manager",
                    investigation_id=investigation_id,
                    context={
                        "shadow_decision": shadow_decision,
                        "shadow_confidence": shadow_confidence,
                        "rule_family": rule_family,
                    },
                )
            except Exception:
                pass  # fire-and-forget

    async def record_analyst_decision(
        self,
        tenant_id: str,
        rule_family: str,
        analyst_decision: str,
        investigation_id: str,
    ) -> None:
        """Log what the analyst actually decided."""
        client = self._store._get_client()
        key = f"{self.SHADOW_LOG_PREFIX}{tenant_id}:{rule_family}"
        entry = json.dumps({
            "type": "analyst",
            "analyst_decision": analyst_decision,
            "investigation_id": investigation_id,
            "ts": time.time(),
        })
        await client.rpush(key, entry)

    async def compute_agreement_rate(
        self,
        tenant_id: str,
        rule_family: str = "",
        window_days: int = 14,
    ) -> float:
        """Compute agreement rate over a time window.

        Matches shadow decisions with analyst decisions by investigation_id,
        then computes the fraction that agree.
        """
        client = self._store._get_client()
        key = f"{self.SHADOW_LOG_PREFIX}{tenant_id}:{rule_family}"
        raw_entries = await client.lrange(key, 0, -1)
        if not raw_entries:
            return 0.0

        cutoff = time.time() - (window_days * 86400)

        shadow_map: dict[str, str] = {}
        analyst_map: dict[str, str] = {}

        for raw in raw_entries:
            entry = json.loads(raw)
            if entry.get("ts", 0) < cutoff:
                continue
            inv_id = entry.get("investigation_id", "")
            if entry.get("type") == "shadow":
                shadow_map[inv_id] = entry["shadow_decision"]
            elif entry.get("type") == "analyst":
                analyst_map[inv_id] = entry["analyst_decision"]

        # Only count investigations that have both shadow + analyst decisions
        paired = set(shadow_map.keys()) & set(analyst_map.keys())
        if not paired:
            return 0.0

        agreements = sum(
            1 for inv_id in paired
            if shadow_map[inv_id] == analyst_map[inv_id]
        )
        return agreements / len(paired)
