"""False Positive short-circuit — Story 7.9.

Checks alert against known FP patterns in Redis before LLM calls.
If matched with confidence > 0.90, skips enrichment and closes directly.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass
from typing import Any, Optional

from shared.schemas.investigation import GraphState, InvestigationState

logger = logging.getLogger(__name__)

FP_CONFIDENCE_THRESHOLD = 0.90


@dataclass
class FPMatchResult:
    """Result of FP pattern matching."""

    matched: bool
    pattern_id: str = ""
    confidence: float = 0.0


class FPShortCircuit:
    """Matches alerts against known FP patterns for zero-LLM-cost closure."""

    def __init__(
        self,
        redis_client: Any,
        kill_switch_manager: Any | None = None,
        threshold_adjuster: Any | None = None,
    ) -> None:
        self._redis = redis_client
        self._kill_switch = kill_switch_manager
        self._threshold_adjuster = threshold_adjuster

    async def check(
        self,
        state: GraphState,
        alert_title: str,
        tenant_id: str = "",
        technique_id: str = "",
        data_source: str = "",
        alert_rule_family: str = "",
        alert_asset_class: str = "",
    ) -> FPMatchResult:
        """Check alert against all FP patterns.

        Returns FPMatchResult indicating whether to short-circuit.
        Kill switches block matching before any pattern evaluation.
        Shadow patterns are excluded from active matching.
        """
        # Kill switch check — if any dimension is killed, skip matching
        if self._kill_switch is not None and tenant_id:
            killed = await self._kill_switch.is_killed(
                tenant_id=tenant_id,
                technique_id=technique_id,
                data_source=data_source,
            )
            if killed:
                return FPMatchResult(matched=False)

        # F5: pass tenant_id for tenant-scoped FP pattern keys
        effective_tenant = tenant_id or state.tenant_id
        pattern_keys = await self._redis.list_fp_patterns(effective_tenant)
        state.queries_executed += 1

        for key in pattern_keys:
            # Keys are now fp:{tenant_id}:{pattern_id} — extract pattern_id
            parts = key.split(":", 2)
            pattern_id = parts[2] if len(parts) == 3 else key
            pattern = await self._redis.get_fp_pattern(effective_tenant, pattern_id)
            state.queries_executed += 1
            if pattern is None:
                continue

            status = pattern.get("status", "")

            # Skip shadow patterns — they run in canary only
            if status == "shadow":
                continue

            # Only match approved or active patterns
            if status not in ("approved", "active"):
                continue

            # Per-pattern kill switch check
            if self._kill_switch is not None:
                pattern_killed = await self._kill_switch.is_killed(
                    tenant_id=tenant_id or "",
                    pattern_id=pattern_id,
                )
                if pattern_killed:
                    continue

            # Blast-radius scope check
            from orchestrator.fp_governance import matches_scope
            if not matches_scope(
                pattern,
                alert_rule_family=alert_rule_family,
                alert_tenant_id=tenant_id,
                alert_asset_class=alert_asset_class,
            ):
                continue

            confidence = self._compute_match_confidence(
                pattern, alert_title, state.entities
            )
            effective_threshold = self._get_effective_threshold()
            if confidence >= effective_threshold:
                return FPMatchResult(
                    matched=True,
                    pattern_id=pattern_id,
                    confidence=confidence,
                )

        return FPMatchResult(matched=False)

    def _get_effective_threshold(self) -> float:
        """Return the effective confidence threshold.

        Uses ThresholdAdjuster if available, otherwise falls back to
        the static FP_CONFIDENCE_THRESHOLD constant.
        """
        if self._threshold_adjuster is not None:
            return self._threshold_adjuster.get_threshold()
        return FP_CONFIDENCE_THRESHOLD

    def apply_shortcircuit(
        self, state: GraphState, match: FPMatchResult
    ) -> GraphState:
        """Apply FP short-circuit: PARSING → CLOSED."""
        state.classification = "false_positive"
        state.confidence = match.confidence
        state.state = InvestigationState.CLOSED
        state.decision_chain.append({
            "agent": "fp_short_circuit",
            "action": "auto_close_fp",
            "pattern_id": match.pattern_id,
            "confidence": match.confidence,
        })
        return state

    def _compute_match_confidence(
        self,
        pattern: dict[str, Any],
        alert_title: str,
        entities: dict[str, Any],
    ) -> float:
        """Compute combined FP match confidence.

        confidence = (alert_name_score + entity_match_score) / 2
        """
        # Alert name match
        alert_regex = pattern.get("alert_name_regex", "")
        alert_score = 1.0 if alert_regex and _safe_regex_match(alert_regex, alert_title) else 0.0

        # Entity pattern match
        entity_patterns = pattern.get("entity_patterns", [])
        entity_score = self._compute_entity_score(entity_patterns, entities)

        if not entity_patterns:
            return alert_score

        return (alert_score + entity_score) / 2

    def _compute_entity_score(
        self,
        entity_patterns: list[dict[str, Any]],
        entities: dict[str, Any],
    ) -> float:
        """Score entity pattern matches."""
        if not entity_patterns:
            return 0.0

        matches = 0
        for ep in entity_patterns:
            etype = ep.get("type", "")
            value_regex = ep.get("value_regex", "")
            value_cidr = ep.get("value_cidr", "")

            # Get entity values for this type
            entity_list = entities.get(f"{etype}s", entities.get(etype, []))
            if not isinstance(entity_list, list):
                continue

            for entity in entity_list:
                value = entity.get("primary_value", "") if isinstance(entity, dict) else str(entity)
                if value_regex and _safe_regex_match(value_regex, value):
                    matches += 1
                    break
                if value_cidr and _cidr_match(value_cidr, value):
                    matches += 1
                    break

        return matches / len(entity_patterns) if entity_patterns else 0.0


def _safe_regex_match(pattern: str, text: str) -> bool:
    """Safely match a regex pattern against text."""
    try:
        return bool(re.match(pattern, text, re.IGNORECASE))
    except re.error:
        logger.warning("Invalid FP regex: %s", pattern)
        return False


def _cidr_match(cidr: str, ip: str) -> bool:
    """Simple CIDR matching for common patterns."""
    try:
        import ipaddress
        network = ipaddress.ip_network(cidr, strict=False)
        return ipaddress.ip_address(ip) in network
    except (ValueError, TypeError):
        return False
