"""SplunkAdapter — Story 16-4.

Maps Splunk Enterprise Security notable event JSON to
:class:`~shared.schemas.alert.CanonicalAlert`.

Splunk SDK imports are confined to this adapter — they never appear in
core pipeline code.
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from typing import Any, Optional

from shared.adapters.ingest import IngestAdapter
from shared.schemas.alert import CanonicalAlert

logger = logging.getLogger(__name__)

# Notable event search names treated as non-actionable health checks.
_HEALTH_PREFIX = "Health"

# Splunk urgency → canonical severity mapping.
_SEVERITY_MAP: dict[str, str] = {
    "critical": "critical",
    "high": "high",
    "medium": "medium",
    "low": "low",
    "informational": "informational",
    "info": "informational",
}


class SplunkAdapter(IngestAdapter):
    """Splunk ES adapter — subscribes to notable events."""

    def source_name(self) -> str:  # noqa: D401
        return "splunk"

    async def subscribe(self) -> None:
        """Connector logic is delegated to :mod:`splunk_adapter.connector`."""
        raise NotImplementedError(
            "Use SplunkHECConnector or SplunkSavedSearchConnector"
        )

    # ------------------------------------------------------------------
    # Field mapping  (Story 16-4)
    # ------------------------------------------------------------------

    def to_canonical(self, raw_event: dict[str, Any]) -> Optional[CanonicalAlert]:
        """Map a Splunk ES notable event dict to a :class:`CanonicalAlert`.

        Returns ``None`` for health-check events (search_name starts with
        ``"Health"``) so they are never published to ``alerts.raw``.
        """
        search_name = raw_event.get("search_name", "")
        if search_name.startswith(_HEALTH_PREFIX):
            logger.debug("Dropping health-check event: %s", search_name)
            return None

        # Extract MITRE from annotations
        annotations = raw_event.get("annotations", {})
        mitre = annotations.get("mitre_attack", {})
        tactics = self._extract_list(mitre.get("mitre_tactic"))
        techniques = self._extract_list(mitre.get("mitre_technique_id"))

        # Build entities_raw from Splunk CIM fields
        entities_raw = self._build_entities_raw(raw_event)

        return CanonicalAlert(
            alert_id=raw_event.get("event_id", raw_event.get("sid", "")),
            source="splunk",
            timestamp=self._parse_timestamp(raw_event.get("_time", "")),
            title=search_name or raw_event.get("rule_title", ""),
            description=raw_event.get("description", ""),
            severity=self._normalise_severity(raw_event.get("urgency")),
            tactics=tactics,
            techniques=techniques,
            entities_raw=entities_raw,
            product=raw_event.get("source", "splunk_es"),
            tenant_id=raw_event.get("tenant_id", "default"),
            raw_payload=raw_event,
        )

    # ------------------------------------------------------------------
    # helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _normalise_severity(value: str | None) -> str:
        """Map Splunk urgency to canonical severity; default ``"medium"``."""
        if not value:
            return "medium"
        return _SEVERITY_MAP.get(value.strip().lower(), "medium")

    @staticmethod
    def _parse_timestamp(value: str) -> str:
        """Parse Splunk ``_time`` (epoch or ISO) to ISO 8601 string."""
        if not value:
            return datetime.now(timezone.utc).isoformat()

        # Try epoch seconds (Splunk sometimes sends numeric timestamps)
        try:
            epoch = float(value)
            return datetime.fromtimestamp(epoch, tz=timezone.utc).isoformat()
        except (ValueError, OverflowError, OSError):
            pass

        # Already ISO — return as-is (CanonicalAlert validator will check)
        return value

    @staticmethod
    def _extract_list(value: Any) -> list[str]:
        """Coerce a value to a list of strings.

        Splunk annotations can be a list, a single string, or CSV.
        """
        if isinstance(value, list):
            return [str(v).strip() for v in value if str(v).strip()]
        if isinstance(value, str) and value.strip():
            return [item.strip() for item in value.split(",") if item.strip()]
        return []

    @staticmethod
    def _build_entities_raw(raw_event: dict[str, Any]) -> str:
        """Build a JSON entity array from Splunk CIM fields.

        Extracts entities from ``src``, ``dest``, ``user``, ``src_ip``,
        ``dest_ip``, ``src_user``, ``dest_user`` fields.
        """
        entities: list[dict[str, Any]] = []
        eid = 1
        seen: set[str] = set()

        # IP entities from src/dest/src_ip/dest_ip
        for field in ("src", "src_ip"):
            ip = raw_event.get(field, "")
            if ip and isinstance(ip, str) and ip not in seen:
                seen.add(ip)
                entities.append({
                    "$id": str(eid),
                    "Type": "ip",
                    "Address": ip,
                })
                eid += 1

        for field in ("dest", "dest_ip"):
            ip = raw_event.get(field, "")
            if ip and isinstance(ip, str) and ip not in seen:
                seen.add(ip)
                entities.append({
                    "$id": str(eid),
                    "Type": "ip",
                    "Address": ip,
                })
                eid += 1

        # Host entities from src_host / dest_host (if they look like hostnames)
        for field in ("src_host", "dest_host"):
            host = raw_event.get(field, "")
            if host and isinstance(host, str) and host not in seen:
                seen.add(host)
                entities.append({
                    "$id": str(eid),
                    "Type": "host",
                    "HostName": host,
                })
                eid += 1

        # Account entities from user/src_user/dest_user
        for field in ("user", "src_user", "dest_user"):
            user = raw_event.get(field, "")
            if user and isinstance(user, str) and user not in seen:
                seen.add(user)
                entities.append({
                    "$id": str(eid),
                    "Type": "account",
                    "Name": user,
                })
                eid += 1

        # Process entity if present
        process_name = raw_event.get("process_name", raw_event.get("process", ""))
        if process_name and isinstance(process_name, str):
            entities.append({
                "$id": str(eid),
                "Type": "process",
                "ProcessId": str(raw_event.get("process_id", "")),
                "CommandLine": raw_event.get("process_exec", ""),
            })
            eid += 1

        return json.dumps(entities)
