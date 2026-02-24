"""ElasticAdapter — Story 16-1.

Maps Elastic SIEM ``signal`` JSON to
:class:`~shared.schemas.alert.CanonicalAlert`.

Elasticsearch SDK imports are confined to this adapter — they never appear
in core pipeline code.
"""

from __future__ import annotations

import json
import logging
from typing import Any, Optional

from shared.adapters.ingest import IngestAdapter
from shared.schemas.alert import CanonicalAlert

logger = logging.getLogger(__name__)

# Signal rule names treated as non-actionable heartbeats / health-checks.
_HEARTBEAT_NAMES = frozenset({
    "heartbeat",
    "test alert",
    "health check",
    "endpoint heartbeat",
    "system health monitor",
})


class ElasticAdapter(IngestAdapter):
    """Elastic SIEM adapter — subscribes to .siem-signals-* index."""

    def source_name(self) -> str:  # noqa: D401
        return "elastic"

    async def subscribe(self) -> None:
        """Connector logic is delegated to :mod:`elastic_adapter.connector`."""
        raise NotImplementedError(
            "Use ElasticConnector for Elasticsearch polling"
        )

    # ------------------------------------------------------------------
    # Field mapping  (Story 16-1)
    # ------------------------------------------------------------------

    def to_canonical(self, raw_event: dict[str, Any]) -> Optional[CanonicalAlert]:
        """Map an Elastic SIEM signal dict to a :class:`CanonicalAlert`.

        Returns ``None`` for heartbeat / test events so they are never
        published to ``alerts.raw``.
        """
        signal = raw_event.get("signal", {})
        rule = signal.get("rule", {})

        rule_name = rule.get("name", "")
        if rule_name.lower().strip() in _HEARTBEAT_NAMES:
            logger.debug("Dropping heartbeat signal: %s", rule_name)
            return None

        # Extract MITRE tactics and techniques from Kibana alert parameters
        tactics = self._extract_tactics(raw_event)
        techniques = self._extract_techniques(raw_event)

        # Build entities_raw from source fields
        entities_raw = self._build_entities_raw(raw_event, signal)

        return CanonicalAlert(
            alert_id=rule.get("id", signal.get("id", "")),
            source="elastic",
            timestamp=raw_event.get("@timestamp", ""),
            title=rule_name,
            description=rule.get("description", ""),
            severity=self._normalise_severity(rule.get("severity")),
            tactics=tactics,
            techniques=techniques,
            entities_raw=entities_raw,
            product=raw_event.get("agent", {}).get("type", "elastic"),
            tenant_id=raw_event.get("kibana.space_ids", ["default"])[0]
            if isinstance(raw_event.get("kibana.space_ids"), list)
            else raw_event.get("tenant_id", "default"),
            raw_payload=raw_event,
        )

    # ------------------------------------------------------------------
    # MITRE extraction helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _extract_tactics(raw_event: dict[str, Any]) -> list[str]:
        """Extract MITRE tactic names from Kibana alert rule parameters."""
        tactics: list[str] = []
        # Path: kibana.alert.rule.parameters.threat[].tactic.name
        params = (
            raw_event
            .get("kibana", {})
            .get("alert", {})
            .get("rule", {})
            .get("parameters", {})
        )
        threats = params.get("threat", [])
        for threat in threats:
            if isinstance(threat, dict):
                tactic = threat.get("tactic", {})
                name = tactic.get("name", "") if isinstance(tactic, dict) else ""
                if name and name not in tactics:
                    tactics.append(name)

        # Fallback: signal.rule.threat[].tactic.name
        if not tactics:
            signal = raw_event.get("signal", {})
            rule = signal.get("rule", {})
            for threat in rule.get("threat", []):
                if isinstance(threat, dict):
                    tactic = threat.get("tactic", {})
                    name = tactic.get("name", "") if isinstance(tactic, dict) else ""
                    if name and name not in tactics:
                        tactics.append(name)

        return tactics

    @staticmethod
    def _extract_techniques(raw_event: dict[str, Any]) -> list[str]:
        """Extract MITRE technique IDs from Kibana alert rule parameters."""
        techniques: list[str] = []
        params = (
            raw_event
            .get("kibana", {})
            .get("alert", {})
            .get("rule", {})
            .get("parameters", {})
        )
        threats = params.get("threat", [])
        for threat in threats:
            if isinstance(threat, dict):
                for tech in threat.get("technique", []):
                    if isinstance(tech, dict):
                        tid = tech.get("id", "")
                        if tid and tid not in techniques:
                            techniques.append(tid)
                        # Sub-techniques
                        for sub in tech.get("subtechnique", []):
                            if isinstance(sub, dict):
                                sid = sub.get("id", "")
                                if sid and sid not in techniques:
                                    techniques.append(sid)

        # Fallback: signal.rule.threat[].technique[].id
        if not techniques:
            signal = raw_event.get("signal", {})
            rule = signal.get("rule", {})
            for threat in rule.get("threat", []):
                if isinstance(threat, dict):
                    for tech in threat.get("technique", []):
                        if isinstance(tech, dict):
                            tid = tech.get("id", "")
                            if tid and tid not in techniques:
                                techniques.append(tid)
                            for sub in tech.get("subtechnique", []):
                                if isinstance(sub, dict):
                                    sid = sub.get("id", "")
                                    if sid and sid not in techniques:
                                        techniques.append(sid)

        return techniques

    # ------------------------------------------------------------------
    # Entity extraction
    # ------------------------------------------------------------------

    @staticmethod
    def _build_entities_raw(
        raw_event: dict[str, Any], signal: dict[str, Any]
    ) -> str:
        """Build a JSON entity array from Elastic source fields.

        Extracts entities from ``host.*``, ``user.*``, ``source.ip``,
        ``destination.ip``, ``process.*``, and ``signal.original_event``.
        """
        entities: list[dict[str, Any]] = []
        eid = 1

        # Host entity
        host = raw_event.get("host", {})
        if isinstance(host, dict) and host.get("name"):
            entities.append({
                "$id": str(eid),
                "Type": "host",
                "HostName": host["name"],
                "OSFamily": host.get("os", {}).get("family", "")
                if isinstance(host.get("os"), dict) else "",
            })
            eid += 1

        # User entity
        user = raw_event.get("user", {})
        if isinstance(user, dict) and user.get("name"):
            entity: dict[str, Any] = {
                "$id": str(eid),
                "Type": "account",
                "Name": user["name"],
            }
            domain = user.get("domain", "")
            if domain:
                entity["UPNSuffix"] = domain
            entities.append(entity)
            eid += 1

        # Source IP
        source = raw_event.get("source", {})
        if isinstance(source, dict) and source.get("ip"):
            entities.append({
                "$id": str(eid),
                "Type": "ip",
                "Address": source["ip"],
            })
            eid += 1

        # Destination IP
        dest = raw_event.get("destination", {})
        if isinstance(dest, dict) and dest.get("ip"):
            entities.append({
                "$id": str(eid),
                "Type": "ip",
                "Address": dest["ip"],
            })
            eid += 1

        # Process entity
        process = raw_event.get("process", {})
        if isinstance(process, dict) and (process.get("name") or process.get("pid")):
            entities.append({
                "$id": str(eid),
                "Type": "process",
                "ProcessId": str(process.get("pid", "")),
                "CommandLine": process.get("command_line", process.get("args", "")),
            })
            eid += 1

        # Original event entities (for nested alert payloads)
        original = signal.get("original_event", {})
        if isinstance(original, dict):
            for key in ("source_ip", "dest_ip", "user"):
                val = original.get(key)
                if val and isinstance(val, str):
                    if "ip" in key:
                        entities.append({
                            "$id": str(eid),
                            "Type": "ip",
                            "Address": val,
                        })
                    else:
                        entities.append({
                            "$id": str(eid),
                            "Type": "account",
                            "Name": val,
                        })
                    eid += 1

        return json.dumps(entities)

    # ------------------------------------------------------------------
    # helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _normalise_severity(value: str | None) -> str:
        """Lowercase the Elastic severity; default to ``"medium"``.

        Elastic uses: critical, high, medium, low — same as canonical.
        """
        if not value:
            return "medium"
        normalised = value.strip().lower()
        valid = {"critical", "high", "medium", "low", "informational"}
        return normalised if normalised in valid else "medium"
