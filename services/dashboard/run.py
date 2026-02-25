"""Standalone runner for the Analyst Dashboard.

Usage:
    python -m services.dashboard.run

Starts the dashboard on http://localhost:8080 with an in-memory mock DB
so you can preview the UI without Postgres/Redis running.
"""

from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from typing import Any

import uvicorn


# ---------------------------------------------------------------------------
# In-memory mock Postgres client (same pattern as integration tests)
# ---------------------------------------------------------------------------

class MockPostgresClient:
    """In-memory store that satisfies the dashboard's DB interface."""

    def __init__(self) -> None:
        self._investigations: dict[str, dict[str, Any]] = {}

    async def execute(self, query: str, *args: Any) -> None:
        if "INSERT INTO investigations" in query:
            inv_id = args[0]
            self._investigations[inv_id] = {
                "investigation_id": inv_id,
                "alert_id": args[1],
                "tenant_id": args[2],
                "state": args[3],
                "graphstate_json": json.loads(args[4]) if isinstance(args[4], str) else args[4],
                "decision_chain": json.loads(args[5]) if isinstance(args[5], str) else args[5],
                "updated_at": datetime.now(timezone.utc).isoformat(),
                "created_at": datetime.now(timezone.utc).isoformat(),
            }

    async def fetch_one(self, query: str, *args: Any) -> dict[str, Any] | None:
        if "SELECT graphstate_json FROM investigations" in query:
            row = self._investigations.get(args[0])
            return {"graphstate_json": row["graphstate_json"]} if row else None
        if "kill_switches" in query:
            return {"count": 0}
        if "AVG" in query:
            return {"avg_seconds": 3600.0}
        if "FILTER" in query:
            return {"fp_count": 2, "total": 10}
        return None

    async def fetch_many(self, query: str, *args: Any) -> list[dict[str, Any]]:
        if "FROM investigations" in query:
            results = list(self._investigations.values())
            if args and "state = $1" in query:
                state_filter = args[0] if args else ""
                if state_filter:
                    results = [r for r in results if r.get("state") == state_filter]
            for r in results:
                gs = r.get("graphstate_json", {})
                if isinstance(gs, dict):
                    r["severity"] = gs.get("severity", "")
            return results
        if "GROUP BY state" in query:
            counts: dict[str, int] = {}
            for inv in self._investigations.values():
                s = inv.get("state", "unknown")
                counts[s] = counts.get(s, 0) + 1
            return [{"state": k, "count": v} for k, v in counts.items()]
        if "GROUP BY" in query:
            return []
        return []


def _seed_demo_data(db: MockPostgresClient) -> None:
    """Populate mock DB with realistic demo investigations."""
    from shared.schemas.investigation import GraphState, InvestigationState

    demos = [
        {
            "id": str(uuid.uuid4()),
            "alert_id": "sentinel-mde-ps-001",
            "tenant_id": "contoso",
            "state": InvestigationState.AWAITING_HUMAN,
            "severity": "critical",
            "classification": "true_positive",
            "confidence": 0.92,
            "chain": [
                {"agent": "ioc_extractor", "action": "Extracted 5 IOCs (2 IPs, 1 hash, 2 domains)", "confidence": 0.95, "timestamp": "2026-02-25T08:01:00Z"},
                {"agent": "context_enricher", "action": "Enriched: IP 45.33.32.156 linked to APT29 C2", "confidence": 0.88, "timestamp": "2026-02-25T08:01:30Z"},
                {"agent": "atlas_mapper", "action": "Matched ATLAS technique AML.T0043 (LLM prompt injection)", "confidence": 0.76, "timestamp": "2026-02-25T08:02:00Z"},
                {"agent": "reasoning_agent", "action": "Classified as true positive — high confidence C2 beacon", "confidence": 0.92, "timestamp": "2026-02-25T08:02:30Z"},
            ],
        },
        {
            "id": str(uuid.uuid4()),
            "alert_id": "elastic-net-anomaly-042",
            "tenant_id": "megacorp",
            "state": InvestigationState.REASONING,
            "severity": "high",
            "classification": "",
            "confidence": 0.0,
            "chain": [
                {"agent": "ioc_extractor", "action": "Extracted 2 IPs from impossible travel alert", "confidence": 0.90, "timestamp": "2026-02-25T09:15:00Z"},
                {"agent": "context_enricher", "action": "GeoIP: US→CN in 20 min, user=CFO", "confidence": 0.85, "timestamp": "2026-02-25T09:15:30Z"},
            ],
        },
        {
            "id": str(uuid.uuid4()),
            "alert_id": "splunk-bf-access-007",
            "tenant_id": "contoso",
            "state": InvestigationState.CLOSED,
            "severity": "medium",
            "classification": "false_positive",
            "confidence": 0.97,
            "chain": [
                {"agent": "ioc_extractor", "action": "Extracted source IP 10.0.0.99", "confidence": 0.99, "timestamp": "2026-02-25T07:00:00Z"},
                {"agent": "reasoning_agent", "action": "Matched FP pattern: internal scanner IP", "confidence": 0.97, "timestamp": "2026-02-25T07:00:30Z"},
                {"agent": "response_agent", "action": "Auto-closed as false positive", "confidence": 0.97, "timestamp": "2026-02-25T07:01:00Z"},
            ],
        },
        {
            "id": str(uuid.uuid4()),
            "alert_id": "sentinel-aadip-travel-003",
            "tenant_id": "megacorp",
            "state": InvestigationState.AWAITING_HUMAN,
            "severity": "high",
            "classification": "suspicious",
            "confidence": 0.78,
            "chain": [
                {"agent": "ioc_extractor", "action": "Extracted 2 IPs, 1 account", "confidence": 0.95, "timestamp": "2026-02-25T10:30:00Z"},
                {"agent": "ctem_correlator", "action": "CTEM: VPN misconfiguration exposure found for user", "confidence": 0.82, "timestamp": "2026-02-25T10:30:30Z"},
                {"agent": "reasoning_agent", "action": "Escalated — possible account compromise via VPN gap", "confidence": 0.78, "timestamp": "2026-02-25T10:31:00Z"},
            ],
        },
        {
            "id": str(uuid.uuid4()),
            "alert_id": "elastic-endpoint-proc-019",
            "tenant_id": "contoso",
            "state": InvestigationState.RESPONDING,
            "severity": "critical",
            "classification": "true_positive",
            "confidence": 0.95,
            "chain": [
                {"agent": "ioc_extractor", "action": "Extracted encoded PowerShell, C2 IP, user account", "confidence": 0.98, "timestamp": "2026-02-25T06:45:00Z"},
                {"agent": "reasoning_agent", "action": "True positive: Cobalt Strike beacon detected", "confidence": 0.95, "timestamp": "2026-02-25T06:46:00Z"},
                {"agent": "response_agent", "action": "Executing playbook: isolate host, block C2 IP", "confidence": 0.95, "timestamp": "2026-02-25T06:46:30Z"},
            ],
        },
    ]

    for d in demos:
        gs = GraphState(
            investigation_id=d["id"],
            state=d["state"],
            alert_id=d["alert_id"],
            tenant_id=d["tenant_id"],
            severity=d["severity"],
            classification=d["classification"],
            confidence=d["confidence"],
            decision_chain=d["chain"],
        )
        db._investigations[d["id"]] = {
            "investigation_id": d["id"],
            "alert_id": d["alert_id"],
            "tenant_id": d["tenant_id"],
            "state": d["state"].value,
            "graphstate_json": json.loads(gs.model_dump_json()),
            "decision_chain": d["chain"],
            "updated_at": d["chain"][-1]["timestamp"],
            "created_at": d["chain"][0]["timestamp"],
            "severity": d["severity"],
            "classification": d["classification"],
        }


def main() -> None:
    db = MockPostgresClient()
    _seed_demo_data(db)

    from services.dashboard.app import init_app
    app = init_app(db)

    print("\n  ALUSKORT Analyst Dashboard")
    print("  http://localhost:8080\n")
    print("  Demo data: 5 investigations (2 awaiting approval)")
    print("  RBAC: add header X-User-Role: senior_analyst to approve/reject\n")

    uvicorn.run(app, host="0.0.0.0", port=8080)


if __name__ == "__main__":
    main()
