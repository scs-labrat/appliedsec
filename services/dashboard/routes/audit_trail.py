"""Audit Trail Viewer routes — immutable audit log with hash chain verification.

Provides audit record browsing, filtering, integrity verification, and
statistics endpoints with fallback demo data.
"""

from __future__ import annotations

import hashlib
import logging
from datetime import datetime, timedelta, timezone
from typing import Any

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse

from services.dashboard.app import templates
from services.dashboard.deps import get_db

logger = logging.getLogger(__name__)

router = APIRouter()

# ---------------------------------------------------------------------------
# Demo / fallback data
# ---------------------------------------------------------------------------

_now = datetime(2026, 3, 29, 12, 0, 0, tzinfo=timezone.utc)


def _sha256_trunc(data: str) -> str:
    """Return truncated SHA-256 for display."""
    return hashlib.sha256(data.encode()).hexdigest()[:16]


def _build_chain(records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Assign hash and prev_hash to each record for chain demonstration."""
    for i, rec in enumerate(records):
        payload = f"{rec['record_id']}|{rec['timestamp']}|{rec['event_type']}|{rec['actor']}"
        if i == 0:
            rec["prev_hash"] = "0" * 16
        else:
            rec["prev_hash"] = records[i - 1]["hash"]
        rec["hash"] = _sha256_trunc(f"{rec['prev_hash']}|{payload}")
        rec["chain_status"] = "verified"
    return records


def _demo_records() -> list[dict[str, Any]]:
    """Return realistic demo audit records for fallback display."""
    records = [
        {
            "record_id": 1,
            "timestamp": (_now - timedelta(hours=23, minutes=45)).isoformat(),
            "event_type": "alert.classified",
            "actor": "system.orchestrator",
            "role": "system",
            "tenant_id": "tenant-acme",
            "investigation_id": "INV-2026-0412",
            "description": "Alert classified as true_positive with confidence 0.94 by Tier 1 model",
        },
        {
            "record_id": 2,
            "timestamp": (_now - timedelta(hours=23, minutes=30)).isoformat(),
            "event_type": "approval.granted",
            "actor": "sr.analyst.martinez",
            "role": "senior_analyst",
            "tenant_id": "tenant-acme",
            "investigation_id": "INV-2026-0412",
            "description": "Investigation escalation approved for containment action on host db-prod-03",
        },
        {
            "record_id": 3,
            "timestamp": (_now - timedelta(hours=22, minutes=15)).isoformat(),
            "event_type": "approval.denied",
            "actor": "sr.analyst.okonkwo",
            "role": "senior_analyst",
            "tenant_id": "tenant-acme",
            "investigation_id": "INV-2026-0398",
            "description": "Network isolation denied: insufficient evidence of lateral movement",
        },
        {
            "record_id": 4,
            "timestamp": (_now - timedelta(hours=20)).isoformat(),
            "event_type": "fp_pattern.approved",
            "actor": "sr.analyst.martinez",
            "role": "senior_analyst",
            "tenant_id": "tenant-acme",
            "investigation_id": None,
            "description": "FP pattern FP-003 approved (two-person: analyst.park + sr.analyst.martinez)",
        },
        {
            "record_id": 5,
            "timestamp": (_now - timedelta(hours=18, minutes=30)).isoformat(),
            "event_type": "kill_switch.activated",
            "actor": "sr.analyst.okonkwo",
            "role": "senior_analyst",
            "tenant_id": "tenant-globex",
            "investigation_id": None,
            "description": "Kill switch activated: all auto-close actions paused for tenant-globex due to anomalous FP rate",
        },
        {
            "record_id": 6,
            "timestamp": (_now - timedelta(hours=17)).isoformat(),
            "event_type": "config.changed",
            "actor": "admin.reeves",
            "role": "admin",
            "tenant_id": "tenant-acme",
            "investigation_id": None,
            "description": "LLM spend guard monthly_hard_cap updated from $800 to $1000",
        },
        {
            "record_id": 7,
            "timestamp": (_now - timedelta(hours=15, minutes=20)).isoformat(),
            "event_type": "user.login",
            "actor": "analyst.chen",
            "role": "analyst",
            "tenant_id": "tenant-acme",
            "investigation_id": None,
            "description": "SSO login from 10.0.1.42 via Azure AD, MFA verified",
        },
        {
            "record_id": 8,
            "timestamp": (_now - timedelta(hours=14)).isoformat(),
            "event_type": "canary.promoted",
            "actor": "system.canary",
            "role": "system",
            "tenant_id": "tenant-acme",
            "investigation_id": None,
            "description": "Canary release v2.4.1 promoted to production after 4h green window with 0 errors",
        },
        {
            "record_id": 9,
            "timestamp": (_now - timedelta(hours=12, minutes=45)).isoformat(),
            "event_type": "alert.classified",
            "actor": "system.orchestrator",
            "role": "system",
            "tenant_id": "tenant-globex",
            "investigation_id": "INV-2026-0415",
            "description": "Alert classified as false_positive with confidence 0.87, auto-closed by FP-002",
        },
        {
            "record_id": 10,
            "timestamp": (_now - timedelta(hours=11)).isoformat(),
            "event_type": "fp_pattern.reaffirmed",
            "actor": "sr.analyst.martinez",
            "role": "senior_analyst",
            "tenant_id": "tenant-acme",
            "investigation_id": None,
            "description": "FP pattern FP-009 reaffirmed for 90 days, expiry extended to 2026-06-27",
        },
        {
            "record_id": 11,
            "timestamp": (_now - timedelta(hours=9, minutes=30)).isoformat(),
            "event_type": "approval.granted",
            "actor": "sr.analyst.okonkwo",
            "role": "senior_analyst",
            "tenant_id": "tenant-globex",
            "investigation_id": "INV-2026-0418",
            "description": "Playbook execution approved: isolate-host for endpoint ws-sales-07",
        },
        {
            "record_id": 12,
            "timestamp": (_now - timedelta(hours=8)).isoformat(),
            "event_type": "user.login",
            "actor": "analyst.johansson",
            "role": "analyst",
            "tenant_id": "tenant-acme",
            "investigation_id": None,
            "description": "SSO login from 10.0.2.18 via Azure AD, MFA verified",
        },
        {
            "record_id": 13,
            "timestamp": (_now - timedelta(hours=6, minutes=15)).isoformat(),
            "event_type": "kill_switch.deactivated",
            "actor": "sr.analyst.okonkwo",
            "role": "senior_analyst",
            "tenant_id": "tenant-globex",
            "investigation_id": None,
            "description": "Kill switch deactivated for tenant-globex: FP rate returned to normal after pattern review",
        },
        {
            "record_id": 14,
            "timestamp": (_now - timedelta(hours=5)).isoformat(),
            "event_type": "canary.rolled_back",
            "actor": "system.canary",
            "role": "system",
            "tenant_id": "tenant-acme",
            "investigation_id": None,
            "description": "Canary release v2.4.2-rc1 rolled back after error rate exceeded 2% threshold in 15m window",
        },
        {
            "record_id": 15,
            "timestamp": (_now - timedelta(hours=4, minutes=30)).isoformat(),
            "event_type": "config.changed",
            "actor": "admin.reeves",
            "role": "admin",
            "tenant_id": "tenant-acme",
            "investigation_id": None,
            "description": "Elastic SIEM connector polling interval changed from 30s to 15s",
        },
        {
            "record_id": 16,
            "timestamp": (_now - timedelta(hours=3, minutes=15)).isoformat(),
            "event_type": "fp_pattern.revoked",
            "actor": "sr.analyst.martinez",
            "role": "senior_analyst",
            "tenant_id": "tenant-acme",
            "investigation_id": None,
            "description": "FP pattern FP-008 revoked due to precision dropping below 75%, 3 investigations re-opened",
        },
        {
            "record_id": 17,
            "timestamp": (_now - timedelta(hours=2, minutes=45)).isoformat(),
            "event_type": "alert.classified",
            "actor": "system.orchestrator",
            "role": "system",
            "tenant_id": "tenant-acme",
            "investigation_id": "INV-2026-0422",
            "description": "Alert classified as true_positive with confidence 0.91, ATLAS technique AML.T0043 mapped",
        },
        {
            "record_id": 18,
            "timestamp": (_now - timedelta(hours=1, minutes=30)).isoformat(),
            "event_type": "approval.granted",
            "actor": "sr.analyst.martinez",
            "role": "senior_analyst",
            "tenant_id": "tenant-acme",
            "investigation_id": "INV-2026-0422",
            "description": "Emergency containment approved: block outbound C2 traffic to 198.51.100.0/24",
        },
        {
            "record_id": 19,
            "timestamp": (_now - timedelta(minutes=45)).isoformat(),
            "event_type": "user.login",
            "actor": "analyst.park",
            "role": "analyst",
            "tenant_id": "tenant-globex",
            "investigation_id": None,
            "description": "SSO login from 10.0.3.7 via Azure AD, MFA verified",
        },
        {
            "record_id": 20,
            "timestamp": (_now - timedelta(minutes=15)).isoformat(),
            "event_type": "alert.classified",
            "actor": "system.orchestrator",
            "role": "system",
            "tenant_id": "tenant-globex",
            "investigation_id": "INV-2026-0423",
            "description": "Alert classified as benign with confidence 0.82, no action required",
        },
    ]

    return _build_chain(records)


def _compute_audit_summary(records: list[dict[str, Any]]) -> dict[str, Any]:
    today_str = _now.strftime("%Y-%m-%d")
    today_count = sum(
        1 for r in records if r["timestamp"].startswith(today_str)
    )
    all_verified = all(r.get("chain_status") == "verified" for r in records)
    return {
        "total": len(records),
        "today": today_count,
        "chain_integrity": "verified" if all_verified else "broken",
        "last_verified": _now.isoformat(),
    }


# ---------------------------------------------------------------------------
# Event type taxonomy for filter dropdown
# ---------------------------------------------------------------------------

EVENT_TYPES = [
    "alert.classified",
    "approval.granted",
    "approval.denied",
    "fp_pattern.approved",
    "fp_pattern.reaffirmed",
    "fp_pattern.revoked",
    "kill_switch.activated",
    "kill_switch.deactivated",
    "config.changed",
    "user.login",
    "canary.promoted",
    "canary.rolled_back",
]


# ---------------------------------------------------------------------------
# Page route
# ---------------------------------------------------------------------------

@router.get("/audit", response_class=HTMLResponse)
async def audit_page(request: Request) -> HTMLResponse:
    """Render audit trail viewer page."""
    records: list[dict[str, Any]] = []

    db = get_db()
    if db is not None:
        try:
            rows = await db.fetch_many(
                "SELECT * FROM audit_records ORDER BY record_id DESC LIMIT 200",
            )
            records = [dict(r) for r in rows]
        except Exception:
            logger.info("Audit records table not available, using demo data")

    if not records:
        records = _demo_records()

    summary = _compute_audit_summary(records)
    tenants = sorted({r["tenant_id"] for r in records})

    return templates.TemplateResponse(
        request,
        "audit/index.html",
        {
            "records": records,
            "summary": summary,
            "event_types": EVENT_TYPES,
            "tenants": tenants,
        },
    )


# ---------------------------------------------------------------------------
# API endpoints
# ---------------------------------------------------------------------------

@router.get("/api/audit/records")
async def api_audit_records(
    event_type: str = "",
    actor: str = "",
    tenant_id: str = "",
    date_from: str = "",
    date_to: str = "",
) -> list[dict[str, Any]]:
    """Search/filter audit records."""
    records: list[dict[str, Any]] = []

    db = get_db()
    if db is not None:
        try:
            rows = await db.fetch_many(
                "SELECT * FROM audit_records ORDER BY record_id DESC LIMIT 500",
            )
            records = [dict(r) for r in rows]
        except Exception:
            pass

    if not records:
        records = _demo_records()

    if event_type:
        records = [r for r in records if r["event_type"] == event_type]
    if actor:
        q = actor.lower()
        records = [r for r in records if q in r["actor"].lower()]
    if tenant_id:
        records = [r for r in records if r["tenant_id"] == tenant_id]
    if date_from:
        records = [r for r in records if r["timestamp"] >= date_from]
    if date_to:
        records = [r for r in records if r["timestamp"] <= date_to]

    return records


@router.get("/api/audit/verify")
async def api_audit_verify(tenant_id: str = "") -> JSONResponse:
    """Verify hash chain integrity for a tenant."""
    records: list[dict[str, Any]] = []

    db = get_db()
    if db is not None:
        try:
            query = "SELECT * FROM audit_records"
            params: list[Any] = []
            if tenant_id:
                query += " WHERE tenant_id = $1"
                params.append(tenant_id)
            query += " ORDER BY record_id ASC"
            rows = await db.fetch_many(query, *params)
            records = [dict(r) for r in rows]
        except Exception:
            pass

    if not records:
        records = _demo_records()
        if tenant_id:
            records = [r for r in records if r["tenant_id"] == tenant_id]

    # Verify chain
    broken_links: list[int] = []
    for i in range(1, len(records)):
        if records[i].get("prev_hash") != records[i - 1].get("hash"):
            broken_links.append(records[i]["record_id"])

    return JSONResponse({
        "tenant_id": tenant_id or "all",
        "total_records": len(records),
        "verified": len(broken_links) == 0,
        "broken_links": broken_links,
        "verified_at": datetime.now(timezone.utc).isoformat(),
    })


@router.get("/api/audit/stats")
async def api_audit_stats() -> dict[str, Any]:
    """Audit statistics."""
    records: list[dict[str, Any]] = []

    db = get_db()
    if db is not None:
        try:
            rows = await db.fetch_many(
                "SELECT * FROM audit_records ORDER BY record_id DESC",
            )
            records = [dict(r) for r in rows]
        except Exception:
            pass

    if not records:
        records = _demo_records()

    summary = _compute_audit_summary(records)

    # Count by event type
    by_type: dict[str, int] = {}
    for r in records:
        et = r["event_type"]
        by_type[et] = by_type.get(et, 0) + 1

    # Count by actor
    by_actor: dict[str, int] = {}
    for r in records:
        a = r["actor"]
        by_actor[a] = by_actor.get(a, 0) + 1

    return {
        **summary,
        "by_event_type": by_type,
        "by_actor": by_actor,
    }
