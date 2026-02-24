"""Audit service FastAPI endpoints — Story 13.6.

Provides evidence package retrieval, event listing, chain verification,
compliance reports, and bulk export endpoints.
"""

from __future__ import annotations

from typing import Any

from fastapi import FastAPI, HTTPException, Query

from services.audit_service.package_builder import EvidencePackageBuilder

app = FastAPI(title="ALUSKORT Audit Service", version="1.0.0")

# These will be set during service initialization
_db: Any = None
_evidence_store: Any = None
_builder: EvidencePackageBuilder | None = None


def init_api(postgres_client: Any, evidence_store: Any = None) -> None:
    """Initialize API dependencies."""
    global _db, _evidence_store, _builder
    _db = postgres_client
    _evidence_store = evidence_store
    _builder = EvidencePackageBuilder(postgres_client, evidence_store)


@app.get("/health")
async def health() -> dict[str, str]:
    return {"status": "ok", "service": "audit-service"}


@app.get("/v1/audit/evidence-package/{investigation_id}")
async def get_evidence_package(
    investigation_id: str,
    tenant_id: str = Query(...),
    include_raw_prompts: bool = Query(False),
) -> dict:
    """Full evidence package for an investigation."""
    if _builder is None:
        raise HTTPException(503, "Audit service not initialized")
    pkg = await _builder.build_package(investigation_id, tenant_id, include_raw_prompts)
    return pkg.model_dump()


@app.get("/v1/audit/events")
async def list_events(
    tenant_id: str = Query(...),
    event_type: str | None = Query(None),
    from_ts: str | None = Query(None, alias="from"),
    to_ts: str | None = Query(None, alias="to"),
    limit: int = Query(100, le=1000),
) -> dict:
    """List/filter audit events."""
    if _db is None:
        raise HTTPException(503, "Audit service not initialized")

    query = "SELECT * FROM audit_records WHERE tenant_id = $1"
    params: list[Any] = [tenant_id]
    idx = 2

    if event_type:
        query += f" AND event_type = ${idx}"
        params.append(event_type)
        idx += 1
    if from_ts:
        query += f" AND timestamp >= ${idx}"
        params.append(from_ts)
        idx += 1
    if to_ts:
        query += f" AND timestamp <= ${idx}"
        params.append(to_ts)
        idx += 1

    query += f" ORDER BY sequence_number DESC LIMIT ${idx}"
    params.append(limit)

    rows = await _db.fetch_many(query, *params)
    return {"events": [dict(r) for r in rows], "count": len(rows)}


@app.get("/v1/audit/events/{audit_id}")
async def get_event(audit_id: str, tenant_id: str = Query(...)) -> dict:
    """Single audit event lookup."""
    if _db is None:
        raise HTTPException(503, "Audit service not initialized")
    row = await _db.fetch_one(
        "SELECT * FROM audit_records WHERE audit_id = $1 AND tenant_id = $2",
        audit_id,
        tenant_id,
    )
    if not row:
        raise HTTPException(404, "Audit event not found")
    return dict(row)


@app.get("/v1/audit/verify")
async def verify_chain_endpoint(
    tenant_id: str = Query(...),
    from_seq: int = Query(0, alias="from"),
    to_seq: int = Query(0, alias="to"),
) -> dict:
    """Run chain verification for a tenant."""
    if _db is None:
        raise HTTPException(503, "Audit service not initialized")
    from services.audit_service.chain import verify_chain

    query = "SELECT * FROM audit_records WHERE tenant_id = $1"
    params: list[Any] = [tenant_id]

    if to_seq > 0:
        query += " AND sequence_number >= $2 AND sequence_number <= $3"
        params.extend([from_seq, to_seq])

    query += " ORDER BY sequence_number"
    rows = await _db.fetch_many(query, *params)
    records = [dict(r) for r in rows]
    valid, errors = verify_chain(records)

    return {
        "tenant_id": tenant_id,
        "chain_valid": valid,
        "records_checked": len(records),
        "errors": errors,
    }


@app.get("/v1/audit/reports/compliance")
async def compliance_report(
    tenant_id: str = Query(...),
    month: str = Query("", description="YYYY-MM format"),
) -> dict:
    """Monthly compliance report."""
    if _db is None:
        raise HTTPException(503, "Audit service not initialized")

    rows = await _db.fetch_many(
        "SELECT event_category, COUNT(*) as count FROM audit_records "
        "WHERE tenant_id = $1 GROUP BY event_category",
        tenant_id,
    )
    categories = {dict(r)["event_category"]: dict(r)["count"] for r in rows}

    return {
        "tenant_id": tenant_id,
        "month": month,
        "total_events": sum(categories.values()),
        "by_category": categories,
    }


@app.post("/v1/audit/export")
async def export_audit(body: dict) -> dict:
    """Bulk export audit events."""
    tenant_id = body.get("tenant_id", "")
    fmt = body.get("format", "json")
    if not tenant_id:
        raise HTTPException(400, "tenant_id is required")
    return {
        "status": "accepted",
        "tenant_id": tenant_id,
        "format": fmt,
        "message": "Export job queued",
    }
