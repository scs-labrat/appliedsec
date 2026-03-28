"""CTEM (Continuous Threat Exposure Management) dashboard routes.

Provides HTML page and JSON API for viewing CTEM exposures, validation
status, and remediation progress across all connected scanning tools.
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Query, Request
from fastapi.responses import HTMLResponse

from services.dashboard.app import templates
from services.dashboard.deps import get_db

router = APIRouter()

# -- CTEM source tool metadata ------------------------------------------------

CTEM_SOURCES: list[dict[str, Any]] = [
    {
        "id": "wiz",
        "label": "Wiz CSPM",
        "description": "Cloud misconfigurations & compliance violations",
        "kafka_topic": "ctem.raw.wiz",
    },
    {
        "id": "snyk",
        "label": "Snyk SCA",
        "description": "Dependency vulnerabilities & license risks",
        "kafka_topic": "ctem.raw.snyk",
    },
    {
        "id": "garak",
        "label": "Garak LLM Scanner",
        "description": "LLM prompt injection & jailbreak probes",
        "kafka_topic": "ctem.raw.garak",
    },
    {
        "id": "art",
        "label": "MITRE ART",
        "description": "Adversarial ML robustness testing",
        "kafka_topic": "ctem.raw.art",
    },
    {
        "id": "burp",
        "label": "Burp Suite",
        "description": "DAST web application scanning",
        "kafka_topic": "ctem.raw.burp",
    },
]


# -- HTML page ----------------------------------------------------------------

@router.get("/ctem", response_class=HTMLResponse)
async def ctem_page(request: Request) -> HTMLResponse:
    """Render the CTEM exposures dashboard page."""
    exposures = await _list_exposures(limit=50)
    stats = await _build_stats()
    source_counts = await _source_counts()

    # Annotate source metadata with live counts
    sources_with_counts = []
    for src in CTEM_SOURCES:
        entry = {**src, "count": source_counts.get(src["id"], 0)}
        entry["status"] = "active" if entry["count"] > 0 else "idle"
        sources_with_counts.append(entry)

    return templates.TemplateResponse(
        request,
        "ctem/index.html",
        {
            "exposures": exposures,
            "stats": stats,
            "sources": sources_with_counts,
        },
    )


# -- JSON API endpoints -------------------------------------------------------

@router.get("/api/ctem/exposures")
async def api_ctem_exposures(
    severity: str | None = Query(None),
    source_tool: str | None = Query(None),
    status: str | None = Query(None),
    asset_zone: str | None = Query(None),
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
) -> dict[str, Any]:
    """List CTEM exposures with optional filters."""
    exposures = await _list_exposures(
        severity=severity,
        source_tool=source_tool,
        status=status,
        asset_zone=asset_zone,
        limit=limit,
        offset=offset,
    )
    return {"exposures": exposures, "count": len(exposures)}


@router.get("/api/ctem/stats")
async def api_ctem_stats() -> dict[str, Any]:
    """Return CTEM summary statistics."""
    return await _build_stats()


# -- Helpers -------------------------------------------------------------------

async def _list_exposures(
    *,
    severity: str | None = None,
    source_tool: str | None = None,
    status: str | None = None,
    asset_zone: str | None = None,
    limit: int = 50,
    offset: int = 0,
) -> list[dict[str, Any]]:
    """Fetch exposures from the ctem_exposures table with optional filters."""
    db = get_db()
    if db is None:
        return []

    try:
        clauses: list[str] = []
        params: list[Any] = []
        idx = 1

        if severity:
            clauses.append(f"severity = ${idx}")
            params.append(severity.upper())
            idx += 1
        if source_tool:
            clauses.append(f"source_tool = ${idx}")
            params.append(source_tool.lower())
            idx += 1
        if status:
            clauses.append(f"status = ${idx}")
            params.append(status.lower())
            idx += 1
        if asset_zone:
            clauses.append(f"asset_zone = ${idx}")
            params.append(asset_zone)
            idx += 1

        where = f"WHERE {' AND '.join(clauses)}" if clauses else ""

        query = f"""
            SELECT exposure_key, ts, source_tool, title, description,
                   asset_id, asset_type, asset_zone, severity,
                   original_severity, exploitability_score, ctem_score,
                   physical_consequence, atlas_technique, attack_technique,
                   status, assigned_to, sla_deadline,
                   remediation_guidance, tenant_id
            FROM ctem_exposures
            {where}
            ORDER BY ts DESC
            LIMIT ${idx} OFFSET ${idx + 1}
        """
        params.extend([limit, offset])

        rows = await db.fetch_many(query, *params)
        return [dict(r) for r in rows]
    except Exception:
        return []


async def _build_stats() -> dict[str, Any]:
    """Build summary statistics from ctem_exposures, ctem_validations, ctem_remediations."""
    db = get_db()
    defaults: dict[str, Any] = {
        "total": 0,
        "by_severity": {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0},
        "by_status": {
            "open": 0,
            "in_progress": 0,
            "remediated": 0,
            "verified": 0,
            "closed": 0,
        },
        "by_source": {},
        "validations_count": 0,
        "remediations_count": 0,
        "sources_active": 0,
    }

    if db is None:
        return defaults

    stats = dict(defaults)

    # Severity counts
    try:
        rows = await db.fetch_many(
            "SELECT severity, count(*) AS cnt FROM ctem_exposures GROUP BY severity"
        )
        severity_map: dict[str, int] = {}
        total = 0
        for r in rows:
            severity_map[r["severity"]] = r["cnt"]
            total += r["cnt"]
        stats["by_severity"] = {
            "CRITICAL": severity_map.get("CRITICAL", 0),
            "HIGH": severity_map.get("HIGH", 0),
            "MEDIUM": severity_map.get("MEDIUM", 0),
            "LOW": severity_map.get("LOW", 0),
        }
        stats["total"] = total
    except Exception:
        pass

    # Status counts
    try:
        rows = await db.fetch_many(
            "SELECT status, count(*) AS cnt FROM ctem_exposures GROUP BY status"
        )
        status_map: dict[str, int] = {}
        for r in rows:
            status_map[r["status"]] = r["cnt"]
        stats["by_status"] = {
            "open": status_map.get("open", 0),
            "in_progress": status_map.get("in_progress", 0),
            "remediated": status_map.get("remediated", 0),
            "verified": status_map.get("verified", 0),
            "closed": status_map.get("closed", 0),
        }
    except Exception:
        pass

    # Source counts
    try:
        rows = await db.fetch_many(
            "SELECT source_tool, count(*) AS cnt FROM ctem_exposures GROUP BY source_tool"
        )
        source_map: dict[str, int] = {}
        for r in rows:
            source_map[r["source_tool"]] = r["cnt"]
        stats["by_source"] = source_map
        stats["sources_active"] = len(source_map)
    except Exception:
        pass

    # Validation count
    try:
        row = await db.fetch_one("SELECT count(*) AS cnt FROM ctem_validations")
        stats["validations_count"] = row["cnt"] if row else 0
    except Exception:
        pass

    # Remediation count
    try:
        row = await db.fetch_one("SELECT count(*) AS cnt FROM ctem_remediations")
        stats["remediations_count"] = row["cnt"] if row else 0
    except Exception:
        pass

    return stats


async def _source_counts() -> dict[str, int]:
    """Return exposure count per source_tool."""
    db = get_db()
    if db is None:
        return {}

    try:
        rows = await db.fetch_many(
            "SELECT source_tool, count(*) AS cnt FROM ctem_exposures GROUP BY source_tool"
        )
        return {r["source_tool"]: r["cnt"] for r in rows}
    except Exception:
        return {}
