"""CTI (Cyber Threat Intelligence) dashboard routes.

Provides HTML page and JSON APIs for viewing threat intelligence IOCs,
feed status, and summary statistics.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any

from fastapi import APIRouter, Query, Request
from fastapi.responses import HTMLResponse

from services.dashboard.app import templates
from services.dashboard.deps import get_db

logger = logging.getLogger(__name__)

router = APIRouter()

# -- CTI Source Definitions ------------------------------------------------

IOC_SOURCES: list[dict[str, Any]] = [
    {
        "id": "misp",
        "label": "MISP",
        "description": "Malware Information Sharing Platform",
        "icon": "M",
        "color": "blue",
    },
    {
        "id": "taxii",
        "label": "STIX/TAXII",
        "description": "Structured Threat Information eXpression feeds",
        "icon": "T",
        "color": "purple",
    },
    {
        "id": "otx",
        "label": "AlienVault OTX",
        "description": "Open Threat Exchange pulse subscriptions",
        "icon": "O",
        "color": "green",
    },
    {
        "id": "abuseipdb",
        "label": "AbuseIPDB",
        "description": "Community-driven IP abuse reports",
        "icon": "A",
        "color": "orange",
    },
]

IOC_TYPES: list[str] = ["ip", "domain", "file_hash", "url", "email", "account"]


# -- Helpers ---------------------------------------------------------------

async def _fetch_iocs(
    limit: int = 100,
    offset: int = 0,
    ioc_type: str | None = None,
    source: str | None = None,
    search: str | None = None,
) -> list[dict[str, Any]]:
    """Fetch IOCs from the threat_intel_iocs table."""
    db = get_db()
    if db is None:
        return []

    try:
        clauses: list[str] = []
        params: list[Any] = []
        idx = 1

        if ioc_type:
            clauses.append(f"ioc_type = ${idx}")
            params.append(ioc_type)
            idx += 1
        if source:
            clauses.append(f"source = ${idx}")
            params.append(source)
            idx += 1
        if search:
            clauses.append(f"value ILIKE ${idx}")
            params.append(f"%{search}%")
            idx += 1

        where = f"WHERE {' AND '.join(clauses)}" if clauses else ""

        params.append(limit)
        limit_param = f"${idx}"
        idx += 1
        params.append(offset)
        offset_param = f"${idx}"

        rows = await db.fetch_many(
            f"""
            SELECT ioc_id, ioc_type, value, source, threat_type,
                   confidence, first_seen, last_seen, tags
            FROM threat_intel_iocs
            {where}
            ORDER BY first_seen DESC
            LIMIT {limit_param} OFFSET {offset_param}
            """,
            *params,
        )
        return [dict(r) for r in rows]
    except Exception as exc:
        logger.warning("IOC query failed (table may not exist): %s", exc)
        return []


async def _fetch_stats() -> dict[str, Any]:
    """Aggregate IOC statistics."""
    db = get_db()
    if db is None:
        return _empty_stats()

    stats: dict[str, Any] = {}

    try:
        # Total count
        row = await db.fetch_one(
            "SELECT COUNT(*) AS total FROM threat_intel_iocs"
        )
        stats["total"] = dict(row).get("total", 0) if row else 0

        # Count by type
        rows = await db.fetch_many(
            "SELECT ioc_type, COUNT(*) AS count FROM threat_intel_iocs GROUP BY ioc_type"
        )
        stats["by_type"] = {dict(r)["ioc_type"]: dict(r)["count"] for r in rows}

        # Count by source
        rows = await db.fetch_many(
            "SELECT source, COUNT(*) AS count FROM threat_intel_iocs GROUP BY source"
        )
        stats["by_source"] = {dict(r)["source"]: dict(r)["count"] for r in rows}

        # Recent additions (last 24h)
        row = await db.fetch_one(
            """
            SELECT COUNT(*) AS count FROM threat_intel_iocs
            WHERE first_seen >= NOW() - INTERVAL '24 hours'
            """
        )
        stats["recent_24h"] = dict(row).get("count", 0) if row else 0

        # Recent additions (last 7d)
        row = await db.fetch_one(
            """
            SELECT COUNT(*) AS count FROM threat_intel_iocs
            WHERE first_seen >= NOW() - INTERVAL '7 days'
            """
        )
        stats["recent_7d"] = dict(row).get("count", 0) if row else 0

    except Exception as exc:
        logger.warning("IOC stats query failed (table may not exist): %s", exc)
        return _empty_stats()

    return stats


async def _fetch_feed_status() -> list[dict[str, Any]]:
    """Build feed status for each configured CTI source."""
    db = get_db()
    feeds: list[dict[str, Any]] = []

    for src in IOC_SOURCES:
        feed: dict[str, Any] = {
            "id": src["id"],
            "label": src["label"],
            "description": src["description"],
            "icon": src["icon"],
            "color": src["color"],
            "status": "disconnected",
            "last_sync": None,
            "ioc_count": 0,
        }

        if db is not None:
            try:
                # Check if connector is configured and enabled
                row = await db.fetch_one(
                    """
                    SELECT enabled, updated_at
                    FROM connectors
                    WHERE adapter_type = $1
                    ORDER BY created_at DESC
                    LIMIT 1
                    """,
                    src["id"],
                )
                if row:
                    d = dict(row)
                    feed["status"] = "connected" if d.get("enabled") else "disabled"
                    feed["last_sync"] = d.get("updated_at")

                # IOC count from this source
                row = await db.fetch_one(
                    "SELECT COUNT(*) AS count FROM threat_intel_iocs WHERE source = $1",
                    src["id"],
                )
                if row:
                    feed["ioc_count"] = dict(row).get("count", 0)
            except Exception:
                pass  # Table may not exist yet

        feeds.append(feed)

    return feeds


def _empty_stats() -> dict[str, Any]:
    """Return zero-value stats for empty/unavailable DB."""
    return {
        "total": 0,
        "by_type": {},
        "by_source": {},
        "recent_24h": 0,
        "recent_7d": 0,
    }


# -- HTML page -------------------------------------------------------------

@router.get("/cti", response_class=HTMLResponse)
async def cti_page(request: Request) -> HTMLResponse:
    """Render the CTI threat intelligence dashboard."""
    stats = await _fetch_stats()
    feeds = await _fetch_feed_status()
    iocs = await _fetch_iocs(limit=50)

    return templates.TemplateResponse(
        request,
        "cti/index.html",
        {
            "stats": stats,
            "feeds": feeds,
            "iocs": iocs,
            "ioc_sources": IOC_SOURCES,
            "ioc_types": IOC_TYPES,
        },
    )


# -- JSON API endpoints ----------------------------------------------------

@router.get("/api/cti/iocs")
async def api_cti_iocs(
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    ioc_type: str | None = Query(None),
    source: str | None = Query(None),
    search: str | None = Query(None),
) -> dict[str, Any]:
    """JSON endpoint for IOC listing with optional filters."""
    iocs = await _fetch_iocs(
        limit=limit, offset=offset,
        ioc_type=ioc_type, source=source, search=search,
    )
    return {"iocs": iocs, "count": len(iocs)}


@router.get("/api/cti/stats")
async def api_cti_stats() -> dict[str, Any]:
    """JSON endpoint for IOC summary statistics."""
    stats = await _fetch_stats()
    feeds = await _fetch_feed_status()
    return {"stats": stats, "feeds": feeds}
