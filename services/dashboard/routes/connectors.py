"""Connector configuration routes.

Provides HTML page and JSON API for managing SIEM/event ingestion connectors.
"""

from __future__ import annotations

import json
import uuid
from typing import Any

from fastapi import APIRouter, HTTPException, Query, Request
from fastapi.responses import HTMLResponse
from pydantic import BaseModel, Field

from services.dashboard.app import templates
from services.dashboard.deps import get_db

router = APIRouter()

# -- Connector type metadata (drives the UI form fields) ------------------

CONNECTOR_CATEGORIES: list[dict[str, Any]] = [
    {"id": "siem", "label": "SIEM / Alert Ingestion", "description": "Ingest alerts from SIEM platforms"},
    {"id": "ctem", "label": "CTEM / Exposure Scanning", "description": "Continuous threat exposure management tools"},
    {"id": "cti", "label": "CTI / Threat Intelligence", "description": "Threat intelligence feeds and IOC sources"},
]

CONNECTOR_TYPES: list[dict[str, Any]] = [
    # ---- SIEM Adapters ----
    {
        "adapter_type": "elastic",
        "label": "Elastic SIEM",
        "category": "siem",
        "modes": ["polling"],
        "fields": [
            {"name": "es_host", "label": "Elasticsearch Host", "type": "url",
             "placeholder": "https://es.example.com:9200", "required": True},
            {"name": "es_api_key", "label": "API Key", "type": "password", "required": True},
            {"name": "poll_interval", "label": "Poll Interval (s)", "type": "number",
             "placeholder": "30", "required": False},
        ],
    },
    {
        "adapter_type": "splunk",
        "label": "Splunk",
        "category": "siem",
        "modes": ["polling", "webhook"],
        "fields": [
            {"name": "splunk_host", "label": "Splunk Host", "type": "url",
             "placeholder": "https://splunk.example.com:8089", "required": True,
             "show_for": "polling"},
            {"name": "splunk_token", "label": "Auth Token", "type": "password", "required": True},
            {"name": "poll_interval", "label": "Poll Interval (s)", "type": "number",
             "placeholder": "60", "required": False, "show_for": "polling"},
            {"name": "hec_port", "label": "HEC Listen Port", "type": "number",
             "placeholder": "8088", "required": False, "show_for": "webhook"},
        ],
    },
    {
        "adapter_type": "sentinel",
        "label": "Microsoft Sentinel",
        "category": "siem",
        "modes": ["polling", "eventhub"],
        "fields": [
            {"name": "workspace_id", "label": "Log Analytics Workspace ID", "type": "text",
             "placeholder": "xxxxxxxx-xxxx-...", "required": True, "show_for": "polling"},
            {"name": "credential", "label": "Azure Credential / Client Secret", "type": "password",
             "required": True},
            {"name": "poll_interval", "label": "Poll Interval (s)", "type": "number",
             "placeholder": "30", "required": False, "show_for": "polling"},
            {"name": "event_hub_connection_string", "label": "Event Hub Connection String",
             "type": "password", "required": True, "show_for": "eventhub"},
            {"name": "consumer_group", "label": "Consumer Group", "type": "text",
             "placeholder": "$Default", "required": False, "show_for": "eventhub"},
        ],
    },
    # ---- CTEM / Exposure Tools ----
    {
        "adapter_type": "wiz",
        "label": "Wiz CSPM",
        "category": "ctem",
        "modes": ["webhook", "polling"],
        "fields": [
            {"name": "wiz_api_url", "label": "Wiz API URL", "type": "url",
             "placeholder": "https://api.us1.app.wiz.io/graphql", "required": True},
            {"name": "wiz_client_id", "label": "Client ID", "type": "text", "required": True},
            {"name": "wiz_client_secret", "label": "Client Secret", "type": "password", "required": True},
            {"name": "webhook_secret", "label": "Webhook Secret", "type": "password",
             "required": False, "show_for": "webhook"},
            {"name": "poll_interval", "label": "Poll Interval (s)", "type": "number",
             "placeholder": "300", "required": False, "show_for": "polling"},
        ],
    },
    {
        "adapter_type": "snyk",
        "label": "Snyk SCA",
        "category": "ctem",
        "modes": ["webhook", "polling"],
        "fields": [
            {"name": "snyk_api_token", "label": "API Token", "type": "password", "required": True},
            {"name": "snyk_org_id", "label": "Organization ID", "type": "text",
             "placeholder": "xxxxxxxx-xxxx-...", "required": True},
            {"name": "snyk_api_url", "label": "API URL", "type": "url",
             "placeholder": "https://api.snyk.io", "required": False},
            {"name": "poll_interval", "label": "Poll Interval (s)", "type": "number",
             "placeholder": "600", "required": False, "show_for": "polling"},
        ],
    },
    {
        "adapter_type": "garak",
        "label": "Garak LLM Scanner",
        "category": "ctem",
        "modes": ["webhook"],
        "fields": [
            {"name": "garak_results_dir", "label": "Results Directory", "type": "text",
             "placeholder": "/data/garak/results", "required": True},
            {"name": "webhook_secret", "label": "Webhook Secret", "type": "password",
             "required": False},
        ],
    },
    {
        "adapter_type": "art",
        "label": "MITRE ART (Adversarial ML)",
        "category": "ctem",
        "modes": ["webhook"],
        "fields": [
            {"name": "art_api_url", "label": "ART API URL", "type": "url",
             "placeholder": "http://art-runner:8090", "required": True},
            {"name": "art_api_key", "label": "API Key", "type": "password", "required": False},
        ],
    },
    {
        "adapter_type": "burp",
        "label": "Burp Suite",
        "category": "ctem",
        "modes": ["webhook"],
        "fields": [
            {"name": "burp_api_url", "label": "Burp Enterprise API URL", "type": "url",
             "placeholder": "https://burp.example.com:8443", "required": True},
            {"name": "burp_api_key", "label": "API Key", "type": "password", "required": True},
        ],
    },
    # ---- CTI / Threat Intelligence Feeds ----
    {
        "adapter_type": "misp",
        "label": "MISP",
        "category": "cti",
        "modes": ["polling"],
        "fields": [
            {"name": "misp_url", "label": "MISP URL", "type": "url",
             "placeholder": "https://misp.example.com", "required": True},
            {"name": "misp_api_key", "label": "API Key", "type": "password", "required": True},
            {"name": "poll_interval", "label": "Poll Interval (s)", "type": "number",
             "placeholder": "300", "required": False},
        ],
    },
    {
        "adapter_type": "taxii",
        "label": "STIX/TAXII Feed",
        "category": "cti",
        "modes": ["polling"],
        "fields": [
            {"name": "taxii_url", "label": "TAXII Server URL", "type": "url",
             "placeholder": "https://taxii.example.com/taxii2/", "required": True},
            {"name": "collection_id", "label": "Collection ID", "type": "text", "required": True},
            {"name": "taxii_user", "label": "Username", "type": "text", "required": False},
            {"name": "taxii_password", "label": "Password", "type": "password", "required": False},
            {"name": "poll_interval", "label": "Poll Interval (s)", "type": "number",
             "placeholder": "600", "required": False},
        ],
    },
    {
        "adapter_type": "otx",
        "label": "AlienVault OTX",
        "category": "cti",
        "modes": ["polling"],
        "fields": [
            {"name": "otx_api_key", "label": "OTX API Key", "type": "password", "required": True},
            {"name": "pulse_subscriptions", "label": "Pulse Subscriptions (comma-separated)",
             "type": "text", "placeholder": "all", "required": False},
            {"name": "poll_interval", "label": "Poll Interval (s)", "type": "number",
             "placeholder": "900", "required": False},
        ],
    },
    {
        "adapter_type": "abuse_ipdb",
        "label": "AbuseIPDB",
        "category": "cti",
        "modes": ["polling"],
        "fields": [
            {"name": "abuseipdb_api_key", "label": "API Key", "type": "password", "required": True},
            {"name": "confidence_minimum", "label": "Min Confidence Score", "type": "number",
             "placeholder": "80", "required": False},
            {"name": "poll_interval", "label": "Poll Interval (s)", "type": "number",
             "placeholder": "3600", "required": False},
        ],
    },
    # ---- Testing ----
    {
        "adapter_type": "test_harness",
        "label": "Test Harness",
        "category": "testing",
        "modes": ["manual", "continuous"],
        "fields": [
            {"name": "scenario", "label": "Scenario Set", "type": "text",
             "placeholder": "all  (or: apt, insider, malware, cloud, ot)",
             "required": False},
            {"name": "alert_count", "label": "Alerts per Batch", "type": "number",
             "placeholder": "5", "required": False},
            {"name": "interval", "label": "Auto-fire Interval (s)", "type": "number",
             "placeholder": "60", "required": False, "show_for": "continuous"},
        ],
    },
]

CONNECTOR_CATEGORIES.append(
    {"id": "testing", "label": "Testing / Simulation",
     "description": "Generate synthetic alerts for end-to-end validation"},
)


# -- HTML page ------------------------------------------------------------

@router.get("/connectors", response_class=HTMLResponse)
async def connectors_page(request: Request) -> HTMLResponse:
    """Render the connectors configuration page."""
    connectors = await _list_connectors()
    return templates.TemplateResponse(
        request,
        "connectors/list.html",
        {
            "connectors": connectors,
            "connector_types": CONNECTOR_TYPES,
            "connector_categories": CONNECTOR_CATEGORIES,
        },
    )


# -- JSON API endpoints ---------------------------------------------------

class ConnectorCreate(BaseModel):
    name: str
    adapter_type: str
    connector_mode: str = "polling"
    config: dict[str, Any] = Field(default_factory=dict)
    enabled: bool = True
    tenant_id: str = "default"


class ConnectorUpdate(BaseModel):
    name: str | None = None
    connector_mode: str | None = None
    config: dict[str, Any] | None = None
    enabled: bool | None = None


@router.get("/api/connectors")
async def api_list_connectors() -> dict[str, Any]:
    """List all configured connectors."""
    connectors = await _list_connectors()
    return {"connectors": connectors, "count": len(connectors)}


@router.post("/api/connectors")
async def api_create_connector(req: ConnectorCreate) -> dict[str, Any]:
    """Create a new connector configuration."""
    db = get_db()
    if db is None:
        raise HTTPException(503, "Database not available")

    connector_id = str(uuid.uuid4())
    await db.execute(
        """
        INSERT INTO connectors (connector_id, tenant_id, name, adapter_type,
                                connector_mode, config, enabled)
        VALUES ($1, $2, $3, $4, $5, $6, $7)
        """,
        connector_id, req.tenant_id, req.name, req.adapter_type,
        req.connector_mode, json.dumps(req.config), req.enabled,
    )
    return {"connector_id": connector_id, "status": "created"}


@router.put("/api/connectors/{connector_id}")
async def api_update_connector(
    connector_id: str, req: ConnectorUpdate,
) -> dict[str, Any]:
    """Update an existing connector configuration."""
    db = get_db()
    if db is None:
        raise HTTPException(503, "Database not available")

    sets: list[str] = []
    params: list[Any] = []
    idx = 2  # $1 is connector_id

    if req.name is not None:
        sets.append(f"name = ${idx}")
        params.append(req.name)
        idx += 1
    if req.connector_mode is not None:
        sets.append(f"connector_mode = ${idx}")
        params.append(req.connector_mode)
        idx += 1
    if req.config is not None:
        sets.append(f"config = ${idx}")
        params.append(json.dumps(req.config))
        idx += 1
    if req.enabled is not None:
        sets.append(f"enabled = ${idx}")
        params.append(req.enabled)
        idx += 1

    if not sets:
        return {"status": "no changes"}

    sets.append("updated_at = now()")
    query = f"UPDATE connectors SET {', '.join(sets)} WHERE connector_id = $1"
    await db.execute(query, connector_id, *params)
    return {"status": "updated"}


@router.delete("/api/connectors/{connector_id}")
async def api_delete_connector(connector_id: str) -> dict[str, Any]:
    """Delete a connector configuration."""
    db = get_db()
    if db is None:
        raise HTTPException(503, "Database not available")

    await db.execute(
        "DELETE FROM connectors WHERE connector_id = $1", connector_id,
    )
    return {"status": "deleted"}


@router.post("/api/connectors/{connector_id}/toggle")
async def api_toggle_connector(connector_id: str) -> dict[str, Any]:
    """Toggle a connector's enabled state."""
    db = get_db()
    if db is None:
        raise HTTPException(503, "Database not available")

    await db.execute(
        """
        UPDATE connectors SET enabled = NOT enabled, updated_at = now()
        WHERE connector_id = $1
        """,
        connector_id,
    )
    return {"status": "toggled"}


# -- Helpers ---------------------------------------------------------------

async def _list_connectors() -> list[dict[str, Any]]:
    """Fetch all connectors from DB, falling back to empty list."""
    db = get_db()
    if db is None:
        return []

    try:
        rows = await db.fetch_many(
            """
            SELECT connector_id, tenant_id, name, adapter_type,
                   connector_mode, config, enabled, created_at, updated_at
            FROM connectors
            ORDER BY created_at DESC
            """,
        )
        return [dict(r) for r in rows]
    except Exception:
        return []
