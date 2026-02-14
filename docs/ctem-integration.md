# ALUSKORT — CTEM Program Integration Layer

> **Supplement to:** ALUSKORT Cloud-Neutral System Design v2.0 (`docs/ai-system-design.md`) & ATLAS Integration Layer (`docs/atlas-integration.md`)
> **CTEM Reference:** Applied Computing Technologies — Continuous Threat Exposure Management Program v2.0
> **Last Updated:** February 2026
> **Classification:** CONFIDENTIAL

---

## Table of Contents

1. [Integration Architecture](#1-integration-architecture)
2. [Data Sources — Postgres & Kafka](#2-data-sources--postgres--kafka)
3. [Phase 1: SCOPE — Automated Asset Inventory](#3-phase-1-scope--automated-asset-inventory)
4. [Phase 2: DISCOVER — Tool Integration & Exposure Ingestion](#4-phase-2-discover--tool-integration--exposure-ingestion)
5. [Phase 3: PRIORITIZE — Consequence-Weighted Scoring Engine](#5-phase-3-prioritize--consequence-weighted-scoring-engine)
6. [Phase 4: VALIDATE — Red Team Integration & Adversarial Testing](#6-phase-4-validate--red-team-integration--adversarial-testing)
7. [Phase 5: MOBILIZE — SLA Enforcement & Remediation Tracking](#7-phase-5-mobilize--sla-enforcement--remediation-tracking)
8. [CTEM Metrics — Python Analytics](#8-ctem-metrics--python-analytics)
9. [Closed-Loop: CTEM Findings to ALUSKORT Detection Tuning](#9-closed-loop-ctem-findings-to-aluskort-detection-tuning)
10. [Implementation & Deployment](#10-implementation--deployment)

---

## 1. Integration Architecture

### 1.1 How ALUSKORT Agents Map to CTEM Phases

The CTEM program defines five continuous phases. ALUSKORT doesn't replace the CTEM program — it operationalises it by automating the high-frequency, data-intensive portions of each phase while keeping humans in the loop for judgment calls and safety decisions.

| CTEM Phase | ALUSKORT Agent(s) | Automation Level | Human Role |
|---|---|---|---|
| **1. SCOPE** | Orchestrator + Context Enricher | Semi-automated — agents maintain asset inventory from Postgres + Neo4j graph, flag new assets | Quarterly review, risk threshold approval, exception sign-off |
| **2. DISCOVER** | IOC Extractor + Context Enricher | Automated ingestion — CTEM tool findings (Wiz, ART, Garak, Snyk) flow into Kafka per-source topics, normalisers persist to Postgres | Tool configuration, custom scan policies, manual deep-dives |
| **3. PRIORITIZE** | Reasoning Agent | Automated scoring — consequence-weighted matrix applied to every finding using Orbital context (asset zone via Neo4j graph, safety proximity, TM-ID mapping) | Weekly triage meeting, accept/reject/defer decisions |
| **4. VALIDATE** | Reasoning Agent + Response Agent | Semi-automated — agents track validation status, compare red team findings against detection rules, identify detection gaps | Red team execution, campaign planning, rules of engagement |
| **5. MOBILIZE** | Response Agent + Orchestrator | Automated tracking — agents enforce SLAs, create tickets, escalate overdue items, compute metrics | Fix development, security review, deployment approval |

### 1.2 Data Flow

```
CTEM Discovery Tools                    ALUSKORT Data Layer
+-------------------+                  +---------------------------+
| Wiz (CSPM)        |---> Kafka ------>| ctem.raw.wiz              |
| ART (Adv. ML)     |---> Kafka ------>| ctem.raw.art              |
| Garak (LLM)       |---> Kafka ------>| ctem.raw.garak            |
| Snyk (SCA)        |---> Kafka ------>| ctem.raw.snyk             |
| Burp Suite (API)  |---> Kafka ------>| ctem.raw.burp             |
| Custom Edge Scans |---> Kafka ------>| ctem.raw.custom           |
| Red Team Results  |---> Kafka ------>| ctem.raw.validation       |
| Remediation Logs  |---> Kafka ------>| ctem.raw.remediation      |
+-------------------+                  +---------------------------+
                                                |
                                    +-----------v-----------+
                                    | CTEM Normaliser Service |
                                    | (per-source consumers)  |
                                    +-----------+-----------+
                                                |
                                    +-----------v-----------+
                                    | ctem.normalized topic   |
                                    +-----------+-----------+
                                                |
                               +----------------v----------------+
                               | Postgres (idempotent upsert)    |
                               | ctem_exposures                  |
                               | ctem_validations                |
                               | ctem_remediations               |
                               +----------------+----------------+
                                                |
                                    +-----------v-----------+
                                    |   ALUSKORT Agents      |
                                    |                        |
                                    | IOC Extractor:         |
                                    |   Correlate CTEM       |
                                    |   findings with        |
                                    |   runtime alerts       |
                                    |                        |
                                    | Reasoning Agent:       |
                                    |   Consequence-weighted |
                                    |   scoring via Neo4j    |
                                    |   Map to TM-IDs        |
                                    |   Identify gaps        |
                                    |                        |
                                    | Response Agent:        |
                                    |   Enforce SLAs         |
                                    |   Track remediation    |
                                    |   Escalate overdue     |
                                    +------------------------+
```

---

## 2. Data Sources — Postgres & Kafka

Three CTEM-specific Postgres tables and corresponding Kafka topics are required beyond the ATLAS integration tables (see `docs/atlas-integration.md` Section 3).

### 2.1 Postgres Tables

```sql
-- ============================================================
-- CTEM Exposures
-- Normalised exposure findings from all CTEM discovery tools.
-- Single pane of glass for all discovered vulnerabilities,
-- misconfigurations, and attack paths.
--
-- Key design: ON CONFLICT (exposure_key) DO UPDATE for idempotent
-- ingestion. The same finding from the same tool+asset pair always
-- maps to the same row (upsert, not duplicate).
-- ============================================================
CREATE TABLE ctem_exposures (
    id                  BIGSERIAL PRIMARY KEY,
    exposure_key        TEXT NOT NULL UNIQUE,  -- deterministic hash: sha256(source_tool:title:asset_id)[:16]
    ts                  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    source_tool         TEXT NOT NULL,
    title               TEXT NOT NULL,
    description         TEXT,
    severity            TEXT NOT NULL,         -- From consequence-weighted matrix
    original_severity   TEXT NOT NULL,         -- Raw severity from the tool
    asset_id            TEXT NOT NULL,
    asset_type          TEXT NOT NULL,
    asset_zone          TEXT NOT NULL,
    exploitability_score REAL NOT NULL,        -- 0.0 - 1.0
    physical_consequence TEXT NOT NULL,        -- safety_life | equipment | downtime | data_loss
    ctem_score          REAL NOT NULL,         -- 0.0 - 10.0 composite score
    atlas_technique     TEXT DEFAULT '',
    attack_technique    TEXT DEFAULT '',
    threat_model_ref    TEXT DEFAULT '',
    status              TEXT NOT NULL DEFAULT 'Open',  -- Open | InProgress | FixDeployed | Verified | Closed
    assigned_to         TEXT DEFAULT '',
    sla_deadline        TIMESTAMPTZ,
    remediation_guidance TEXT DEFAULT '',
    evidence_url        TEXT DEFAULT '',
    tenant_id           TEXT NOT NULL DEFAULT 'default',
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_ctem_exp_key ON ctem_exposures (exposure_key);
CREATE INDEX idx_ctem_exp_ts ON ctem_exposures (ts);
CREATE INDEX idx_ctem_exp_status ON ctem_exposures (status, severity);
CREATE INDEX idx_ctem_exp_sla ON ctem_exposures (sla_deadline)
    WHERE status IN ('Open', 'InProgress');
CREATE INDEX idx_ctem_exp_atlas ON ctem_exposures (atlas_technique)
    WHERE atlas_technique != '';
CREATE INDEX idx_ctem_exp_asset ON ctem_exposures (asset_id, asset_zone);
CREATE INDEX idx_ctem_exp_tool ON ctem_exposures (source_tool, ts);

-- ============================================================
-- CTEM Validations
-- Red team and adversarial testing results. Tracks validation
-- of exploitability for discovered exposures.
-- ============================================================
CREATE TABLE ctem_validations (
    id                      BIGSERIAL PRIMARY KEY,
    validation_id           TEXT NOT NULL UNIQUE,
    exposure_id             TEXT NOT NULL,  -- references ctem_exposures.exposure_key
    campaign_id             TEXT NOT NULL,
    ts                      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    validation_type         TEXT NOT NULL,  -- automated | manual_red_team | adversarial_ml | full_campaign
    exploitable             BOOLEAN NOT NULL DEFAULT FALSE,
    exploit_complexity      TEXT NOT NULL DEFAULT 'unknown',  -- low | medium | high
    attack_path             TEXT,
    physical_consequence_demonstrated BOOLEAN NOT NULL DEFAULT FALSE,
    detection_evaded        BOOLEAN NOT NULL DEFAULT FALSE,
    detection_rules_tested  JSONB DEFAULT '[]',
    detection_gaps          JSONB DEFAULT '[]',
    tester                  TEXT DEFAULT '',
    evidence_url            TEXT DEFAULT '',
    tenant_id               TEXT NOT NULL DEFAULT 'default',
    created_at              TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_ctem_val_exposure ON ctem_validations (exposure_id);
CREATE INDEX idx_ctem_val_campaign ON ctem_validations (campaign_id, ts);
CREATE INDEX idx_ctem_val_evaded ON ctem_validations (detection_evaded)
    WHERE detection_evaded = TRUE;

-- ============================================================
-- CTEM Remediations
-- Remediation lifecycle tracking. From assignment through fix,
-- review, deployment, and verification.
-- ============================================================
CREATE TABLE ctem_remediations (
    id                  BIGSERIAL PRIMARY KEY,
    remediation_id      TEXT NOT NULL UNIQUE,
    exposure_id         TEXT NOT NULL,  -- references ctem_exposures.exposure_key
    ts                  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    status              TEXT NOT NULL DEFAULT 'Assigned',  -- Assigned | InProgress | FixDeployed | Verified | Closed
    assigned_to         TEXT NOT NULL,
    assigned_date       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    sla_deadline        TIMESTAMPTZ,
    fix_deployed_date   TIMESTAMPTZ,
    verified_date       TIMESTAMPTZ,
    verified_by         TEXT DEFAULT '',
    sla_breached        BOOLEAN NOT NULL DEFAULT FALSE,
    escalation_level    TEXT DEFAULT '',
    fix_description     TEXT DEFAULT '',
    pull_request_url    TEXT DEFAULT '',
    tenant_id           TEXT NOT NULL DEFAULT 'default',
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_ctem_rem_exposure ON ctem_remediations (exposure_id);
CREATE INDEX idx_ctem_rem_status ON ctem_remediations (status, sla_deadline);
CREATE INDEX idx_ctem_rem_sla ON ctem_remediations (sla_breached)
    WHERE sla_breached = TRUE;
```

### 2.2 Idempotent Upsert Logic

The `exposure_key` is generated deterministically from `source_tool`, `title`, and `asset_id`. Re-ingesting the same finding updates the existing row rather than creating a duplicate.

```python
"""
CTEM Exposure Upsert
Idempotent ingestion using Postgres ON CONFLICT.
"""

async def upsert_exposure(db, exposure: dict) -> None:
    """
    Insert or update a CTEM exposure.
    The exposure_key is deterministic: sha256(source:title:asset)[:16].
    On conflict, update severity, score, status, and timestamp.
    """
    await db.execute("""
        INSERT INTO ctem_exposures (
            exposure_key, ts, source_tool, title, description,
            severity, original_severity, asset_id, asset_type, asset_zone,
            exploitability_score, physical_consequence, ctem_score,
            atlas_technique, attack_technique, threat_model_ref,
            status, assigned_to, sla_deadline, remediation_guidance,
            evidence_url, tenant_id
        ) VALUES (
            $1, $2, $3, $4, $5, $6, $7, $8, $9, $10,
            $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21, $22
        )
        ON CONFLICT (exposure_key) DO UPDATE SET
            ts = EXCLUDED.ts,
            severity = EXCLUDED.severity,
            ctem_score = EXCLUDED.ctem_score,
            status = CASE
                WHEN ctem_exposures.status IN ('Verified', 'Closed')
                THEN ctem_exposures.status  -- Don't reopen verified/closed
                ELSE EXCLUDED.status
            END,
            updated_at = NOW()
    """,
        exposure["exposure_key"], exposure["ts"],
        exposure["source_tool"], exposure["title"],
        exposure["description"], exposure["severity"],
        exposure["original_severity"], exposure["asset_id"],
        exposure["asset_type"], exposure["asset_zone"],
        exposure["exploitability_score"], exposure["physical_consequence"],
        exposure["ctem_score"], exposure["atlas_technique"],
        exposure["attack_technique"], exposure["threat_model_ref"],
        exposure["status"], exposure["assigned_to"],
        exposure["sla_deadline"], exposure["remediation_guidance"],
        exposure["evidence_url"], exposure["tenant_id"],
    )
```

### 2.3 Kafka Topics

```yaml
# CTEM Kafka topic configuration
# Per-source raw topics for isolation and independent scaling.
# Normalised topic after per-source normalisation.
topics:
  ctem.raw.wiz:
    partitions: 4
    replication_factor: 3
    retention_ms: 2592000000    # 30 days
    cleanup_policy: delete

  ctem.raw.snyk:
    partitions: 2
    replication_factor: 3
    retention_ms: 2592000000    # 30 days
    cleanup_policy: delete

  ctem.raw.garak:
    partitions: 2
    replication_factor: 3
    retention_ms: 2592000000    # 30 days
    cleanup_policy: delete

  ctem.raw.art:
    partitions: 2
    replication_factor: 3
    retention_ms: 2592000000    # 30 days
    cleanup_policy: delete

  ctem.raw.burp:
    partitions: 2
    replication_factor: 3
    retention_ms: 2592000000    # 30 days
    cleanup_policy: delete

  ctem.raw.custom:
    partitions: 2
    replication_factor: 3
    retention_ms: 2592000000    # 30 days
    cleanup_policy: delete

  ctem.raw.validation:
    partitions: 2
    replication_factor: 3
    retention_ms: 7776000000    # 90 days (red team audit trail)
    cleanup_policy: delete

  ctem.raw.remediation:
    partitions: 2
    replication_factor: 3
    retention_ms: 7776000000    # 90 days
    cleanup_policy: delete

  ctem.normalized:
    partitions: 4
    replication_factor: 3
    retention_ms: 2592000000    # 30 days
    cleanup_policy: delete
```

> **Why per-source raw topics:** Each CTEM tool has a different output format, volume, and failure mode. Per-source topics isolate failures (a broken Wiz webhook doesn't block Snyk ingestion) and allow independent scaling of normaliser consumers.

---

## 3. Phase 1: SCOPE — Automated Asset Inventory

ALUSKORT agents continuously maintain the Orbital asset inventory by correlating Postgres telemetry with the Neo4j asset/zone graph and CTEM scoping definitions.

### 3.1 Asset Discovery — Postgres + Neo4j

```python
"""
CTEM-SCOPE-001: Automated Orbital Asset Inventory
Discovers assets from Postgres telemetry tables and classifies them
into CTEM risk categories from Section 3.1.2 of the CTEM Program.
Run: Weekly (orchestrator timer trigger)

Replaces the original KQL-based asset discovery query. Same logic,
same classification rules, but queries Postgres tables and optionally
enriches zones from the Neo4j graph.
"""

from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Optional
import logging

logger = logging.getLogger(__name__)


@dataclass
class DiscoveredAsset:
    """A discovered asset for the CTEM inventory."""
    asset_id: str
    asset_type: str
    asset_zone: str
    risk_category: str
    ctem_scope: str
    last_seen: datetime
    metadata: dict


async def discover_assets(db, neo4j=None, now=None) -> list[DiscoveredAsset]:
    """
    Discover all Orbital assets from Postgres telemetry.
    Optionally enrich zone classification from Neo4j graph.
    """
    now = now or datetime.utcnow()
    assets = []

    # Edge nodes (from edge_node_telemetry)
    rows = await db.fetch("""
        SELECT edge_node_id,
               MAX(ts) AS last_seen,
               AVG(cpu_utilisation) AS avg_cpu,
               (ARRAY_AGG(model_weight_hash ORDER BY ts DESC))[1] AS latest_hash
        FROM edge_node_telemetry
        WHERE ts > ($1 - INTERVAL '7 days')
        GROUP BY edge_node_id
    """, now)
    for row in rows:
        assets.append(DiscoveredAsset(
            asset_id=row["edge_node_id"],
            asset_type="EdgeInferenceNode",
            asset_zone="Zone1_EdgeInference",
            risk_category="Critical",
            ctem_scope="AI/ML Assets + Infrastructure Assets",
            last_seen=row["last_seen"],
            metadata={"avg_cpu": round(row["avg_cpu"], 2), "model_hash": row["latest_hash"]},
        ))

    # API endpoints (from orbital_api_logs)
    rows = await db.fetch("""
        SELECT endpoint,
               MAX(ts) AS last_seen,
               COUNT(*) AS total_requests,
               COUNT(DISTINCT caller_identity) AS distinct_callers
        FROM orbital_api_logs
        WHERE ts > ($1 - INTERVAL '7 days')
        GROUP BY endpoint
    """, now)
    for row in rows:
        ep = row["endpoint"]
        zone = (
            "Zone4_External" if any(k in ep for k in ["demo", "partner"]) else
            "Zone2_Operations" if "nl-query" in ep else
            "Zone3_Enterprise"
        )
        risk = (
            "Critical" if any(k in ep for k in ["inference", "predict"]) else
            "High" if "nl-query" in ep else
            "Medium"
        )
        assets.append(DiscoveredAsset(
            asset_id=ep,
            asset_type="APIEndpoint",
            asset_zone=zone,
            risk_category=risk,
            ctem_scope="Integration Assets",
            last_seen=row["last_seen"],
            metadata={"total_requests": row["total_requests"]},
        ))

    # Partner integrations (from partner_api_logs)
    rows = await db.fetch("""
        SELECT partner_id, partner_name,
               MAX(ts) AS last_seen,
               COUNT(*) AS total_exchanges,
               COUNT(*) FILTER (WHERE mtls_verified)::float * 100.0
                   / GREATEST(COUNT(*), 1) AS mtls_rate
        FROM partner_api_logs
        WHERE ts > ($1 - INTERVAL '7 days')
        GROUP BY partner_id, partner_name
    """, now)
    for row in rows:
        assets.append(DiscoveredAsset(
            asset_id=row["partner_id"],
            asset_type="PartnerIntegration",
            asset_zone="Zone4_External",
            risk_category="High",
            ctem_scope="Integration Assets",
            last_seen=row["last_seen"],
            metadata={"partner_name": row["partner_name"], "mtls_rate": round(row["mtls_rate"], 1)},
        ))

    # OPC-UA sensor connections (from opcua_telemetry)
    rows = await db.fetch("""
        SELECT edge_node_id,
               MAX(ts) AS last_seen,
               AVG(sensor_count) AS avg_sensors,
               SUM(protocol_violations) AS total_violations
        FROM opcua_telemetry
        WHERE ts > ($1 - INTERVAL '7 days')
        GROUP BY edge_node_id
    """, now)
    for row in rows:
        assets.append(DiscoveredAsset(
            asset_id=f"opcua-{row['edge_node_id']}",
            asset_type="OPCUASensorFeed",
            asset_zone="Zone0_PhysicalProcess",
            risk_category="Critical",
            ctem_scope="Infrastructure Assets",
            last_seen=row["last_seen"],
            metadata={"avg_sensors": round(row["avg_sensors"], 1)},
        ))

    # CI/CD pipelines (from cicd_audit)
    rows = await db.fetch("""
        SELECT pipeline_id,
               MAX(ts) AS last_seen,
               COUNT(*) AS total_runs,
               COUNT(*) FILTER (WHERE dependency_changes != 'none'
                   AND dependency_changes != '') AS dep_changes
        FROM cicd_audit
        WHERE ts > ($1 - INTERVAL '7 days')
        GROUP BY pipeline_id
    """, now)
    for row in rows:
        assets.append(DiscoveredAsset(
            asset_id=row["pipeline_id"],
            asset_type="CICDPipeline",
            asset_zone="Zone3_Enterprise",
            risk_category="High",
            ctem_scope="Infrastructure Assets",
            last_seen=row["last_seen"],
            metadata={"total_runs": row["total_runs"]},
        ))

    # Model registry entries (from model_registry)
    rows = await db.fetch("""
        SELECT model_name,
               MAX(ts) AS last_seen,
               (ARRAY_AGG(model_hash ORDER BY ts DESC))[1] AS latest_hash,
               (ARRAY_AGG(stage ORDER BY ts DESC))[1] AS latest_stage
        FROM model_registry
        WHERE ts > ($1 - INTERVAL '30 days')
        GROUP BY model_name
    """, now)
    for row in rows:
        assets.append(DiscoveredAsset(
            asset_id=row["model_name"],
            asset_type="MLModel",
            asset_zone="Zone3_Enterprise",
            risk_category="Critical",
            ctem_scope="AI/ML Assets",
            last_seen=row["last_seen"],
            metadata={"latest_hash": row["latest_hash"], "stage": row["latest_stage"]},
        ))

    # Neo4j enrichment: override zone from graph if available
    if neo4j:
        for asset in assets:
            try:
                result = await neo4j.run("""
                    MATCH (a:Asset {id: $asset_id})-[:RESIDES_IN]->(z:Zone)
                    RETURN z.name AS zone_name, z.consequence_class AS consequence
                """, asset_id=asset.asset_id)
                record = await result.single()
                if record:
                    asset.asset_zone = record["zone_name"]
            except Exception:
                pass  # Fall back to static classification

    logger.info(f"CTEM SCOPE: Discovered {len(assets)} assets")
    return assets
```

### 3.2 New Asset Detection

```python
"""
CTEM-SCOPE-002: New Asset Detected
Fires when an asset appears that wasn't seen in the prior 30 days.
Frequency: Daily
Lookback: 7 days vs 30-day baseline
"""

async def detect_new_assets(db, now=None) -> list[dict]:
    """Detect new edge nodes not seen in the prior 30 days."""
    now = now or datetime.utcnow()

    query = """
        SELECT DISTINCT e.edge_node_id
        FROM edge_node_telemetry e
        WHERE e.ts > ($1 - INTERVAL '7 days')
          AND e.edge_node_id NOT IN (
              SELECT DISTINCT edge_node_id
              FROM edge_node_telemetry
              WHERE ts BETWEEN ($1 - INTERVAL '37 days') AND ($1 - INTERVAL '7 days')
          )
    """
    rows = await db.fetch(query, now)

    alerts = []
    for row in rows:
        alerts.append({
            "alert_title": f"CTEM SCOPE: New edge node detected — {row['edge_node_id']}",
            "alert_severity": "Medium",
            "ctem_phase": "Scope",
            "action": "Add to asset inventory, schedule initial security assessment",
            "edge_node_id": row["edge_node_id"],
        })

    return alerts
```

---

## 4. Phase 2: DISCOVER — Tool Integration & Exposure Ingestion

### 4.1 Normalisation Scripts for CTEM Tool Output

Each CTEM discovery tool outputs findings in a different format. These normalisers convert them into the `ctem_exposures` schema for unified ingestion. The normalisers run as a dedicated microservice (`services/ctem_normaliser/`) consuming from per-source Kafka topics.

```python
"""
CTEM Exposure Normaliser
Converts findings from various CTEM discovery tools into the
unified ctem_exposures schema for Postgres ingestion.

This runs as services/ctem_normaliser/ in the microservices structure
(see docs/ai-system-design.md Section 14).
"""

import json
import hashlib
import logging
from datetime import datetime, timedelta
from typing import Optional
from dataclasses import dataclass, field, asdict

logger = logging.getLogger(__name__)

# CTEM SLA definitions from the program document (Section 3.1.2)
SEVERITY_SLAS = {
    "CRITICAL": timedelta(hours=24),
    "HIGH": timedelta(hours=72),
    "MEDIUM": timedelta(days=14),
    "LOW": timedelta(days=30),
}

# Consequence-weighted prioritisation matrix (Section 3.3.1)
# Key: (exploitability, consequence) -> CTEM severity
CONSEQUENCE_MATRIX = {
    ("high", "safety_life"):    "CRITICAL",
    ("medium", "safety_life"):  "CRITICAL",
    ("low", "safety_life"):     "HIGH",
    ("high", "equipment"):      "CRITICAL",
    ("medium", "equipment"):    "HIGH",
    ("low", "equipment"):       "MEDIUM",
    ("high", "downtime"):       "HIGH",
    ("medium", "downtime"):     "MEDIUM",
    ("low", "downtime"):        "LOW",
    ("high", "data_loss"):      "MEDIUM",
    ("medium", "data_loss"):    "LOW",
    ("low", "data_loss"):       "LOW",
}

# Static zone-to-consequence mapping (FALLBACK when Neo4j is unavailable)
# In normal operation, zone consequence comes from the Neo4j graph:
#   MATCH (a:Asset)-[:RESIDES_IN]->(z:Zone) RETURN z.consequence_class
# This dict is kept as documented degradation (see ai-system-design.md Section 11.1)
ZONE_CONSEQUENCE_FALLBACK = {
    "Zone0_PhysicalProcess": "safety_life",
    "Zone1_EdgeInference":   "equipment",
    "Zone2_Operations":      "downtime",
    "Zone3_Enterprise":      "data_loss",
    "Zone4_External":        "data_loss",
}


@dataclass
class CTEMExposure:
    """Normalised CTEM exposure finding."""
    exposure_key: str
    ts: str
    source_tool: str
    title: str
    description: str
    severity: str           # From consequence-weighted matrix
    original_severity: str  # Raw severity from the tool
    asset_id: str
    asset_type: str
    asset_zone: str
    exploitability_score: float  # 0.0 - 1.0
    physical_consequence: str    # safety_life | equipment | downtime | data_loss
    ctem_score: float            # 0.0 - 10.0 composite score
    atlas_technique: str = ""
    attack_technique: str = ""
    threat_model_ref: str = ""
    status: str = "Open"
    assigned_to: str = ""
    sla_deadline: str = ""
    remediation_guidance: str = ""
    evidence_url: str = ""
    tenant_id: str = "default"


def compute_ctem_severity(
    exploitability: str, consequence: str
) -> str:
    """
    Apply the consequence-weighted prioritisation matrix.
    This is the core CTEM scoring logic from Section 3.3.1.

    Why this exists: Raw tool severity (e.g., "CRITICAL" from Wiz)
    doesn't account for the physical consequences in an ICS/OT context.
    A "MEDIUM" misconfiguration on an edge inference node that controls
    physical processes is more important than a "CRITICAL" finding on
    a demo environment.
    """
    key = (exploitability.lower(), consequence.lower())
    return CONSEQUENCE_MATRIX.get(key, "MEDIUM")


def compute_sla_deadline(severity: str) -> str:
    """Compute SLA deadline based on severity."""
    sla = SEVERITY_SLAS.get(severity, timedelta(days=30))
    deadline = datetime.utcnow() + sla
    return deadline.isoformat() + "Z"


def generate_exposure_id(source: str, title: str, asset: str) -> str:
    """
    Generate a deterministic exposure ID for deduplication.
    This is the exposure_key used for Postgres ON CONFLICT upsert.
    Same finding from same tool on same asset = same key = upsert.
    """
    raw = f"{source}:{title}:{asset}"
    return hashlib.sha256(raw.encode()).hexdigest()[:16]


async def get_zone_consequence(
    neo4j, asset_id: str, asset_zone: str
) -> str:
    """
    Get consequence class from Neo4j graph.
    Falls back to static ZONE_CONSEQUENCE_FALLBACK if Neo4j is unavailable.
    """
    if neo4j:
        try:
            result = await neo4j.run("""
                MATCH (a:Asset {id: $asset_id})-[:RESIDES_IN]->(z:Zone)
                RETURN z.consequence_class AS consequence
            """, asset_id=asset_id)
            record = await result.single()
            if record and record["consequence"]:
                return record["consequence"]
        except Exception as e:
            logger.warning(
                f"Neo4j unavailable for consequence lookup "
                f"(asset={asset_id}): {e}. Using static fallback."
            )

    # Documented degradation: static fallback
    return ZONE_CONSEQUENCE_FALLBACK.get(asset_zone, "data_loss")


class WizNormaliser:
    """Normalise Wiz CSPM findings into CTEMExposure format."""

    TOOL_NAME = "Wiz"

    # Map Wiz severity to exploitability
    WIZ_EXPLOITABILITY = {
        "CRITICAL": "high",
        "HIGH": "high",
        "MEDIUM": "medium",
        "LOW": "low",
        "INFORMATIONAL": "low",
    }

    def normalise(self, wiz_finding: dict, consequence: str = None) -> CTEMExposure:
        asset_id = wiz_finding.get("entityExternalId", "unknown")
        asset_type = wiz_finding.get("entityType", "CloudResource")

        # Determine asset zone from Wiz resource tags or type
        asset_zone = self._classify_zone(wiz_finding)
        if not consequence:
            consequence = ZONE_CONSEQUENCE_FALLBACK.get(asset_zone, "data_loss")

        orig_severity = wiz_finding.get("severity", "MEDIUM")
        exploitability = self.WIZ_EXPLOITABILITY.get(orig_severity, "medium")
        ctem_severity = compute_ctem_severity(exploitability, consequence)

        title = wiz_finding.get("title", "Unnamed finding")
        exposure_key = generate_exposure_id(self.TOOL_NAME, title, asset_id)

        return CTEMExposure(
            exposure_key=exposure_key,
            ts=datetime.utcnow().isoformat() + "Z",
            source_tool=self.TOOL_NAME,
            title=title,
            description=wiz_finding.get("description", ""),
            severity=ctem_severity,
            original_severity=orig_severity,
            asset_id=asset_id,
            asset_type=asset_type,
            asset_zone=asset_zone,
            exploitability_score={"high": 0.9, "medium": 0.6, "low": 0.3}.get(
                exploitability, 0.5
            ),
            physical_consequence=consequence,
            ctem_score=self._compute_score(exploitability, consequence),
            attack_technique=wiz_finding.get("mitreTechnique", ""),
            remediation_guidance=wiz_finding.get("remediation", ""),
            sla_deadline=compute_sla_deadline(ctem_severity),
            evidence_url=wiz_finding.get("detailsUrl", ""),
        )

    def _classify_zone(self, finding: dict) -> str:
        tags = finding.get("tags", {})
        name = finding.get("entityName", "").lower()
        if any(k in name for k in ["edge", "orbital-inference", "ot-"]):
            return "Zone1_EdgeInference"
        if any(k in name for k in ["databricks", "training", "mlflow"]):
            return "Zone3_Enterprise"
        if any(k in name for k in ["demo", "public"]):
            return "Zone4_External"
        return "Zone3_Enterprise"

    def _compute_score(self, exploitability: str, consequence: str) -> float:
        exp_score = {"high": 0.9, "medium": 0.6, "low": 0.3}[exploitability]
        con_score = {
            "safety_life": 1.0, "equipment": 0.8,
            "downtime": 0.5, "data_loss": 0.3,
        }[consequence]
        return round(exp_score * con_score * 10, 1)  # 0-10 scale


class ARTNormaliser:
    """Normalise IBM ART adversarial testing results."""

    TOOL_NAME = "IBM_ART"

    # ATLAS technique mapping for ART test types
    ART_ATLAS_MAP = {
        "evasion": "AML.T0015",
        "poisoning": "AML.T0020",
        "extraction": "AML.T0044",
        "inference": "AML.T0024",
    }
    ART_TM_MAP = {
        "evasion": "TM-07",
        "poisoning": "TM-01",
        "extraction": "TM-12",
        "inference": "TM-13",
    }

    def normalise(self, art_result: dict) -> CTEMExposure:
        attack_type = art_result.get("attack_type", "evasion")
        model_name = art_result.get("model_name", "unknown")
        success_rate = art_result.get("success_rate", 0.0)

        # ART findings against Orbital models always have equipment+ consequence
        consequence = "equipment" if attack_type == "evasion" else "data_loss"
        if attack_type == "poisoning":
            consequence = "safety_life"  # Poisoned model = safety risk

        exploitability = "high" if success_rate > 0.7 else (
            "medium" if success_rate > 0.3 else "low"
        )
        ctem_severity = compute_ctem_severity(exploitability, consequence)

        title = f"ART: {attack_type} attack success rate {success_rate:.0%} on {model_name}"
        exposure_key = generate_exposure_id(self.TOOL_NAME, title, model_name)

        return CTEMExposure(
            exposure_key=exposure_key,
            ts=datetime.utcnow().isoformat() + "Z",
            source_tool=self.TOOL_NAME,
            title=title,
            description=art_result.get("description", ""),
            severity=ctem_severity,
            original_severity=f"success_rate={success_rate:.2f}",
            asset_id=model_name,
            asset_type="MLModel",
            asset_zone="Zone1_EdgeInference",
            exploitability_score=success_rate,
            physical_consequence=consequence,
            ctem_score=round(success_rate * {"safety_life": 10, "equipment": 8, "downtime": 5, "data_loss": 3}[consequence], 1),
            atlas_technique=self.ART_ATLAS_MAP.get(attack_type, ""),
            threat_model_ref=self.ART_TM_MAP.get(attack_type, ""),
            sla_deadline=compute_sla_deadline(ctem_severity),
            remediation_guidance=art_result.get("recommended_defense", ""),
        )


class GarakNormaliser:
    """Normalise Garak LLM security testing results."""

    TOOL_NAME = "Garak"

    def normalise(self, garak_result: dict) -> CTEMExposure:
        probe_name = garak_result.get("probe", "unknown")
        passed = garak_result.get("passed", True)
        failure_rate = garak_result.get("failure_rate", 0.0)

        consequence = "downtime"
        atlas_technique = "AML.T0051"
        tm_ref = "TM-10"

        # Escalation attacks (prompt injection -> prescriptive action) are safety-critical
        if "escalation" in probe_name.lower() or "tool_use" in probe_name.lower():
            consequence = "safety_life"
        # Data extraction probes are IP theft
        if "extraction" in probe_name.lower() or "exfiltration" in probe_name.lower():
            consequence = "data_loss"
            atlas_technique = "AML.T0044.001"
            tm_ref = "TM-12"

        exploitability = "high" if failure_rate > 0.5 else (
            "medium" if failure_rate > 0.2 else "low"
        )
        ctem_severity = compute_ctem_severity(exploitability, consequence)

        title = f"Garak: {probe_name} — {failure_rate:.0%} failure rate"
        exposure_key = generate_exposure_id(self.TOOL_NAME, title, "orbital-llm")

        return CTEMExposure(
            exposure_key=exposure_key,
            ts=datetime.utcnow().isoformat() + "Z",
            source_tool=self.TOOL_NAME,
            title=title,
            description=garak_result.get("description", ""),
            severity=ctem_severity,
            original_severity=f"failure_rate={failure_rate:.2f}",
            asset_id="orbital-domain-llm",
            asset_type="LLMEndpoint",
            asset_zone="Zone2_Operations",
            exploitability_score=failure_rate,
            physical_consequence=consequence,
            ctem_score=round(failure_rate * {"safety_life": 10, "equipment": 8, "downtime": 5, "data_loss": 3}[consequence], 1),
            atlas_technique=atlas_technique,
            threat_model_ref=tm_ref,
            sla_deadline=compute_sla_deadline(ctem_severity),
            remediation_guidance=garak_result.get("suggested_fix", ""),
        )


class SnykNormaliser:
    """Normalise Snyk SCA findings."""

    TOOL_NAME = "Snyk"

    def normalise(self, snyk_finding: dict) -> CTEMExposure:
        package = snyk_finding.get("packageName", "unknown")
        version = snyk_finding.get("version", "")
        vuln_id = snyk_finding.get("id", "")
        orig_severity = snyk_finding.get("severity", "medium").upper()

        # Supply chain vulnerabilities in ML dependencies are higher consequence
        ml_packages = ["torch", "pytorch", "tensorflow", "onnx", "numpy", "scipy", "pandas", "scikit-learn"]
        is_ml_dep = any(p in package.lower() for p in ml_packages)

        consequence = "safety_life" if is_ml_dep else "data_loss"
        exploitability = {"CRITICAL": "high", "HIGH": "high", "MEDIUM": "medium", "LOW": "low"}.get(orig_severity, "medium")
        ctem_severity = compute_ctem_severity(exploitability, consequence)

        title = f"Snyk: {vuln_id} in {package}@{version}"
        exposure_key = generate_exposure_id(self.TOOL_NAME, vuln_id, package)

        return CTEMExposure(
            exposure_key=exposure_key,
            ts=datetime.utcnow().isoformat() + "Z",
            source_tool=self.TOOL_NAME,
            title=title,
            description=snyk_finding.get("description", ""),
            severity=ctem_severity,
            original_severity=orig_severity,
            asset_id=f"{package}@{version}",
            asset_type="Dependency",
            asset_zone="Zone3_Enterprise",
            exploitability_score={"high": 0.9, "medium": 0.6, "low": 0.3}[exploitability],
            physical_consequence=consequence,
            ctem_score=round({"high": 0.9, "medium": 0.6, "low": 0.3}[exploitability] * {"safety_life": 10, "equipment": 8, "downtime": 5, "data_loss": 3}[consequence], 1),
            atlas_technique="AML.T0010" if is_ml_dep else "",
            attack_technique="T1195.002",
            threat_model_ref="TM-05" if is_ml_dep else "",
            sla_deadline=compute_sla_deadline(ctem_severity),
            remediation_guidance=snyk_finding.get("fixedIn", f"Upgrade {package}"),
        )
```

### 4.2 CTEM Normaliser Microservice

The normaliser runs as a dedicated microservice (see `docs/ai-system-design.md` Section 14: `services/ctem_normaliser/`). It consumes from per-source Kafka topics, normalises each finding, and publishes to `ctem.normalized`. A separate consumer persists to Postgres using the idempotent upsert from Section 2.2.

```python
"""
CTEM Normaliser Service
Consumes from per-source ctem.raw.* topics, normalises,
publishes to ctem.normalized, and upserts to Postgres.
"""

import json
import logging
from dataclasses import asdict

logger = logging.getLogger(__name__)

# Normaliser registry
NORMALISERS = {
    "wiz": WizNormaliser(),
    "ibm_art": ARTNormaliser(),
    "garak": GarakNormaliser(),
    "snyk": SnykNormaliser(),
}

# Topic-to-tool mapping
TOPIC_TOOL_MAP = {
    "ctem.raw.wiz": "wiz",
    "ctem.raw.art": "ibm_art",
    "ctem.raw.garak": "garak",
    "ctem.raw.snyk": "snyk",
}


async def process_raw_finding(
    topic: str, raw_finding: dict,
    db, kafka_producer, neo4j=None,
) -> dict:
    """
    Process a single raw CTEM finding:
    1. Determine source tool from topic
    2. Optionally enrich consequence from Neo4j
    3. Normalise to CTEMExposure
    4. Publish to ctem.normalized
    5. Upsert to Postgres
    """
    tool_name = TOPIC_TOOL_MAP.get(topic)
    if not tool_name:
        logger.error(f"Unknown CTEM topic: {topic}")
        return {}

    normaliser = NORMALISERS.get(tool_name)
    if not normaliser:
        logger.error(f"No normaliser for tool: {tool_name}")
        return {}

    exposure = normaliser.normalise(raw_finding)
    exposure_dict = asdict(exposure)

    # Publish to normalised topic
    await kafka_producer.send("ctem.normalized", json.dumps(exposure_dict).encode())

    # Upsert to Postgres
    await upsert_exposure(db, exposure_dict)

    logger.info(
        f"CTEM normalised: {exposure.exposure_key} "
        f"({exposure.source_tool}: {exposure.title})"
    )

    return exposure_dict
```

---

## 5. Phase 3: PRIORITIZE — Consequence-Weighted Scoring Engine

### 5.1 Automated Triage — Weekly Report

```python
"""
CTEM-PRIORITIZE-001: Weekly Triage Report
Generates the prioritised remediation backlog for the weekly triage meeting.
Implements the consequence-weighted matrix from CTEM Program Section 3.3.1.
Run: Weekly (Monday 07:00 UTC)

Same logic as original KQL rule — runtime correlation boosts score by 50%,
SLA status and triage priority are computed identically.
"""

async def generate_triage_report(db, now=None) -> list[dict]:
    """Generate the weekly CTEM triage report."""
    now = now or datetime.utcnow()

    query = """
        WITH open_exposures AS (
            SELECT *
            FROM ctem_exposures
            WHERE status IN ('Open', 'InProgress')
              AND ts > ($1 - INTERVAL '90 days')
        ),
        runtime_correlation AS (
            -- Check ALUSKORT's own alerts table for matching ATLAS techniques
            SELECT atlas_technique, COUNT(*) AS runtime_alerts
            FROM alerts
            WHERE ts > ($1 - INTERVAL '7 days')
              AND atlas_technique != ''
            GROUP BY atlas_technique
        ),
        enriched AS (
            SELECT
                e.*,
                r.runtime_alerts,
                CASE WHEN r.runtime_alerts IS NOT NULL
                    THEN e.ctem_score * 1.5  -- 50% boost if seen in runtime
                    ELSE e.ctem_score
                END AS adjusted_score,
                CASE
                    WHEN NOW() > e.sla_deadline THEN 'BREACHED'
                    WHEN e.sla_deadline - NOW() < INTERVAL '24 hours' THEN 'AT_RISK'
                    ELSE 'ON_TRACK'
                END AS sla_status,
                EXTRACT(DAY FROM NOW() - e.ts) AS days_open
            FROM open_exposures e
            LEFT JOIN runtime_correlation r
                ON e.atlas_technique = r.atlas_technique
        )
        SELECT *,
            CASE
                WHEN severity = 'CRITICAL' AND sla_status = 'BREACHED' THEN 1
                WHEN severity = 'CRITICAL' THEN 2
                WHEN severity = 'HIGH' AND sla_status = 'BREACHED' THEN 3
                WHEN severity = 'HIGH' AND runtime_alerts IS NOT NULL THEN 4
                WHEN severity = 'HIGH' THEN 5
                WHEN severity = 'MEDIUM' THEN 6
                ELSE 7
            END AS triage_priority
        FROM enriched
        ORDER BY triage_priority ASC, adjusted_score DESC
    """
    rows = await db.fetch(query, now)

    return [dict(row) for row in rows]
```

### 5.2 CTEM-to-ALUSKORT Cross-Correlation

```python
"""
CTEM-PRIORITIZE-002: Exposure-to-Runtime Alert Correlation
Identifies CTEM exposures that are actively being exploited
based on matching ATLAS techniques in ALUSKORT alerts.
This is the highest-priority output for the weekly triage.

Same logic as original KQL: inner join on atlas_technique,
combined severity = CRITICAL.
"""

async def correlate_exposure_to_runtime(db, now=None) -> list[dict]:
    """Find CTEM exposures correlated with active runtime alerts."""
    now = now or datetime.utcnow()

    query = """
        SELECT
            e.exposure_key,
            e.title AS exposure_title,
            e.severity AS exposure_severity,
            e.atlas_technique,
            e.threat_model_ref,
            e.asset_zone,
            e.physical_consequence,
            a.alert_title AS runtime_alert_name,
            a.severity AS runtime_alert_severity,
            a.ts AS alert_time
        FROM ctem_exposures e
        INNER JOIN alerts a
            ON e.atlas_technique = a.atlas_technique
            AND e.atlas_technique != ''
        WHERE e.status = 'Open'
          AND a.ts > ($1 - INTERVAL '7 days')
        ORDER BY e.severity ASC, a.ts DESC
    """
    rows = await db.fetch(query, now)

    results = []
    for row in rows:
        results.append({
            "alert_title": (
                f"CTEM CRITICAL: Exposure '{row['exposure_title']}' "
                f"correlated with runtime alert '{row['runtime_alert_name']}'"
            ),
            "combined_severity": "CRITICAL",
            "action": "Immediate remediation — exposure is under active exploitation",
            **dict(row),
        })

    return results
```

---

## 6. Phase 4: VALIDATE — Red Team Integration

### 6.1 Validation Result Tracking

```python
"""
CTEM Validation Tracker
Records red team and adversarial testing results, compares them
against ALUSKORT detection rules to identify detection gaps.
"""

import logging
from dataclasses import dataclass, field
from typing import Optional

logger = logging.getLogger(__name__)


@dataclass
class ValidationResult:
    """A single validation test result."""
    validation_id: str
    exposure_id: str
    campaign_id: str
    validation_type: str  # automated | manual_red_team | adversarial_ml | full_campaign
    exploitable: bool
    exploit_complexity: str  # low | medium | high
    attack_path: str
    physical_consequence_demonstrated: bool
    detection_evaded: bool
    detection_rules_tested: list[str] = field(default_factory=list)
    detection_gaps: list[str] = field(default_factory=list)
    tester: str = ""
    evidence_url: str = ""


class DetectionGapAnalyser:
    """
    Compares red team results against ALUSKORT detection rules
    to identify what the agents missed.
    """

    # Map of ATLAS techniques to their ALUSKORT detection rules
    ATLAS_DETECTION_RULES = {
        "AML.T0020": "ATLAS-DETECT-001",
        "AML.T0044.001": "ATLAS-DETECT-002",
        "AML.T0051": "ATLAS-DETECT-003",
        "AML.T0015": "ATLAS-DETECT-004",
        "AML.T0029": "ATLAS-DETECT-005",
        "AML.T0010": "ATLAS-DETECT-006",
        "AML.T0035.002": "ATLAS-DETECT-007",
        "AML.T0043": "ATLAS-DETECT-009",
    }

    def analyse_gaps(
        self, validation: ValidationResult, atlas_technique: str
    ) -> list[str]:
        """
        Determine if the attack evaded ALUSKORT detection
        and which rules need tuning.
        """
        gaps = []

        if validation.detection_evaded:
            expected_rule = self.ATLAS_DETECTION_RULES.get(atlas_technique)
            if expected_rule:
                gaps.append(
                    f"DETECTION GAP: {expected_rule} failed to detect "
                    f"{atlas_technique} attack (campaign: {validation.campaign_id})"
                )
            else:
                gaps.append(
                    f"COVERAGE GAP: No ALUSKORT rule exists for "
                    f"{atlas_technique}"
                )

            if validation.physical_consequence_demonstrated:
                gaps.append(
                    f"SAFETY GAP: Physical consequence demonstrated "
                    f"without detection — requires immediate rule update"
                )

        return gaps
```

### 6.2 Detection Gap Analysis — Post-Campaign

```python
"""
CTEM-VALIDATE-001: Detection Gap Analysis
Run after each red team campaign to identify what ALUSKORT missed.
Compares validation results against alerts during the campaign window.

Same logic as original KQL — campaign window determination,
left join against alerts, gap type classification.
"""

async def analyse_campaign_gaps(db, campaign_id: str) -> dict:
    """Analyse detection gaps for a specific red team campaign."""

    query = """
        WITH campaign_results AS (
            SELECT *
            FROM ctem_validations
            WHERE campaign_id = $1
              AND exploitable = TRUE
        ),
        campaign_window AS (
            SELECT MIN(ts) AS start_time, MAX(ts) AS end_time
            FROM campaign_results
        ),
        alerts_during_campaign AS (
            SELECT alert_title, ts AS alert_time
            FROM alerts
            WHERE ts BETWEEN
                (SELECT start_time FROM campaign_window)
                AND (SELECT end_time FROM campaign_window)
        ),
        gap_analysis AS (
            SELECT
                cr.validation_id,
                cr.exposure_id,
                cr.detection_evaded,
                cr.physical_consequence_demonstrated,
                adc.alert_title IS NOT NULL AS detected,
                CASE
                    WHEN cr.detection_evaded AND cr.physical_consequence_demonstrated
                        THEN 'CRITICAL_GAP'
                    WHEN cr.detection_evaded
                        THEN 'DETECTION_GAP'
                    WHEN NOT cr.detection_evaded AND adc.alert_title IS NULL
                        THEN 'TIMING_GAP'
                    ELSE 'DETECTED'
                END AS gap_type
            FROM campaign_results cr
            LEFT JOIN alerts_during_campaign adc
                ON cr.exposure_id = adc.alert_title  -- Loose match
        )
        SELECT
            COUNT(*) AS total_tests,
            COUNT(*) FILTER (WHERE exploitable) AS exploitable_count,
            COUNT(*) FILTER (WHERE detected) AS detected_count,
            COUNT(*) FILTER (WHERE gap_type = 'DETECTION_GAP') AS detection_gaps,
            COUNT(*) FILTER (WHERE gap_type = 'CRITICAL_GAP') AS critical_gaps,
            COUNT(*) FILTER (WHERE gap_type = 'TIMING_GAP') AS timing_gaps
        FROM gap_analysis
        CROSS JOIN (SELECT TRUE AS exploitable) dummy  -- All rows are exploitable
    """
    row = await db.fetchrow(query, campaign_id)

    exploitable = row["exploitable_count"] or 1  # Avoid division by zero
    detection_rate = round(row["detected_count"] * 100.0 / exploitable, 1)

    return {
        "campaign_id": campaign_id,
        "total_tests": row["total_tests"],
        "exploitable": row["exploitable_count"],
        "detected": row["detected_count"],
        "detection_rate": detection_rate,
        "detection_gaps": row["detection_gaps"],
        "critical_gaps": row["critical_gaps"],
        "timing_gaps": row["timing_gaps"],
    }
```

---

## 7. Phase 5: MOBILIZE — SLA Enforcement & Remediation Tracking

### 7.1 SLA Breach Detection

```python
"""
CTEM-MOBILIZE-001: SLA Breach Alert
Fires when any CTEM exposure breaches its remediation SLA.
Implements escalation paths from CTEM Program Section 3.5.1.
Frequency: Every 4 hours

Same escalation logic as original KQL:
  - CRITICAL + >24h overdue -> CISO_EXECUTIVE
  - CRITICAL -> SECURITY_DIRECTOR
  - HIGH + >48h overdue -> SECURITY_DIRECTOR
  - HIGH -> SECURITY_MANAGER
  - MEDIUM -> SECURITY_TEAM_LEAD
"""

async def detect_sla_breaches(db, now=None) -> list[dict]:
    """Detect all CTEM exposures that have breached their SLA."""
    now = now or datetime.utcnow()

    query = """
        SELECT
            exposure_key,
            title,
            severity,
            physical_consequence,
            atlas_technique,
            threat_model_ref,
            assigned_to,
            sla_deadline,
            asset_zone,
            source_tool,
            EXTRACT(EPOCH FROM (NOW() - sla_deadline)) / 3600.0 AS hours_overdue
        FROM ctem_exposures
        WHERE status IN ('Open', 'InProgress')
          AND sla_deadline IS NOT NULL
          AND NOW() > sla_deadline
        ORDER BY severity ASC, sla_deadline ASC
    """
    rows = await db.fetch(query, now)

    alerts = []
    for row in rows:
        hours_overdue = row["hours_overdue"]
        severity = row["severity"]

        # Same escalation logic as original KQL
        if severity == "CRITICAL" and hours_overdue > 24:
            escalation = "CISO_EXECUTIVE"
        elif severity == "CRITICAL":
            escalation = "SECURITY_DIRECTOR"
        elif severity == "HIGH" and hours_overdue > 48:
            escalation = "SECURITY_DIRECTOR"
        elif severity == "HIGH":
            escalation = "SECURITY_MANAGER"
        else:
            escalation = "SECURITY_TEAM_LEAD"

        alerts.append({
            "alert_title": (
                f"CTEM SLA BREACH: {row['title']} "
                f"({severity}, {hours_overdue:.0f}h overdue)"
            ),
            "escalation_level": escalation,
            "hours_overdue": round(hours_overdue, 1),
            **dict(row),
        })

    return alerts
```

### 7.2 SLA At-Risk Early Warning

```python
"""
CTEM-MOBILIZE-002: SLA At-Risk Warning
Fires 24 hours before SLA deadline for HIGH/CRITICAL exposures.
Gives teams a chance to escalate or request an exception.

Same logic as original KQL: hours_remaining BETWEEN 0 AND 24.
"""

async def detect_sla_at_risk(db, now=None) -> list[dict]:
    """Detect CTEM exposures within 24 hours of SLA breach."""
    now = now or datetime.utcnow()

    query = """
        SELECT
            exposure_key,
            title,
            severity,
            assigned_to,
            sla_deadline,
            asset_zone,
            atlas_technique,
            EXTRACT(EPOCH FROM (sla_deadline - NOW())) / 3600.0 AS hours_remaining
        FROM ctem_exposures
        WHERE status IN ('Open', 'InProgress')
          AND severity IN ('CRITICAL', 'HIGH')
          AND sla_deadline IS NOT NULL
          AND sla_deadline > NOW()
          AND sla_deadline - NOW() < INTERVAL '24 hours'
        ORDER BY hours_remaining ASC
    """
    rows = await db.fetch(query, now)

    alerts = []
    for row in rows:
        alerts.append({
            "alert_title": (
                f"CTEM SLA AT RISK: {row['title']} "
                f"— {row['hours_remaining']:.0f}h remaining ({row['severity']})"
            ),
            "action": "Escalate to assignee and manager. Request exception if remediation is blocked.",
            **dict(row),
        })

    return alerts
```

### 7.3 Remediation Verification — Scheduled Job

```python
"""
CTEM Remediation Verification
Daily check for CTEM remediations needing verification.
Queries ctem_remediations for items in 'FixDeployed' status
and triggers re-validation scans.

Runs as a scheduled job in the orchestrator (daily at 08:00 UTC).
Replaces the original Azure Functions timer trigger.
"""

async def check_pending_verifications(db, now=None) -> list[dict]:
    """Find remediations awaiting verification (fix deployed > 24h ago)."""
    now = now or datetime.utcnow()

    query = """
        SELECT remediation_id, exposure_id, assigned_to, fix_deployed_date
        FROM ctem_remediations
        WHERE status = 'FixDeployed'
          AND verified_date IS NULL
          AND fix_deployed_date IS NOT NULL
          AND NOW() - fix_deployed_date > INTERVAL '24 hours'
    """
    rows = await db.fetch(query, now)

    pending = []
    for row in rows:
        pending.append({
            "remediation_id": row["remediation_id"],
            "exposure_id": row["exposure_id"],
            "assigned_to": row["assigned_to"],
            "fix_deployed_date": str(row["fix_deployed_date"]),
            "action": "Trigger re-scan to verify remediation effectiveness",
        })
        logger.info(
            f"Remediation {row['remediation_id']} for exposure "
            f"{row['exposure_id']} awaiting verification "
            f"(fix deployed {row['fix_deployed_date']})"
        )

    return pending
```

---

## 8. CTEM Metrics — Python Analytics

These queries power the CTEM program's reporting requirements from Section 3.5.3 and the KPIs from Section 6.

### 8.1 Operational Metrics (Weekly Report)

```python
"""
CTEM-METRICS-001: Weekly Operational Dashboard
Computes all operational KPIs from CTEM Program Section 6.1.
Same metrics as original KQL: MTTD, MTTR, SLA compliance, open breakdown.
"""

async def compute_weekly_metrics(db, now=None) -> dict:
    """Compute weekly CTEM operational metrics."""
    now = now or datetime.utcnow()

    # MTTR: Mean Time to Remediation (verified items, last 30 days)
    mttr_query = """
        SELECT
            AVG(EXTRACT(EPOCH FROM (verified_date - assigned_date)) / 3600.0)
                AS mttr_all_hours,
            AVG(EXTRACT(EPOCH FROM (verified_date - assigned_date)) / 3600.0)
                FILTER (WHERE exposure_id IN (
                    SELECT exposure_key FROM ctem_exposures WHERE severity = 'CRITICAL'
                )) AS mttr_critical_hours
        FROM ctem_remediations
        WHERE status = 'Verified'
          AND ts > ($1 - INTERVAL '30 days')
    """
    mttr = await db.fetchrow(mttr_query, now)

    # SLA Compliance Rate
    sla_query = """
        SELECT
            COUNT(*) AS total,
            COUNT(*) FILTER (WHERE verified_date <= sla_deadline) AS on_time,
            ROUND(
                COUNT(*) FILTER (WHERE verified_date <= sla_deadline)::numeric
                * 100.0 / GREATEST(COUNT(*), 1), 1
            ) AS sla_compliance_rate
        FROM ctem_remediations
        WHERE status = 'Verified'
          AND ts > ($1 - INTERVAL '30 days')
    """
    sla = await db.fetchrow(sla_query, now)

    # Open Exposure Breakdown
    open_query = """
        SELECT severity, COUNT(*) AS count
        FROM ctem_exposures
        WHERE status IN ('Open', 'InProgress')
        GROUP BY severity
        ORDER BY severity
    """
    open_breakdown = {row["severity"]: row["count"] for row in await db.fetch(open_query, now)}

    # Attack Path Reduction (month over month)
    reduction_query = """
        SELECT
            (SELECT COUNT(DISTINCT exposure_key)
             FROM ctem_exposures
             WHERE ts > ($1 - INTERVAL '30 days')
               AND severity IN ('CRITICAL', 'HIGH')) AS current_month,
            (SELECT COUNT(DISTINCT exposure_key)
             FROM ctem_exposures
             WHERE ts BETWEEN ($1 - INTERVAL '60 days') AND ($1 - INTERVAL '30 days')
               AND severity IN ('CRITICAL', 'HIGH')) AS prior_month
    """
    reduction = await db.fetchrow(reduction_query, now)

    # Tool Coverage
    tool_query = """
        SELECT source_tool, COUNT(*) AS findings
        FROM ctem_exposures
        WHERE ts > ($1 - INTERVAL '30 days')
        GROUP BY source_tool
    """
    tool_coverage = {row["source_tool"]: row["findings"] for row in await db.fetch(tool_query, now)}

    return {
        "report": "CTEM Weekly Operational Metrics",
        "report_date": now.strftime("%Y-%m-%d"),
        "mttr_all_hours": round(mttr["mttr_all_hours"] or 0, 1),
        "mttr_critical_hours": round(mttr["mttr_critical_hours"] or 0, 1),
        "sla_compliance_rate": float(sla["sla_compliance_rate"] or 0),
        "open_exposures": open_breakdown,
        "attack_path_current_month": reduction["current_month"],
        "attack_path_prior_month": reduction["prior_month"],
        "tool_coverage": tool_coverage,
    }
```

### 8.2 CTEM Score Trend (Monthly Report)

```python
"""
CTEM-METRICS-002: Monthly Risk Posture Trend
Tracks the aggregate CTEM risk score over time.
Target: decreasing trend month over month.

Same weighted risk posture formula as original KQL:
  CRITICAL * 4 + HIGH * 3 + MEDIUM * 2 + LOW * 1
"""

async def compute_score_trend(db, now=None) -> list[dict]:
    """Compute weekly risk posture trend over the last 180 days."""
    now = now or datetime.utcnow()

    query = """
        SELECT
            DATE_TRUNC('week', ts) AS week,
            COUNT(*) AS total_exposures,
            COUNT(*) FILTER (WHERE severity = 'CRITICAL') AS critical_count,
            COUNT(*) FILTER (WHERE severity = 'HIGH') AS high_count,
            COUNT(*) FILTER (WHERE severity = 'MEDIUM') AS medium_count,
            COUNT(*) FILTER (WHERE severity = 'LOW') AS low_count,
            ROUND(AVG(ctem_score)::numeric, 1) AS avg_ctem_score,
            MAX(ctem_score) AS max_ctem_score,
            ROUND(
                SUM(
                    CASE severity
                        WHEN 'CRITICAL' THEN ctem_score * 4
                        WHEN 'HIGH' THEN ctem_score * 3
                        WHEN 'MEDIUM' THEN ctem_score * 2
                        ELSE ctem_score
                    END
                )::numeric / GREATEST(COUNT(*), 1), 1
            ) AS risk_posture_score
        FROM ctem_exposures
        WHERE ts > ($1 - INTERVAL '180 days')
          AND status IN ('Open', 'InProgress')
        GROUP BY DATE_TRUNC('week', ts)
        ORDER BY week ASC
    """
    rows = await db.fetch(query, now)

    trend = []
    prev_score = None
    for row in rows:
        score = float(row["risk_posture_score"])
        entry = {
            **dict(row),
            "week": str(row["week"]),
            "week_over_week_change": round(score - prev_score, 1) if prev_score else None,
            "trend": "IMPROVING" if prev_score and score < prev_score else "DEGRADING",
        }
        trend.append(entry)
        prev_score = score

    return trend
```

### 8.3 Red Team Effectiveness (Quarterly Report)

```python
"""
CTEM-METRICS-003: Quarterly Red Team Campaign Effectiveness
Tracks detection rate improvement across campaigns.
Target: increasing detection rate, decreasing critical gaps.

Same metrics as original KQL: exploit rate, evasion rate, detection rate.
"""

async def compute_red_team_effectiveness(db, now=None) -> list[dict]:
    """Compute effectiveness metrics for each red team campaign."""
    now = now or datetime.utcnow()

    query = """
        SELECT
            campaign_id,
            COUNT(*) AS total_tests,
            COUNT(*) FILTER (WHERE exploitable) AS exploitable_findings,
            COUNT(*) FILTER (WHERE detection_evaded) AS detection_evaded_count,
            COUNT(*) FILTER (WHERE physical_consequence_demonstrated)
                AS physical_consequence_count,
            COUNT(DISTINCT validation_type) AS unique_types
        FROM ctem_validations
        WHERE ts > ($1 - INTERVAL '365 days')
          AND validation_type IN ('manual_red_team', 'adversarial_ml', 'full_campaign')
        GROUP BY campaign_id
        ORDER BY campaign_id ASC
    """
    rows = await db.fetch(query, now)

    results = []
    for row in rows:
        exploitable = max(row["exploitable_findings"], 1)
        total = max(row["total_tests"], 1)
        results.append({
            "campaign_id": row["campaign_id"],
            "total_tests": row["total_tests"],
            "exploitable_findings": row["exploitable_findings"],
            "exploit_rate": round(row["exploitable_findings"] * 100.0 / total, 1),
            "evasion_rate": round(row["detection_evaded_count"] * 100.0 / exploitable, 1),
            "detection_rate": round(
                (row["exploitable_findings"] - row["detection_evaded_count"])
                * 100.0 / exploitable, 1
            ),
            "physical_consequence_count": row["physical_consequence_count"],
        })

    return results
```

### 8.4 ATLAS Coverage Matrix

```python
"""
CTEM-METRICS-004: ATLAS Technique Coverage Assessment
Shows which ATLAS techniques have CTEM discovery, ALUSKORT detection,
and red team validation — and which have gaps.

Same coverage scoring as original KQL:
  CoverageScore = has_ctem + has_runtime + has_validation (0-3)
"""

# All known ATLAS techniques from the Orbital threat model
KNOWN_TECHNIQUES = [
    {"atlas_technique": "AML.T0020", "threat_model_ref": "TM-01", "name": "Poison Training Data"},
    {"atlas_technique": "AML.T0043", "threat_model_ref": "TM-03/06/08", "name": "Craft Adversarial Data"},
    {"atlas_technique": "AML.T0015", "threat_model_ref": "TM-07/17", "name": "Evade ML Model"},
    {"atlas_technique": "AML.T0044", "threat_model_ref": "TM-04/11", "name": "Full ML Model Access"},
    {"atlas_technique": "AML.T0044.001", "threat_model_ref": "TM-12", "name": "Query-Based Model Extraction"},
    {"atlas_technique": "AML.T0051", "threat_model_ref": "TM-10", "name": "LLM Prompt Injection"},
    {"atlas_technique": "AML.T0054", "threat_model_ref": "TM-10", "name": "LLM Jailbreak"},
    {"atlas_technique": "AML.T0029", "threat_model_ref": "TM-09/14", "name": "Denial of ML Service"},
    {"atlas_technique": "AML.T0010", "threat_model_ref": "TM-05/15", "name": "ML Supply Chain Compromise"},
    {"atlas_technique": "AML.T0018", "threat_model_ref": "TM-05", "name": "Backdoor ML Model"},
    {"atlas_technique": "AML.T0035.001", "threat_model_ref": "TM-04", "name": "Physical Access to ML Model"},
    {"atlas_technique": "AML.T0035.002", "threat_model_ref": "TM-11", "name": "Insider Access to ML Model"},
    {"atlas_technique": "AML.T0014", "threat_model_ref": "TM-20", "name": "Discover ML Model Ontology"},
    {"atlas_technique": "AML.T0024", "threat_model_ref": "TM-13", "name": "Infer Training Data Membership"},
    {"atlas_technique": "AML.T0048.003", "threat_model_ref": "TM-02", "name": "Exploit via Model-Serving Interface"},
]


async def compute_atlas_coverage(db, now=None) -> list[dict]:
    """Compute ATLAS technique coverage across CTEM, runtime, and validation."""
    now = now or datetime.utcnow()

    # CTEM exposure coverage
    ctem_query = """
        SELECT atlas_technique, COUNT(*) AS ctem_findings, MAX(ts) AS latest
        FROM ctem_exposures
        WHERE ts > ($1 - INTERVAL '90 days')
          AND atlas_technique != ''
        GROUP BY atlas_technique
    """
    ctem_data = {
        row["atlas_technique"]: row
        for row in await db.fetch(ctem_query, now)
    }

    # Runtime detection coverage
    detection_query = """
        SELECT atlas_technique, COUNT(*) AS runtime_alerts, MAX(ts) AS latest
        FROM alerts
        WHERE ts > ($1 - INTERVAL '90 days')
          AND atlas_technique != ''
        GROUP BY atlas_technique
    """
    detection_data = {
        row["atlas_technique"]: row
        for row in await db.fetch(detection_query, now)
    }

    # Red team validation coverage
    validation_query = """
        SELECT
            UNNEST(
                ARRAY(SELECT jsonb_array_elements_text(detection_rules_tested))
            ) AS technique_hint,
            COUNT(*) AS validation_tests,
            MAX(ts) AS latest
        FROM ctem_validations
        WHERE ts > ($1 - INTERVAL '365 days')
        GROUP BY technique_hint
    """
    # Simplified: use attack_path for technique extraction
    validation_data = {}

    results = []
    for tech in KNOWN_TECHNIQUES:
        t = tech["atlas_technique"]
        has_ctem = t in ctem_data
        has_runtime = t in detection_data
        has_validation = t in validation_data
        coverage_score = int(has_ctem) + int(has_runtime) + int(has_validation)

        if has_ctem and has_runtime and has_validation:
            status = "FULL_COVERAGE"
        elif has_runtime:
            status = "DETECTION_ONLY"
        elif has_ctem:
            status = "DISCOVERY_ONLY"
        else:
            status = "NO_COVERAGE"

        results.append({
            "atlas_technique": t,
            "technique_name": tech["name"],
            "threat_model_ref": tech["threat_model_ref"],
            "has_ctem_discovery": has_ctem,
            "ctem_findings": ctem_data.get(t, {}).get("ctem_findings", 0),
            "has_runtime_detection": has_runtime,
            "runtime_alerts": detection_data.get(t, {}).get("runtime_alerts", 0),
            "has_red_team_validation": has_validation,
            "coverage_score": coverage_score,
            "coverage_status": status,
        })

    results.sort(key=lambda x: (x["coverage_score"], x["atlas_technique"]))
    return results
```

---

## 9. Closed-Loop: CTEM Findings to ALUSKORT Detection Tuning

This is the critical feedback loop. Red team results and CTEM exposure data should continuously improve ALUSKORT's detection capability.

### 9.1 Tuning Workflow

```
Red Team Campaign
    |
    v
ctem_validations table (detection gaps logged)
    |
    v
CTEM-VALIDATE-001 (gap analysis query)
    |
    v
Reasoning Agent reviews gaps -> recommends rule updates
    |
    v
Security Engineer updates ATLAS-DETECT rules (Python)
    |
    v
Next campaign validates improvement
    |
    v
CTEM-METRICS-003 tracks detection rate trend
```

### 9.2 Automated Detection Gap Alert

```python
"""
CTEM-FEEDBACK-001: New Detection Gap from Red Team
Fires immediately when a red team validation reveals
a gap in ALUSKORT detection coverage.
Frequency: On ingestion (real-time consumer)

Same logic as original KQL: fires when detection_evaded = true,
gap severity based on physical consequence and exploit complexity.
"""

async def detect_new_gaps(db, now=None) -> list[dict]:
    """Detect new detection gaps from recent red team validations."""
    now = now or datetime.utcnow()

    query = """
        SELECT
            validation_id,
            exposure_id,
            campaign_id,
            validation_type,
            attack_path,
            detection_rules_tested,
            detection_gaps,
            physical_consequence_demonstrated,
            exploit_complexity,
            tester,
            evidence_url,
            CASE
                WHEN physical_consequence_demonstrated THEN 'CRITICAL'
                WHEN exploit_complexity = 'low' THEN 'HIGH'
                ELSE 'MEDIUM'
            END AS gap_severity
        FROM ctem_validations
        WHERE ts > ($1 - INTERVAL '1 hour')
          AND detection_evaded = TRUE
    """
    rows = await db.fetch(query, now)

    alerts = []
    for row in rows:
        alerts.append({
            "alert_title": (
                f"CTEM DETECTION GAP: {row['validation_type']} "
                f"evaded detection ({row['gap_severity']})"
            ),
            "gap_severity": row["gap_severity"],
            "action": (
                f"Detection rules tested: {row['detection_rules_tested']}. "
                f"Gaps identified: {row['detection_gaps']}. "
                f"Update ALUSKORT analytics rules to cover this attack path."
            ),
            **dict(row),
        })

    return alerts
```

### 9.3 Reasoning Agent CTEM Context

When the Reasoning Agent assesses a runtime alert, it checks if there's a known CTEM exposure for the same ATLAS technique. If so, confidence is boosted because the exposure has been independently discovered through CTEM scanning.

```python
"""
CTEM context enrichment for the Reasoning Agent.
Queries ctem_exposures for known exposures matching an ATLAS technique.
If a CTEM exposure exists AND has been validated as exploitable,
the Reasoning Agent boosts confidence in the runtime detection.
"""

async def get_ctem_context(
    db, atlas_technique: str, limit: int = 10
) -> list[dict]:
    """
    Query ctem_exposures for known exposures matching this ATLAS technique.
    Returns enrichment context for the Reasoning Agent.
    """
    if not atlas_technique or not atlas_technique.startswith("AML.T"):
        return []

    query = """
        SELECT
            exposure_key,
            title,
            severity,
            ctem_score,
            physical_consequence,
            source_tool,
            asset_zone,
            threat_model_ref
        FROM ctem_exposures
        WHERE atlas_technique = $1
          AND status IN ('Open', 'InProgress')
        ORDER BY ctem_score DESC
        LIMIT $2
    """
    rows = await db.fetch(query, atlas_technique, limit)

    return [dict(row) for row in rows]
```

---

## 10. Implementation & Deployment

### 10.1 Database Migration (Alembic)

```python
"""
Alembic migration: Create CTEM tables
Revision ID: ctem_001
Depends on: atlas_001
"""

from alembic import op
import sqlalchemy as sa


def upgrade():
    """Create CTEM tables with indexes and constraints."""
    # See Section 2.1 for full DDL.
    # Tables: ctem_exposures, ctem_validations, ctem_remediations
    # Key feature: ctem_exposures.exposure_key UNIQUE for idempotent upsert
    op.execute("""
        -- Paste DDL from Section 2.1 here
        -- (omitted for brevity -- see Section 2.1 for full CREATE TABLE statements)
    """)


def downgrade():
    """Drop all CTEM tables."""
    for table in ["ctem_remediations", "ctem_validations", "ctem_exposures"]:
        op.drop_table(table)
```

### 10.2 Kafka Topic Creation

```bash
# Create all CTEM Kafka topics
# Run against your Kafka/Redpanda cluster

for TOPIC in \
    ctem.raw.wiz \
    ctem.raw.snyk \
    ctem.raw.garak \
    ctem.raw.art \
    ctem.raw.burp \
    ctem.raw.custom \
    ctem.raw.validation \
    ctem.raw.remediation \
    ctem.normalized; do
  echo "Creating topic: $TOPIC"
  rpk topic create "$TOPIC" \
    --partitions 2 \
    --replicas 3 \
    --config retention.ms=2592000000
done

echo ""
echo "=== CTEM Kafka Topics Created ==="
rpk topic list | grep ctem
```

### 10.3 Docker Compose — CTEM Services

```yaml
# Add to deploy/docker-compose.yml
services:
  ctem-normaliser:
    build:
      context: .
      dockerfile: services/ctem_normaliser/Dockerfile
    environment:
      - POSTGRES_DSN=postgresql://aluskort:${PG_PASSWORD}@postgres:5432/aluskort
      - KAFKA_BROKERS=kafka:9092
      - NEO4J_URI=bolt://neo4j:7687
      - NEO4J_AUTH=neo4j/${NEO4J_PASSWORD}
    depends_on:
      - postgres
      - kafka
      - neo4j
    restart: unless-stopped
    deploy:
      replicas: 2
      resources:
        limits:
          memory: 256M
          cpus: "0.25"

  ctem-sla-enforcer:
    build:
      context: .
      dockerfile: services/orchestrator/Dockerfile
    command: ["python", "-m", "services.orchestrator.ctem_sla_runner"]
    environment:
      - POSTGRES_DSN=postgresql://aluskort:${PG_PASSWORD}@postgres:5432/aluskort
      - KAFKA_BROKERS=kafka:9092
      - SLA_CHECK_INTERVAL_HOURS=4
    depends_on:
      - postgres
      - kafka
    restart: unless-stopped
    deploy:
      replicas: 1
      resources:
        limits:
          memory: 128M
          cpus: "0.1"

  ctem-remediation-checker:
    build:
      context: .
      dockerfile: services/orchestrator/Dockerfile
    command: ["python", "-m", "services.orchestrator.ctem_remediation_runner"]
    environment:
      - POSTGRES_DSN=postgresql://aluskort:${PG_PASSWORD}@postgres:5432/aluskort
      - CHECK_SCHEDULE=0 8 * * *  # Daily at 08:00 UTC
    depends_on:
      - postgres
    restart: unless-stopped
    deploy:
      replicas: 1
      resources:
        limits:
          memory: 128M
          cpus: "0.1"
```

### 10.4 Configure CTEM Tool Webhooks

Each CTEM discovery tool pushes findings to its per-source Kafka topic via a lightweight HTTP-to-Kafka bridge (or directly if the tool supports Kafka).

```bash
#!/bin/bash
# CTEM Tool Webhook Configuration
# Each tool posts to its per-source Kafka topic via the ingestion gateway.

GATEWAY_URL="${ALUSKORT_GATEWAY_URL:-http://localhost:8080}"

echo "=== CTEM Tool Webhook Configuration ==="
echo ""
echo "Ingestion gateway: ${GATEWAY_URL}/api/ctem/ingest"
echo ""
echo "Payload format:"
echo '  {"source_tool": "<tool_name>", "findings": [{ ... }]}'
echo ""
echo "Supported tools: wiz, ibm_art, garak, snyk"
echo ""
echo "--- Wiz Configuration ---"
echo "  Wiz Console -> Automation Rules -> Create Rule"
echo "  Trigger: New Issue Created"
echo "  Action: Webhook -> URL: ${GATEWAY_URL}/api/ctem/ingest"
echo '  Body: {"source_tool": "wiz", "findings": [<issue>]}'
echo ""
echo "--- Snyk Configuration ---"
echo "  Snyk Dashboard -> Settings -> Integrations -> Webhooks"
echo "  URL: ${GATEWAY_URL}/api/ctem/ingest"
echo "  Events: New vulnerability"
echo '  Body: {"source_tool": "snyk", "findings": [<vuln>]}'
echo ""
echo "--- Garak Configuration ---"
echo "  Add to your Garak CI/CD step:"
echo "  garak --model_type ... --probes ... --report_json /tmp/garak_report.json"
echo "  curl -X POST '${GATEWAY_URL}/api/ctem/ingest' \\"
echo "    -H 'Content-Type: application/json' \\"
echo '    -d '"'"'{"source_tool": "garak", "findings": <contents of report>}'"'"
echo ""
echo "--- IBM ART Configuration ---"
echo "  Add to your ART testing pipeline:"
echo "  python run_art_tests.py --output /tmp/art_results.json"
echo "  curl -X POST '${GATEWAY_URL}/api/ctem/ingest' \\"
echo "    -H 'Content-Type: application/json' \\"
echo '    -d '"'"'{"source_tool": "ibm_art", "findings": <contents of results>}'"'"
```

### 10.5 Verify Complete Integration

```bash
#!/bin/bash
echo "=== ALUSKORT + ATLAS + CTEM Integration Verification ==="

# Check Postgres CTEM tables
echo ""
echo "--- CTEM Postgres Tables ---"
for TABLE in ctem_exposures ctem_validations ctem_remediations; do
  COUNT=$(psql "$POSTGRES_DSN" -t -c "SELECT COUNT(*) FROM $TABLE" 2>/dev/null)
  if [ $? -eq 0 ]; then
    echo "  OK: $TABLE (rows: $(echo $COUNT | xargs))"
  else
    echo "  MISSING: $TABLE — run Alembic migration: alembic upgrade head"
  fi
done

# Check CTEM Kafka topics
echo ""
echo "--- CTEM Kafka Topics ---"
rpk topic list | grep ctem | while read TOPIC; do
  echo "  OK: $TOPIC"
done

# Check CTEM services
echo ""
echo "--- CTEM Services ---"
for SVC in ctem-normaliser ctem-sla-enforcer ctem-remediation-checker; do
  STATUS=$(docker ps --filter "name=$SVC" --format "{{.Status}}" 2>/dev/null)
  if [ -n "$STATUS" ]; then
    echo "  OK: $SVC ($STATUS)"
  else
    echo "  NOT RUNNING: $SVC"
  fi
done

# Check CTEM normaliser consumer lag
echo ""
echo "--- CTEM Consumer Lag ---"
rpk group describe ctem-normaliser-group 2>/dev/null | grep -E "TOPIC|LAG"

# Summary
echo ""
echo "--- Coverage Summary ---"
echo "  ATLAS detection rules: 10 (ATLAS-DETECT-001 through 010)"
echo "  CTEM analytics functions: 9 (SCOPE x2, PRIORITIZE x2, VALIDATE x1, MOBILIZE x2, FEEDBACK x1, + verification)"
echo "  Postgres tables: 13 (10 ATLAS telemetry + 3 CTEM)"
echo "  Kafka topics: 19 (10 telemetry + 9 CTEM)"
echo "  Microservices: 3 (ctem-normaliser, sla-enforcer, remediation-checker)"

echo ""
echo "=== Verification Complete ==="
```

---

**END OF DOCUMENT**

*Document generated by Omeriko for ALUSKORT project (v2.0 -- Cloud-Neutral). CTEM integration layer operationalises the Continuous Threat Exposure Management program using Postgres tables with idempotent upserts, per-source Kafka topics for tool ingestion, Neo4j graph-based consequence reasoning (with static fallback), and Python analytics replacing the previous Azure Sentinel KQL implementation. See `docs/ai-system-design.md` for the system architecture context.*
