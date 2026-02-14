# ALUSKORT — MITRE ATLAS Integration Layer

> **Supplement to:** ALUSKORT Cloud-Neutral System Design v2.0 (`docs/ai-system-design.md`)
> **Threat Model Reference:** Orbital Foundation Model Platform — Detailed Threat Model v1.0
> **Last Updated:** February 2026
> **Classification:** CONFIDENTIAL — aligns with parent threat model classification

---

## Table of Contents

1. [ATLAS Framework Overview & Rationale](#1-atlas-framework-overview--rationale)
2. [Threat Model to ATLAS Technique Mapping](#2-threat-model-to-atlas-technique-mapping)
3. [Data Source Requirements — Postgres & Kafka](#3-data-source-requirements--postgres--kafka)
4. [ATLAS Detection Rules — Python Analytics](#4-atlas-detection-rules--python-analytics)
5. [Updated Agent Implementations](#5-updated-agent-implementations)
6. [Self-Protection: ALUSKORT as an Attack Surface](#6-self-protection-aluskort-as-an-attack-surface)
7. [ATLAS-Aware Response Playbooks](#7-atlas-aware-response-playbooks)
8. [Validation & Red Team Scenarios](#8-validation--red-team-scenarios)
9. [Implementation & Deployment](#9-implementation--deployment)

---

## 1. ATLAS Framework Overview & Rationale

### 1.1 Why ATLAS in Addition to ATT&CK

MITRE ATT&CK covers adversary TTPs against traditional IT/OT systems. MITRE ATLAS (Adversarial Threat Landscape for AI Systems) extends this to cover TTPs specific to machine learning systems. The Orbital platform is both:

- **An IT/OT system** subject to ATT&CK tactics (credential theft, lateral movement, ransomware)
- **An AI/ML system** subject to ATLAS tactics (training data poisoning, model extraction, adversarial evasion, prompt injection)

ALUSKORT must detect and reason about both taxonomies simultaneously. A single incident may span both — for example, TM-01 (training data poisoning) starts with ATT&CK T1078 (Valid Accounts) to access Databricks, then proceeds with ATLAS AML.T0020 (Poison Training Data) to corrupt the foundation model.

### 1.2 ATLAS Tactic Summary (Relevant to Orbital)

| ATLAS Tactic | ID | Orbital Relevance |
|---|---|---|
| Reconnaissance | AML.TA0002 | Adversary maps Orbital deployments, model architecture, partner integrations |
| Resource Development | AML.TA0003 | Adversary develops adversarial perturbations, surrogate models |
| ML Model Access | AML.TA0000 | Adversary gains access to model via API, demo env, partner endpoint, or edge node |
| Execution | AML.TA0004 | Adversary triggers backdoor, runs adversarial input, executes prompt injection |
| Persistence | AML.TA0005 | Adversary embeds backdoor in training data or model weights |
| Evasion | AML.TA0006 | Adversary crafts inputs to evade anomaly detection or physics validation |
| Discovery | AML.TA0007 | Adversary probes model to understand decision boundaries |
| Collection | AML.TA0008 | Adversary extracts training data, model weights, or operational insights |
| Exfiltration | AML.TA0009 | Adversary exfiltrates model IP or operational data |
| Impact | AML.TA0010 | Adversary degrades model performance, causes unsafe outputs, destroys availability |

---

## 2. Threat Model to ATLAS Technique Mapping

This is the core reference table. Every TM-ID from the Orbital threat model is mapped to its primary ATLAS technique(s), the detection approach, and the ALUSKORT agent responsible.

| TM-ID | Threat | Risk | ATLAS Technique(s) | ATT&CK Technique(s) | Detection Agent | Postgres Table(s) / Kafka Topic(s) |
|---|---|---|---|---|---|---|
| TM-01 | Training data poisoning via Databricks | CRITICAL (20) | AML.T0020 (Poison Training Data), AML.T0019 (Publish Poisoned Datasets) | T1078 (Valid Accounts), T1565.001 (Data Manipulation: Stored Data) | Reasoning Agent | `databricks_audit`, `telemetry.databricks.audit` |
| TM-02 | Lateral movement from edge to DCS/SCADA | CRITICAL (15) | AML.T0048.003 (Exploit via Model-Serving Interface) | T1021 (Remote Services), T1570 (Lateral Tool Transfer), T1210 (Exploitation of Remote Services) | Context Enricher | `ot_network_flows`, `telemetry.network.ot` |
| TM-03 | Physics constraint manipulation | CRITICAL (15) | AML.T0043 (Craft Adversarial Data), AML.T0020 (Poison Training Data) | T1565 (Data Manipulation) | Reasoning Agent | `orbital_physics_oracle`, `telemetry.orbital.physics` |
| TM-04 | Model weight theft from edge node | CRITICAL (16) | AML.T0044 (Full ML Model Access), AML.T0035.001 (Physical Access to ML Model) | T1005 (Data from Local System), T1052 (Exfiltration Over Physical Medium) | IOC Extractor + Context Enricher | `edge_node_telemetry`, `telemetry.edge.health` |
| TM-05 | Supply chain backdoor in foundation model | CRITICAL (15) | AML.T0010 (ML Supply Chain Compromise), AML.T0018.000 (Backdoor ML Model) | T1195 (Supply Chain Compromise) | Reasoning Agent | `cicd_audit`, `model_registry`, `telemetry.cicd.*` |
| TM-06 | Sensor data spoofing | CRITICAL (16) | AML.T0043 (Craft Adversarial Data) | T1565.002 (Data Manipulation: Transmitted Data) | IOC Extractor | `opcua_telemetry`, `telemetry.opcua.sensors` |
| TM-07 | Adversarial evasion of anomaly detection | HIGH (12) | AML.T0015 (Evade ML Model), AML.T0043 (Craft Adversarial Data) | -- | Reasoning Agent | `orbital_inference_logs`, `telemetry.orbital.inference` |
| TM-08 | Partner integration compromise | HIGH (12) | AML.T0043 (Craft Adversarial Data) | T1199 (Trusted Relationship), T1078.004 (Cloud Accounts) | Context Enricher | `partner_api_logs`, `telemetry.partner.api` |
| TM-09 | Ransomware on edge nodes | HIGH (12) | AML.T0029 (Denial of ML Service) | T1486 (Data Encrypted for Impact), T1490 (Inhibit System Recovery) | IOC Extractor | `edge_node_telemetry`, `alerts.raw` |
| TM-10 | LLM prompt injection | HIGH (12) | AML.T0051 (LLM Prompt Injection), AML.T0054 (LLM Jailbreak) | -- | IOC Extractor + Reasoning Agent | `orbital_nl_query_logs`, `telemetry.orbital.nlquery` |
| TM-11 | Insider IP theft | HIGH (12) | AML.T0044 (Full ML Model Access), AML.T0035.002 (Insider Access to ML Model) | T1078 (Valid Accounts), T1567 (Exfiltration Over Web Service) | Context Enricher | `databricks_audit`, UEBA via adapter |
| TM-12 | Query-based model extraction | HIGH (12) | AML.T0044.001 (Query-Based Model Extraction), AML.T0044.002 (Surrogate Model Training) | T1530 (Data from Cloud Storage Object) | Reasoning Agent | `orbital_api_logs`, `orbital_nl_query_logs` |
| TM-13 | Model inversion revealing physics priors | HIGH (9) | AML.T0024 (Infer Training Data Membership) | -- | Reasoning Agent | `orbital_api_logs` |
| TM-14 | Physics validation oracle DoS | HIGH (10) | AML.T0029 (Denial of ML Service) | T1499 (Endpoint Denial of Service) | IOC Extractor | `orbital_physics_oracle` |
| TM-15 | CI/CD pipeline compromise | HIGH (10) | AML.T0010 (ML Supply Chain Compromise) | T1195.002 (Compromise Software Supply Chain) | Context Enricher | `cicd_audit` |
| TM-17 | Alert fatigue exploitation | MEDIUM (9) | AML.T0015 (Evade ML Model) | -- | Reasoning Agent | `alerts` (ALUSKORT's own alert table) |
| TM-20 | Demo environment exploitation | MEDIUM (8) | AML.T0014 (Discover ML Model Ontology), AML.T0044.001 (Query-Based Extraction) | T1595 (Active Scanning) | Context Enricher | `demo_env_access_logs` |

---

## 3. Data Source Requirements — Postgres & Kafka

The Orbital threat model requires custom telemetry sources beyond any SIEM's built-in tables. In ALUSKORT v2.0, these are stored in Postgres and ingested via Kafka topics. Adapters publish raw telemetry to per-source Kafka topics; consumers normalise and persist to Postgres.

### 3.1 Postgres Tables (replacing custom Sentinel tables)

| Postgres Table | Replaces (Sentinel) | Kafka Topic | Description | Key Columns |
|---|---|---|---|---|
| `orbital_inference_logs` | `OrbitalInferenceLog_CL` | `telemetry.orbital.inference` | Edge inference engine logs | `ts`, `edge_node_id`, `model_version`, `input_hash`, `output_hash`, `physics_check_result`, `confidence_score`, `inference_latency_ms` |
| `orbital_physics_oracle` | `OrbitalPhysicsOracle_CL` | `telemetry.orbital.physics` | Physics validation oracle logs | `ts`, `edge_node_id`, `constraint_id`, `check_result`, `latency_ms`, `error_state`, `input_hash` |
| `orbital_nl_query_logs` | `OrbitalNLQueryLog_CL` | `telemetry.orbital.nlquery` | Natural language query interface logs | `ts`, `user_id`, `session_id`, `query_text`, `response_summary`, `tool_calls_made`, `safety_filter_triggered`, `token_count` |
| `orbital_api_logs` | `OrbitalAPILog_CL` | `telemetry.orbital.api` | All API access to Orbital endpoints | `ts`, `caller_ip`, `caller_identity`, `endpoint`, `method`, `response_code`, `request_payload_size`, `response_payload_size` |
| `edge_node_telemetry` | `EdgeNodeTelemetry_CL` | `telemetry.edge.health` | Edge node health telemetry | `ts`, `edge_node_id`, `model_weight_hash`, `disk_integrity`, `boot_attestation`, `active_connections`, `cpu_utilisation`, `memory_utilisation` |
| `databricks_audit` | `DatabricksAudit_CL` | `telemetry.databricks.audit` | Databricks workspace audit logs | `ts`, `user_id`, `action`, `target_resource`, `source_ip`, `workspace_id`, `cluster_name` |
| `model_registry` | `ModelRegistry_CL` | `telemetry.modelregistry.events` | Model registry events | `ts`, `user_id`, `action`, `model_name`, `model_version`, `model_hash`, `stage`, `approved_by` |
| `cicd_audit` | `CICDAudit_CL` | `telemetry.cicd.audit` | CI/CD pipeline audit | `ts`, `pipeline_id`, `trigger_type`, `commit_hash`, `dependency_changes`, `tests_passed`, `tests_failed`, `deployer` |
| `partner_api_logs` | `PartnerAPILog_CL` | `telemetry.partner.api` | Partner integration API logs | `ts`, `partner_id`, `partner_name`, `direction`, `data_type`, `payload_size`, `response_code`, `mtls_verified` |
| `opcua_telemetry` | `OPCUATelemetry_CL` | `telemetry.opcua.sensors` | OPC-UA communication telemetry | `ts`, `edge_node_id`, `sensor_count`, `data_points_received`, `connection_state`, `auth_method`, `protocol_violations` |

### 3.2 CREATE TABLE DDL — Key Tables

```sql
-- ============================================================
-- Orbital Inference Logs
-- Source: Edge inference engines via telemetry.orbital.inference
-- Used by: ATLAS-DETECT-004 (Adversarial Evasion)
-- ============================================================
CREATE TABLE orbital_inference_logs (
    id              BIGSERIAL PRIMARY KEY,
    ts              TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    edge_node_id    TEXT NOT NULL,
    model_version   TEXT NOT NULL,
    input_hash      TEXT NOT NULL,
    output_hash     TEXT NOT NULL,
    physics_check_result TEXT NOT NULL,  -- 'PASS', 'FAIL', 'SKIP'
    confidence_score     REAL NOT NULL,
    inference_latency_ms INTEGER NOT NULL,
    tenant_id       TEXT NOT NULL DEFAULT 'default',
    ingested_at     TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_inference_ts ON orbital_inference_logs (ts);
CREATE INDEX idx_inference_edge ON orbital_inference_logs (edge_node_id, ts);
CREATE INDEX idx_inference_physics ON orbital_inference_logs (physics_check_result, ts);

-- Partition by month for retention management
-- ALTER TABLE orbital_inference_logs PARTITION BY RANGE (ts);

-- ============================================================
-- Physics Validation Oracle
-- Source: Physics validation process via telemetry.orbital.physics
-- Used by: ATLAS-DETECT-005 (Physics Oracle DoS)
-- ============================================================
CREATE TABLE orbital_physics_oracle (
    id              BIGSERIAL PRIMARY KEY,
    ts              TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    edge_node_id    TEXT NOT NULL,
    constraint_id   TEXT NOT NULL,
    check_result    TEXT NOT NULL,  -- 'PASS', 'FAIL'
    latency_ms      INTEGER NOT NULL,
    error_state     TEXT NOT NULL DEFAULT 'NONE',
    input_hash      TEXT NOT NULL,
    tenant_id       TEXT NOT NULL DEFAULT 'default',
    ingested_at     TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_physics_ts ON orbital_physics_oracle (ts);
CREATE INDEX idx_physics_edge ON orbital_physics_oracle (edge_node_id, ts);
CREATE INDEX idx_physics_errors ON orbital_physics_oracle (error_state, ts)
    WHERE error_state != 'NONE';

-- ============================================================
-- Orbital NL Query Logs
-- Source: Domain-specific LLM interface via telemetry.orbital.nlquery
-- Used by: ATLAS-DETECT-003 (Prompt Injection)
-- ============================================================
CREATE TABLE orbital_nl_query_logs (
    id                      BIGSERIAL PRIMARY KEY,
    ts                      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    user_id                 TEXT NOT NULL,
    session_id              TEXT NOT NULL,
    query_text              TEXT NOT NULL,
    response_summary        TEXT,
    tool_calls_made         JSONB DEFAULT '[]',
    safety_filter_triggered BOOLEAN NOT NULL DEFAULT FALSE,
    token_count             INTEGER NOT NULL DEFAULT 0,
    tenant_id               TEXT NOT NULL DEFAULT 'default',
    ingested_at             TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_nlquery_ts ON orbital_nl_query_logs (ts);
CREATE INDEX idx_nlquery_user ON orbital_nl_query_logs (user_id, ts);
CREATE INDEX idx_nlquery_safety ON orbital_nl_query_logs (safety_filter_triggered, ts)
    WHERE safety_filter_triggered = TRUE;

-- ============================================================
-- Orbital API Logs
-- Source: API gateway via telemetry.orbital.api
-- Used by: ATLAS-DETECT-002 (Model Extraction)
-- ============================================================
CREATE TABLE orbital_api_logs (
    id                      BIGSERIAL PRIMARY KEY,
    ts                      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    caller_ip               INET NOT NULL,
    caller_identity         TEXT NOT NULL,
    endpoint                TEXT NOT NULL,
    method                  TEXT NOT NULL,
    response_code           SMALLINT NOT NULL,
    request_payload_size    INTEGER NOT NULL DEFAULT 0,
    response_payload_size   INTEGER NOT NULL DEFAULT 0,
    tenant_id               TEXT NOT NULL DEFAULT 'default',
    ingested_at             TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_api_ts ON orbital_api_logs (ts);
CREATE INDEX idx_api_caller ON orbital_api_logs (caller_identity, ts);
CREATE INDEX idx_api_endpoint ON orbital_api_logs (endpoint, ts);

-- ============================================================
-- Databricks Audit
-- Source: Databricks audit log export via telemetry.databricks.audit
-- Used by: ATLAS-DETECT-001 (Training Data Poisoning),
--          ATLAS-DETECT-007 (Insider Exfiltration)
-- ============================================================
CREATE TABLE databricks_audit (
    id              BIGSERIAL PRIMARY KEY,
    ts              TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    user_id         TEXT NOT NULL,
    action          TEXT NOT NULL,
    target_resource TEXT NOT NULL,
    source_ip       INET,
    workspace_id    TEXT,
    cluster_name    TEXT,
    tenant_id       TEXT NOT NULL DEFAULT 'default',
    ingested_at     TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_databricks_ts ON databricks_audit (ts);
CREATE INDEX idx_databricks_user ON databricks_audit (user_id, ts);
CREATE INDEX idx_databricks_action ON databricks_audit (action, ts);

-- ============================================================
-- Edge Node Telemetry
-- Source: Edge node agent via telemetry.edge.health
-- Used by: ATLAS-DETECT-006 (Supply Chain)
-- ============================================================
CREATE TABLE edge_node_telemetry (
    id                  BIGSERIAL PRIMARY KEY,
    ts                  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    edge_node_id        TEXT NOT NULL,
    model_weight_hash   TEXT NOT NULL,
    disk_integrity      TEXT,
    boot_attestation    TEXT,
    active_connections  INTEGER NOT NULL DEFAULT 0,
    cpu_utilisation     REAL NOT NULL DEFAULT 0.0,
    memory_utilisation  REAL NOT NULL DEFAULT 0.0,
    tenant_id           TEXT NOT NULL DEFAULT 'default',
    ingested_at         TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_edge_ts ON edge_node_telemetry (ts);
CREATE INDEX idx_edge_node ON edge_node_telemetry (edge_node_id, ts);

-- ============================================================
-- OPC-UA Telemetry
-- Source: OPC-UA gateway via telemetry.opcua.sensors
-- Used by: ATLAS-DETECT-009 (Sensor Spoofing)
-- ============================================================
CREATE TABLE opcua_telemetry (
    id                      BIGSERIAL PRIMARY KEY,
    ts                      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    edge_node_id            TEXT NOT NULL,
    sensor_count            INTEGER NOT NULL DEFAULT 0,
    data_points_received    INTEGER NOT NULL DEFAULT 0,
    connection_state        TEXT NOT NULL DEFAULT 'Connected',
    auth_method             TEXT,
    protocol_violations     INTEGER NOT NULL DEFAULT 0,
    tenant_id               TEXT NOT NULL DEFAULT 'default',
    ingested_at             TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_opcua_ts ON opcua_telemetry (ts);
CREATE INDEX idx_opcua_edge ON opcua_telemetry (edge_node_id, ts);
CREATE INDEX idx_opcua_violations ON opcua_telemetry (protocol_violations, ts)
    WHERE protocol_violations > 0;

-- ============================================================
-- Partner API Logs
-- Source: Integration gateway via telemetry.partner.api
-- Used by: ATLAS-DETECT-010 (Partner Compromise)
-- ============================================================
CREATE TABLE partner_api_logs (
    id              BIGSERIAL PRIMARY KEY,
    ts              TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    partner_id      TEXT NOT NULL,
    partner_name    TEXT NOT NULL,
    direction       TEXT NOT NULL,  -- 'inbound', 'outbound'
    data_type       TEXT,
    payload_size    INTEGER NOT NULL DEFAULT 0,
    response_code   SMALLINT NOT NULL,
    mtls_verified   BOOLEAN NOT NULL DEFAULT TRUE,
    tenant_id       TEXT NOT NULL DEFAULT 'default',
    ingested_at     TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_partner_ts ON partner_api_logs (ts);
CREATE INDEX idx_partner_id ON partner_api_logs (partner_id, ts);
CREATE INDEX idx_partner_mtls ON partner_api_logs (mtls_verified, ts)
    WHERE mtls_verified = FALSE;

-- ============================================================
-- Model Registry
-- Source: MLflow / model registry via telemetry.modelregistry.events
-- Used by: ATLAS-DETECT-006 (Supply Chain)
-- ============================================================
CREATE TABLE model_registry (
    id              BIGSERIAL PRIMARY KEY,
    ts              TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    user_id         TEXT NOT NULL,
    action          TEXT NOT NULL,
    model_name      TEXT NOT NULL,
    model_version   TEXT,
    model_hash      TEXT,
    stage           TEXT,  -- 'staging', 'production', 'archived'
    approved_by     TEXT,
    tenant_id       TEXT NOT NULL DEFAULT 'default',
    ingested_at     TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_registry_ts ON model_registry (ts);
CREATE INDEX idx_registry_model ON model_registry (model_name, ts);
CREATE INDEX idx_registry_stage ON model_registry (stage, ts);

-- ============================================================
-- CI/CD Audit
-- Source: CI/CD platform via telemetry.cicd.audit
-- Used by: ATLAS-DETECT-006 (Supply Chain)
-- ============================================================
CREATE TABLE cicd_audit (
    id                  BIGSERIAL PRIMARY KEY,
    ts                  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    pipeline_id         TEXT NOT NULL,
    trigger_type        TEXT NOT NULL,
    commit_hash         TEXT NOT NULL,
    dependency_changes  TEXT DEFAULT '',
    tests_passed        INTEGER NOT NULL DEFAULT 0,
    tests_failed        INTEGER NOT NULL DEFAULT 0,
    deployer            TEXT,
    tenant_id           TEXT NOT NULL DEFAULT 'default',
    ingested_at         TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_cicd_ts ON cicd_audit (ts);
CREATE INDEX idx_cicd_pipeline ON cicd_audit (pipeline_id, ts);
```

### 3.3 Kafka Topic Configuration

Each telemetry source publishes to its own Kafka topic. Adapters (see `docs/ai-system-design.md` Section 6.2) consume from the source's native event stream and publish to these topics.

```yaml
# Kafka topic configuration for ATLAS telemetry sources
# Retention: 7 days for high-volume, 30 days for audit
topics:
  telemetry.orbital.inference:
    partitions: 8
    replication_factor: 3
    retention_ms: 604800000      # 7 days
    cleanup_policy: delete

  telemetry.orbital.physics:
    partitions: 4
    replication_factor: 3
    retention_ms: 604800000      # 7 days
    cleanup_policy: delete

  telemetry.orbital.nlquery:
    partitions: 4
    replication_factor: 3
    retention_ms: 2592000000     # 30 days (audit trail)
    cleanup_policy: delete

  telemetry.orbital.api:
    partitions: 8
    replication_factor: 3
    retention_ms: 604800000      # 7 days
    cleanup_policy: delete

  telemetry.databricks.audit:
    partitions: 4
    replication_factor: 3
    retention_ms: 2592000000     # 30 days
    cleanup_policy: delete

  telemetry.edge.health:
    partitions: 4
    replication_factor: 3
    retention_ms: 604800000      # 7 days
    cleanup_policy: delete

  telemetry.modelregistry.events:
    partitions: 2
    replication_factor: 3
    retention_ms: 2592000000     # 30 days
    cleanup_policy: delete

  telemetry.cicd.audit:
    partitions: 2
    replication_factor: 3
    retention_ms: 2592000000     # 30 days
    cleanup_policy: delete

  telemetry.partner.api:
    partitions: 4
    replication_factor: 3
    retention_ms: 604800000      # 7 days
    cleanup_policy: delete

  telemetry.opcua.sensors:
    partitions: 4
    replication_factor: 3
    retention_ms: 604800000      # 7 days
    cleanup_policy: delete
```

---

## 4. ATLAS Detection Rules — Python Analytics

In ALUSKORT v2.0, detection rules are Python classes that evaluate against the canonical schema stored in Postgres. Each rule preserves the **exact same detection logic** (thresholds, baselines, statistical methods) as the original KQL rules but operates on Postgres data via SQL queries. Rules are registered with the detection engine and executed on a schedule.

### 4.0 Detection Rule Framework

```python
"""
ALUSKORT ATLAS Detection Rule Framework
Each rule implements evaluate() against Postgres data using
the same statistical methods and thresholds as the original KQL analytics.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Optional
from enum import Enum

import logging

logger = logging.getLogger(__name__)


@dataclass
class DetectionResult:
    """Output from a detection rule evaluation."""
    rule_id: str
    triggered: bool
    alert_title: str = ""
    alert_severity: str = "Medium"  # Low | Medium | High | Critical
    atlas_technique: str = ""
    attack_technique: str = ""
    threat_model_ref: str = ""
    confidence: float = 0.0
    evidence: dict = field(default_factory=dict)
    entities: list = field(default_factory=list)
    requires_immediate_action: bool = False
    timestamp: str = ""


class DetectionRule(ABC):
    """Base class for all ATLAS detection rules."""

    @property
    @abstractmethod
    def rule_id(self) -> str:
        """Unique rule identifier (e.g., ATLAS-DETECT-001)."""
        ...

    @property
    @abstractmethod
    def frequency(self) -> timedelta:
        """How often this rule should be evaluated."""
        ...

    @property
    @abstractmethod
    def lookback(self) -> timedelta:
        """How far back the rule looks for data."""
        ...

    @abstractmethod
    async def evaluate(self, db, now: Optional[datetime] = None) -> list[DetectionResult]:
        """
        Evaluate the detection rule against Postgres data.

        Args:
            db: AsyncPG connection pool or SQLAlchemy async session.
            now: Current time (injectable for testing).

        Returns:
            List of DetectionResult objects (empty if nothing triggered).
        """
        ...
```

### 4.1 ATLAS-DETECT-001: Training Data Poisoning (TM-01 / AML.T0020)

```python
class TrainingDataPoisoningDetection(DetectionRule):
    """
    ATLAS-DETECT-001: Training Data Poisoning Indicators
    Severity: High | Frequency: Every 1 hour | Lookback: 24 hours + 30-day baseline

    Detects anomalous Databricks activity patterns that indicate potential
    training data poisoning. Uses the same deviation-factor and threshold
    logic as the original KQL rule:
      - DeviationFactor > 3.0 (today vs 30-day daily average)
      - DistinctTables > 5
      - TodayCount > 50
      - High severity if DeviationFactor > 10.0
    """

    SUSPICIOUS_ACTIONS = [
        "deltaDMLEvent", "deltaTableWrite", "notebookRun", "clusterCreate"
    ]

    @property
    def rule_id(self) -> str:
        return "ATLAS-DETECT-001"

    @property
    def frequency(self) -> timedelta:
        return timedelta(hours=1)

    @property
    def lookback(self) -> timedelta:
        return timedelta(hours=24)

    async def evaluate(self, db, now=None) -> list[DetectionResult]:
        now = now or datetime.utcnow()
        results = []

        # Step 1: Compute 30-day baseline per user (average daily count)
        baseline_query = """
            SELECT user_id,
                   COUNT(*)::float / 30.0 AS avg_daily
            FROM databricks_audit
            WHERE ts BETWEEN ($1 - INTERVAL '30 days') AND ($1 - INTERVAL '1 day')
              AND action = ANY($2)
            GROUP BY user_id
        """
        baselines = {
            row["user_id"]: row["avg_daily"]
            for row in await db.fetch(baseline_query, now, self.SUSPICIOUS_ACTIONS)
        }

        # Step 2: Current 24-hour activity
        current_query = """
            SELECT user_id,
                   COUNT(*) AS today_count,
                   COUNT(DISTINCT target_resource) AS distinct_tables,
                   COUNT(DISTINCT action) AS distinct_actions,
                   ARRAY_AGG(DISTINCT source_ip::text) AS source_ips,
                   MIN(ts) AS earliest_action,
                   MAX(ts) AS latest_action
            FROM databricks_audit
            WHERE ts > ($1 - INTERVAL '24 hours')
              AND action = ANY($2)
            GROUP BY user_id
        """
        rows = await db.fetch(current_query, now, self.SUSPICIOUS_ACTIONS)

        for row in rows:
            user_id = row["user_id"]
            today_count = row["today_count"]
            distinct_tables = row["distinct_tables"]
            avg_daily = baselines.get(user_id, 0.0)

            # Deviation factor: same logic as KQL
            deviation_factor = (today_count / avg_daily) if avg_daily > 0 else 999.0

            # Threshold check: same as KQL
            if deviation_factor > 3.0 or distinct_tables > 5 or today_count > 50:
                severity = "High" if deviation_factor > 10.0 else "Medium"
                results.append(DetectionResult(
                    rule_id=self.rule_id,
                    triggered=True,
                    alert_title=f"ATLAS: Potential training data poisoning by {user_id}",
                    alert_severity=severity,
                    atlas_technique="AML.T0020",
                    attack_technique="T1565.001",
                    threat_model_ref="TM-01",
                    confidence=min(0.95, 0.5 + (deviation_factor / 20.0)),
                    evidence={
                        "user_id": user_id,
                        "today_count": today_count,
                        "distinct_tables": distinct_tables,
                        "deviation_factor": round(deviation_factor, 2),
                        "avg_daily_baseline": round(avg_daily, 2),
                        "source_ips": row["source_ips"][:10],
                        "earliest_action": str(row["earliest_action"]),
                        "latest_action": str(row["latest_action"]),
                    },
                    entities=[{"type": "user", "id": user_id}],
                    timestamp=now.isoformat() + "Z",
                ))

        return results
```

### 4.2 ATLAS-DETECT-002: Query-Based Model Extraction (TM-12 / AML.T0044.001)

```python
class ModelExtractionDetection(DetectionRule):
    """
    ATLAS-DETECT-002: Query-Based Model Extraction Attempt
    Severity: High | Frequency: Every 30 minutes | Lookback: 6 hours

    Detects systematic querying patterns that indicate model extraction.
    Same thresholds as original KQL:
      - extractionThreshold = 100 queries
      - automationGapMs = 500ms (median inter-query gap)
      - Confidence tiers: >500 queries + <200ms gap = 0.95, etc.
    """

    EXTRACTION_THRESHOLD = 100
    AUTOMATION_GAP_MS = 500
    INFERENCE_ENDPOINTS = ["predict", "forecast", "inference", "query", "nl-query"]

    @property
    def rule_id(self) -> str:
        return "ATLAS-DETECT-002"

    @property
    def frequency(self) -> timedelta:
        return timedelta(minutes=30)

    @property
    def lookback(self) -> timedelta:
        return timedelta(hours=6)

    async def evaluate(self, db, now=None) -> list[DetectionResult]:
        now = now or datetime.utcnow()
        results = []

        query = """
            WITH caller_stats AS (
                SELECT
                    caller_identity,
                    COUNT(*) AS query_count,
                    COUNT(DISTINCT endpoint) AS distinct_endpoints,
                    PERCENTILE_CONT(0.5) WITHIN GROUP (
                        ORDER BY EXTRACT(EPOCH FROM (ts - LAG(ts) OVER (
                            PARTITION BY caller_identity ORDER BY ts
                        ))) * 1000
                    ) AS median_gap_ms,
                    SUM(response_payload_size) AS total_payload_bytes,
                    COUNT(DISTINCT request_payload_size) AS distinct_input_sizes,
                    ARRAY_AGG(DISTINCT caller_ip::text) AS source_ips,
                    EXTRACT(EPOCH FROM (MAX(ts) - MIN(ts))) / 60.0 AS session_window_min
                FROM orbital_api_logs
                WHERE ts > ($1 - INTERVAL '6 hours')
                  AND endpoint LIKE ANY(ARRAY['%predict%','%forecast%','%inference%','%query%','%nl-query%'])
                GROUP BY caller_identity
            )
            SELECT * FROM caller_stats
            WHERE query_count > $2
        """
        rows = await db.fetch(query, now, self.EXTRACTION_THRESHOLD)

        for row in rows:
            query_count = row["query_count"]
            median_gap_ms = row["median_gap_ms"] or 9999
            distinct_endpoints = row["distinct_endpoints"]

            # Same automation detection logic as KQL
            if not (median_gap_ms < self.AUTOMATION_GAP_MS or distinct_endpoints > 2):
                continue

            # Same confidence tiers as KQL
            if query_count > 500 and median_gap_ms < 200:
                confidence = 0.95
            elif query_count > 200 and distinct_endpoints > 3:
                confidence = 0.85
            elif query_count > self.EXTRACTION_THRESHOLD:
                confidence = 0.70
            else:
                confidence = 0.50

            if confidence <= 0.65:
                continue

            results.append(DetectionResult(
                rule_id=self.rule_id,
                triggered=True,
                alert_title=f"ATLAS: Model extraction attempt by {row['caller_identity']}",
                alert_severity="High",
                atlas_technique="AML.T0044.001",
                threat_model_ref="TM-12",
                confidence=confidence,
                evidence={
                    "caller_identity": row["caller_identity"],
                    "query_count": query_count,
                    "distinct_endpoints": distinct_endpoints,
                    "median_gap_ms": round(median_gap_ms, 1),
                    "total_payload_bytes": row["total_payload_bytes"],
                    "source_ips": row["source_ips"][:10],
                    "session_window_min": round(row["session_window_min"], 1),
                },
                entities=[{"type": "identity", "id": row["caller_identity"]}],
                timestamp=now.isoformat() + "Z",
            ))

        return results
```

### 4.3 ATLAS-DETECT-003: LLM Prompt Injection (TM-10 / AML.T0051)

```python
class PromptInjectionDetection(DetectionRule):
    """
    ATLAS-DETECT-003: LLM Prompt Injection Attempt
    Severity: High | Frequency: Every 15 minutes | Lookback: 1 hour

    Detects prompt injection and jailbreak attempts against the Orbital
    NL query interface. Same pattern lists and severity logic as original KQL.
    """

    INJECTION_PATTERNS = [
        "ignore previous instructions", "ignore all instructions",
        "disregard your instructions", "forget your rules",
        "you are now", "new persona", "override safety",
        "bypass filter", "system prompt", "reveal your prompt",
        "DAN mode", "developer mode", "jailbreak",
        "pretend you are", "act as if you have no restrictions",
        "hypothetically if you could", "for educational purposes only",
        "ignore the above",
    ]

    ESCALATION_PATTERNS = [
        "execute command", "run script", "modify setpoint",
        "change parameter", "override alarm", "disable safety",
        "bypass interlock", "adjust pressure", "increase temperature",
        "open valve", "close valve", "shutdown",
    ]

    @property
    def rule_id(self) -> str:
        return "ATLAS-DETECT-003"

    @property
    def frequency(self) -> timedelta:
        return timedelta(minutes=15)

    @property
    def lookback(self) -> timedelta:
        return timedelta(hours=1)

    async def evaluate(self, db, now=None) -> list[DetectionResult]:
        now = now or datetime.utcnow()
        results = []

        query = """
            SELECT user_id, session_id, query_text,
                   safety_filter_triggered, token_count, ts
            FROM orbital_nl_query_logs
            WHERE ts > ($1 - INTERVAL '1 hour')
        """
        rows = await db.fetch(query, now)

        for row in rows:
            query_lower = row["query_text"].lower()

            injection_matches = sum(
                1 for p in self.INJECTION_PATTERNS if p in query_lower
            )
            escalation_matches = sum(
                1 for p in self.ESCALATION_PATTERNS if p in query_lower
            )

            # Same trigger logic as KQL
            if not (injection_matches > 0 or escalation_matches > 0
                    or row["safety_filter_triggered"] or row["token_count"] > 4000):
                continue

            # Same threat type classification as KQL
            if escalation_matches > 0 and injection_matches > 0:
                threat_type = "Injection+Escalation"
            elif escalation_matches > 0:
                threat_type = "Prescriptive_Escalation"
            elif injection_matches > 0:
                threat_type = "Prompt_Injection"
            elif row["token_count"] > 4000:
                threat_type = "Suspicious_Length"
            else:
                threat_type = "Safety_Filter_Triggered"

            # Same severity logic as KQL
            if escalation_matches > 0:
                severity = "High"
            elif injection_matches > 0 and row["safety_filter_triggered"]:
                severity = "High"
            elif injection_matches > 0:
                severity = "Medium"
            else:
                severity = "Low"

            atlas_technique = "AML.T0051" if injection_matches > 0 else "AML.T0054"

            results.append(DetectionResult(
                rule_id=self.rule_id,
                triggered=True,
                alert_title=f"ATLAS: {threat_type} on NL interface by {row['user_id']}",
                alert_severity=severity,
                atlas_technique=atlas_technique,
                threat_model_ref="TM-10",
                confidence=0.9 if escalation_matches > 0 else 0.75,
                evidence={
                    "user_id": row["user_id"],
                    "session_id": row["session_id"],
                    "threat_type": threat_type,
                    "injection_matches": injection_matches,
                    "escalation_matches": escalation_matches,
                    "safety_filter_triggered": row["safety_filter_triggered"],
                    "token_count": row["token_count"],
                    "query_preview": row["query_text"][:200],
                },
                entities=[{"type": "user", "id": row["user_id"]}],
                timestamp=now.isoformat() + "Z",
            ))

        return results
```

### 4.4 ATLAS-DETECT-004: Adversarial Evasion / Anomaly Blinding (TM-07 / AML.T0015)

```python
class AdversarialEvasionDetection(DetectionRule):
    """
    ATLAS-DETECT-004: Adversarial Evasion of Anomaly Detection
    Severity: High | Frequency: Every 15 minutes | Lookback: 1 hour + 7-day baseline

    Compares current inference statistics against a 7-day baseline per edge node.
    Same statistical methods as original KQL:
      - Confidence z-score: (current_avg - baseline_avg) / baseline_std
      - Physics fail rate increase: current_rate - baseline_rate
      - Latency increase with minimum sample size
    Thresholds preserved:
      - ConfidenceZScore < -2.0
      - PhysicsFailRateIncrease > 0.1
      - LatencyIncrease > 500 AND InferenceCount > 10
    """

    @property
    def rule_id(self) -> str:
        return "ATLAS-DETECT-004"

    @property
    def frequency(self) -> timedelta:
        return timedelta(minutes=15)

    @property
    def lookback(self) -> timedelta:
        return timedelta(hours=1)

    async def evaluate(self, db, now=None) -> list[DetectionResult]:
        now = now or datetime.utcnow()
        results = []

        query = """
            WITH baseline AS (
                SELECT
                    edge_node_id,
                    AVG(confidence_score) AS baseline_avg_confidence,
                    STDDEV(confidence_score) AS baseline_std_confidence,
                    COUNT(*) FILTER (WHERE physics_check_result = 'FAIL')::float
                        / GREATEST(COUNT(*), 1) AS baseline_physics_fail_rate,
                    AVG(inference_latency_ms) AS baseline_avg_latency
                FROM orbital_inference_logs
                WHERE ts BETWEEN ($1 - INTERVAL '7 days') AND ($1 - INTERVAL '1 hour')
                GROUP BY edge_node_id
            ),
            current_period AS (
                SELECT
                    edge_node_id,
                    AVG(confidence_score) AS current_avg_confidence,
                    STDDEV(confidence_score) AS current_std_confidence,
                    COUNT(*) FILTER (WHERE physics_check_result = 'FAIL')::float
                        / GREATEST(COUNT(*), 1) AS current_physics_fail_rate,
                    AVG(inference_latency_ms) AS current_avg_latency,
                    COUNT(*) AS inference_count,
                    COUNT(*) FILTER (WHERE physics_check_result = 'FAIL') AS physics_fail_count
                FROM orbital_inference_logs
                WHERE ts > ($1 - INTERVAL '1 hour')
                GROUP BY edge_node_id
            )
            SELECT
                c.edge_node_id,
                c.current_avg_confidence,
                b.baseline_avg_confidence,
                b.baseline_std_confidence,
                c.current_physics_fail_rate,
                b.baseline_physics_fail_rate,
                c.current_avg_latency,
                b.baseline_avg_latency,
                c.inference_count,
                c.physics_fail_count,
                CASE WHEN b.baseline_std_confidence > 0 THEN
                    (c.current_avg_confidence - b.baseline_avg_confidence) / b.baseline_std_confidence
                ELSE 0.0 END AS confidence_z_score,
                c.current_physics_fail_rate - b.baseline_physics_fail_rate AS physics_fail_rate_increase,
                c.current_avg_latency - b.baseline_avg_latency AS latency_increase
            FROM current_period c
            INNER JOIN baseline b ON c.edge_node_id = b.edge_node_id
        """
        rows = await db.fetch(query, now)

        for row in rows:
            z_score = row["confidence_z_score"]
            fail_rate_increase = row["physics_fail_rate_increase"]
            latency_increase = row["latency_increase"]
            inference_count = row["inference_count"]

            # Same threshold logic as KQL
            if not (z_score < -2.0
                    or fail_rate_increase > 0.1
                    or (latency_increase > 500 and inference_count > 10)):
                continue

            results.append(DetectionResult(
                rule_id=self.rule_id,
                triggered=True,
                alert_title=(
                    f"ATLAS: Anomaly detection evasion on {row['edge_node_id']}"
                ),
                alert_severity="High",
                atlas_technique="AML.T0015",
                threat_model_ref="TM-07",
                confidence=0.85,
                evidence={
                    "edge_node_id": row["edge_node_id"],
                    "confidence_z_score": round(z_score, 3),
                    "physics_fail_rate_increase": round(fail_rate_increase, 4),
                    "latency_increase_ms": round(latency_increase, 1),
                    "inference_count": inference_count,
                    "physics_fail_count": row["physics_fail_count"],
                    "baseline_avg_confidence": round(row["baseline_avg_confidence"], 4),
                    "current_avg_confidence": round(row["current_avg_confidence"], 4),
                },
                entities=[{"type": "edge_node", "id": row["edge_node_id"]}],
                timestamp=now.isoformat() + "Z",
            ))

        return results
```

### 4.5 ATLAS-DETECT-005: Physics Oracle DoS / Bypass (TM-14 / AML.T0029)

```python
class PhysicsOracleDoSDetection(DetectionRule):
    """
    ATLAS-DETECT-005: Physics Validation Oracle DoS or Bypass
    Severity: Critical | Frequency: Every 5 minutes | Lookback: 15 minutes

    Detects DoS or bypass attacks against the physics validation oracle.
    Same thresholds as original KQL:
      - ErrorCount > 3
      - TimeoutCount > 2 (latency > 5000ms)
      - Fail rate > 50% with sample size > 10
      - TotalChecks == 0 (oracle silent)
      - MaxLatency > 10000ms
    Always flags as requires_immediate_action.
    """

    @property
    def rule_id(self) -> str:
        return "ATLAS-DETECT-005"

    @property
    def frequency(self) -> timedelta:
        return timedelta(minutes=5)

    @property
    def lookback(self) -> timedelta:
        return timedelta(minutes=15)

    async def evaluate(self, db, now=None) -> list[DetectionResult]:
        now = now or datetime.utcnow()
        results = []

        # Per edge node, per 5-minute bin
        query = """
            SELECT
                edge_node_id,
                DATE_TRUNC('minute', ts) -
                    (EXTRACT(MINUTE FROM ts)::int % 5) * INTERVAL '1 minute' AS time_bin,
                COUNT(*) AS total_checks,
                COUNT(*) FILTER (WHERE check_result = 'FAIL') AS fail_count,
                COUNT(*) FILTER (WHERE error_state != 'NONE' AND error_state != '') AS error_count,
                COUNT(*) FILTER (WHERE latency_ms > 5000) AS timeout_count,
                AVG(latency_ms) AS avg_latency,
                MAX(latency_ms) AS max_latency,
                COUNT(DISTINCT constraint_id) AS distinct_constraints
            FROM orbital_physics_oracle
            WHERE ts > ($1 - INTERVAL '15 minutes')
            GROUP BY edge_node_id,
                     DATE_TRUNC('minute', ts) -
                         (EXTRACT(MINUTE FROM ts)::int % 5) * INTERVAL '1 minute'
        """
        rows = await db.fetch(query, now)

        for row in rows:
            total_checks = row["total_checks"]
            fail_count = row["fail_count"]
            error_count = row["error_count"]
            timeout_count = row["timeout_count"]
            max_latency = row["max_latency"]

            # Same threshold logic as KQL
            if not (error_count > 3
                    or timeout_count > 2
                    or (total_checks > 10
                        and fail_count / total_checks > 0.5)
                    or total_checks == 0
                    or max_latency > 10000):
                continue

            results.append(DetectionResult(
                rule_id=self.rule_id,
                triggered=True,
                alert_title=(
                    f"CRITICAL: Physics oracle anomaly on {row['edge_node_id']}"
                ),
                alert_severity="High",
                atlas_technique="AML.T0029",
                threat_model_ref="TM-14",
                confidence=0.9,
                requires_immediate_action=True,
                evidence={
                    "edge_node_id": row["edge_node_id"],
                    "time_bin": str(row["time_bin"]),
                    "total_checks": total_checks,
                    "fail_count": fail_count,
                    "error_count": error_count,
                    "timeout_count": timeout_count,
                    "avg_latency_ms": round(row["avg_latency"], 1),
                    "max_latency_ms": max_latency,
                    "distinct_constraints": row["distinct_constraints"],
                },
                entities=[{"type": "edge_node", "id": row["edge_node_id"]}],
                timestamp=now.isoformat() + "Z",
            ))

        return results
```

### 4.6 ATLAS-DETECT-006: Supply Chain Compromise (TM-05 / AML.T0010)

```python
class SupplyChainCompromiseDetection(DetectionRule):
    """
    ATLAS-DETECT-006: ML Supply Chain Compromise Indicators
    Severity: Critical | Frequency: Every 1 hour | Lookback: 24 hours

    Three detection signals (union, same as original KQL):
    1. Dependency changes in CI/CD pipelines
    2. Unapproved model promotions to production/staging
    3. Edge node model hash mismatches against registry
    """

    @property
    def rule_id(self) -> str:
        return "ATLAS-DETECT-006"

    @property
    def frequency(self) -> timedelta:
        return timedelta(hours=1)

    @property
    def lookback(self) -> timedelta:
        return timedelta(hours=24)

    async def evaluate(self, db, now=None) -> list[DetectionResult]:
        now = now or datetime.utcnow()
        results = []

        # Signal 1: Dependency changes
        dep_query = """
            SELECT ts, pipeline_id, commit_hash, dependency_changes, deployer
            FROM cicd_audit
            WHERE ts > ($1 - INTERVAL '24 hours')
              AND dependency_changes != ''
              AND dependency_changes != 'none'
        """
        dep_rows = await db.fetch(dep_query, now)
        for row in dep_rows:
            results.append(DetectionResult(
                rule_id=self.rule_id,
                triggered=True,
                alert_title=f"ATLAS: Dependency change in pipeline {row['pipeline_id']}",
                alert_severity="High",
                atlas_technique="AML.T0010",
                threat_model_ref="TM-05",
                confidence=0.7,
                evidence={
                    "alert_type": "DependencyChange",
                    "pipeline_id": row["pipeline_id"],
                    "commit_hash": row["commit_hash"],
                    "dependency_changes": row["dependency_changes"],
                    "deployer": row["deployer"],
                },
                timestamp=now.isoformat() + "Z",
            ))

        # Signal 2: Unapproved model promotions
        promo_query = """
            SELECT ts, user_id, model_name, model_version, model_hash, stage
            FROM model_registry
            WHERE ts > ($1 - INTERVAL '24 hours')
              AND action IN ('promote', 'stage_transition', 'deploy')
              AND stage IN ('production', 'staging')
              AND (approved_by IS NULL OR approved_by = '')
        """
        promo_rows = await db.fetch(promo_query, now)
        for row in promo_rows:
            results.append(DetectionResult(
                rule_id=self.rule_id,
                triggered=True,
                alert_title=f"ATLAS: Unapproved model promotion — {row['model_name']} to {row['stage']}",
                alert_severity="High",
                atlas_technique="AML.T0010",
                threat_model_ref="TM-05",
                confidence=0.85,
                evidence={
                    "alert_type": "UnapprovedPromotion",
                    "user_id": row["user_id"],
                    "model_name": row["model_name"],
                    "model_version": row["model_version"],
                    "model_hash": row["model_hash"],
                    "stage": row["stage"],
                },
                entities=[{"type": "user", "id": row["user_id"]}],
                timestamp=now.isoformat() + "Z",
            ))

        # Signal 3: Hash mismatches (edge node hash not in production registry)
        hash_query = """
            SELECT e.ts, e.edge_node_id, e.model_weight_hash
            FROM edge_node_telemetry e
            WHERE e.ts > ($1 - INTERVAL '24 hours')
              AND e.model_weight_hash NOT IN (
                  SELECT DISTINCT model_hash
                  FROM model_registry
                  WHERE stage = 'production'
                    AND model_hash IS NOT NULL
              )
        """
        hash_rows = await db.fetch(hash_query, now)
        for row in hash_rows:
            results.append(DetectionResult(
                rule_id=self.rule_id,
                triggered=True,
                alert_title=f"ATLAS: Model hash mismatch on {row['edge_node_id']}",
                alert_severity="High",
                atlas_technique="AML.T0010",
                threat_model_ref="TM-05",
                confidence=0.9,
                requires_immediate_action=True,
                evidence={
                    "alert_type": "HashMismatch",
                    "edge_node_id": row["edge_node_id"],
                    "model_weight_hash": row["model_weight_hash"],
                },
                entities=[{"type": "edge_node", "id": row["edge_node_id"]}],
                timestamp=now.isoformat() + "Z",
            ))

        return results
```

### 4.7 ATLAS-DETECT-007: Insider Model Exfiltration (TM-11 / AML.T0035.002)

```python
class InsiderExfiltrationDetection(DetectionRule):
    """
    ATLAS-DETECT-007: Insider Model Exfiltration Indicators
    Severity: High | Frequency: Every 1 hour | Lookback: 24h + 30d baseline

    Same thresholds and deviation logic as original KQL:
      - DeviationFactor > 5.0
      - DistinctResources > 3
      - AfterHoursCount > 5 (before 06:00 or after 20:00)
      - AccessCount > 50
    """

    SUSPICIOUS_RESOURCES = [
        "model-weights", "model-registry", "training-data",
        "architecture-docs", "hyperparameters", "model-config",
    ]

    @property
    def rule_id(self) -> str:
        return "ATLAS-DETECT-007"

    @property
    def frequency(self) -> timedelta:
        return timedelta(hours=1)

    @property
    def lookback(self) -> timedelta:
        return timedelta(hours=24)

    async def evaluate(self, db, now=None) -> list[DetectionResult]:
        now = now or datetime.utcnow()
        results = []

        # 30-day baseline
        baseline_query = """
            SELECT user_id,
                   COUNT(*)::float / 30.0 AS daily_avg
            FROM databricks_audit
            WHERE ts BETWEEN ($1 - INTERVAL '30 days') AND ($1 - INTERVAL '1 day')
              AND target_resource ILIKE ANY(
                  SELECT '%' || unnest || '%' FROM unnest($2::text[])
              )
            GROUP BY user_id
        """
        baselines = {
            row["user_id"]: row["daily_avg"]
            for row in await db.fetch(baseline_query, now, self.SUSPICIOUS_RESOURCES)
        }

        # Current 24-hour window
        current_query = """
            SELECT
                user_id,
                COUNT(*) AS access_count,
                COUNT(DISTINCT target_resource) AS distinct_resources,
                ARRAY_AGG(DISTINCT source_ip::text) AS source_ips,
                ARRAY_AGG(DISTINCT target_resource) AS resources,
                COUNT(*) FILTER (
                    WHERE EXTRACT(HOUR FROM ts) < 6
                       OR EXTRACT(HOUR FROM ts) > 20
                ) AS after_hours_count
            FROM databricks_audit
            WHERE ts > ($1 - INTERVAL '24 hours')
              AND target_resource ILIKE ANY(
                  SELECT '%' || unnest || '%' FROM unnest($2::text[])
              )
            GROUP BY user_id
        """
        rows = await db.fetch(current_query, now, self.SUSPICIOUS_RESOURCES)

        for row in rows:
            user_id = row["user_id"]
            access_count = row["access_count"]
            distinct_resources = row["distinct_resources"]
            after_hours = row["after_hours_count"]
            daily_avg = baselines.get(user_id, 0.0)

            deviation_factor = (access_count / daily_avg) if daily_avg > 0 else 999.0

            # Same threshold logic as KQL
            if not (deviation_factor > 5.0
                    or distinct_resources > 3
                    or after_hours > 5
                    or access_count > 50):
                continue

            results.append(DetectionResult(
                rule_id=self.rule_id,
                triggered=True,
                alert_title=f"ATLAS: Insider model access anomaly — {user_id}",
                alert_severity="High",
                atlas_technique="AML.T0035.002",
                threat_model_ref="TM-11",
                confidence=min(0.95, 0.6 + (deviation_factor / 30.0)),
                evidence={
                    "user_id": user_id,
                    "access_count": access_count,
                    "distinct_resources": distinct_resources,
                    "after_hours_count": after_hours,
                    "deviation_factor": round(deviation_factor, 2),
                    "daily_avg_baseline": round(daily_avg, 2),
                    "source_ips": row["source_ips"][:10],
                    "resources": row["resources"][:20],
                },
                entities=[{"type": "user", "id": user_id}],
                timestamp=now.isoformat() + "Z",
            ))

        return results
```

### 4.8 ATLAS-DETECT-008: Alert Fatigue Exploitation (TM-17 / AML.T0015)

```python
class AlertFatigueDetection(DetectionRule):
    """
    ATLAS-DETECT-008: Alert Fatigue Exploitation
    Severity: Medium | Frequency: Every 1 hour | Lookback: 6h + 7d baseline

    Detects when an attacker floods ALUSKORT with decoy alerts to exhaust
    analyst attention and bury real threats. Same spike ratio as KQL:
      - SpikeRatio > 5.0 (current hourly count vs 7-day hourly average)
    This is a meta-alert — an alert ABOUT the alerting system itself.
    """

    @property
    def rule_id(self) -> str:
        return "ATLAS-DETECT-008"

    @property
    def frequency(self) -> timedelta:
        return timedelta(hours=1)

    @property
    def lookback(self) -> timedelta:
        return timedelta(hours=6)

    async def evaluate(self, db, now=None) -> list[DetectionResult]:
        now = now or datetime.utcnow()
        results = []

        # Query ALUSKORT's own alert table for Orbital-related alerts.
        # 7-day baseline: average hourly count per alert_name.
        # Current: per-hour count in the last 6 hours.
        query = """
            WITH baseline AS (
                SELECT alert_title,
                       COUNT(*)::float / (7.0 * 24) AS hourly_avg
                FROM alerts
                WHERE ts BETWEEN ($1 - INTERVAL '7 days') AND ($1 - INTERVAL '6 hours')
                  AND (product ILIKE '%orbital%' OR source ILIKE '%orbital%')
                GROUP BY alert_title
            ),
            current_hourly AS (
                SELECT alert_title,
                       DATE_TRUNC('hour', ts) AS hour_bin,
                       COUNT(*) AS current_count
                FROM alerts
                WHERE ts > ($1 - INTERVAL '6 hours')
                  AND (product ILIKE '%orbital%' OR source ILIKE '%orbital%')
                GROUP BY alert_title, DATE_TRUNC('hour', ts)
            )
            SELECT c.alert_title, c.hour_bin, c.current_count,
                   b.hourly_avg,
                   c.current_count / GREATEST(b.hourly_avg, 0.1) AS spike_ratio
            FROM current_hourly c
            INNER JOIN baseline b ON c.alert_title = b.alert_title
            WHERE c.current_count / GREATEST(b.hourly_avg, 0.1) > 5.0
        """
        rows = await db.fetch(query, now)

        for row in rows:
            results.append(DetectionResult(
                rule_id=self.rule_id,
                triggered=True,
                alert_title=(
                    f"ATLAS: Alert fatigue — '{row['alert_title']}' "
                    f"spike ratio {row['spike_ratio']:.1f}x"
                ),
                alert_severity="Medium",
                atlas_technique="AML.T0015",
                threat_model_ref="TM-17",
                confidence=0.7,
                evidence={
                    "alert_title": row["alert_title"],
                    "hour_bin": str(row["hour_bin"]),
                    "current_count": row["current_count"],
                    "hourly_avg_baseline": round(row["hourly_avg"], 2),
                    "spike_ratio": round(row["spike_ratio"], 2),
                    "is_meta_alert": True,
                },
                timestamp=now.isoformat() + "Z",
            ))

        return results
```

### 4.9 ATLAS-DETECT-009: Sensor Data Spoofing (TM-06 / AML.T0043)

```python
class SensorSpoofingDetection(DetectionRule):
    """
    ATLAS-DETECT-009: Sensor Data Spoofing Indicators
    Severity: Critical | Frequency: Every 5 minutes | Lookback: 15 min + 24h baseline

    Same z-score and threshold logic as original KQL:
      - DataPointZScore: (current - avg) / std, threshold |z| > 3.0
      - ProtocolViolationCount > 0
      - SensorCountDelta |delta| > 5
      - ConnectionChanges > 2
    """

    @property
    def rule_id(self) -> str:
        return "ATLAS-DETECT-009"

    @property
    def frequency(self) -> timedelta:
        return timedelta(minutes=5)

    @property
    def lookback(self) -> timedelta:
        return timedelta(minutes=15)

    async def evaluate(self, db, now=None) -> list[DetectionResult]:
        now = now or datetime.utcnow()
        results = []

        query = """
            WITH baseline AS (
                SELECT edge_node_id,
                       AVG(data_points_received) AS avg_data_points,
                       STDDEV(data_points_received) AS std_data_points,
                       AVG(sensor_count) AS avg_sensor_count
                FROM opcua_telemetry
                WHERE ts BETWEEN ($1 - INTERVAL '24 hours') AND ($1 - INTERVAL '15 minutes')
                GROUP BY edge_node_id
            ),
            current_period AS (
                SELECT edge_node_id,
                       AVG(data_points_received) AS current_data_points,
                       AVG(sensor_count) AS current_sensor_count,
                       SUM(protocol_violations) AS protocol_violation_count,
                       COUNT(DISTINCT connection_state) FILTER (
                           WHERE connection_state != 'Connected'
                       ) AS connection_changes
                FROM opcua_telemetry
                WHERE ts > ($1 - INTERVAL '15 minutes')
                GROUP BY edge_node_id
            )
            SELECT
                c.edge_node_id,
                c.current_data_points,
                b.avg_data_points,
                b.std_data_points,
                c.current_sensor_count,
                b.avg_sensor_count,
                c.protocol_violation_count,
                c.connection_changes,
                CASE WHEN b.std_data_points > 0 THEN
                    (c.current_data_points - b.avg_data_points) / b.std_data_points
                ELSE 0.0 END AS data_point_z_score,
                c.current_sensor_count - b.avg_sensor_count AS sensor_count_delta
            FROM current_period c
            INNER JOIN baseline b ON c.edge_node_id = b.edge_node_id
        """
        rows = await db.fetch(query, now)

        for row in rows:
            z_score = row["data_point_z_score"]
            violations = row["protocol_violation_count"]
            sensor_delta = row["sensor_count_delta"]
            connection_changes = row["connection_changes"]

            # Same threshold logic as KQL
            if not (abs(z_score) > 3.0
                    or violations > 0
                    or abs(sensor_delta) > 5
                    or connection_changes > 2):
                continue

            results.append(DetectionResult(
                rule_id=self.rule_id,
                triggered=True,
                alert_title=(
                    f"ATLAS: Sensor data spoofing on {row['edge_node_id']}"
                ),
                alert_severity="High",
                atlas_technique="AML.T0043",
                threat_model_ref="TM-06",
                confidence=0.85,
                requires_immediate_action=True,
                evidence={
                    "edge_node_id": row["edge_node_id"],
                    "data_point_z_score": round(z_score, 3),
                    "protocol_violation_count": violations,
                    "sensor_count_delta": round(sensor_delta, 1),
                    "connection_changes": connection_changes,
                    "current_data_points": round(row["current_data_points"], 1),
                    "baseline_avg_data_points": round(row["avg_data_points"], 1),
                },
                entities=[{"type": "edge_node", "id": row["edge_node_id"]}],
                timestamp=now.isoformat() + "Z",
            ))

        return results
```

### 4.10 ATLAS-DETECT-010: Partner Integration Compromise (TM-08 / AML.T0043 + T1199)

```python
class PartnerCompromiseDetection(DetectionRule):
    """
    ATLAS-DETECT-010: Partner Integration Anomaly
    Severity: High | Frequency: Every 30 minutes | Lookback: 6h + 7d baseline

    Same deviation and z-score logic as original KQL:
      - VolumeDeviation > 3.0 (6h count vs daily avg / 4)
      - PayloadZScore > 3.0
      - mTLS failure when historical rate > 99%
      - ErrorCount > 10
    """

    @property
    def rule_id(self) -> str:
        return "ATLAS-DETECT-010"

    @property
    def frequency(self) -> timedelta:
        return timedelta(minutes=30)

    @property
    def lookback(self) -> timedelta:
        return timedelta(hours=6)

    async def evaluate(self, db, now=None) -> list[DetectionResult]:
        now = now or datetime.utcnow()
        results = []

        query = """
            WITH baseline AS (
                SELECT partner_id, direction,
                       COUNT(*)::float / 7.0 AS avg_daily_requests,
                       AVG(payload_size) AS avg_payload_size,
                       STDDEV(payload_size) AS std_payload_size,
                       COUNT(*) FILTER (WHERE mtls_verified)::float
                           / GREATEST(COUNT(*), 1) AS normal_mtls_rate
                FROM partner_api_logs
                WHERE ts BETWEEN ($1 - INTERVAL '7 days') AND ($1 - INTERVAL '6 hours')
                GROUP BY partner_id, direction
            ),
            current_period AS (
                SELECT partner_id, partner_name, direction,
                       COUNT(*) AS request_count,
                       AVG(payload_size) AS avg_payload,
                       MAX(payload_size) AS max_payload,
                       COUNT(*) FILTER (WHERE response_code >= 400) AS error_count,
                       COUNT(*) FILTER (WHERE NOT mtls_verified) AS mtls_fail_count,
                       COUNT(DISTINCT data_type) AS distinct_data_types
                FROM partner_api_logs
                WHERE ts > ($1 - INTERVAL '6 hours')
                GROUP BY partner_id, partner_name, direction
            )
            SELECT
                c.partner_id, c.partner_name, c.direction,
                c.request_count, c.avg_payload, c.max_payload,
                c.error_count, c.mtls_fail_count, c.distinct_data_types,
                b.avg_daily_requests, b.avg_payload_size, b.std_payload_size,
                b.normal_mtls_rate,
                CASE WHEN b.avg_daily_requests > 0 THEN
                    c.request_count / (b.avg_daily_requests / 4.0)
                ELSE 999 END AS volume_deviation,
                CASE WHEN b.std_payload_size > 0 THEN
                    (c.avg_payload - b.avg_payload_size) / b.std_payload_size
                ELSE 0 END AS payload_z_score
            FROM current_period c
            INNER JOIN baseline b ON c.partner_id = b.partner_id
                AND c.direction = b.direction
        """
        rows = await db.fetch(query, now)

        for row in rows:
            vol_dev = row["volume_deviation"]
            payload_z = row["payload_z_score"]
            mtls_anomalous = (row["mtls_fail_count"] > 0
                              and row["normal_mtls_rate"] > 0.99)
            error_count = row["error_count"]

            # Same threshold logic as KQL
            if not (vol_dev > 3.0 or payload_z > 3.0
                    or mtls_anomalous or error_count > 10):
                continue

            results.append(DetectionResult(
                rule_id=self.rule_id,
                triggered=True,
                alert_title=(
                    f"ATLAS: Partner anomaly — {row['partner_name']} "
                    f"({row['direction']})"
                ),
                alert_severity="High",
                atlas_technique="AML.T0043",
                attack_technique="T1199",
                threat_model_ref="TM-08",
                confidence=0.8,
                evidence={
                    "partner_id": row["partner_id"],
                    "partner_name": row["partner_name"],
                    "direction": row["direction"],
                    "request_count": row["request_count"],
                    "volume_deviation": round(vol_dev, 2),
                    "payload_z_score": round(payload_z, 2),
                    "mtls_fail_count": row["mtls_fail_count"],
                    "error_count": error_count,
                    "mtls_anomalous": mtls_anomalous,
                },
                entities=[{"type": "partner", "id": row["partner_id"]}],
                timestamp=now.isoformat() + "Z",
            ))

        return results
```

### 4.11 Detection Rule Registry

```python
"""
ALUSKORT ATLAS Detection Rule Registry
Registers all detection rules and provides the execution loop.
"""

from typing import Optional
from datetime import datetime


# Registry of all ATLAS detection rules
ATLAS_DETECTION_RULES = [
    TrainingDataPoisoningDetection(),       # ATLAS-DETECT-001
    ModelExtractionDetection(),              # ATLAS-DETECT-002
    PromptInjectionDetection(),              # ATLAS-DETECT-003
    AdversarialEvasionDetection(),           # ATLAS-DETECT-004
    PhysicsOracleDoSDetection(),             # ATLAS-DETECT-005
    SupplyChainCompromiseDetection(),        # ATLAS-DETECT-006
    InsiderExfiltrationDetection(),          # ATLAS-DETECT-007
    AlertFatigueDetection(),                 # ATLAS-DETECT-008
    SensorSpoofingDetection(),              # ATLAS-DETECT-009
    PartnerCompromiseDetection(),             # ATLAS-DETECT-010
]


async def run_detection_cycle(db, now: Optional[datetime] = None):
    """
    Execute all detection rules whose schedule is due.
    Called by the orchestrator on a timer.
    Publishes any triggered DetectionResults to alerts.normalized topic.
    """
    now = now or datetime.utcnow()

    for rule in ATLAS_DETECTION_RULES:
        try:
            detections = await rule.evaluate(db, now)
            for detection in detections:
                if detection.triggered:
                    logger.info(
                        f"Detection triggered: {detection.rule_id} — "
                        f"{detection.alert_title}"
                    )
                    # Publish to alerts.normalized Kafka topic
                    # await kafka_producer.send("alerts.normalized", detection)
        except Exception as e:
            logger.error(
                f"Detection rule {rule.rule_id} failed: {e}",
                exc_info=True,
            )
```

---

## 5. Updated Agent Implementations

### 5.1 ATLAS-Aware Reasoning Agent System Prompt

```
You are a senior SOC analyst reasoning engine specialising in adversarial
AI threats against critical energy infrastructure.

You operate within the ALUSKORT autonomous SOC architecture protecting the
Orbital Foundation Model Platform — a physics-grounded AI system deployed
at refineries, petrochemical plants, LNG terminals, and upstream facilities.

ARCHITECTURE CONTEXT:
You receive normalised alerts from ingest adapters via the alerts.normalized
Kafka topic. Your context is enriched with data from Postgres (structured
queries), Neo4j (asset/zone graph), Redis (IOC cache), and a vector database
(semantic retrieval of past incidents). You do NOT query any SIEM directly —
all data reaches you through the ALUSKORT data layer.

YOUR THREAT FRAMEWORK:
You reason using BOTH MITRE ATT&CK (for IT/OT TTPs) and MITRE ATLAS
(for AI/ML-specific TTPs). Many attacks span both frameworks.

ATLAS TACTICS YOU MUST CONSIDER:
- AML.T0020: Poison Training Data
- AML.T0043: Craft Adversarial Data
- AML.T0015: Evade ML Model
- AML.T0044: Full ML Model Access
- AML.T0044.001: Query-Based Model Extraction
- AML.T0051: LLM Prompt Injection
- AML.T0054: LLM Jailbreak
- AML.T0029: Denial of ML Service
- AML.T0010: ML Supply Chain Compromise
- AML.T0018: Backdoor ML Model
- AML.T0035: ML Model Access
- AML.T0014: Discover ML Model Ontology
- AML.T0024: Infer Training Data Membership

SAFETY-CRITICAL CONTEXT:
Orbital operates in ISA-95 Level 2-3. Its prescriptive outputs can
influence physical processes at refineries. ALWAYS escalate to CRITICAL
severity when:
1. Physics validation oracle anomalies are detected
2. Sensor data spoofing is suspected
3. Lateral movement toward DCS/SCADA (Level 0-1) is indicated
4. Model weights may have been tampered with on edge nodes

Return a JSON object with: threat_classification, confidence, severity,
summary, evidence, atlas_tactics, attack_techniques, threat_model_refs,
kill_chain_phase, orbital_safety_impact, recommended_actions, reasoning_chain.

Rules:
- ALWAYS check if the attack path could reach ICS Level 0-1.
  If so, severity is CRITICAL regardless of other factors.
- Map to BOTH ATT&CK and ATLAS where applicable.
- When evidence is ambiguous, classify as requires_investigation, never false_positive.
- For physics oracle anomalies, ALWAYS recommend verifying fail-closed behaviour.
- For model integrity issues, ALWAYS recommend hash verification against the registry.
```

### 5.2 ATLAS-Aware IOC Extractor

Extracts both traditional IOCs and ATLAS-specific indicators:
- Model hashes, dataset identifiers, API endpoints
- Query patterns, injection payloads, edge node IDs
- Pipeline IDs, partner identifiers, constraint IDs
- Sensor anomalies

### 5.3 ATLAS Threat Assessment Data Model

```python
@dataclass
class OrbitalSafetyImpact:
    affects_prescriptive_output: bool = False
    affects_physics_oracle: bool = False
    affects_edge_integrity: bool = False
    ics_safety_relevance: str = "none"  # none | indirect | direct
    requires_fail_closed: bool = False


@dataclass
class ATLASThreatAssessment:
    alert_id: str
    threat_classification: str
    confidence: float
    severity: str
    summary: str
    evidence: list[str]
    atlas_techniques: list[str]
    attack_techniques: list[str]
    threat_model_refs: list[str]
    safety_impact: OrbitalSafetyImpact
    recommended_actions: list[str]
    reasoning_chain: list[str]
```

### 5.4 ATLAS Technique to Orbital TM Mapping

15 ATLAS techniques mapped to 17 Orbital threat model IDs with severity, safety impact, and descriptions. Used by the Reasoning Agent for cross-referencing detections.

---

## 6. Self-Protection: ALUSKORT as an Attack Surface

ALUSKORT itself is an AI system using an LLM. It is subject to ATLAS attacks.

| Attack | ATLAS Technique | Impact | Mitigation |
|---|---|---|---|
| Poison alert data to manipulate IOC Extractor | AML.T0043 | Agent extracts wrong IOCs | Input sanitisation via Context Gateway, multi-model validation |
| SQL injection via crafted alert entities | AML.T0051 (adapted) | Agent executes attacker queries | Parameterised queries only (no string interpolation in SQL), Context Gateway regex |
| Prompt inject via alert Description field | AML.T0051 | LLM follows attacker instructions | Context Gateway system prompt hardening, output validation |
| Flood alerts to overwhelm agents | AML.T0029 | Rate limits hit, real threats missed | Priority queues with per-severity concurrency limits (see system design Section 6.3) |
| Manipulate confidence scores | AML.T0043 | True positives dismissed as FP | Confidence floor for safety-critical patterns |
| Exfiltrate query patterns via crafted IOCs | AML.T0024 (adapted) | Adversary learns detection coverage | Audit logging to `audit.events` topic, output filtering |

> **Why this matters:** If an attacker can manipulate ALUSKORT's reasoning, they can suppress detection of their actual attack. Self-protection is not optional — it is a prerequisite for the system to function as designed.

### Self-Protection Guardrails

- **Alert sanitisation** via Context Gateway before LLM processing (injection pattern detection + redaction — see `docs/ai-system-design.md` Section 7)
- **Confidence floor enforcement** for safety-critical detections:
  - Physics oracle alerts: confidence >= 0.7
  - Sensor spoofing alerts: confidence >= 0.7
  - Lateral movement to ICS: confidence >= 0.8
- **Safety-relevant dismissal prevention** (LLM cannot classify safety-relevant alerts as `false_positive`)
- **Parameterised queries only** (all SQL uses parameter binding via asyncpg `$1, $2, ...` — no string interpolation)

---

## 7. ATLAS-Aware Response Playbooks

| TM-ID | Detection | Auto-Response | Human-Approved Response |
|---|---|---|---|
| TM-01 | ATLAS-DETECT-001 | Quarantine Databricks user session | Freeze Delta Lake tables, initiate data audit |
| TM-03 | ATLAS-DETECT-004/005 | Trigger physics oracle health check | Halt prescriptive outputs (fail-closed) |
| TM-06 | ATLAS-DETECT-009 | Flag affected edge node for manual review | Isolate edge node from OPC-UA, switch to manual ops |
| TM-10 | ATLAS-DETECT-003 | Block user session, log query | Disable NL interface, review session history |
| TM-12 | ATLAS-DETECT-002 | Rate limit caller, add output perturbation | Revoke API credentials, block IP |
| TM-14 | ATLAS-DETECT-005 | **IMMEDIATE: verify fail-closed** | Isolate edge node, manual physics check |

> **Why response playbooks reference detection rules:** Each playbook is triggered by a specific detection rule's `DetectionResult`. The Response Agent receives the result from the Reasoning Agent (via the investigation graph) and matches it to the appropriate playbook. Human-approved responses are gated via the `AWAITING_HUMAN` state in the investigation graph (see `docs/ai-system-design.md` Section 4.1).

---

## 8. Validation & Red Team Scenarios

| Test | Target | Method | Expected Result |
|---|---|---|---|
| AT-1 | Alert prompt injection | Inject "ignore instructions" in alert Description | Sanitised by Context Gateway before LLM, redacted marker inserted |
| AT-2 | Confidence floor | LLM returns 0.3 for physics oracle alert | Floor enforced to 0.7 |
| AT-3 | Safety dismissal | LLM classifies sensor alert as false_positive | Overridden to requires_investigation |
| AT-4 | SQL injection via IOC | IOC contains `'; DROP TABLE alerts; --` | Parameterised query prevents injection, IOC flagged |
| AT-5 | Technique mapping | Check all critical TM-IDs have ATLAS mappings | All 6 critical TM-IDs covered |

> **Why red team validation of ALUSKORT itself is required:** If we only validate detection of external threats but never test ALUSKORT's own self-protection, an adversary who understands the architecture can bypass the SOC entirely. AT-1 through AT-5 test the system's resistance to meta-attacks — attacks against the defender.

---

## 9. Implementation & Deployment

### 9.1 Database Migration (Alembic)

```python
"""
Alembic migration: Create ATLAS telemetry tables
Revision ID: atlas_001
"""

from alembic import op
import sqlalchemy as sa


def upgrade():
    """Create all 10 ATLAS telemetry tables."""
    # See Section 3.2 for full DDL.
    # Each table is created with appropriate indexes.
    # Tables: orbital_inference_logs, orbital_physics_oracle,
    #         orbital_nl_query_logs, orbital_api_logs,
    #         edge_node_telemetry, databricks_audit,
    #         model_registry, cicd_audit,
    #         partner_api_logs, opcua_telemetry
    op.execute("""
        -- Paste DDL from Section 3.2 here
        -- (omitted for brevity — see Section 3.2 for full CREATE TABLE statements)
    """)


def downgrade():
    """Drop all ATLAS telemetry tables."""
    for table in [
        "orbital_inference_logs", "orbital_physics_oracle",
        "orbital_nl_query_logs", "orbital_api_logs",
        "edge_node_telemetry", "databricks_audit",
        "model_registry", "cicd_audit",
        "partner_api_logs", "opcua_telemetry",
    ]:
        op.drop_table(table)
```

### 9.2 Detection Rule Registration

```python
"""
Register ATLAS detection rules with the orchestrator's scheduler.
Each rule is executed on its defined frequency.
"""

from services.orchestrator.scheduler import DetectionScheduler

scheduler = DetectionScheduler()

for rule in ATLAS_DETECTION_RULES:
    scheduler.register(
        rule_id=rule.rule_id,
        rule=rule,
        frequency=rule.frequency,
        enabled=True,
    )
    print(f"Registered: {rule.rule_id} (every {rule.frequency})")

# Output:
# Registered: ATLAS-DETECT-001 (every 1:00:00)
# Registered: ATLAS-DETECT-002 (every 0:30:00)
# Registered: ATLAS-DETECT-003 (every 0:15:00)
# Registered: ATLAS-DETECT-004 (every 0:15:00)
# Registered: ATLAS-DETECT-005 (every 0:05:00)
# Registered: ATLAS-DETECT-006 (every 1:00:00)
# Registered: ATLAS-DETECT-007 (every 1:00:00)
# Registered: ATLAS-DETECT-008 (every 1:00:00)
# Registered: ATLAS-DETECT-009 (every 0:05:00)
# Registered: ATLAS-DETECT-010 (every 0:30:00)
```

### 9.3 Kafka Topic Creation

```bash
# Create all ATLAS telemetry topics
# Run against your Kafka/Redpanda cluster

for TOPIC in \
    telemetry.orbital.inference \
    telemetry.orbital.physics \
    telemetry.orbital.nlquery \
    telemetry.orbital.api \
    telemetry.databricks.audit \
    telemetry.edge.health \
    telemetry.modelregistry.events \
    telemetry.cicd.audit \
    telemetry.partner.api \
    telemetry.opcua.sensors; do
  echo "Creating topic: $TOPIC"
  rpk topic create "$TOPIC" \
    --partitions 4 \
    --replicas 3 \
    --config retention.ms=604800000
done

echo ""
echo "=== ATLAS Telemetry Topics Created ==="
rpk topic list | grep telemetry
```

### 9.4 Docker Compose — ATLAS Detection Service

```yaml
# Add to deploy/docker-compose.yml
services:
  atlas-detection:
    build:
      context: .
      dockerfile: services/orchestrator/Dockerfile
    command: ["python", "-m", "services.orchestrator.detection_runner"]
    environment:
      - POSTGRES_DSN=postgresql://aluskort:${PG_PASSWORD}@postgres:5432/aluskort
      - KAFKA_BROKERS=kafka:9092
      - DETECTION_RULES=atlas
    depends_on:
      - postgres
      - kafka
    restart: unless-stopped
    deploy:
      replicas: 2
      resources:
        limits:
          memory: 512M
          cpus: "0.5"
```

### 9.5 Verify Integration

```bash
#!/bin/bash
echo "=== ALUSKORT ATLAS Integration Verification ==="

# Check Postgres tables
echo ""
echo "--- Postgres Tables ---"
for TABLE in \
    orbital_inference_logs orbital_physics_oracle orbital_nl_query_logs \
    orbital_api_logs edge_node_telemetry databricks_audit \
    model_registry cicd_audit partner_api_logs opcua_telemetry; do
  COUNT=$(psql "$POSTGRES_DSN" -t -c "SELECT COUNT(*) FROM $TABLE" 2>/dev/null)
  if [ $? -eq 0 ]; then
    echo "  OK: $TABLE (rows: $(echo $COUNT | xargs))"
  else
    echo "  MISSING: $TABLE"
  fi
done

# Check Kafka topics
echo ""
echo "--- Kafka Topics ---"
rpk topic list | grep telemetry | while read TOPIC; do
  echo "  OK: $TOPIC"
done

# Check detection rules
echo ""
echo "--- Detection Rules ---"
echo "  Registered: 10 ATLAS detection rules (ATLAS-DETECT-001 through 010)"
echo "  Critical frequency (5 min): ATLAS-DETECT-005, ATLAS-DETECT-009"
echo "  High frequency (15 min): ATLAS-DETECT-003, ATLAS-DETECT-004"
echo "  Standard frequency (30 min - 1 hr): ATLAS-DETECT-001, 002, 006, 007, 008, 010"

echo ""
echo "=== Verification Complete ==="
```

---

*Document generated by Omeriko for ALUSKORT project (v2.0 — Cloud-Neutral). ATLAS integration layer provides AI/ML-specific adversarial threat detection for the Orbital Foundation Model Platform using Python detection rules against Postgres data, replacing the previous Azure Sentinel KQL implementation. See `docs/ai-system-design.md` for the system architecture context.*
