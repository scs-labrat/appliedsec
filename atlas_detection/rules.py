"""ATLAS detection rules — Story 9.2.

10 detection rules (ATLAS-DETECT-001 through 010) with exact
statistical thresholds from the Orbital threat model.
"""

from __future__ import annotations

import math
from datetime import datetime, timedelta, timezone
from typing import Any

from atlas_detection.models import DetectionResult, DetectionRule


# ===========================================================================
# ATLAS-DETECT-001 — Training Data Poisoning (TM-01)
# ===========================================================================

class TrainingDataPoisoningRule(DetectionRule):
    """Detect anomalous Databricks activity indicating data poisoning."""

    rule_id = "ATLAS-DETECT-001"
    frequency = timedelta(hours=1)
    lookback = timedelta(hours=24)

    SUSPICIOUS_ACTIONS = (
        "deltaDMLEvent", "deltaTableWrite", "notebookRun", "clusterCreate",
    )
    DEVIATION_THRESHOLD = 3.0
    DISTINCT_TABLES_THRESHOLD = 5
    TODAY_COUNT_THRESHOLD = 50
    BASELINE_DAYS = 30

    async def evaluate(self, db: Any, now: datetime | None = None) -> list[DetectionResult]:
        now = now or datetime.now(timezone.utc)
        lookback_start = now - self.lookback
        baseline_start = now - timedelta(days=self.BASELINE_DAYS)

        # Current activity
        current = await db.fetch_many(
            """
            SELECT user_id, COUNT(*) as cnt,
                   COUNT(DISTINCT target_resource) as distinct_tables
            FROM databricks_audit
            WHERE ts >= $1 AND ts < $2
              AND action = ANY($3)
            GROUP BY user_id
            """,
            lookback_start, now, list(self.SUSPICIOUS_ACTIONS),
        )

        # Baseline averages
        baseline = await db.fetch_many(
            """
            SELECT user_id, COUNT(*) / 30.0 as avg_daily
            FROM databricks_audit
            WHERE ts >= $1 AND ts < $2
              AND action = ANY($3)
            GROUP BY user_id
            """,
            baseline_start, lookback_start, list(self.SUSPICIOUS_ACTIONS),
        )
        baseline_map = {r["user_id"]: r["avg_daily"] for r in baseline}

        results: list[DetectionResult] = []
        for row in current:
            user_id = row["user_id"]
            count = row["cnt"]
            distinct = row["distinct_tables"]
            avg_daily = baseline_map.get(user_id, 0)
            deviation = count / avg_daily if avg_daily > 0 else count

            if (deviation > self.DEVIATION_THRESHOLD
                    or distinct > self.DISTINCT_TABLES_THRESHOLD
                    or count > self.TODAY_COUNT_THRESHOLD):
                confidence = min(0.95, 0.5 + deviation / 20.0)
                results.append(DetectionResult(
                    rule_id=self.rule_id,
                    triggered=True,
                    alert_title=f"Training data poisoning: anomalous activity by {user_id}",
                    alert_severity="High",
                    atlas_technique="AML.T0020",
                    attack_technique="T1565.001",
                    threat_model_ref="TM-01",
                    confidence=confidence,
                    evidence={
                        "user_id": user_id,
                        "count": count,
                        "distinct_tables": distinct,
                        "deviation_factor": round(deviation, 2),
                        "baseline_avg": round(avg_daily, 2),
                    },
                    entities=[{"type": "user", "id": user_id}],
                ))
        return results


# ===========================================================================
# ATLAS-DETECT-002 — Model Extraction (TM-12)
# ===========================================================================

class ModelExtractionRule(DetectionRule):
    """Detect systematic query patterns indicating model extraction."""

    rule_id = "ATLAS-DETECT-002"
    frequency = timedelta(minutes=30)
    lookback = timedelta(hours=6)

    QUERY_COUNT_THRESHOLD = 100
    MEDIAN_GAP_MS_THRESHOLD = 500

    async def evaluate(self, db: Any, now: datetime | None = None) -> list[DetectionResult]:
        now = now or datetime.now(timezone.utc)
        start = now - self.lookback

        rows = await db.fetch_many(
            """
            SELECT user_id, COUNT(*) as query_count,
                   PERCENTILE_CONT(0.5) WITHIN GROUP (ORDER BY token_count) as median_tokens
            FROM orbital_nl_query_logs
            WHERE ts >= $1 AND ts < $2
            GROUP BY user_id
            HAVING COUNT(*) > $3
            """,
            start, now, self.QUERY_COUNT_THRESHOLD,
        )

        results: list[DetectionResult] = []
        for row in rows:
            confidence = min(0.9, 0.6 + row["query_count"] / 1000.0)
            results.append(DetectionResult(
                rule_id=self.rule_id,
                triggered=True,
                alert_title=f"Model extraction: high query volume by {row['user_id']}",
                alert_severity="High",
                atlas_technique="AML.T0044.001",
                attack_technique="T1530",
                threat_model_ref="TM-12",
                confidence=confidence,
                evidence={
                    "user_id": row["user_id"],
                    "query_count": row["query_count"],
                    "median_tokens": row.get("median_tokens", 0),
                },
                entities=[{"type": "user", "id": row["user_id"]}],
            ))
        return results


# ===========================================================================
# ATLAS-DETECT-003 — LLM Prompt Injection (TM-10)
# ===========================================================================

class PromptInjectionRule(DetectionRule):
    """Detect injection patterns in NL query logs."""

    rule_id = "ATLAS-DETECT-003"
    frequency = timedelta(minutes=15)
    lookback = timedelta(hours=1)

    async def evaluate(self, db: Any, now: datetime | None = None) -> list[DetectionResult]:
        now = now or datetime.now(timezone.utc)
        start = now - self.lookback

        rows = await db.fetch_many(
            """
            SELECT user_id, session_id, query_text, safety_filter_triggered
            FROM orbital_nl_query_logs
            WHERE ts >= $1 AND ts < $2
              AND safety_filter_triggered = true
            """,
            start, now,
        )

        results: list[DetectionResult] = []
        for row in rows:
            results.append(DetectionResult(
                rule_id=self.rule_id,
                triggered=True,
                alert_title=f"Prompt injection attempt by {row['user_id']}",
                alert_severity="High",
                atlas_technique="AML.T0051",
                threat_model_ref="TM-10",
                confidence=0.85,
                evidence={
                    "user_id": row["user_id"],
                    "session_id": row["session_id"],
                    "safety_filter_triggered": True,
                },
                entities=[{"type": "user", "id": row["user_id"]}],
            ))
        return results


# ===========================================================================
# ATLAS-DETECT-004 — Adversarial Evasion (TM-07)
# ===========================================================================

class AdversarialEvasionRule(DetectionRule):
    """Detect adversarial evasion via inference accuracy drops."""

    rule_id = "ATLAS-DETECT-004"
    frequency = timedelta(minutes=15)
    lookback = timedelta(hours=1)

    ZSCORE_THRESHOLD = -2.0
    PHYSICS_FAIL_RATE_THRESHOLD = 0.1
    LATENCY_INCREASE_MS = 500
    BASELINE_DAYS = 7

    async def evaluate(self, db: Any, now: datetime | None = None) -> list[DetectionResult]:
        now = now or datetime.now(timezone.utc)
        start = now - self.lookback
        baseline_start = now - timedelta(days=self.BASELINE_DAYS)

        current = await db.fetch_many(
            """
            SELECT edge_node_id,
                   AVG(confidence_score) as avg_confidence,
                   AVG(inference_latency_ms) as avg_latency,
                   SUM(CASE WHEN physics_check_result = 'fail' THEN 1 ELSE 0 END)::float
                       / NULLIF(COUNT(*), 0) as fail_rate,
                   COUNT(*) as count
            FROM orbital_inference_logs
            WHERE ts >= $1 AND ts < $2
            GROUP BY edge_node_id
            """,
            start, now,
        )

        baseline = await db.fetch_many(
            """
            SELECT edge_node_id,
                   AVG(confidence_score) as avg_confidence,
                   STDDEV(confidence_score) as stddev_confidence,
                   AVG(inference_latency_ms) as avg_latency
            FROM orbital_inference_logs
            WHERE ts >= $1 AND ts < $2
            GROUP BY edge_node_id
            """,
            baseline_start, start,
        )
        baseline_map = {r["edge_node_id"]: r for r in baseline}

        results: list[DetectionResult] = []
        for row in current:
            node = row["edge_node_id"]
            bl = baseline_map.get(node)
            if not bl or not bl.get("stddev_confidence"):
                continue

            zscore = (
                (row["avg_confidence"] - bl["avg_confidence"])
                / bl["stddev_confidence"]
            )
            latency_increase = row["avg_latency"] - bl.get("avg_latency", 0)
            fail_rate = row.get("fail_rate", 0) or 0

            if (zscore < self.ZSCORE_THRESHOLD
                    or fail_rate > self.PHYSICS_FAIL_RATE_THRESHOLD
                    or latency_increase > self.LATENCY_INCREASE_MS):
                confidence = self._apply_confidence_floor(
                    min(0.95, 0.6 + abs(zscore) / 10.0)
                )
                results.append(DetectionResult(
                    rule_id=self.rule_id,
                    triggered=True,
                    alert_title=f"Adversarial evasion on edge node {node}",
                    alert_severity="Critical",
                    atlas_technique="AML.T0015",
                    threat_model_ref="TM-07",
                    confidence=confidence,
                    evidence={
                        "edge_node_id": node,
                        "z_score": round(zscore, 3),
                        "fail_rate": round(fail_rate, 3),
                        "latency_increase_ms": round(latency_increase, 1),
                    },
                    entities=[{"type": "host", "id": node}],
                    safety_relevant=True,
                ))
        return results


# ===========================================================================
# ATLAS-DETECT-005 — Physics Oracle DoS (TM-14)
# ===========================================================================

class PhysicsOracleDoSRule(DetectionRule):
    """Detect physics oracle denial of service."""

    rule_id = "ATLAS-DETECT-005"
    frequency = timedelta(minutes=5)
    lookback = timedelta(minutes=15)

    ERROR_COUNT_THRESHOLD = 3
    TIMEOUT_COUNT_THRESHOLD = 2
    FAIL_RATE_THRESHOLD = 0.5
    MIN_COUNT_FOR_RATE = 10
    MAX_LATENCY_MS = 10_000

    async def evaluate(self, db: Any, now: datetime | None = None) -> list[DetectionResult]:
        now = now or datetime.now(timezone.utc)
        start = now - self.lookback

        rows = await db.fetch_many(
            """
            SELECT edge_node_id,
                   COUNT(*) as total_checks,
                   SUM(CASE WHEN error_state IS NOT NULL THEN 1 ELSE 0 END) as error_count,
                   SUM(CASE WHEN latency_ms > $3 THEN 1 ELSE 0 END) as timeout_count,
                   SUM(CASE WHEN check_result = 'fail' THEN 1 ELSE 0 END)::float
                       / NULLIF(COUNT(*), 0) as fail_rate,
                   MAX(latency_ms) as max_latency
            FROM orbital_physics_oracle
            WHERE ts >= $1 AND ts < $2
            GROUP BY edge_node_id
            """,
            start, now, self.MAX_LATENCY_MS,
        )

        results: list[DetectionResult] = []
        for row in rows:
            node = row["edge_node_id"]
            triggered = (
                row["error_count"] > self.ERROR_COUNT_THRESHOLD
                or row["timeout_count"] > self.TIMEOUT_COUNT_THRESHOLD
                or (row.get("fail_rate", 0) and row["fail_rate"] > self.FAIL_RATE_THRESHOLD
                    and row["total_checks"] > self.MIN_COUNT_FOR_RATE)
                or row["total_checks"] == 0
                or (row.get("max_latency") and row["max_latency"] > self.MAX_LATENCY_MS)
            )

            if triggered:
                confidence = self._apply_confidence_floor(0.9)
                results.append(DetectionResult(
                    rule_id=self.rule_id,
                    triggered=True,
                    alert_title=f"Physics oracle DoS on edge node {node}",
                    alert_severity="Critical",
                    atlas_technique="AML.T0029",
                    attack_technique="T1499",
                    threat_model_ref="TM-14",
                    confidence=confidence,
                    evidence={
                        "edge_node_id": node,
                        "total_checks": row["total_checks"],
                        "error_count": row["error_count"],
                        "timeout_count": row["timeout_count"],
                        "fail_rate": round(row.get("fail_rate", 0) or 0, 3),
                        "max_latency_ms": row.get("max_latency", 0),
                    },
                    entities=[{"type": "host", "id": node}],
                    requires_immediate_action=True,
                    safety_relevant=True,
                ))
        return results


# ===========================================================================
# ATLAS-DETECT-006 — Supply Chain Compromise (TM-05)
# ===========================================================================

class SupplyChainRule(DetectionRule):
    """Detect supply chain compromise via CI/CD and model registry."""

    rule_id = "ATLAS-DETECT-006"
    frequency = timedelta(hours=1)
    lookback = timedelta(hours=24)

    async def evaluate(self, db: Any, now: datetime | None = None) -> list[DetectionResult]:
        now = now or datetime.now(timezone.utc)
        start = now - self.lookback

        # Check for unapproved model promotions
        promotions = await db.fetch_many(
            """
            SELECT user_id, model_name, model_version, stage, approved_by
            FROM model_registry
            WHERE ts >= $1 AND ts < $2
              AND action = 'stage_transition'
              AND stage = 'Production'
              AND (approved_by IS NULL OR approved_by = '')
            """,
            start, now,
        )

        # Check for dependency changes without passing tests
        dep_changes = await db.fetch_many(
            """
            SELECT pipeline_id, commit_hash, dependency_changes, deployer
            FROM cicd_audit
            WHERE ts >= $1 AND ts < $2
              AND dependency_changes IS NOT NULL
              AND dependency_changes != ''
              AND tests_passed = 0
            """,
            start, now,
        )

        results: list[DetectionResult] = []
        for row in promotions:
            results.append(DetectionResult(
                rule_id=self.rule_id,
                triggered=True,
                alert_title=f"Unapproved model promotion: {row['model_name']} v{row['model_version']}",
                alert_severity="High",
                atlas_technique="AML.T0010",
                attack_technique="T1195",
                threat_model_ref="TM-05",
                confidence=0.85,
                evidence={
                    "user_id": row["user_id"],
                    "model_name": row["model_name"],
                    "model_version": row["model_version"],
                    "approved_by": row.get("approved_by", ""),
                },
                entities=[{"type": "user", "id": row["user_id"]}],
            ))

        for row in dep_changes:
            results.append(DetectionResult(
                rule_id=self.rule_id,
                triggered=True,
                alert_title=f"Dependency change without tests: pipeline {row['pipeline_id']}",
                alert_severity="High",
                atlas_technique="AML.T0018",
                attack_technique="T1195",
                threat_model_ref="TM-05",
                confidence=0.8,
                evidence={
                    "pipeline_id": row["pipeline_id"],
                    "commit_hash": row["commit_hash"],
                    "dependency_changes": row["dependency_changes"],
                    "deployer": row.get("deployer", ""),
                },
                entities=[{"type": "user", "id": row.get("deployer", "")}],
            ))
        return results


# ===========================================================================
# ATLAS-DETECT-007 — Insider Exfiltration (TM-11)
# ===========================================================================

class InsiderExfiltrationRule(DetectionRule):
    """Detect insider IP theft via anomalous API access patterns."""

    rule_id = "ATLAS-DETECT-007"
    frequency = timedelta(hours=1)
    lookback = timedelta(hours=24)

    DEVIATION_THRESHOLD = 5.0
    DISTINCT_RESOURCES_THRESHOLD = 3
    AFTER_HOURS_THRESHOLD = 5
    BASELINE_DAYS = 30

    async def evaluate(self, db: Any, now: datetime | None = None) -> list[DetectionResult]:
        now = now or datetime.now(timezone.utc)
        start = now - self.lookback
        baseline_start = now - timedelta(days=self.BASELINE_DAYS)

        current = await db.fetch_many(
            """
            SELECT caller_identity, COUNT(*) as cnt,
                   COUNT(DISTINCT endpoint) as distinct_endpoints,
                   SUM(CASE WHEN EXTRACT(HOUR FROM ts) < 6
                             OR EXTRACT(HOUR FROM ts) > 22 THEN 1 ELSE 0 END) as after_hours
            FROM orbital_api_logs
            WHERE ts >= $1 AND ts < $2
            GROUP BY caller_identity
            """,
            start, now,
        )

        baseline = await db.fetch_many(
            """
            SELECT caller_identity, COUNT(*) / 30.0 as avg_daily
            FROM orbital_api_logs
            WHERE ts >= $1 AND ts < $2
            GROUP BY caller_identity
            """,
            baseline_start, start,
        )
        baseline_map = {r["caller_identity"]: r["avg_daily"] for r in baseline}

        results: list[DetectionResult] = []
        for row in current:
            identity = row["caller_identity"]
            avg = baseline_map.get(identity, 0)
            deviation = row["cnt"] / avg if avg > 0 else row["cnt"]

            if (deviation > self.DEVIATION_THRESHOLD
                    or row["distinct_endpoints"] > self.DISTINCT_RESOURCES_THRESHOLD
                    or row["after_hours"] > self.AFTER_HOURS_THRESHOLD):
                confidence = min(0.95, 0.5 + deviation / 20.0)
                results.append(DetectionResult(
                    rule_id=self.rule_id,
                    triggered=True,
                    alert_title=f"Insider exfiltration: anomalous API access by {identity}",
                    alert_severity="High",
                    atlas_technique="AML.T0035.002",
                    attack_technique="T1567",
                    threat_model_ref="TM-11",
                    confidence=confidence,
                    evidence={
                        "caller_identity": identity,
                        "count": row["cnt"],
                        "distinct_endpoints": row["distinct_endpoints"],
                        "after_hours": row["after_hours"],
                        "deviation_factor": round(deviation, 2),
                    },
                    entities=[{"type": "user", "id": identity}],
                ))
        return results


# ===========================================================================
# ATLAS-DETECT-008 — Alert Fatigue (TM-17)
# ===========================================================================

class AlertFatigueRule(DetectionRule):
    """Meta-alert: detect alert flooding targeting ALUSKORT itself."""

    rule_id = "ATLAS-DETECT-008"
    frequency = timedelta(hours=1)
    lookback = timedelta(hours=6)

    SPIKE_RATIO_THRESHOLD = 5.0
    BASELINE_DAYS = 7

    async def evaluate(self, db: Any, now: datetime | None = None) -> list[DetectionResult]:
        now = now or datetime.now(timezone.utc)
        start = now - self.lookback
        baseline_start = now - timedelta(days=self.BASELINE_DAYS)

        current_row = await db.fetch_one(
            """
            SELECT COUNT(*) as alert_count
            FROM investigations
            WHERE created_at >= $1 AND created_at < $2
            """,
            start, now,
        )
        current_count = current_row["alert_count"] if current_row else 0

        baseline_row = await db.fetch_one(
            """
            SELECT COUNT(*) / ($3 * 24.0 / 6.0) as avg_6h_count
            FROM investigations
            WHERE created_at >= $1 AND created_at < $2
            """,
            baseline_start, start, self.BASELINE_DAYS,
        )
        baseline_avg = baseline_row["avg_6h_count"] if baseline_row else 0

        if baseline_avg > 0:
            spike_ratio = current_count / baseline_avg
        else:
            spike_ratio = current_count

        results: list[DetectionResult] = []
        if spike_ratio > self.SPIKE_RATIO_THRESHOLD:
            results.append(DetectionResult(
                rule_id=self.rule_id,
                triggered=True,
                alert_title="Alert fatigue: abnormal alert volume spike detected",
                alert_severity="High",
                atlas_technique="AML.T0015",
                threat_model_ref="TM-17",
                confidence=min(0.9, 0.5 + spike_ratio / 20.0),
                evidence={
                    "current_count": current_count,
                    "baseline_avg": round(baseline_avg, 2),
                    "spike_ratio": round(spike_ratio, 2),
                },
            ))
        return results


# ===========================================================================
# ATLAS-DETECT-009 — Sensor Spoofing (TM-06)
# ===========================================================================

class SensorSpoofingRule(DetectionRule):
    """Detect OPC-UA sensor data manipulation."""

    rule_id = "ATLAS-DETECT-009"
    frequency = timedelta(minutes=5)
    lookback = timedelta(minutes=15)

    DATAPOINT_ZSCORE_THRESHOLD = 3.0
    PROTOCOL_VIOLATIONS_THRESHOLD = 0
    SENSOR_DELTA_THRESHOLD = 5
    BASELINE_HOURS = 24

    async def evaluate(self, db: Any, now: datetime | None = None) -> list[DetectionResult]:
        now = now or datetime.now(timezone.utc)
        start = now - self.lookback
        baseline_start = now - timedelta(hours=self.BASELINE_HOURS)

        current = await db.fetch_many(
            """
            SELECT edge_node_id, sensor_count, data_points_received,
                   protocol_violations, connection_state
            FROM opcua_telemetry
            WHERE ts >= $1 AND ts < $2
            """,
            start, now,
        )

        baseline = await db.fetch_many(
            """
            SELECT edge_node_id,
                   AVG(data_points_received) as avg_points,
                   STDDEV(data_points_received) as stddev_points,
                   AVG(sensor_count) as avg_sensors
            FROM opcua_telemetry
            WHERE ts >= $1 AND ts < $2
            GROUP BY edge_node_id
            """,
            baseline_start, start,
        )
        baseline_map = {r["edge_node_id"]: r for r in baseline}

        results: list[DetectionResult] = []
        for row in current:
            node = row["edge_node_id"]
            bl = baseline_map.get(node)

            violations = row.get("protocol_violations", 0) or 0
            sensor_delta = 0
            zscore = 0.0

            if bl and bl.get("stddev_points") and bl["stddev_points"] > 0:
                zscore = abs(
                    (row["data_points_received"] - bl["avg_points"])
                    / bl["stddev_points"]
                )
                sensor_delta = abs(row["sensor_count"] - (bl.get("avg_sensors", 0) or 0))

            if (zscore > self.DATAPOINT_ZSCORE_THRESHOLD
                    or violations > self.PROTOCOL_VIOLATIONS_THRESHOLD
                    or sensor_delta > self.SENSOR_DELTA_THRESHOLD):
                confidence = self._apply_confidence_floor(0.85)
                results.append(DetectionResult(
                    rule_id=self.rule_id,
                    triggered=True,
                    alert_title=f"Sensor spoofing detected on {node}",
                    alert_severity="Critical",
                    atlas_technique="AML.T0043",
                    attack_technique="T1565.002",
                    threat_model_ref="TM-06",
                    confidence=confidence,
                    evidence={
                        "edge_node_id": node,
                        "z_score": round(zscore, 3),
                        "protocol_violations": violations,
                        "sensor_delta": sensor_delta,
                    },
                    entities=[{"type": "host", "id": node}],
                    requires_immediate_action=True,
                    safety_relevant=True,
                ))
        return results


# ===========================================================================
# ATLAS-DETECT-010 — Partner Compromise (TM-08)
# ===========================================================================

class PartnerCompromiseRule(DetectionRule):
    """Detect compromised partner API integrations."""

    rule_id = "ATLAS-DETECT-010"
    frequency = timedelta(minutes=30)
    lookback = timedelta(hours=6)

    VOLUME_DEVIATION_THRESHOLD = 3.0
    PAYLOAD_ZSCORE_THRESHOLD = 3.0
    BASELINE_DAYS = 7

    async def evaluate(self, db: Any, now: datetime | None = None) -> list[DetectionResult]:
        now = now or datetime.now(timezone.utc)
        start = now - self.lookback
        baseline_start = now - timedelta(days=self.BASELINE_DAYS)

        current = await db.fetch_many(
            """
            SELECT partner_id, partner_name,
                   COUNT(*) as call_count,
                   AVG(payload_size) as avg_payload,
                   SUM(CASE WHEN mtls_verified = false THEN 1 ELSE 0 END) as mtls_failures
            FROM partner_api_logs
            WHERE ts >= $1 AND ts < $2
            GROUP BY partner_id, partner_name
            """,
            start, now,
        )

        baseline = await db.fetch_many(
            """
            SELECT partner_id,
                   COUNT(*) / ($3 * 24.0 / 6.0) as avg_6h_calls,
                   AVG(payload_size) as avg_payload,
                   STDDEV(payload_size) as stddev_payload
            FROM partner_api_logs
            WHERE ts >= $1 AND ts < $2
            GROUP BY partner_id
            """,
            baseline_start, start, self.BASELINE_DAYS,
        )
        baseline_map = {r["partner_id"]: r for r in baseline}

        results: list[DetectionResult] = []
        for row in current:
            pid = row["partner_id"]
            bl = baseline_map.get(pid)

            vol_dev = 0.0
            payload_z = 0.0
            if bl:
                avg_calls = bl.get("avg_6h_calls", 0) or 0
                vol_dev = row["call_count"] / avg_calls if avg_calls > 0 else row["call_count"]
                stddev = bl.get("stddev_payload", 0) or 0
                if stddev > 0:
                    payload_z = abs(
                        (row["avg_payload"] - bl["avg_payload"]) / stddev
                    )

            mtls_failures = row.get("mtls_failures", 0) or 0

            if (vol_dev > self.VOLUME_DEVIATION_THRESHOLD
                    or payload_z > self.PAYLOAD_ZSCORE_THRESHOLD
                    or mtls_failures > 0):
                confidence = min(0.9, 0.6 + vol_dev / 10.0)
                results.append(DetectionResult(
                    rule_id=self.rule_id,
                    triggered=True,
                    alert_title=f"Partner compromise: anomalous activity from {row['partner_name']}",
                    alert_severity="High",
                    atlas_technique="AML.T0043",
                    attack_technique="T1199",
                    threat_model_ref="TM-08",
                    confidence=confidence,
                    evidence={
                        "partner_id": pid,
                        "partner_name": row["partner_name"],
                        "volume_deviation": round(vol_dev, 2),
                        "payload_z_score": round(payload_z, 2),
                        "mtls_failures": mtls_failures,
                    },
                    entities=[{"type": "account", "id": pid}],
                ))
        return results


# ===========================================================================
# Registry
# ===========================================================================

ALL_RULES: list[type[DetectionRule]] = [
    TrainingDataPoisoningRule,
    ModelExtractionRule,
    PromptInjectionRule,
    AdversarialEvasionRule,
    PhysicsOracleDoSRule,
    SupplyChainRule,
    InsiderExfiltrationRule,
    AlertFatigueRule,
    SensorSpoofingRule,
    PartnerCompromiseRule,
]
