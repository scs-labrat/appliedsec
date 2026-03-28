# ATLAS / Adversarial AI

## MITRE ATLAS Framework Overview

MITRE ATLAS (Adversarial Threat Landscape for AI Systems) is a knowledge base of adversarial techniques targeting machine learning systems. It complements the MITRE ATT&CK framework by covering AI-specific threats such as model poisoning, evasion attacks, model extraction, and prompt injection.

ALUSKORT integrates ATLAS into the SOC investigation pipeline through:
1. **Detection rules** that identify adversarial AI activity in telemetry data
2. **ATLAS Mapper agent** that correlates investigation entities with ATLAS techniques
3. **Dashboard views** for monitoring adversarial AI threats
4. **CTEM integration** for AI/ML vulnerability management (Garak, ART)

---

## ATLAS Techniques Covered

| ATLAS ID | Technique Name | Threat Model Ref | Severity | Description |
|----------|---------------|-------------------|----------|-------------|
| AML.T0020 | Training Data Poisoning | TM-01 | High | Manipulation of training data to introduce backdoors or degrade model performance |
| AML.T0015 | Adversarial Evasion | TM-07 | Critical | Crafting inputs to cause models to misclassify or make incorrect predictions |
| AML.T0044 | Model Extraction | TM-12 | High | Systematic querying to reconstruct or approximate a target model |
| AML.T0051 | Prompt Injection | TM-10 | High | Injecting malicious instructions into LLM prompts to override system behaviour |
| AML.T0043 | Sensor Spoofing | TM-06 | Critical | Manipulating physical or digital sensors to feed false data to AI models |
| AML.T0040 | Edge Node Compromise | TM-04 | Critical | Compromising edge inference nodes to tamper with model weights or outputs |

---

## Detection Rules

### ATLAS-DETECT-001: Training Data Poisoning

| Property | Value |
|----------|-------|
| **ATLAS Technique** | AML.T0020 |
| **ATT&CK Technique** | T1565.001 (Data Manipulation) |
| **Threat Model** | TM-01 |
| **Frequency** | Every 1 hour |
| **Lookback** | 24 hours |
| **Data Source** | `databricks_audit` |
| **Severity** | High |

**Detection Logic**: Identifies anomalous Databricks activity indicating potential data poisoning:
- Suspicious actions: `deltaDMLEvent`, `deltaTableWrite`, `notebookRun`, `clusterCreate`
- Deviation factor > 3.0x baseline (30-day average)
- Distinct tables accessed > 5
- Daily action count > 50

**Confidence**: `min(0.95, 0.5 + deviation / 20.0)`

---

### ATLAS-DETECT-002: Model Extraction

| Property | Value |
|----------|-------|
| **ATLAS Technique** | AML.T0044.001 |
| **ATT&CK Technique** | T1530 (Data from Cloud Storage) |
| **Threat Model** | TM-12 |
| **Frequency** | Every 30 minutes |
| **Lookback** | 6 hours |
| **Data Source** | `orbital_nl_query_logs` |
| **Severity** | High |

**Detection Logic**: Detects systematic query patterns indicating model extraction:
- Query count threshold > 100 queries in lookback period
- Median inter-query gap analysis

**Confidence**: `min(0.9, 0.6 + query_count / 1000.0)`

---

### ATLAS-DETECT-003: LLM Prompt Injection

| Property | Value |
|----------|-------|
| **ATLAS Technique** | AML.T0051 |
| **Threat Model** | TM-10 |
| **Frequency** | Every 15 minutes |
| **Lookback** | 1 hour |
| **Data Source** | `orbital_nl_query_logs` |
| **Severity** | High |

**Detection Logic**: Identifies prompt injection attempts via safety filter triggers:
- Queries where `safety_filter_triggered = true`
- Each triggered query generates a detection result

**Confidence**: Fixed at 0.85

---

### ATLAS-DETECT-004: Adversarial Evasion

| Property | Value |
|----------|-------|
| **ATLAS Technique** | AML.T0015 |
| **Threat Model** | TM-07 |
| **Frequency** | Every 15 minutes |
| **Lookback** | 1 hour |
| **Data Source** | `orbital_inference_logs` |
| **Severity** | Critical |
| **Safety Relevant** | Yes |

**Detection Logic**: Detects adversarial evasion via statistical analysis:
- Confidence Z-score < -2.0 (significant drop from 7-day baseline)
- Physics check failure rate > 10%
- Inference latency increase > 500ms above baseline

**Confidence**: `min(0.95, 0.6 + abs(zscore) / 10.0)` with confidence floor applied

---

### ATLAS-DETECT-005: Physics Oracle DoS

| Property | Value |
|----------|-------|
| **ATLAS Technique** | AML.T0029 |
| **ATT&CK Technique** | T1499 (Endpoint DoS) |
| **Threat Model** | TM-14 |
| **Frequency** | Every 5 minutes |
| **Lookback** | 15 minutes |
| **Data Source** | `orbital_physics_oracle` |
| **Severity** | Critical |
| **Safety Relevant** | Yes |
| **Immediate Action** | Yes |

**Detection Logic**: Detects physics oracle denial of service:
- Error count > 3
- Timeout count > 2
- Failure rate > 50% (with minimum 10 checks)
- Zero checks (oracle completely down)
- Max latency > 10,000ms

**Confidence**: 0.9 with confidence floor

---

### ATLAS-DETECT-006: Supply Chain Compromise

| Property | Value |
|----------|-------|
| **ATLAS Technique** | AML.T0010, AML.T0018 |
| **ATT&CK Technique** | T1195 (Supply Chain Compromise) |
| **Threat Model** | TM-05 |
| **Frequency** | Every 1 hour |
| **Lookback** | 24 hours |
| **Data Sources** | `model_registry`, `cicd_audit` |
| **Severity** | High |

**Detection Logic**: Two sub-detections:
1. **Unapproved model promotions**: Models promoted to Production without `approved_by` set
2. **Dependency changes without tests**: CI/CD pipeline deployments with dependency changes where `tests_passed = 0`

**Confidence**: 0.85 (model promotion), 0.80 (dependency change)

---

### ATLAS-DETECT-007: Insider Exfiltration

| Property | Value |
|----------|-------|
| **ATLAS Technique** | AML.T0035.002 |
| **ATT&CK Technique** | T1567 (Exfiltration Over Web Service) |
| **Threat Model** | TM-11 |
| **Frequency** | Every 1 hour |
| **Lookback** | 24 hours |
| **Data Source** | `orbital_api_logs` |
| **Severity** | High |

**Detection Logic**: Detects insider IP theft via anomalous API access:
- Access volume deviation > 5.0x baseline (30-day average)
- Distinct endpoints accessed > 3
- After-hours access count > 5 (before 06:00 or after 22:00)

**Confidence**: `min(0.95, 0.5 + deviation / 20.0)`

---

### ATLAS-DETECT-008: Alert Fatigue

| Property | Value |
|----------|-------|
| **ATLAS Technique** | AML.T0015 |
| **Threat Model** | TM-17 |
| **Frequency** | Every 1 hour |
| **Lookback** | 6 hours |
| **Data Source** | `investigations` |
| **Severity** | High |

**Detection Logic**: Meta-alert detecting alert flooding targeting ALUSKORT itself:
- Current alert volume compared to 7-day baseline
- Spike ratio threshold > 5.0x average

**Confidence**: `min(0.9, 0.5 + spike_ratio / 20.0)`

---

### ATLAS-DETECT-009: Sensor Spoofing

| Property | Value |
|----------|-------|
| **ATLAS Technique** | AML.T0043 |
| **ATT&CK Technique** | T1565.002 (Transmitted Data Manipulation) |
| **Threat Model** | TM-06 |
| **Frequency** | Every 5 minutes |
| **Lookback** | 15 minutes |
| **Data Source** | `opcua_telemetry` |
| **Severity** | Critical |
| **Safety Relevant** | Yes |
| **Immediate Action** | Yes |

**Detection Logic**: Detects OPC-UA sensor data manipulation:
- Data point Z-score > 3.0 (against 24-hour baseline)
- Protocol violations > 0
- Sensor count delta > 5

**Trust Model**: Applies trust downgrade for OPC-UA telemetry with confidence floor re-applied. Attestation status set to `unavailable`.

---

### ATLAS-DETECT-010: Partner Compromise

| Property | Value |
|----------|-------|
| **ATLAS Technique** | AML.T0043 |
| **ATT&CK Technique** | T1199 (Trusted Relationship) |
| **Threat Model** | TM-08 |
| **Frequency** | Every 30 minutes |
| **Lookback** | 6 hours |
| **Data Source** | `partner_api_logs` |
| **Severity** | High |

**Detection Logic**: Detects compromised partner API integrations:
- Volume deviation > 3.0x baseline (7-day average)
- Payload size Z-score > 3.0
- Any mTLS verification failures

---

### ATLAS-DETECT-011: Edge Node Compromise

| Property | Value |
|----------|-------|
| **ATLAS Technique** | AML.T0040 |
| **ATT&CK Technique** | T1195.002 (Compromise Software Supply Chain) |
| **Threat Model** | TM-04 |
| **Frequency** | Every 5 minutes |
| **Lookback** | 15 minutes |
| **Data Source** | `edge_node_telemetry` |
| **Severity** | Critical |
| **Immediate Action** | Yes |

**Detection Logic**: Detects compromised edge nodes:
- Boot attestation failure or unavailable
- Disk integrity check failure
- CPU utilisation > 95%
- Memory utilisation > 95%

**Trust Model**: Applies trust downgrade for edge node telemetry with confidence floor. Attestation status from boot attestation value.

---

## Statistical Thresholds Summary

| Rule | Key Thresholds |
|------|---------------|
| DETECT-001 | Deviation > 3.0x, Distinct tables > 5, Daily count > 50 |
| DETECT-002 | Query count > 100, Median gap < 500ms |
| DETECT-003 | safety_filter_triggered = true |
| DETECT-004 | Z-score < -2.0, Fail rate > 10%, Latency increase > 500ms |
| DETECT-005 | Errors > 3, Timeouts > 2, Fail rate > 50%, Max latency > 10s |
| DETECT-006 | Unapproved promotion, Dep changes with failed tests |
| DETECT-007 | Deviation > 5.0x, Distinct endpoints > 3, After-hours > 5 |
| DETECT-008 | Spike ratio > 5.0x |
| DETECT-009 | Z-score > 3.0, Protocol violations > 0, Sensor delta > 5 |
| DETECT-010 | Volume deviation > 3.0x, Payload Z-score > 3.0, mTLS failures |
| DETECT-011 | Attestation fail, Disk fail, CPU > 95%, Memory > 95% |

---

## Model Registry and Inference Logging

ATLAS detection rules rely on several telemetry tables:

| Table | Source | Key Fields |
|-------|--------|------------|
| `databricks_audit` | Databricks | user_id, action, target_resource, ts |
| `orbital_nl_query_logs` | NL Query API | user_id, session_id, query_text, safety_filter_triggered |
| `orbital_inference_logs` | Model Serving | edge_node_id, confidence_score, inference_latency_ms, physics_check_result |
| `orbital_physics_oracle` | Physics Oracle | edge_node_id, check_result, error_state, latency_ms |
| `model_registry` | MLflow/Registry | model_name, model_version, stage, approved_by |
| `cicd_audit` | CI/CD Pipeline | pipeline_id, commit_hash, dependency_changes, tests_passed |
| `orbital_api_logs` | API Gateway | caller_identity, endpoint, ts |
| `opcua_telemetry` | OPC-UA Gateway | edge_node_id, sensor_count, data_points_received, protocol_violations |
| `partner_api_logs` | Partner APIs | partner_id, partner_name, payload_size, mtls_verified |
| `edge_node_telemetry` | Edge Nodes | edge_node_id, boot_attestation, model_weight_hash, disk_integrity |

---

## Scanning Tools Integration

### Garak

Garak is an LLM vulnerability scanner that probes models for:
- Prompt injection susceptibility
- Jailbreak techniques
- Hallucination triggers
- Data leakage

Results are normalised by the CTEM Normaliser and mapped to ATLAS techniques.

### ART (Adversarial Robustness Toolbox)

IBM's ART framework tests ML models against:
- Evasion attacks (adversarial examples)
- Poisoning attacks (training data manipulation)
- Extraction attacks (model stealing)

Results feed into both CTEM scoring and ATLAS detection correlation.

---

## Dashboard Views

### Adversarial AI Dashboard (`/adversarial-ai`)

The Adversarial AI dashboard provides:

1. **Detection Summary**: Active detections grouped by ATLAS technique
2. **Rule Status**: Health and last-run time for all 11 detection rules
3. **Technique Coverage**: Matrix showing which ATLAS techniques are covered
4. **Trust Assessment**: Distribution of telemetry trust levels (trusted/untrusted)
5. **Timeline**: Chronological view of ATLAS detections
6. **Investigation Correlation**: Investigations linked to ATLAS detections
