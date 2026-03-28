# CTEM Program Integration

## What is CTEM?

Continuous Threat Exposure Management (CTEM) is a systematic approach to continuously identifying, prioritising, validating, and remediating security exposures across an organisation's attack surface. Unlike traditional vulnerability management that focuses on CVSS scores alone, CTEM incorporates:

- **Business context**: What is the real-world consequence of exploiting this exposure?
- **Exploitability**: How easy is it to exploit in the current environment?
- **Validation**: Has the exposure been confirmed exploitable through active testing?
- **Remediation tracking**: Is the fix deployed and verified?

ALUSKORT integrates CTEM into the SOC investigation pipeline, enabling analysts to see not just what alerts fired, but what underlying exposures exist on affected assets and how severe the consequences could be.

---

## CTEM Normaliser Service Architecture

The CTEM Normaliser (`ctem_normaliser/`) is a Kafka consumer service that normalises vulnerability and exposure findings from multiple security scanning tools into a unified `CTEMExposure` schema.

```
+----------+   +----------+   +----------+   +----------+
| Wiz      |   | Snyk     |   | Garak    |   | ART      |
| Findings |   | Findings |   | Results  |   | Results  |
+----+-----+   +----+-----+   +----+-----+   +----+-----+
     |              |              |              |
  ctem.raw.wiz  ctem.raw.snyk  ctem.raw.garak ctem.raw.art
     |              |              |              |
     +-------+------+------+------+------+-------+
             |                            |
      +------v----------------------------v------+
      |          CTEM Normaliser Service          |
      |                                           |
      |  1. Parse source-specific format           |
      |  2. Map asset to Purdue zone               |
      |  3. Determine consequence category          |
      |  4. Compute severity (consequence matrix)   |
      |  5. Calculate CTEM score                    |
      |  6. Set SLA deadline                        |
      |  7. Generate deterministic exposure_key     |
      |  8. Upsert to PostgreSQL                    |
      +---------------------+---------------------+
                            |
                     ctem.normalized (Kafka)
                            |
                     +------v------+
                     | PostgreSQL  |
                     | ctem_       |
                     | exposures   |
                     +-------------+
```

### Source-Specific Normalisers

| Module | Source Tool | Input Format | Key Mappings |
|--------|-----------|--------------|-------------|
| `wiz.py` | Wiz | Wiz vulnerability JSON | Cloud asset ID, severity, remediation guidance |
| `snyk.py` | Snyk | Snyk issue JSON | Package name, CVE, fix version |
| `garak.py` | Garak | LLM probe result JSON | Probe type, model vulnerability, ATLAS technique |
| `art.py` | ART | Adversarial Robustness Toolbox JSON | Attack type, model name, success rate |
| `base.py` | Base class | -- | Common normalisation interface |

---

## Source Integrations

### Wiz

| Property | Value |
|----------|-------|
| **Kafka Topic** | `ctem.raw.wiz` |
| **Finding Types** | Cloud misconfigurations, container vulnerabilities, IaC issues |
| **Asset Mapping** | Cloud resource ID to asset_id, region/VPC to asset_zone |

### Snyk

| Property | Value |
|----------|-------|
| **Kafka Topic** | `ctem.raw.snyk` |
| **Finding Types** | Open source vulnerabilities, license issues, code vulnerabilities |
| **Asset Mapping** | Project/package to asset_id, repository to asset_zone |

### Garak

| Property | Value |
|----------|-------|
| **Kafka Topic** | `ctem.raw.garak` |
| **Finding Types** | LLM prompt injection, jailbreak, hallucination probes |
| **Asset Mapping** | Model endpoint to asset_id, deployment zone to asset_zone |
| **ATLAS Mapping** | Probe type mapped to ATLAS technique IDs |

### ART (Adversarial Robustness Toolbox)

| Property | Value |
|----------|-------|
| **Kafka Topic** | `ctem.raw.art` |
| **Finding Types** | Evasion attacks, poisoning attacks, model extraction |
| **Asset Mapping** | Model name to asset_id, training pipeline to asset_zone |
| **ATLAS Mapping** | Attack type mapped to ATLAS technique IDs |

---

## Consequence-Weighted Severity Matrix

ALUSKORT replaces standard CVSS-only severity with a two-dimensional matrix that considers both exploitability and physical consequence.

### Severity Matrix

| | safety_life | equipment | downtime | data_loss |
|---|:-----------:|:---------:|:--------:|:---------:|
| **high** exploitability | CRITICAL | CRITICAL | HIGH | MEDIUM |
| **medium** exploitability | CRITICAL | HIGH | MEDIUM | LOW |
| **low** exploitability | HIGH | MEDIUM | LOW | LOW |

### Consequence Weights

| Consequence Category | Weight | Description |
|---------------------|--------|-------------|
| `safety_life` | 1.0 | Risk to human safety or life |
| `equipment` | 0.8 | Risk of equipment damage or destruction |
| `downtime` | 0.5 | Risk of operational downtime |
| `data_loss` | 0.3 | Risk of data breach or loss |

### CTEM Score Computation

```
ctem_score = exploitability_score * consequence_weight * 10
```

Where:
- `exploitability_score` is 0.0-1.0 (from the scanner)
- `consequence_weight` is from the table above
- Result is 0.0-10.0

Example: An easily exploitable (0.9) vulnerability on a safety-critical system:
```
ctem_score = 0.9 * 1.0 * 10 = 9.0
```

---

## Purdue Model Zones and Zone-Consequence Mapping

ALUSKORT maps every asset to a Purdue model zone, and each zone has a default consequence category.

### Zone Mapping

| Zone | Examples | Consequence |
|------|----------|-------------|
| **Zone 0 -- Physical Process** | Physical process equipment, safety systems, field devices | `safety_life` |
| **Zone 1 -- Basic Control** | Edge inference nodes, PLCs, sensor networks | `equipment` |
| **Zone 2 -- Area Supervisory** | SCADA, HMI, operations systems | `downtime` |
| **Zone 3 -- Site Operations** | Enterprise IT, manufacturing systems | `downtime` |
| **Zone 3.5 -- DMZ** | Demilitarised zone between IT and OT | `data_loss` |
| **Zone 4 -- Enterprise** | Corporate IT, cloud infrastructure | `data_loss` |
| **Zone 5 -- Internet** | External-facing systems | `data_loss` |

### Comprehensive Zone-Consequence Fallback Map

| Zone Key | Consequence |
|----------|-------------|
| `Zone0_PhysicalProcess` | safety_life |
| `Zone0_Safety` | safety_life |
| `Zone0_FieldDevices` | safety_life |
| `Zone1_EdgeInference` | equipment |
| `Zone1_BasicControl` | equipment |
| `Zone1_SensorNetwork` | equipment |
| `Zone1_PLCNetwork` | equipment |
| `Zone2_Operations` | downtime |
| `Zone2_AreaSupervisory` | downtime |
| `Zone2_SCADA` | downtime |
| `Zone2_HMI` | downtime |
| `Zone3_Enterprise` | data_loss |
| `Zone3_SiteOperations` | downtime |
| `Zone3_Manufacturing` | downtime |
| `Zone3_5_DMZ` | data_loss |
| `Zone4_External` | data_loss |
| `Zone4_Corporate` | data_loss |
| `Zone4_Cloud` | data_loss |
| `Zone5_Internet` | data_loss |
| `Cloud_Production` | downtime |
| `Cloud_Staging` | data_loss |
| `Cloud_Development` | data_loss |
| `Cloud_Management` | downtime |
| `IT_DataCenter` | downtime |
| `IT_UserWorkstations` | data_loss |
| `IT_NetworkInfra` | downtime |
| `OT_FieldBus` | equipment |
| `OT_ControlNetwork` | equipment |
| `OT_ProcessNetwork` | safety_life |
| `OT_SafetyInstrumentedSystem` | safety_life |

**Default for unknown zones**: `data_loss` (least severe, avoids false negatives)

---

## SLA Deadline Computation

SLA deadlines are automatically computed based on the consequence-weighted severity:

| Severity | SLA Deadline | Hours |
|----------|-------------|-------|
| CRITICAL | 24 hours | 24 |
| HIGH | 3 days | 72 |
| MEDIUM | 14 days | 336 |
| LOW | 30 days | 720 |

The `compute_sla_deadline()` function returns an ISO 8601 timestamp computed from the current time plus the SLA hours.

---

## Dashboard Views

### CTEM Exposure Dashboard

The CTEM dashboard (`/ctem`) provides:

1. **Exposure Summary**: Total open exposures by severity
2. **SLA Status**: Exposures approaching or past SLA deadline
3. **Zone Heatmap**: Exposure density across Purdue model zones
4. **Top Assets**: Assets with the most critical exposures
5. **Trend Charts**: Exposure count over time

### Investigation Detail -- CTEM Panel

When viewing an investigation, the CTEM panel shows:
- All CTEM exposures matched to investigation entities
- Severity, CTEM score, and SLA deadline for each
- Asset zone and consequence category
- Remediation status (Open, InProgress, Verified)
- Links to the full exposure record

---

## Remediation Tracking

### Remediation Lifecycle

```
Open --> Assigned --> InProgress --> FixDeployed --> Verified --> Closed
                                         |
                                    SLA Breached? --> Escalation
```

### Database Tables

| Table | Purpose |
|-------|---------|
| `ctem_exposures` | Master exposure records with severity and SLA |
| `ctem_validations` | Validation campaign results (exploitable? detection evaded?) |
| `ctem_remediations` | Remediation assignment, SLA tracking, verification |

### SLA Breach Handling

When an exposure's SLA deadline passes without remediation:
- `sla_breached` flag set to `true`
- Escalation level incremented
- Prometheus alert `AluskortBatchSLABreach` fires
- Dashboard highlights overdue exposures in the CTEM view
