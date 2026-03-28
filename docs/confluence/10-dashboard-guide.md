# Dashboard User Guide

## Overview

The ALUSKORT Analyst Dashboard is a server-rendered web application built with FastAPI, HTMX, and Jinja2. It provides SOC analysts with a comprehensive view of investigations, approvals, threat exposure, and system health.

**Access**: `http://localhost:8080` (development) or via Kubernetes Ingress (production)

---

## Navigation

The dashboard provides 9 primary sections accessible from the navigation bar:

| # | Section | Path | Description |
|---|---------|------|-------------|
| 1 | Investigations | `/investigations` | Investigation list with filtering and sorting |
| 2 | Investigation Detail | `/investigations/{id}` | Full investigation context in a single pane |
| 3 | Approvals | `/approvals` | Queue of investigations awaiting analyst approval |
| 4 | CTEM | `/ctem` | Continuous Threat Exposure Management dashboard |
| 5 | CTI | `/cti` | Cyber Threat Intelligence feeds and IOC data |
| 6 | Adversarial AI | `/adversarial-ai` | MITRE ATLAS monitoring and detection status |
| 7 | Connectors | `/connectors` | SIEM connector management |
| 8 | Settings | `/settings` | System configuration and LLM tier management |
| 9 | Test Harness | `/test-harness` | Demo data generation for testing |

Additionally:
- **Metrics** (`/metrics`): System performance and health metrics
- **Timeline** (`/investigations/{id}/timeline`): Investigation event timeline

---

## 1. Investigations List

**Path**: `/investigations`

### Layout

The investigations list displays all investigations with key summary information in a table format.

### Columns

| Column | Description |
|--------|-------------|
| Status | Visual indicator (colour-coded badge): `received`, `parsing`, `enriching`, `reasoning`, `awaiting_human`, `responding`, `closed`, `failed` |
| Severity | Critical (red), High (orange), Medium (yellow), Low (blue), Informational (grey) |
| Alert Title | Source alert title from the SIEM |
| Classification | AI-generated classification (e.g., "APT lateral movement") |
| Confidence | Classification confidence (0-100%) |
| Created | Timestamp when the investigation was created |
| Cost | Total LLM cost for the investigation in USD |

### Filtering

- **By status**: Filter to specific investigation states
- **By severity**: Filter by severity level
- **By tenant**: Multi-tenant filtering

### Sorting

Click column headers to sort ascending/descending. Default sort: most recent first.

### Real-Time Updates

The investigation list updates in real-time via WebSocket (`/ws/investigations`). New investigations appear at the top, and status changes update automatically via HTMX polling.

---

## 2. Investigation Detail

**Path**: `/investigations/{id}`

The investigation detail page presents all collected evidence and decisions in a single-pane view. This is the primary analyst workspace for reviewing an investigation.

### Panel: Alert Information

| Field | Description |
|-------|-------------|
| Alert ID | Source SIEM alert identifier |
| Source | SIEM name (Sentinel, Elastic, Splunk) |
| Timestamp | Original alert timestamp |
| Title | Alert title |
| Description | Full alert description text |
| Severity | Alert severity level |
| Tactics | MITRE ATT&CK tactics |
| Techniques | MITRE ATT&CK technique IDs |

### Panel: Approval Banner

Displayed only for investigations in `AWAITING_HUMAN` state:
- Prominent banner with investigation classification and confidence
- **Approve** button (green) -- requires `senior_analyst` or `admin` role
- **Reject** button (red) -- requires `senior_analyst` or `admin` role
- Inline investigation summary for quick review

### Panel: Recommended Actions

Ordered list of response actions recommended by the Reasoning Agent:
- Action description
- Target entity
- Risk assessment
- Whether the action requires approval

### Panel: Decision Chain

Chronological list of all decisions made during the investigation:
- Agent name and role
- Action taken
- Reasoning explanation
- Confidence at each step
- Attestation status (for ATLAS detections)
- Timestamps

### Panel: IOC Matches

Indicators of compromise matched against threat intelligence:
- IOC type and value
- Threat intel source
- Confidence score
- Associated campaigns and groups
- First seen / last seen dates

### Panel: CTEM Exposures

CTEM exposures matched to investigation entities:
- Exposure title and severity
- CTEM score
- Asset ID and zone
- Consequence category
- SLA deadline and status
- Remediation guidance

### Panel: Entities

Parsed entities from the alert:
- Entity type (account, host, IP, file, process, URL, etc.)
- Primary value
- Additional properties
- Extraction confidence

### Panel: UEBA Context

User and Entity Behaviour Analytics data:
- Entity risk state (no_baseline, unknown, low, medium, high)
- Risk score
- Data freshness
- Behavioural anomalies

### Panel: Similar Incidents

Historically similar investigations found via Qdrant semantic search:
- Incident ID and title
- Similarity score
- Outcome (true positive, false positive)
- Classification
- Date

### Panel: Playbooks

Matched response playbooks:
- Playbook title and category
- Matched MITRE techniques
- Steps (automated vs. manual)
- Review status (draft, approved)

### Panel: ATLAS Techniques

MITRE ATLAS technique matches:
- ATLAS technique ID and name
- Telemetry trust level (trusted/untrusted)
- Attestation status
- Detection rule that fired
- Evidence summary

### Panel: Scoring

Investigation scoring breakdown:
- Overall confidence score
- Per-agent confidence contributions
- LLM calls made
- Total cost in USD
- Queries executed

---

## 3. Approvals Queue

**Path**: `/approvals`

### Purpose

The approvals queue shows all investigations in `AWAITING_HUMAN` state, sorted by severity (critical first) and then by age (oldest first).

### Workflow

1. Analyst opens the approvals queue
2. Selects an investigation from the list
3. Reviews the inline investigation summary (or clicks through to full detail)
4. Clicks **Approve** to allow the Response Agent to execute recommended actions
5. Or clicks **Reject** to close the investigation without executing actions

### Access Control

- **analyst** role: Can view the queue but cannot approve or reject
- **senior_analyst** role: Can approve or reject investigations
- **admin** role: Can approve or reject investigations

### Timeout Behaviour

| Severity | Timeout Behaviour |
|----------|-------------------|
| Critical | Escalate (remains in queue, emits `approval.escalated`) |
| High | Escalate (remains in queue, emits `approval.escalated`) |
| Medium | Auto-close after timeout |
| Low | Auto-close after timeout |

---

## 4. CTEM Dashboard

**Path**: `/ctem`

See [CTEM Program Integration](08-ctem-program.md) for full details.

### Views

- **Exposure Summary**: Total open exposures by severity (CRITICAL / HIGH / MEDIUM / LOW)
- **SLA Status**: Count of exposures within SLA, approaching SLA, and breached
- **Zone Heatmap**: Exposure density across Purdue model zones
- **Top Vulnerable Assets**: Assets ranked by cumulative CTEM score
- **Exposure Trend**: Chart showing new vs. closed exposures over time
- **Remediation Progress**: Percentage of exposures in each remediation stage

---

## 5. CTI Dashboard

**Path**: `/cti`

### Views

- **Active IOCs**: Recently ingested indicators of compromise with confidence scores
- **Threat Campaigns**: Active campaigns from threat intelligence feeds
- **MITRE Technique Heat Map**: Most frequently observed ATT&CK techniques
- **IOC Age Distribution**: Freshness of threat intelligence data
- **Source Coverage**: Which TI feeds are active and their contribution

---

## 6. Adversarial AI Dashboard

**Path**: `/adversarial-ai`

See [ATLAS / Adversarial AI](09-atlas-adversarial-ai.md) for full details.

### Views

- **Detection Summary**: Active ATLAS detections grouped by technique
- **Rule Status**: Health status for all 11 detection rules
- **Technique Coverage Matrix**: Which ATLAS techniques have active detection rules
- **Trust Assessment**: Telemetry trust level distribution
- **Detection Timeline**: Chronological view of detections
- **Investigation Links**: Investigations correlated with ATLAS detections

---

## 7. Connectors

**Path**: `/connectors`

### Purpose

Manage SIEM connector configurations for Sentinel, Elastic, and Splunk adapters.

### Connector Properties

| Property | Description |
|----------|-------------|
| Connector ID | Unique identifier |
| Type | sentinel, elastic, splunk |
| Status | active, paused, error |
| Configuration | JSON configuration (credentials, endpoints, filters) |
| Last Poll | Timestamp of last successful poll |
| Alert Count | Total alerts ingested |

### Actions

- **Add Connector**: Configure a new SIEM connection
- **Edit Connector**: Modify existing connector settings
- **Pause/Resume**: Temporarily pause alert ingestion
- **Delete Connector**: Remove a connector (admin only)
- **Test Connection**: Verify connectivity to the SIEM

---

## 8. Settings

**Path**: `/settings`

### System Configuration

- **Log Level**: Adjust logging verbosity (DEBUG, INFO, WARNING, ERROR)
- **Kill Switches**: View and manage active kill switches across all 4 dimensions

### LLM Tier Management

- **Model Configuration**: View current model assignments per tier
- **Fallback Status**: Current fallback provider health
- **Degradation Level**: Current system degradation level (full_capability, secondary_active, deterministic_only)

### Spend Tracking

- **Monthly Spend**: Current month's LLM API spend vs. soft limit and hard cap
- **Spend by Tier**: Breakdown of cost by model tier
- **Spend by Tenant**: Per-tenant cost allocation
- **Spend by Task Type**: Cost breakdown by task category

---

## 9. Test Harness

**Path**: `/test-harness`

### Purpose

Generate synthetic investigation data for testing and demonstration. The test harness creates full-fidelity `GraphState` objects that populate every section of the investigation detail page.

### Scenario Categories (5)

| Category | Tag | Description |
|----------|-----|-------------|
| APT / Nation-state | `apt` | Advanced persistent threat scenarios (Cobalt Strike, lateral movement) |
| Ransomware | `ransomware` | Ransomware deployment and encryption scenarios |
| Insider Threat | `insider` | Insider IP theft and data exfiltration scenarios |
| Cloud Compromise | `cloud` | Cloud infrastructure attacks (IAM, key theft) |
| Adversarial AI | `adversarial_ai` | AI/ML-specific attacks (model poisoning, prompt injection) |

### Scenarios (15)

| # | Title | Category | Severity |
|---|-------|----------|----------|
| 1 | Cobalt Strike Beacon -- C2 Callback Detected | APT | Critical |
| 2 | Suspected APT Lateral Movement via PsExec | APT | High |
| 3 | DLL Side-Loading from Suspicious Path | APT | High |
| 4 | Ransomware Pre-Encryption: Volume Shadow Copy Deletion | Ransomware | Critical |
| 5 | Mass File Encryption Detected on File Server | Ransomware | Critical |
| 6 | Ransomware C2 Beacon to Known Infrastructure | Ransomware | High |
| 7 | Unusual Data Transfer to Personal Cloud Storage | Insider | High |
| 8 | Privileged Account Accessing Sensitive Repositories | Insider | Medium |
| 9 | Bulk Download of Customer Database Records | Insider | High |
| 10 | AWS Root Account API Key Used from Unknown IP | Cloud | Critical |
| 11 | Azure AD Conditional Access Policy Disabled | Cloud | High |
| 12 | GCP Service Account Key Exported | Cloud | Medium |
| 13 | ML Model Training Data Poisoning Attempt | Adversarial AI | High |
| 14 | LLM Prompt Injection via Customer Support Channel | Adversarial AI | High |
| 15 | Edge Node Inference Model Tampering | Adversarial AI | Critical |

### Usage

1. Navigate to `/test-harness`
2. Select scenario category or individual scenarios
3. Click "Generate" to create investigations
4. Investigations appear immediately in the investigations list
5. Full detail pages are populated with realistic data
