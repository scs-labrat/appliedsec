# Dashboard User Guide

## Overview

The ALUSKORT Analyst Dashboard is a server-rendered web application built with FastAPI, HTMX, Jinja2, and Tailwind CSS. It provides SOC analysts and executives with comprehensive views of investigations, approvals, threat exposure, system health, and operational metrics.

**Access**: `http://localhost:8080` (development) or via ALB/Ingress (production)

---

## Navigation

The dashboard provides 20 pages organised into four navigation groups via dropdown menus:

### Top-Level Pages

| # | Section | Path | Description |
|---|---------|------|-------------|
| 1 | CISO Executive | `/ciso` | Executive dashboard with KPIs, interactive charts, click-to-expand |
| 2 | Overview | `/overview` | Operational metrics summary |
| 3 | Investigations | `/investigations` | Investigation list with filtering, sorting, WebSocket updates |
| 4 | Approvals | `/approvals` | Queue of investigations awaiting analyst approval |

### Threat Intel (Dropdown)

| # | Section | Path | Description |
|---|---------|------|-------------|
| 5 | CTEM Exposures | `/ctem` | Continuous Threat Exposure Management dashboard |
| 6 | CTI / IOC Feeds | `/cti` | Cyber Threat Intelligence feeds and IOC data |
| 7 | Adversarial AI | `/adversarial-ai` | MITRE ATLAS monitoring and detection status |
| 8 | FP Patterns | `/fp-patterns` | False positive pattern library with governance rules |
| 9 | Playbooks | `/playbooks` | Response playbook management (create/edit/delete) |

### Platform (Dropdown)

| # | Section | Path | Description |
|---|---------|------|-------------|
| 10 | LLM Health | `/llm-health` | LLM provider health, latency, error rates, model status |
| 11 | Shadow Mode | `/shadow-mode` | Test rules against live traffic without production impact |
| 12 | Canary Rollout | `/canary` | Progressive rule deployment (shadow → 10% → 25% → 50% → 100%) |
| 13 | Batch Jobs | `/batch-jobs` | Scheduled batch job monitoring and history |
| 14 | Audit Trail | `/audit` | Immutable audit records with filtering and export |
| 15 | Connectors | `/connectors` | SIEM connector management (Sentinel, Elastic, Splunk) |

### Admin (Dropdown)

| # | Section | Path | Description |
|---|---------|------|-------------|
| 16 | Users & Roles | `/users` | User management with RBAC role assignment |
| 17 | Settings | `/settings` | System config, LLM provider/model CRUD, global demo data |
| 18 | Test Harness | `/test-harness` | Synthetic investigation generation for testing |

### Additional Pages

| # | Section | Path | Description |
|---|---------|------|-------------|
| 19 | Investigation Detail | `/investigations/{id}` | Full investigation context in a single pane |
| 20 | Timeline | `/investigations/{id}/timeline` | Investigation event timeline |

---

## 1. CISO Executive Dashboard

**Path**: `/ciso`

The executive dashboard provides C-suite-ready metrics with interactive visualisations.

### KPI Cards (8)

| KPI | Description | Target |
|-----|-------------|--------|
| MTTD | Mean Time to Detect | < 30s |
| MTTR | Mean Time to Respond | < 15m |
| Automation Rate | Percentage of alerts handled without human intervention | > 80% |
| FP Accuracy | False positive classification accuracy | > 98% |
| SLA Compliance | Investigations resolved within SLA | > 95% |
| Investigations (30d) | Total investigations in last 30 days | -- |
| LLM Cost | Total LLM API spend (30d) vs budget | < $400 |
| Risk Score | Composite risk posture score | > 80 |

### Interactive Charts (7)

All charts support **click-to-expand**: clicking any chart opens a full-width modal with:
- **Zoom & pan** — scroll to zoom, drag to select a range
- **Data point inspection** — click any point to see exact values
- **Toggle data points** — show/hide point markers on line charts
- **Data table** — toggle raw data table beneath the chart with row highlighting
- **Export PNG** — download chart as high-resolution image
- **Copy to clipboard** — copy data table as tab-separated values
- **Keyboard**: Escape to close

| # | Chart | Type | Description |
|---|-------|------|-------------|
| 1 | Alert Volume | Line (3 series) | Total alerts, auto-closed, escalated over 30 days |
| 2 | MTTD & MTTR Trend | Dual-axis line | Detection and response time trends over 30 days |
| 3 | Severity Distribution | Doughnut | Open investigations by severity (Critical/High/Medium/Low/Info) |
| 4 | Investigation Outcomes | Doughnut | True positive vs false positive vs escalated (30d) |
| 5 | Top MITRE ATT&CK Tactics | Horizontal bar | Most frequently detected tactics (8 categories) |
| 6 | LLM API Cost | Bar | Daily LLM spend over 30 days |
| 7 | Automation Rate | Line + target | Automation percentage vs target threshold over 30 days |

### Additional Panels

- **SLA Compliance by Severity** — Progress bars showing SLA met percentage for Critical, High, Medium, Low
- **CTEM Exposure Posture** — Severity breakdown with remediation progress and overdue count
- **Adversarial AI Defense** — Injection attempts blocked, ATLAS detections, models monitored
- **30-Day Executive Summary** — Key numbers: auto-closed, escalated, TP/FP, avg cost/alert, CTEM overdue

### JSON API

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/ciso/metrics` | All CISO metrics as JSON (supports auto-refresh) |

---

## 2. Overview Metrics

**Path**: `/overview`

Operational metrics summary including:
- Investigations by state (open, closed, failed, awaiting human)
- Severity breakdown (last 24 hours)
- Mean time to close (7-day rolling average)
- False positive rate
- Active kill switches
- ATLAS detections by trust level

---

## 3. Investigations List

**Path**: `/investigations`

### Columns

| Column | Description |
|--------|-------------|
| Status | Colour-coded badge: `received`, `parsing`, `enriching`, `reasoning`, `awaiting_human`, `responding`, `closed`, `failed` |
| Severity | Critical (red), High (orange), Medium (yellow), Low (blue), Informational (grey) |
| Alert Title | Source alert title from the SIEM |
| Classification | AI-generated classification |
| Confidence | Classification confidence (0-100%) |
| Created | Timestamp |
| Cost | Total LLM cost in USD |

### Features
- **Filtering**: By status, severity, tenant
- **Sorting**: Click column headers
- **Real-time updates**: WebSocket (`/ws/investigations`) + HTMX polling

---

## 4. Approvals Queue

**Path**: `/approvals`

Shows investigations in `AWAITING_HUMAN` state, sorted by severity then age.

### Access Control

| Role | Permission |
|------|-----------|
| `analyst` | View only |
| `senior_analyst` | Approve or reject |
| `admin` | Approve or reject |

### Timeout Behaviour

| Severity | Action |
|----------|--------|
| Critical/High | Escalate (remains in queue) |
| Medium/Low | Auto-close after timeout |

---

## 5–9. Threat Intel Pages

### CTEM Exposures (`/ctem`)
Exposure summary by severity, SLA status, zone heatmap, top vulnerable assets, exposure trend, remediation progress.

### CTI / IOC Feeds (`/cti`)
Active IOCs, threat campaigns, MITRE technique heat map, IOC age distribution, source coverage.

### Adversarial AI (`/adversarial-ai`)
ATLAS detection summary, rule status for all 11 rules, technique coverage matrix, trust assessment, detection timeline.

### FP Patterns (`/fp-patterns`)
False positive pattern library with governance-approved suppression rules, pattern confidence scores, and match statistics.

### Playbooks (`/playbooks`)
Response playbook management with create, edit, and delete functionality. Playbooks are categorised by threat type and linked to MITRE techniques.

---

## 10–15. Platform Pages

### LLM Health (`/llm-health`)
Provider health status, model latency graphs, error rates, token usage, cost breakdown by model.

### Shadow Mode (`/shadow-mode`)
Test new rules against live traffic without affecting production outcomes. Shows shadow vs production comparison metrics.

### Canary Rollout (`/canary`)
Progressive rule deployment with 5 phases: shadow → 10% → 25% → 50% → 100%.

| Feature | Description |
|---------|-------------|
| Promote | Advance a canary slice to the next phase |
| Rollback | Return a slice to shadow mode |
| Create | Add a new canary slice (name, rule family, dimension, value, threshold) |
| Edit | Modify slice configuration inline |
| Delete | Remove a canary slice |
| Auto-rollback | Automatic rollback when success rate drops below threshold (default 95%) |
| History | Full promotion/rollback history with actor and timestamp |

### Batch Jobs (`/batch-jobs`)
Monitor scheduled batch jobs (FP training, retrospective analysis, embedding refresh). View execution history and status.

### Audit Trail (`/audit`)
Browse immutable, chain-verified audit records. Filter by event type, severity, actor, date range. Records include decision, action, approval, security, and system events.

### Connectors (`/connectors`)
Manage SIEM connections for Sentinel, Elastic, and Splunk. Add, edit, pause/resume, delete, and test connectivity.

---

## 16–18. Admin Pages

### Users & Roles (`/users`)
User management with RBAC role assignment (analyst, senior_analyst, admin). Create, edit, enable/disable, and delete user accounts.

### Settings (`/settings`)

Four configuration tabs:

| Tab | Features |
|-----|----------|
| **General** | Log level, kill switches, spend limits, degradation level |
| **LLM Tiers** | Model tier assignments and routing configuration |
| **Spend** | Monthly spend tracking, per-tier and per-tenant breakdown |
| **LLM Providers** | Full CRUD for providers, models, and API keys |

#### LLM Provider Management
- **Add/Edit/Delete providers**: Name, base URL, API key (masked after save)
- **Add/Edit/Delete models**: Model name, tier, context window, token limits, temperature, cost, SLO, tasks, fallback, extended thinking
- **Enable/Disable**: Toggle providers and models on/off
- **Demo data**: Load or clear demo providers/models

#### Global Demo Data Management
- **Load All Demo Data**: Populates all pages (users, LLM providers/models, canary slices, shadow mode, playbooks, batch jobs, investigations)
- **Remove All Demo Data**: Clears all demo data across DB tables and in-memory stores

### Test Harness (`/test-harness`)
Generate synthetic investigation data across 15 scenarios in 5 categories (APT, Ransomware, Insider Threat, Cloud Compromise, Adversarial AI).

---

## Design System

The dashboard uses the **Applied Computing Technologies** design system:

| Element | Value |
|---------|-------|
| Primary font | Montserrat |
| Body font | Figtree |
| Mono font | Fragment Mono |
| Background | `#0e0e0e` |
| Surface | `#131317` |
| Card | `#18181c` |
| Accent (red) | `#e9311a` |
| Success (green) | `#028d5c` |
| Warning (orange) | `#ed6c35` |
| Info (blue) | `#2060df` |
| Charts | Chart.js 4.4.7 + chartjs-plugin-zoom 2.2.0 |
| Interactivity | HTMX 1.9.10 |
