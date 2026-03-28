# ALUSKORT SOC Platform

| | |
|---|---|
| **Project** | ALUSKORT -- Autonomous SOC Investigation Platform |
| **Version** | 1.0.0 |
| **Last Updated** | 2026-03-29 |
| **Classification** | INTERNAL -- Security Operations |

---

## Welcome

ALUSKORT is an AI-augmented Security Operations Centre (SOC) platform that automates alert triage, investigation, and response across traditional IT/OT and adversarial AI threat landscapes. It integrates MITRE ATT&CK, MITRE ATLAS, and Continuous Threat Exposure Management (CTEM) into a unified investigation pipeline powered by tiered LLM reasoning.

---

## Quick Navigation

| # | Page | Description |
|---|------|-------------|
| 01 | [Executive Summary](01-executive-summary.md) | Business case, key metrics, current status |
| 02 | [Architecture Overview](02-architecture-overview.md) | 5-layer architecture, tech stack, data flow |
| 03 | [Service Catalogue](03-service-catalogue.md) | All 9+ services with APIs, dependencies, config |
| 04 | [Investigation Workflow](04-investigation-workflow.md) | State machine, agents, decision chain, HITL gates |
| 05 | [Data Model Reference](05-data-model.md) | SQL tables, Pydantic models, Kafka topics |
| 06 | [LLM Architecture](06-llm-architecture.md) | 4-tier routing, Context Gateway, spend control |
| 07 | [Security Controls](07-security-controls.md) | AuthN/AuthZ, adversarial AI defense, audit trail |
| 08 | [CTEM Program](08-ctem-program.md) | Exposure management, Purdue zones, SLA computation |
| 09 | [ATLAS / Adversarial AI](09-atlas-adversarial-ai.md) | MITRE ATLAS detections, 11 rules, threat model |
| 10 | [Dashboard User Guide](10-dashboard-guide.md) | All 9 dashboard sections, workflow instructions |
| 11 | [Deployment Guide](11-deployment-guide.md) | Docker, K8s, migrations, env vars |
| 12 | [Operations Runbook](12-operations-runbook.md) | Monitoring, troubleshooting, incident response |
| 13 | [API Reference](13-api-reference.md) | REST, WebSocket, Kafka contracts |
| 14 | [Testing Guide](14-testing-guide.md) | Test harness, pytest, security testing |

---

## Status Badges

| Component | Status | Notes |
|-----------|--------|-------|
| Core Pipeline | `ACTIVE` | Entity Parser, Orchestrator, Context Gateway |
| Dashboard | `ACTIVE` | FastAPI + HTMX analyst UI |
| SIEM Adapters | `ACTIVE` | Sentinel, Elastic, Splunk |
| CTEM Normaliser | `ACTIVE` | Wiz, Snyk, Garak, ART integrations |
| ATLAS Detection | `ACTIVE` | 11 detection rules operational |
| Batch Scheduler | `ACTIVE` | FP pattern training, retrospective analysis |
| Audit Service | `ACTIVE` | SHA-256 hash-chain, per-tenant |

---

## Team Contacts

| Role | Name | Contact |
|------|------|---------|
| Platform Lead | _TBD_ | _TBD_ |
| Security Architect | _TBD_ | _TBD_ |
| SOC Lead Analyst | _TBD_ | _TBD_ |
| DevOps / SRE | _TBD_ | _TBD_ |
| On-Call Rotation | _TBD_ | _see PagerDuty schedule_ |

---

## Key Links

| Resource | URL |
|----------|-----|
| Source Repository | `https://github.com/org/aluskort` |
| Dashboard (Dev) | `http://localhost:8080` |
| Context Gateway (Dev) | `http://localhost:8030` |
| LLM Router (Dev) | `http://localhost:8031` |
| Kafka UI (Dev) | `http://localhost:9092` |
| Prometheus Alerts | See `infra/prometheus/alerts.yml` |
