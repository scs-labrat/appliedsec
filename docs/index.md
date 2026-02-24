# ALUSKORT — Documentation Index

**Project:** ALUSKORT - Cloud-Neutral Security Reasoning Control Plane
**Version:** 0.1.0
**Last Updated:** 2026-02-21

---

## Project Overview

- **Type:** Monolith repository, microservice deployment
- **Primary Language:** Python >=3.12 (async throughout)
- **Architecture:** Event-driven microservices with polyglot persistence

### Quick Reference

- **Tech Stack:** Python 3.12, Pydantic v2, asyncpg/PostgreSQL 16, Redis 7, Qdrant, Neo4j 5, Kafka/Redpanda, Anthropic Claude, MinIO
- **Services:** 8 deployable + 1 audit service + shared libraries
- **Message Bus:** Kafka (Redpanda) — 31 topics
- **Auth:** OIDC (external) + mTLS (inter-service)
- **Deployment:** Docker Compose (dev) / Kubernetes (prod) / GHCR
- **Tests:** 91 files, 90% coverage gate
- **CI/CD:** GitHub Actions

---

## Generated Documentation

| Document | Description |
|----------|-------------|
| [Project Overview](./project-overview.md) | Quick reference, architecture diagram, repo structure, doc map |
| [Architecture Reference](./architecture-reference.md) | Implementation-derived architecture (12 sections) |
| [Source Tree Analysis](./source-tree-analysis.md) | Annotated directory structure with entry points and data flow |
| [Development Guide](./development-guide.md) | Setup, build, test, CI/CD, common tasks |
| [Data Models](./data-models.md) | Database schema (30+ tables), Pydantic models, enums, indexing |
| [API Contracts](./api-contracts.md) | Service interfaces, Kafka topics, communication patterns |

---

## Existing Design Documentation

### Planning & Requirements

| Document | Description |
|----------|-------------|
| [Product Requirements (PRD)](./prd.md) | Product Requirements Document v2.0 |
| [Testing Requirements](./testing-requirements.md) | Test plan (T1-T12) |
| [Remediation Backlog](./remediation-backlog.md) | Outstanding items and improvements |

### Architecture & Design

| Document | Description |
|----------|-------------|
| [Architecture](./architecture.md) | Design-time architecture v2.0 |
| [AI System Design](./ai-system-design.md) | AI reasoning system architecture |
| [Data Pipeline](./data-pipeline.md) | Ingestion and processing pipeline |
| [RAG Design](./rag-design.md) | Retrieval-augmented generation design |
| [Inference Optimization](./inference-optimization.md) | LLM performance tuning |

### Integration Layers

| Document | Description |
|----------|-------------|
| [ATLAS Integration](./atlas-integration.md) | MITRE ATT&CK/ATLAS layer |
| [CTEM Integration](./ctem-integration.md) | CTEM program layer |
| [Audit Architecture](./audit-architecture.md) | Immutable audit trail design |

### Operations

| Document | Description |
|----------|-------------|
| [Runbook](./runbook.md) | Operations procedures |
| [Provider Outage Playbook](./provider-outage-playbook.md) | LLM degradation handling |
| [Research Notes](./research-notes.md) | Cutting-edge techniques and explorations |

---

## Getting Started

```bash
# 1. Install
pip install -e ".[dev]"

# 2. Start infrastructure
docker-compose up -d

# 3. Initialize databases
python infra/scripts/create_kafka_topics.py
python infra/scripts/init_neo4j.py
python infra/scripts/init_qdrant.py

# 4. Run tests
python -m pytest tests/ -v

# 5. Set ANTHROPIC_API_KEY for LLM features
export ANTHROPIC_API_KEY=sk-ant-...
```

See [Development Guide](./development-guide.md) for detailed instructions.
