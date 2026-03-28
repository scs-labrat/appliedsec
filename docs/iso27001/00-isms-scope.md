# ISMS Scope Statement

**Document ID:** ALUSKORT-ISMS-00
**Version:** 1.0
**Classification:** Internal
**Owner:** Chief Information Security Officer (CISO)
**Approved by:** Board of Directors, Applied Computing Technologies
**Effective date:** 2026-03-29
**Review date:** 2027-03-29
**Standard reference:** ISO/IEC 27001:2022 Clauses 4.1 -- 4.4, 6.1

---

## 1. Organisation

| Field | Value |
|---|---|
| Legal entity | Applied Computing Technologies Ltd |
| Trading name | Applied Computing Technologies |
| Primary product | ALUSKORT SOC Platform |
| Industry sector | Cybersecurity -- Managed Detection & Response |
| Headquarters | United Kingdom |
| Employees in scope | Platform Engineering, SOC Operations, Security Architecture, DevOps |

---

## 2. Purpose

This document defines the scope of the Information Security Management System (ISMS) established, implemented, maintained, and continually improved by Applied Computing Technologies for the ALUSKORT SOC Platform. The ISMS is designed to protect the confidentiality, integrity, and availability of information assets processed by the platform and to comply with ISO/IEC 27001:2022.

---

## 3. Context of the Organisation (Clause 4.1)

### 3.1 Internal Context

Applied Computing Technologies develops and operates the ALUSKORT SOC Platform, an autonomous Security Operations Centre that leverages artificial intelligence to detect, investigate, and respond to cybersecurity threats on behalf of its customers. The platform is multi-tenant, serving organisations of varying sizes across regulated industries.

Key internal factors:

| Factor | Description |
|---|---|
| Strategic direction | Deliver AI-powered autonomous SOC capabilities while maintaining human oversight and auditability |
| Organisational structure | Lean engineering team operating in agile sprints; SOC analysts provide L1--L3 triage |
| Technology stack | 8 microservices + 1 audit service, 7 AI agents (LangGraph), 4-tier LLM routing (Anthropic Claude), PostgreSQL 16, Redis 7, Qdrant, Neo4j 5, Kafka/Redpanda, MinIO |
| Deployment model | Docker Compose (development) transitioning to Kubernetes (production) |
| AI dependency | Core detection and investigation capabilities depend on Anthropic Claude API (Haiku, Sonnet, Opus, Batch tiers) |
| Risk appetite | Low tolerance for false negatives; moderate tolerance for false positives with human review |

### 3.2 External Context

| Factor | Description |
|---|---|
| Market | Growing demand for AI-augmented SOC platforms; increasing regulatory scrutiny of AI in security operations |
| Regulatory landscape | UK Data Protection Act 2018, EU GDPR, EU AI Act, NIS2 Directive, sector-specific regulations of tenants |
| Technology trends | Rapid evolution of LLM capabilities; emerging adversarial AI threats; MITRE ATLAS framework adoption |
| Threat landscape | Nation-state actors, ransomware groups, insider threats, supply chain attacks, adversarial ML attacks |
| Competition | Traditional SIEM/SOAR vendors adding AI; other AI-native SOC platforms |

---

## 4. Interested Parties (Clause 4.2)

| Interested Party | Needs and Expectations | Relevance to ISMS |
|---|---|---|
| **SOC Analysts (L1/L2/L3)** | Reliable platform; accurate AI recommendations; clear decision audit trails; ergonomic interfaces | Primary users; depend on platform integrity for security decisions |
| **CISO / Security Management** | Demonstrable compliance; risk reduction metrics; cost efficiency; auditability | Accountable for security posture; require assurance of AI governance |
| **Tenant Customers** | Data confidentiality; service availability; regulatory compliance evidence; SLA adherence | Entrust their security telemetry and alert data to the platform |
| **Regulators (ICO, ENISA)** | Lawful data processing; GDPR compliance; AI transparency; incident notification | Enforcement authority; may audit or investigate |
| **Anthropic (LLM Provider)** | Acceptable use of Claude API; compliance with terms of service; responsible AI usage | Critical supplier; processes tenant data during inference |
| **Cloud Infrastructure Providers** | Contractual compliance; resource usage within quotas | Host platform compute and storage |
| **SIEM Vendors (Microsoft, Elastic, Splunk)** | Correct API usage; data handling per integration agreements | Source of security telemetry ingested by the platform |
| **Auditors (Internal & External)** | Complete documentation; evidence of control effectiveness; access to audit trails | Assess ISMS conformity and effectiveness |
| **Board of Directors** | Reduced organisational risk; regulatory compliance; protection of reputation | Ultimate governance responsibility |
| **Open Source Communities** | Responsible use of OSS components; contribution back where appropriate | Supply chain dependency |

---

## 5. Scope of the ISMS (Clause 4.3)

### 5.1 In Scope

The ISMS covers all information assets, processes, people, and technology associated with the design, development, deployment, operation, and maintenance of the ALUSKORT SOC Platform, specifically:

#### 5.1.1 Services and Components

| Component | Description |
|---|---|
| Alert Ingestion Service | Receives and normalises security alerts from SIEM integrations |
| Triage Service | AI-powered initial alert classification and prioritisation |
| Investigation Service | LangGraph-based multi-agent investigation pipeline (7 AI agents) |
| Context Gateway | Adversarial AI defence layer (injection detection, PII redaction, output validation) |
| LLM Router | 4-tier routing to Anthropic Claude (Haiku/Sonnet/Opus/Batch) with spend guard |
| Response Service | Automated and human-approved response actions |
| Case Management Service | Investigation lifecycle management |
| Dashboard Service | Analyst-facing investigation dashboard and approval interfaces |
| Audit Service | Immutable hash-chain audit trail (SHA-256, per-tenant) |

#### 5.1.2 Data Stores

| Data Store | Purpose |
|---|---|
| PostgreSQL 16 | Primary relational data (alerts, cases, users, tenants, audit records) |
| Redis 7 | Caching, session state, rate limiting, spend tracking |
| Qdrant | Vector database for semantic similarity search on alerts and investigations |
| Neo4j 5 | Graph database for entity relationships and attack chain modelling |
| Kafka / Redpanda | Event streaming and message bus |
| MinIO | Object storage for evidence packages, investigation artefacts |

#### 5.1.3 AI and LLM Components

| Component | Description |
|---|---|
| 7 AI Agents | Triage, enrichment, correlation, investigation, recommendation, reporting, review agents within LangGraph |
| 4 LLM Tiers | Haiku (fast/cheap), Sonnet (balanced), Opus (complex reasoning), Batch (bulk processing) |
| Context Gateway | Prompt injection detection, PII redaction, structured evidence isolation, output validation |
| MITRE ATLAS Rules | 11 adversarial AI detection rules |
| Spend Guard | Per-tenant LLM budget enforcement (premium=500, standard=100, trial=20 calls/hour) |

#### 5.1.4 Infrastructure

| Element | Description |
|---|---|
| Docker Compose | Development and testing environments |
| Kubernetes | Production deployment (multi-node cluster) |
| Container registry | Container image storage and scanning |
| CI/CD pipeline | Automated build, test, security scan, and deployment |
| Network infrastructure | K8s namespaces, network policies, ingress controllers |

#### 5.1.5 Processes

- Security alert ingestion and normalisation
- AI-powered triage and investigation
- Human-in-the-loop approval workflows
- Automated and semi-automated response execution
- Audit trail generation and verification
- Tenant onboarding and offboarding
- Platform change management and deployment
- Incident response for the platform itself
- LLM provider management and failover
- Vulnerability management (CTEM integration)

#### 5.1.6 People

- Platform Engineering team (development, DevOps, SRE)
- SOC Operations team (L1, L2, L3 analysts)
- Security Architecture team
- CISO and security management
- System administrators

### 5.2 Out of Scope

The following are explicitly excluded from this ISMS scope:

| Exclusion | Rationale |
|---|---|
| Customer-side SIEM infrastructure | Managed by tenant organisations; ALUSKORT receives data via APIs only |
| Customer endpoint devices | Not under ALUSKORT operational control |
| Anthropic's internal infrastructure | Governed by Anthropic's own ISMS; managed via supplier agreements |
| Cloud provider physical data centres | Governed by cloud provider certifications (ISO 27001, SOC 2); managed via contracts |
| Corporate IT systems (email, HR) | Covered by a separate corporate ISMS; interfaces documented where relevant |
| Marketing website and public content | Separate system with no connection to the SOC platform |
| Physical office security | Covered by the corporate ISMS; platform team operates remotely with no physical SOC facility |

### 5.3 Scope Boundaries

```
                        ISMS Scope Boundary
 ┌──────────────────────────────────────────────────────────────────┐
 │                                                                  │
 │  ┌──────────────┐  ┌──────────────┐  ┌──────────────────────┐   │
 │  │ Alert        │  │ Triage       │  │ Investigation        │   │
 │  │ Ingestion    │──│ Service      │──│ Service (7 Agents)   │   │
 │  └──────┬───────┘  └──────────────┘  └──────────┬───────────┘   │
 │         │                                        │               │
 │  ┌──────┴───────┐  ┌──────────────┐  ┌──────────┴───────────┐   │
 │  │ SIEM         │  │ Context      │  │ LLM Router           │   │
 │  │ Adapters     │  │ Gateway      │  │ (Spend Guard)        │   │
 │  └──────────────┘  └──────────────┘  └──────────┬───────────┘   │
 │                                                  │               │
 │  ┌──────────────┐  ┌──────────────┐  ┌──────────┴───────────┐   │
 │  │ Response     │  │ Case Mgmt    │  │ Dashboard            │   │
 │  │ Service      │  │ Service      │  │ Service              │   │
 │  └──────────────┘  └──────────────┘  └──────────────────────┘   │
 │                                                                  │
 │  ┌──────────────┐  ┌──────────────┐  ┌──────────────────────┐   │
 │  │ Audit        │  │ Data Stores  │  │ Infrastructure       │   │
 │  │ Service      │  │ (PG/Redis/   │  │ (K8s/Docker)         │   │
 │  │ (Hash Chain) │  │  Qdrant/Neo4j│  │                      │   │
 │  └──────────────┘  │  Kafka/MinIO)│  └──────────────────────┘   │
 │                     └──────────────┘                             │
 └──────────────────────────────┬───────────────────────────────────┘
                                │
                    External Interfaces
                    (Out of scope internally)
                                │
          ┌─────────────────────┼─────────────────────┐
          │                     │                     │
   ┌──────┴──────┐    ┌────────┴───────┐    ┌────────┴───────┐
   │ Anthropic   │    │ Customer SIEM  │    │ Cloud Provider │
   │ Claude API  │    │ (Sentinel,     │    │ Infrastructure │
   │             │    │  Elastic,      │    │                │
   │             │    │  Splunk)       │    │                │
   └─────────────┘    └────────────────┘    └────────────────┘
```

---

## 6. Applicable Legal, Regulatory, and Contractual Requirements

| Requirement | Applicability | Impact on ISMS |
|---|---|---|
| **UK Data Protection Act 2018 / UK GDPR** | Processing of personal data within security alerts (IP addresses, usernames, email addresses) | Data protection controls, PII redaction, DPIA, data retention limits |
| **EU General Data Protection Regulation (GDPR)** | EU-based tenants; cross-border data transfers to LLM providers | Lawful basis for processing, data transfer mechanisms, right to erasure |
| **EU AI Act (2024/1689)** | AI system used in security-critical decision-making | Risk classification, transparency requirements, human oversight, documentation |
| **NIS2 Directive (2022/2555)** | Platform provides security services to entities in NIS2 scope | Security incident notification, supply chain security, risk management |
| **ISO/IEC 27001:2022** | Voluntary certification target | Full ISMS implementation |
| **ISO/IEC 42001:2023** | AI management system (reference standard) | AI-specific controls, model governance, bias management |
| **MITRE ATLAS** | Industry framework for adversarial AI | 11 detection rules implemented; adversarial defence posture |
| **PCI DSS v4.0** | Tenants in payment card industry | Relevant controls for data handling and access control |
| **SOC 2 Type II** | Customer trust and assurance | Controls mapping for security, availability, confidentiality |
| **Tenant contractual SLAs** | Availability, response time, data handling commitments | Operational controls, BCP, capacity management |

---

## 7. Statement of Applicability Reference

The full Statement of Applicability (SoA) is maintained in document **ALUSKORT-ISMS-12** (`12-statement-of-applicability.md`). The SoA maps all 93 controls of ISO/IEC 27001:2022 Annex A to the ALUSKORT platform, documenting applicability, implementation status, and justification for any exclusions.

---

## 8. ISMS Objectives

The ISMS for the ALUSKORT SOC Platform pursues the following measurable objectives:

| Objective | Measure | Target |
|---|---|---|
| Protect tenant data confidentiality | Zero cross-tenant data leakage incidents | 0 incidents per year |
| Maintain platform availability | Uptime percentage | >= 99.9% |
| Ensure AI decision auditability | Percentage of AI decisions with complete audit trail | 100% |
| Prevent adversarial AI exploitation | Prompt injection detection rate | >= 99% |
| Maintain regulatory compliance | Audit findings (major non-conformities) | 0 major findings |
| Reduce mean time to detect (MTTD) | Average time from alert ingestion to triage | < 60 seconds |
| Control LLM costs | Budget adherence per tenant tier | 100% within quota |

---

## 9. Document Control

| Version | Date | Author | Changes |
|---|---|---|---|
| 1.0 | 2026-03-29 | CISO | Initial release |

---

*This document is part of the ALUSKORT SOC Platform ISMS. It shall be reviewed annually or upon significant change to the platform, organisation, or regulatory environment.*
