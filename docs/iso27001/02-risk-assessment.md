# Risk Assessment and Treatment

**Document ID:** ALUSKORT-ISMS-02
**Version:** 1.0
**Classification:** Confidential
**Owner:** Chief Information Security Officer (CISO)
**Approved by:** Board of Directors, Applied Computing Technologies
**Effective date:** 2026-03-29
**Review date:** 2027-03-29
**Standard reference:** ISO/IEC 27001:2022 Clauses 6.1, 8.2, 8.3; Annex A.5.3, A.8

---

## 1. Purpose

This document defines the risk assessment methodology, identifies and evaluates information security risks to the ALUSKORT SOC Platform, and specifies the risk treatment plan. It addresses both traditional information security risks and AI-specific risks inherent to an autonomous, LLM-powered security operations platform.

---

## 2. Risk Assessment Methodology

### 2.1 Approach

The ALUSKORT risk assessment follows a qualitative, asset-based methodology aligned with ISO/IEC 27005:2022. Risks are identified by analysing threats to, and vulnerabilities of, each information asset, then evaluated using a likelihood-impact matrix.

### 2.2 Risk Identification Process

1. **Asset identification** -- enumerate all information assets within the ISMS scope
2. **Threat identification** -- identify threats relevant to each asset, including AI-specific threats
3. **Vulnerability identification** -- identify weaknesses that threats could exploit
4. **Existing control identification** -- document controls already in place
5. **Risk evaluation** -- score likelihood and impact considering existing controls
6. **Risk treatment** -- select treatment option and define additional controls where needed

### 2.3 Likelihood Scale

| Score | Level | Description | Frequency Guidance |
|---|---|---|---|
| 1 | Very Low | Highly unlikely to occur | Less than once per 5 years |
| 2 | Low | Could occur but not expected | Once per 1--5 years |
| 3 | Medium | Reasonable possibility of occurrence | Once per quarter to once per year |
| 4 | High | Likely to occur | Monthly to quarterly |
| 5 | Very High | Expected to occur regularly | Weekly or more frequently |

### 2.4 Impact Scale

| Score | Level | Confidentiality Impact | Integrity Impact | Availability Impact |
|---|---|---|---|---|
| 1 | Negligible | No sensitive data exposed | Minor data inaccuracy, self-correcting | < 5 minutes downtime |
| 2 | Low | Internal data exposed to limited audience | Data inaccuracy requiring manual correction | 5 min -- 1 hour downtime |
| 3 | Medium | Confidential data of single tenant exposed | Investigation integrity compromised for single case | 1 -- 4 hours downtime |
| 4 | High | Confidential data of multiple tenants exposed | Systematic investigation integrity failure | 4 -- 24 hours downtime |
| 5 | Critical | Restricted data (keys, PII, deanonymisation maps) exposed | Audit trail integrity compromised; undetectable tampering | > 24 hours downtime |

### 2.5 Risk Matrix

|  | **Impact 1** | **Impact 2** | **Impact 3** | **Impact 4** | **Impact 5** |
|---|---|---|---|---|---|
| **Likelihood 5** | 5 (Medium) | 10 (Medium) | 15 (High) | 20 (Critical) | 25 (Critical) |
| **Likelihood 4** | 4 (Low) | 8 (Medium) | 12 (High) | 16 (High) | 20 (Critical) |
| **Likelihood 3** | 3 (Low) | 6 (Medium) | 9 (Medium) | 12 (High) | 15 (High) |
| **Likelihood 2** | 2 (Low) | 4 (Low) | 6 (Medium) | 8 (Medium) | 10 (Medium) |
| **Likelihood 1** | 1 (Low) | 2 (Low) | 3 (Low) | 4 (Low) | 5 (Medium) |

### 2.6 Risk Treatment Options

| Option | Description | When Applied |
|---|---|---|
| **Mitigate** | Implement controls to reduce likelihood and/or impact | Risk score exceeds acceptable level and controls are feasible |
| **Transfer** | Transfer risk to a third party (insurance, supplier SLA) | Risk cannot be fully mitigated internally |
| **Accept** | Formally accept the residual risk | Risk score is within acceptable level after treatment |
| **Avoid** | Eliminate the activity that causes the risk | Risk cannot be reduced to acceptable level |

### 2.7 Risk Acceptance Criteria

| Risk Level | Score Range | Treatment Required | Approval Authority |
|---|---|---|---|
| **Critical** | 16 -- 25 | Immediate mitigation required; cannot be accepted | Board of Directors |
| **High** | 11 -- 15 | Mitigation required within 30 days | CISO |
| **Medium** | 5 -- 10 | Mitigation planned within 90 days or accepted with justification | CISO |
| **Low** | 1 -- 4 | Accepted or mitigated at management discretion | Security Architect |

---

## 3. Asset Inventory

### 3.1 Service Assets

| Asset ID | Asset Name | Asset Type | Owner | Classification | Criticality |
|---|---|---|---|---|---|
| SVC-01 | Alert Ingestion Service | Microservice | Platform Eng Lead | Confidential | High |
| SVC-02 | Triage Service | Microservice | Platform Eng Lead | Confidential | Critical |
| SVC-03 | Investigation Service | Microservice | AI/ML Eng Lead | Confidential | Critical |
| SVC-04 | Context Gateway | Microservice | Security Architect | Restricted | Critical |
| SVC-05 | LLM Router | Microservice | AI/ML Eng Lead | Restricted | Critical |
| SVC-06 | Response Service | Microservice | Platform Eng Lead | Confidential | High |
| SVC-07 | Case Management Service | Microservice | Platform Eng Lead | Confidential | High |
| SVC-08 | Dashboard Service | Microservice | Platform Eng Lead | Internal | Medium |
| SVC-09 | Audit Service | Microservice | Security Architect | Restricted | Critical |

### 3.2 Data Store Assets

| Asset ID | Asset Name | Asset Type | Owner | Classification | Criticality |
|---|---|---|---|---|---|
| DS-01 | PostgreSQL 16 | Database | DevOps Lead | Confidential | Critical |
| DS-02 | Redis 7 | Cache/Session Store | DevOps Lead | Confidential | High |
| DS-03 | Qdrant | Vector Database | AI/ML Eng Lead | Confidential | High |
| DS-04 | Neo4j 5 | Graph Database | AI/ML Eng Lead | Confidential | High |
| DS-05 | Kafka / Redpanda | Message Bus | DevOps Lead | Confidential | Critical |
| DS-06 | MinIO | Object Storage | DevOps Lead | Confidential | High |

### 3.3 AI and LLM Assets

| Asset ID | Asset Name | Asset Type | Owner | Classification | Criticality |
|---|---|---|---|---|---|
| AI-01 | LangGraph Agent Pipeline (7 agents) | AI System | AI/ML Eng Lead | Confidential | Critical |
| AI-02 | LLM Tier Configuration (Haiku/Sonnet/Opus/Batch) | Configuration | AI/ML Eng Lead | Restricted | Critical |
| AI-03 | Agent Prompts and Templates | Intellectual Property | AI/ML Eng Lead | Restricted | High |
| AI-04 | MITRE ATLAS Detection Rules (11 rules) | Security Controls | Security Architect | Confidential | High |
| AI-05 | Spend Guard Configuration | Configuration | Platform Eng Lead | Confidential | High |
| AI-06 | PII Redaction Pipeline | AI System | Security Architect | Restricted | Critical |
| AI-07 | Deanonymisation Maps | Data | Security Architect | Restricted | Critical |

### 3.4 Infrastructure Assets

| Asset ID | Asset Name | Asset Type | Owner | Classification | Criticality |
|---|---|---|---|---|---|
| INF-01 | Kubernetes Cluster | Infrastructure | DevOps Lead | Confidential | Critical |
| INF-02 | Docker Compose (Dev) | Infrastructure | DevOps Lead | Internal | Low |
| INF-03 | CI/CD Pipeline | Infrastructure | DevOps Lead | Confidential | High |
| INF-04 | Container Registry | Infrastructure | DevOps Lead | Confidential | High |
| INF-05 | mTLS Certificates | Credential | Security Architect | Restricted | Critical |
| INF-06 | OIDC Provider Configuration | Configuration | Security Architect | Restricted | Critical |

### 3.5 Credential and Key Assets

| Asset ID | Asset Name | Asset Type | Owner | Classification | Criticality |
|---|---|---|---|---|---|
| KEY-01 | Anthropic Claude API Keys | API Credential | AI/ML Eng Lead | Restricted | Critical |
| KEY-02 | Database Credentials | Credential | DevOps Lead | Restricted | Critical |
| KEY-03 | Kafka Authentication Credentials | Credential | DevOps Lead | Restricted | High |
| KEY-04 | MinIO Access Keys | Credential | DevOps Lead | Restricted | High |
| KEY-05 | OIDC Client Secrets | Credential | Security Architect | Restricted | Critical |
| KEY-06 | mTLS Private Keys | Credential | Security Architect | Restricted | Critical |
| KEY-07 | Tenant Encryption Keys | Credential | Security Architect | Restricted | Critical |

---

## 4. Threat Catalogue

### 4.1 AI-Specific Threats

| Threat ID | Threat | Description | Target Assets | MITRE ATLAS Reference |
|---|---|---|---|---|
| T-AI-01 | **Prompt Injection Attack** | Adversary crafts malicious input embedded in security alert data to manipulate LLM agent behaviour, bypassing security controls or exfiltrating data | AI-01, AI-03, SVC-04 | AML.T0051 |
| T-AI-02 | **Model Poisoning** | Adversary manipulates training data or fine-tuning inputs to bias AI agent decisions, causing systematic false negatives | AI-01, AI-04 | AML.T0020 |
| T-AI-03 | **Data Exfiltration via LLM Responses** | Adversary exploits LLM context window to extract sensitive data (tenant data, system prompts, credentials) through crafted prompts | AI-01, AI-02, KEY-01 | AML.T0024 |
| T-AI-04 | **Adversarial Evasion** | Adversary crafts attacks specifically designed to evade AI-based detection, exploiting known weaknesses in ML classification | AI-01, AI-04, SVC-02 | AML.T0015 |
| T-AI-05 | **LLM Hallucination** | AI agent generates fabricated investigation findings or false correlations, leading to incorrect security decisions | AI-01, SVC-03 | -- |
| T-AI-06 | **Model Extraction** | Adversary systematically queries the platform to reconstruct agent behaviour patterns and detection logic | AI-01, AI-03, AI-04 | AML.T0024 |
| T-AI-07 | **PII Leakage Through LLM Context** | Personal data included in LLM context windows is transmitted to Anthropic or extracted through prompt manipulation | AI-06, AI-07, DS-01 | -- |
| T-AI-08 | **Spend Exhaustion Attack** | Adversary generates high volumes of complex alerts to exhaust tenant LLM budgets, causing denial of service | AI-05, SVC-05 | -- |
| T-AI-09 | **Agent Jailbreak** | Adversary manipulates an AI agent to operate outside its intended scope, executing unauthorised actions | AI-01, SVC-06 | AML.T0051.001 |
| T-AI-10 | **Bias in AI Decision-Making** | Systematic bias in AI agent decisions leads to unequal treatment of alerts from different sources, tenants, or categories | AI-01 | -- |

### 4.2 Platform and Infrastructure Threats

| Threat ID | Threat | Description | Target Assets |
|---|---|---|---|
| T-PLT-01 | **Insider Threat via Admin Role Abuse** | Malicious or compromised administrator uses elevated privileges to access tenant data, modify AI behaviour, or disable security controls | All assets |
| T-PLT-02 | **Supply Chain Compromise of LLM Provider** | Anthropic's systems are compromised, leading to model manipulation, data breach, or service disruption | AI-01, AI-02, KEY-01 |
| T-PLT-03 | **Denial of Service on Investigation Pipeline** | Adversary floods the platform with alerts or API requests, overwhelming the investigation pipeline and preventing legitimate alert processing | SVC-01 through SVC-08, DS-05 |
| T-PLT-04 | **Audit Trail Tampering** | Adversary or malicious insider attempts to modify or delete audit records to conceal unauthorised actions | SVC-09, DS-01 |
| T-PLT-05 | **Tenant Data Cross-Contamination** | Software defect or misconfiguration causes data from one tenant to be visible to or mixed with another tenant's data | DS-01 through DS-06 |
| T-PLT-06 | **Credential Compromise** | API keys, database credentials, or mTLS private keys are exposed through code repository, logs, or configuration files | KEY-01 through KEY-07 |
| T-PLT-07 | **Container Escape** | Adversary exploits container vulnerability to break out of container isolation and access the host or other containers | INF-01, INF-02 |
| T-PLT-08 | **Kafka Message Tampering** | Adversary gains access to Kafka topics and modifies messages in transit, corrupting investigation data flow | DS-05 |
| T-PLT-09 | **Database Compromise** | SQL injection or credential compromise leads to unauthorised access to PostgreSQL, Redis, Qdrant, or Neo4j | DS-01 through DS-04 |
| T-PLT-10 | **Ransomware / Destructive Attack** | Adversary encrypts or destroys platform data and infrastructure | All data store assets |
| T-PLT-11 | **OIDC Provider Compromise** | Identity provider is compromised, allowing adversary to forge authentication tokens | INF-06 |
| T-PLT-12 | **Certificate Compromise** | mTLS certificates or private keys are compromised, allowing impersonation of internal services | INF-05, KEY-06 |

---

## 5. Risk Register

### 5.1 AI-Specific Risks

| Risk ID | Threat | Likelihood | Impact | Risk Score | Risk Level | Existing Controls |
|---|---|---|---|---|---|---|
| R-AI-01 | Prompt Injection Attack (T-AI-01) | 5 | 4 | 20 | **Critical** | Context Gateway injection detection; structured evidence isolation; deny-by-default output validation; MITRE ATLAS rules |
| R-AI-02 | Model Poisoning (T-AI-02) | 2 | 5 | 10 | **Medium** | Using pre-trained Anthropic models (no fine-tuning); prompt-based agents; canary rollout |
| R-AI-03 | Data Exfiltration via LLM (T-AI-03) | 3 | 4 | 12 | **High** | Context Gateway output validation; PII redaction; structured evidence isolation |
| R-AI-04 | Adversarial Evasion (T-AI-04) | 4 | 4 | 16 | **Critical** | MITRE ATLAS 11 detection rules; human-in-the-loop review; FP precision monitoring |
| R-AI-05 | LLM Hallucination (T-AI-05) | 4 | 3 | 12 | **High** | Confidence scores; human approval gates; multi-agent cross-validation; structured evidence |
| R-AI-06 | Model Extraction (T-AI-06) | 2 | 3 | 6 | **Medium** | Rate limiting; tenant quotas; audit trail; no direct model access exposed |
| R-AI-07 | PII Leakage Through LLM (T-AI-07) | 3 | 4 | 12 | **High** | PII redaction pipeline; deanonymisation access controls; data minimisation in prompts |
| R-AI-08 | Spend Exhaustion Attack (T-AI-08) | 3 | 2 | 6 | **Medium** | Spend guard; per-tenant quotas (premium=500, standard=100, trial=20 calls/hour) |
| R-AI-09 | Agent Jailbreak (T-AI-09) | 3 | 5 | 15 | **High** | Kill switch; human approval gates; output validation; structured action schema |
| R-AI-10 | Bias in AI Decisions (T-AI-10) | 2 | 3 | 6 | **Medium** | FP precision evaluation; per-tenant monitoring; human review of AI decisions |

### 5.2 Platform and Infrastructure Risks

| Risk ID | Threat | Likelihood | Impact | Risk Score | Risk Level | Existing Controls |
|---|---|---|---|---|---|---|
| R-PLT-01 | Admin Role Abuse (T-PLT-01) | 2 | 5 | 10 | **Medium** | RBAC; audit trail; two-person approval; access reviews |
| R-PLT-02 | LLM Provider Compromise (T-PLT-02) | 1 | 5 | 5 | **Medium** | Anthropic security practices; fallback to OpenAI; output validation; no sensitive data in prompts (post-redaction) |
| R-PLT-03 | DoS on Investigation Pipeline (T-PLT-03) | 3 | 3 | 9 | **Medium** | Rate limiting; per-tenant quotas; Kafka buffering; horizontal scaling (K8s) |
| R-PLT-04 | Audit Trail Tampering (T-PLT-04) | 2 | 5 | 10 | **Medium** | SHA-256 hash-chain; per-tenant genesis blocks; tamper detection; immutable append-only design |
| R-PLT-05 | Tenant Cross-Contamination (T-PLT-05) | 2 | 5 | 10 | **Medium** | Tenant ID in all queries; database row-level filtering; separate Kafka topics; testing |
| R-PLT-06 | Credential Compromise (T-PLT-06) | 3 | 5 | 15 | **High** | K8s secrets; environment variable injection; no credentials in code; secret scanning in CI |
| R-PLT-07 | Container Escape (T-PLT-07) | 1 | 5 | 5 | **Medium** | Non-root containers; read-only root filesystem; K8s security contexts; image scanning |
| R-PLT-08 | Kafka Message Tampering (T-PLT-08) | 2 | 4 | 8 | **Medium** | Kafka ACLs; mTLS; message integrity via hash-chain; consumer group isolation |
| R-PLT-09 | Database Compromise (T-PLT-09) | 2 | 5 | 10 | **Medium** | Parameterised queries; network policies; credential rotation; encryption at rest |
| R-PLT-10 | Ransomware (T-PLT-10) | 2 | 5 | 10 | **Medium** | Automated backups; point-in-time recovery; immutable backups; DR procedures |
| R-PLT-11 | OIDC Provider Compromise (T-PLT-11) | 1 | 5 | 5 | **Medium** | Token validation; short token lifetimes; provider security assessment; fallback auth |
| R-PLT-12 | Certificate Compromise (T-PLT-12) | 1 | 4 | 4 | **Low** | Certificate rotation; short-lived certificates; cert-manager automation; monitoring |

---

## 6. Risk Treatment Plan

### 6.1 Critical Risks (Immediate Mitigation)

#### R-AI-01: Prompt Injection Attack (Score: 20)

| Treatment | Control | Owner | Deadline | Status |
|---|---|---|---|---|
| Mitigate | Enhance Context Gateway with multi-layer injection detection (regex, ML classifier, LLM-based detection) | AI/ML Eng Lead | Implemented | Complete |
| Mitigate | Implement structured evidence isolation -- alert data never directly interpolated into prompts | Security Architect | Implemented | Complete |
| Mitigate | Deploy deny-by-default output validation with strict JSON schema enforcement | AI/ML Eng Lead | Implemented | Complete |
| Mitigate | Maintain and update MITRE ATLAS detection rules | Security Architect | Ongoing | Active |
| Mitigate | Canary rollout for prompt template changes with automatic rollback | DevOps Lead | Implemented | Complete |
| Mitigate | Regular adversarial red team testing of prompt injection vectors | Security Architect | Quarterly | Active |
| Monitor | Track injection detection rate, false positive rate, bypass attempts | AI/ML Eng Lead | Continuous | Active |
| **Residual Risk** | **Score: 8 (Medium)** -- accepted by CISO | | | |

#### R-AI-04: Adversarial Evasion (Score: 16)

| Treatment | Control | Owner | Deadline | Status |
|---|---|---|---|---|
| Mitigate | Implement MITRE ATLAS framework with 11 detection rules | Security Architect | Implemented | Complete |
| Mitigate | Human-in-the-loop approval gates for high-severity alerts | SOC Manager | Implemented | Complete |
| Mitigate | FP precision continuous evaluation with drift detection | AI/ML Eng Lead | Implemented | Complete |
| Mitigate | 90-day pattern expiry with reaffirmation requirement | Security Architect | Implemented | Complete |
| Mitigate | Two-person approval for FP pattern creation | SOC Manager | Implemented | Complete |
| Mitigate | CTEM integration for continuous threat exposure assessment | Security Architect | Implemented | Complete |
| Monitor | Track evasion attempt detection rate, ATLAS rule performance | Security Architect | Continuous | Active |
| **Residual Risk** | **Score: 8 (Medium)** -- accepted by CISO | | | |

### 6.2 High Risks (Mitigation Within 30 Days)

#### R-AI-03: Data Exfiltration via LLM (Score: 12)

| Treatment | Control | Owner | Deadline | Status |
|---|---|---|---|---|
| Mitigate | Output validation with deny-by-default policy | AI/ML Eng Lead | Implemented | Complete |
| Mitigate | PII redaction before LLM context window | Security Architect | Implemented | Complete |
| Mitigate | Structured evidence isolation (data presented as typed fields, not raw text) | AI/ML Eng Lead | Implemented | Complete |
| Mitigate | Inference logging and audit of all LLM interactions | AI/ML Eng Lead | Implemented | Complete |
| Monitor | Anomaly detection on LLM response patterns | AI/ML Eng Lead | Planned | Q2 2026 |
| **Residual Risk** | **Score: 6 (Medium)** -- accepted by CISO | | | |

#### R-AI-05: LLM Hallucination (Score: 12)

| Treatment | Control | Owner | Deadline | Status |
|---|---|---|---|---|
| Mitigate | Confidence scores and thresholds on all AI recommendations | AI/ML Eng Lead | Implemented | Complete |
| Mitigate | Human approval gates for automated response actions | SOC Manager | Implemented | Complete |
| Mitigate | Multi-agent cross-validation in investigation pipeline | AI/ML Eng Lead | Implemented | Complete |
| Mitigate | Structured evidence requirements -- agents must cite sources | AI/ML Eng Lead | Implemented | Complete |
| Monitor | Track hallucination rate through analyst feedback loop | SOC Manager | Ongoing | Active |
| **Residual Risk** | **Score: 6 (Medium)** -- accepted by CISO | | | |

#### R-AI-07: PII Leakage Through LLM (Score: 12)

| Treatment | Control | Owner | Deadline | Status |
|---|---|---|---|---|
| Mitigate | PII redaction pipeline in Context Gateway | Security Architect | Implemented | Complete |
| Mitigate | Deanonymisation maps access-controlled with audit logging | Security Architect | Implemented | Complete |
| Mitigate | Data minimisation in LLM prompts (only necessary context included) | AI/ML Eng Lead | Implemented | Complete |
| Mitigate | Anthropic data processing agreement with no-training clause | CISO | In Progress | Q2 2026 |
| Transfer | Contractual liability for data processing failures | CISO | In Progress | Q2 2026 |
| **Residual Risk** | **Score: 6 (Medium)** -- accepted by CISO | | | |

#### R-AI-09: Agent Jailbreak (Score: 15)

| Treatment | Control | Owner | Deadline | Status |
|---|---|---|---|---|
| Mitigate | Kill switch for emergency shutdown of autonomous actions | CISO | Implemented | Complete |
| Mitigate | Human approval gates at critical decision points | SOC Manager | Implemented | Complete |
| Mitigate | Output validation with strict action schema enforcement | AI/ML Eng Lead | Implemented | Complete |
| Mitigate | Agent scope limitations enforced by service-level controls | Platform Eng Lead | Implemented | Complete |
| Mitigate | Regular jailbreak testing as part of adversarial red team exercises | Security Architect | Quarterly | Active |
| **Residual Risk** | **Score: 6 (Medium)** -- accepted by CISO | | | |

#### R-PLT-06: Credential Compromise (Score: 15)

| Treatment | Control | Owner | Deadline | Status |
|---|---|---|---|---|
| Mitigate | Store all secrets in Kubernetes Secrets (encrypted at rest via etcd encryption) | DevOps Lead | Implemented | Complete |
| Mitigate | Inject credentials via environment variables, never in code | Platform Eng Lead | Implemented | Complete |
| Mitigate | Secret scanning in CI/CD pipeline (pre-commit hooks) | DevOps Lead | Implemented | Complete |
| Mitigate | Credential rotation every 90 days | DevOps Lead | Implemented | Complete |
| Mitigate | Vault integration for dynamic secret generation | DevOps Lead | Planned | Q3 2026 |
| Monitor | Alert on credential exposure in logs or repositories | DevOps Lead | Implemented | Complete |
| **Residual Risk** | **Score: 6 (Medium)** -- accepted by CISO | | | |

### 6.3 Medium Risks (Mitigation Within 90 Days or Accept)

| Risk ID | Treatment Decision | Additional Controls | Residual Score | Accepted By |
|---|---|---|---|---|
| R-AI-02 | Accept | Existing controls sufficient (no fine-tuning); monitor Anthropic advisories | 10 | CISO |
| R-AI-06 | Accept | Rate limiting and quotas provide adequate protection | 6 | CISO |
| R-AI-08 | Accept | Spend guard provides hard budget enforcement | 6 | CISO |
| R-AI-10 | Mitigate | Implement bias monitoring dashboard; per-category detection rate analysis | 4 | CISO |
| R-PLT-01 | Mitigate | Quarterly admin access review; implement break-glass procedure with mandatory justification | 6 | CISO |
| R-PLT-02 | Transfer | Ensure contractual protections; maintain OpenAI fallback capability | 5 | CISO |
| R-PLT-03 | Accept | Current rate limiting and scaling controls sufficient | 9 | CISO |
| R-PLT-04 | Accept | Hash-chain design provides strong tamper detection | 10 | CISO |
| R-PLT-05 | Mitigate | Add tenant isolation integration tests; implement row-level security in PostgreSQL | 6 | CISO |
| R-PLT-07 | Accept | Container security controls provide adequate protection | 5 | Security Architect |
| R-PLT-08 | Accept | Kafka ACLs and mTLS provide adequate protection | 8 | CISO |
| R-PLT-09 | Mitigate | Implement database activity monitoring; add parameterised query enforcement checks | 6 | CISO |
| R-PLT-10 | Mitigate | Test backup restoration quarterly; implement immutable backup storage | 6 | CISO |
| R-PLT-11 | Accept | Token validation controls sufficient; low likelihood | 5 | Security Architect |
| R-PLT-12 | Accept | Certificate management controls sufficient; low likelihood | 4 | Security Architect |

---

## 7. Risk Heat Map (Post-Treatment)

```
Impact →   1          2          3          4          5
          Negligible  Low        Medium     High       Critical
     5  │           │           │           │           │
  V.High│           │           │           │           │
     4  │           │           │           │           │
  High  │           │           │           │           │
     3  │           │           │R-PLT-03   │           │
  Med   │           │R-AI-08    │           │           │
     2  │           │R-AI-10    │R-PLT-01   │R-AI-01*   │R-PLT-04
  Low   │           │           │R-PLT-05   │R-AI-03*   │R-PLT-09
        │           │           │R-AI-02    │R-AI-04*   │R-PLT-10
     1  │           │           │           │R-PLT-02   │R-PLT-07
  V.Low │           │R-PLT-12   │           │R-PLT-11   │
        └───────────┴───────────┴───────────┴───────────┘
  Likelihood ↑

  * = Post-treatment residual risk (reduced from original score)
```

---

## 8. Risk Monitoring and Review

### 8.1 Continuous Monitoring

| Metric | Source | Threshold | Action |
|---|---|---|---|
| Prompt injection detection rate | Context Gateway logs | < 99% | Immediate investigation; update detection rules |
| ATLAS rule trigger rate | MITRE ATLAS engine | Anomalous increase (> 2 std dev) | Security Architect review |
| Spend guard violations | LLM Router metrics | Any violation | Investigate; review tenant quotas |
| Cross-tenant query attempts | Audit trail | Any occurrence | Immediate investigation; incident response |
| Credential exposure alerts | CI/CD + monitoring | Any alert | Immediate rotation; incident response |
| Hash-chain verification failures | Audit Service | Any failure | Immediate investigation; incident response |
| LLM hallucination reports | Analyst feedback | Increase > 10% month-over-month | AI/ML team review; prompt refinement |

### 8.2 Periodic Review

| Activity | Frequency | Owner |
|---|---|---|
| Full risk assessment review | Annually | CISO |
| Risk register update | Quarterly | Security Architect |
| AI-specific risk review | Semi-annually | AI/ML Eng Lead + Security Architect |
| Threat intelligence update | Monthly | Security Architect |
| Control effectiveness testing | Quarterly | Internal Audit |
| Adversarial red team exercise | Quarterly | Security Architect (external team) |
| Penetration testing | Annually | External provider |

---

## 9. Document Control

| Version | Date | Author | Changes |
|---|---|---|---|
| 1.0 | 2026-03-29 | CISO | Initial release |

---

*This document is part of the ALUSKORT SOC Platform ISMS. It shall be reviewed annually or upon significant change to the threat landscape, platform architecture, or regulatory requirements.*
