# Supplier Relationships

**Document ID:** ALUSKORT-ISMS-07
**Version:** 1.0
**Classification:** Confidential
**Owner:** CISO
**Approved by:** CISO, Applied Computing Technologies
**Effective date:** 2026-03-29
**Review date:** 2027-03-29
**Standard reference:** ISO/IEC 27001:2022 Annex A.5.19--5.22

---

## 1. Purpose

This document defines the supplier relationship management policy for the ALUSKORT SOC Platform, covering the assessment, contracting, monitoring, and offboarding of all suppliers whose products or services interact with the platform's information assets.

---

## 2. Supplier Security Policy (A.5.19)

### 2.1 Principles

1. All suppliers who access, process, store, or transmit ALUSKORT information assets shall be assessed for information security risk before engagement.
2. Contractual agreements shall include information security requirements proportionate to the risk.
3. Supplier compliance shall be monitored throughout the relationship lifecycle.
4. Supplier dependencies shall be minimised where feasible; fallback options shall be maintained for critical suppliers.
5. Supply chain security shall be assessed end-to-end, including the supplier's own suppliers.

### 2.2 Supplier Criticality Classification

| Criticality | Definition | Assessment Frequency | Example |
|---|---|---|---|
| **Critical** | Supplier failure would directly impact platform availability, integrity, or confidentiality; no immediate alternative | Annually (full) + quarterly (review) | Anthropic (LLM provider) |
| **High** | Supplier failure would degrade platform capability; alternative exists but migration is non-trivial | Annually | Cloud infrastructure provider, SIEM vendors |
| **Medium** | Supplier failure would cause inconvenience; alternatives readily available | Every 2 years | Open source library maintainers, monitoring tools |
| **Low** | Supplier failure has minimal impact; easily replaceable | At onboarding only | Documentation tools, development utilities |

---

## 3. Supplier Inventory

### 3.1 Critical Suppliers

#### 3.1.1 Anthropic (Claude API) -- LLM Provider

| Aspect | Details |
|---|---|
| **Service provided** | Large Language Model inference (Claude Haiku, Sonnet, Opus, Batch) |
| **Data shared** | Security alert data (PII-redacted), investigation context, prompt templates |
| **Data NOT shared** | Raw PII (redacted before transmission), credentials, deanonymisation maps |
| **Criticality** | Critical -- core AI investigation capability depends on this service |
| **Fallback** | OpenAI API (GPT-4 family) as secondary LLM provider |
| **Contract type** | API service agreement |

**Contractual security requirements for Anthropic:**

| Requirement | Status |
|---|---|
| Data Processing Agreement (DPA) compliant with UK GDPR | Required |
| No training on customer data (opt-out confirmed) | Required |
| API data retention policy: < 30 days | Required |
| SOC 2 Type II report or equivalent | Required |
| Incident notification within 72 hours | Required |
| Encryption in transit (TLS 1.2+) | Verified |
| Geographic data processing restrictions (if applicable) | Required |
| Right to audit (or independent audit report) | Required |
| Sub-processor notification | Required |

**Provider outage procedures:**

| Scenario | Action | RTO |
|---|---|---|
| Anthropic API degradation (latency > 10s) | Automatic retry with exponential backoff; alert operations team | N/A (degraded) |
| Anthropic API partial outage (specific model) | LLM Router routes to alternative tier (e.g., Sonnet → Haiku) | < 1 minute |
| Anthropic API full outage | Automatic failover to OpenAI API; alert operations team; notify affected tenants | < 5 minutes |
| Anthropic API extended outage (> 4 hours) | OpenAI primary; queue non-urgent requests for batch processing; status page update | Ongoing |
| Anthropic security incident | Pause all API calls; assess impact; activate incident response; consider data breach notification | Immediate |

#### 3.1.2 OpenAI (GPT API) -- Fallback LLM Provider

| Aspect | Details |
|---|---|
| **Service provided** | Fallback LLM inference when Anthropic is unavailable |
| **Data shared** | Same as Anthropic (PII-redacted alert data, investigation context) |
| **Criticality** | High -- provides resilience for critical LLM capability |
| **Same contractual requirements** | DPA, no-training clause, retention limits, SOC 2 |

### 3.2 High Criticality Suppliers

#### 3.2.1 Cloud Infrastructure Provider

| Aspect | Details |
|---|---|
| **Service provided** | Compute, storage, networking for Kubernetes cluster |
| **Data hosted** | All ALUSKORT platform data (encrypted at rest) |
| **Criticality** | High |
| **Certifications required** | ISO 27001, SOC 2 Type II, CSA STAR |
| **Contract type** | Cloud service agreement with SLA |

**Required contractual terms:**

| Requirement | Details |
|---|---|
| SLA (availability) | >= 99.95% for compute; >= 99.99% for storage |
| Data residency | Data processing within agreed geographic region |
| Encryption | Encryption at rest (AES-256) and in transit (TLS 1.3) |
| Incident notification | Within 24 hours of confirmed security incident |
| Data deletion on termination | Cryptographic erasure within 90 days |
| Penetration testing | Customer authorised to conduct (with notification) |
| Sub-processor transparency | List of sub-processors available; notification of changes |

#### 3.2.2 SIEM Vendor Integrations

| Vendor | Integration Type | Data Flow | Authentication | Criticality |
|---|---|---|---|---|
| **Microsoft (Sentinel)** | REST API pull | Alerts from Sentinel → ALUSKORT | OAuth 2.0 client credentials | High |
| **Elastic (SIEM)** | REST API pull | Alerts from Elastic → ALUSKORT | API key | High |
| **Splunk** | HEC webhook push | Alerts from Splunk → ALUSKORT | HEC token | High |

**SIEM integration security requirements:**

| Requirement | Implementation |
|---|---|
| Authentication | Strong authentication per vendor (see table above) |
| Transport security | TLS 1.3 minimum |
| Data validation | Input validation on all received alert data (JSON schema) |
| Rate limiting | 100 requests/minute per integration |
| Credential management | Credentials stored in K8s Secrets; rotated every 90 days |
| Failure handling | Circuit breaker pattern; retry with backoff; alert on persistent failure |
| Data scope | Minimal data pull (alerts only; no full SIEM data access) |

### 3.3 Medium Criticality Suppliers

#### 3.3.1 Open Source Dependencies

| Category | Examples | Risk | Controls |
|---|---|---|---|
| Python packages | LangChain, LangGraph, FastAPI, Pydantic, SQLAlchemy | Supply chain compromise, vulnerability | Dependency pinning, Snyk scanning, lockfile verification |
| Node.js packages | React, WebSocket libraries | Supply chain compromise | npm audit, lockfile integrity, Snyk scanning |
| Container base images | Python slim, Node.js alpine, PostgreSQL, Redis | Compromised base image | Image scanning (Trivy), signed images, minimal base images |
| Kubernetes tools | cert-manager, ingress-nginx, Prometheus | Misconfiguration, vulnerability | Version pinning, Helm chart verification, security scanning |

**Open source supply chain controls:**

| Control | Implementation |
|---|---|
| Dependency pinning | All dependencies pinned to exact versions in lockfiles |
| Vulnerability scanning | Snyk continuous monitoring; alerts on new CVEs |
| Licence compliance | Automated licence scanning; approved licence list (MIT, Apache 2.0, BSD) |
| Dependency update policy | Security patches: within SLA; feature updates: quarterly review |
| Private registry mirror | Package mirror for critical dependencies (reduces supply chain risk) |
| SBOM generation | Software Bill of Materials generated per release |
| Signature verification | Container image signatures verified before deployment |

---

## 4. Supplier Assessment Process (A.5.20)

### 4.1 Pre-Engagement Assessment

| Step | Activity | Owner | Output |
|---|---|---|---|
| 1 | Identify supplier criticality classification | Security Architect | Criticality rating |
| 2 | Security questionnaire (proportionate to criticality) | Security Architect | Completed questionnaire |
| 3 | Review certifications (ISO 27001, SOC 2, etc.) | Security Architect | Certification verification |
| 4 | Assess data processing activities (DPA requirements) | CISO | DPA assessment |
| 5 | Review sub-processor chain | Security Architect | Sub-processor register |
| 6 | Risk assessment | CISO | Risk rating + treatment |
| 7 | Contractual negotiation (security clauses) | CISO + Legal | Signed agreement |
| 8 | Onboarding (credential provisioning, access setup) | DevOps Lead | Access configured |

### 4.2 Security Questionnaire Topics

| Topic | Questions Cover |
|---|---|
| Information security management | ISMS certification, security policy, risk management |
| Access control | Authentication, authorisation, privilege management |
| Cryptography | Encryption at rest/transit, key management |
| Operations security | Change management, vulnerability management, monitoring |
| Incident management | Incident response capability, notification timelines |
| Business continuity | DR capability, RTO/RPO, geographic redundancy |
| Data protection | GDPR compliance, data processing location, retention, deletion |
| Personnel security | Background checks, security training, NDA |
| Sub-processors | Sub-processor management, transparency, notification |
| AI-specific (for LLM providers) | Model training data policy, inference data retention, bias management |

---

## 5. Supplier Monitoring (A.5.22)

### 5.1 Ongoing Monitoring Activities

| Activity | Frequency | Scope | Owner |
|---|---|---|---|
| Service availability monitoring | Continuous | Critical and high suppliers | DevOps Lead |
| Security certification review | Annually | All suppliers with certifications | Security Architect |
| Vulnerability disclosure monitoring | Continuous | All software suppliers and OSS | Security Architect |
| DPA compliance review | Annually | Suppliers processing personal data | CISO |
| Incident notification review | Per incident | All suppliers reporting incidents | CISO |
| Sub-processor change review | On notification | Suppliers with sub-processor clauses | Security Architect |
| API usage and cost monitoring | Monthly | LLM providers (Anthropic, OpenAI) | Platform Eng Lead |
| Dependency vulnerability scan | Continuous | Open source dependencies | DevOps Lead |

### 5.2 Supplier Performance Metrics

| Metric | Target | Source |
|---|---|---|
| Anthropic API availability | >= 99.9% | LLM Router monitoring |
| Anthropic API latency (P99) | < 10 seconds | LLM Router metrics |
| Cloud infrastructure availability | >= 99.95% | Provider SLA dashboard |
| SIEM integration reliability | >= 99.5% | Alert Ingestion metrics |
| Security incident notification time | < 72 hours | Incident records |
| Vulnerability patch availability | Critical: < 48h, High: < 7d | Vendor advisories |

### 5.3 Supplier Non-Compliance Handling

| Severity | Response | Timeline |
|---|---|---|
| Critical (data breach, service compromise) | Immediate incident response; consider service suspension; CISO notification | Immediate |
| High (SLA breach, missing certification renewal) | Formal notification to supplier; remediation plan request; escalation if unresolved | 7 days |
| Medium (minor non-compliance, slow response) | Written notification; documented in supplier review record | 30 days |
| Low (documentation gaps, process deviations) | Noted in next scheduled review | Next review cycle |

---

## 6. Supplier Offboarding

### 6.1 Offboarding Checklist

| Step | Action | Owner | Timeline |
|---|---|---|---|
| 1 | Notify supplier of contract termination | CISO | Per contract terms |
| 2 | Revoke all supplier access credentials | DevOps Lead | Day of termination |
| 3 | Request confirmation of data deletion from supplier | CISO | Within 30 days |
| 4 | Verify data deletion (certificate of destruction) | Security Architect | Within 90 days |
| 5 | Remove supplier integrations from platform | Platform Eng Lead | Day of termination |
| 6 | Update supplier register | Security Architect | Day of termination |
| 7 | Update risk assessment (if critical supplier) | CISO | Within 7 days |
| 8 | Archive supplier records | Security Architect | Within 30 days |

### 6.2 LLM Provider Migration Plan

In the event of Anthropic contract termination or unacceptable risk:

| Phase | Action | Timeline |
|---|---|---|
| 1. Activate fallback | Switch LLM Router to OpenAI as primary | Immediate (automated) |
| 2. Prompt migration | Adapt prompt templates for OpenAI model compatibility | 1--2 weeks |
| 3. Testing | Full regression testing of AI agents with new provider | 2--4 weeks |
| 4. Validation | Shadow mode comparison of old vs. new provider quality | 2--4 weeks |
| 5. Production | Full production migration; decommission Anthropic integration | After validation |
| 6. Credential cleanup | Revoke Anthropic API keys; update all configurations | Same day as migration |

---

## 7. Document Control

| Version | Date | Author | Changes |
|---|---|---|---|
| 1.0 | 2026-03-29 | CISO | Initial release |

---

*This document is part of the ALUSKORT SOC Platform ISMS. It shall be reviewed annually or upon changes to supplier relationships, contractual terms, or supplier security posture.*
