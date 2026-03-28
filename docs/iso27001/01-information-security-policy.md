# Information Security Policy

**Document ID:** ALUSKORT-ISMS-01
**Version:** 1.0
**Classification:** Internal
**Owner:** Chief Information Security Officer (CISO)
**Approved by:** Board of Directors, Applied Computing Technologies
**Effective date:** 2026-03-29
**Review date:** 2027-03-29
**Standard reference:** ISO/IEC 27001:2022 Clause 5.2, Annex A.5

---

## 1. Policy Statement

Applied Computing Technologies is committed to protecting the confidentiality, integrity, and availability of all information assets associated with the ALUSKORT SOC Platform. This commitment extends to the security of tenant data, the integrity of AI-driven security decisions, and the trustworthiness of the autonomous investigation pipeline.

The organisation shall:

1. Establish, implement, maintain, and continually improve an Information Security Management System (ISMS) in accordance with ISO/IEC 27001:2022.
2. Ensure that information security objectives are established, are compatible with the strategic direction of the organisation, and are measured.
3. Satisfy applicable information security requirements, including legal, regulatory, and contractual obligations.
4. Treat the security of AI systems and LLM integrations as a first-class security concern, with controls that address the unique risks of autonomous AI-driven decision-making.
5. Maintain human oversight over all autonomous security actions through approval gates, kill switches, and audit trails.
6. Protect tenant data through strict multi-tenant isolation, PII redaction, and least-privilege access controls.

This policy applies to all personnel, contractors, and third parties who access, process, or manage information within the ALUSKORT SOC Platform.

---

## 2. Information Security Objectives

| Objective | Description | KPI | Target |
|---|---|---|---|
| **Confidentiality** | Prevent unauthorised disclosure of tenant data, investigation findings, and platform credentials | Cross-tenant data leakage incidents | 0 per year |
| **Integrity** | Ensure accuracy and completeness of security alerts, AI investigations, and audit trails | Audit trail hash-chain verification failures | 0 per year |
| **Availability** | Maintain platform uptime and investigation pipeline throughput | Platform availability | >= 99.9% |
| **AI Trustworthiness** | Ensure AI-driven decisions are accurate, explainable, and free from adversarial manipulation | Prompt injection detection rate | >= 99% |
| **Compliance** | Meet all applicable legal, regulatory, and contractual requirements | Major audit non-conformities | 0 per audit cycle |
| **Resilience** | Recover from incidents and disasters within defined targets | Recovery Time Objective (RTO) achieved | 100% |
| **Cost Control** | Operate within defined LLM spend budgets per tenant tier | Budget overrun incidents | 0 per quarter |

---

## 3. Roles and Responsibilities

### 3.1 Governance Structure

```
Board of Directors
        │
        ▼
Chief Information Security Officer (CISO)
        │
        ├── SOC Manager
        │       ├── L3 Senior Analysts
        │       ├── L2 Analysts
        │       └── L1 Analysts
        │
        ├── Platform Engineering Lead
        │       ├── Backend Engineers
        │       ├── AI/ML Engineers
        │       └── DevOps / SRE Engineers
        │
        └── Security Architect
```

### 3.2 Role Descriptions

| Role | Responsibilities |
|---|---|
| **Board of Directors** | Approve the information security policy; allocate resources for ISMS; oversee risk appetite; receive quarterly security reports |
| **CISO** | Own the ISMS; define security strategy and objectives; approve risk treatment plans; represent security to the board; authorise kill switch activation; lead incident response for critical incidents; approve supplier security assessments |
| **SOC Manager** | Manage day-to-day SOC operations; supervise analyst team; review AI-generated investigation outputs; approve escalation procedures; manage analyst access reviews; ensure SLA compliance |
| **L3 Senior Analysts** | Handle complex investigations; review AI recommendations for high-severity alerts; approve automated response actions (senior_analyst role); participate in two-person approval for FP patterns; conduct post-incident reviews |
| **L2 Analysts** | Investigate medium-severity alerts; review AI triage decisions; execute approved response playbooks; escalate to L3 when required (analyst role) |
| **L1 Analysts** | Monitor alert dashboard; perform initial human review of AI triage; escalate unresolved alerts; document investigation notes (analyst role) |
| **Platform Engineering Lead** | Own platform architecture and security controls; manage deployment pipeline; approve infrastructure changes; ensure separation of environments |
| **Backend Engineers** | Develop and maintain microservices; implement security controls in code; follow secure development practices; conduct peer code reviews |
| **AI/ML Engineers** | Develop and maintain AI agents, LLM prompts, and Context Gateway; implement adversarial AI defences; monitor model performance and drift; manage LLM routing and spend guard |
| **DevOps / SRE Engineers** | Manage infrastructure (K8s, databases, message bus); implement network policies; manage secrets and certificates; operate monitoring and alerting; execute disaster recovery procedures |
| **Security Architect** | Design security architecture; review new features for security implications; maintain threat model; manage MITRE ATLAS rules; conduct security assessments |

### 3.3 Platform RBAC Role Mapping

| Platform Role | Mapped To | Key Permissions |
|---|---|---|
| `admin` | CISO, Platform Engineering Lead, SOC Manager | Full platform configuration; tenant management; user management; kill switch; audit trail access; system settings |
| `senior_analyst` | L3 Senior Analysts | Approve/reject AI recommendations; two-person FP pattern approval; investigation management; case escalation; evidence package export |
| `analyst` | L1 Analysts, L2 Analysts | View alerts and investigations; add investigation notes; request escalation; view assigned cases; limited dashboard access |

---

## 4. Policy Principles

### 4.1 Least Privilege

All access to the ALUSKORT platform shall be granted on a least-privilege basis. Users shall receive only the minimum permissions necessary to perform their duties. The three-tier RBAC model (analyst, senior_analyst, admin) enforces this principle at the application level.

### 4.2 Defence in Depth

Security controls shall be layered across the platform:

| Layer | Controls |
|---|---|
| Network | Kubernetes network policies, namespace isolation, ingress rules, DDoS protection |
| Transport | TLS 1.3 for external connections, mTLS for inter-service communication |
| Application | OIDC authentication, RBAC authorisation, input validation, rate limiting |
| AI | Context Gateway (prompt injection detection, PII redaction, output validation, structured evidence isolation) |
| Data | Encryption at rest, tenant isolation, data classification, PII redaction |
| Audit | Immutable hash-chain audit trail, evidence packages, tamper detection |
| Operations | Monitoring, alerting, vulnerability management, change management |

### 4.3 Separation of Duties

Critical actions shall require multiple authorised individuals:

- **Two-person approval** for false positive (FP) pattern creation
- **Kill switch activation** requires admin role and documented justification
- **Production deployments** require code review + CI/CD pipeline approval
- **Tenant onboarding** requires admin role with audit trail entry
- **Access grants** for admin role require CISO approval

### 4.4 Accountability and Auditability

Every action on the platform shall be recorded in the immutable hash-chain audit trail. This includes:

- All user actions (authentication, authorisation decisions, configuration changes)
- All AI agent decisions (triage, investigation steps, recommendations)
- All automated responses (with approval status)
- All system events (deployments, configuration changes, health status)

### 4.5 Privacy by Design

Personal data protection shall be embedded into the platform design:

- PII redaction occurs at the Context Gateway before data enters LLM context windows
- Deanonymisation maps are access-controlled and audited
- Data minimisation is applied to LLM prompts
- Retention policies automatically purge data beyond defined periods

---

## 5. Acceptable Use

### 5.1 Permitted Uses

The ALUSKORT platform shall be used exclusively for:

- Security alert monitoring, triage, and investigation
- Threat detection and response within authorised tenant environments
- Security reporting and compliance evidence generation
- Platform administration and maintenance by authorised personnel

### 5.2 Prohibited Uses

The following uses are prohibited:

| Prohibited Activity | Rationale |
|---|---|
| Accessing tenant data outside assigned scope | Confidentiality, multi-tenant isolation |
| Attempting to bypass AI safety controls or kill switch | Integrity of autonomous decision pipeline |
| Using platform LLM access for non-security purposes | Cost control, acceptable use of supplier API |
| Sharing credentials or API keys | Authentication integrity |
| Disabling or circumventing audit logging | Audit trail integrity |
| Extracting or exporting data without authorisation | Data protection, contractual obligations |
| Introducing untested prompts into production agents | AI safety, adversarial risk |
| Approving own actions (self-approval) | Separation of duties |

---

## 6. Information Classification

All information processed by or stored within the ALUSKORT platform shall be classified according to the following scheme:

| Classification | Definition | Examples | Handling Requirements |
|---|---|---|---|
| **Restricted** | Highest sensitivity; unauthorised disclosure would cause severe damage | LLM API keys, mTLS private keys, deanonymisation maps, admin credentials, tenant encryption keys | Encrypted at rest and in transit; access limited to named individuals; logged and alerted; no external sharing |
| **Confidential** | Sensitive business or tenant information | Tenant alert data, investigation findings, AI agent prompts, RBAC configurations, audit records, PII before redaction | Encrypted at rest and in transit; access via RBAC; logged; shared only with authorised parties under NDA |
| **Internal** | Information for internal use only | Platform architecture documents, deployment procedures, monitoring dashboards, non-sensitive configurations | Access limited to staff; not shared externally without approval; stored in controlled repositories |
| **Public** | Information approved for public disclosure | Published API documentation, marketing materials, public status page | No handling restrictions; must be approved before publication |

---

## 7. Policy Compliance

### 7.1 Compliance Monitoring

Compliance with this policy shall be monitored through:

- Automated audit trail analysis
- Quarterly access reviews
- Annual internal ISMS audit
- External certification audit (annual)
- Continuous monitoring via Prometheus alerting rules
- CTEM vulnerability scanning

### 7.2 Non-Compliance

Violations of this policy may result in:

- Immediate access revocation
- Formal disciplinary action
- Contract termination (for third parties)
- Regulatory notification where required by law
- Legal action in cases of wilful misconduct

### 7.3 Exception Process

Exceptions to this policy must be:

1. Requested in writing with business justification
2. Risk-assessed by the Security Architect
3. Approved by the CISO
4. Documented with compensating controls
5. Time-limited (maximum 90 days) with reaffirmation required
6. Recorded in the risk register

---

## 8. Policy Review Schedule

| Review Activity | Frequency | Responsible |
|---|---|---|
| Full policy review | Annually | CISO |
| Triggered review (incident, regulatory change, significant platform change) | As needed | CISO |
| RBAC model review | Quarterly | SOC Manager + CISO |
| Classification scheme review | Annually | Security Architect |
| AI-specific controls review | Semi-annually | AI/ML Engineering Lead + Security Architect |
| Board reporting | Quarterly | CISO |

---

## 9. Related Documents

| Document ID | Title |
|---|---|
| ALUSKORT-ISMS-00 | ISMS Scope Statement |
| ALUSKORT-ISMS-02 | Risk Assessment and Treatment |
| ALUSKORT-ISMS-03 | Access Control Policy |
| ALUSKORT-ISMS-04 | Cryptographic Controls |
| ALUSKORT-ISMS-05 | Operations Security |
| ALUSKORT-ISMS-06 | Communications Security |
| ALUSKORT-ISMS-07 | Supplier Relationships |
| ALUSKORT-ISMS-08 | Incident Management |
| ALUSKORT-ISMS-09 | Business Continuity |
| ALUSKORT-ISMS-10 | Data Protection and Privacy |
| ALUSKORT-ISMS-11 | AI-Specific Security Controls |
| ALUSKORT-ISMS-12 | Statement of Applicability |
| ALUSKORT-ISMS-13 | Audit Trail Technical Specification |

---

## 10. Document Control

| Version | Date | Author | Changes |
|---|---|---|---|
| 1.0 | 2026-03-29 | CISO | Initial release |

---

*This document is part of the ALUSKORT SOC Platform ISMS. It shall be reviewed annually or upon significant change to the platform, organisation, or regulatory environment.*
