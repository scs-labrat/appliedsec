# Data Protection and Privacy

**Document ID:** ALUSKORT-ISMS-10
**Version:** 1.0
**Classification:** Confidential
**Owner:** CISO (acting as Data Protection Officer liaison)
**Approved by:** CISO, Applied Computing Technologies
**Effective date:** 2026-03-29
**Review date:** 2027-03-29
**Standard reference:** ISO/IEC 27001:2022 Annex A.5.34, A.8.10--8.12

---

## 1. Purpose

This document defines the data protection and privacy controls for the ALUSKORT SOC Platform, covering personal data processing, the PII redaction pipeline, deanonymisation controls, data retention, classification, tenant isolation, data subject rights, cross-border transfers, and the Data Protection Impact Assessment (DPIA).

---

## 2. Personal Data Processed by ALUSKORT

### 2.1 Categories of Personal Data

| Data Category | Examples | Source | Lawful Basis | Retention |
|---|---|---|---|---|
| **Security alert entities** | IP addresses, email addresses, usernames, hostnames, file hashes associated with security events | Tenant SIEM integrations | Legitimate interest (security monitoring) / Contractual (tenant agreement) | Per tenant tier retention policy |
| **User account data** | Analyst names, email addresses, role assignments, authentication identifiers | User provisioning | Contractual (employment / service agreement) | Duration of account + 1 year |
| **Investigation data** | Entity correlations, behavioural patterns, threat actor attributions that may include personal data | AI investigation pipeline | Legitimate interest (security monitoring) | Per tenant tier retention policy |
| **Audit trail records** | User IDs, IP addresses of analysts, action timestamps | Platform audit system | Legal obligation (compliance) / Legitimate interest | Per tenant tier retention (min 1 year) |
| **LLM interaction logs** | PII-redacted prompt summaries (may contain residual personal references) | LLM Router logging | Legitimate interest (AI oversight and compliance) | 180 days |

### 2.2 Data Subjects

| Data Subject Category | Relationship | Data Types |
|---|---|---|
| SOC Analysts (platform users) | Direct users of the platform | Account data, access logs, actions in audit trail |
| Threat actors / suspects | Entities identified in security alerts | IP addresses, email addresses, usernames, behavioural patterns |
| Employees of tenant organisations | May appear in security alert data | Email addresses, usernames, IP addresses, device identifiers |
| Third parties | May appear in security alert data (e.g., external IP addresses) | IP addresses, domain names |

### 2.3 Processing Activities Register

| Activity | Purpose | Data Types | Legal Basis | Recipients | Transfer |
|---|---|---|---|---|---|
| Alert ingestion | Receive and normalise security alerts | Alert entity data (IPs, emails, usernames) | Legitimate interest / Contract | Internal services | No |
| AI triage | Classify and prioritise alerts | Alert entity data | Legitimate interest / Contract | Internal services, LLM provider (redacted) | To LLM provider (redacted) |
| AI investigation | Investigate and correlate security events | Alert entity data, enrichment data | Legitimate interest / Contract | Internal services, LLM provider (redacted) | To LLM provider (redacted) |
| PII redaction | Remove personal data before LLM processing | All personal data in alert context | Data protection by design | Context Gateway (internal) | No |
| LLM inference | AI-powered analysis via Claude API | PII-redacted alert context | Legitimate interest | Anthropic (redacted data only) | Cross-border (see section 9) |
| Audit logging | Compliance and accountability | User IDs, actions, timestamps | Legal obligation | Internal audit service | No |
| Evidence packaging | Compliance evidence for tenants | Investigation data (may include personal data) | Contract | Tenant (data controller) | To tenant |

---

## 3. PII Redaction Pipeline (A.8.11)

### 3.1 Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                      Context Gateway                             │
│                                                                   │
│  ┌────────────┐    ┌────────────┐    ┌────────────┐             │
│  │ 1. Injection│    │ 2. PII     │    │ 3. Prompt  │             │
│  │   Detection │───►│   Redaction│───►│   Assembly │             │
│  └────────────┘    └─────┬──────┘    └─────┬──────┘             │
│                          │                  │                     │
│                    ┌─────┴──────┐     ┌─────┴──────┐             │
│                    │ Deanon.    │     │ Structured  │             │
│                    │ Map Store  │     │ Evidence    │             │
│                    │ (encrypted)│     │ Isolation   │             │
│                    └────────────┘     └─────┬──────┘             │
│                                             │                     │
│                                       ┌─────┴──────┐             │
│                                       │ 4. Output  │             │
│                                       │  Validation│             │
│                                       └────────────┘             │
└─────────────────────────────────────────────────────────────────┘
```

### 3.2 PII Detection and Redaction

| PII Type | Detection Method | Redaction Format | Example |
|---|---|---|---|
| Email addresses | Regex + NER | `[EMAIL_REDACTED_<hash>]` | `john.doe@company.com` → `[EMAIL_REDACTED_a1b2c3]` |
| IP addresses (IPv4/IPv6) | Regex | `[IP_REDACTED_<hash>]` | `192.168.1.100` → `[IP_REDACTED_d4e5f6]` |
| Usernames | NER + context analysis | `[USER_REDACTED_<hash>]` | `jdoe` → `[USER_REDACTED_g7h8i9]` |
| Phone numbers | Regex + NER | `[PHONE_REDACTED_<hash>]` | `+44 7700 900123` → `[PHONE_REDACTED_j0k1l2]` |
| National ID numbers | Regex (per-country patterns) | `[ID_REDACTED_<hash>]` | `AB 12 34 56 C` → `[ID_REDACTED_m3n4o5]` |
| Credit card numbers | Luhn-validated regex | `[CARD_REDACTED_<hash>]` | `4111 1111 1111 1111` → `[CARD_REDACTED_p6q7r8]` |
| Hostnames (with owner context) | Regex + DNS pattern | `[HOST_REDACTED_<hash>]` | `jdoe-laptop.corp.com` → `[HOST_REDACTED_s9t0u1]` |
| Physical addresses | NER | `[ADDRESS_REDACTED_<hash>]` | Full address → `[ADDRESS_REDACTED_v2w3x4]` |
| Names (natural person) | NER (spaCy/custom model) | `[NAME_REDACTED_<hash>]` | `John Doe` → `[NAME_REDACTED_y5z6a7]` |

### 3.3 Redaction Integrity

| Control | Implementation |
|---|---|
| Hash consistency | Same PII value always produces same redaction hash (deterministic within investigation context) |
| Contextual coherence | Redacted references remain consistent across the investigation (same entity → same hash) |
| Redaction verification | Output validation checks for PII patterns in LLM responses |
| Redaction coverage | > 99.5% detection rate target; regular testing with synthetic PII datasets |
| False positive handling | Over-redaction preferred to under-redaction (safety-first approach) |

---

## 4. Deanonymisation Controls

### 4.1 Deanonymisation Map

| Aspect | Details |
|---|---|
| Purpose | Map redaction tokens back to original PII for investigation context when needed |
| Storage | Encrypted (AES-256-GCM) per-tenant storage in PostgreSQL |
| Encryption key | Per-tenant DEK, encrypted by platform KEK |
| Access control | `senior_analyst` and `admin` roles only; access logged in audit trail |
| Lifetime | Maps retained for the same period as the associated investigation data |
| Deletion | Maps deleted when associated investigation data is purged |

### 4.2 Deanonymisation Access Controls

| Control | Implementation |
|---|---|
| Role restriction | Only `senior_analyst` and `admin` can request deanonymisation |
| Audit logging | Every deanonymisation request recorded in hash-chain audit trail |
| Justification required | Deanonymisation request must include justification reason |
| Rate limiting | Maximum 50 deanonymisation requests per hour per user |
| Alert on anomaly | > 20 deanonymisation requests in 10 minutes triggers alert to CISO |
| Bulk deanonymisation | Prohibited; only individual entity deanonymisation permitted |
| Export restriction | Deanonymised data cannot be exported from the platform without admin approval |

---

## 5. Data Retention Policies (A.8.10)

### 5.1 Retention Schedule

| Data Type | Trial Tier | Standard Tier | Premium Tier | Legal Minimum |
|---|---|---|---|---|
| Security alerts | 30 days | 180 days | 365 days | N/A |
| Investigation records | 30 days | 180 days | 365 days | N/A |
| AI agent decision chains | 30 days | 180 days | 365 days | N/A |
| Audit trail records | 90 days | 365 days | 365 days | 1 year (regulatory) |
| Evidence packages | 30 days | 180 days | 365 days | N/A |
| LLM inference logs | 30 days | 180 days | 180 days | N/A |
| User account data | Account life + 30 days | Account life + 1 year | Account life + 1 year | Account life + 1 year |
| Deanonymisation maps | Same as investigation | Same as investigation | Same as investigation | N/A |
| Application logs | 30 days | 90 days | 90 days | N/A |
| Backup data | 7 days | 30 days | 30 days | N/A |
| Kafka messages | 3 days | 7 days | 7 days | N/A |

### 5.2 Retention Enforcement

| Control | Implementation |
|---|---|
| Automated purging | Scheduled jobs delete data beyond retention period |
| Purge verification | Post-purge verification confirms data removal |
| Cascade deletion | When investigation deleted, all related data (evidence, LLM logs, deanon maps) also deleted |
| Audit of purging | Purge actions recorded in audit trail (but purged records are not stored -- only purge event) |
| Legal hold | Data subject to legal hold is exempt from automated purging until hold released |
| Backup alignment | Backups older than retention period are purged on schedule |

---

## 6. Data Classification Scheme (A.5.12, A.5.13)

| Classification | Definition | Examples in ALUSKORT | Handling Requirements |
|---|---|---|---|
| **Restricted** | Highest sensitivity; unauthorised disclosure causes severe harm | API keys, mTLS private keys, deanonymisation maps, tenant encryption keys, admin credentials | Encrypted at rest + transit; named-individual access only; full audit; no external sharing |
| **Confidential** | Sensitive; unauthorised disclosure causes significant harm | Tenant alert data, investigation findings, AI agent prompts, audit records, PII (pre-redaction), RBAC config | Encrypted at rest + transit; RBAC-controlled access; audit logged; NDA for external sharing |
| **Internal** | For internal use; unauthorised disclosure causes limited harm | Architecture documents, deployment procedures, monitoring dashboards, redacted LLM logs | Access limited to staff; not externally shared without approval |
| **Public** | Approved for public disclosure | Published API documentation, status page, marketing content | No restrictions; must be approved before publication |

### 6.1 Classification Responsibilities

| Role | Responsibility |
|---|---|
| Data owner (per asset) | Assign classification at creation; review periodically |
| Security Architect | Define classification criteria; review disputes |
| All personnel | Handle data according to its classification |
| CISO | Approve declassification requests |

---

## 7. Tenant Data Isolation (A.8.11)

### 7.1 Isolation Controls Matrix

| Layer | Isolation Mechanism | Verification |
|---|---|---|
| **API** | Tenant ID extracted from authenticated session; injected into all downstream calls | Automated integration tests; penetration testing |
| **Application** | Tenant ID mandatory parameter on all data access functions | Code review; static analysis |
| **PostgreSQL** | `WHERE tenant_id = :id` on all queries; Row-Level Security (planned) | Query logging and review; RLS testing |
| **Redis** | Key prefix: `tenant:{id}:` | Key pattern audit |
| **Qdrant** | Tenant-scoped collections or metadata filter | Collection access testing |
| **Neo4j** | Tenant property on all nodes; Cypher query filters | Query review; isolation testing |
| **Kafka** | Tenant ID in message key; consumer filtering | Message audit |
| **MinIO** | Bucket path prefix: `tenant-{id}/` | Bucket policy review |
| **Audit trail** | Per-tenant hash chains with independent genesis blocks | Hash-chain verification |
| **LLM context** | Tenant context isolated per request; no cross-tenant data in prompts | Prompt audit; output validation |

### 7.2 Cross-Tenant Access Prevention

| Control | Implementation |
|---|---|
| Middleware enforcement | Tenant ID validated and injected at API gateway; cannot be spoofed by client |
| No cross-tenant queries | Application code has no mechanism to query across tenants (except admin audit) |
| Admin cross-tenant access | Admin can view cross-tenant data only via explicit admin audit endpoints; all access logged |
| Testing | Automated cross-tenant access tests in CI pipeline; penetration testing annually |
| Monitoring | Alert on any cross-tenant query attempt (should be 0 in normal operation) |

---

## 8. Data Subject Rights

### 8.1 Rights Applicable to ALUSKORT

| Right | Applicability | Implementation |
|---|---|---|
| **Right of access (Article 15)** | Applicable for analyst accounts; limited for security alert subjects | Account data: export via admin API; Alert subjects: tenant responsibility as data controller |
| **Right to rectification (Article 16)** | Applicable for analyst accounts | Admin can update account data; audit trail records are immutable (correction via new record) |
| **Right to erasure (Article 17)** | Applicable for analyst accounts; complex for security alert data | Account deletion: data purged per retention policy; Alert data: tenant decision as controller; audit trail: anonymisation rather than deletion (integrity) |
| **Right to restriction (Article 18)** | Applicable | Data can be flagged for restricted processing |
| **Right to portability (Article 20)** | Applicable for analyst accounts | Account data export in machine-readable format |
| **Right to object (Article 21)** | Limited -- security monitoring is legitimate interest | Assessed case by case; tenant contractual basis typically applies |

### 8.2 Erasure Considerations for Audit Trail

The immutable hash-chain audit trail presents a specific challenge for right to erasure:

| Approach | Implementation |
|---|---|
| **Anonymisation** (preferred) | Replace personal data in audit records with anonymised tokens; hash-chain integrity maintained as content hash changes are documented in a correction record |
| **Tombstone records** | Mark records as "erased" while maintaining hash-chain links; record content replaced with deletion notice |
| **Legal justification** | Document lawful basis for retaining anonymised audit records (legal obligation for compliance, legitimate interest for security) |
| **Tenant responsibility** | Tenants as data controllers make erasure decisions for alert entity data; ALUSKORT provides the mechanism |

---

## 9. Cross-Border Data Transfer (A.5.34)

### 9.1 Transfer Mapping

| Transfer | Source | Destination | Data Types | Mechanism |
|---|---|---|---|---|
| LLM inference (Anthropic) | ALUSKORT platform (UK/EU) | Anthropic servers (US) | PII-redacted alert context, investigation prompts | Standard Contractual Clauses (SCCs); DPA; PII redaction |
| LLM inference (OpenAI fallback) | ALUSKORT platform (UK/EU) | OpenAI servers (US) | PII-redacted alert context | SCCs; DPA; PII redaction |
| Cloud infrastructure | Platform data | Cloud provider regions | All platform data (encrypted) | Cloud provider DPA; SCCs; encryption |

### 9.2 Transfer Safeguards

| Safeguard | Implementation |
|---|---|
| PII redaction | All personal data redacted before transmission to LLM providers |
| Encryption in transit | TLS 1.3 for all cross-border transfers |
| Data Processing Agreement | DPAs with all international data recipients |
| Standard Contractual Clauses | SCCs incorporated into supplier agreements |
| Transfer Impact Assessment | Conducted for each international transfer route |
| Data minimisation | Only necessary context sent to LLM providers; no bulk data transfer |
| Provider no-training clause | Contractual prohibition on using transferred data for model training |
| Provider data retention | Maximum 30-day retention at provider (contractual) |

---

## 10. Data Protection Impact Assessment (DPIA) Summary

### 10.1 DPIA Requirement Assessment

A DPIA is required for the ALUSKORT platform because the processing:
- Involves systematic monitoring of individuals (security alert processing)
- Uses innovative technology (AI/LLM-based automated analysis)
- Involves large-scale processing of personal data
- Involves automated decision-making with potential significant effects

### 10.2 DPIA Summary

| Aspect | Assessment |
|---|---|
| **Processing description** | AI-powered analysis of security alerts containing personal data (IP addresses, usernames, email addresses) from tenant SIEMs, using LLM inference for investigation and response recommendation |
| **Necessity and proportionality** | Processing is necessary for the legitimate purpose of security monitoring; data minimisation through PII redaction; only security-relevant data processed; automated decisions subject to human oversight |
| **Risks to data subjects** | (1) PII leakage through LLM context windows; (2) Cross-tenant data exposure; (3) Inaccurate AI profiling of threat actors; (4) Re-identification from redacted data; (5) Excessive data retention |
| **Mitigation measures** | PII redaction pipeline; multi-layer tenant isolation; human-in-the-loop approval; deanonymisation access controls; automated retention enforcement; audit trail for all data access |
| **Residual risk** | Low -- comprehensive technical and organisational measures in place |
| **DPO consultation** | DPO consulted and approves processing with current safeguards |
| **Review schedule** | Annual review or upon significant processing changes |

### 10.3 DPIA Risk Register

| Risk | Likelihood | Impact | Mitigation | Residual Risk |
|---|---|---|---|---|
| PII leakage via LLM | Low (redaction in place) | High | PII redaction pipeline; output validation; no-training clause | Low |
| Cross-tenant data exposure | Low (isolation controls) | High | Multi-layer tenant isolation; automated testing | Low |
| AI bias in threat profiling | Medium | Medium | Human oversight; FP monitoring; bias evaluation | Low |
| Re-identification from redacted data | Low | Medium | Deterministic redaction within context only; deanon maps encrypted | Low |
| Excessive data retention | Low (automated) | Medium | Automated purge schedules; retention policy enforcement | Low |
| Unauthorised deanonymisation | Low (access controls) | High | RBAC; audit logging; rate limiting; anomaly alerts | Low |

---

## 11. Document Control

| Version | Date | Author | Changes |
|---|---|---|---|
| 1.0 | 2026-03-29 | CISO | Initial release |

---

*This document is part of the ALUSKORT SOC Platform ISMS. It shall be reviewed annually, upon regulatory changes, or upon significant changes to personal data processing activities.*
