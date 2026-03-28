# Statement of Applicability (SoA)

**Document ID:** ALUSKORT-ISMS-12
**Version:** 1.0
**Classification:** Confidential
**Owner:** CISO
**Approved by:** CISO, Applied Computing Technologies
**Effective date:** 2026-03-29
**Review date:** 2027-03-29
**Standard reference:** ISO/IEC 27001:2022 Clause 6.1.3 d)

---

## 1. Purpose

This Statement of Applicability (SoA) documents all 93 controls from ISO/IEC 27001:2022 Annex A, their applicability to the ALUSKORT SOC Platform, implementation status, and specific implementation details. This is a mandatory document for ISO 27001 certification.

### Implementation Status Key

| Status | Definition |
|---|---|
| **Implemented** | Control is fully implemented and operational |
| **Partially Implemented** | Control is implemented but with gaps or limitations identified for remediation |
| **Planned** | Control is not yet implemented; implementation is scheduled |
| **Not Applicable** | Control is not applicable to the ALUSKORT SOC Platform with documented justification |

---

## 2. A.5 -- Organisational Controls (37 Controls)

| Control ID | Control Name | Applicable | Status | Implementation Details | Document Ref |
|---|---|---|---|---|---|
| A.5.1 | Policies for information security | Yes | Implemented | Information security policy established, approved by Board, reviewed annually | ISMS-01 |
| A.5.2 | Information security roles and responsibilities | Yes | Implemented | CISO, SOC Manager, analysts, engineers defined with clear responsibilities; RACI documented | ISMS-01 §3 |
| A.5.3 | Segregation of duties | Yes | Implemented | Two-person FP pattern approval; admin cannot self-approve; code review + CI/CD approval for deployments | ISMS-01 §4.3 |
| A.5.4 | Management responsibilities | Yes | Implemented | Board oversight; CISO quarterly reporting; management commitment in policy | ISMS-01 |
| A.5.5 | Contact with authorities | Yes | Implemented | Regulatory notification procedures (ICO, ENISA); law enforcement contacts documented | ISMS-08 §6 |
| A.5.6 | Contact with special interest groups | Yes | Implemented | Membership in MITRE ATLAS community; threat intelligence sharing groups; CERT coordination | ISMS-02 |
| A.5.7 | Threat intelligence | Yes | Implemented | CTEM integration; MITRE ATLAS framework; threat feeds consumed by enrichment agent; continuous threat monitoring | ISMS-05 §7 |
| A.5.8 | Information security in project management | Yes | Implemented | Security review gate in sprint process; Security Architect reviews all feature designs; threat modelling for new features | ISMS-01 |
| A.5.9 | Inventory of information and other associated assets | Yes | Implemented | Full asset inventory maintained (services, databases, AI components, credentials); asset register in ISMS-02 | ISMS-02 §3 |
| A.5.10 | Acceptable use of information and other associated assets | Yes | Implemented | Acceptable use policy defines permitted and prohibited platform uses | ISMS-01 §5 |
| A.5.11 | Return of assets | Yes | Partially Implemented | Leaver process includes account disablement and credential revocation; physical asset return managed by corporate IT | ISMS-03 §8.3 |
| A.5.12 | Classification of information | Yes | Implemented | Four-level classification: Public, Internal, Confidential, Restricted; applied to all ALUSKORT data | ISMS-01 §6, ISMS-10 §6 |
| A.5.13 | Labelling of information | Yes | Partially Implemented | Document headers include classification; database records classified by type; automated labelling planned for dashboard exports | ISMS-10 §6 |
| A.5.14 | Information transfer | Yes | Implemented | TLS 1.3 for all transfers; mTLS inter-service; PII redaction before LLM transfer; encrypted evidence export | ISMS-06 §8 |
| A.5.15 | Access control | Yes | Implemented | RBAC with three roles (analyst, senior_analyst, admin); default deny; tenant isolation | ISMS-03 |
| A.5.16 | Identity management | Yes | Implemented | Unique user IDs; OIDC identity management (planned); service identities via mTLS certificates | ISMS-03 §4 |
| A.5.17 | Authentication information | Yes | Implemented | OIDC tokens (production); mTLS certificates (inter-service); API keys (SIEM); Argon2id password hashing | ISMS-03 §4, ISMS-04 |
| A.5.18 | Access rights | Yes | Implemented | Least privilege RBAC; quarterly access reviews; JML process; privileged access management for admin role | ISMS-03 §5, §8 |
| A.5.19 | Information security in supplier relationships | Yes | Implemented | Supplier security policy; assessment process; contractual requirements; Anthropic DPA requirements | ISMS-07 |
| A.5.20 | Addressing information security within supplier agreements | Yes | Implemented | Security clauses in supplier contracts; DPA requirements; SLA commitments; incident notification requirements | ISMS-07 §4 |
| A.5.21 | Managing information security in the ICT supply chain | Yes | Implemented | Open source dependency scanning (Snyk); container image verification; SBOM generation; supply chain risk assessment | ISMS-07 §3.3 |
| A.5.22 | Monitoring, review and change management of supplier services | Yes | Implemented | Continuous availability monitoring; annual certification review; performance metrics; non-compliance handling | ISMS-07 §5 |
| A.5.23 | Information security for use of cloud services | Yes | Implemented | Cloud provider assessment; shared responsibility model documented; encryption controls; contractual requirements | ISMS-07 §3.2 |
| A.5.24 | Information security incident management planning and preparation | Yes | Implemented | Incident response plan; team structure; on-call rotation; communication templates; evidence preservation procedures | ISMS-08 |
| A.5.25 | Assessment and decision on information security events | Yes | Implemented | Four-severity classification (P1-P4); incident categories defined; triage procedure documented | ISMS-08 §3 |
| A.5.26 | Response to information security incidents | Yes | Implemented | Kill switch procedure; canary rollback; escalation matrix; communication plan; audit trail verification | ISMS-08 §5 |
| A.5.27 | Learning from information security incidents | Yes | Implemented | Post-incident review process; root cause analysis; lessons learned integration; risk register updates | ISMS-08 §9 |
| A.5.28 | Collection of evidence | Yes | Implemented | Evidence collection checklist; chain of custody; hash-verified evidence packages; audit trail export | ISMS-08 §8 |
| A.5.29 | Information security during disruption | Yes | Implemented | BCP for ALUSKORT platform; RPO/RTO targets; DR procedures; failover capabilities | ISMS-09 |
| A.5.30 | ICT readiness for business continuity | Yes | Implemented | Multi-level resilience (pod, node, AZ, region); automated failover; DR testing schedule | ISMS-09 §3 |
| A.5.31 | Legal, statutory, regulatory and contractual requirements | Yes | Implemented | Applicable requirements documented (UK DPA, GDPR, EU AI Act, NIS2); compliance monitoring | ISMS-00 §6 |
| A.5.32 | Intellectual property rights | Yes | Implemented | OSS licence compliance scanning; prompt templates classified as Restricted; IP assignments in contracts | ISMS-07 §3.3 |
| A.5.33 | Protection of records | Yes | Implemented | Immutable hash-chain audit trail; retention policies per data type; encrypted backup; tamper detection | ISMS-13, ISMS-10 §5 |
| A.5.34 | Privacy and protection of PII | Yes | Implemented | DPIA completed; PII redaction pipeline; deanonymisation controls; data subject rights procedures; cross-border transfer safeguards | ISMS-10 |
| A.5.35 | Independent review of information security | Yes | Planned | Annual external audit planned; internal audit capability being established | ISMS-01 §7 |
| A.5.36 | Compliance with policies, rules and standards for information security | Yes | Implemented | Automated compliance monitoring via audit trail; quarterly access reviews; annual ISMS audit | ISMS-01 §7 |
| A.5.37 | Documented operating procedures | Yes | Implemented | Operational procedures documented for all services; runbooks for incident response; DR procedures | ISMS-05, ISMS-08, ISMS-09 |

---

## 3. A.6 -- People Controls (8 Controls)

| Control ID | Control Name | Applicable | Status | Implementation Details | Document Ref |
|---|---|---|---|---|---|
| A.6.1 | Screening | Yes | Implemented | Background checks for all personnel with access to Restricted data; enhanced vetting for admin role holders | ISMS-01 |
| A.6.2 | Terms and conditions of employment | Yes | Implemented | Security responsibilities included in employment contracts; NDA for all platform personnel; acceptable use agreement | ISMS-01 §5 |
| A.6.3 | Information security awareness, education and training | Yes | Partially Implemented | Security awareness training at onboarding; AI-specific security training for engineers; annual refresher; adversarial AI training planned for analysts | ISMS-01 |
| A.6.4 | Disciplinary process | Yes | Implemented | Non-compliance consequences defined in policy; graduated response from access revocation to legal action | ISMS-01 §7.2 |
| A.6.5 | Responsibilities after termination or change of employment | Yes | Implemented | JML process: immediate account disable; credential revocation; audit trail review; NDA remains effective | ISMS-03 §8.3 |
| A.6.6 | Confidentiality or non-disclosure agreements | Yes | Implemented | NDA required for all personnel and contractors; supplier NDAs; tenant confidentiality in service agreements | ISMS-01, ISMS-07 |
| A.6.7 | Remote working | Yes | Implemented | Platform accessed via OIDC-authenticated HTTPS; no VPN required (zero-trust model); device security requirements defined | ISMS-03 §4 |
| A.6.8 | Information security event reporting | Yes | Implemented | Incident reporting procedure; automated alerting (12 Prometheus rules); analyst can report via dashboard; anonymous reporting channel | ISMS-08 §3 |

---

## 4. A.7 -- Physical Controls (14 Controls)

| Control ID | Control Name | Applicable | Status | Implementation Details | Document Ref |
|---|---|---|---|---|---|
| A.7.1 | Physical security perimeters | No | Not Applicable | Cloud-hosted platform; no physical data centre operated by Applied Computing Technologies. Cloud provider physical security covered by their ISO 27001 certification. | ISMS-00 §5.2 |
| A.7.2 | Physical entry | No | Not Applicable | No physical facility in scope. Cloud provider manages physical access to data centres. | ISMS-00 §5.2 |
| A.7.3 | Securing offices, rooms and facilities | No | Not Applicable | No dedicated offices in scope; corporate office security managed by separate ISMS. Remote-first team. | ISMS-00 §5.2 |
| A.7.4 | Physical security monitoring | No | Not Applicable | Cloud provider responsibility. No physical infrastructure operated. | ISMS-00 §5.2 |
| A.7.5 | Protecting against physical and environmental threats | No | Not Applicable | Cloud provider responsibility. Multi-AZ/multi-region deployment provides resilience. | ISMS-09 §3 |
| A.7.6 | Working in secure areas | No | Not Applicable | No secure physical areas operated. | ISMS-00 §5.2 |
| A.7.7 | Clear desk and clear screen | Yes | Partially Implemented | Clear screen policy for analysts; automatic session timeout (30 min idle); screen lock enforced by endpoint management | ISMS-03 §7 |
| A.7.8 | Equipment siting and protection | No | Not Applicable | Cloud-hosted; no physical equipment to site. Endpoint devices managed by corporate IT. | ISMS-00 §5.2 |
| A.7.9 | Security of assets off-premises | Yes | Partially Implemented | Endpoint device encryption required; remote access via OIDC/HTTPS; no platform data stored on endpoints | ISMS-03 §4 |
| A.7.10 | Storage media | Yes | Implemented | Cloud storage encrypted at rest (AES-256); evidence package export encrypted; no removable media policy for platform data | ISMS-04 §3 |
| A.7.11 | Supporting utilities | No | Not Applicable | Cloud provider responsibility (power, cooling, network). Cloud SLA covers availability. | ISMS-07 §3.2 |
| A.7.12 | Cabling security | No | Not Applicable | Cloud provider responsibility. No physical network infrastructure operated. | ISMS-00 §5.2 |
| A.7.13 | Equipment maintenance | No | Not Applicable | Cloud-managed infrastructure; Kubernetes handles compute lifecycle. | ISMS-00 §5.2 |
| A.7.14 | Secure disposal or re-use of equipment | No | Not Applicable | Cloud provider handles hardware disposal per their ISO 27001. Cryptographic erasure used for data deletion. | ISMS-04 §6 |

---

## 5. A.8 -- Technological Controls (34 Controls)

| Control ID | Control Name | Applicable | Status | Implementation Details | Document Ref |
|---|---|---|---|---|---|
| A.8.1 | User endpoint devices | Yes | Partially Implemented | Endpoint security requirements defined; device encryption required; platform accessed via browser (no agent installation); endpoint management integration planned | ISMS-03 |
| A.8.2 | Privileged access rights | Yes | Implemented | Admin role restricted to max 5 accounts; CISO approval required; quarterly review; all admin actions audited; break-glass procedure documented | ISMS-03 §5 |
| A.8.3 | Information access restriction | Yes | Implemented | RBAC enforces per-role data access; tenant isolation at all layers; default deny policy | ISMS-03 §3.2, §6 |
| A.8.4 | Access to source code | Yes | Implemented | Source code in private Git repository; branch protection; peer review required for merge; no public code exposure | ISMS-05 |
| A.8.5 | Secure authentication | Yes | Implemented | OIDC with JWT (production); mTLS for inter-service; API keys for SIEM; Argon2id for any stored passwords; MFA for admin (planned) | ISMS-03 §4, ISMS-04 |
| A.8.6 | Capacity management | Yes | Implemented | Resource monitoring with Prometheus; HPA for auto-scaling; per-tenant quotas; capacity alerts at 70%/85% thresholds | ISMS-05 §3 |
| A.8.7 | Protection against malware | Yes | Implemented | Container image scanning (Trivy); read-only root filesystem; non-root containers; runtime monitoring (Falco); no user file uploads to platform (except SIEM data via API) | ISMS-05 §8 |
| A.8.8 | Management of technical vulnerabilities | Yes | Implemented | CTEM integration; container/dependency scanning (Snyk/Trivy); SAST (Semgrep); DAST (ZAP); patch management SLAs defined | ISMS-05 §7 |
| A.8.9 | Configuration management | Yes | Implemented | GitOps for K8s configuration; infrastructure as code; config drift detection; immutable container images; environment-specific configs | ISMS-05 §2, §4 |
| A.8.10 | Information deletion | Yes | Implemented | Automated retention enforcement; cascade deletion for related data; purge verification; legal hold support; deanonymisation map deletion | ISMS-10 §5 |
| A.8.11 | Data masking | Yes | Implemented | PII redaction pipeline in Context Gateway; deterministic redaction with deanonymisation maps; log sanitisation; credential redaction | ISMS-10 §3 |
| A.8.12 | Data leakage prevention | Yes | Implemented | PII redaction before LLM; output validation; egress network controls; DLP scanning on exports; credential pattern detection in logs | ISMS-10 §3, ISMS-06 §3.3 |
| A.8.13 | Information backup | Yes | Implemented | PostgreSQL WAL + daily full backup; Redis RDB snapshots; Kafka MirrorMaker 2; MinIO cross-site replication; encrypted backups; regular restore testing | ISMS-05 §5 |
| A.8.14 | Redundancy of information processing facilities | Yes | Implemented | Multi-pod deployment (HPA); multi-AZ K8s cluster; PostgreSQL read replicas; Kafka replication factor 3; warm DR region standby | ISMS-09 §3 |
| A.8.15 | Logging | Yes | Implemented | Immutable hash-chain audit trail; application logs; LLM inference logs; security logs; infrastructure logs; centralised logging; PII-sanitised | ISMS-05 §6, ISMS-13 |
| A.8.16 | Monitoring activities | Yes | Implemented | Prometheus with 12 alerting rules; Grafana dashboards; Kafka consumer lag monitoring; certificate expiry monitoring; anomaly detection | ISMS-05 §6.3 |
| A.8.17 | Clock synchronisation | Yes | Implemented | All K8s nodes synchronised via NTP (chrony); < 1ms drift tolerance; UTC timestamps across all services; audit trail timestamp verification | ISMS-05 §6.4 |
| A.8.18 | Use of privileged utility programs | Yes | Implemented | No direct database or OS access in production; admin actions through platform API only; kubectl access restricted and audited | ISMS-03 §5 |
| A.8.19 | Installation of software on operational systems | Yes | Implemented | Immutable container images; no runtime package installation; container images built by CI/CD only; image signing and verification | ISMS-05 §2 |
| A.8.20 | Networks security | Yes | Implemented | K8s network policies (default deny); namespace isolation; mTLS inter-service; TLS 1.3 external; Kafka ACLs; ingress controller | ISMS-06 |
| A.8.21 | Security of network services | Yes | Implemented | Cloud provider managed network; K8s NetworkPolicy enforcement; ingress controller with rate limiting; WAF for DDoS protection | ISMS-06 §7 |
| A.8.22 | Segregation of networks | Yes | Implemented | Four K8s namespaces (app, data, monitor, system); network policies enforce segment boundaries; data namespace not externally accessible | ISMS-06 §3 |
| A.8.23 | Web filtering | Yes | Implemented | Egress network policies restrict outbound connections to known destinations only (Anthropic, OpenAI, SIEM endpoints, ACME CA) | ISMS-06 §3.3 |
| A.8.24 | Use of cryptography | Yes | Implemented | AES-256-GCM at rest; TLS 1.3 in transit; SHA-256 hash-chain; ECDSA certificates; approved algorithm list; key management lifecycle | ISMS-04 |
| A.8.25 | Secure development life cycle | Yes | Implemented | Secure SDLC: peer code review, SAST, DAST, dependency scanning, security design review, threat modelling; CI/CD security gates | ISMS-05 §2, §7 |
| A.8.26 | Application security requirements | Yes | Implemented | Input validation (JSON schema); output validation (deny-by-default); authentication/authorisation; rate limiting; injection prevention | ISMS-03, ISMS-06 §5, ISMS-11 §5 |
| A.8.27 | Secure system architecture and engineering principles | Yes | Implemented | Microservice isolation; defence in depth; zero trust (mTLS); Context Gateway as security layer; immutable infrastructure; least privilege | ISMS-01 §4.2 |
| A.8.28 | Secure coding | Yes | Implemented | Secure coding guidelines; SAST enforcement; peer review; no hardcoded credentials; parameterised queries; structured prompt assembly | ISMS-05 §7 |
| A.8.29 | Security testing in development and acceptance | Yes | Implemented | Security scans in CI (SAST, SCA, image scan); DAST in staging; penetration testing annually; adversarial AI testing quarterly | ISMS-05 §7.2 |
| A.8.30 | Outsourced development | Yes | Partially Implemented | Open source dependencies managed via SCA; contributor licence agreements where applicable; no outsourced custom development currently | ISMS-07 §3.3 |
| A.8.31 | Separation of development, test and production environments | Yes | Implemented | Four environments (dev, CI/test, staging, production); separate credentials/data per environment; production access restricted | ISMS-05 §4 |
| A.8.32 | Change management | Yes | Implemented | Four change categories (standard, normal, emergency, significant); approval workflows; canary deployment; automatic rollback | ISMS-05 §2 |
| A.8.33 | Test information | Yes | Implemented | Synthetic data for non-production environments; no production data in dev/test; anonymised sample data for staging; test data generators | ISMS-05 §4.2 |
| A.8.34 | Protection of information systems during audit testing | Yes | Implemented | Audit testing conducted in staging where possible; production testing requires CISO approval; read-only access for auditors; dedicated audit credentials | ISMS-03 |

---

## 6. Summary Statistics

| Category | Total Controls | Implemented | Partially Implemented | Planned | Not Applicable |
|---|---|---|---|---|---|
| A.5 Organisational | 37 | 35 | 1 | 1 | 0 |
| A.6 People | 8 | 7 | 1 | 0 | 0 |
| A.7 Physical | 14 | 2 | 2 | 0 | 10 |
| A.8 Technological | 34 | 32 | 2 | 0 | 0 |
| **Total** | **93** | **76** | **6** | **1** | **10** |

### Partially Implemented Controls -- Remediation Plan

| Control | Gap | Remediation Action | Target Date | Owner |
|---|---|---|---|---|
| A.5.11 Return of assets | Physical asset return managed separately | Integrate physical asset register with platform JML process | Q3 2026 | DevOps Lead |
| A.5.13 Labelling of information | Automated labelling not yet applied to all exports | Implement classification labels on dashboard exports and API responses | Q2 2026 | Platform Eng Lead |
| A.6.3 Security awareness training | AI-specific training for analysts not yet delivered | Develop and deliver adversarial AI awareness module for SOC analysts | Q2 2026 | SOC Manager |
| A.7.7 Clear desk/screen | Endpoint management policy defined but enforcement dependent on corporate IT | Integrate endpoint compliance check into OIDC authentication flow | Q3 2026 | Security Architect |
| A.7.9 Off-premises asset security | Endpoint encryption verification not automated | Implement device posture check at OIDC authentication | Q3 2026 | Security Architect |
| A.8.1 User endpoint devices | Endpoint management integration pending | Deploy endpoint posture assessment with OIDC conditional access | Q3 2026 | Security Architect |
| A.8.30 Outsourced development | OSS contributor agreement tracking not formalised | Establish OSS contribution policy and tracking process | Q3 2026 | Platform Eng Lead |

### Planned Controls -- Implementation Schedule

| Control | Implementation Plan | Target Date | Owner |
|---|---|---|---|
| A.5.35 Independent review | Engage external auditor for independent ISMS review; establish internal audit function | Q4 2026 | CISO |

### Not Applicable Controls -- Justification

All 10 Not Applicable controls are in the A.7 (Physical) category. The ALUSKORT SOC Platform is cloud-hosted with no physical infrastructure operated by Applied Computing Technologies. Physical security is the responsibility of the cloud infrastructure provider, whose ISO 27001 certification and SOC 2 Type II reports are reviewed annually as part of supplier management (ISMS-07). The platform team operates remotely with no dedicated physical facility in scope.

---

## 7. Document Control

| Version | Date | Author | Changes |
|---|---|---|---|
| 1.0 | 2026-03-29 | CISO | Initial release |

---

*This Statement of Applicability is a controlled document within the ALUSKORT SOC Platform ISMS. It shall be reviewed annually, upon significant changes to the platform architecture, and during ISMS management reviews.*
