# Information Security Incident Management

**Document ID:** ALUSKORT-ISMS-08
**Version:** 1.0
**Classification:** Confidential
**Owner:** CISO
**Approved by:** CISO, Applied Computing Technologies
**Effective date:** 2026-03-29
**Review date:** 2027-03-29
**Standard reference:** ISO/IEC 27001:2022 Annex A.5.24--5.28

---

## 1. Purpose

This document defines the security incident management procedures for the ALUSKORT SOC Platform itself (not the security incidents that the platform investigates on behalf of tenants). It covers incident detection, classification, response, recovery, evidence preservation, and post-incident review.

---

## 2. Scope

This procedure covers security incidents affecting the ALUSKORT platform, including:

- Unauthorised access to platform systems or tenant data
- Data breaches involving tenant data, PII, or credentials
- AI system compromise (prompt injection exploitation, model manipulation)
- Platform availability incidents (outages, degradation)
- Audit trail integrity failures
- Supply chain security incidents (LLM provider compromise)
- Insider threat incidents
- Cross-tenant data leakage

---

## 3. Incident Classification (A.5.25)

### 3.1 Severity Levels

| Severity | Definition | Examples | Response Time | Escalation |
|---|---|---|---|---|
| **P1 -- Critical** | Active data breach, total platform outage, audit trail compromise, or active adversarial AI exploitation | Tenant data exfiltration; hash-chain integrity failure; prompt injection bypass causing unauthorised actions; complete investigation pipeline failure | 15 minutes | Immediate CISO notification; all hands |
| **P2 -- High** | Significant security control failure, partial outage affecting multiple tenants, or confirmed adversarial activity | Single tenant data exposure; LLM provider security incident; admin credential compromise; partial service outage > 30 min | 1 hour | CISO notification; incident team assembly |
| **P3 -- Medium** | Security control degradation, limited impact incident, or suspicious activity requiring investigation | Elevated prompt injection attempts; single service degradation; suspicious admin activity; SIEM integration failure | 4 hours | Platform Eng Lead notification |
| **P4 -- Low** | Minor security event with no confirmed impact | Failed authentication spikes; non-critical vulnerability discovered; single pod restart | 24 hours | Logged and tracked |

### 3.2 Incident Categories

| Category | Description | Examples |
|---|---|---|
| **Data Breach** | Unauthorised access to or exfiltration of tenant data or platform credentials | Cross-tenant data leakage; credential exposure; PII leakage via LLM |
| **AI Security** | Compromise or manipulation of AI components | Successful prompt injection; adversarial evasion of detection; agent jailbreak |
| **Availability** | Platform outage or degradation | Investigation pipeline failure; database outage; Kafka cluster failure |
| **Integrity** | Unauthorised modification of platform data or configuration | Audit trail tampering; configuration manipulation; FP pattern poisoning |
| **Access Control** | Unauthorised access or privilege escalation | Admin credential compromise; RBAC bypass; OIDC provider compromise |
| **Supply Chain** | Security incident at a supplier affecting ALUSKORT | Anthropic data breach; cloud provider compromise; OSS supply chain attack |
| **Insider Threat** | Malicious or negligent action by authorised personnel | Admin data exfiltration; intentional misconfiguration; credential sharing |

---

## 4. Incident Response Team

### 4.1 Team Structure

| Role | Primary | Backup | Responsibilities |
|---|---|---|---|
| **Incident Commander** | CISO | Platform Eng Lead | Overall incident coordination; stakeholder communication; regulatory notification decisions |
| **Technical Lead** | Platform Eng Lead | Security Architect | Technical investigation; containment actions; recovery coordination |
| **AI Security Lead** | AI/ML Eng Lead | Security Architect | AI-specific incident analysis; Context Gateway assessment; LLM interaction review |
| **Infrastructure Lead** | DevOps Lead | SRE Engineer | Infrastructure assessment; service restoration; backup/recovery execution |
| **Communications Lead** | CISO | SOC Manager | Tenant notification; regulatory notification; status page updates |
| **Evidence Lead** | Security Architect | DevOps Lead | Evidence preservation; audit trail verification; forensic analysis |

### 4.2 On-Call Rotation

| Time | Coverage | Escalation Path |
|---|---|---|
| Business hours (Mon--Fri 08:00--18:00 UTC) | Full team available | Direct notification |
| Out of hours | On-call engineer (rotating weekly) | PagerDuty → Phone → SMS |
| Weekends / holidays | On-call engineer + on-call manager | PagerDuty → Phone → SMS |

---

## 5. Incident Response Procedures

### 5.1 Response Lifecycle

```
 1. Detection     2. Triage        3. Containment   4. Eradication
    & Reporting      & Classification                    & Recovery
 ┌──────────┐    ┌──────────┐     ┌──────────┐     ┌──────────┐
 │ Alert     │    │ Classify │     │ Isolate  │     │ Remove   │
 │ received  │───►│ severity │────►│ affected │────►│ threat   │
 │ or event  │    │ & type   │     │ systems  │     │ & restore│
 │ reported  │    │          │     │          │     │          │
 └──────────┘    └──────────┘     └──────────┘     └──────────┘
                                                         │
 6. Closure      5. Post-Incident   4b. Evidence         │
    & Tracking      Review             Preservation       │
 ┌──────────┐    ┌──────────┐     ┌──────────┐          │
 │ Close     │    │ Root     │     │ Preserve │          │
 │ incident  │◄───│ cause    │◄────│ logs,    │◄─────────┘
 │ record    │    │ analysis │     │ audit    │
 │           │    │ lessons  │     │ trail    │
 └──────────┘    └──────────┘     └──────────┘
```

### 5.2 Kill Switch Activation Procedure

The kill switch is the emergency mechanism to halt all autonomous AI actions on the ALUSKORT platform.

**When to activate:**
- Confirmed AI agent executing unauthorised actions
- Confirmed prompt injection bypass causing harm
- Audit trail integrity failure (hash-chain break)
- Active data exfiltration via AI components
- Any P1 incident involving AI system compromise

**Activation procedure:**

| Step | Action | Actor | Time |
|---|---|---|---|
| 1 | Decision to activate kill switch | Incident Commander (CISO) or on-call manager | Immediate |
| 2 | Execute kill switch API call (`POST /api/v1/system/kill-switch` with `admin` role) | Technical Lead | < 1 minute |
| 3 | Verify kill switch activation in audit trail | Evidence Lead | < 2 minutes |
| 4 | Confirm all AI agent processing has stopped | AI Security Lead | < 5 minutes |
| 5 | Notify all connected analysts via dashboard and email | Communications Lead | < 10 minutes |
| 6 | Document activation reason in incident record | Incident Commander | < 15 minutes |

**Kill switch effects:**
- All AI agent investigations are paused
- No new LLM API calls are made
- Pending response actions are held (not executed)
- Alert ingestion continues (alerts queued for manual review)
- Audit trail continues recording
- Dashboard displays kill switch status banner

**Deactivation procedure:**
1. Root cause identified and mitigated
2. Deactivation approved by CISO (written justification)
3. Canary reactivation: AI processing enabled for a single non-critical tenant
4. Monitor for 1 hour; verify no recurrence
5. Gradual reactivation across all tenants
6. Full restoration confirmed; documented in incident record

### 5.3 Canary Rollback Procedure

When a deployment introduces a security issue:

| Step | Action | Actor | Time |
|---|---|---|---|
| 1 | Automated detection of anomaly during canary rollout | Monitoring system | Automatic |
| 2 | Automatic rollback triggered (or manual trigger) | CI/CD system / DevOps | < 2 minutes |
| 3 | Verify rollback completion | DevOps Lead | < 5 minutes |
| 4 | Verify service restoration (health checks, hash-chain) | Technical Lead | < 10 minutes |
| 5 | Investigate root cause of canary failure | Technical Lead | Within 4 hours |
| 6 | Document in change management and incident record | DevOps Lead | Within 24 hours |

### 5.4 Audit Trail Verification During Incident

| Step | Action | Purpose |
|---|---|---|
| 1 | Trigger full hash-chain verification for affected tenant(s) | Confirm audit trail integrity |
| 2 | Export audit records for incident time window | Preserve evidence before any system changes |
| 3 | Generate audit package with cryptographic proof | Create tamper-evident evidence bundle |
| 4 | Store audit package in separate, access-controlled location | Prevent evidence contamination |
| 5 | Compare audit records with application logs | Cross-reference for completeness |
| 6 | Document verification results in incident record | Demonstrate evidence integrity |

---

## 6. Escalation Matrix (A.5.26)

| Condition | Escalation To | Method | Timeline |
|---|---|---|---|
| Any P1 incident | CISO + Board representative | Phone + email | Immediate |
| P2 incident not contained within 2 hours | CISO | Phone | 2 hours |
| Confirmed data breach (tenant PII) | CISO → Legal → ICO (if UK GDPR applies) | Per regulatory requirements | 72 hours (regulatory) |
| Confirmed data breach (EU tenant data) | CISO → Legal → Relevant DPA | Per GDPR Article 33 | 72 hours (regulatory) |
| LLM provider security incident | CISO + AI Security Lead | Phone + email | 1 hour |
| Insider threat suspicion | CISO + HR + Legal | Confidential meeting | 4 hours |
| Multi-tenant impact | CISO + all tenant account managers | Email + phone | 1 hour |
| Media or public attention | CISO + Communications Lead | Immediate coordination | 30 minutes |

---

## 7. Communication Plan (A.5.26)

### 7.1 Internal Communication

| Audience | Channel | Content | Frequency |
|---|---|---|---|
| Incident response team | Dedicated incident channel (Slack/Teams) | Real-time updates, technical details | Continuous during incident |
| SOC analysts | Dashboard notification + email | Impact summary, workarounds, status | Hourly during P1/P2 |
| All staff | Email | Summary (non-sensitive) | At incident declaration and resolution |
| Board | CISO briefing email | Executive summary, risk assessment, regulatory implications | P1: within 4 hours; P2: within 24 hours |

### 7.2 External Communication

| Audience | Channel | Content | Frequency | Approval |
|---|---|---|---|---|
| Affected tenants | Email + status page | Impact, mitigation, expected resolution | Hourly during P1 | CISO |
| All tenants | Status page | Service status update | At declaration and resolution | Communications Lead |
| Regulators (ICO/DPA) | Formal notification (per regulation) | Data breach details per regulatory requirements | Within 72 hours | CISO + Legal |
| Data subjects | Direct notification (if required) | Nature of breach, data affected, protective measures | Per regulatory timelines | CISO + Legal |
| LLM provider (if relevant) | Support ticket + account manager | Incident details relevant to provider | As needed | AI Security Lead |

### 7.3 Communication Templates

Pre-approved communication templates are maintained for:
- Tenant notification (data breach)
- Tenant notification (service outage)
- Regulatory notification (ICO initial report)
- Status page update (investigating / identified / monitoring / resolved)
- Internal all-hands notification

---

## 8. Evidence Preservation (A.5.28)

### 8.1 Evidence Collection Checklist

| Evidence Type | Collection Method | Retention | Storage |
|---|---|---|---|
| Audit trail records (hash-chain) | Export via Audit Service API; verify hash-chain integrity | Duration of investigation + 7 years | Encrypted MinIO bucket (incident evidence) |
| Application logs | Export from centralised logging (Loki/ELK) | Duration of investigation + 3 years | Encrypted MinIO bucket |
| Infrastructure logs | Export from K8s and system logs | Duration of investigation + 1 year | Encrypted MinIO bucket |
| LLM inference logs | Export from LLM Router logging | Duration of investigation + 3 years | Encrypted MinIO bucket |
| Network captures (if applicable) | Kubernetes packet capture | Duration of investigation + 1 year | Encrypted MinIO bucket |
| Configuration snapshots | GitOps repository snapshot; K8s ConfigMap/Secret metadata | Duration of investigation + 3 years | Git repository + encrypted backup |
| Prometheus metrics | Export time-series data for incident window | Duration of investigation + 1 year | Encrypted MinIO bucket |
| Container images | Preserve running container image digests | Duration of investigation + 1 year | Container registry (immutable tags) |

### 8.2 Chain of Custody

All evidence shall be:
1. **Timestamped** -- collection time recorded in UTC
2. **Hash-verified** -- SHA-256 hash computed at collection time
3. **Access-controlled** -- stored in access-restricted location; access logged
4. **Tamper-evident** -- stored in append-only or write-once storage where possible
5. **Documented** -- evidence log maintained with collector identity, collection method, and hash values

---

## 9. Post-Incident Review (A.5.27)

### 9.1 Review Timeline

| Severity | Review Deadline | Participants | Output |
|---|---|---|---|
| P1 | Within 5 business days | Full incident team + CISO + management | Full post-incident report |
| P2 | Within 10 business days | Incident team + relevant managers | Post-incident report |
| P3 | Within 20 business days | Technical team | Abbreviated review |
| P4 | Monthly batch review | Security Architect | Trend analysis |

### 9.2 Post-Incident Report Structure

1. **Executive summary** -- what happened, impact, resolution
2. **Timeline** -- chronological sequence of events (detection to resolution)
3. **Root cause analysis** -- underlying cause(s); 5-whys or fishbone analysis
4. **Impact assessment** -- tenants affected, data exposed, duration, financial impact
5. **Response effectiveness** -- what worked well, what could improve
6. **Evidence summary** -- audit trail verification results, log analysis findings
7. **Corrective actions** -- specific improvements with owners and deadlines
8. **Risk register update** -- changes to risk assessment based on incident
9. **Metrics** -- MTTD (mean time to detect), MTTR (mean time to respond), MTTR (mean time to recover)

### 9.3 Lessons Learned Integration

| Action | Owner | Timeline |
|---|---|---|
| Update incident response procedures | CISO | Within 30 days |
| Update risk assessment if new threat identified | Security Architect | Within 30 days |
| Implement corrective actions (technical) | Assigned owners | Per corrective action plan |
| Update monitoring and alerting rules | DevOps Lead | Within 14 days |
| Update AI security controls (if AI-related) | AI/ML Eng Lead | Within 14 days |
| Conduct targeted training (if human factor) | SOC Manager | Within 30 days |
| Update supplier assessment (if supply chain) | CISO | Within 30 days |

---

## 10. Incident Metrics and Reporting

### 10.1 Key Metrics

| Metric | Definition | Target |
|---|---|---|
| MTTD (Mean Time to Detect) | Time from incident occurrence to detection | P1: < 15 min; P2: < 1 hour |
| MTTR (Mean Time to Respond) | Time from detection to containment | P1: < 30 min; P2: < 2 hours |
| MTTR (Mean Time to Recover) | Time from detection to full service restoration | P1: < 4 hours; P2: < 8 hours |
| Incidents per quarter | Total incidents by severity | Trending downward |
| Kill switch activations | Number of kill switch activations per quarter | < 2 per quarter |
| Regulatory notifications | Number of reportable data breaches | 0 per year |

### 10.2 Reporting

| Report | Audience | Frequency | Content |
|---|---|---|---|
| Incident dashboard | Operations team | Real-time | Active incidents, status, metrics |
| Monthly incident summary | CISO, management | Monthly | Incident count, trends, key lessons |
| Quarterly security report | Board of Directors | Quarterly | Incident summary, risk posture, improvement actions |
| Annual incident review | ISMS management review | Annually | Year-over-year trends, ISMS effectiveness metrics |

---

## 11. Document Control

| Version | Date | Author | Changes |
|---|---|---|---|
| 1.0 | 2026-03-29 | CISO | Initial release |

---

*This document is part of the ALUSKORT SOC Platform ISMS. It shall be reviewed annually, after every P1 incident, and upon significant changes to the platform architecture or threat landscape.*
