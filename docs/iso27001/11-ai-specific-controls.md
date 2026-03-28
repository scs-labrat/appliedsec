# AI-Specific Security Controls

**Document ID:** ALUSKORT-ISMS-11
**Version:** 1.0
**Classification:** Confidential
**Owner:** Security Architect
**Approved by:** CISO, Applied Computing Technologies
**Effective date:** 2026-03-29
**Review date:** 2026-09-29 (semi-annual due to AI risk evolution)
**Standard reference:** ISO/IEC 27001:2022 (extended), ISO/IEC 42001:2023 (AI Management System), NIST AI RMF, MITRE ATLAS

---

## 1. Purpose

This document defines the AI-specific security controls for the ALUSKORT SOC Platform. While ISO/IEC 27001:2022 does not include explicit AI controls, this document bridges the gap by referencing ISO/IEC 42001:2023 (AI Management System Standard) and the NIST AI Risk Management Framework to provide comprehensive governance of the AI systems that form the core of the ALUSKORT platform.

This is the most critical document in the ALUSKORT ISMS due to the platform's fundamental dependence on AI for its core security operations function.

---

## 2. AI System Inventory

### 2.1 AI Agent Registry

| Agent ID | Agent Name | Function | LLM Tier(s) Used | Risk Classification | Autonomy Level |
|---|---|---|---|---|---|
| AGT-01 | Triage Agent | Initial alert classification, severity scoring, and prioritisation | Haiku (default), Sonnet (complex) | High | Semi-autonomous (human review on high severity) |
| AGT-02 | Enrichment Agent | Gather additional context from threat intelligence, WHOIS, DNS, and internal databases | Haiku | Medium | Autonomous (data gathering only; no actions) |
| AGT-03 | Correlation Agent | Correlate alerts across time, entities, and attack patterns using graph analysis | Sonnet | High | Autonomous (analysis only; no actions) |
| AGT-04 | Investigation Agent | Deep-dive investigation of correlated alert clusters; hypothesis generation and testing | Opus (complex), Sonnet (standard) | Critical | Semi-autonomous (human approval on recommendations) |
| AGT-05 | Recommendation Agent | Generate response recommendations with risk assessments and confidence scores | Opus | Critical | Semi-autonomous (all recommendations require human approval) |
| AGT-06 | Reporting Agent | Generate investigation reports and evidence summaries | Sonnet | Medium | Autonomous (report generation only) |
| AGT-07 | Review Agent | Quality review of investigation findings; cross-check against known patterns | Sonnet | High | Autonomous (review only; flags issues for human review) |

### 2.2 LLM Tier Configuration

| Tier | Model | Use Cases | Cost per 1K Tokens (approx.) | Latency (P50) | Accuracy Target |
|---|---|---|---|---|---|
| **Haiku** | Claude 3.5 Haiku | Fast triage, enrichment, simple classification | Low | < 1 second | >= 90% |
| **Sonnet** | Claude 3.5 Sonnet | Correlation, standard investigation, reporting, review | Medium | 2--5 seconds | >= 95% |
| **Opus** | Claude 3 Opus | Complex investigation, recommendation generation | High | 5--15 seconds | >= 98% |
| **Batch** | Claude (Batch API) | Bulk re-analysis, trend analysis, pattern mining | Very Low | Minutes--hours | >= 95% |

### 2.3 Context Gateway Components

| Component | Function | Risk Addressed |
|---|---|---|
| Injection Detector | Multi-layer prompt injection detection (regex, ML classifier, LLM-based) | Prompt injection attacks (ATLAS AML.T0051) |
| PII Redactor | Detect and redact personal data before LLM context | PII leakage through LLM context windows |
| Evidence Isolator | Present alert data as structured typed fields, not raw text | Prompt injection via data content |
| Output Validator | Deny-by-default validation of LLM responses against strict JSON schemas | Data exfiltration, hallucination, jailbreak |
| Spend Guard | Per-tenant LLM budget tracking and enforcement | Cost control, spend exhaustion attacks |

---

## 3. AI Risk Assessment

### 3.1 AI-Specific Threat Model

| Threat ID | Threat | MITRE ATLAS ID | Likelihood | Impact | Risk Score | Primary Control |
|---|---|---|---|---|---|---|
| AI-T01 | **Direct prompt injection** -- attacker crafts input to manipulate agent behaviour | AML.T0051 | 5 (Very High) | 4 (High) | 20 (Critical) | Context Gateway injection detection |
| AI-T02 | **Indirect prompt injection** -- malicious content in alert data manipulates agents | AML.T0051.001 | 4 (High) | 4 (High) | 16 (Critical) | Structured evidence isolation |
| AI-T03 | **LLM hallucination** -- agent generates fabricated findings or false correlations | -- | 4 (High) | 3 (Medium) | 12 (High) | Confidence scores; human approval |
| AI-T04 | **Data exfiltration via LLM** -- sensitive data extracted through crafted prompts | AML.T0024 | 3 (Medium) | 4 (High) | 12 (High) | PII redaction; output validation |
| AI-T05 | **Adversarial evasion** -- attacks designed to evade AI detection | AML.T0015 | 4 (High) | 4 (High) | 16 (Critical) | ATLAS rules; human review; pattern expiry |
| AI-T06 | **Model extraction** -- reconstruct agent logic through systematic querying | AML.T0024 | 2 (Low) | 3 (Medium) | 6 (Medium) | Rate limiting; query logging |
| AI-T07 | **Agent jailbreak** -- manipulate agent to operate outside intended scope | AML.T0051.001 | 3 (Medium) | 5 (Critical) | 15 (High) | Kill switch; scope constraints; output validation |
| AI-T08 | **Bias amplification** -- systematic bias in AI decisions across categories | -- | 2 (Low) | 3 (Medium) | 6 (Medium) | FP monitoring; per-category analysis |
| AI-T09 | **Supply chain model compromise** -- LLM provider model tampered | AML.T0020 | 1 (Very Low) | 5 (Critical) | 5 (Medium) | Output validation; provider assessment |
| AI-T10 | **Spend exhaustion** -- deliberate budget depletion to deny service | -- | 3 (Medium) | 2 (Low) | 6 (Medium) | Spend guard; per-tenant quotas |
| AI-T11 | **Prompt template leakage** -- system prompts extracted via LLM interaction | AML.T0024 | 3 (Medium) | 2 (Low) | 6 (Medium) | Output validation; prompt obfuscation |

### 3.2 EU AI Act Risk Classification

| Criterion | Assessment |
|---|---|
| AI system type | AI system used in security-relevant decision support |
| Risk category | **High-risk** (AI system used for law enforcement / security purposes per Annex III) |
| Requirements | Risk management, data governance, technical documentation, transparency, human oversight, accuracy/robustness |
| ALUSKORT compliance | Addressed through this document and related ISMS documentation |

---

## 4. Model Governance

### 4.1 Model Registry and Versioning

| Attribute | Details |
|---|---|
| Registry location | Internal model registry (Git-based configuration repository) |
| Versioning scheme | `{agent_name}-{prompt_version}-{model_tier}-{date}` (e.g., `triage-v2.3-haiku-20260329`) |
| Change control | All prompt template and agent configuration changes tracked in Git; peer review required |
| Approval process | AI/ML Eng Lead approval for all prompt changes; Security Architect approval for Context Gateway changes |
| Rollback capability | Previous versions preserved; immediate rollback via configuration change |

### 4.2 Model Registry Contents (per Agent)

| Field | Description |
|---|---|
| Agent ID | Unique identifier (AGT-01 through AGT-07) |
| Agent version | Current version number |
| Prompt template version | Version of the system/user prompt templates |
| Model tier | LLM tier used (Haiku/Sonnet/Opus) |
| Input schema | JSON schema defining expected input format |
| Output schema | JSON schema defining expected output format (deny-by-default validation) |
| Confidence threshold | Minimum confidence score for autonomous action |
| Risk classification | Risk level (Medium/High/Critical) |
| Owner | Responsible engineer |
| Last reviewed | Date of last security review |
| Performance metrics | Accuracy, precision, recall, F1 score (where measurable) |

### 4.3 Inference Logging and Audit

Every LLM inference call is logged:

| Field | Description |
|---|---|
| `request_id` | Unique identifier for the inference request |
| `tenant_id` | Tenant context |
| `agent_id` | Agent making the request |
| `model_tier` | LLM tier used |
| `model_version` | Specific model version (e.g., `claude-3-5-sonnet-20241022`) |
| `prompt_hash` | SHA-256 hash of the prompt template (not content) |
| `input_token_count` | Number of input tokens |
| `output_token_count` | Number of output tokens |
| `latency_ms` | Inference latency in milliseconds |
| `cost_usd` | Estimated cost in USD |
| `pii_entities_redacted` | Count of PII entities redacted before inference |
| `injection_score` | Prompt injection detection confidence score |
| `output_validation_result` | Pass/fail of output schema validation |
| `confidence_score` | Agent's confidence in its output |
| `timestamp` | UTC timestamp |

### 4.4 Spend Guard and Budget Controls

| Control | Implementation |
|---|---|
| Per-tenant hourly quota | Premium: 500, Standard: 100, Trial: 20 LLM calls per hour |
| Real-time tracking | Redis counter per tenant; decremented with each LLM call |
| Budget enforcement | HTTP 429 returned when quota exhausted; alert to tenant |
| Cost attribution | Every LLM call attributed to tenant and agent for cost allocation |
| Anomaly detection | Alert when tenant usage exceeds 80% of quota; alert on unusual usage patterns |
| Admin override | Admin can temporarily increase quota (documented in audit trail) |
| Monthly reporting | Per-tenant cost report generated monthly |
| Global spend cap | Platform-wide monthly spend limit with alert at 90% |

### 4.5 Shadow Mode Testing

| Aspect | Details |
|---|---|
| Purpose | Test new agent versions or prompt changes against production data without affecting live operations |
| Mechanism | New version receives same input as production; output compared but not acted upon |
| Duration | Minimum 72 hours of shadow testing before promotion |
| Comparison metrics | Accuracy, confidence distribution, latency, cost, hallucination rate |
| Promotion criteria | New version must meet or exceed current version on all metrics; no regression in injection detection |
| Approval | AI/ML Eng Lead + Security Architect approval to promote from shadow to canary |

### 4.6 Canary Rollout with Automatic Rollback

```
Shadow Mode (72h min)
    │
    ▼ (Metrics pass + approval)
Canary (5% traffic, 24h)
    │
    ├── Metrics pass → 25% traffic (24h)
    │                      │
    │                      ├── Metrics pass → 50% traffic (24h)
    │                      │                      │
    │                      │                      ├── Metrics pass → 100% traffic
    │                      │                      │
    │                      │                      └── Metrics fail → Automatic rollback
    │                      │
    │                      └── Metrics fail → Automatic rollback
    │
    └── Metrics fail → Automatic rollback
```

**Canary rollback triggers:**
- Error rate > 1%
- Confidence score mean drops > 10%
- Prompt injection detection rate drops below baseline
- Output validation failure rate > 0.5%
- Latency P99 > 2x baseline
- Any hash-chain integrity failure

---

## 5. Adversarial AI Defences

### 5.1 MITRE ATLAS Framework Compliance

The ALUSKORT platform implements detection rules aligned with the MITRE ATLAS (Adversarial Threat Landscape for AI Systems) framework:

| Rule # | ATLAS Technique | Rule Description | Detection Method | Action on Detection |
|---|---|---|---|---|
| 1 | AML.T0051 -- LLM Prompt Injection | Detect direct prompt injection attempts in user input | Regex patterns + ML classifier + LLM-based detection | Block request; log attempt; alert if threshold exceeded |
| 2 | AML.T0051.001 -- Indirect Prompt Injection | Detect injection payloads embedded in alert data | Structured evidence isolation; content scanning | Isolate data; sanitise before processing |
| 3 | AML.T0015 -- Evade ML Model | Detect adversarial inputs designed to evade classification | Confidence score anomaly detection; cross-agent validation | Flag for human review; increase scrutiny |
| 4 | AML.T0024 -- Exfiltration via ML API | Detect attempts to extract data through LLM responses | Output validation; pattern matching for sensitive data | Block response; redact content; alert |
| 5 | AML.T0020 -- Poison Training Data | Detect attempts to influence AI behaviour through crafted inputs | FP pattern integrity checks; two-person approval | Reject pattern; alert; require manual review |
| 6 | AML.T0043 -- Craft Adversarial Data | Detect specially crafted alert data designed to manipulate AI analysis | Input anomaly detection; statistical analysis of alert features | Quarantine alert; human investigation |
| 7 | AML.T0042 -- Verify Attack | Detect adversary probing AI system behaviour | Rate limiting; query pattern analysis | Throttle; alert; investigation |
| 8 | AML.T0040 -- ML Model Inference API Access | Detect systematic model querying for extraction | API usage pattern analysis; tenant quota enforcement | Rate limit; alert; account review |
| 9 | AML.T0047 -- ML-Enabled Product Abuse | Detect misuse of AI capabilities for unintended purposes | Behaviour analysis; output pattern monitoring | Alert; access review; potential suspension |
| 10 | AML.T0049 -- Exploit Public-Facing Application | Detect exploitation of platform APIs targeting AI components | WAF rules; input validation; API security controls | Block; alert; incident response |
| 11 | AML.T0025 -- Exfiltration via Cyber Means | Detect data exfiltration through non-LLM channels exploiting AI-gathered intelligence | Network monitoring; egress controls; data loss prevention | Block; alert; incident response |

### 5.2 Prompt Injection Detection and Classification

#### 5.2.1 Multi-Layer Detection

| Layer | Method | Accuracy | Latency | Purpose |
|---|---|---|---|---|
| Layer 1 -- Regex | Pattern matching against known injection signatures | High precision, moderate recall | < 1 ms | Fast pre-filter for known attack patterns |
| Layer 2 -- ML Classifier | Trained classifier on injection/benign corpus | High precision and recall | < 10 ms | Catch novel injection patterns |
| Layer 3 -- LLM-Based | LLM evaluates suspicious content for injection intent | Highest accuracy | 100--500 ms | Final check for sophisticated attacks |

#### 5.2.2 Injection Classification

| Classification | Confidence | Action |
|---|---|---|
| **Confirmed injection** | > 95% | Block; log; alert; increment attack counter |
| **Suspected injection** | 70--95% | Quarantine; flag for human review; process with increased monitoring |
| **Unlikely injection** | 30--70% | Process with standard controls; log classification |
| **Benign** | < 30% | Process normally |

### 5.3 Structured Evidence Isolation

| Principle | Implementation |
|---|---|
| Data/instruction separation | Alert data is never directly interpolated into prompt instructions |
| Typed fields | All alert data presented as strongly-typed JSON fields with defined schemas |
| Boundary markers | Clear delimiters between system instructions, agent reasoning, and evidence data |
| Read-only evidence | Evidence data marked as read-only context; agents instructed not to interpret as commands |
| Size limits | Maximum evidence context size enforced (prevents context window overflow attacks) |

### 5.4 Output Validation (Deny-by-Default)

| Aspect | Implementation |
|---|---|
| Schema enforcement | Every agent output must conform to a strict JSON schema; non-conforming outputs rejected |
| Default action | If output validation fails, default is to deny/discard the output (not to fall back to unvalidated) |
| Content scanning | Outputs scanned for PII patterns, credential patterns, and prohibited content |
| Action validation | Recommended actions validated against allowed action catalogue; unknown actions rejected |
| Confidence gating | Outputs below confidence threshold routed to human review regardless of content |
| Recursion detection | Detect and prevent agent output being fed back as injection vector |

---

## 6. Human Oversight

### 6.1 Human-in-the-Loop Approval Gates

| Gate | Trigger Condition | Approver Role | Timeout Action |
|---|---|---|---|
| **Response action approval** | Any AI-recommended response action (containment, remediation) | `senior_analyst` or `admin` | Queue for next available analyst; no auto-execution |
| **High-severity alert escalation** | Alert severity >= Critical and AI confidence < 95% | `senior_analyst` | Escalate to next tier; no auto-close |
| **FP pattern creation** | AI or analyst proposes new false positive pattern | Two `senior_analyst` approvals required | Pattern not created until dual approval |
| **Investigation closure** | AI recommends closing investigation as benign | `analyst` (low severity), `senior_analyst` (high severity) | Remain open until human review |
| **Configuration change** | Any change to AI agent behaviour, thresholds, or rules | `admin` | Change not applied until approved |

### 6.2 Kill Switch

| Aspect | Details |
|---|---|
| **Purpose** | Emergency halt of all autonomous AI actions |
| **Activation** | `POST /api/v1/system/kill-switch` -- requires `admin` role |
| **Scope** | Stops all AI agent processing; halts all LLM API calls; queues pending response actions |
| **Preservation** | Alert ingestion continues; audit trail continues; manual operations continue |
| **Authority** | CISO or designated deputy; any admin in emergency |
| **Documentation** | Activation reason recorded in audit trail; incident record created automatically |
| **Deactivation** | Requires CISO written approval; gradual canary reactivation |
| **Testing** | Kill switch functionality tested quarterly |
| **Latency** | All AI processing halted within 60 seconds of activation |

### 6.3 Two-Person Approval for FP Patterns

| Aspect | Details |
|---|---|
| **Purpose** | Prevent single-person introduction of malicious or incorrect false positive patterns that could mask real attacks |
| **Process** | First `senior_analyst` proposes pattern → second `senior_analyst` reviews and approves |
| **Self-approval** | Prohibited -- proposer cannot be the approver |
| **Justification** | Both proposer and approver must provide written justification |
| **Audit** | Full audit trail of proposal, review, and approval (or rejection) |
| **Scope** | Pattern defines conditions under which alerts are automatically classified as false positive |
| **Risk** | Malicious FP pattern could suppress detection of real attacks |

### 6.4 90-Day Pattern Reaffirmation

| Aspect | Details |
|---|---|
| **Purpose** | Prevent stale FP patterns from masking evolving threats |
| **Mechanism** | All FP patterns expire after 90 days unless reaffirmed |
| **Reaffirmation process** | Pattern owner reviews pattern validity; reaffirms or retires |
| **Notification** | 14-day advance notification before expiry |
| **Expiry action** | Expired patterns automatically disabled; suppressed alerts resume normal processing |
| **Audit** | Reaffirmation and expiry events recorded in audit trail |
| **Override** | Admin can extend pattern without reaffirmation in documented emergency (max 30 days) |

---

## 7. Transparency and Explainability

### 7.1 Decision Chain Audit Trail

Every AI-driven decision is recorded in the immutable hash-chain audit trail:

| Field | Description |
|---|---|
| `decision_id` | Unique identifier for the decision |
| `agent_id` | Agent that made the decision |
| `agent_version` | Version of the agent at decision time |
| `input_summary` | Summarised (PII-redacted) input context |
| `reasoning_chain` | Step-by-step reasoning produced by the agent |
| `output_decision` | The decision or recommendation made |
| `confidence_score` | Agent's self-assessed confidence (0.0 -- 1.0) |
| `evidence_cited` | List of evidence items supporting the decision |
| `alternative_decisions` | Other options considered and why they were rejected |
| `risk_assessment` | Risk level of the recommended action |
| `human_approval_required` | Whether human approval is needed |
| `human_decision` | If applicable, the human approver's decision and rationale |
| `timestamp` | UTC timestamp |
| `hash_chain_link` | SHA-256 hash linking to previous audit record |

### 7.2 Confidence Scores and Thresholds

| Confidence Range | Interpretation | Action |
|---|---|---|
| 0.95 -- 1.00 | Very high confidence | May proceed automatically (low-severity actions only) |
| 0.80 -- 0.94 | High confidence | Human notification; auto-proceed for low risk |
| 0.60 -- 0.79 | Moderate confidence | Human approval required |
| 0.40 -- 0.59 | Low confidence | Escalate to senior analyst; additional investigation recommended |
| 0.00 -- 0.39 | Very low confidence | Flag as uncertain; manual investigation required |

### 7.3 Recommendation Descriptions

Every AI recommendation includes:

| Element | Description |
|---|---|
| Action description | Clear, non-technical description of what will happen |
| Risk assessment | Low/Medium/High/Critical risk rating for the action |
| Potential impact | Description of what could go wrong if the action is incorrect |
| Evidence summary | Key evidence supporting the recommendation |
| Confidence level | Numerical confidence with natural language interpretation |
| Alternative actions | Other options considered |
| Reversibility | Whether the action can be undone and how |

---

## 8. Continuous Monitoring

### 8.1 Drift Detection

| Metric | Baseline | Monitoring Method | Alert Threshold |
|---|---|---|---|
| Triage accuracy | Established per agent version | Comparison against human-reviewed sample | Accuracy drop > 5% over 7 days |
| Confidence score distribution | Established per agent version | Statistical comparison of confidence histograms | KL divergence > 0.1 from baseline |
| Alert category distribution | Historical average | Chi-squared test on category proportions | Significant deviation (p < 0.01) |
| Investigation outcome distribution | Historical average | Proportion of true positive/false positive/benign outcomes | Shift > 10% in any category |
| LLM response latency | Established per model tier | Percentile tracking (P50, P95, P99) | P99 > 2x baseline |
| Injection detection rate | Established baseline | Rolling average of detection rate | Rate deviation > 2 std dev |

### 8.2 False Positive Precision Evaluation

| Metric | Measurement | Frequency | Target |
|---|---|---|---|
| FP pattern precision | Percentage of alerts correctly classified as FP by active patterns | Weekly (sampled review) | >= 99% |
| FP pattern recall | Percentage of actual FPs caught by patterns | Monthly (full analysis) | >= 90% |
| FP pattern staleness | Age distribution of active FP patterns | Weekly | No patterns > 90 days without reaffirmation |
| Human override rate | Percentage of AI FP classifications overridden by analysts | Daily | < 5% |
| Category-specific FP rate | FP rate broken down by alert category and source | Weekly | No category deviation > 2x average |

### 8.3 ATLAS Rule Performance

| Rule # | Metric | Target | Monitoring |
|---|---|---|---|
| 1--11 (all rules) | Detection rate (true positive) | >= 95% | Monthly red team exercise results |
| 1--11 (all rules) | False positive rate | < 1% | Weekly log analysis |
| 1--2 (injection rules) | Detection latency | < 100 ms (Layer 1+2) | Continuous (Prometheus) |
| 1--11 (all rules) | Rule trigger count | Trending (contextual) | Daily dashboard review |
| 1--11 (all rules) | Bypass attempts detected | All detected (0 successful bypasses) | Quarterly red team + continuous |

### 8.4 Cost and Usage Metrics

| Metric | Granularity | Dashboard | Alert |
|---|---|---|---|
| Total LLM cost (USD) | Per tenant, per day | Daily cost dashboard | Monthly budget > 90% consumed |
| LLM calls per hour | Per tenant | Real-time dashboard | Quota > 80% utilised |
| Token usage (input/output) | Per agent, per model tier | Weekly report | Unusual spike (> 2 std dev) |
| Cost per investigation | Per tenant | Monthly report | Cost per investigation > 2x average |
| Model tier distribution | Platform-wide | Weekly report | Opus usage > 30% of total (cost concern) |
| Batch processing backlog | Platform-wide | Real-time dashboard | Backlog > 1000 items |

---

## 9. AI Governance Review Cycle

| Activity | Frequency | Participants | Output |
|---|---|---|---|
| Agent performance review | Monthly | AI/ML Eng Lead, SOC Manager | Performance report; tuning recommendations |
| Adversarial red team exercise | Quarterly | External red team, Security Architect | Red team report; ATLAS rule updates |
| Prompt template security review | Semi-annually | AI/ML Eng Lead, Security Architect | Review findings; prompt hardening |
| AI risk assessment update | Semi-annually | CISO, Security Architect, AI/ML Eng Lead | Updated risk register |
| Full AI governance review | Annually | CISO, Board representative, all leads | Governance report; strategic recommendations |
| EU AI Act compliance review | Annually | CISO, Legal | Compliance assessment |
| ISO 42001 alignment review | Annually | CISO, Security Architect | Gap analysis; improvement plan |
| Bias and fairness assessment | Annually | AI/ML Eng Lead, external reviewer | Bias report; corrective actions |

---

## 10. Compliance Mapping

| Framework | Requirement | ALUSKORT Implementation | Reference |
|---|---|---|---|
| ISO 42001:2023 | AI risk management | AI risk assessment (Section 3); continuous monitoring (Section 8) | This document |
| ISO 42001:2023 | AI system lifecycle management | Model registry; shadow testing; canary rollout (Section 4) | This document |
| ISO 42001:2023 | Human oversight | Approval gates; kill switch; two-person approval (Section 6) | This document |
| ISO 42001:2023 | Transparency | Decision chain audit trail; confidence scores (Section 7) | This document |
| EU AI Act | Risk classification | High-risk classification documented (Section 3.2) | This document |
| EU AI Act | Technical documentation | Full AI system inventory and documentation | This document |
| EU AI Act | Human oversight | Approval gates; kill switch (Section 6) | This document |
| EU AI Act | Accuracy, robustness, cybersecurity | Adversarial defences; testing; monitoring (Sections 5, 8) | This document |
| NIST AI RMF | Govern | AI governance review cycle (Section 9) | This document |
| NIST AI RMF | Map | AI system inventory; risk classification (Section 2, 3) | This document |
| NIST AI RMF | Measure | Continuous monitoring metrics (Section 8) | This document |
| NIST AI RMF | Manage | Treatment plan; human oversight; kill switch (Sections 5, 6) | This document |
| MITRE ATLAS | Adversarial ML defence | 11 detection rules (Section 5.1) | This document |

---

## 11. Document Control

| Version | Date | Author | Changes |
|---|---|---|---|
| 1.0 | 2026-03-29 | Security Architect | Initial release |

---

*This document is part of the ALUSKORT SOC Platform ISMS. Due to the rapidly evolving nature of AI threats and capabilities, this document shall be reviewed semi-annually, after any AI-related security incident, and upon significant changes to AI components or regulatory requirements.*
