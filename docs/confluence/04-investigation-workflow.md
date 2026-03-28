# Investigation Workflow

## State Machine

Every alert that enters ALUSKORT becomes an investigation managed by a finite state machine (FSM) in the Orchestrator. The investigation transitions through well-defined states, with each transition recorded in the decision chain and emitted as an audit event.

```
                         +----------+
                         | RECEIVED |
                         +----+-----+
                              |
                         IOC Extractor
                              |
                         +----v-----+
                         | PARSING  |
                         +----+-----+
                              |
                         FP Short-Circuit Check
                              |
                    +---------+---------+
                    |                   |
               FP matched          Not matched
               (auto-close)             |
                    |              +----v------+
               +----v---+         | ENRICHING |
               | CLOSED |         +----+------+
               +--------+              |
                              Parallel enrichment:
                              - Context Enricher
                              - CTEM Correlator
                              - ATLAS Mapper
                                        |
                                   +----v------+
                                   | REASONING |
                                   +----+------+
                                        |
                              Trust constraint check
                              Confidence evaluation
                                        |
                          +-------------+-------------+
                          |                           |
                   Confidence >= threshold     Confidence < threshold
                   AND no trust issues         OR critical severity
                          |                    OR untrusted telemetry
                          |                    OR shadow mode
                     +----v------+        +---v-----------+
                     | RESPONDING|        | AWAITING_HUMAN|
                     +----+------+        +---+-----------+
                          |                   |
                     Response Agent      Analyst review
                          |                   |
                     +----v---+     +---------+---------+
                     | CLOSED |     |                   |
                     +--------+  Approved           Rejected/Timeout
                                    |                   |
                              +-----v-----+       +----v---+
                              | RESPONDING|       | CLOSED |
                              +-----+-----+       +--------+
                                    |
                              +-----v-----+
                              |  CLOSED   |
                              +-----------+
```

### State Definitions

| State | Value | Description |
|-------|-------|-------------|
| RECEIVED | `received` | Alert ingested, investigation created, `GraphState` initialised |
| PARSING | `parsing` | IOC Extractor agent is running, extracting indicators of compromise |
| ENRICHING | `enriching` | Three enrichment agents running in parallel |
| REASONING | `reasoning` | Reasoning Agent is analysing all evidence and forming a verdict |
| AWAITING_HUMAN | `awaiting_human` | Investigation requires analyst approval before proceeding |
| RESPONDING | `responding` | Response Agent is executing approved actions |
| CLOSED | `closed` | Investigation complete (auto-closed, responded, or rejected) |
| FAILED | `failed` | Unrecoverable error during pipeline execution |

---

## Agent Descriptions

### Agent 1: IOC Extractor

| Property | Value |
|----------|-------|
| **Role** | `ioc_extractor` |
| **Stage** | RECEIVED -> PARSING |
| **Input** | Raw alert entities, description text |
| **Output** | Structured IOCs (IPs, domains, hashes, URLs, email addresses) |
| **LLM Tier** | Tier 0 (Haiku) -- task type `ioc_extraction` |

Extracts indicators of compromise from the alert's raw entity data and description text. Outputs a structured list of IOCs categorised by type (IP, domain, file hash, URL, email). These IOCs feed into the Context Enricher for threat intelligence matching.

### Agent 2: Context Enricher

| Property | Value |
|----------|-------|
| **Role** | `context_enricher` |
| **Stage** | ENRICHING (parallel) |
| **Input** | Extracted IOCs, entity identifiers |
| **Output** | IOC matches, UEBA context, similar incidents, risk state |
| **LLM Tier** | Tier 1 (Sonnet) -- task type `investigation` |

Enriches the investigation with contextual data:
- **IOC Matching**: Queries `threat_intel_iocs` table for known indicators
- **UEBA Context**: Queries entity behaviour baselines from `org_context`
- **Similar Incidents**: Semantic search via Qdrant for historically similar investigations
- **Risk State**: Computes `RiskSignal` from UEBA priority scores with explicit handling of absent data (`NO_BASELINE` != `LOW`)

### Agent 3: CTEM Correlator

| Property | Value |
|----------|-------|
| **Role** | `ctem_correlator` |
| **Stage** | ENRICHING (parallel) |
| **Input** | Investigation entities (hosts, IPs, assets) |
| **Output** | Matched CTEM exposures with consequence-weighted scores |
| **LLM Tier** | Tier 1 (Sonnet) -- task type `ctem_correlation` |

Correlates investigation entities against the `ctem_exposures` table to identify:
- Known vulnerabilities on affected assets
- Exposure severity weighted by physical consequence (safety, equipment, downtime, data loss)
- SLA status and remediation progress
- Zone-aware consequence mapping using the Purdue model

### Agent 4: ATLAS Mapper

| Property | Value |
|----------|-------|
| **Role** | `atlas_mapper` |
| **Stage** | ENRICHING (parallel) |
| **Input** | Alert tactics, techniques, entity types |
| **Output** | Matched MITRE ATLAS techniques with telemetry trust levels |
| **LLM Tier** | Tier 1 (Sonnet) -- task type `atlas_reasoning` |

Maps alert indicators to MITRE ATLAS adversarial AI techniques. Identifies whether the alert may involve:
- Training data poisoning (AML.T0020)
- Adversarial evasion (AML.T0015)
- Model extraction (AML.T0044)
- Prompt injection (AML.T0051)
- Sensor spoofing (AML.T0043)
- Edge node compromise (AML.T0040)

Each mapping includes a `telemetry_trust_level` (trusted/untrusted) and `attestation_status`.

### Agent 5: Reasoning Agent

| Property | Value |
|----------|-------|
| **Role** | `reasoning_agent` |
| **Stage** | REASONING |
| **Input** | Complete enriched GraphState (all IOC, CTEM, ATLAS, UEBA data) |
| **Output** | Classification, confidence score, recommended actions, approval decision |
| **LLM Tier** | Tier 1 (Sonnet) or Tier 1+ (Opus) for low-confidence escalation |

Analyses all collected evidence and produces:
- **Classification**: Alert category (e.g., "APT lateral movement", "ransomware execution")
- **Confidence score**: 0.0-1.0 confidence in the classification
- **Recommended actions**: Ordered list of response steps
- **Approval decision**: Whether to auto-respond or escalate to human

Escalation to Tier 1+ (Opus) occurs when:
- Previous confidence < 0.6 on critical/high severity alerts
- Extended thinking is enabled for deeper analysis

### Agent 6: Response Agent

| Property | Value |
|----------|-------|
| **Role** | `response_agent` |
| **Stage** | RESPONDING |
| **Input** | Classified investigation with approved actions |
| **Output** | Executed response actions, final investigation status |
| **LLM Tier** | Tier 1 (Sonnet) -- task type `investigation` |

Executes the approved response actions. Includes an `ApprovalGate` with severity-aware timeout behaviour:
- **Critical/High**: Timeout escalates (keeps AWAITING_HUMAN)
- **Medium/Low**: Timeout auto-closes

---

## Decision Chain

Every investigation maintains a `decision_chain` -- an ordered list of `DecisionEntry` records that form a complete audit trail of every automated decision.

### DecisionEntry Fields

| Field | Type | Description |
|-------|------|-------------|
| `step` | string | Pipeline step name (e.g., "ioc_extraction", "trust_constraint") |
| `agent` | string | Agent role that made the decision |
| `action` | string | Action taken (e.g., "start_ioc_extraction", "force_human_review") |
| `reasoning` | string | Human-readable explanation of the decision |
| `confidence` | float | Confidence score at this decision point (0.0-1.0) |
| `attestation_status` | string | Telemetry trust level for trust model tracking |
| `taxonomy_version` | string | Version of the event taxonomy used |

---

## Human-in-the-Loop Approval Gates

### When Does an Investigation Require Human Approval?

1. **Low confidence**: Reasoning Agent confidence below threshold
2. **Critical severity**: High-impact alerts always require human review
3. **Untrusted telemetry**: All ATLAS detections based on untrusted sources
4. **Shadow mode**: New rule families running in shadow mode
5. **Kill switch active**: Any active kill switch in any dimension

### Approval Workflow

1. Investigation enters `AWAITING_HUMAN` state
2. Dashboard displays the investigation in the Approvals Queue with a clickable approval card
3. Analyst reviews all evidence panels (IOC matches, CTEM exposures, ATLAS techniques, decision chain)
4. Analyst clicks **Approve** or **Reject**
5. On approval: investigation transitions to `RESPONDING`, Response Agent executes actions
6. On rejection: investigation transitions to `CLOSED` with rejection recorded in decision chain
7. On timeout: behaviour depends on severity:
   - Critical/High: escalate (remains `AWAITING_HUMAN`, emits `approval.escalated`)
   - Medium/Low: auto-close

---

## FP Short-Circuit Path

The FP (False Positive) Short-Circuit is a fast path that bypasses the full investigation pipeline for known benign alert patterns.

### How It Works

1. After IOC extraction (PARSING), the Orchestrator checks the `fp_patterns` table
2. If the alert matches a known FP pattern with confidence >= threshold:
   - Kill switch check (tenant, pattern, technique, datasource dimensions)
   - If not killed: auto-close immediately
   - Record `alert.auto_closed` audit event with pattern ID and confidence
3. If no match: continue to ENRICHING stage

### Kill Switch Dimensions

| Dimension | Key Pattern | Effect |
|-----------|-------------|--------|
| `tenant` | `kill_switch:tenant:{tenant_id}` | Blocks all FP auto-close for tenant |
| `pattern` | `kill_switch:pattern:{pattern_id}` | Blocks specific FP pattern |
| `technique` | `kill_switch:technique:{technique_id}` | Blocks FP for MITRE technique |
| `datasource` | `kill_switch:datasource:{source}` | Blocks FP from specific data source |

---

## Confidence Thresholds and Escalation Rules

| Condition | Tier | Behaviour |
|-----------|------|-----------|
| Confidence >= 0.8, severity low/medium | Tier 0/1 | Auto-respond |
| Confidence >= 0.8, severity high/critical | Tier 1 | Escalate to human |
| Confidence 0.6-0.8, any severity | Tier 1 | Escalate to human |
| Confidence < 0.6, severity high/critical | Tier 1+ (Opus) | Re-analyse with extended thinking |
| All ATLAS detections untrusted | Any | Force human review |
| Shadow mode active for rule family | Any | Log decision, force human review |

---

## Example Investigation Walkthrough: APT Lateral Movement

### Scenario
Cobalt Strike Beacon C2 callback detected on WORKSTATION-42 (user: jsmith, Finance department). Endpoint EDR flagged outbound HTTPS beaconing to known C2 infrastructure (185.220.101.34).

### Step-by-step

**1. RECEIVED** -- Alert ingested from Sentinel adapter via `alerts.raw`

**2. PARSING** -- IOC Extractor identifies:
- IP: `185.220.101.34` (C2 server)
- Host: `WORKSTATION-42`
- User: `jsmith`
- Process: `rundll32.exe`
- Technique: `T1071.001` (Web Protocols), `T1218.011` (Rundll32)

**3. FP CHECK** -- No matching FP pattern found. Proceed to enrichment.

**4. ENRICHING** (parallel):

- **Context Enricher**:
  - IOC match: `185.220.101.34` found in threat intel with confidence 95, linked to APT29
  - UEBA: `jsmith` has risk state `MEDIUM` (investigation priority 4, data fresh)
  - Similar incidents: 2 previous Cobalt Strike investigations found via Qdrant
  - Org context: `WORKSTATION-42` is in Finance, criticality `high`

- **CTEM Correlator**:
  - `WORKSTATION-42` has 1 open exposure: outdated EDR agent (severity HIGH, zone IT_UserWorkstations)
  - SLA deadline: 72 hours remaining

- **ATLAS Mapper**:
  - No ATLAS technique match (traditional attack, not adversarial AI)

**5. REASONING** -- Reasoning Agent (Tier 1 Sonnet) analyses:
- Classification: "APT lateral movement -- Cobalt Strike C2"
- Confidence: 0.92
- Severity: critical
- Recommended actions: [Isolate host, Block C2 IP, Reset user credentials, Initiate forensic collection]
- Decision: Escalate to human (critical severity)

**6. AWAITING_HUMAN** -- Investigation appears in analyst dashboard with:
- Full decision chain (5 entries)
- IOC match panel showing APT29 attribution
- Recommended actions with risk assessment
- Approval card with Approve/Reject buttons

**7. Analyst approves** -- Senior analyst reviews evidence, approves response.

**8. RESPONDING** -- Response Agent executes:
- Host isolation command prepared
- Firewall rule for C2 IP blocking prepared
- Credential reset ticket created
- Forensic collection initiated

**9. CLOSED** -- Investigation complete. Full audit trail archived via hash-chain. Investigation stored in incident memory for future similarity matching.
