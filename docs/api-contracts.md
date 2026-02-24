# ALUSKORT — API Contracts Reference

**Project:** ALUSKORT - Cloud-Neutral Security Reasoning Control Plane
**Generated:** 2026-02-21

---

## 1. Service Interface Summary

| Service | Protocol | Public Interface | Key Data Types |
|---------|----------|-----------------|----------------|
| context_gateway | Internal async | `ContextGateway.complete(GatewayRequest)` | GatewayRequest, GatewayResponse |
| llm_router | Internal async | `LLMRouter.route(TaskContext)` | TaskContext, RoutingDecision |
| orchestrator | Kafka + async | `InvestigationGraph.run(alert_id, ...)` | GraphState, InvestigationState |
| entity_parser | Kafka consumer | `EntityParserService.process_message(bytes)` | CanonicalAlert, AlertEntities |
| ctem_normaliser | Kafka consumer | `CTEMNormaliserService.process_message(topic, raw)` | CTEMExposure |
| atlas_detection | Scheduled | `DetectionRunner.run_all()` | DetectionResult |
| batch_scheduler | Timer + count | `BatchScheduler.tick()` | BatchTask, BatchJob |
| sentinel_adapter | EventHub/API | `SentinelConnector.start()` | CanonicalAlert |
| audit_service | REST + Kafka | `AuditService` API | AuditRecord, EvidencePackage |

---

## 2. Context Gateway

### `ContextGateway.complete(request: GatewayRequest) -> GatewayResponse`

**Pipeline:** sanitise → spend check → redact PII → build prompt → call LLM → validate output → strip quarantined → deanonymise

```python
@dataclass
class GatewayRequest:
    agent_id: str           # Calling agent identity
    task_type: str          # Maps to LLM tier
    system_prompt: str      # Task instructions
    user_content: str       # Alert/investigation content
    output_schema: dict | None  # Expected JSON schema
    tenant_id: str

@dataclass
class GatewayResponse:
    content: str            # Validated, deanonymised LLM output
    model_id: str
    tokens_used: int
    valid: bool             # Output validation passed
    raw_output: str         # Pre-validation output
    validation_errors: list[str]
    quarantined_ids: list[str]  # Technique IDs denied
    metrics: APICallMetrics | None
    injection_detections: list[str]
```

**Side effects:** Publishes `technique.quarantined` events to `audit.events` Kafka topic.

### Supporting Classes

| Class | Purpose |
|-------|---------|
| `AluskortAnthropicClient` | Anthropic API with retry (429/5xx backoff) |
| `SpendGuard` | Monthly cost tracking ($500 soft / $1000 hard) |
| `sanitise_input()` | 14+ injection regex patterns |
| `validate_output()` | Schema + technique ID quarantine |
| `redact_pii() / deanonymise_text()` | Reversible PII anonymisation |

---

## 3. LLM Router

### `LLMRouter.route(ctx: TaskContext) -> RoutingDecision`

**Override chain:** base tier → time budget → severity → context size → escalation → capability validation → health-aware selection → fallback population

```python
@dataclass
class TaskContext:
    task_type: str              # Maps to TASK_TIER_MAP
    context_tokens: int
    time_budget_seconds: int
    alert_severity: str
    tenant_tier: str
    requires_reasoning: bool
    previous_confidence: float | None  # For escalation

@dataclass
class RoutingDecision:
    tier: ModelTier
    model_config: ModelConfig
    max_tokens: int
    temperature: float
    use_extended_thinking: bool
    use_prompt_caching: bool
    reason: str
    fallback_configs: list[ModelConfig]
    degradation_level: str
```

### Task-to-Tier Mapping (13 task types)

| Tier 0 (Haiku) | Tier 1 (Sonnet) | Tier 2 (Batch) |
|-----------------|-----------------|----------------|
| ioc_extraction | investigation | fp_pattern_training |
| log_summarisation | ctem_correlation | playbook_generation |
| entity_normalisation | atlas_reasoning | agent_red_team |
| fp_suggestion | attack_path_analysis | detection_rule_generation |
| alert_classification | incident_report | retrospective_analysis |
| severity_assessment | playbook_selection | threat_landscape_summary |

### Circuit Breaker

```python
class CircuitBreaker:
    # States: CLOSED → OPEN → HALF_OPEN
    record_success() -> None
    record_failure() -> None
    is_available: bool  # property
```

---

## 4. Orchestrator

### `InvestigationGraph.run(alert_id, tenant_id, entities, alert_title, severity) -> GraphState`

**Pipeline:** IOC_EXTRACT → FP_CHECK → (parallel: ENRICH + CTEM + ATLAS) → REASON → (RESPOND | AWAIT_HUMAN) → CLOSED

### Agent Protocol

All agents implement:
```python
async def execute(state: GraphState) -> GraphState
```

| Agent | Tier | Inputs | Outputs (on GraphState) |
|-------|------|--------|------------------------|
| IOCExtractorAgent | Tier 0 | entities_raw | ioc_matches |
| ContextEnricherAgent | — | ioc_matches | ueba_context, similar_incidents |
| CTEMCorrelatorAgent | — | entities.asset_id | ctem_exposures |
| ATLASMapperAgent | — | techniques | atlas_techniques |
| ReasoningAgent | Tier 1→1+ | all context | classification, confidence, severity |
| ResponseAgent | — | classification | recommended_actions, playbook_matches |

### Executor Constraints

```python
@dataclass(frozen=True)
class ExecutorConstraints:
    allowlisted_playbooks: frozenset[str]
    min_confidence_for_auto_close: float
    require_fp_match_for_auto_close: bool
    can_modify_routing_policy: bool       # Always False
    can_disable_guardrails: bool          # Always False
```

### Approval Gate

- **Timeout:** 4 hours (`APPROVAL_TIMEOUT_HOURS`)
- **Triggers:** Tier 2 actions (isolate, disable, firewall rules)
- **Resume:** `InvestigationGraph.resume_from_approval(investigation_id, approved)`

---

## 5. Entity Parser

### Kafka Interface

| Direction | Topic | Schema |
|-----------|-------|--------|
| Consume | `alerts.raw` | `CanonicalAlert` JSON |
| Produce | `alerts.normalized` | `CanonicalAlert` + parsed `AlertEntities` |
| Produce | `alerts.raw.dlq` | Failed messages |

### `parse_alert_entities(entities_raw, raw_payload) -> AlertEntities`

Parses Sentinel JSON format or falls back to regex IOC extraction. Returns normalised entities across 10 categories (accounts, hosts, IPs, files, processes, URLs, DNS, file hashes, mailboxes, other).

---

## 6. CTEM Normaliser

### Kafka Interface

| Direction | Topic | Schema |
|-----------|-------|--------|
| Consume | `ctem.raw.wiz` | Vendor-specific |
| Consume | `ctem.raw.snyk` | Vendor-specific |
| Consume | `ctem.raw.garak` | Vendor-specific |
| Consume | `ctem.raw.art` | Vendor-specific |
| Consume | `ctem.raw.burp` | Vendor-specific |
| Consume | `ctem.raw.custom` | Vendor-specific |
| Produce | `ctem.normalized` | `CTEMExposure` |
| Produce | `ctem.normalized.dlq` | Failed normalisation |

### Normaliser Implementations

| Normaliser | Source | Special Features |
|-----------|--------|-----------------|
| WizNormaliser | Wiz cloud security | Neo4j threat correlation |
| SnykNormaliser | Snyk vulnerabilities | CVE → ATT&CK mapping |
| GarakNormaliser | GARAK LLM attacks | ATLAS technique mapping |
| ARTNormaliser | ATT&CK Range Testing | Technique validation results |

### Severity Matrix (consequence-weighted)

| Exploitability \ Consequence | safety_life | equipment | downtime | data_loss |
|------------------------------|-------------|-----------|----------|-----------|
| high | CRITICAL | CRITICAL | HIGH | MEDIUM |
| medium | CRITICAL | HIGH | MEDIUM | LOW |
| low | HIGH | MEDIUM | LOW | LOW |

---

## 7. ATLAS Detection

### `DetectionRunner.run_all() -> dict[str, list[DetectionResult]]`

10 statistical detection rules evaluated against PostgreSQL telemetry:

| Rule ID | Name | Technique | Safety |
|---------|------|-----------|--------|
| ATLAS-DETECT-001 | Training Data Poisoning | AML.T0020 | No |
| ATLAS-DETECT-002 | Model Extraction | AML.T0024 | No |
| ATLAS-DETECT-003 | Prompt Injection | AML.T0051 | No |
| ATLAS-DETECT-004 | Adversarial Evasion | AML.T0015 | **Yes** |
| ATLAS-DETECT-005 | Physics Oracle DoS | AML.T0029 | **Yes** (floor: 0.7) |
| ATLAS-DETECT-006 | Supply Chain | AML.T0010 | No |
| ATLAS-DETECT-007 | Insider Exfiltration | AML.T0035 | No |
| ATLAS-DETECT-008 | Alert Fatigue | — | No |
| ATLAS-DETECT-009 | Sensor Spoofing | AML.T0047 | **Yes** (floor: 0.7) |
| ATLAS-DETECT-010 | Partner Compromise | AML.T0042 | No |

**Output:** Triggered detections published to `alerts.raw` as `CanonicalAlert`.

---

## 8. Batch Scheduler

### `BatchScheduler.tick() -> BatchJob | None`

**Dual triggers:** count >= 50 tasks OR time >= 6 hours since last flush.

**Batch SLA:** 24 hours (alert on breach).

### Task Types

| Type | Output | Destination |
|------|--------|-------------|
| FP Pattern Generation | `FPPattern` | `fp_patterns` table + `knowledge.fp.approved` |
| Playbook Generation | `PlaybookDraft` | `playbooks` table |

---

## 9. Sentinel Adapter

### `SentinelConnector`

Two ingestion modes:

| Mode | Method | Latency | Use Case |
|------|--------|---------|----------|
| EventHub | Real-time streaming | Sub-second | Production |
| Log Analytics API | Polling (30s interval) | Seconds | Development/fallback |

**Output:** `CanonicalAlert` published to `alerts.raw`.

---

## 10. Audit Service

### REST API (`services/audit_service/api.py`)

| Endpoint | Method | Purpose |
|----------|--------|---------|
| Query audit records | GET | Filter by tenant, investigation, time range |
| Get evidence package | GET | Assembled investigation evidence |
| Verify chain | POST | On-demand chain integrity check |

### Kafka Interface

| Direction | Topic | Schema |
|-----------|-------|--------|
| Consume | `audit.events` | AuditProducer envelope |

### Evidence Package

Self-contained investigation evidence including: source alert, events, state transitions, LLM interactions, reasoning chain, actions, approvals, analyst feedback, and chain verification status.

---

## 11. Kafka Topic Catalog (31 topics)

### Core Pipeline

| Topic | Partitions | Retention | Producers | Consumers |
|-------|------------|-----------|-----------|-----------|
| `alerts.raw` | 4 | 7d | sentinel_adapter, atlas_detection | entity_parser |
| `alerts.normalized` | 4 | 7d | entity_parser | orchestrator |
| `incidents.enriched` | 4 | 7d | orchestrator | orchestrator/response |
| `actions.pending` | 2 | 7d | response_agent | action-executor |
| `audit.events` | 4 | 90d | ALL services | audit_service |

### LLM Priority Queues

| Topic | Partitions | Retention |
|-------|------------|-----------|
| `jobs.llm.priority.critical` | 4 | 3d |
| `jobs.llm.priority.high` | 4 | 3d |
| `jobs.llm.priority.normal` | 4 | 7d |
| `jobs.llm.priority.low` | 2 | 14d |

### CTEM

| Topic | Partitions | Retention |
|-------|------------|-----------|
| `ctem.raw.{wiz,snyk,garak,art,burp,custom}` | 2-4 | 30d |
| `ctem.normalized` | 4 | 30d |

### Knowledge

| Topic | Partitions | Retention |
|-------|------------|-----------|
| `knowledge.mitre.updated` | 1 | 7d |
| `knowledge.ti.ioc.new` | 2 | 7d |
| `knowledge.ti.report.new` | 2 | 7d |
| `knowledge.playbook.updated` | 1 | 7d |
| `knowledge.incident.stored` | 2 | 7d |
| `knowledge.fp.approved` | 1 | 7d |

### Dead-Letter Queues

`alerts.raw.dlq`, `ctem.normalized.dlq`, `jobs.llm.priority.*.dlq` (all 2 partitions, 30d retention)

---

## 12. Inter-Service Communication Patterns

### Event-Driven (Kafka)

```
sentinel_adapter ──→ alerts.raw ──→ entity_parser ──→ alerts.normalized ──→ orchestrator
atlas_detection  ──→ alerts.raw ──┘
ctem_normaliser  ──→ ctem.normalized ──→ orchestrator (enrichment)
ALL services     ──→ audit.events ──→ audit_service
```

### Direct Async Calls

| Caller | Callee | Purpose |
|--------|--------|---------|
| IOC Extractor | Context Gateway | IOC extraction (Haiku) |
| Reasoning Agent | Context Gateway | Classification (Sonnet/Opus) |
| Context Enricher | Redis, PG, Qdrant | Parallel enrichment |
| CTEM Correlator | PostgreSQL | Exposure lookup |
| ATLAS Mapper | PG + Qdrant | Technique mapping |
| Response Agent | PostgreSQL | Playbook selection |

### Execution Guarantees

| Service | Guarantee | Mechanism |
|---------|-----------|-----------|
| Entity Parser | At-least-once | Kafka offset management |
| CTEM Normaliser | At-least-once | Idempotent upsert via exposure_key |
| Orchestrator | Exactly-once | PG transaction per state transition |
| Batch Scheduler | At-most-once | Queue cleared before submit |
| Detection Rules | Stateless | Re-executable on schedule |
