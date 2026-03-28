# LLM Architecture

## 4-Tier Model Routing

ALUSKORT uses a tiered model architecture to balance cost, latency, and reasoning depth. The LLM Router selects the optimal tier for each task based on multiple factors.

```
+---------------------------------------------------------------+
|                     LLM Router                                 |
|                                                                |
|  Input: TaskContext (task_type, severity, context_tokens,      |
|         time_budget, previous_confidence, requires_reasoning)  |
|                                                                |
|  Override Chain:                                                |
|  1. Base tier from TASK_TIER_MAP                               |
|  2. Time budget < 3s  -->  force Tier 0                       |
|  3. Critical + reasoning  -->  min Tier 1                     |
|  4. Context > 100K tokens  -->  min Tier 1                    |
|  5. Low confidence escalation  -->  Tier 1+                   |
|  6. Capability validation (log-only)                           |
|  7. Populate fallback configs                                  |
|  8. Health-aware primary selection                              |
+---------------------------------------------------------------+
```

### Tier Definitions

| Tier | Model | Provider | Use Case | Max Tokens | Temperature | Cost (input/output per MTok) |
|------|-------|----------|----------|-----------|-------------|------------------------------|
| **Tier 0** | Claude Haiku 4.5 | Anthropic | Fast, cheap tasks | 2,048 | 0.1 | $0.80 / $4.00 |
| **Tier 1** | Claude Sonnet 4.5 | Anthropic | Deep reasoning | 8,192 | 0.2 | $3.00 / $15.00 |
| **Tier 1+** | Claude Opus 4.6 | Anthropic | Complex / escalation | 16,384 | 0.2 | $15.00 / $75.00 |
| **Tier 2** | Claude Sonnet 4.5 (Batch) | Anthropic | Offline batch jobs | 16,384 | 0.3 | $1.50 / $7.50 |

### Fallback Providers

| Tier | Fallback Model | Provider | Context Limit |
|------|---------------|----------|---------------|
| Tier 0 | GPT-4o-mini | OpenAI | 128K |
| Tier 1 | GPT-4o | OpenAI | 128K |
| Tier 1+ | GPT-4o | OpenAI | 128K (no extended thinking) |
| Tier 2 | -- | None | No fallback for batch |

---

## Task-to-Tier Mapping

### Tier 0 Tasks (Fast, Cheap -- Haiku)

| Task Type | JSON Reliability | Max Context | Latency SLO |
|-----------|-----------------|-------------|-------------|
| `ioc_extraction` | Required | 4,096 | 3s |
| `log_summarisation` | -- | 8,192 | 3s |
| `entity_normalisation` | Required | 4,096 | 3s |
| `fp_suggestion` | Required | 4,096 | 3s |
| `alert_classification` | Required | 4,096 | 3s |
| `severity_assessment` | Required | 4,096 | 3s |

### Tier 1 Tasks (Deep Reasoning -- Sonnet)

| Task Type | Tool Use | JSON Reliability | Max Context |
|-----------|----------|-----------------|-------------|
| `investigation` | Required | Required | 100,000 |
| `ctem_correlation` | Required | Required | 50,000 |
| `atlas_reasoning` | Required | Required | 50,000 |
| `attack_path_analysis` | Required | Required | 100,000 |
| `incident_report` | -- | Required | 50,000 |
| `playbook_selection` | Required | Required | 50,000 |

### Tier 2 Tasks (Batch Offline -- Sonnet at 50% cost)

| Task Type | Tool Use | Max Context | Latency SLO |
|-----------|----------|-------------|-------------|
| `fp_pattern_training` | -- | 200,000 | 24 hours |
| `playbook_generation` | Required | 100,000 | 24 hours |
| `agent_red_team` | Required | 200,000 | 24 hours |
| `detection_rule_generation` | Required | 100,000 | 24 hours |
| `retrospective_analysis` | -- | 200,000 | 24 hours |
| `threat_landscape_summary` | -- | 200,000 | 24 hours |

---

## Context Gateway Pipeline

The Context Gateway is the single point of LLM interaction for all ALUSKORT services. Every LLM call passes through this 9-stage pipeline.

```
Request
  |
  v
+--[1. Spend Guard]----------------------------------+
| Check monthly budget against hard/soft caps         |
| Hard cap ($1000): reject with error                 |
| Soft cap ($500): allow but emit spend.soft_limit    |
+-----------------------------------------------------+
  |
  v
+--[2. Injection Classification]----------------------+
| RegexInjectionClassifier scans user content          |
| Risk levels: NONE, LOW, MEDIUM, HIGH                 |
| Actions: PASS, SUMMARIZE, QUARANTINE                  |
| No redaction markers (prevents tuning oracle attack)  |
+-----------------------------------------------------+
  |
  v
+--[3. Content Transform]----------------------------+
| PASS: content unchanged                              |
| SUMMARIZE: lossy summarization (strips detail)       |
| QUARANTINE: reject immediately, emit audit event     |
+-----------------------------------------------------+
  |
  v
+--[4. PII Redaction]---------------------------------+
| Regex-based PII detection and replacement            |
| Generates RedactionMap for later deanonymisation     |
| Covers: emails, IPs, names, SSNs, credit cards      |
+-----------------------------------------------------+
  |
  v
+--[5. Structured Prompt Building]--------------------+
| XML evidence isolation: <untrusted_alert_data>       |
| System blocks with prompt caching                    |
| Structured evidence blocks wrapping alert content    |
+-----------------------------------------------------+
  |
  v
+--[6. Anthropic API Call]----------------------------+
| AluskortAnthropicClient with retry and metrics       |
| Returns response_text + APICallMetrics               |
| (Skipped if quarantined in step 3)                   |
+-----------------------------------------------------+
  |
  v
+--[7. Output Validation]----------------------------+
| Validate against output schema if provided           |
| Check technique IDs against taxonomy_ids allowlist   |
| Unknown IDs -> quarantined (deny-by-default)         |
+-----------------------------------------------------+
  |
  v
+--[7b. Strip Quarantined IDs]-----------------------+
| Word-boundary regex removal of quarantined IDs       |
| Prevents hallucinated techniques from driving        |
| automation (playbook selection, severity, FP)        |
+-----------------------------------------------------+
  |
  v
+--[8. Deanonymise]----------------------------------+
| Restore PII from RedactionMap                        |
| Map anonymised tokens back to original values        |
+-----------------------------------------------------+
  |
  v
GatewayResponse (content, model_id, tokens_used, valid, quarantined_ids)
```

---

## Spend Guard and Budget Enforcement

### Budget Tiers

| Tier | Threshold | Action |
|------|-----------|--------|
| Soft Limit | $500/month | Emit `spend.soft_limit` audit event, alert ops |
| Hard Cap | $1,000/month | Reject all LLM calls, emit `spend.hard_limit` |

### Spend Tracking

The `SpendGuard` records every LLM call with:
- Cost in USD
- Model ID
- Task type
- Tenant ID

Monthly totals are tracked per-tenant and globally. The Prometheus alert `AluskortMonthlySpendHardCap` fires when the global spend exceeds the hard cap.

### Target Monthly Spend

Under normal operations, the target monthly spend is **$250-$400**, achieved by:
- Routing 60-70% of tasks to Tier 0 (Haiku at $0.80/$4.00 per MTok)
- Using batch pricing for offline jobs (50% discount)
- FP short-circuit eliminating LLM calls for known benign patterns
- Prompt caching reducing input token costs

---

## Prompt Engineering Patterns

### Structured Evidence Isolation

All untrusted alert data is wrapped in XML delimiters to prevent prompt injection:

```xml
<untrusted_alert_data>
  <alert_title>Cobalt Strike Beacon Detected</alert_title>
  <alert_description>EDR flagged outbound beaconing...</alert_description>
  <entities_json>{"ips": ["185.220.101.34"], ...}</entities_json>
</untrusted_alert_data>
```

This pattern:
- Clearly separates trusted system prompts from untrusted input
- Allows the LLM to reason about potentially malicious content safely
- Prevents injection payloads in alert titles/descriptions from escaping the evidence block

### Lossy Summarisation (Anti-Injection)

When the injection classifier detects MEDIUM risk, content is summarised using a lossy transform that:
- Strips specific commands and injection patterns
- Preserves security-relevant factual content
- Does NOT use redaction markers (which could serve as a tuning oracle)

### System Block Caching

System prompts use Anthropic's prompt caching with `cache_control` blocks:
- Agent role descriptions cached across calls
- Reduces input token costs by up to 90% for repeated system prompts
- Cache TTL managed per-task-type

---

## Circuit Breaker and Health-Aware Fallback

### Provider Health Registry

The `ProviderHealthRegistry` tracks the health of each LLM provider:

| State | Meaning | Behaviour |
|-------|---------|-----------|
| Healthy | All calls succeeding | Normal routing |
| Degraded | Error rate elevated | Log warnings, continue |
| Unhealthy | Consecutive failures exceed threshold | Swap to fallback |

### Degradation Levels

| Level | Condition | Effect |
|-------|-----------|--------|
| `full_capability` | All providers healthy | Normal operation |
| `secondary_active` | Primary (Anthropic) down, fallback (OpenAI) active | Confidence threshold override 0.95, no extended thinking, max Tier 1, alert ops |
| `deterministic_only` | All LLM providers down | Confidence override 1.0, max Tier 0, alert ops, all investigations -> AWAITING_HUMAN |

### Failover Flow

```
1. Router selects primary model (Anthropic)
2. ProviderHealthRegistry.is_available(anthropic) == False
3. Router iterates FALLBACK_REGISTRY[tier]
4. First healthy fallback selected (OpenAI)
5. Emit routing.provider_failover audit event
6. Record provider selection metrics (is_fallback=True)
7. Compute degradation level and include in RoutingDecision
```

---

## Cost Tracking and Metrics

### Per-Call Metrics (APICallMetrics)

| Field | Description |
|-------|-------------|
| `model_id` | Model used (e.g., claude-haiku-4-5-20251001) |
| `input_tokens` | Input tokens consumed |
| `output_tokens` | Output tokens generated |
| `cost_usd` | Computed cost based on tier pricing |
| `latency_ms` | End-to-end API call latency |

### Routing Audit Trail

Every LLM call emits a `routing.tier_selected` audit event containing:
- Provider and model ID
- Input/output token counts
- Cost in USD
- Latency
- System prompt hash (SHA-256 first 16 chars)
- Task type

### Prometheus Metrics

| Metric | Type | Description |
|--------|------|-------------|
| `aluskort_llm_cost_usd_total` | Counter | Total LLM spend in USD |
| `aluskort_llm_circuit_breaker_state` | Gauge | Circuit breaker state (open/closed) |
| `aluskort_llm_calls_total` | Counter | Total LLM API calls by tier |
| `aluskort_llm_latency_seconds` | Histogram | LLM call latency distribution |
