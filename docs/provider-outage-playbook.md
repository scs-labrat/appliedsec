# Provider Outage Playbook

Documented RTO/RPO per provider outage scenario, degradation policies,
auto-close authority rules, and confidence threshold adjustments.

## Degradation Levels

| Level | Enum Value | Trigger Condition |
|---|---|---|
| Full Capability | `full_capability` | All providers healthy |
| Secondary Active | `secondary_active` | Primary (Anthropic) down, secondary (OpenAI) up |
| Deterministic Only | `deterministic_only` | All LLM providers down |
| Passthrough | `passthrough` | All infrastructure down (Kafka, DB, etc.) |

## Scenario Table

| Provider State | Degradation Level | Auto-Close | Extended Thinking | Confidence Override | Max Tier | RTO | RPO |
|---|---|---|---|---|---|---|---|
| All healthy | FULL_CAPABILITY | Allowed | Available | None | All tiers | N/A | N/A |
| Anthropic down, OpenAI up | SECONDARY_ACTIVE | Allowed | **Not available** | **0.95** | All tiers (via fallback) | < 30 s (automatic failover) | Zero (no data loss) |
| All LLM providers down | DETERMINISTIC_ONLY | **Not allowed** | Not available | N/A | **None** (no LLM calls) | Depends on provider recovery | Zero (alerts queued) |
| All infrastructure down | PASSTHROUGH | **Not allowed** | Not available | N/A | None | Depends on infrastructure recovery | Bounded by Kafka retention (30 d) |

## Per-Scenario Details

### FULL_CAPABILITY

- **System behavior**: Normal operation. All tiers available. Anthropic is primary provider.
- **Auto-close**: Allowed per normal confidence thresholds.
- **Extended thinking**: Available for Tier 1+ (Opus) tasks.
- **Monitoring**: All metrics at baseline. No special action required.

### SECONDARY_ACTIVE

- **System behavior**: Primary provider (Anthropic) circuit breaker is OPEN. LLMRouter automatically routes to OpenAI fallback providers. Tier 0 uses `gpt-4o-mini`, Tier 1 uses `gpt-4o`. Tier 1+ has no fallback (< 1% volume; accept degradation). Tier 2 (batch) has no fallback (can wait).
- **Confidence threshold**: Raised to **0.95** to compensate for potential quality differences between providers.
- **Extended thinking**: **Not available** (OpenAI models do not support this feature).
- **Auto-close**: Still allowed, but with raised confidence threshold.
- **Cost**: Per-provider cost tracking remains active. OpenAI pricing differs from Anthropic — monitor `aluskort_llm_cost_usd_total` by provider label.
- **Recovery**: Circuit breaker automatically probes primary after `recovery_timeout_seconds` (default 30 s). On successful probe, transitions HALF_OPEN -> CLOSED and system returns to FULL_CAPABILITY.

### DETERMINISTIC_ONLY

- **System behavior**: No LLM calls possible. All alerts are queued for human review. Only deterministic pipeline stages run (entity parsing with regex, IOC extraction with pattern matching).
- **Auto-close**: **Not allowed**. All investigations remain open for human analyst review.
- **Monitoring**: Watch for Kafka consumer lag growth. Alert queue will grow until provider recovery.
- **Operator action**:
  1. Verify all provider status pages (Anthropic, OpenAI).
  2. Check circuit breaker states via health endpoint.
  3. No manual intervention needed — system automatically recovers when providers return.
  4. If extended outage (> 1 hour), notify SOC lead about investigation backlog.

### PASSTHROUGH

- **System behavior**: Reserved for catastrophic failure where all infrastructure (Kafka, DB, LLM providers) is unavailable. Alerts may be lost if Kafka is also down.
- **Auto-close**: **Not allowed**.
- **Operator action**: Focus on infrastructure recovery. Alerts within Kafka retention window (30 days) will be reprocessed on recovery.

## Auto-Close Authority Rules

| Degradation Level | Auto-Close Allowed | Rationale |
|---|---|---|
| FULL_CAPABILITY | Yes | Normal operation, LLM confidence is reliable |
| SECONDARY_ACTIVE | Yes (with 0.95 threshold) | Fallback provider may have different quality profile |
| DETERMINISTIC_ONLY | **No** | No LLM analysis available to support auto-close decision |
| PASSTHROUGH | **No** | System is non-functional |

## Confidence Threshold Adjustments

| Degradation Level | Confidence Override | Effect |
|---|---|---|
| FULL_CAPABILITY | None (use default) | Normal thresholds apply |
| SECONDARY_ACTIVE | 0.95 | Higher bar for automated decisions during failover |
| DETERMINISTIC_ONLY | N/A | No LLM calls made |
| PASSTHROUGH | N/A | No LLM calls made |

## Monitoring

### Prometheus Metrics to Watch

- `aluskort_circuit_breaker_state` — per-provider circuit breaker state
- `aluskort_llm_provider_selected_total` — provider selection counts (watch for fallback spike)
- `aluskort_llm_cost_usd_total` — cost by provider (watch for cost changes during failover)
- `aluskort_kafka_consumer_lag` — alert queue growth during LLM outage

### Alerting Thresholds

- Circuit breaker OPEN for any provider → `AluskortLLMCircuitBreakerOpen` (warning)
- All providers OPEN → `AluskortAllProvidersDown` (critical)
- Consumer lag > 10,000 during DETERMINISTIC_ONLY → escalate to SOC lead

## Recovery Procedures

1. **Automatic recovery**: Circuit breaker probes primary after recovery timeout (30 s default). Successful probe closes breaker and restores FULL_CAPABILITY.
2. **Verification**: After recovery, check:
   - `aluskort_circuit_breaker_state` returns to `closed` for all providers
   - Investigation processing resumes (Kafka lag decreasing)
   - Cost metrics show primary provider usage resuming
3. **Backlog processing**: Investigations queued during DETERMINISTIC_ONLY will be processed once LLM availability is restored. Expect a temporary lag spike during backlog drain.
