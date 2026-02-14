# ALUSKORT Operations Runbook

## 1. LLM Degradation

**Alert:** `AluskortLLMCircuitBreakerOpen`

### Symptoms
- Circuit breaker state = open
- LLM calls returning errors or timeouts
- Investigations stuck in REASONING state

### Steps
1. Check circuit breaker state:
   ```
   curl http://context-gateway/health | jq .dependencies
   ```
2. Verify Anthropic API status: check https://status.anthropic.com
3. Confirm deterministic-only mode is active:
   ```
   kubectl logs -n aluskort deploy/context-gateway | grep "circuit_breaker"
   ```
4. If Anthropic is down: no action needed, deterministic fallback handles it
5. If local issue: restart context-gateway pods:
   ```
   kubectl rollout restart deploy/context-gateway -n aluskort
   ```
6. Monitor recovery via Grafana LLM dashboard

### Escalation
- If unresolved after 30 minutes, escalate to platform engineering

---

## 2. Kafka Lag Spike

**Alert:** `AluskortKafkaConsumerLagHigh` / `AluskortKafkaConsumerLagCritical`

### Symptoms
- Consumer lag > 1,000 messages (warning) or > 10,000 (critical)
- Alert processing delays
- Investigation backlog growing

### Steps
1. Identify the lagging consumer group and topic:
   ```
   kubectl exec -n aluskort deploy/entity-parser -- \
     kafka-consumer-groups --bootstrap-server $KAFKA_BOOTSTRAP \
     --describe --group aluskort-entity-parser
   ```
2. Check for stuck partitions (lag not decreasing):
   ```
   # Run twice with 30s gap, compare lag values
   ```
3. Check consumer pod health:
   ```
   kubectl get pods -n aluskort -l app.kubernetes.io/name=entity-parser
   kubectl logs -n aluskort deploy/entity-parser --tail=100
   ```
4. If consumer is healthy but slow — scale the consumer group:
   ```
   kubectl scale deploy/entity-parser -n aluskort --replicas=4
   ```
5. If consumer is crash-looping — check for poison messages in the topic
6. If partition is stuck — reassign partitions or restart consumer

### Escalation
- If lag > 10,000 for > 15 minutes, escalate to platform engineering

---

## 3. Cost Overrun

**Alert:** `AluskortMonthlySpendSoftLimit` / `AluskortMonthlySpendHardCap`

### Symptoms
- Monthly spend exceeds $500 (soft) or $1,000 (hard)
- Hard cap triggers LLM call rejection

### Steps
1. Check spend breakdown by tier:
   ```
   curl http://context-gateway/metrics | grep aluskort_llm_cost_usd_total
   ```
2. Identify the cause:
   - **Escalation storm:** High Tier 1+ usage → check confidence thresholds
   - **Batch spike:** Large batch submitted → check batch scheduler queue
   - **Runaway investigation:** Single investigation with many LLM calls
3. If escalation storm:
   ```
   # Temporarily raise confidence threshold to reduce escalations
   kubectl set env deploy/orchestrator -n aluskort \
     ESCALATION_CONFIDENCE_THRESHOLD=0.5
   ```
4. If batch spike:
   ```
   # Pause batch scheduler
   kubectl scale deploy/batch-scheduler -n aluskort --replicas=0
   ```
5. After investigation, adjust limits if needed:
   ```
   kubectl set env deploy/context-gateway -n aluskort \
     MONTHLY_SPEND_HARD_CAP=1500
   ```

### Escalation
- Hard cap hit: notify SOC manager immediately
- Requires budget approval to increase cap

---

## 4. DLQ Processing

**Alert:** Manual check (no automatic alert)

### Symptoms
- Messages accumulating in DLQ topics
- Processing failures in normaliser or entity parser

### Steps
1. List DLQ topics and their sizes:
   ```
   kafka-topics --bootstrap-server $KAFKA_BOOTSTRAP --list | grep dlq
   kafka-consumer-groups --bootstrap-server $KAFKA_BOOTSTRAP \
     --describe --group aluskort-dlq-processor
   ```
2. Inspect DLQ messages:
   ```
   kafka-console-consumer --bootstrap-server $KAFKA_BOOTSTRAP \
     --topic alerts.raw.dlq --from-beginning --max-messages 5
   ```
3. Identify the failure reason from message headers or payload
4. Fix the root cause (schema mismatch, malformed data, etc.)
5. Replay failed messages:
   ```
   # Move messages from DLQ back to the source topic
   kafka-console-consumer --bootstrap-server $KAFKA_BOOTSTRAP \
     --topic alerts.raw.dlq --from-beginning | \
   kafka-console-producer --bootstrap-server $KAFKA_BOOTSTRAP \
     --topic alerts.raw
   ```
6. Clear the DLQ after replay:
   ```
   kafka-topics --bootstrap-server $KAFKA_BOOTSTRAP \
     --alter --topic alerts.raw.dlq \
     --config retention.ms=1000
   # Wait 1 minute, then restore retention
   kafka-topics --bootstrap-server $KAFKA_BOOTSTRAP \
     --alter --topic alerts.raw.dlq \
     --config retention.ms=2592000000
   ```

### Escalation
- If DLQ contains > 100 messages, investigate root cause before replay

---

## 5. Stuck Investigations

**Alert:** `AluskortInvestigationStuck`

### Symptoms
- Investigation in AWAITING_HUMAN state for > 3 hours

### Steps
1. Identify stuck investigations:
   ```
   curl http://orchestrator/api/investigations?state=awaiting_human
   ```
2. Check the pending action details for each investigation
3. Notify the assigned SOC analyst
4. If analyst is unavailable, the SOC lead should review and act
5. For timeout: the approval gate auto-expires after 4 hours, transitioning
   the investigation to a safe default state

### Escalation
- If > 5 investigations stuck simultaneously, escalate to SOC lead

---

## 6. Service Recovery

### Steps for any crashed service
1. Check pod status:
   ```
   kubectl get pods -n aluskort
   ```
2. Check logs for the failing pod:
   ```
   kubectl logs -n aluskort <pod-name> --tail=200
   ```
3. Check readiness probe failures:
   ```
   kubectl describe pod <pod-name> -n aluskort | grep -A5 "Conditions"
   ```
4. Restart the deployment:
   ```
   kubectl rollout restart deploy/<service-name> -n aluskort
   ```
5. Verify recovery:
   ```
   kubectl rollout status deploy/<service-name> -n aluskort
   curl http://<service-name>.aluskort.svc.cluster.local/ready
   ```
