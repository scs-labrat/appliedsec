# Operations Runbook

## Service Health Monitoring

### Health Endpoints

| Service | Endpoint | Expected Response |
|---------|----------|-------------------|
| Dashboard | `GET /health` | `{"status": "ok", "service": "dashboard"}` |
| Context Gateway | `GET /health` | `{"status": "ok", "service": "context-gateway"}` |
| LLM Router | `GET /health` | `{"status": "ok", "service": "llm-router"}` |
| Entity Parser | `GET /health` | `{"status": "ok"}` |
| Orchestrator | `GET /health` | `{"status": "ok"}` |
| CTEM Normaliser | `GET /health` | `{"status": "ok"}` |
| Audit Service | `GET /health` | `{"status": "ok"}` |
| Batch Scheduler | `GET /health` | `{"status": "ok"}` |

### Infrastructure Health

```bash
# PostgreSQL
docker compose exec postgres pg_isready -U aluskort
# Expected: accepting connections

# Redis
docker compose exec redis redis-cli ping
# Expected: PONG

# Kafka/Redpanda
docker compose exec kafka rpk cluster health
# Expected: HEALTHY

# Qdrant
curl http://localhost:6333/healthz
# Expected: 200 OK

# Neo4j
docker compose exec neo4j cypher-shell -u neo4j -p localdev "RETURN 1"
# Expected: 1
```

### Prometheus Alerts

Monitor the following alerts (defined in `infra/prometheus/alerts.yml`):

| Alert | Threshold | Action |
|-------|-----------|--------|
| LLM Circuit Breaker Open | State = open > 1m | Check Anthropic API status, verify fallback |
| Kafka Consumer Lag High | > 1,000 messages > 5m | Check consumer health, restart if needed |
| Kafka Consumer Lag Critical | > 10,000 messages > 5m | Immediate investigation, scale consumers |
| Investigation Stuck | AWAITING_HUMAN > 3 hours | Notify SOC lead, review pending approvals |
| Monthly Spend Soft Limit | > $500 | Review cost, check for anomalous usage |
| Monthly Spend Hard Cap | > $1,000 | LLM calls blocked, increase cap or wait for reset |
| Batch SLA Breach | Any breach | Check batch scheduler, review job queue |
| Detection Rule Failure | 0 evaluations > 15m | Check ATLAS detection runner, restart service |

---

## Log Locations and Formats

### Docker Compose

```bash
# View logs for a specific service
docker compose logs -f dashboard
docker compose logs -f orchestrator
docker compose logs -f context-gateway

# View all service logs
docker compose --profile services logs -f

# Filter by level
docker compose logs orchestrator 2>&1 | grep ERROR
```

### Kubernetes

```bash
# View pod logs
kubectl logs -n aluskort deployment/dashboard -f
kubectl logs -n aluskort deployment/orchestrator -f --tail=100

# View logs from all pods of a deployment
kubectl logs -n aluskort -l app.kubernetes.io/name=orchestrator -f
```

### Log Format

All services use Python's `logging` module with structured output:

```
LEVEL    TIMESTAMP    MODULE    MESSAGE
INFO     2026-03-29T10:15:30Z  orchestrator.graph  Investigation abc123 started
WARNING  2026-03-29T10:15:31Z  context_gateway.gateway  Injection risk detected: MEDIUM
ERROR    2026-03-29T10:15:32Z  llm_router.circuit_breaker  Anthropic API unavailable
```

---

## Common Failure Modes and Remediation

### 1. LLM Provider Outage

**Symptoms**: Context Gateway returning errors, circuit breaker OPEN, investigations stuck in REASONING.

**Remediation**:
1. Check Anthropic API status page
2. Verify circuit breaker state: check `AluskortLLMCircuitBreakerOpen` alert
3. System should auto-fallback to OpenAI if configured
4. If all providers down, system enters `deterministic_only` degradation mode
5. All new investigations will route to AWAITING_HUMAN
6. Once provider recovers, circuit breaker auto-resets

### 2. Kafka/Redpanda Unavailable

**Symptoms**: No new investigations appearing, consumer lag alerts, services failing health checks.

**Remediation**:
1. Check Kafka health: `rpk cluster health`
2. Check disk space on Kafka volumes
3. Restart Kafka: `docker compose restart kafka`
4. If data loss: topics auto-recreate but messages in-flight are lost
5. Check DLQ topics for failed messages after recovery

### 3. PostgreSQL Connection Failure

**Symptoms**: Dashboard 500 errors, Orchestrator cannot persist state, Audit Service failing.

**Remediation**:
1. Check PostgreSQL status: `pg_isready -U aluskort`
2. Check connection count: `SELECT count(*) FROM pg_stat_activity;`
3. Check disk space: `df -h /var/lib/postgresql/data`
4. Restart if needed: `docker compose restart postgres`
5. Verify migrations: `\dt` in psql

### 4. Redis Failure

**Symptoms**: Kill switches not working (fail-open), cache misses, session loss.

**Remediation**:
1. Check Redis: `redis-cli ping`
2. Check memory: `redis-cli info memory`
3. Kill switches fail-open by design (FP auto-close proceeds)
4. Restart: `docker compose restart redis`
5. Kill switch state is lost on restart -- re-activate if needed

### 5. Investigation Pipeline Stuck

**Symptoms**: Investigations in PARSING or ENRICHING for > 10 minutes.

**Remediation**:
1. Check Orchestrator logs for errors
2. Check agent health (Context Gateway, LLM Router)
3. Check for Kafka consumer lag on `alerts.normalized`
4. If agent crashed: restart Orchestrator
5. Stuck investigations may need manual state transition via database

### 6. Audit Chain Integrity Failure

**Symptoms**: Chain verification returns errors, hash mismatch alerts.

**Remediation**:
1. **DO NOT** modify audit records
2. Run chain verification: check `audit_chain_state` for the affected tenant
3. Identify the broken record by sequence number
4. If caused by concurrent writes: investigate and fix race condition
5. If caused by data corruption: escalate to security team
6. Archive evidence for forensic review

---

## Database Maintenance

### PostgreSQL Vacuum

```bash
# Analyse and vacuum all tables
docker compose exec postgres psql -U aluskort -c "VACUUM ANALYZE;"

# Vacuum a specific table
docker compose exec postgres psql -U aluskort -c "VACUUM ANALYZE investigations;"

# Check table bloat
docker compose exec postgres psql -U aluskort -c "
  SELECT schemaname, tablename,
         pg_size_pretty(pg_total_relation_size(schemaname||'.'||tablename)) as size
  FROM pg_tables
  WHERE schemaname = 'public'
  ORDER BY pg_total_relation_size(schemaname||'.'||tablename) DESC;
"
```

### PostgreSQL Reindex

```bash
# Reindex all indexes
docker compose exec postgres psql -U aluskort -c "REINDEX DATABASE aluskort;"

# Reindex specific table
docker compose exec postgres psql -U aluskort -c "REINDEX TABLE investigations;"
```

### PostgreSQL Backup

```bash
# Full database dump
docker compose exec postgres pg_dump -U aluskort aluskort > backup_$(date +%Y%m%d).sql

# Compressed dump
docker compose exec postgres pg_dump -U aluskort -Fc aluskort > backup_$(date +%Y%m%d).dump

# Restore
docker compose exec -T postgres psql -U aluskort aluskort < backup_20260329.sql
```

---

## Kafka Topic Management

### View Topics

```bash
# List all topics
docker compose exec kafka rpk topic list

# Describe a specific topic
docker compose exec kafka rpk topic describe alerts.normalized

# Check consumer groups and lag
docker compose exec kafka rpk group list
docker compose exec kafka rpk group describe orchestrator-group
```

### Manage Consumer Lag

```bash
# Reset consumer offset to latest (skip backlog)
docker compose exec kafka rpk group seek orchestrator-group --to end --topics alerts.normalized

# Reset to specific offset
docker compose exec kafka rpk group seek orchestrator-group --to 100 --topics alerts.normalized
```

### DLQ Management

```bash
# Check DLQ message count
docker compose exec kafka rpk topic describe alerts.raw.dlq

# Consume and inspect DLQ messages
docker compose exec kafka rpk topic consume alerts.raw.dlq --num 10

# Replay DLQ messages (publish back to main topic)
# Manual process: consume from DLQ, fix issues, republish to main topic
```

---

## Redis Cache Management

### Inspect Cache

```bash
# Check all keys
docker compose exec redis redis-cli KEYS "*"

# Check kill switch keys
docker compose exec redis redis-cli KEYS "kill_switch:*"

# Get specific kill switch
docker compose exec redis redis-cli GET "kill_switch:tenant:default"

# Check memory usage
docker compose exec redis redis-cli INFO memory
```

### Flush Cache

```bash
# Flush all keys (CAUTION: removes kill switches)
docker compose exec redis redis-cli FLUSHALL

# Delete specific key
docker compose exec redis redis-cli DEL "kill_switch:tenant:default"
```

---

## Scaling Procedures

### Horizontal Scaling (Kubernetes)

```bash
# Scale a deployment
kubectl scale deployment orchestrator -n aluskort --replicas=4

# Scale with autoscaler
kubectl autoscale deployment orchestrator -n aluskort --min=2 --max=8 --cpu-percent=70
```

### Kafka Partition Scaling

To increase throughput for high-volume topics:

```bash
# Increase partitions (cannot be decreased)
docker compose exec kafka rpk topic alter-config alerts.normalized --set partition-count=8
```

Note: Increasing partitions may affect message ordering within a topic.

---

## Incident Response for Platform Issues

### Severity Classification

| Severity | Definition | Response Time |
|----------|-----------|---------------|
| P1 (Critical) | Platform completely down, no investigations processing | < 15 minutes |
| P2 (High) | Major component failure, degraded operation | < 1 hour |
| P3 (Medium) | Non-critical component failure, workaround available | < 4 hours |
| P4 (Low) | Minor issue, no operational impact | Next business day |

### Incident Checklist

1. Identify affected component(s)
2. Check Prometheus alerts dashboard
3. Review service logs for errors
4. Check infrastructure health (Kafka, Postgres, Redis)
5. Determine if LLM provider is involved (check circuit breaker state)
6. Apply remediation from the failure modes section above
7. Verify recovery via health endpoints
8. Document incident in post-mortem

---

## Kill Switch Activation Procedure

### When to Activate

- FP auto-close producing incorrect results
- Suspected manipulation of FP patterns
- Compromised data source feeding bad data
- Regulatory requirement to pause automation for a tenant

### Activation Steps

1. **Identify the dimension**: tenant, pattern, technique, or datasource
2. **Navigate to Dashboard Settings** or use the API directly
3. **Activate the kill switch**:

```bash
# Via Redis directly (emergency)
docker compose exec redis redis-cli SET "kill_switch:tenant:default" \
  '{"activated_by":"admin","activated_at":"2026-03-29T10:00:00Z","reason":"Suspected FP manipulation"}'

# The KillSwitchManager also activates via the Orchestrator API
```

4. **Verify activation**: Check that FP auto-close is blocked for affected scope
5. **Investigate the root cause**
6. **Deactivate when resolved**:

```bash
docker compose exec redis redis-cli DEL "kill_switch:tenant:default"
```

### Kill Switch Behaviour

- **Fail-open**: If Redis is unreachable, auto-close proceeds (logged as warning)
- **Audit trail**: Activation/deactivation emits audit events
- **Scope**: Multiple kill switches across different dimensions are additive (any active one blocks)

---

## Rollback Procedures

### Application Rollback (Docker)

```bash
# Roll back to previous image
docker compose pull  # if using tagged images
docker compose --profile services down
docker compose --profile services up -d
```

### Application Rollback (Kubernetes)

```bash
# Check rollout history
kubectl rollout history deployment/orchestrator -n aluskort

# Rollback to previous revision
kubectl rollout undo deployment/orchestrator -n aluskort

# Rollback to specific revision
kubectl rollout undo deployment/orchestrator -n aluskort --to-revision=2

# Verify rollback
kubectl rollout status deployment/orchestrator -n aluskort
```

### Database Rollback

SQL migrations in ALUSKORT use `CREATE TABLE IF NOT EXISTS` and are idempotent. To roll back a migration:

1. Identify the affected tables
2. Drop the tables added by the migration (CAUTION: data loss)
3. Re-run the migration after fixing the issue

```sql
-- Example: rollback migration 012
DROP TABLE IF EXISTS connectors;
```

**Important**: Never modify `audit_records` or `audit_chain_state` tables. Audit data must be preserved for compliance.
