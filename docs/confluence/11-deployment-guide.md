# Deployment Guide

## Prerequisites

| Requirement | Version | Purpose |
|-------------|---------|---------|
| Docker | 24.0+ | Container runtime |
| Docker Compose | 2.20+ | Local development orchestration |
| Python | 3.12+ | Application runtime |
| pip | latest | Python package management |
| kubectl | 1.28+ | Kubernetes CLI (production only) |
| Helm | 3.x | Kubernetes package manager (optional) |
| Anthropic API Key | -- | LLM API access |

---

## Local Development Setup

### Step 1: Clone and Install

```bash
git clone https://github.com/org/aluskort.git
cd aluskort
pip install -e .
```

### Step 2: Set Environment Variables

```bash
export ANTHROPIC_API_KEY="sk-ant-..."
```

### Step 3: Start Infrastructure

```bash
# Start all infrastructure services (Kafka, PostgreSQL, Redis, Qdrant, Neo4j, MinIO)
docker compose up -d
```

This starts:
- **Kafka/Redpanda** on port 9092
- **PostgreSQL 16** on port 5432 (user: `aluskort`, password: `localdev`, db: `aluskort`)
- **Redis 7** on port 6379
- **Qdrant** on ports 6333/6334
- **Neo4j 5** on ports 7474/7687 (user: `neo4j`, password: `localdev`)
- **MinIO** on ports 9000/9001 (user: `minioadmin`, password: `minioadmin`)

### Step 4: Wait for Health Checks

```bash
# Verify all infrastructure is healthy
docker compose ps
```

All services should show `healthy` status.

### Step 5: Create Kafka Topics

```bash
python -m infra.scripts.create_kafka_topics --bootstrap-servers localhost:9092
```

Creates all 30 Kafka topics (9 core + 9 CTEM + 6 DLQ + 6 knowledge).

### Step 6: Initialise Databases

```bash
# PostgreSQL migrations run automatically via docker-entrypoint-initdb.d
# Verify tables exist:
docker compose exec postgres psql -U aluskort -c "\dt"

# Initialise Qdrant collections
python -m infra.scripts.init_qdrant

# Initialise Neo4j schema
python -m infra.scripts.init_neo4j
```

### Step 7: Start Application Services

```bash
# Start all application services
docker compose --profile services up -d
```

Or run individual services locally for development:

```bash
# Dashboard (port 8080)
uvicorn services.dashboard.app:app --host 0.0.0.0 --port 8080 --reload

# Context Gateway (port 8030)
uvicorn context_gateway.api:app --host 0.0.0.0 --port 8030 --reload

# LLM Router (port 8031)
uvicorn llm_router.api:app --host 0.0.0.0 --port 8031 --reload

# Entity Parser
python -m entity_parser.service

# Orchestrator
python -m orchestrator.service

# CTEM Normaliser
python -m ctem_normaliser.service
```

### Step 8: Verify

```bash
# Dashboard
curl http://localhost:8080/health
# Expected: {"status":"ok","service":"dashboard"}

# Context Gateway
curl http://localhost:8030/health

# LLM Router
curl http://localhost:8031/health
```

Open `http://localhost:8080` in a browser to access the dashboard.

---

## Environment Variables Reference

### Infrastructure

| Variable | Default | Services | Description |
|----------|---------|----------|-------------|
| `KAFKA_BOOTSTRAP_SERVERS` | `kafka:9092` | Entity Parser, Orchestrator, CTEM Normaliser, Batch Scheduler | Kafka/Redpanda bootstrap servers |
| `POSTGRES_DSN` | `postgresql://aluskort:localdev@postgres:5432/aluskort` | All services | PostgreSQL connection string |
| `REDIS_HOST` | `redis` | Orchestrator, Dashboard | Redis hostname |
| `REDIS_PORT` | `6379` | Orchestrator, Dashboard | Redis port |
| `QDRANT_HOST` | `qdrant` | Orchestrator, Batch Scheduler | Qdrant hostname |
| `QDRANT_PORT` | `6333` | Orchestrator, Batch Scheduler | Qdrant HTTP port |
| `NEO4J_URI` | `bolt://neo4j:7687` | Orchestrator | Neo4j bolt connection URI |
| `NEO4J_HOST` | `neo4j` | Orchestrator | Neo4j hostname (K8s) |
| `NEO4J_PORT` | `7687` | Orchestrator | Neo4j bolt port (K8s) |

### API Keys

| Variable | Default | Services | Description |
|----------|---------|----------|-------------|
| `ANTHROPIC_API_KEY` | -- (required) | Context Gateway | Anthropic API key for LLM calls |

### Service Configuration

| Variable | Default | Services | Description |
|----------|---------|----------|-------------|
| `PORT` | varies | Context Gateway, LLM Router, Dashboard | HTTP listen port |
| `CONTEXT_GATEWAY_URL` | `http://context-gateway:8030` | Orchestrator, LLM Router | Context Gateway base URL |
| `LOG_LEVEL` | `INFO` | All | Logging verbosity |
| `EMBEDDING_MODEL` | `text-embedding-3-small` | Batch Scheduler | OpenAI embedding model |
| `EMBEDDING_DIMENSIONS` | `1536` | Batch Scheduler | Embedding vector dimensions |

### Spend Control

| Variable | Default | Services | Description |
|----------|---------|----------|-------------|
| `MONTHLY_SPEND_HARD_CAP` | `1000` | Context Gateway | Hard spend limit in USD |
| `MONTHLY_SPEND_SOFT_ALERT` | `500` | Context Gateway | Soft spend alert threshold in USD |

### SIEM Adapters

| Variable | Default | Services | Description |
|----------|---------|----------|-------------|
| `SENTINEL_WORKSPACE_ID` | -- | Sentinel Adapter | Azure Sentinel workspace ID |
| `SENTINEL_TENANT_ID` | -- | Sentinel Adapter | Azure AD tenant ID |
| `SENTINEL_CLIENT_ID` | -- | Sentinel Adapter | Azure AD app client ID |
| `SENTINEL_CLIENT_SECRET` | -- | Sentinel Adapter | Azure AD app client secret |
| `ELASTIC_HOST` | -- | Elastic Adapter | Elasticsearch host URL |
| `ELASTIC_API_KEY` | -- | Elastic Adapter | Elasticsearch API key |
| `SPLUNK_HOST` | -- | Splunk Adapter | Splunk management API host |
| `SPLUNK_TOKEN` | -- | Splunk Adapter | Splunk HEC/API token |

### Object Storage

| Variable | Default | Services | Description |
|----------|---------|----------|-------------|
| `MINIO_ENDPOINT` | `minio:9000` | Audit Service | MinIO S3 endpoint |
| `MINIO_ACCESS_KEY` | `minioadmin` | Audit Service | MinIO access key |
| `MINIO_SECRET_KEY` | `minioadmin` | Audit Service | MinIO secret key |

---

## Database Migration Procedure

### Automatic (Docker Compose)

PostgreSQL migrations in `infra/migrations/` are automatically applied on container startup via Docker's `docker-entrypoint-initdb.d` volume mount:

```yaml
volumes:
  - ./infra/migrations:/docker-entrypoint-initdb.d
```

Files are executed in alphabetical order (001 through 013).

### Manual Application

```bash
# Connect to PostgreSQL
docker compose exec postgres psql -U aluskort -d aluskort

# Apply a specific migration
\i /docker-entrypoint-initdb.d/001_core_tables.sql

# Verify
\dt
```

### Migration List

| Order | File | Key Changes |
|-------|------|-------------|
| 001 | `001_core_tables.sql` | mitre_techniques, mitre_groups, taxonomy_ids, threat_intel_iocs, playbooks, playbook_steps, incident_memory, fp_patterns, org_context |
| 002 | `002_ctem_tables.sql` | ctem_exposures, ctem_validations, ctem_remediations |
| 003 | `003_atlas_tables.sql` | Atlas detection storage tables |
| 004 | `004_atlas_telemetry.sql` | Atlas telemetry and trust level tracking |
| 005 | `005_taxonomy_seed_data.sql` | Seed MITRE ATT&CK and ATLAS technique IDs |
| 006 | `006_audit_records.sql` | Audit trail record storage |
| 007 | `007_audit_chain_state.sql` | Per-tenant hash chain state |
| 008 | `008_fp_governance.sql` | FP pattern governance |
| 009 | `009_embedding_migration.sql` | Vector embedding migration log |
| 010 | `010_incident_memory_rare.sql` | Incident memory rare entity columns |
| 011 | `011_dashboard_sessions.sql` | Dashboard session management |
| 012 | `012_connectors.sql` | SIEM connector configuration |
| 013 | `013_llm_providers.sql` | LLM providers and models tables |

---

## Docker Build and Deploy

### Build the Application Image

```bash
# Build from the project root using the shared Dockerfile
docker build -t aluskort:latest .
```

The single Dockerfile is shared by all services. Each service is selected via the `command` field in docker-compose or Kubernetes deployment.

### Tag and Push

```bash
docker tag aluskort:latest ghcr.io/aluskort/aluskort:latest
docker push ghcr.io/aluskort/aluskort:latest
```

---

## AWS Production Deployment (Terraform)

ALUSKORT includes a complete Terraform configuration for production deployment on AWS, located in `infra/terraform/`.

### Prerequisites (AWS)

| Requirement | Version | Purpose |
|-------------|---------|---------|
| Terraform | 1.5+ | Infrastructure as Code |
| AWS CLI | 2.x | AWS credential management |
| Docker | 24.0+ | Container image build/push |
| AWS Account | -- | With IAM permissions for VPC, ECS, RDS, ElastiCache, MSK, ECR, ALB, Secrets Manager, CloudWatch |

### Infrastructure Provisioned

| Component | Service | Details |
|-----------|---------|---------|
| **Networking** | VPC | 3-AZ, public/private subnets, NAT gateway, VPC flow logs |
| **Compute** | ECS Fargate | 6 services with auto-scaling, circuit breaker rollback |
| **Database** | RDS PostgreSQL 16 | Multi-AZ (prod), encrypted, 14-day backups, performance insights |
| **Cache** | ElastiCache Redis 7 | Encrypted at rest/transit, automatic failover, 2 replicas |
| **Streaming** | MSK Kafka 3.6 | 3 brokers, TLS encryption, CloudWatch logging |
| **Load Balancer** | ALB | HTTPS (TLS 1.3), HTTP redirect, access logs to S3 |
| **Registry** | ECR | Per-service repos with image scanning and lifecycle policies |
| **Secrets** | Secrets Manager | Anthropic API key, DB credentials |
| **Monitoring** | CloudWatch | CPU/memory/storage alarms, SNS email alerts, operational dashboard |

### Interactive Deployment Wizard

```bash
cd infra/terraform
bash deploy.sh
```

The wizard guides through 9 steps:

| Step | Configuration |
|------|---------------|
| 1 | AWS region and environment (prod/staging/dev) |
| 2 | Domain name and ACM certificate ARN (optional, for HTTPS) |
| 3 | RDS instance class and database password |
| 4 | ElastiCache Redis and MSK Kafka instance sizes |
| 5 | Anthropic API key |
| 6 | CloudWatch alarm notification email |
| 7 | ECS service replica counts per service |
| 8 | Generate `terraform.tfvars` |
| 9 | Review configuration and estimated cost |

After confirmation, the wizard runs `terraform init`, `plan`, `apply`, then builds and pushes Docker images to ECR and triggers ECS redeployment.

### Estimated Monthly Cost

| Component | Estimate |
|-----------|----------|
| RDS (db.t4g.medium) | ~$50–100 |
| ElastiCache (cache.t4g.small) | ~$25–50 |
| MSK (3 x kafka.t3.small) | ~$150–200 |
| ECS Fargate (6 services) | ~$100–200 |
| ALB + NAT | ~$40–60 |
| **Total** | **~$365–610/mo** |

### Wizard Flags

```bash
bash deploy.sh --plan-only    # Generate config + plan without applying
bash deploy.sh --skip-build   # Apply infra without building Docker images
bash deploy.sh --destroy      # Tear down all infrastructure
```

### Manual Terraform (without wizard)

```bash
cd infra/terraform
terraform init

# Create terraform.tfvars with required variables (see variables.tf)
terraform plan -var-file=terraform.tfvars
terraform apply -var-file=terraform.tfvars
```

### Terraform Modules

| Module | Path | Resources |
|--------|------|-----------|
| `vpc` | `modules/vpc/` | VPC, subnets, IGW, NAT, route tables, flow logs |
| `ecr` | `modules/ecr/` | ECR repositories with lifecycle policies |
| `secrets` | `modules/secrets/` | Secrets Manager secret |
| `rds` | `modules/rds/` | RDS instance, subnet group, security group, parameter group |
| `elasticache` | `modules/elasticache/` | Redis replication group, subnet group, security group |
| `msk` | `modules/msk/` | MSK cluster, configuration, security group |
| `alb` | `modules/alb/` | ALB, listeners, target group, S3 access logs |
| `ecs` | `modules/ecs/` | ECS cluster, task definitions, services, auto-scaling, IAM roles |
| `monitoring` | `modules/monitoring/` | CloudWatch alarms, SNS topic, operational dashboard |

### Post-Deployment

After deployment completes:

1. **Verify**: `curl https://your-domain.com/health`
2. **DNS**: Create a CNAME record pointing your domain to the ALB DNS name
3. **Logs**: `aws logs tail /ecs/aluskort-prod/dashboard --follow`
4. **Monitor**: Open CloudWatch dashboard `aluskort-prod-overview`
5. **ECS**: `aws ecs list-services --cluster aluskort-prod-cluster`

---

## Kubernetes Deployment

### Manifests

All Kubernetes manifests are in `infra/k8s/`:

| File | Resource | Description |
|------|----------|-------------|
| `namespace.yaml` | Namespace | `aluskort` namespace |
| `configmap.yaml` | ConfigMap | Shared configuration for all services |
| `secrets.yaml` | Secret | API keys and database credentials |
| `deployments.yaml` | Deployments (8) | One deployment per service |
| `services.yaml` | Services | ClusterIP services for inter-pod communication |

### Deploy

```bash
# Create namespace
kubectl apply -f infra/k8s/namespace.yaml

# Create configuration
kubectl apply -f infra/k8s/configmap.yaml
kubectl apply -f infra/k8s/secrets.yaml

# Deploy services
kubectl apply -f infra/k8s/deployments.yaml
kubectl apply -f infra/k8s/services.yaml
```

### ConfigMap Values

| Key | Value |
|-----|-------|
| `KAFKA_BOOTSTRAP_SERVERS` | `kafka.aluskort.svc.cluster.local:9092` |
| `QDRANT_HOST` | `qdrant.aluskort.svc.cluster.local` |
| `QDRANT_PORT` | `6333` |
| `REDIS_HOST` | `redis.aluskort.svc.cluster.local` |
| `REDIS_PORT` | `6379` |
| `NEO4J_HOST` | `neo4j.aluskort.svc.cluster.local` |
| `NEO4J_PORT` | `7687` |
| `EMBEDDING_MODEL` | `text-embedding-3-small` |
| `EMBEDDING_DIMENSIONS` | `1536` |
| `LOG_LEVEL` | `INFO` |
| `MONTHLY_SPEND_HARD_CAP` | `1000` |
| `MONTHLY_SPEND_SOFT_ALERT` | `500` |

### Deployment Resources

| Service | Replicas | CPU Request | CPU Limit | Memory Request | Memory Limit |
|---------|----------|-------------|-----------|----------------|-------------|
| entity-parser | 2 | 250m | 500m | 256Mi | 512Mi |
| ctem-normaliser | 2 | 250m | 500m | 256Mi | 512Mi |
| orchestrator | 2 | 500m | 1000m | 512Mi | 1Gi |
| context-gateway | 2 | 500m | 1000m | 512Mi | 1Gi |
| llm-router | 1 | 250m | 500m | 256Mi | 512Mi |
| batch-scheduler | 1 | 250m | 500m | 256Mi | 512Mi |
| sentinel-adapter | 2 | 250m | 500m | 256Mi | 512Mi |
| atlas-detection | 1 | 250m | 500m | 256Mi | 512Mi |

### Health Probes

All deployments include:

```yaml
livenessProbe:
  httpGet:
    path: /health
    port: 8080
  initialDelaySeconds: 10
  periodSeconds: 15
readinessProbe:
  httpGet:
    path: /ready
    port: 8080
  initialDelaySeconds: 5
  periodSeconds: 10
```

---

## Health Check Verification

After deployment, verify all services are healthy:

```bash
# Kubernetes
kubectl get pods -n aluskort
kubectl get deployments -n aluskort

# Check individual service health
kubectl exec -n aluskort deployment/dashboard -- curl -s http://localhost:8080/health
kubectl exec -n aluskort deployment/context-gateway -- curl -s http://localhost:8080/health
kubectl exec -n aluskort deployment/llm-router -- curl -s http://localhost:8080/health

# Docker Compose
docker compose ps
curl http://localhost:8080/health
curl http://localhost:8030/health
curl http://localhost:8031/health
```

---

## Monitoring Setup

### Prometheus Alerts

Deploy the Prometheus alert rules from `infra/prometheus/alerts.yml`:

| Alert | Severity | Condition |
|-------|----------|-----------|
| `AluskortLLMCircuitBreakerOpen` | critical | LLM circuit breaker is OPEN for > 1m |
| `AluskortKafkaConsumerLagHigh` | warning | Consumer lag > 1,000 messages for > 5m |
| `AluskortKafkaConsumerLagCritical` | critical | Consumer lag > 10,000 messages for > 5m |
| `AluskortInvestigationStuck` | critical | Investigation in AWAITING_HUMAN > 3 hours |
| `AluskortMonthlySpendSoftLimit` | warning | Monthly spend > $500 |
| `AluskortMonthlySpendHardCap` | critical | Monthly spend > $1,000 |
| `AluskortBatchSLABreach` | warning | Batch job exceeded 24-hour SLA |
| `AluskortDetectionRuleFailure` | warning | No detection rule evaluations for 15 minutes |

---

## Troubleshooting Common Issues

| Issue | Likely Cause | Resolution |
|-------|-------------|------------|
| Dashboard returns 500 | PostgreSQL not connected | Check `POSTGRES_DSN`, verify PostgreSQL is healthy |
| Investigations not appearing | Kafka topics not created | Run `python -m infra.scripts.create_kafka_topics` |
| LLM calls failing | Invalid or missing API key | Verify `ANTHROPIC_API_KEY` is set and valid |
| Context Gateway 503 | Spend hard cap reached | Check monthly spend, increase `MONTHLY_SPEND_HARD_CAP` |
| Orchestrator stuck | Redis unavailable | Check Redis health, verify `REDIS_HOST` |
| Vector search failing | Qdrant not initialised | Run `python -m infra.scripts.init_qdrant` |
| Neo4j connection refused | Neo4j not ready | Wait for Neo4j health check, verify `NEO4J_URI` |
| Kill switch not working | Redis key not set | Check Redis with `redis-cli GET kill_switch:{dim}:{val}` |
| Audit chain broken | PostgreSQL write failure | Run chain verification, check disk space |
