# ALUSKORT — Source Tree Analysis

**Project:** ALUSKORT - Cloud-Neutral Security Reasoning Control Plane
**Generated:** 2026-02-21
**Scan Level:** Deep
**Repository Type:** Monolith (single Python package, microservice deployment)

---

## Annotated Source Tree

```
SOC/
├── pyproject.toml                    [CONFIG] Project metadata, deps, test config
├── docker-compose.yml                [CONFIG] Local dev infra (6 services + 5 ALUSKORT services)
│
├── context_gateway/                  # LLM input sanitisation, output validation, PII redaction
│   ├── __init__.py
│   ├── anthropic_client.py           # Anthropic API wrapper with retry/backoff
│   ├── evidence_builder.py           # Evidence collection and assembly
│   ├── gateway.py                    [ENTRY] Main gateway: sanitise→redact→prompt→LLM→validate→deanonymise
│   ├── injection_classifier.py       # LLM-as-judge injection classifier (Haiku second opinion)
│   ├── injection_detector.py         # 14+ regex patterns for jailbreak/role-change detection
│   ├── output_validator.py           # Schema + technique ID quarantine (deny-by-default)
│   ├── pii_redactor.py              # Reversible PII anonymisation with redaction map
│   ├── prompt_adapter.py            # Provider-neutral prompt formatting
│   ├── prompt_builder.py            # Anthropic cache_control system block builder
│   ├── spend_guard.py               # Monthly cost tracking ($500 soft / $1000 hard cap)
│   └── summarizer.py                # Lossy summarisation for token optimisation
│
├── llm_router/                       # Multi-tier LLM routing with health-aware fallback
│   ├── __init__.py
│   ├── circuit_breaker.py            # Per-provider circuit breaker (CLOSED→OPEN→HALF_OPEN)
│   ├── concurrency.py               # Rate limiting and concurrency control
│   ├── escalation.py                # Tier escalation on low confidence
│   ├── metrics.py                   # Routing outcome metrics (cost, latency, confidence)
│   ├── models.py                    # ModelTier, TaskContext, RoutingDecision, MODEL_REGISTRY
│   └── router.py                    [ENTRY] Route task→tier→provider with degradation awareness
│
├── orchestrator/                     # Investigation state machine and agent orchestration
│   ├── __init__.py
│   ├── agents/                       # 7 specialised investigation agents
│   │   ├── __init__.py
│   │   ├── atlas_mapper.py           # MITRE ATT&CK/ATLAS technique mapping via PG+Qdrant
│   │   ├── base.py                   # AgentNode protocol: async execute(GraphState)→GraphState
│   │   ├── context_enricher.py       # Parallel enrichment: Redis IOC + PG UEBA + Qdrant similar
│   │   ├── ctem_correlator.py        # CTEM exposure correlation by asset_id
│   │   ├── ioc_extractor.py          # IOC extraction via Context Gateway (Haiku)
│   │   ├── reasoning_agent.py        # Classification via Sonnet, escalation to Opus
│   │   └── response_agent.py         # Playbook selection, action tiering, approval gating
│   ├── executor_constraints.py       # Hard constraints: allowlist playbooks, confidence floors
│   ├── fp_shortcircuit.py           # FP pattern matching (0.90 threshold), skips reasoning
│   ├── graph.py                     [ENTRY] InvestigationGraph: IOC→FP→ENRICH→REASON→RESPOND
│   └── persistence.py              # PostgreSQL-backed state persistence with transitions
│
├── entity_parser/                    # Normalise source-specific alert entities to canonical schema
│   ├── __init__.py
│   ├── parser.py                    # Sentinel JSON + regex IOC extraction fallback
│   ├── service.py                   [ENTRY] Kafka consumer (alerts.raw→alerts.normalized)
│   └── validation.py               # Input sanitisation, IP/hash validation
│
├── ctem_normaliser/                  # Normalise CTEM findings from 4+ vendor feeds
│   ├── __init__.py
│   ├── art.py                       # ATT&CK Range Testing normaliser
│   ├── base.py                      # BaseNormaliser ABC (source_name, normalise)
│   ├── garak.py                     # GARAK LLM attack normaliser
│   ├── models.py                    # CTEMExposure (22 fields), severity matrix, SLA deadlines
│   ├── service.py                   [ENTRY] Route raw topics to vendor normalisers, upsert to PG
│   ├── snyk.py                      # Snyk vulnerability normaliser
│   ├── upsert.py                    # Idempotent exposure_key-based upsert to Postgres
│   └── wiz.py                       # Wiz cloud security normaliser (Neo4j-aware)
│
├── atlas_detection/                  # Statistical detection rules for adversarial ML attacks
│   ├── __init__.py
│   ├── models.py                    # DetectionResult, safety confidence floors, 10 rule IDs
│   ├── rules.py                     # 10 detection rules (poisoning, extraction, injection, evasion...)
│   └── runner.py                    [ENTRY] Run rules, publish triggered → alerts.raw as CanonicalAlert
│
├── batch_scheduler/                  # Batch LLM tasks with dual-trigger (count=50 / time=6h)
│   ├── __init__.py
│   ├── client.py                    # AluskortBatchClient for Anthropic Batch API
│   ├── fp_generator.py              # Generate FP patterns from closed investigations
│   ├── models.py                    # BatchTask, BatchJob, FPPattern, PlaybookDraft
│   ├── processor.py                 # Process completed batch results → PG + Kafka
│   └── scheduler.py                 [ENTRY] Enqueue, flush, poll with SLA tracking (24h)
│
├── sentinel_adapter/                 # Microsoft Sentinel SIEM connector
│   ├── __init__.py
│   ├── adapter.py                   # Sentinel-specific alert transformation
│   └── connector.py                 [ENTRY] EventHub (real-time) + Log Analytics API (polling 30s)
│
├── services/                         # Standalone microservices
│   └── audit_service/               # Immutable audit trail with hash-chain integrity
│       ├── __init__.py
│       ├── api.py                   [ENTRY] REST API for audit queries and evidence packages
│       ├── chain.py                 # Per-tenant hash chain (sequence_number + previous_hash)
│       ├── evidence.py              # Evidence artifact storage (MinIO S3)
│       ├── models.py               # EvidencePackage model
│       ├── package_builder.py       # Assemble investigation evidence packages
│       ├── service.py              # Core audit service logic
│       └── verification.py         # Chain integrity verification (daily + weekly cold)
│
├── shared/                           # Cross-service shared libraries
│   ├── __init__.py
│   ├── adapters/                    # Data source adapter abstractions
│   │   ├── __init__.py
│   │   └── ingest.py               # IngestAdapter ABC (subscribe, to_canonical)
│   ├── audit/                       # Audit event production
│   │   ├── __init__.py
│   │   └── producer.py             # AuditProducer: fire-and-forget to audit.events topic
│   ├── auth/                        # Authentication layer
│   │   ├── __init__.py
│   │   ├── exceptions.py           # AuthenticationError with typed error codes
│   │   ├── mtls.py                 # mTLS SSLContext creation for inter-service comm
│   │   └── oidc.py                 # OIDC/JWT validation via JWKS endpoint
│   ├── db/                          # Database client wrappers (all async, all with health_check)
│   │   ├── __init__.py
│   │   ├── neo4j_graph.py          # Neo4j: consequence reasoning + static fallback
│   │   ├── postgres.py             # asyncpg: pooled connections, transactions, taxonomy lookup
│   │   ├── redis_cache.py          # Redis: IOC cache + FP patterns (fail-open)
│   │   └── vector.py              # Qdrant: HNSW-tuned, 4 collections, circuit-breaker errors
│   └── schemas/                     # Pydantic v2 data contracts
│       ├── __init__.py
│       ├── alert.py                # CanonicalAlert, SeverityLevel
│       ├── audit.py                # AuditRecord, AuditContext (70 fields), AuditDecision, AuditOutcome
│       ├── entity.py               # EntityType (15), NormalizedEntity, AlertEntities
│       ├── event_taxonomy.py       # EventTaxonomy (45 events), EventCategory (5)
│       ├── investigation.py        # GraphState, InvestigationState (8), AgentRole (6), DecisionEntry
│       ├── risk.py                 # RiskState (5), RiskSignal, classify_risk (absent≠low)
│       ├── routing.py              # LLMProvider (4), ModelConfig, TaskCapabilities
│       └── scoring.py             # IncidentScore, composite scoring (α=0.4 sim + β=0.3 recency)
│
├── ops/                              # Operational observability
│   ├── __init__.py
│   ├── alerts.py                    # 12 AlertRule definitions (circuit breaker, lag, spend, SLA)
│   ├── alerting_rules.yml          [CONFIG] Prometheus alerting rules
│   ├── health.py                   # HealthCheck: liveness + readiness with 5 dependency probes
│   └── metrics.py                  # MetricDef registry for all 10 service modules
│
├── infra/                            # Infrastructure as code
│   ├── __init__.py
│   ├── k8s/                        [CONFIG] Kubernetes manifests
│   │   ├── configmap.yaml          # Service config (Kafka, Qdrant, Redis, Neo4j, embedding, spend caps)
│   │   ├── deployments.yaml        # 8 Deployments with health probes and resource limits
│   │   ├── namespace.yaml          # aluskort namespace
│   │   ├── secrets.yaml            # API keys, DSNs, passwords (Base64)
│   │   └── services.yaml          # 8 ClusterIP services (port 80→8080)
│   ├── migrations/                  # PostgreSQL DDL (7 migrations, 30+ tables)
│   │   ├── 001_core_tables.sql     # mitre_techniques, taxonomy_ids, playbooks, incident_memory, fp_patterns
│   │   ├── 002_ctem_tables.sql     # ctem_exposures, ctem_validations, ctem_remediations
│   │   ├── 003_atlas_tables.sql    # investigation_state, inference_logs, orbital telemetry
│   │   ├── 004_atlas_telemetry.sql # 10 extended telemetry tables
│   │   ├── 005_taxonomy_seed_data.sql # 53 ATT&CK+ATLAS techniques, taxonomy_metadata
│   │   ├── 006_audit_records.sql   # Partitioned immutable audit_records (SOC 2 CC6.8)
│   │   └── 007_audit_chain_state.sql # audit_chain_state, audit_verification_log
│   ├── prometheus/
│   │   └── alerts.yml             [CONFIG] Prometheus alert rules
│   └── scripts/                    # Initialisation scripts
│       ├── __init__.py
│       ├── create_kafka_topics.py  # 31 Kafka topics with partition/retention config
│       ├── init_neo4j.py          # Constraints, indexes, sample data
│       └── init_qdrant.py         # 4 vector collections (HNSW m=16, ef=200)
│
├── tests/                           [TEST] 91 test files across 15 directories
│   ├── __init__.py
│   ├── security/                   [TEST] Red-team injection regression suite
│   │   ├── __init__.py
│   │   ├── conftest.py
│   │   └── test_injection_regression.py
│   ├── test_atlas_detection/       [TEST] 3 test files
│   ├── test_audit/                 [TEST] 7 test files
│   ├── test_auth/                  [TEST] 3 test files
│   ├── test_batch_scheduler/       [TEST] 5 test files
│   ├── test_context_gateway/       [TEST] 14 test files
│   ├── test_ctem_normaliser/       [TEST] 7 test files
│   ├── test_db/                    [TEST] 4 test files
│   ├── test_entity_parser/         [TEST] 5 test files
│   ├── test_infra/                 [TEST] 6 test files
│   ├── test_llm_router/           [TEST] 6 test files
│   ├── test_ops/                   [TEST] 3 test files
│   ├── test_orchestrator/          [TEST] 12 test files
│   ├── test_schemas/               [TEST] 8 test files
│   └── test_sentinel_adapter/      [TEST] 3 test files
│
├── docs/                             # Project documentation (14 markdown files)
│   ├── architecture.md             # System architecture v2.0
│   ├── ai-system-design.md        # AI reasoning system design
│   ├── atlas-integration.md       # MITRE ATT&CK/ATLAS integration layer
│   ├── audit-architecture.md      # Immutable audit trail architecture
│   ├── ctem-integration.md        # CTEM program integration layer
│   ├── data-pipeline.md           # Data ingestion/processing pipeline
│   ├── inference-optimization.md  # LLM inference optimisation
│   ├── prd.md                     # Product Requirements Document v2.0
│   ├── provider-outage-playbook.md # Provider outage RTO/RPO procedures
│   ├── rag-design.md             # RAG knowledge base design
│   ├── remediation-backlog.md    # Critical review remediation items
│   ├── research-notes.md         # Cutting-edge technique research
│   ├── runbook.md                # Operations runbook
│   └── testing-requirements.md   # Complete test plan (T1-T12)
│
└── .github/workflows/              [CONFIG] CI/CD
    └── ci-cd.yml                   # Test (PG+Redis, 90% coverage) → Build matrix → GHCR push
```

## Critical Folders Summary

| Folder | Purpose | Files | Key Patterns |
|--------|---------|-------|-------------|
| `context_gateway/` | LLM safety layer | 12 | Injection detection, PII redaction, spend control |
| `orchestrator/` | Investigation engine | 14 | State machine, 7 agents, constraint enforcement |
| `llm_router/` | Model routing | 7 | 4-tier routing, circuit breaker, degradation |
| `ctem_normaliser/` | Threat normalisation | 9 | 4 vendor normalisers, severity matrix |
| `atlas_detection/` | ML attack detection | 4 | 10 rules, safety confidence floors |
| `shared/schemas/` | Data contracts | 9 | 45 event types, 20+ Pydantic models |
| `shared/db/` | DB clients | 5 | 4 async clients, all with health checks |
| `infra/migrations/` | Database DDL | 7 | 30+ tables, partitioned audit, hash chain |
| `tests/` | Test suite | 91 | 90% coverage gate, injection regression |

## Data Flow Through the Tree

```
sentinel_adapter/ ──→ alerts.raw ──→ entity_parser/ ──→ alerts.normalized ──→ orchestrator/
                                                                                    │
ctem_normaliser/ ──→ ctem.normalized ──────────────────────────────────────────────→ │
                                                                                    │
atlas_detection/ ──→ alerts.raw ───────────────────→ entity_parser/ ──────────────→ │
                                                                                    ▼
                                                                            orchestrator/graph.py
                                                                            IOC → FP → ENRICH → REASON
                                                                                    │
                                                                                    ▼
                                                                            orchestrator/agents/
                                                                            response_agent.py
                                                                                    │
                                                            ┌───────────────────────┤
                                                            ▼                       ▼
                                                    context_gateway/        actions.pending
                                                    (LLM calls via         (approval workflow)
                                                     llm_router/)
                                                            │
                                                            ▼
                                                    audit.events ──→ services/audit_service/
```
