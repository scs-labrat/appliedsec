---
stepsCompleted: [1, 2, 3, 4]
inputDocuments:
  - "docs/prd.md"
  - "_bmad-output/planning-artifacts/architecture.md"
---

# ALUSKORT Epics and Stories Planning Artifact

## 1. Requirements Inventory

### 1.1 Functional Requirements

#### Alert Ingestion (FR-ING-*)

| ID | Summary |
|---|---|
| FR-ING-001 | Ingest alerts from multiple SIEM/XDR sources via adapter pattern |
| FR-ING-002 | Normalise all alerts to CanonicalAlert schema |
| FR-ING-003 | Provide adapters for Sentinel, Elastic, Splunk, Wiz |
| FR-ING-004 | Publish raw/parsed/enriched alerts to respective Kafka topics |
| FR-ING-005 | Route LLM work to severity-prioritised queues |
| FR-ING-006 | Enforce per-queue concurrency limits (critical=8, high=4, normal=2, low=1) |
| FR-ING-007 | Enforce per-tenant quotas (premium=500, standard=100, trial=20 calls/hr) |
| FR-ING-008 | Alert pipeline latency < 5 seconds end-to-end |

#### Entity Extraction and Enrichment (FR-ENR-*)

| ID | Summary |
|---|---|
| FR-ENR-001 | Extract structured entities from alert entities_raw field |
| FR-ENR-002 | Source-aware parsing (Sentinel JSON, Elastic raw_payload, regex fallback) |
| FR-ENR-003 | Validate IOC values against format patterns, sanitise dangerous characters |
| FR-ENR-004 | Enrich IOCs via Redis exact-match lookup with TTL policy |
| FR-ENR-005 | Enrich with UEBA/risk context using RiskState model |
| FR-ENR-006 | Correlate alerts with CTEM exposure records |
| FR-ENR-007 | Perform TI report semantic search via Qdrant |

#### Reasoning and Classification (FR-RSN-*)

| ID | Summary |
|---|---|
| FR-RSN-001 | LLM-powered multi-hop investigation with structured JSON output |
| FR-RSN-002 | Map alerts to ATT&CK and ATLAS technique IDs with validation |
| FR-RSN-003 | Attack path analysis via Neo4j graph traversal |
| FR-RSN-004 | Time-decayed composite scoring for incident memory |
| FR-RSN-005 | Confidence scoring with Opus escalation for low-confidence critical alerts |
| FR-RSN-006 | FP pattern short-circuit at parsing stage |
| FR-RSN-007 | Track investigation state via GraphState persisted to Postgres |

#### Response and Remediation (FR-RSP-*)

| ID | Summary |
|---|---|
| FR-RSP-001 | Support three remediation tiers |
| FR-RSP-002 | All destructive actions require human approval |
| FR-RSP-003 | Human approval gates with 4-hour timeout |
| FR-RSP-004 | Log all response actions to audit.events Kafka topic |
| FR-RSP-005 | Select playbooks based on tactics, techniques, product, severity |
| FR-RSP-006 | Confidence threshold 0.85 for Tier 2 auto-preparation |

#### Knowledge Base and RAG (FR-RAG-*)

| ID | Summary |
|---|---|
| FR-RAG-001 | Split retrieval across Postgres, Qdrant, Redis, S3/MinIO |
| FR-RAG-002 | Maintain five knowledge domains |
| FR-RAG-003 | MITRE techniques as structured records and vector embeddings |
| FR-RAG-004 | TI report section-aware chunking (512 tokens, 64-token overlap) |
| FR-RAG-005 | FP pattern store in Redis (hot) and Postgres (audit) |
| FR-RAG-006 | Vendor-neutral embeddings (1024 dimensions, cosine distance) |
| FR-RAG-007 | Auto-generate playbook drafts from investigation patterns |
| FR-RAG-008 | Context assembly with 4,096 token budget |

#### ATLAS Threat Model (FR-ATL-*)

| ID | Summary |
|---|---|
| FR-ATL-001 | Detect 17 TM-IDs via 10 Python detection rules |
| FR-ATL-002 | Detection rules operate on 10 Postgres telemetry tables |
| FR-ATL-003 | Detection frequencies from 5 minutes to 1 hour |
| FR-ATL-004 | Preserve exact statistical thresholds from original KQL rules |
| FR-ATL-005 | Map detections to both ATLAS and ATT&CK technique IDs |
| FR-ATL-006 | Self-protection: confidence floors and safety dismissal prevention |

#### CTEM Integration (FR-CTM-*)

| ID | Summary |
|---|---|
| FR-CTM-001 | Implement all 5 CTEM phases |
| FR-CTM-002 | Ingest findings from Wiz, Snyk, Garak, ART, Burp, custom |
| FR-CTM-003 | Normalise findings to CTEMExposure schema via per-tool normalisers |
| FR-CTM-004 | Consequence-weighted severity scoring |
| FR-CTM-005 | Neo4j graph traversal for consequence determination |
| FR-CTM-006 | SLA deadlines: CRITICAL=24h, HIGH=72h, MEDIUM=14d, LOW=30d |
| FR-CTM-007 | Idempotent upsert with deterministic exposure_key |
| FR-CTM-008 | Auto-discover assets from Postgres telemetry weekly |

#### Case Management (FR-CSM-*)

| ID | Summary |
|---|---|
| FR-CSM-001 | Investigation timeline with full decision chain in Postgres JSONB |
| FR-CSM-002 | Analyst UI for case management (deferred to v1.2+) |
| FR-CSM-003 | Record all decisions to immutable audit.events Kafka topic |
| FR-CSM-004 | Analyst feedback on classifications with FP pattern generation |

### 1.2 Non-Functional Requirements

#### Performance (NFR-PRF-*)

| ID | Summary |
|---|---|
| NFR-PRF-001 | Alert pipeline (parse + enrich) < 5 seconds |
| NFR-PRF-002 | Investigation pipeline < 10 seconds per query |
| NFR-PRF-003 | Tier 0 (Haiku) < 3 seconds |
| NFR-PRF-004 | Tier 1 (Sonnet) < 30 seconds |
| NFR-PRF-005 | Tier 1+ (Opus) < 60 seconds |
| NFR-PRF-006 | Tier 2 (Batch) 24-hour SLA |
| NFR-PRF-007 | Support 2,000 alerts/day (median 1,200/day) |
| NFR-PRF-008 | Redis IOC lookup < 1ms |

#### Security (NFR-SEC-*)

| ID | Summary |
|---|---|
| NFR-SEC-001 | All LLM interactions through Context Gateway |
| NFR-SEC-002 | Injection detection and redaction (14+ patterns) |
| NFR-SEC-003 | Safety system prompt prefix on all LLM calls |
| NFR-SEC-004 | Output validation against JSON schemas and taxonomy_ids |
| NFR-SEC-005 | Role-based agent permissions |
| NFR-SEC-006 | Information accumulation guards |
| NFR-SEC-007 | Parameterised SQL only (no string interpolation) |
| NFR-SEC-008 | Entity extraction sanitisation |

#### Reliability (NFR-REL-*)

| ID | Summary |
|---|---|
| NFR-REL-001 | 5-level degradation strategy |
| NFR-REL-002 | Kafka retention survives consumer crashes |
| NFR-REL-003 | Deterministic-only mode when LLM Router unreachable |
| NFR-REL-004 | Postgres full-text search fallback when Vector DB down |
| NFR-REL-005 | Static zone-consequence fallback when Neo4j down |
| NFR-REL-006 | Multiple Kubernetes replicas with auto-restart |
| NFR-REL-007 | Exponential backoff retry (3 retries, 1s base delay) |

#### Scalability (NFR-SCL-*)

| ID | Summary |
|---|---|
| NFR-SCL-001 | Single tenant initially, multi-tenant architecture ready |
| NFR-SCL-002 | Horizontal scaling via Kubernetes per pipeline stage |
| NFR-SCL-003 | Configurable per-tenant LLM quotas |
| NFR-SCL-004 | < 10 GB/day per tenant data volume |

#### Observability (NFR-OBS-*)

| ID | Summary |
|---|---|
| NFR-OBS-001 | Prometheus metrics for LLM, Kafka, pipeline, investigations |
| NFR-OBS-002 | Per-task LLM metrics for routing refinement |
| NFR-OBS-003 | Cost tracking dashboard |
| NFR-OBS-004 | CTEM data staleness flagging |
| NFR-OBS-005 | UEBA/risk signal freshness monitoring |

#### Compliance (NFR-CMP-*)

| ID | Summary |
|---|---|
| NFR-CMP-001 | Immutable audit trail via audit.events Kafka topic |
| NFR-CMP-002 | Incident memory partitioned by month, archive > 12 months |
| NFR-CMP-003 | FP patterns: approved_by, approval_date, status lifecycle |
| NFR-CMP-004 | CTEM remediation lifecycle tracking with SLA breach tracking |

---

## 2. FR Coverage Map

| Epic | FRs Covered | NFRs Covered |
|---|---|---|
| **Epic 1: Foundation** | (enables all FRs) | NFR-SEC-005, NFR-SEC-007, NFR-SEC-008 |
| **Epic 2: Infrastructure** | FR-ING-004, FR-ING-005 | NFR-REL-002, NFR-SCL-001, NFR-SCL-004 |
| **Epic 3: Entity Parser** | FR-ING-002, FR-ENR-001, FR-ENR-002, FR-ENR-003 | NFR-PRF-001, NFR-SEC-008 |
| **Epic 4: Sentinel Adapter** | FR-ING-001, FR-ING-003 | NFR-PRF-007 |
| **Epic 5: Context Gateway** | FR-RSN-002 (validation) | NFR-SEC-001, NFR-SEC-002, NFR-SEC-003, NFR-SEC-004, NFR-REL-007 |
| **Epic 6: LLM Router** | FR-ING-005, FR-ING-006, FR-ING-007, FR-RSN-005 | NFR-PRF-003, NFR-PRF-004, NFR-PRF-005, NFR-SCL-003 |
| **Epic 7: Orchestrator** | FR-RSN-001, FR-RSN-003, FR-RSN-004, FR-RSN-006, FR-RSN-007, FR-RSP-001 to FR-RSP-006, FR-ENR-004 to FR-ENR-007, FR-RAG-001 to FR-RAG-008, FR-CSM-001, FR-CSM-003, FR-CSM-004 | NFR-PRF-002, NFR-PRF-008, NFR-REL-001, NFR-REL-003, NFR-REL-004, NFR-REL-005, NFR-SEC-005, NFR-SEC-006, NFR-CMP-001 |
| **Epic 8: CTEM Normaliser** | FR-CTM-001 to FR-CTM-008 | NFR-CMP-004 |
| **Epic 9: ATLAS Detection** | FR-ATL-001 to FR-ATL-006 | NFR-SEC-007 |
| **Epic 10: Batch Scheduler** | FR-RAG-005, FR-RAG-007 | NFR-PRF-006, NFR-OBS-003 |
| **Epic 11: Operations** | (enables all FRs in production) | NFR-OBS-001 to NFR-OBS-005, NFR-REL-006, NFR-SCL-002, NFR-CMP-001, NFR-CMP-002 |

---

## 3. Epic List

### Epic 1: Foundation -- Shared Schemas and DB Clients

**Goal:** Create the `shared/` directory with canonical Pydantic schemas and database client wrappers that all services depend on.

**Blocked by:** Nothing (foundation layer).
**Blocks:** All other epics.

#### Story 1.1: Create Canonical Pydantic Models

**As a** developer building ALUSKORT services,
**I want** shared Pydantic v2 models for CanonicalAlert, GraphState, InvestigationState, IncidentScore, RiskSignal, and RiskState,
**so that** all services use the same data contracts for inter-service communication.

**Acceptance Criteria:**

- **Given** a raw alert dict from any source, **When** it is validated against CanonicalAlert, **Then** all required fields (alert_id, source, timestamp, title, description, severity, tactics, techniques, entities_raw, product, tenant_id, raw_payload) are present and typed correctly.
- **Given** an InvestigationState enum, **When** a GraphState is initialised, **Then** it defaults to RECEIVED state with empty collections for entities, ioc_matches, ueba_context, ctem_exposures, atlas_techniques, similar_incidents, playbook_matches, and decision_chain.
- **Given** a RiskSignal with missing UEBA data, **When** risk_state is determined, **Then** it is set to NO_BASELINE (not LOW).
- **Given** an IncidentScore, **When** composite is calculated, **Then** it uses weights ALPHA=0.4, BETA=0.3, GAMMA=0.15, DELTA=0.15 with LAMBDA=0.023 decay.

**FRs:** FR-ING-002, FR-RSN-007, FR-RSN-004, FR-ENR-005
**NFRs:** NFR-SEC-008

#### Story 1.2: Create Postgres Client Wrapper

**As a** developer building services that query PostgreSQL,
**I want** an asyncpg connection pool wrapper with query helpers in `shared/db/postgres.py`,
**so that** all services use consistent, parameterised database access.

**Acceptance Criteria:**

- **Given** a Postgres DSN, **When** the client is initialised, **Then** it creates an asyncpg connection pool with configurable min/max connections.
- **Given** a query with parameters, **When** `execute()` is called, **Then** parameters are bound via `$1, $2` syntax (no string interpolation).
- **Given** the pool is at max connections, **When** a new query arrives, **Then** it waits for a connection with configurable timeout.

**FRs:** (enables FR-RSN-007, FR-CTM-007, FR-ATL-002)
**NFRs:** NFR-SEC-007

#### Story 1.3: Create Redis Client Wrapper

**As a** developer building services that use Redis for IOC caching and FP patterns,
**I want** a Redis client wrapper in `shared/db/redis_cache.py` with IOC lookup and FP pattern store methods,
**so that** IOC exact-match lookups and FP pattern hot-cache access are consistent across services.

**Acceptance Criteria:**

- **Given** an IOC type and value, **When** `get_ioc()` is called, **Then** it looks up key `ioc:{type}:{value}` and returns parsed JSON or None.
- **Given** Redis is unavailable, **When** a lookup is attempted, **Then** the client fails open (returns None, does not raise).
- **Given** an IOC with confidence > 80, **When** stored, **Then** TTL is set to 30 days. For confidence 50-80: 7 days. For < 50: 24 hours.

**FRs:** FR-ENR-004, FR-RAG-005
**NFRs:** NFR-PRF-008

#### Story 1.4: Create Qdrant Client Wrapper

**As a** developer building services that perform semantic search,
**I want** a Qdrant client wrapper in `shared/db/vector.py` with collection management and search methods,
**so that** vector similarity search is encapsulated with consistent configuration.

**Acceptance Criteria:**

- **Given** a collection name and vector config, **When** `ensure_collection()` is called, **Then** the collection is created if not present with HNSW config (m=16, ef_construct=200) and Cosine distance.
- **Given** a query vector and top_k, **When** `search()` is called, **Then** it returns up to top_k results with scores and payloads.
- **Given** Qdrant is unavailable, **When** a search is attempted, **Then** it raises a retriable exception (for circuit breaker handling).

**FRs:** FR-RAG-001, FR-RAG-003, FR-ENR-007
**NFRs:** NFR-REL-004

#### Story 1.5: Create Neo4j Client Wrapper

**As a** developer building consequence reasoning queries,
**I want** a Neo4j driver wrapper in `shared/db/neo4j_graph.py` with Cypher query helpers,
**so that** graph traversal for attack path analysis uses consistent connection management.

**Acceptance Criteria:**

- **Given** a Neo4j URI and credentials, **When** the client is initialised, **Then** it creates a driver with configurable connection pool.
- **Given** a finding_id, **When** `get_consequence_severity()` is called, **Then** it executes the consequence reasoning Cypher query and returns the max consequence severity.
- **Given** Neo4j is unavailable, **When** a query is attempted, **Then** the client falls back to `ZONE_CONSEQUENCE_FALLBACK` static dict and logs `GRAPH_UNAVAILABLE`.

**FRs:** FR-RSN-003, FR-CTM-005
**NFRs:** NFR-REL-005

#### Story 1.6: Create Auth Utilities

**As a** developer building secure inter-service communication,
**I want** OIDC token validation and mTLS certificate management utilities in `shared/auth/`,
**so that** all services enforce authentication consistently.

**Acceptance Criteria:**

- **Given** a JWT token, **When** `validate_oidc_token()` is called, **Then** it validates the token against the configured IdP JWKS endpoint and returns claims.
- **Given** a mTLS configuration, **When** the service starts, **Then** it loads client certificates and configures TLS context for outbound connections.
- **Given** an expired or invalid token, **When** validation is attempted, **Then** it raises an AuthenticationError with a descriptive message.

**FRs:** (enables all service-to-service communication)
**NFRs:** NFR-SEC-005

---

### Epic 2: Infrastructure -- Kafka and Database Setup

**Goal:** Provision Kafka topics, create Postgres DDL, and set up Docker Compose for local development.

**Blocked by:** Epic 1.
**Blocks:** Epics 3, 4, 7, 8, 9.

#### Story 2.1: Create Docker Compose for Local Dev

**As a** developer setting up a local development environment,
**I want** a Docker Compose file that starts Kafka/Redpanda, Postgres, Redis, Qdrant, Neo4j, and MinIO,
**so that** I can develop and test all services locally without external dependencies.

**Acceptance Criteria:**

- **Given** `docker-compose up`, **When** all services start, **Then** Redpanda is available on port 9092, Postgres on 5432, Redis on 6379, Qdrant on 6333, Neo4j on 7474/7687, MinIO on 9000/9001.
- **Given** the compose file includes volume mounts, **When** containers are restarted, **Then** data is persisted across restarts.
- **Given** ALUSKORT services are included, **When** they start, **Then** each service connects to its infrastructure dependencies.

**FRs:** FR-ING-004
**NFRs:** NFR-SCL-004

#### Story 2.2: Create Postgres DDL Migration Scripts

**As a** developer initialising the database,
**I want** DDL migration scripts for all Postgres tables (MITRE, TI IOCs, playbooks, incident memory, FP patterns, org context, CTEM exposures/validations/remediations, ATLAS telemetry),
**so that** the database schema is versioned and reproducible.

**Acceptance Criteria:**

- **Given** an empty Postgres database, **When** the migration scripts run, **Then** all tables, indexes, and constraints from the architecture document are created.
- **Given** time-series tables (incident_memory, inference_logs, telemetry), **When** created, **Then** they are partitioned by month using `PARTITION BY RANGE (ts)`.
- **Given** the `ctem_exposures` table, **When** created, **Then** it includes the `exposure_key` UNIQUE constraint for ON CONFLICT upsert support.
- **Given** the `taxonomy_ids` table, **When** populated, **Then** it contains ATT&CK and ATLAS technique IDs with framework, name, and deprecated status.

**FRs:** FR-RSN-002, FR-ATL-002, FR-CTM-007
**NFRs:** NFR-CMP-002

#### Story 2.3: Create Kafka Topic Provisioning Script

**As a** developer setting up the message bus,
**I want** a script that creates all Kafka topics with correct partition counts and retention settings,
**so that** the pipeline has all required topics before services start.

**Acceptance Criteria:**

- **Given** the provisioning script runs, **When** complete, **Then** all core pipeline topics (alerts.raw, alerts.normalized, incidents.enriched, jobs.llm.priority.*, actions.pending, audit.events) exist with specified partition counts.
- **Given** CTEM topics, **When** created, **Then** all ctem.raw.* topics (wiz, snyk, garak, art, burp, custom, validation, remediation) and ctem.normalized exist with 30-day retention.
- **Given** DLQ topics, **When** created, **Then** alerts.raw.dlq, jobs.llm.priority.*.dlq, and ctem.normalized.dlq exist.
- **Given** a produce/consume smoke test, **When** executed, **Then** a test message is published and consumed successfully.

**FRs:** FR-ING-004, FR-ING-005
**NFRs:** NFR-REL-002

#### Story 2.4: Create Qdrant Collection Initialisation

**As a** developer setting up the vector database,
**I want** an initialisation script that creates all Qdrant collections (aluskort-mitre, aluskort-threat-intel, aluskort-playbooks, aluskort-incident-memory),
**so that** semantic search is available when services start.

**Acceptance Criteria:**

- **Given** the initialisation script runs, **When** complete, **Then** all four collections exist with vector size 1024, Cosine distance, HNSW config (m=16, ef_construct=200).
- **Given** a test vector, **When** upserted and searched, **Then** the vector is returned as the top result.
- **Given** a collection already exists, **When** the script runs again, **Then** it is idempotent (no error, no data loss).

**FRs:** FR-RAG-003, FR-RAG-006
**NFRs:** (none directly)

#### Story 2.5: Create Neo4j Schema Constraints and Indexes

**As a** developer setting up the graph database,
**I want** Cypher scripts that create uniqueness constraints and indexes for Asset, Zone, Model, Finding, and Tenant nodes,
**so that** consequence reasoning queries are efficient and data integrity is enforced.

**Acceptance Criteria:**

- **Given** the schema script runs, **When** complete, **Then** uniqueness constraints exist for Asset.id, Zone.id, Model.id, Finding.id, Tenant.id.
- **Given** relationships, **When** RESIDES_IN, DEPLOYS_TO, AFFECTS, OWNED_BY, and CONNECTS_TO are used, **Then** they connect the correct node types.
- **Given** the consequence reasoning query, **When** executed against test data, **Then** it returns the correct max_consequence_severity.

**FRs:** FR-RSN-003, FR-CTM-005
**NFRs:** (none directly)

---

### Epic 3: Ingest -- Entity Parser Service

**Goal:** Build the `entity_parser` service that consumes `alerts.raw` and produces `alerts.normalized` with extracted and validated entities.

**Blocked by:** Epics 1, 2.
**Blocks:** Epic 7 (orchestrator consumes normalised alerts).

#### Story 3.1: Create Entity Parser Core

**As a** SOC platform processing raw alerts,
**I want** an entity parsing engine that extracts structured entities (accounts, hosts, IPs, files, processes, URLs, DNS, file hashes, mailboxes) from alert data,
**so that** downstream services receive clean, typed entity data.

**Acceptance Criteria:**

- **Given** a Sentinel alert with JSON entities, **When** parsed, **Then** all entity types (account, host, IP, file, process, URL, DNS, filehash, mailbox) are correctly extracted with type and primary_value.
- **Given** an Elastic alert with no native Entities field, **When** parsed, **Then** the parser falls back to raw_payload regex extraction for IPs, hashes, domains, and URLs.
- **Given** an alert from an unknown source, **When** parsed, **Then** the parser applies regex fallback extraction for all IOC types.

**FRs:** FR-ENR-001, FR-ENR-002
**NFRs:** NFR-PRF-001

#### Story 3.2: Create Kafka Consumer for alerts.raw

**As a** pipeline operator,
**I want** the entity parser to consume from `alerts.raw` Kafka topic as consumer group `aluskort.entity-parser`,
**so that** raw alerts are automatically processed as they arrive.

**Acceptance Criteria:**

- **Given** the entity parser service starts, **When** a message appears on `alerts.raw`, **Then** it is consumed, deserialized to CanonicalAlert, and passed to the parsing engine.
- **Given** manual offset commits, **When** parsing succeeds, **Then** the offset is committed after successful production to `alerts.normalized`.
- **Given** a malformed message, **When** deserialization fails, **Then** the message is sent to `alerts.raw.dlq` with error details.

**FRs:** FR-ING-004
**NFRs:** NFR-REL-002

#### Story 3.3: Create Kafka Producer for alerts.normalized

**As a** pipeline operator,
**I want** the entity parser to produce parsed alerts (CanonicalAlert + AlertEntities) to `alerts.normalized`,
**so that** downstream services (enrichment, priority router) can consume normalised data.

**Acceptance Criteria:**

- **Given** a successfully parsed alert, **When** produced to `alerts.normalized`, **Then** the message key is `alert_id` and the value contains both the CanonicalAlert and AlertEntities.
- **Given** a production failure, **When** the Kafka producer fails after retries, **Then** the alert is logged with error details and the consumer offset is not committed.
- **Given** the FP pattern short-circuit, **When** a parsed alert matches an approved FP pattern with confidence > 0.90, **Then** the alert is auto-closed without producing to the LLM job queue.

**FRs:** FR-ING-004, FR-RSN-006
**NFRs:** NFR-PRF-001

#### Story 3.4: Create Input Validation and Sanitisation

**As a** security-conscious platform,
**I want** all extracted entity values validated against format patterns and sanitised of dangerous characters,
**so that** downstream services are protected from injection attacks via alert data.

**Acceptance Criteria:**

- **Given** an extracted IP address, **When** validated, **Then** it matches the IPv4 pattern (or IPv6). Invalid IPs are rejected with a parse_error.
- **Given** an extracted hash value, **When** validated, **Then** it matches the expected length (SHA256=64, SHA1=40, MD5=32) and is hexadecimal only.
- **Given** an entity value with dangerous characters or length > 2,048 chars, **When** sanitised, **Then** dangerous characters are stripped and the value is truncated.

**FRs:** FR-ENR-003
**NFRs:** NFR-SEC-008

#### Story 3.5: Unit Tests for Entity Extraction

**As a** developer maintaining the entity parser,
**I want** comprehensive unit tests covering IP, hash, domain, URL, and account extraction from Sentinel and Elastic sample payloads,
**so that** regressions are caught before deployment.

**Acceptance Criteria:**

- **Given** a Sentinel sample payload, **When** test_sentinel_entities.py runs, **Then** all entity types are correctly extracted with expected values.
- **Given** an Elastic sample payload, **When** test_elastic_entities.py runs, **Then** regex fallback correctly extracts IPs, hashes, and domains from raw_payload.
- **Given** an alert with prompt injection patterns in entities_raw, **When** test_injection.py runs, **Then** injection content does not affect entity extraction and is flagged.
- **Given** edge cases (empty entities, malformed JSON, oversized values), **When** tested, **Then** the parser handles them gracefully with appropriate parse_errors.

**FRs:** FR-ENR-001, FR-ENR-002, FR-ENR-003
**NFRs:** NFR-SEC-002

---

### Epic 4: Ingest -- Sentinel Adapter

**Goal:** Build the first SIEM adapter (Microsoft Sentinel) implementing the IngestAdapter pattern.

**Blocked by:** Epics 1, 2, 3.
**Blocks:** Epic 7 (needs at least one SIEM adapter to produce alerts).

#### Story 4.1: Create SentinelAdapter Implementing IngestAdapter ABC

**As a** platform integrating with Microsoft Sentinel,
**I want** a SentinelAdapter class that implements `source_name()`, `subscribe()`, and `to_canonical()` from the IngestAdapter ABC,
**so that** Sentinel alerts are ingested through the standard adapter interface.

**Acceptance Criteria:**

- **Given** the SentinelAdapter, **When** `source_name()` is called, **Then** it returns "sentinel".
- **Given** the SentinelAdapter, **When** `to_canonical()` receives a Sentinel SecurityAlert dict, **Then** it maps SystemAlertId, TimeGenerated, AlertName, Description, Severity, Tactics, Techniques, Entities, ProductName, and TenantId to CanonicalAlert fields.
- **Given** a Sentinel heartbeat event, **When** `to_canonical()` is called, **Then** it returns None (event dropped).

**FRs:** FR-ING-001, FR-ING-003
**NFRs:** (none directly)

#### Story 4.2: Create Event Hub / Log Analytics API Connector

**As a** platform consuming Sentinel alerts,
**I want** a connector that subscribes to Sentinel via Event Hub or Log Analytics API polling,
**so that** alerts are received in near-real-time.

**Acceptance Criteria:**

- **Given** Event Hub connection string, **When** `subscribe()` is called, **Then** the adapter begins consuming events from the configured Event Hub.
- **Given** Log Analytics API credentials, **When** polling mode is configured, **Then** the adapter polls at a configurable interval (default 30 seconds) for new SecurityAlert records.
- **Given** a connection failure, **When** the connector retries, **Then** it uses exponential backoff (3 retries, 1s base delay).

**FRs:** FR-ING-001
**NFRs:** NFR-REL-007

#### Story 4.3: Create Sentinel to CanonicalAlert Mapping

**As a** developer ensuring correct data mapping,
**I want** the Sentinel adapter to correctly map all Sentinel SecurityAlert fields to CanonicalAlert fields,
**so that** no data is lost or misinterpreted during normalisation.

**Acceptance Criteria:**

- **Given** a Sentinel alert with comma-separated Tactics, **When** mapped, **Then** tactics field is a list of individual tactic names.
- **Given** a Sentinel alert with Entities JSON, **When** mapped, **Then** entities_raw contains the raw Entities string for downstream entity parser processing.
- **Given** a Sentinel alert with missing Severity, **When** mapped, **Then** severity defaults to "medium".

**FRs:** FR-ING-002
**NFRs:** (none directly)

#### Story 4.4: Contract Tests with Sample Sentinel Alerts

**As a** developer ensuring adapter correctness,
**I want** contract tests that verify Sentinel sample payloads produce valid CanonicalAlert objects,
**so that** the adapter contract is verified against real data shapes.

**Acceptance Criteria:**

- **Given** 3+ sample Sentinel SecurityAlert JSON payloads, **When** test_sentinel_contract.py runs, **Then** each produces a valid CanonicalAlert with all required fields populated.
- **Given** a sample payload with all entity types, **When** mapped, **Then** entities_raw is valid JSON parseable by the entity parser.
- **Given** the adapter publishes to `alerts.raw`, **When** the entity parser consumes, **Then** the round-trip produces a valid `alerts.normalized` message.

**FRs:** FR-ING-001, FR-ING-003
**NFRs:** NFR-PRF-001

---

### Epic 5: Reasoning -- Context Gateway

**Goal:** Build the centralised LLM sanitisation service that enforces injection detection, PII redaction, safety prompt prefix, and output validation for all LLM interactions.

**Blocked by:** Epics 1, 2.
**Blocks:** Epic 6 (LLM Router depends on Context Gateway), Epic 7 (Orchestrator depends on Context Gateway).

#### Story 5.1: Create Injection Detection Engine

**As a** security-conscious platform,
**I want** a regex-based injection detection engine that identifies and redacts prompt injection patterns in LLM input,
**so that** attacker-crafted alert data cannot manipulate LLM behaviour.

**Acceptance Criteria:**

- **Given** input containing "ignore previous instructions", **When** `sanitise_input()` is called, **Then** the pattern is replaced with `[REDACTED_INJECTION_ATTEMPT]`.
- **Given** input containing any of 14+ known injection patterns (DAN mode, jailbreak, system prompt, etc.), **When** sanitised, **Then** all patterns are redacted.
- **Given** input with embedded markup (`\`\`\`system...\`\`\``), **When** sanitised, **Then** the markup is replaced with `[REDACTED_MARKUP]`.
- **Given** clean input with no injection patterns, **When** sanitised, **Then** the input is returned unchanged.

**FRs:** (enables FR-RSN-001)
**NFRs:** NFR-SEC-002

#### Story 5.2: Create PII Redaction with Reversible Mapping

**As a** privacy-conscious platform,
**I want** PII redaction that replaces real entity values with placeholders before LLM calls and restores them after,
**so that** sensitive data (usernames, IPs, hostnames) never leaves the cluster.

**Acceptance Criteria:**

- **Given** user content with real usernames and IPs, **When** `redact_pii()` is called, **Then** values are replaced with placeholders (USER_001, IP_SRC_001) and a RedactionMap is created.
- **Given** an LLM response containing placeholders, **When** `deanonymise_text()` is called with the RedactionMap, **Then** all placeholders are restored to original values.
- **Given** the same entity appears multiple times, **When** redacted, **Then** it gets the same placeholder consistently within the investigation.

**FRs:** (enables FR-RSN-001)
**NFRs:** NFR-SEC-001

#### Story 5.3: Create System Prompt Builder with Cache Support

**As a** platform optimising LLM costs,
**I want** a system prompt builder that prepends the safety prefix and marks system prompt blocks for Anthropic prompt caching,
**so that** all LLM calls have the safety prefix and repeated calls benefit from cache hits.

**Acceptance Criteria:**

- **Given** a task-specific system prompt, **When** `build_request()` is called, **Then** the SYSTEM_PREFIX is prepended before the task prompt.
- **Given** the system prompt block, **When** sent to Anthropic, **Then** it includes `cache_control: ephemeral` for prompt caching (5-minute lifetime, 90% cost reduction on cached reads).
- **Given** two sequential calls with the same system prompt, **When** the second call executes within 5 minutes, **Then** it benefits from cached prompt tokens.

**FRs:** (enables FR-RSN-001)
**NFRs:** NFR-SEC-003, NFR-PRF-003, NFR-PRF-004

#### Story 5.4: Create Output Validator

**As a** platform ensuring LLM output quality,
**I want** an output validator that checks LLM responses against expected JSON schemas and validates technique IDs against the taxonomy_ids Postgres table,
**so that** hallucinated technique IDs are caught and quarantined.

**Acceptance Criteria:**

- **Given** an LLM response with technique IDs, **When** validated, **Then** each technique ID is checked against the `taxonomy_ids` table. Valid IDs pass; unknown IDs are quarantined in the response.
- **Given** an LLM response with an output_schema defined, **When** validated, **Then** the response is checked against the JSON schema. Schema violations are returned in `validation_errors`.
- **Given** a completely malformed LLM response, **When** validated, **Then** `valid` is set to False with descriptive error messages.

**FRs:** FR-RSN-002
**NFRs:** NFR-SEC-004

#### Story 5.5: Create Anthropic API Client Wrapper

**As a** platform interfacing with the Anthropic API,
**I want** an async Anthropic client wrapper (AluskortAnthropicClient) with retry logic, streaming support, and per-call cost tracking,
**so that** all Anthropic API interactions are consistent, resilient, and cost-tracked.

**Acceptance Criteria:**

- **Given** a GatewayRequest, **When** sent to the Anthropic API, **Then** the client uses `anthropic.AsyncAnthropic` for non-blocking calls.
- **Given** a 429 or 5xx error, **When** the API call fails, **Then** the client retries with exponential backoff (max 3 retries, 1s base delay, doubling). 4xx errors are not retried.
- **Given** a completed API call, **When** metrics are recorded, **Then** `APICallMetrics` captures input_tokens, output_tokens, cache_read_tokens, cache_write_tokens, cost_usd, and latency_ms.
- **Given** a streaming request, **When** processed, **Then** the client returns an SSE stream of text chunks.

**FRs:** (enables FR-RSN-001)
**NFRs:** NFR-REL-007, NFR-OBS-002

#### Story 5.6: Create Spend Guard and Cost Tracking

**As a** SOC manager monitoring API costs,
**I want** a spend guard that enforces daily and monthly cost limits and tracks per-call costs,
**so that** API spend never exceeds budget unexpectedly.

**Acceptance Criteria:**

- **Given** a monthly hard cap of $1,000, **When** cumulative spend reaches the cap, **Then** all LLM calls are blocked with an appropriate error.
- **Given** a soft alert threshold of $500/month, **When** reached, **Then** an alert is generated but calls continue.
- **Given** each completed API call, **When** cost is recorded, **Then** it is tracked per tier, per task type, and per tenant for dashboard display.

**FRs:** (enables all reasoning FRs)
**NFRs:** NFR-OBS-003

#### Story 5.7: Integration Tests with Mocked Anthropic API

**As a** developer testing the Context Gateway,
**I want** integration tests that exercise the full gateway pipeline (sanitise -> redact -> call API -> validate -> deanonymise) with a mocked Anthropic API,
**so that** the gateway can be tested without real API calls or spend.

**Acceptance Criteria:**

- **Given** a mocked Anthropic API returning valid JSON, **When** the full gateway pipeline executes, **Then** the response passes output validation and PII is deanonymised correctly.
- **Given** a mocked API returning an invalid technique ID, **When** the pipeline executes, **Then** the output validator quarantines the unknown ID.
- **Given** input with injection patterns, **When** the pipeline executes, **Then** the injection is redacted before reaching the (mocked) API.

**FRs:** (validates all Context Gateway stories)
**NFRs:** NFR-SEC-001 through NFR-SEC-004

---

### Epic 6: Reasoning -- LLM Router

**Goal:** Build the model tier routing service that dispatches tasks to the correct Claude model based on task type, severity, context size, and cost constraints.

**Blocked by:** Epic 5 (depends on Context Gateway for actual LLM calls).
**Blocks:** Epic 7 (Orchestrator uses LLM Router for all model decisions).

#### Story 6.1: Create LLMRouter with TASK_TIER_MAP

**As a** platform routing LLM tasks efficiently,
**I want** an LLMRouter class that maps task types to model tiers using TASK_TIER_MAP and applies routing overrides based on severity, context size, and time budget,
**so that** each task gets the most cost-effective model that meets its quality requirements.

**Acceptance Criteria:**

- **Given** task_type="ioc_extraction", **When** routed, **Then** the decision is Tier 0 (Haiku) with max_tokens=2048 and temperature=0.1.
- **Given** task_type="investigation" with severity="critical", **When** routed, **Then** the decision is Tier 1 (Sonnet) minimum.
- **Given** any task with time_budget < 3s, **When** routed, **Then** the decision is forced to Tier 0.
- **Given** context_tokens > 100K, **When** routed, **Then** the decision is forced to Tier 1 minimum.

**FRs:** FR-ING-005, FR-ING-006
**NFRs:** NFR-PRF-003, NFR-PRF-004, NFR-PRF-005

#### Story 6.2: Create Concurrency Controller with Priority-Based Rate Limits

**As a** platform protecting against alert flood attacks,
**I want** a concurrency controller that enforces per-queue concurrency limits (critical=8, high=4, normal=2, low=1) and per-tenant quotas (premium=500, standard=100, trial=20 calls/hr),
**so that** critical alerts are never starved by low-priority floods.

**Acceptance Criteria:**

- **Given** the critical queue has 8 active workers, **When** a new critical job arrives, **Then** it waits in the queue (does not exceed concurrency limit).
- **Given** a standard tenant has made 100 LLM calls this hour, **When** a new call is attempted, **Then** it is rejected with a quota-exceeded error.
- **Given** critical and low jobs arrive simultaneously, **When** workers become available, **Then** critical jobs are processed first (drain order: critical > high > normal > low).

**FRs:** FR-ING-006, FR-ING-007
**NFRs:** NFR-SCL-003

#### Story 6.3: Create Escalation Manager

**As a** platform ensuring critical alert quality,
**I want** an escalation manager that upgrades Sonnet (Tier 1) calls to Opus (Tier 1+) when confidence < 0.6 on critical/high severity alerts,
**so that** low-confidence critical alerts get the best available reasoning.

**Acceptance Criteria:**

- **Given** a Sonnet response with confidence 0.55 on a critical alert, **When** evaluated, **Then** the escalation manager triggers a re-analysis with Opus (Tier 1+) including extended thinking (budget: 8192 tokens).
- **Given** Opus escalation requests, **When** tracked, **Then** a maximum of 10 escalations per hour is enforced as a cost guard.
- **Given** an escalation, **When** Opus returns a response, **Then** the higher-confidence result replaces the Sonnet result in the investigation state.

**FRs:** FR-RSN-005
**NFRs:** NFR-PRF-005

#### Story 6.4: Create Routing Metrics and Outcome Tracking

**As a** platform operator refining routing decisions,
**I want** per-task outcome tracking (success/failure, cost, latency, confidence) stored for each task_type:tier combination,
**so that** routing decisions can be refined based on operational data.

**Acceptance Criteria:**

- **Given** a completed LLM task, **When** `record_outcome()` is called, **Then** total, success, total_cost, total_latency, and confidence_sum are incremented for the task_type:tier key.
- **Given** routing metrics, **When** queried, **Then** average success rate, average cost, and average latency per task_type:tier are available.
- **Given** Prometheus scraping, **When** `/metrics` is hit, **Then** routing metrics are exported as Prometheus counters and histograms.

**FRs:** (enables FR-ING-005)
**NFRs:** NFR-OBS-001, NFR-OBS-002

#### Story 6.5: Unit Tests for All Routing Scenarios

**As a** developer maintaining the LLM Router,
**I want** unit tests covering all routing overrides (severity, time budget, context size, tenant tier, escalation),
**so that** routing logic is verified for every scenario.

**Acceptance Criteria:**

- **Given** all TASK_TIER_MAP entries, **When** tested with default context, **Then** each maps to the expected tier.
- **Given** critical severity with reasoning task, **When** tested, **Then** tier is upgraded to Tier 1.
- **Given** time_budget=2 seconds, **When** tested, **Then** tier is forced to Tier 0.
- **Given** confidence < 0.6 on critical severity, **When** escalation is tested, **Then** the task is re-routed to Tier 1+.

**FRs:** FR-ING-005, FR-ING-006, FR-RSN-005
**NFRs:** NFR-PRF-003 through NFR-PRF-005

---

### Epic 7: Reasoning -- Orchestrator (LangGraph)

**Goal:** Build the investigation state machine using LangGraph, implementing the full investigation lifecycle from alert intake through response.

**Blocked by:** Epics 1, 2, 3, 5, 6.
**Blocks:** Epic 11 (production deployment needs working orchestrator).

#### Story 7.1: Create GraphState and InvestigationState

**As a** platform tracking investigation lifecycle,
**I want** the GraphState dataclass and InvestigationState enum implemented with Postgres persistence,
**so that** every investigation has an explicit, replayable state.

**Acceptance Criteria:**

- **Given** a new investigation, **When** created, **Then** GraphState initialises with state=RECEIVED and all collections empty.
- **Given** a state transition, **When** the state changes, **Then** the GraphState is persisted to Postgres with the full decision_chain, llm_calls, and total_cost_usd.
- **Given** a failed investigation, **When** an unrecoverable error occurs, **Then** the state transitions to FAILED with error details in the decision_chain.

**FRs:** FR-RSN-007, FR-CSM-001
**NFRs:** NFR-CMP-001

#### Story 7.2: Create IOC Extractor Agent Node (Tier 0)

**As a** platform performing initial alert triage,
**I want** an IOC Extractor agent node that uses Tier 0 (Haiku) to extract IOCs from normalised alert entities,
**so that** structured IOC data is available for enrichment.

**Acceptance Criteria:**

- **Given** a normalised alert, **When** the IOC Extractor runs, **Then** it extracts IPs, hashes, domains, URLs, and accounts using Tier 0 LLM calls via Context Gateway.
- **Given** extracted IOCs, **When** checked against Redis, **Then** known IOCs are enriched with TI context (confidence, severity, campaigns).
- **Given** the IOC Extractor completes, **When** state transitions, **Then** RECEIVED -> PARSING with entities and ioc_matches populated in GraphState.

**FRs:** FR-ENR-001, FR-ENR-004
**NFRs:** NFR-PRF-003, NFR-PRF-008

#### Story 7.3: Create Context Enricher Agent Node (Parallel Lookups)

**As a** platform building investigation context,
**I want** a Context Enricher agent node that performs parallel lookups (Redis IOC, Postgres UEBA, Qdrant similar incidents, CTEM exposures),
**so that** the Reasoning Agent has full context for classification.

**Acceptance Criteria:**

- **Given** the PARSING state completes, **When** the Context Enricher runs, **Then** it executes Redis IOC lookup, Postgres UEBA query, and Qdrant similar incident search concurrently via asyncio.gather.
- **Given** UEBA data is missing for an entity, **When** risk_state is determined, **Then** it is set to NO_BASELINE (not LOW).
- **Given** similar incidents are found, **When** ranked, **Then** they use the time-decayed composite score (ALPHA=0.4, BETA=0.3, GAMMA=0.15, DELTA=0.15).
- **Given** all enrichment completes, **When** state transitions, **Then** PARSING -> ENRICHING with ueba_context, ioc_matches, similar_incidents, and ctem_exposures populated.

**FRs:** FR-ENR-004, FR-ENR-005, FR-ENR-006, FR-ENR-007, FR-RSN-004, FR-RAG-001
**NFRs:** NFR-PRF-001, NFR-PRF-008, NFR-REL-004, NFR-REL-005

#### Story 7.4: Create Reasoning Agent Node (Tier 1, Tool Use)

**As a** platform classifying alerts with LLM reasoning,
**I want** a Reasoning Agent node that uses Tier 1 (Sonnet) with tool use to classify alerts, assess severity, map techniques, and recommend actions,
**so that** investigations produce structured, auditable classification decisions.

**Acceptance Criteria:**

- **Given** enriched context (IOCs, UEBA, similar incidents, CTEM, ATLAS), **When** the Reasoning Agent runs, **Then** it produces a structured JSON output with classification, confidence, severity, ATT&CK techniques, and recommended_actions.
- **Given** a classification with confidence >= 0.6, **When** the alert is non-destructive, **Then** state transitions to RESPONDING (auto-close path).
- **Given** a classification requiring destructive action, **When** evaluated, **Then** state transitions to AWAITING_HUMAN regardless of confidence.
- **Given** confidence < 0.6 on critical/high severity, **When** evaluated, **Then** the alert is escalated to Tier 1+ (Opus) via the LLM Router.

**FRs:** FR-RSN-001, FR-RSN-002, FR-RSN-005, FR-RSP-001
**NFRs:** NFR-PRF-004, NFR-SEC-001

#### Story 7.5: Create Response Agent Node

**As a** platform executing response actions,
**I want** a Response Agent node that formats recommended actions, selects playbooks, and triggers human approval gates for destructive actions,
**so that** investigations conclude with actionable, auditable outcomes.

**Acceptance Criteria:**

- **Given** recommended actions from the Reasoning Agent, **When** the Response Agent runs, **Then** it selects the appropriate playbook based on tactics, techniques, product, and severity.
- **Given** a destructive action (account disable, endpoint isolation, firewall block), **When** evaluated, **Then** the Response Agent sets `requires_human_approval = True` and transitions to AWAITING_HUMAN.
- **Given** human approval is granted, **When** the investigation resumes, **Then** the Response Agent executes the approved actions and publishes to `actions.pending` and `audit.events`.
- **Given** the 4-hour approval timeout expires, **When** no approval is received, **Then** the investigation closes with `timed_out` status.

**FRs:** FR-RSP-001 through FR-RSP-006, FR-CSM-003
**NFRs:** NFR-CMP-001

#### Story 7.6: Create CTEM Correlator Agent Node

**As a** platform correlating alerts with exposure data,
**I want** a CTEM Correlator agent node that matches alerts against CTEM exposure records in Postgres by asset_id and asset_zone,
**so that** investigations include known vulnerability and exposure context.

**Acceptance Criteria:**

- **Given** alert entities with an asset_id, **When** the CTEM Correlator runs, **Then** it queries `ctem_exposures` by asset_id and asset_zone, returning matching open exposures.
- **Given** matching CTEM exposures, **When** added to GraphState, **Then** ctem_exposures list contains exposure_key, severity, ctem_score, and source_tool for each match.
- **Given** CTEM data is stale (> 24 hours), **When** the correlator runs, **Then** it flags the context as stale in the investigation state.

**FRs:** FR-ENR-006, FR-CTM-001
**NFRs:** NFR-OBS-004

#### Story 7.7: Create ATLAS Mapper Agent Node

**As a** platform detecting adversarial ML threats,
**I want** an ATLAS Mapper agent node that maps alert techniques to ATLAS technique IDs and correlates with ATT&CK cross-framework mappings,
**so that** investigations include adversarial ML context when relevant.

**Acceptance Criteria:**

- **Given** alert techniques, **When** the ATLAS Mapper runs, **Then** it queries both the `taxonomy_ids` table and Qdrant `aluskort-mitre` collection for ATLAS technique matches.
- **Given** a cross-framework detection (e.g., T1078 + AML.T0020), **When** mapped, **Then** both technique IDs are included in atlas_techniques with the correlation link.
- **Given** no ATLAS technique matches, **When** the mapper completes, **Then** atlas_techniques is empty (no false mappings).

**FRs:** FR-ATL-005, FR-RSN-002
**NFRs:** (none directly)

#### Story 7.8: Wire Investigation Graph with Edges and State Transitions

**As a** developer implementing the LangGraph state machine,
**I want** the INVESTIGATION_GRAPH edge definitions wired into a LangGraph graph with proper state transitions and parallel execution,
**so that** the investigation lifecycle follows the designed flow.

**Acceptance Criteria:**

- **Given** the graph definition, **When** an investigation starts, **Then** it follows: RECEIVED -> PARSING -> ENRICHING -> REASONING -> RESPONDING/AWAITING_HUMAN -> CLOSED.
- **Given** the ENRICHING state, **When** entered, **Then** Context Enricher, CTEM Correlator, and ATLAS Mapper run in parallel.
- **Given** the AWAITING_HUMAN state, **When** entered, **Then** the graph pauses and waits for external approval signal or 4-hour timeout.
- **Given** any state transition, **When** executed, **Then** the transition is recorded in the decision_chain with agent, action, and timestamp.

**FRs:** FR-RSN-007
**NFRs:** (none directly)

#### Story 7.9: Create FP Short-Circuit Logic

**As a** platform optimising LLM costs,
**I want** FP pattern short-circuit logic that checks parsed alerts against approved FP patterns before LLM calls,
**so that** known false positives are auto-closed without spending API tokens.

**Acceptance Criteria:**

- **Given** a normalised alert, **When** it matches an approved FP pattern in Redis with confidence > 0.90, **Then** the investigation transitions directly from PARSING to CLOSED with classification="false_positive" and no LLM call.
- **Given** a FP short-circuit closure, **When** logged, **Then** the decision_chain includes the pattern_id, confidence, and "fp_short_circuit" action.
- **Given** no FP pattern match, **When** evaluated, **Then** the investigation proceeds normally to ENRICHING.

**FRs:** FR-RSN-006, FR-RAG-005
**NFRs:** NFR-PRF-001

#### Story 7.10: Integration Test -- Full Pipeline with Mocked LLM

**As a** developer validating the orchestrator end-to-end,
**I want** an integration test that runs the full investigation pipeline (RECEIVED through CLOSED) with a mocked LLM and real Postgres/Redis/Qdrant,
**so that** the complete lifecycle is verified before production deployment.

**Acceptance Criteria:**

- **Given** a sample CanonicalAlert, **When** the full pipeline runs with mocked LLM, **Then** the investigation progresses through all states and closes with a valid classification.
- **Given** the pipeline completes, **When** state is queried, **Then** GraphState is persisted in Postgres with populated entities, ioc_matches, decision_chain, classification, confidence, and severity.
- **Given** the pipeline completes, **When** audit.events is checked, **Then** all state transitions and agent decisions are recorded.
- **Given** a destructive action scenario, **When** the pipeline reaches AWAITING_HUMAN, **Then** it pauses and resumes correctly on simulated approval.

**FRs:** FR-RSN-001, FR-RSN-007, FR-RSP-002, FR-RSP-003, FR-CSM-001, FR-CSM-003
**NFRs:** NFR-CMP-001

---

### Epic 8: Intelligence -- CTEM Normaliser

**Goal:** Build the CTEM finding normalisation service that consumes from per-source Kafka topics and upserts normalised exposures to Postgres.

**Blocked by:** Epics 1, 2.
**Blocks:** Epic 7 Story 7.6 (CTEM Correlator agent needs exposure data).

#### Story 8.1: Create Wiz Normaliser

**As a** platform ingesting Wiz CSPM findings,
**I want** a WizNormaliser that maps Wiz finding format to the CTEM exposure schema with consequence-weighted severity scoring,
**so that** Wiz cloud security findings are normalised for CTEM correlation.

**Acceptance Criteria:**

- **Given** a raw Wiz finding, **When** normalised, **Then** it produces a valid CTEM exposure with deterministic exposure_key = sha256(wiz:title:asset_id)[:16].
- **Given** Wiz severity and exploitability, **When** consequence-weighted scoring is applied, **Then** the ctem_score reflects the (exploitability, consequence) matrix.
- **Given** the normalised exposure, **When** upserted to Postgres, **Then** ON CONFLICT updates ts, severity, ctem_score, and updated_at.

**FRs:** FR-CTM-002, FR-CTM-003, FR-CTM-004, FR-CTM-007
**NFRs:** (none directly)

#### Story 8.2: Create Snyk Normaliser

**As a** platform ingesting Snyk SCA findings,
**I want** a SnykNormaliser that maps Snyk vulnerability format to the CTEM exposure schema,
**so that** software composition analysis findings are normalised for CTEM correlation.

**Acceptance Criteria:**

- **Given** a raw Snyk vulnerability, **When** normalised, **Then** it produces a valid CTEM exposure with correct asset_id, asset_type, and severity mapping.
- **Given** a Snyk finding with CVSS score, **When** mapped, **Then** exploitability_score is derived from the CVSS exploitability sub-score.
- **Given** the deterministic exposure_key, **When** the same finding is re-ingested, **Then** it upserts (updates, not duplicates).

**FRs:** FR-CTM-002, FR-CTM-003, FR-CTM-007
**NFRs:** (none directly)

#### Story 8.3: Create Garak Normaliser

**As a** platform ingesting Garak LLM security findings,
**I want** a GarakNormaliser that maps Garak findings to the CTEM exposure schema with ATLAS technique mapping,
**so that** LLM security vulnerabilities are tracked as exposures.

**Acceptance Criteria:**

- **Given** a raw Garak finding, **When** normalised, **Then** atlas_technique is populated with the corresponding ATLAS technique ID (e.g., AML.T0051).
- **Given** a Garak finding affecting a deployed model, **When** normalised, **Then** asset_id maps to the model name and asset_zone maps to the deployment zone.
- **Given** the normalised exposure, **When** upserted, **Then** the exposure_key is deterministic and idempotent.

**FRs:** FR-CTM-002, FR-CTM-003, FR-ATL-005
**NFRs:** (none directly)

#### Story 8.4: Create ART Normaliser

**As a** platform ingesting IBM ART adversarial ML findings,
**I want** an ARTNormaliser that maps ART findings to the CTEM exposure schema with ATLAS technique mapping,
**so that** adversarial ML test results are tracked as exposures.

**Acceptance Criteria:**

- **Given** a raw ART finding, **When** normalised, **Then** atlas_technique and attack_technique are populated with both ATLAS and ATT&CK technique IDs.
- **Given** an ART finding with physical consequence potential, **When** consequence scoring is applied, **Then** physical_consequence maps to the correct zone consequence class.
- **Given** the normalised exposure, **When** upserted, **Then** existing records in Verified or Closed status are not overwritten.

**FRs:** FR-CTM-002, FR-CTM-003, FR-CTM-004
**NFRs:** (none directly)

#### Story 8.5: Create Postgres Upsert Logic (ON CONFLICT)

**As a** platform ensuring idempotent exposure records,
**I want** a Postgres upsert function that inserts new exposures and updates existing ones using ON CONFLICT on exposure_key,
**so that** re-ingesting the same finding updates rather than duplicates.

**Acceptance Criteria:**

- **Given** a new exposure, **When** upserted, **Then** it is inserted with all 22 fields.
- **Given** an existing exposure, **When** re-upserted, **Then** ts, severity, ctem_score, and updated_at are updated. Status is NOT overwritten if current status is Verified or Closed.
- **Given** the upsert uses parameterised SQL, **When** executed, **Then** all values are bound via `$1, $2, ...` (no string interpolation).

**FRs:** FR-CTM-007
**NFRs:** NFR-SEC-007

#### Story 8.6: Create Kafka Consumers for ctem.raw.* Topics

**As a** pipeline operator,
**I want** Kafka consumers that subscribe to ctem.raw.wiz, ctem.raw.snyk, ctem.raw.garak, ctem.raw.art, ctem.raw.burp, and ctem.raw.custom topics,
**so that** CTEM findings from all sources are automatically normalised as they arrive.

**Acceptance Criteria:**

- **Given** the CTEM normaliser service starts, **When** a message appears on any ctem.raw.* topic, **Then** it is consumed, routed to the correct normaliser, and the result is upserted to Postgres.
- **Given** a normalised exposure, **When** upserted successfully, **Then** the exposure is also published to `ctem.normalized` for downstream consumers.
- **Given** a normalisation failure, **When** the error is unrecoverable, **Then** the message is sent to `ctem.normalized.dlq` with error details.

**FRs:** FR-CTM-002, FR-CTM-003
**NFRs:** NFR-REL-002

---

### Epic 9: Intelligence -- ATLAS Detection

**Goal:** Build the ATLAS adversarial ML detection rules that monitor Postgres telemetry tables and generate alerts.

**Blocked by:** Epics 1, 2 (ATLAS Postgres telemetry tables).
**Blocks:** Nothing directly (results flow through the standard alert pipeline).

#### Story 9.1: Create DetectionRule Base Class

**As a** developer implementing detection rules,
**I want** a DetectionRule base class with execute(), get_frequency(), and get_threshold() methods and a DetectionResult dataclass,
**so that** all ATLAS detection rules follow a consistent pattern.

**Acceptance Criteria:**

- **Given** the DetectionRule ABC, **When** a new rule is implemented, **Then** it must implement execute() (returns list of DetectionResult), get_frequency() (returns timedelta), and get_thresholds() (returns dict).
- **Given** a DetectionResult, **When** created, **Then** it contains rule_id, threat_model_refs (list of TM-IDs), atlas_techniques, attack_techniques, severity, confidence, evidence, and timestamp.
- **Given** a detection result, **When** published, **Then** it is formatted as a CanonicalAlert and published to `alerts.raw`.

**FRs:** FR-ATL-001
**NFRs:** (none directly)

#### Story 9.2: Implement 10 Detection Rules

**As a** platform monitoring for adversarial ML threats,
**I want** all 10 ATLAS detection rules (ATLAS-DETECT-001 through ATLAS-DETECT-010) implemented as Python analytics against Postgres telemetry tables,
**so that** 17 threat model IDs are monitored with exact statistical thresholds.

**Acceptance Criteria:**

- **Given** each detection rule, **When** executed against synthetic test data, **Then** it correctly identifies the threat pattern with confidence above the configured floor.
- **Given** ATLAS-DETECT-001 (inference pattern anomaly), **When** DeviationFactor > 3.0, **Then** an alert is generated for TM-01.
- **Given** ATLAS-DETECT thresholds, **When** implemented, **Then** exact thresholds are preserved: DeviationFactor > 3.0, extractionThreshold = 100, z-score < -2.0, SpikeRatio > 5.0.
- **Given** safety-relevant rules (physics oracle, sensor spoofing, ICS lateral movement), **When** confidence floors are applied, **Then** physics oracle >= 0.7, sensor spoofing >= 0.7, ICS lateral movement >= 0.8.

**FRs:** FR-ATL-001, FR-ATL-003, FR-ATL-004, FR-ATL-006
**NFRs:** NFR-SEC-007

#### Story 9.3: Create Postgres Telemetry Tables

**As a** platform storing ATLAS telemetry data,
**I want** all 10 telemetry tables (orbital_inference_logs, orbital_physics_oracle, orbital_nl_query_logs, orbital_api_logs, edge_node_telemetry, databricks_audit, model_registry, cicd_audit, partner_api_logs, opcua_telemetry) created with appropriate indexes,
**so that** detection rules can query telemetry efficiently.

**Acceptance Criteria:**

- **Given** the DDL scripts, **When** executed, **Then** all 10 telemetry tables are created with correct columns, types, and NOT NULL constraints.
- **Given** each table, **When** created, **Then** it has indexes on (ts) and on the primary lookup key for efficient time-windowed queries.
- **Given** time-series tables, **When** created, **Then** they are partitioned by month for data lifecycle management.

**FRs:** FR-ATL-002
**NFRs:** NFR-CMP-002

#### Story 9.4: Create Detection Runner and Alerting

**As a** platform scheduling detection rule execution,
**I want** a detection runner that executes each rule at its configured frequency and publishes detected threats as CanonicalAlerts to `alerts.raw`,
**so that** ATLAS detections flow through the standard alert pipeline.

**Acceptance Criteria:**

- **Given** rule frequencies, **When** the runner schedules execution, **Then** critical rules (physics oracle DoS, sensor spoofing) run every 5 minutes and non-critical rules run every 1 hour.
- **Given** a detection fires, **When** published, **Then** the CanonicalAlert source is "atlas", techniques include both ATLAS and ATT&CK IDs, and the raw_payload contains the full DetectionResult.
- **Given** ATLAS self-protection, **When** a safety-relevant alert is generated, **Then** the LLM cannot classify it as false_positive (enforced in the alert metadata).

**FRs:** FR-ATL-001, FR-ATL-003, FR-ATL-005, FR-ATL-006
**NFRs:** (none directly)

---

### Epic 10: Batch -- Batch Scheduler

**Goal:** Build the Tier 2 batch processing service that accumulates offline tasks and submits them via the Anthropic Batch API.

**Blocked by:** Epics 5, 6 (depends on Context Gateway and LLM Router).
**Blocks:** Nothing directly (batch processing is asynchronous).

#### Story 10.1: Create Anthropic Batch API Client

**As a** platform using the Anthropic Batch API for offline tasks,
**I want** an AluskortBatchClient wrapper that submits batch requests, polls for completion, and processes results,
**so that** Tier 2 tasks benefit from the 50% batch discount.

**Acceptance Criteria:**

- **Given** a list of batch tasks, **When** submitted, **Then** the client creates an Anthropic Batch API request with max batch size 10,000.
- **Given** a submitted batch, **When** polling for completion, **Then** the client checks status at configurable intervals until all items are complete or the 24-hour SLA expires.
- **Given** batch results, **When** processed, **Then** each result is parsed, validated through the output validator, and stored.

**FRs:** (enables FR-RAG-005, FR-RAG-007)
**NFRs:** NFR-PRF-006

#### Story 10.2: Create BatchScheduler with Time/Count Triggers

**As a** platform accumulating batch tasks efficiently,
**I want** a BatchScheduler that submits accumulated tasks every 6 hours or when the queue reaches 50 items (whichever comes first),
**so that** batch processing is timely without excessive API calls.

**Acceptance Criteria:**

- **Given** 50 accumulated tasks, **When** the count trigger fires, **Then** the batch is submitted immediately.
- **Given** fewer than 50 tasks, **When** the 6-hour timer fires, **Then** all accumulated tasks are submitted as a batch.
- **Given** no accumulated tasks, **When** the timer fires, **Then** no batch is submitted (no empty batches).

**FRs:** (enables FR-RAG-005, FR-RAG-007)
**NFRs:** NFR-PRF-006

#### Story 10.3: Create Batch Result Processor

**As a** platform processing batch results,
**I want** a result processor that handles completed batch responses, routes results to the appropriate storage, and logs outcomes,
**so that** FP patterns, playbook drafts, and detection rules are stored correctly.

**Acceptance Criteria:**

- **Given** a completed FP pattern generation batch, **When** processed, **Then** generated patterns are stored in Postgres fp_patterns with status="pending_review" and published to `knowledge.fp.approved` after analyst approval.
- **Given** a completed playbook generation batch, **When** processed, **Then** playbook drafts are published to `playbooks.draft` Kafka topic for analyst review.
- **Given** a batch with partial failures, **When** processed, **Then** successful results are stored and failed items are logged with error details.

**FRs:** FR-RAG-005, FR-RAG-007
**NFRs:** NFR-CMP-003

#### Story 10.4: Create FP Pattern Generator (Batch Job)

**As a** platform improving FP detection over time,
**I want** a batch job that analyses closed investigations to generate FP pattern candidates,
**so that** recurring false positives are automatically identified for analyst review and approval.

**Acceptance Criteria:**

- **Given** a set of investigations closed as false_positive with analyst confirmation, **When** the FP pattern generator runs, **Then** it identifies common patterns (alert_name, entity patterns, severity) and generates pattern candidates.
- **Given** a generated FP pattern, **When** created, **Then** it requires analyst approval (approved_by, approval_date) before activation.
- **Given** an approved FP pattern, **When** activated, **Then** it is loaded into the Redis hot cache for sub-ms matching in the short-circuit engine.

**FRs:** FR-RAG-005, FR-RSN-006, FR-CSM-004
**NFRs:** NFR-CMP-003

---

### Epic 11: Operations -- Monitoring and Deployment

**Goal:** Production readiness: metrics, alerting, Kubernetes manifests, CI/CD pipeline, health checks, and runbooks.

**Blocked by:** All previous epics (Epics 1-10).
**Blocks:** Nothing (final epic).

#### Story 11.1: Create Prometheus Metrics for All Services

**As a** platform operator monitoring system health,
**I want** Prometheus metrics exposed on `/metrics` for all services covering LLM call count/latency/cost, Kafka consumer group lag, pipeline stage latency, and investigation state distribution,
**so that** operational health is visible in Grafana dashboards.

**Acceptance Criteria:**

- **Given** each service, **When** `/metrics` is scraped, **Then** it returns Prometheus-format metrics including service-specific counters (e.g., entity_parser_alerts_processed_total, context_gateway_llm_calls_total).
- **Given** LLM metrics, **When** exported, **Then** they include call_count, latency_histogram, cost_total, and confidence_histogram broken down by tier and task_type.
- **Given** Kafka metrics, **When** exported, **Then** they include consumer_lag per topic/partition and produce_errors_total.
- **Given** investigation metrics, **When** exported, **Then** they include investigations_active, investigations_by_state, and investigation_duration_histogram.

**FRs:** (enables all observability)
**NFRs:** NFR-OBS-001, NFR-OBS-002

#### Story 11.2: Create Alerting Rules

**As a** platform operator,
**I want** Prometheus alerting rules for critical conditions (LLM circuit breaker open, Kafka consumer lag > threshold, investigation stuck in AWAITING_HUMAN > 3 hours, monthly spend > soft limit),
**so that** operational issues are detected and escalated automatically.

**Acceptance Criteria:**

- **Given** Anthropic API circuit breaker opens, **When** the alert fires, **Then** it notifies the on-call team with severity=critical and includes degradation mode status.
- **Given** Kafka consumer lag exceeds 1,000 messages, **When** the alert fires, **Then** it notifies with severity=warning and includes the topic and consumer group.
- **Given** an investigation in AWAITING_HUMAN for > 3 hours, **When** the alert fires, **Then** it notifies the SOC lead with investigation_id and pending action details.
- **Given** monthly API spend exceeds $500, **When** the alert fires, **Then** it notifies the SOC manager with current spend breakdown by tier.

**FRs:** (enables operational readiness)
**NFRs:** NFR-OBS-001, NFR-OBS-003

#### Story 11.3: Create Kubernetes Deployment Manifests

**As a** platform operator deploying to production,
**I want** Kubernetes Deployment, Service, ConfigMap, and Secret manifests for all services in namespace `aluskort`,
**so that** the system can be deployed to any Kubernetes cluster.

**Acceptance Criteria:**

- **Given** the manifests, **When** applied to a Kubernetes cluster, **Then** all services (entity-parser, ctem-normaliser, orchestrator, context-gateway, llm-router, batch-scheduler, sentinel-adapter) are deployed with correct replicas, resource requests/limits, and environment variables.
- **Given** each Deployment, **When** configured, **Then** it includes liveness and readiness probes pointing to `/health` and `/ready`.
- **Given** the ConfigMap, **When** applied, **Then** it contains kafka_bootstrap, qdrant_host/port, redis_host/port, embedding config, and log_level.
- **Given** Secrets, **When** applied, **Then** they contain Anthropic API key, Postgres DSN, Neo4j URI with appropriate base64 encoding.

**FRs:** (enables production deployment)
**NFRs:** NFR-REL-006, NFR-SCL-002

#### Story 11.4: Create GitHub Actions CI/CD Pipeline

**As a** developer automating builds and deployments,
**I want** GitHub Actions workflows for CI (unit + contract + integration tests) and CD (Docker build + push + K8s deploy),
**so that** every merge to main is automatically tested and deployable.

**Acceptance Criteria:**

- **Given** a push to main or PR, **When** CI runs, **Then** it executes pytest on tests/unit/, tests/contract/, and tests/integration/ with 90% coverage gate on shared/.
- **Given** CI passes on main, **When** CD runs, **Then** Docker images are built for all services using the matrix strategy and pushed to GHCR with the commit SHA tag.
- **Given** CI requires Postgres and Redis, **When** test services start, **Then** GitHub Actions service containers for postgres:16-alpine and redis:7-alpine are available.

**FRs:** (enables CI/CD)
**NFRs:** (none directly)

#### Story 11.5: Create Health Check Endpoints for All Services

**As a** Kubernetes operator ensuring service availability,
**I want** `/health` (liveness) and `/ready` (readiness) endpoints on every service that check connectivity to dependent infrastructure,
**so that** Kubernetes can automatically restart unhealthy pods and route traffic only to ready pods.

**Acceptance Criteria:**

- **Given** a service with all dependencies available, **When** `/ready` is called, **Then** it returns 200 OK after verifying connectivity to its databases, Kafka, and external APIs.
- **Given** a service with a failed database connection, **When** `/ready` is called, **Then** it returns 503 Service Unavailable with details of the failed dependency.
- **Given** a service that is running but initialising, **When** `/health` is called, **Then** it returns 200 OK (process is alive even if not yet ready).

**FRs:** (enables operational readiness)
**NFRs:** NFR-REL-006

#### Story 11.6: Create Operations Runbook

**As a** SOC operator debugging production issues at 03:00,
**I want** an operations runbook covering common failure scenarios (LLM degradation, Kafka lag, stuck investigations, cost overrun, DLQ processing),
**so that** on-call engineers can diagnose and resolve issues quickly.

**Acceptance Criteria:**

- **Given** the runbook, **When** an LLM degradation event occurs, **Then** it provides step-by-step instructions for verifying circuit breaker state, checking Anthropic status, and confirming deterministic-only mode is active.
- **Given** the runbook, **When** Kafka consumer lag spikes, **Then** it provides instructions for identifying the lagging consumer, checking for stuck partitions, and scaling the consumer group.
- **Given** the runbook, **When** a cost overrun alert fires, **Then** it provides instructions for checking spend breakdown, identifying the cause (escalation storm, batch spike), and adjusting limits.
- **Given** the runbook, **When** DLQ processing is needed, **Then** it provides instructions for inspecting DLQ messages, replaying failed messages, and clearing the DLQ.

**FRs:** (enables operational readiness)
**NFRs:** NFR-REL-001, NFR-OBS-001

---

## 4. Dependency Summary

```
Epic 1 (Foundation)
  |
  +---> Epic 2 (Infrastructure)
  |       |
  |       +---> Epic 3 (Entity Parser) ---> Epic 4 (Sentinel Adapter)
  |       |                                        |
  |       +---> Epic 8 (CTEM Normaliser)           |
  |       |                                        |
  |       +---> Epic 9 (ATLAS Detection)           |
  |                                                |
  +---> Epic 5 (Context Gateway)                   |
          |                                        |
          +---> Epic 6 (LLM Router)                |
          |       |                                |
          |       +---> Epic 7 (Orchestrator) <----+
          |       |
          +---> Epic 10 (Batch Scheduler)
                  |
                  +---> Epic 11 (Operations) <--- All Epics
```

**Parallel tracks:**
- Track A (Ingest): Epics 1 -> 2 -> 3 -> 4
- Track B (Reasoning): Epics 1 -> 5 -> 6
- Track C (Intelligence): Epics 1 -> 2 -> 8, 9

Tracks A and B converge at Epic 7 (Orchestrator). Track C runs independently until CTEM Correlator (Story 7.6) needs Epic 8 data.

---

*Epics and stories planning artifact generated for ALUSKORT project, 2026-02-14.*
