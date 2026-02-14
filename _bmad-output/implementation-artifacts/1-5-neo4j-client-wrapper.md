---
story_id: "1.5"
story_key: "1-5-neo4j-client-wrapper"
title: "Create Neo4j Client Wrapper"
epic: "Epic 1: Foundation"
status: "done"
priority: "high"
---

# Story 1.5: Create Neo4j Client Wrapper

## Story

As a developer building ALUSKORT services,
I want a Neo4j graph database client wrapper with Cypher query execution, consequence reasoning queries, and fallback to a static zone-consequence dictionary when Neo4j is unavailable,
so that all services interact with the asset/zone graph through a consistent, resilient interface with graceful degradation.

## Acceptance Criteria

### AC-1.5.1: Driver Initialization
**Given** valid Neo4j connection parameters (uri, user, password)
**When** Neo4jClient is instantiated and connect() is called
**Then** a neo4j.AsyncDriver is created and connectivity is verified

### AC-1.5.2: Cypher Query Execution
**Given** an active Neo4jClient
**When** execute_query(cypher="MATCH (n:Asset) RETURN n LIMIT 10", params={}) is called
**Then** the Cypher query is executed and results are returned as a list of dicts

### AC-1.5.3: Consequence Severity Query
**Given** an active Neo4jClient with a populated asset/zone graph
**When** get_consequence_severity(finding_id="finding-001") is called
**Then** the consequence reasoning Cypher query from ai-system-design.md Section 8.2 is executed and the max_consequence_severity is returned (one of "CRITICAL", "HIGH", "MEDIUM", "LOW")

### AC-1.5.4: Consequence Severity Mapping
**Given** the consequence reasoning query returns reachable_consequences containing "safety_life"
**When** the severity is mapped
**Then** "CRITICAL" is returned. Similarly: "equipment" -> "HIGH", "downtime" -> "MEDIUM", anything else -> "LOW"

### AC-1.5.5: Fallback When Neo4j Is Down
**Given** a Neo4jClient where Neo4j is unreachable
**When** get_consequence_severity() is called
**Then** the static ZONE_CONSEQUENCE_FALLBACK dict is used: {"safety_life": "CRITICAL", "equipment": "HIGH", "downtime": "MEDIUM", "data_loss": "LOW"} and the fallback result is logged with a warning

### AC-1.5.6: Fallback Returns Default for Unknown Zone
**Given** Neo4j is down and get_consequence_severity() falls back to the static dict
**When** the zone consequence class is not found in the fallback dict
**Then** "LOW" is returned as the default severity

### AC-1.5.7: Graceful Shutdown
**Given** an active Neo4jClient with an open driver
**When** close() is called
**Then** the driver is closed gracefully

### AC-1.5.8: Health Check
**Given** an active Neo4jClient
**When** health_check() is called
**Then** it executes a simple Cypher query (RETURN 1) and returns True if successful, False otherwise

## Tasks/Subtasks

- [ ] Task 1: Create Neo4jClient class
  - [ ] Subtask 1.1: Create shared/db/neo4j_graph.py
  - [ ] Subtask 1.2: Define Neo4jClient with __init__ accepting uri, user, password, database (default "neo4j"), max_connection_pool_size (default 50)
  - [ ] Subtask 1.3: Implement connect() that creates neo4j.AsyncGraphDatabase.driver() and verifies connectivity
  - [ ] Subtask 1.4: Implement close() that calls driver.close()
- [ ] Task 2: Implement Cypher query execution
  - [ ] Subtask 2.1: Implement execute_query(cypher: str, params: Optional[dict] = None, database: Optional[str] = None) -> list[dict]
  - [ ] Subtask 2.2: Use driver.execute_query() with the provided Cypher and params
  - [ ] Subtask 2.3: Convert neo4j Records to list of dicts for return
  - [ ] Subtask 2.4: Add logging for query execution time and result count
- [ ] Task 3: Implement consequence reasoning query
  - [ ] Subtask 3.1: Define CONSEQUENCE_QUERY constant with the Cypher from ai-system-design.md Section 8.2
  - [ ] Subtask 3.2: Implement get_consequence_severity(finding_id: str) -> dict that executes CONSEQUENCE_QUERY with finding_id parameter
  - [ ] Subtask 3.3: Return dict with keys: finding_id, directly_affected_asset, reachable_consequences, max_consequence_severity
  - [ ] Subtask 3.4: Implement consequence priority mapping: safety_life -> CRITICAL, equipment -> HIGH, downtime -> MEDIUM, else -> LOW
- [ ] Task 4: Implement static fallback
  - [ ] Subtask 4.1: Define ZONE_CONSEQUENCE_FALLBACK = {"safety_life": "CRITICAL", "equipment": "HIGH", "downtime": "MEDIUM", "data_loss": "LOW"}
  - [ ] Subtask 4.2: Wrap get_consequence_severity() in try/except for neo4j.exceptions.ServiceUnavailable, neo4j.exceptions.SessionExpired, and general Exception
  - [ ] Subtask 4.3: On Neo4j failure, log warning "GRAPH_UNAVAILABLE: falling back to static zone-consequence mapping"
  - [ ] Subtask 4.4: Implement _fallback_consequence(zone_class: Optional[str] = None) -> str that returns ZONE_CONSEQUENCE_FALLBACK.get(zone_class, "LOW")
- [ ] Task 5: Implement health check and utilities
  - [ ] Subtask 5.1: Implement health_check() -> bool that executes RETURN 1 and returns True/False
  - [ ] Subtask 5.2: Add async context manager support (__aenter__ / __aexit__)
  - [ ] Subtask 5.3: Implement get_asset_graph(asset_id: str) -> dict for retrieving an asset's zone and relationship context
- [ ] Task 6: Write unit tests
  - [ ] Subtask 6.1: Create tests/test_db/test_neo4j_graph.py
  - [ ] Subtask 6.2: Mock neo4j.AsyncGraphDatabase.driver and test connect() creates driver
  - [ ] Subtask 6.3: Mock driver.execute_query and test execute_query() returns list of dicts
  - [ ] Subtask 6.4: Test get_consequence_severity() executes correct Cypher with finding_id param
  - [ ] Subtask 6.5: Test consequence mapping: safety_life -> CRITICAL, equipment -> HIGH, downtime -> MEDIUM, data_loss -> LOW
  - [ ] Subtask 6.6: Test fallback: mock ServiceUnavailable exception -> returns fallback result with warning log
  - [ ] Subtask 6.7: Test fallback returns "LOW" for unknown zone consequence class
  - [ ] Subtask 6.8: Test health_check returns True on success, False on exception
  - [ ] Subtask 6.9: Test close() calls driver.close()

## Dev Notes

### Architecture Requirements
- Use neo4j >= 5.17.0 Python driver with async support
- Neo4j version target: 5.x
- The graph schema models assets, zones, models, findings, and tenants with relationships:
  - (Asset)-[:RESIDES_IN]->(Zone)
  - (Model)-[:DEPLOYS_TO]->(Asset)
  - (Finding)-[:AFFECTS]->(Asset)
  - (Asset)-[:OWNED_BY]->(Tenant)
  - (Zone)-[:CONNECTS_TO]->(Zone)
- Zone consequence_class values: "safety_life", "equipment", "downtime", "data_loss"
- The consequence reasoning query (Section 8.2) walks the graph: Finding -> Asset -> Model -> downstream Assets -> Zones, collecting reachable consequence classes and returning the maximum severity
- Fallback is CRITICAL for resilience: when Neo4j is down, the system must still be able to assess consequence severity using the static ZONE_CONSEQUENCE_FALLBACK dict
- See docs/ai-system-design.md Section 8 for full graph schema and consequence reasoning
- See docs/ai-system-design.md Section 11.1: "Neo4j down -> Fall back to static zone mapping"

### Technical Specifications
- Class: Neo4jClient in shared/db/neo4j_graph.py
- Constructor params: uri (str, default "bolt://localhost:7687"), user (str, default "neo4j"), password (str, default ""), database (str, default "neo4j"), max_connection_pool_size (int, default 50)
- CONSEQUENCE_QUERY constant (Cypher):
  ```cypher
  MATCH (f:Finding {id: $finding_id})-[:AFFECTS]->(a:Asset)
  OPTIONAL MATCH (a)<-[:DEPLOYS_TO]-(m:Model)-[:DEPLOYS_TO]->(downstream:Asset)-[:RESIDES_IN]->(z:Zone)
  WITH f, a, collect(DISTINCT z.consequence_class) AS reachable_consequences
  RETURN f.id,
         a.name AS directly_affected_asset,
         reachable_consequences,
         CASE
             WHEN 'safety_life' IN reachable_consequences THEN 'CRITICAL'
             WHEN 'equipment' IN reachable_consequences THEN 'HIGH'
             WHEN 'downtime' IN reachable_consequences THEN 'MEDIUM'
             ELSE 'LOW'
         END AS max_consequence_severity
  ```
- ZONE_CONSEQUENCE_FALLBACK = {"safety_life": "CRITICAL", "equipment": "HIGH", "downtime": "MEDIUM", "data_loss": "LOW"}
- All public methods must be async
- Logging: use standard Python logging (logging.getLogger(__name__))
- On fallback, log at WARNING level with message containing "GRAPH_UNAVAILABLE"

### Testing Strategy
- pytest with pytest-asyncio
- Mock neo4j.AsyncGraphDatabase.driver (do not require a live Neo4j instance)
- Use unittest.mock.AsyncMock for async method mocks
- Test CONSEQUENCE_QUERY is passed to execute_query correctly
- Test all 4 consequence severity mappings explicitly
- Test fallback behavior by simulating ServiceUnavailable exception
- Test fallback default for unknown zone class
- Verify warning log message contains "GRAPH_UNAVAILABLE"
- All tests must pass before story is marked done

## Dev Agent Record

### Implementation Plan
<!-- Dev agent fills this during implementation -->

### Debug Log
<!-- Dev agent logs issues here -->

### Completion Notes
<!-- Dev agent summarizes what was done -->

## File List
<!-- Dev agent tracks files here -->

## Change Log
<!-- Dev agent tracks changes here -->

## Status

ready-for-dev
