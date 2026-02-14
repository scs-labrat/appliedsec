---
story_id: "1.2"
story_key: "1-2-postgres-client-wrapper"
title: "Create Postgres Client Wrapper"
epic: "Epic 1: Foundation"
status: "done"
priority: "high"
---

# Story 1.2: Create Postgres Client Wrapper

## Story

As a developer building ALUSKORT services,
I want an async PostgreSQL client wrapper using asyncpg with connection pooling, parameterised queries, and transaction support,
so that all services interact with PostgreSQL through a consistent, secure, and performant interface.

## Acceptance Criteria

### AC-1.2.1: Connection Pool Initialization
**Given** valid PostgreSQL connection parameters (host, port, database, user, password)
**When** PostgresClient.connect() is called
**Then** an asyncpg connection pool is created with configurable min_size (default 5) and max_size (default 20)

### AC-1.2.2: Parameterised Query Execution
**Given** an active PostgresClient with a connected pool
**When** execute() is called with a SQL string and positional parameters ($1, $2, ...)
**Then** the query is executed with the parameters safely bound (no string interpolation) and the status string is returned

### AC-1.2.3: Fetch One Row
**Given** an active PostgresClient
**When** fetch_one() is called with a SELECT query matching exactly one row
**Then** the row is returned as a dict (column_name -> value)

### AC-1.2.4: Fetch Many Rows
**Given** an active PostgresClient
**When** fetch_many() is called with a SELECT query matching multiple rows
**Then** all matching rows are returned as a list of dicts

### AC-1.2.5: Transaction Context Manager
**Given** an active PostgresClient
**When** a block of queries is executed inside the transaction() async context manager
**Then** all queries within the block share the same transaction, which commits on success and rolls back on exception

### AC-1.2.6: Connection Timeout
**Given** a PostgresClient configured with a statement timeout of 30 seconds
**When** a query exceeds 30 seconds
**Then** the query is cancelled and a TimeoutError (or asyncpg equivalent) is raised

### AC-1.2.7: Graceful Shutdown
**Given** an active PostgresClient with an open pool
**When** close() is called
**Then** all pool connections are gracefully closed and the pool is terminated

### AC-1.2.8: Health Check
**Given** an active PostgresClient
**When** health_check() is called
**Then** it executes SELECT 1 and returns True if successful, False otherwise

## Tasks/Subtasks

- [ ] Task 1: Create shared/db/ directory structure
  - [ ] Subtask 1.1: Create shared/db/__init__.py
  - [ ] Subtask 1.2: Create shared/db/postgres.py
- [ ] Task 2: Implement PostgresClient class
  - [ ] Subtask 2.1: Define PostgresClient with __init__ accepting dsn or individual params (host, port, database, user, password)
  - [ ] Subtask 2.2: Accept pool config: min_size (default 5), max_size (default 20), statement_timeout (default 30s)
  - [ ] Subtask 2.3: Implement connect() method that creates asyncpg.create_pool()
  - [ ] Subtask 2.4: Implement close() method that calls pool.close()
- [ ] Task 3: Implement query methods
  - [ ] Subtask 3.1: Implement execute(query: str, *args) -> str that runs pool.execute() with positional params
  - [ ] Subtask 3.2: Implement fetch_one(query: str, *args) -> Optional[dict] that runs pool.fetchrow() and converts Record to dict
  - [ ] Subtask 3.3: Implement fetch_many(query: str, *args) -> list[dict] that runs pool.fetch() and converts Records to dicts
- [ ] Task 4: Implement transaction context manager
  - [ ] Subtask 4.1: Implement transaction() as an async context manager using pool.acquire() + connection.transaction()
  - [ ] Subtask 4.2: Yield a TransactionProxy object that exposes execute(), fetch_one(), fetch_many() bound to the transaction connection
  - [ ] Subtask 4.3: Ensure rollback on exception, commit on clean exit
- [ ] Task 5: Implement health check
  - [ ] Subtask 5.1: Implement health_check() -> bool that executes SELECT 1 and returns True/False
  - [ ] Subtask 5.2: Catch all exceptions in health_check and return False instead of propagating
- [ ] Task 6: Implement connection lifecycle hooks
  - [ ] Subtask 6.1: Add async context manager support (__aenter__ / __aexit__) for use with "async with PostgresClient(...) as db:"
  - [ ] Subtask 6.2: Add logging for pool creation, connection acquisition, and errors
- [ ] Task 7: Write unit tests
  - [ ] Subtask 7.1: Create tests/test_db/test_postgres.py
  - [ ] Subtask 7.2: Mock asyncpg.create_pool and test connect() creates pool with correct params
  - [ ] Subtask 7.3: Mock pool.execute and test execute() passes params correctly
  - [ ] Subtask 7.4: Mock pool.fetchrow and test fetch_one() returns dict or None
  - [ ] Subtask 7.5: Mock pool.fetch and test fetch_many() returns list of dicts
  - [ ] Subtask 7.6: Test transaction() context manager commits on success
  - [ ] Subtask 7.7: Test transaction() context manager rolls back on exception
  - [ ] Subtask 7.8: Test health_check() returns True on success, False on exception
  - [ ] Subtask 7.9: Test close() terminates pool

## Dev Notes

### Architecture Requirements
- Use asyncpg >= 0.29.0 as the PostgreSQL driver (async, binary protocol, high performance)
- All queries MUST use parameterised placeholders ($1, $2, ...) -- never string formatting or f-strings
- Connection pool defaults: min_size=5, max_size=20
- Statement timeout: 30 seconds (configurable via constructor parameter)
- PostgreSQL version target: 16+
- The client is used by: orchestrator, ctem_normaliser, context_gateway, batch_scheduler services
- Storage: incidents, alerts, exposures, UEBA snapshots, playbook metadata, investigation state, taxonomy store, query logs, remediation records
- Tables are partitioned by tenant_id + time (the client does not manage partitioning, but queries must include tenant_id)
- See docs/ai-system-design.md Section 5.1 and docs/architecture.md Section 2

### Technical Specifications
- Class: PostgresClient in shared/db/postgres.py
- Constructor params: dsn (Optional[str]), host (str, default "localhost"), port (int, default 5432), database (str, default "aluskort"), user (str, default "aluskort"), password (str, default ""), min_size (int, default 5), max_size (int, default 20), statement_timeout (int, default 30)
- Methods: connect(), close(), execute(query, *args), fetch_one(query, *args), fetch_many(query, *args), transaction(), health_check()
- asyncpg Records must be converted to dicts using dict(record) for return values
- The pool should be stored as self._pool: Optional[asyncpg.Pool]
- All public methods must raise RuntimeError if called before connect()
- Logging: use standard Python logging (logging.getLogger(__name__))

### Testing Strategy
- pytest with pytest-asyncio
- Mock asyncpg.create_pool (do not require a live database)
- Use unittest.mock.AsyncMock for async method mocks
- Test all public methods: connect, close, execute, fetch_one, fetch_many, transaction, health_check
- Test error paths: pool not connected, query timeout, transaction rollback
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

done
