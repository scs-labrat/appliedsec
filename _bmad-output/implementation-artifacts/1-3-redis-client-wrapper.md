---
story_id: "1.3"
story_key: "1-3-redis-client-wrapper"
title: "Create Redis Client Wrapper"
epic: "Epic 1: Foundation"
status: "done"
priority: "high"
---

# Story 1.3: Create Redis Client Wrapper

## Story

As a developer building ALUSKORT services,
I want an async Redis client wrapper with IOC-specific methods, confidence-based TTL tiers, false positive pattern caching, and fail-open behavior,
so that all services interact with the IOC cache and FP pattern store through a consistent, resilient interface.

## Acceptance Criteria

### AC-1.3.1: Connection Pool Initialization
**Given** valid Redis connection parameters (host, port, db, password)
**When** RedisClient.connect() is called
**Then** a redis-py async connection pool is created and a ping succeeds

### AC-1.3.2: IOC Set with Confidence-Based TTL
**Given** an active RedisClient
**When** set_ioc(ioc_type="ip", value="1.2.3.4", data={"family": "emotet"}, confidence=85) is called
**Then** the key "ioc:ip:1.2.3.4" is set in Redis with the JSON-serialised data and a TTL of 30 days (confidence > 80)

### AC-1.3.3: IOC TTL Tier - Medium Confidence
**Given** an active RedisClient
**When** set_ioc() is called with confidence=65
**Then** the TTL is set to 7 days (confidence 50-80)

### AC-1.3.4: IOC TTL Tier - Low Confidence
**Given** an active RedisClient
**When** set_ioc() is called with confidence=30
**Then** the TTL is set to 24 hours (confidence < 50)

### AC-1.3.5: IOC Get Returns Cached Data
**Given** an active RedisClient with a cached IOC entry for "ioc:hash:abc123"
**When** get_ioc(ioc_type="hash", value="abc123") is called
**Then** the cached data dict is returned

### AC-1.3.6: IOC Get Returns None on Cache Miss
**Given** an active RedisClient with no cached entry for the requested IOC
**When** get_ioc() is called
**Then** None is returned (not an error)

### AC-1.3.7: Fail-Open on Connection Error
**Given** a RedisClient where the Redis server is unreachable
**When** get_ioc() or get_fp_pattern() is called
**Then** None is returned (fail-open) and a warning is logged, rather than raising an exception

### AC-1.3.8: FP Pattern Cache
**Given** an active RedisClient
**When** set_fp_pattern(pattern_id="fp-001", pattern_data={"regex": "...", "confidence": 0.95}) is called
**Then** the key "fp:fp-001" is set in Redis with the serialised pattern data

### AC-1.3.9: FP Pattern Retrieval
**Given** an active RedisClient with a cached FP pattern
**When** get_fp_pattern(pattern_id="fp-001") is called
**Then** the pattern data dict is returned

## Tasks/Subtasks

- [ ] Task 1: Create RedisClient class
  - [ ] Subtask 1.1: Create shared/db/redis_cache.py
  - [ ] Subtask 1.2: Define RedisClient with __init__ accepting host, port, db, password, decode_responses flag
  - [ ] Subtask 1.3: Implement connect() method using redis.asyncio.from_url() or Redis() with connection pool
  - [ ] Subtask 1.4: Implement close() method that calls aclose() on the client
- [ ] Task 2: Implement IOC cache methods
  - [ ] Subtask 2.1: Implement _compute_ttl(confidence: float) -> int returning seconds based on tier: >80 -> 2592000 (30d), 50-80 -> 604800 (7d), <50 -> 86400 (24h)
  - [ ] Subtask 2.2: Implement set_ioc(ioc_type: str, value: str, data: dict, confidence: float) using key pattern "ioc:{type}:{value}" with JSON serialisation and computed TTL
  - [ ] Subtask 2.3: Implement get_ioc(ioc_type: str, value: str) -> Optional[dict] that deserialises JSON from Redis
- [ ] Task 3: Implement FP pattern cache methods
  - [ ] Subtask 3.1: Implement set_fp_pattern(pattern_id: str, pattern_data: dict, ttl: int = 86400) using key pattern "fp:{pattern_id}"
  - [ ] Subtask 3.2: Implement get_fp_pattern(pattern_id: str) -> Optional[dict] that deserialises JSON
  - [ ] Subtask 3.3: Implement list_fp_patterns() -> list[str] using SCAN with pattern "fp:*"
- [ ] Task 4: Implement fail-open behavior
  - [ ] Subtask 4.1: Wrap all get_* methods in try/except catching redis.ConnectionError, redis.TimeoutError, and general Exception
  - [ ] Subtask 4.2: On connection failure, log a warning with the error details and return None
  - [ ] Subtask 4.3: On set_* failure, log a warning but do not raise (cache is not critical path)
- [ ] Task 5: Implement health check and utilities
  - [ ] Subtask 5.1: Implement health_check() -> bool that calls ping() and returns True/False
  - [ ] Subtask 5.2: Implement delete_ioc(ioc_type: str, value: str) -> bool for cache invalidation
  - [ ] Subtask 5.3: Add async context manager support (__aenter__ / __aexit__)
- [ ] Task 6: Write unit tests
  - [ ] Subtask 6.1: Create tests/test_db/test_redis_cache.py
  - [ ] Subtask 6.2: Mock redis.asyncio.Redis and test connect() succeeds
  - [ ] Subtask 6.3: Test set_ioc with confidence=85 sets TTL to 2592000s (30 days)
  - [ ] Subtask 6.4: Test set_ioc with confidence=65 sets TTL to 604800s (7 days)
  - [ ] Subtask 6.5: Test set_ioc with confidence=30 sets TTL to 86400s (24 hours)
  - [ ] Subtask 6.6: Test get_ioc returns deserialised dict on cache hit
  - [ ] Subtask 6.7: Test get_ioc returns None on cache miss
  - [ ] Subtask 6.8: Test get_ioc returns None and logs warning on ConnectionError (fail-open)
  - [ ] Subtask 6.9: Test set_fp_pattern and get_fp_pattern round-trip
  - [ ] Subtask 6.10: Test health_check returns True on ping success, False on failure

## Dev Notes

### Architecture Requirements
- Use redis[hiredis] >= 5.0.0 with async support (redis.asyncio)
- Key patterns: "ioc:{type}:{value}" for IOC cache, "fp:{pattern_id}" for FP patterns
- TTL tiers based on confidence score:
  - confidence > 80: 30 days (2,592,000 seconds)
  - confidence 50-80: 7 days (604,800 seconds)
  - confidence < 50: 24 hours (86,400 seconds)
- Fail-open behavior is CRITICAL: Redis is a cache layer, not the source of truth. If Redis is down, the system must continue to operate by falling back to Postgres IOC lookup (handled by callers). The RedisClient must never raise connection exceptions to callers.
- Redis is used by: orchestrator (IOC lookup during investigation), entity_parser (short-circuit FP check at ~1ms)
- See docs/ai-system-design.md Section 5.1 for storage allocation
- See docs/ai-system-design.md Section 11.1: "Redis down -> Fall back to Postgres IOC lookup"

### Technical Specifications
- Class: RedisClient in shared/db/redis_cache.py
- Constructor params: host (str, default "localhost"), port (int, default 6379), db (int, default 0), password (Optional[str], default None), socket_timeout (float, default 5.0), socket_connect_timeout (float, default 5.0)
- IOC data is stored as JSON strings via json.dumps/json.loads
- FP pattern data is stored as JSON strings
- Key format for IOCs: "ioc:{ioc_type}:{value}" e.g. "ioc:ip:192.168.1.1", "ioc:hash:a1b2c3", "ioc:domain:evil.com"
- Key format for FP patterns: "fp:{pattern_id}" e.g. "fp:fp-001"
- All public methods must be async
- Logging: use standard Python logging (logging.getLogger(__name__))

### Testing Strategy
- pytest with pytest-asyncio
- Mock redis.asyncio.Redis (do not require a live Redis instance)
- Use unittest.mock.AsyncMock for async method mocks
- Test all TTL tiers explicitly with confidence boundary values (49, 50, 80, 81)
- Test fail-open by making mock raise redis.ConnectionError
- Test JSON serialisation/deserialisation round-trip
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
