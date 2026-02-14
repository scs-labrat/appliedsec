# Story 4.2: Create Event Hub / Log Analytics API Connector

## Status: done

## Description
Two connector classes for Sentinel alert ingestion with exponential backoff retry.

## Tasks
- [x] Create `sentinel_adapter/connector.py`
- [x] `SentinelEventHubConnector` — near-real-time via Azure Event Hubs SDK (lazy import)
- [x] `SentinelLogAnalyticsConnector` — polling via REST API (30s default interval)
- [x] `retry_with_backoff()` — exponential backoff (1s→2s→4s, 3 retries)
- [x] `_canonical_to_bytes()` — shared serialization helper
- [x] Both connectors produce to `alerts.raw` Kafka topic
- [x] Write tests for retry logic, serialization, connector construction, lifecycle
- [x] All 13 tests pass

## Completion Notes
- Azure SDK imports are lazy (only when subscribe() is called)
- Log Analytics connector tracks `_last_poll_ts` for incremental polling
- Both connectors flush producer and support stop/close lifecycle
