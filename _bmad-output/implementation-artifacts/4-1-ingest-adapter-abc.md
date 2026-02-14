# Story 4.1: Create SentinelAdapter Implementing IngestAdapter ABC

## Status: done

## Description
IngestAdapter abstract base class and SentinelAdapter implementing source_name(), subscribe(), and to_canonical().

## Tasks
- [x] Create `shared/adapters/ingest.py` with IngestAdapter ABC (source_name, subscribe, to_canonical)
- [x] Create `sentinel_adapter/adapter.py` with SentinelAdapter
- [x] `source_name()` returns "sentinel"
- [x] `to_canonical()` returns None for heartbeat/test/health-check events (case-insensitive)
- [x] `subscribe()` delegates to connector classes
- [x] Write tests for ABC conformance and heartbeat handling
- [x] All tests pass

## Completion Notes
- IngestAdapter ABC defines the standard interface for all SIEM adapters
- SentinelAdapter drops heartbeat events before they reach the pipeline
- Heartbeat names: "heartbeat", "test alert", "health check" (case-insensitive)
