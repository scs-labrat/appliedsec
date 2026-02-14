# Story 3.2: Create Kafka Consumer for alerts.raw

## Status: done

## Description
Kafka consumer that reads from `alerts.raw` topic and feeds messages to the entity parsing engine.

## Tasks
- [x] Create `entity_parser/service.py` with `EntityParserService` class
- [x] Configure consumer with `aluskort.entity-parser` group, manual commits, earliest offset
- [x] Deserialize messages to CanonicalAlert for validation
- [x] Route malformed messages to `alerts.raw.dlq` with error details
- [x] Write tests for consumer construction, message processing, DLQ routing
- [x] All tests pass

## Completion Notes
- `EntityParserService` with start/stop/close lifecycle
- Manual offset commit only after successful production to `alerts.normalized`
- DLQ routing for deserialization failures
