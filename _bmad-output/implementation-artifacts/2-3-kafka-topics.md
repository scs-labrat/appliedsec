# Story 2.3: Create Kafka Topic Provisioning Script

## Status: done

## Description
Script that creates all Kafka topics with correct partition counts and retention settings.

## Tasks
- [x] Create `infra/scripts/create_kafka_topics.py` with all topic definitions
- [x] Define CORE_TOPICS: alerts.raw, alerts.normalized, incidents.enriched, 4 priority queues, actions.pending, audit.events
- [x] Define CTEM_TOPICS: 8 raw sources (wiz, snyk, garak, art, burp, custom, validation, remediation) + ctem.normalized
- [x] Define DLQ_TOPICS: alerts.raw.dlq, 4 priority DLQs, ctem.normalized.dlq
- [x] Define KNOWLEDGE_TOPICS: 6 knowledge event topics
- [x] Configure retention: audit.events 90 days, CTEM 30 days
- [x] Configure partitions: critical=4, high=3, normal=3, low=2
- [x] Write tests in `tests/test_infra/test_kafka_topics.py`
- [x] All 16 tests pass

## Completion Notes
- Script is both CLI-runnable (`python -m infra.scripts.create_kafka_topics`) and importable
- `get_all_topic_definitions()` function for programmatic access
- 16/16 tests pass
