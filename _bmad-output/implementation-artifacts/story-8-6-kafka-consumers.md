# Story 8.6 — Kafka Consumers

## Status: Done

## Implementation

### Files
- `ctem_normaliser/service.py` — CTEMNormaliserService with topic routing and DLQ

### Key Decisions
- 6 subscribed topics: ctem.raw.{wiz, snyk, garak, art, burp, custom}
- Topic → normaliser routing via TOPIC_NORMALISER_MAP
- Normalisation failure → ctem.normalized.dlq with error details
- Upsert failure → DLQ (separate from normalisation failure)
- Publishes normalised exposures to ctem.normalized
- Graceful when no Kafka producer configured

### Results
- **130/130 Epic 8 tests passed**
- **833/833 full suite passed** (zero regressions)

### Test Coverage
- `tests/test_ctem_normaliser/test_service.py` — 14 tests (routing, process, DLQ, multi-tool)
