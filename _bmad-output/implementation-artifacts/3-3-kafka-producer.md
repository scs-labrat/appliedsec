# Story 3.3: Create Kafka Producer for alerts.normalized

## Status: done

## Description
Kafka producer that publishes parsed alerts (CanonicalAlert + AlertEntities) to `alerts.normalized`.

## Tasks
- [x] Produce to `alerts.normalized` with `alert_id` as message key
- [x] Include full `parsed_entities` dict in output (all entity lists + raw_iocs + parse_errors)
- [x] Flush producer after each message for reliability
- [x] Do NOT commit offset on producer failure (allow reprocessing)
- [x] `_entity_to_dict()` serializer for NormalizedEntity → JSON
- [x] Write tests for serialization, output format, alert_id preservation
- [x] All tests pass

## Completion Notes
- Producer integrated into `EntityParserService.run()` loop
- Offset committed only after successful produce + flush
- Producer failure logged without offset commit for retry
