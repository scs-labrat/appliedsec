# Story 5.2: Create PII Redaction with Reversible Mapping

## Status: done

## Tasks
- [x] Create `context_gateway/pii_redactor.py`
- [x] RedactionMap with bidirectional forward/reverse mapping
- [x] `redact_pii()` — IPs→IP_SRC_001, emails→USER_001, explicit extra_values
- [x] `deanonymise_text()` — restores original values from RedactionMap
- [x] Consistent placeholder assignment within investigation (same entity → same placeholder)
- [x] 15 tests pass

## Completion Notes
- Longest-first replacement in deanonymise to avoid partial matches
- RedactionMap is reusable across calls for consistency
