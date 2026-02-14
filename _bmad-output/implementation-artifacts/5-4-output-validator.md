# Story 5.4: Create Output Validator

## Status: done

## Tasks
- [x] Create `context_gateway/output_validator.py`
- [x] Technique ID validation against `taxonomy_ids` set (ATT&CK T-codes + ATLAS AML codes)
- [x] JSON schema validation (required fields, type checks)
- [x] Quarantine list for unknown/hallucinated technique IDs
- [x] `validate_output()` returns (valid, errors, quarantined_ids)
- [x] 14 tests pass

## Completion Notes
- Lightweight schema validator (no external dependency; supports required fields + type checks)
- Technique regex: `T\d{4}(\.\d{3})?` and `AML\.T\d{4}`
