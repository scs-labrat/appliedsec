# Story 5.7: Integration Tests with Mocked Anthropic API

## Status: done

## Tasks
- [x] Create `tests/test_context_gateway/test_integration.py`
- [x] Full pipeline: sanitise → redact → build prompt → call API → validate → deanonymise
- [x] Test PII redacted before API call (IP not in sent content)
- [x] Test PII deanonymised in response (placeholder → real value)
- [x] Test injection redacted before API call
- [x] Test unknown technique ID quarantined
- [x] Test JSON schema validation in pipeline
- [x] Test spend guard blocks over-budget calls
- [x] Test cost recorded after call
- [x] Test system prompt has cache_control and safety prefix
- [x] Test metrics in response
- [x] 13 integration tests pass

## Completion Notes
- All tests use mocked AluskortAnthropicClient (no real API calls)
- Full pipeline exercised end-to-end in each test
