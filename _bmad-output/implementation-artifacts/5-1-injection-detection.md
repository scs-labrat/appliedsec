# Story 5.1: Create Injection Detection Engine

## Status: done

## Description
Regex-based injection detection and redaction for LLM input.

## Tasks
- [x] Create `context_gateway/injection_detector.py`
- [x] 14+ injection patterns: instruction override, role-change, DAN/jailbreak, system prompt extraction, developer mode
- [x] Markup detection: fenced code blocks pretending to be system/tool messages
- [x] `sanitise_input()` returns (sanitised_text, detections)
- [x] Clean input passes through unchanged
- [x] 22 tests covering all pattern categories
- [x] All tests pass

## Completion Notes
- Patterns are case-insensitive
- Detections list includes pattern description for audit logging
- `[REDACTED_INJECTION_ATTEMPT]` and `[REDACTED_MARKUP]` replacement tokens
