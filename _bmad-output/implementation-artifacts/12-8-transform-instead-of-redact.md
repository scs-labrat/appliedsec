# Story 12.8: Transform Instead of Redact

Status: review

## Story

As a platform denying attackers a tuning oracle,
I want `[REDACTED_INJECTION_ATTEMPT]` markers replaced with lossy summarization that silently discards instruction-shaped content,
so that attackers cannot observe redaction markers and refine their injection payloads.

## Acceptance Criteria

1. **Given** any LLM input after processing, **When** scanned, **Then** no `[REDACTED_INJECTION_ATTEMPT]` or `[REDACTED_MARKUP]` markers appear in the output (no tuning oracle).
2. **Given** a `suspicious` alert field containing both entities and instruction-shaped content, **When** summarized, **Then** entities (IPs, hashes, domains) and factual claims are preserved while instruction-shaped content is discarded silently.
3. **Given** a `malicious` alert, **When** quarantined, **Then** no content from it is sent to the LLM (replaced with a neutral placeholder).
4. **Given** clean content (no injection), **When** processed, **Then** it passes through unchanged.

## Tasks / Subtasks

- [x] Task 1: Create entity extractor for lossy summarization (AC: 2)
  - [x] 1.1: Create `context_gateway/summarizer.py` with `extract_entities(text: str) -> list[str]` function. Uses regex to extract:
    - IPv4 addresses: `\b(?:\d{1,3}\.){3}\d{1,3}\b`
    - IPv6 addresses (simplified): `\b[0-9a-fA-F:]{7,}\b`
    - MD5 hashes: `\b[a-fA-F0-9]{32}\b`
    - SHA256 hashes: `\b[a-fA-F0-9]{64}\b`
    - Domain names: `\b[a-zA-Z0-9][-a-zA-Z0-9]*(?:\.[a-zA-Z0-9][-a-zA-Z0-9]*)*\.[a-zA-Z]{2,}\b`
    - Email addresses: reuse `_EMAIL_RE` from `pii_redactor.py`
  - [x] 1.2: Add unit tests in `tests/test_context_gateway/test_summarizer.py` — `TestExtractEntities` class: extracts IPs, hashes, domains, emails, handles empty text, handles text with no entities. (8 tests)
- [x] Task 2: Create fact extractor (AC: 2)
  - [x] 2.1: Add `extract_facts(text: str) -> list[str]` function to `context_gateway/summarizer.py`. Uses heuristic sentence splitting and filters:
    - Keep sentences containing extracted entities
    - Keep sentences with factual verbs ("connected", "accessed", "created", "deleted", "modified", "executed", "downloaded", "uploaded")
    - Discard sentences with instruction verbs ("ignore", "pretend", "override", "forget", "reveal", "act as")
  - [x] 2.2: Add unit tests — `TestExtractFacts` class: keeps factual sentences, discards instruction sentences, handles mixed content, preserves entity-containing sentences. (6 tests)
- [x] Task 3: Create instruction remover (AC: 1, 2)
  - [x] 3.1: Add `remove_instructions(text: str) -> str` function to `context_gateway/summarizer.py`. Removes:
    - Complete sentences matching injection patterns (reuse `INJECTION_PATTERNS` from `injection_detector.py`)
    - Sentences starting with imperative instruction verbs
    - Returns remaining text with instruction content silently removed (NO markers, NO `[REDACTED_*]` placeholders)
  - [x] 3.2: Add unit tests — `TestRemoveInstructions` class: removes instruction sentences, preserves factual sentences, no redaction markers in output, handles all 14+ injection patterns. (8 tests)
- [x] Task 4: Create lossy summarizer combining extractors (AC: 1, 2, 3, 4)
  - [x] 4.1: Add `summarize(text: str) -> str` function to `context_gateway/summarizer.py`. Pipeline:
    1. Extract entities
    2. Extract facts
    3. Remove instructions from remaining text
    4. Combine: unique entities + factual claims
    5. If nothing remains, return `"No actionable content detected."`
  - [x] 4.2: Add `transform_content(text: str, action: str) -> str` function:
    - `action == "pass"` → return text unchanged
    - `action == "summarize"` → return `summarize(text)`
    - `action == "quarantine"` → return `"Content quarantined for security review."`
  - [x] 4.3: Verify NO `[REDACTED_INJECTION_ATTEMPT]` or `[REDACTED_MARKUP]` markers appear in any output path.
  - [x] 4.4: Add unit tests — `TestSummarize` class: preserves entities, preserves facts, discards instructions, no markers. `TestTransformContent` class: pass returns unchanged, summarize runs pipeline, quarantine returns neutral placeholder, no redaction markers in any output. (11 tests)
- [x] Task 5: Run full regression (AC: 1-4)
  - [x] 5.1: Run full project test suite (`pytest tests/`) — 1369 tests pass (zero regressions, 33 new)
  - [x] 5.2: Verify existing `sanitise_input()` and `REDACTED_INJECTION` constant still exist unchanged (21/21 injection detector tests + 15/15 PII redactor tests pass)

## Dev Notes

### Critical Architecture Constraints

- **This is Part C of REM-C03.** Depends on Story 12.7 (classifier provides `action` input). Can be developed in parallel since `transform_content()` takes `action: str` parameter.
- **DO NOT modify `injection_detector.py`** — the existing `sanitise_input()` with `[REDACTED_*]` markers still runs. This story creates the replacement mechanism. The gateway pipeline swap (using `transform_content` instead of `sanitise_input`) is a follow-up integration step.
- **DO NOT modify `pii_redactor.py`** — PII redaction is a separate concern from injection handling. PII placeholders (`IP_SRC_001`, `USER_001`) are legitimate and should NOT be replaced by this story.
- **Silent discard is the design goal** — attackers should see consistent, informative-looking output regardless of whether their injection was detected. No `[REDACTED_*]` markers, no error messages, just clean factual content.
- **Lossy is intentional** — the summarizer deliberately loses instruction-shaped content. This is a feature, not a bug.

### Existing Code You MUST Reuse (DO NOT Reinvent)

| Component | File | What It Does |
|---|---|---|
| `INJECTION_PATTERNS` | `context_gateway/injection_detector.py:19-39` | 14+ patterns. **Import for instruction detection in `remove_instructions()`.** |
| `_EMAIL_RE` | `context_gateway/pii_redactor.py:15-16` | Email regex. **Import for entity extraction.** |
| `_IP_RE` | `context_gateway/pii_redactor.py:14` | IP regex. **Import for entity extraction.** |
| `REDACTED_INJECTION` | `context_gateway/injection_detector.py:13` | Marker constant. **Verify it does NOT appear in summarizer output.** |
| `REDACTED_MARKUP` | `context_gateway/injection_detector.py:14` | Marker constant. **Verify it does NOT appear in summarizer output.** |

### Exact File Paths (Verified Against Codebase)

| Target | Correct Path |
|---|---|
| Injection detector | `context_gateway/injection_detector.py` |
| PII redactor | `context_gateway/pii_redactor.py` |
| Summarizer (NEW) | `context_gateway/summarizer.py` |
| Summarizer tests (NEW) | `tests/test_context_gateway/test_summarizer.py` |

### Summarizer Pipeline

```
Input Text (may contain injection + legitimate data)
    │
    ├─ extract_entities() → [IPs, hashes, domains, emails]
    ├─ extract_facts() → [factual sentences with entities/verbs]
    ├─ remove_instructions() → text with instructions silently removed
    │
    ▼
Lossy Summary: entities + facts (no instruction content, no markers)
```

### transform_content() Action Mapping

```
InjectionAction.PASS       → return text unchanged
InjectionAction.SUMMARIZE  → return summarize(text)
InjectionAction.QUARANTINE → return "Content quarantined for security review."
```

### Existing Test Classes That MUST Still Pass (Unchanged)

**test_injection_detector.py (21 tests):**
- All 21 tests unchanged

**test_pii_redactor.py (15 tests):**
- All 15 tests unchanged

**Total existing: 1169 tests — ALL must pass unchanged.**

### Testing Patterns

- Test framework: **pytest**
- Entity extraction tests: craft text with known entities, verify extraction
- Fact extraction tests: mix factual and instruction sentences, verify filtering
- Instruction removal tests: use all 14+ injection patterns, verify silent removal
- Summarizer integration tests: end-to-end with mixed content
- Marker absence tests: scan output for `[REDACTED_` substrings, assert absent

### References

- [Source: docs/remediation-backlog.md#REM-C03 Part C] — Transform instead of redact requirements
- [Source: docs/ai-system-design.md Section 7.4] — Current `[REDACTED_INJECTION_ATTEMPT]` marker
- [Source: docs/prd.md#NFR-SEC-002] — Injection detection requirement

## Dev Agent Record

### Agent Model Used

Claude Opus 4.6 (claude-opus-4-6)

### Debug Log References

### Completion Notes List

- `extract_entities()` extracts IPv4, IPv6, MD5, SHA256, domains, emails using regex; SHA256 extracted before MD5 to avoid partial matches
- Domain regex enhanced to support multi-level subdomains (e.g., `evil.example.com`)
- Sentence splitter uses `(?<=[.!?])\s+` boundary regex to avoid splitting on dots inside IP addresses and domain names
- `extract_facts()` keeps sentences with factual verbs or entities, discards instruction-verb sentences and injection-pattern matches
- `remove_instructions()` silently removes injection-matching and instruction-verb sentences — no `[REDACTED_*]` markers
- `summarize()` pipeline: entities + facts + cleaned text, deduplicated; returns "No actionable content detected." when nothing survives
- `transform_content()` dispatches by action string: pass/summarize/quarantine
- Imports `INJECTION_PATTERNS` from `injection_detector.py` and `_EMAIL_RE` from `pii_redactor.py` — neither file modified
- All 6 marker-absence tests verify `[REDACTED_` never appears in any output path
- 33 new tests, 1369 total passing

### File List

**Created:**
- `context_gateway/summarizer.py` — extract_entities, extract_facts, remove_instructions, summarize, transform_content
- `tests/test_context_gateway/test_summarizer.py` — 33 summarizer unit tests (5 test classes)

**Modified:**
- None (all existing files unchanged)

### Change Log

- 2026-02-21: Story 12.8 implemented — Lossy summarizer with entity/fact extraction, instruction removal, and transform_content action dispatcher. 33 new tests, 1369 total passing.
