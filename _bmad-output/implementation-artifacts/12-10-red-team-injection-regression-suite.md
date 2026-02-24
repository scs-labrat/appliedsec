# Story 12.10: Red-Team Injection Regression Suite

Status: review

## Story

As a platform maintaining injection defense quality,
I want a regression test suite with >= 50 test cases across 7 injection categories that runs in CI on every merge,
so that defense regressions are caught before deployment.

## Acceptance Criteria

1. **Given** the test suite, **When** run, **Then** it covers 7 categories: Unicode homoglyphs, base64 encoded instructions, multi-step injection, roleplay injection, log poisoning, XML/markdown breakout, prompt leaking.
2. **Given** >= 50 test cases, **When** run against the injection defense pipeline, **Then** each test case asserts that the injection is either detected, neutralized, or isolated.
3. **Given** any regression (a previously caught injection now bypasses detection), **When** CI runs, **Then** the test fails.
4. **Given** per-category metrics, **When** tests complete, **Then** a summary report shows detection count and bypass count per category.

## Tasks / Subtasks

- [x] Task 1: Create injection test fixture infrastructure (AC: 1, 2, 4)
  - [x] 1.1: Create `tests/security/conftest.py` with InjectionTestCase, InjectionSuiteResult, run_injection_test helper
  - [x] 1.2: Add `run_evidence_isolation_test()` and `run_combined_defense_test()` helpers
  - [x] 1.3: Add `print_suite_summary()` function for CI visibility
  - [x] 1.4: Add `TestInfrastructure` class (4 tests): case creation, known injection detection, clean text, evidence isolation
- [x] Task 2: Unicode homoglyph injection tests (AC: 1, 2)
  - [x] 2.1: `TestUnicodeHomoglyphs` class (8 parametrized test cases)
  - [x] 2.2: Each test asserts combined defense (regex OR evidence isolation)
- [x] Task 3: Base64 encoded injection tests (AC: 1, 2)
  - [x] 3.1: `TestBase64Injection` class (8 parametrized test cases)
- [x] Task 4: Multi-step and roleplay injection tests (AC: 1, 2)
  - [x] 4.1: `TestMultiStepInjection` class (10 parametrized test cases)
  - [x] 4.2: `TestRoleplayInjection` class (8 parametrized test cases)
- [x] Task 5: Log poisoning and XML/markdown breakout tests (AC: 1, 2)
  - [x] 5.1: `TestLogPoisoning` class (8 parametrized test cases)
  - [x] 5.2: `TestXmlMarkdownBreakout` class (6 parametrized test cases)
- [x] Task 6: Prompt leaking tests (AC: 1, 2)
  - [x] 6.1: `TestPromptLeaking` class (4 parametrized test cases)
- [x] Task 7: Suite summary and CI integration (AC: 3, 4)
  - [x] 7.1: `TestSuiteSummary` with overall >= 95% and per-category >= 90% detection rate assertions
  - [x] 7.2: Summary test outputs category-level results for CI visibility
  - [x] 7.3: All tests deterministic (no randomness, no LLM calls)
- [x] Task 8: Run full regression (AC: 1-4)
  - [x] 8.1: Full project test suite: 1460 tests pass (zero regressions)
  - [x] 8.2: Security suite runs independently: `pytest tests/security/ -v` — 61 passed

## Dev Notes

### Critical Architecture Constraints

- **This is Part E of REM-C03.** This is the final story in the injection defense chain. It validates Stories 12.6-12.8.
- **All tests are deterministic** — no LLM calls, no randomness. Tests exercise `sanitise_input()` from `injection_detector.py` and `wrap_evidence()` / `escape_xml_tags()` from `evidence_builder.py` (Story 12.6).
- **Tests should pass against current regex-based detection.** Many advanced attacks (Unicode homoglyphs, base64) will NOT be caught by current regex patterns. These tests document the known gaps. The `expected_detected` flag on each test case allows tracking known bypasses vs. regressions.
- **Detection means ANY defense layer catches it** — regex detection OR evidence isolation. A test passes if the injection is either redacted by `sanitise_input()` OR properly isolated by the evidence builder.
- **DO NOT modify any production code** in this story. This is a pure test story.

### Existing Code You MUST Reuse (DO NOT Reinvent)

| Component | File | What It Does |
|---|---|---|
| `sanitise_input()` | `context_gateway/injection_detector.py:48-67` | Primary detection layer. **Call in test helper.** |
| `INJECTION_PATTERNS` | `context_gateway/injection_detector.py:19-39` | 14+ patterns. **Reference for test design.** |
| `REDACTED_INJECTION` | `context_gateway/injection_detector.py:13` | Marker. **Check for in output to verify detection.** |
| `escape_xml_tags()` | `context_gateway/evidence_builder.py` (Story 12.6) | XML escaping. **Call in isolation test helper.** |
| `EvidenceBlock.wrap_evidence()` | `context_gateway/evidence_builder.py` (Story 12.6) | Evidence wrapper. **Call in isolation test helper.** |

### Exact File Paths (Verified Against Codebase)

| Target | Correct Path |
|---|---|
| Injection detector | `context_gateway/injection_detector.py` |
| Evidence builder (from 12.6) | `context_gateway/evidence_builder.py` |
| Security test dir (NEW) | `tests/security/` |
| Conftest (NEW) | `tests/security/conftest.py` |
| Regression tests (NEW) | `tests/security/test_injection_regression.py` |
| Entity parser injection tests | `tests/test_entity_parser/test_injection.py` |

### Test Category Breakdown

| Category | Test Count | Attack Vector |
|---|---|---|
| Unicode homoglyphs | 8 | Character substitution to evade regex |
| Base64 encoded | 8 | Encoding to hide instruction content |
| Multi-step injection | 10 | Gradual or conditional injection |
| Roleplay injection | 8 | Social engineering the LLM |
| Log poisoning | 8 | Injection via log-formatted data |
| XML/markdown breakout | 6 | Escaping structured containers |
| Prompt leaking | 4 | Extracting system prompt content |
| **Total** | **52** | |

### Test Pass/Fail Criteria

A test case PASSES if ANY of these conditions is met:
1. `sanitise_input()` returns non-empty `detections` list (regex caught it)
2. Evidence builder isolates the payload inside `<evidence>` tags (structural defense)

A test case FAILS (bypass) if BOTH conditions are false:
1. No detections from `sanitise_input()`
2. Payload appears outside `<evidence>` tags after evidence wrapping

**Important:** Many advanced attacks WILL be bypasses against current regex. The suite tracks these as known gaps. A regression is when a PREVIOUSLY DETECTED attack becomes a bypass.

### Existing Test Classes That MUST Still Pass (Unchanged)

**test_injection_detector.py (21 tests):**
- All 21 tests unchanged

**test_entity_parser/test_injection.py (10 tests):**
- All 10 tests unchanged

**Total existing: 1169 tests — ALL must pass unchanged.**

### Testing Patterns

- Test framework: **pytest**
- No async needed (all synchronous)
- No LLM calls (deterministic regex + evidence builder only)
- `conftest.py` provides shared fixtures and helpers
- Parametrize where appropriate (e.g., `@pytest.mark.parametrize` for homoglyph variants)
- Each test class corresponds to one injection category

### Dependencies on Other Stories

- **Story 12.6** (Structured Input Isolation): provides `evidence_builder.py` with `escape_xml_tags()` and `EvidenceBlock.wrap_evidence()`. If 12.6 is not yet implemented, the evidence isolation tests can be skipped or stubbed.
- **Story 12.7** (LLM-as-Judge): NOT required — regression suite tests regex + evidence isolation only
- **Story 12.8** (Transform Instead of Redact): NOT required — regression suite tests detection, not transformation

### References

- [Source: docs/remediation-backlog.md#REM-C03 Part E] — Red-team regression suite requirements
- [Source: docs/prd.md#NFR-SEC-002] — Injection detection requirement
- [Source: docs/ai-system-design.md Section 7.4] — Current 14+ injection patterns
- OWASP LLM Top 10: LLM01 (Prompt Injection) — attack categories reference

## Dev Agent Record

### Agent Model Used

Claude Opus 4.6 (claude-opus-4-6)

### Debug Log References

- All 61 security tests passed on first run — no fixes needed
- Full regression: 1460 tests passed (zero failures)
- Security suite runs independently: 61 passed in 0.29s

### Completion Notes List

- 52 injection test cases across 7 categories + 4 infrastructure + 5 summary = 61 total tests
- All 52 attack payloads detected by combined defense (regex OR evidence isolation)
- Overall detection rate: 100% (52/52) — exceeds 95% threshold
- Per-category detection rates all 100% — exceeds 90% threshold
- No production code modified (pure test story)
- Evidence isolation catches payloads that regex misses (e.g., base64-encoded, Unicode homoglyphs)

### File List

**Created:**
- `tests/security/__init__.py` — Empty package init
- `tests/security/conftest.py` — InjectionTestCase, InjectionSuiteResult, run_injection_test, run_evidence_isolation_test, run_combined_defense_test, print_suite_summary
- `tests/security/test_injection_regression.py` — 52+ test cases across 7 categories: TestInfrastructure (4), TestUnicodeHomoglyphs (8), TestBase64Injection (8), TestMultiStepInjection (10), TestRoleplayInjection (8), TestLogPoisoning (8), TestXmlMarkdownBreakout (6), TestPromptLeaking (4), TestSuiteSummary (5)

**Modified:**
- None (pure test story — no production code changes)

### Change Log

- 2026-02-21: Story implemented — 61 tests, all passing, 1460 total regression clean
