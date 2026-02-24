# Story 15.4: PII Redaction Completeness

Status: review

## Story

As a privacy-conscious platform,
I want PII detection extended to cover usernames in hostnames (`JSMITH-LAPTOP`), file paths (`/home/jsmith/`), and chat handles, with a secure redaction map for audit re-identification,
so that PII does not leak to LLMs through overlooked data patterns.

## Acceptance Criteria

1. **Given** a hostname containing a username, **When** redacted, **Then** it is pseudonymized to `HOST_001`.
2. **Given** a file path containing a username, **When** redacted, **Then** the username path segment is pseudonymized.
3. **Given** the redaction map, **When** stored, **Then** it is encrypted and accessible only for audit re-identification.
4. **Given** a full alert with multiple PII types, **When** integration test runs, **Then** all PII categories are correctly redacted.

## Tasks / Subtasks

- [x] Task 1: Add hostname-with-username detection (AC: 1)
  - [x] 1.1: Added `_USERNAME_IN_HOSTNAME_RE` pattern (`\b[A-Za-z][A-Za-z0-9]{1,19}[-_][A-Za-z]{2,15}(?:\d{1,3})?\b`).
  - [x] 1.2: Plugged into `redact_pii()` after email detection. `_HOSTNAME_RE` kept as-is (broader pattern, not used for PII).
  - [x] 1.3: Matches redacted as `HOST_001`, `HOST_002`, etc.
  - [x] 1.4: Added `TestHostnameRedaction` — 4 tests.
- [x] Task 2: Add file path username detection (AC: 2)
  - [x] 2.1: Added `_FILE_PATH_USERNAME_RE` pattern for `/home/`, `/Users/`, `C:\Users\`.
  - [x] 2.2: Only the username segment is replaced: `/home/jsmith/Documents` → `/home/USER_001/Documents`.
  - [x] 2.3: Added `TestFilePathRedaction` — 4 tests.
- [x] Task 3: Add chat handle detection (AC: 4)
  - [x] 3.1: Added `_CHAT_HANDLE_RE` pattern (`@[a-zA-Z][a-zA-Z0-9._-]{1,20}\b`).
  - [x] 3.2: Redacted with `USER` prefix for consistency with email redaction.
  - [x] 3.3: Added `TestChatHandleRedaction` — 3 tests.
- [x] Task 4: Add secure redaction map storage (AC: 3)
  - [x] 4.1: Added `encrypt_redaction_map()` using `cryptography.fernet.Fernet`.
  - [x] 4.2: Added `decrypt_redaction_map()` with counter reconstruction.
  - [x] 4.3: Key from `PII_REDACTION_KEY` env var or KMS (documented in docstring).
  - [x] 4.4: Added `TestSecureRedactionMap` — 4 tests.
- [x] Task 5: Add integration test (AC: 4)
  - [x] 5.1: Added `TestPIICompleteness` — 4 tests (all types, hashes preserved, map coverage, round-trip).
- [x] Task 6: Run full regression (AC: 1-4)
  - [x] 6.1: Run full project test suite — all 1977 tests pass (zero regressions)
  - [x] 6.2: All 15 existing PII redactor tests pass unchanged

## Dev Notes

### Critical Architecture Constraints

- **REM-M04** — PII detection currently only handles IPs and emails. Hostnames with usernames, file paths, and chat handles are overlooked.
- **`_HOSTNAME_RE` exists but is never used** — line 17 of `pii_redactor.py` defines a hostname pattern that is NOT plugged into `redact_pii()`. This is a known gap.
- **IP addresses are KEPT** — IPs are needed for security analysis and are not PII in most SOC contexts. Do NOT redact IPs.
- **Hashes are KEPT** — MD5/SHA hashes are not PII. Do NOT redact hashes.
- **Encrypted redaction map** — for compliance, the mapping between real values and placeholders must be stored encrypted. Only audit re-identification should decrypt.
- **DO NOT change the `RedactionMap` class interface** — only add encryption/decryption wrappers around it.

### Existing Code You MUST Reuse (DO NOT Reinvent)

| Component | File | What It Does |
|---|---|---|
| `redact_pii()` | `context_gateway/pii_redactor.py:54-95` | PII redaction. **Extend with new patterns.** |
| `RedactionMap` | `context_gateway/pii_redactor.py:20-51` | Mapping class. **Use for new PII types.** |
| `_IP_RE` | `context_gateway/pii_redactor.py:14` | IP detection. **Keep — IPs not redacted.** |
| `_EMAIL_RE` | `context_gateway/pii_redactor.py:15` | Email detection. **Keep — already works.** |
| `_HOSTNAME_RE` | `context_gateway/pii_redactor.py:17` | Hostname pattern. **Evaluate for use.** |
| `deanonymise_text()` | `context_gateway/pii_redactor.py:98-108` | Restore values. **Not modified.** |

### Exact File Paths (Verified Against Codebase)

| Target | Correct Path |
|---|---|
| PII completeness tests (NEW) | `tests/integration/test_pii_completeness.py` |
| PII redactor | `context_gateway/pii_redactor.py` |
| Existing PII tests | `tests/test_context_gateway/test_pii_redactor.py` |

### PII Category Matrix

| Category | Pattern | Action | Prefix |
|---|---|---|---|
| Email/UPN | `_EMAIL_RE` (existing) | Redact | `USER` |
| IP address | `_IP_RE` (existing) | **KEEP** | — |
| Hostname with user | `_USERNAME_IN_HOSTNAME_RE` (new) | Redact | `HOST` |
| File path username | `_FILE_PATH_USERNAME_RE` (new) | Redact segment | `USER` |
| Chat handle | `_CHAT_HANDLE_RE` (new) | Redact | `USER` |
| MD5/SHA hash | — | **KEEP** | — |

### Existing Test Classes That MUST Still Pass (Unchanged)

**test_context_gateway/test_pii_redactor.py (15 tests):**
- All existing tests unchanged

**Total existing: 1169 tests — ALL must pass unchanged.**

### Testing Patterns

- Test framework: **pytest**
- Pure synchronous tests (regex matching, string replacement)
- Test each PII type independently
- Integration test with all types combined
- Test encryption with `cryptography.fernet.Fernet`

### Dependencies on Other Stories

- **None.** Can start immediately. Fully independent.

### References

- [Source: docs/remediation-backlog.md#REM-M04] — PII redaction completeness
- [Source: docs/prd.md#NFR-SEC-001] — Security / privacy requirement

## Dev Agent Record

### Agent Model Used

Claude Opus 4.6 (claude-opus-4-6)

### Debug Log References

- 1 test failure: `jdoe-Workstation` — `Workstation` is 11 chars, exceeded `{2,10}` limit. Fixed regex to `{2,15}`.

### Completion Notes List

- **Task 1 (Hostname):** `_USERNAME_IN_HOSTNAME_RE` detects `JSMITH-LAPTOP`, `admin-PC01`, `jdoe-Workstation` patterns. Redacted as `HOST_NNN`. 4 tests.
- **Task 2 (File paths):** `_FILE_PATH_USERNAME_RE` detects usernames in `/home/`, `/Users/`, `C:\Users\` paths. Only the username segment is replaced, preserving the rest of the path. 4 tests.
- **Task 3 (Chat handles):** `_CHAT_HANDLE_RE` detects `@username` patterns. Redacted with `USER` prefix for consistency with email redaction. 3 tests.
- **Task 4 (Encryption):** `encrypt_redaction_map()` / `decrypt_redaction_map()` using Fernet symmetric encryption. Round-trip preserves all mappings and counters. Wrong key raises `InvalidToken`. 4 tests.
- **Task 5 (Integration):** Full alert with all PII types redacted. Hashes preserved. Round-trip deanonymisation works. 4 tests.
- **Task 6 (Regression):** 1977 tests passed, 0 failures. All 15 existing PII tests unchanged.

### File List

**Created:**
- `tests/integration/test_pii_completeness.py` — 19 tests (4 hostname + 4 file path + 3 chat handle + 4 encryption + 4 integration)

**Modified:**
- `context_gateway/pii_redactor.py` — added `_USERNAME_IN_HOSTNAME_RE`, `_FILE_PATH_USERNAME_RE`, `_CHAT_HANDLE_RE` patterns; extended `redact_pii()` with hostname, file path, chat handle detection; added `encrypt_redaction_map()` and `decrypt_redaction_map()`

### Change Log

- 2026-02-24: Story 15.4 implemented — PII redaction completeness with hostname-with-username, file path username, chat handle detection, and Fernet-encrypted redaction map storage. 19 new tests, 1977 total tests passing.
