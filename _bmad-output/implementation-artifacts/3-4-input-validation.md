# Story 3.4: Create Input Validation and Sanitisation

## Status: done

## Description
Validation and sanitisation layer protecting downstream services from injection attacks via alert data.

## Tasks
- [x] Create `entity_parser/validation.py` with all validation functions
- [x] `validate_ip()` — IPv4 octet range check + IPv6 format check
- [x] `validate_hash()` — SHA256 (64), SHA1 (40), MD5 (32) hex validation with algorithm-specific and auto-detect modes
- [x] `sanitize_value()` — truncation (>2048 chars), dangerous character stripping, CommandLine exception
- [x] `VALIDATION_PATTERNS` dict with ipv4, ipv6, sha256, sha1, md5, domain, upn, hostname regexes
- [x] `DANGEROUS_CHARS` regex for query injection vectors (`;|&\`$(){}[]<>'\"`)
- [x] Write 34 validation tests covering all patterns, edge cases, and boundary values
- [x] All tests pass

## Completion Notes
- 8 validation patterns covering all IOC types
- CommandLine fields exempt from dangerous character stripping
- None return for empty/whitespace-only inputs
- Non-string inputs coerced to strings
