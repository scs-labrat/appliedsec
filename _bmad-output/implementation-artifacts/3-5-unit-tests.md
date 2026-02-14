# Story 3.5: Unit Tests for Entity Extraction

## Status: done

## Description
Comprehensive unit tests covering all entity parsing, validation, injection protection, and Kafka service behaviour.

## Tasks
- [x] `test_sentinel_entities.py` — 21 tests: account UPN, host FQDN, IP geo, file hashes, process $ref resolution, URL, DNS, mailbox, raw_iocs, no parse errors
- [x] `test_elastic_entities.py` — 12 tests: regex fallback for IPs, SHA256, SHA1, domains; malformed JSON fallback; deduplication; reduced confidence
- [x] `test_injection.py` — 10 tests: SQL injection in names stripped, invalid IP rejected, URL injection stripped, oversized truncation, empty/null/unknown edge cases
- [x] `test_validation.py` — 34 tests: IP validation (IPv4/IPv6/edge cases), hash validation (3 algorithms + auto-detect), sanitisation (truncation, dangerous chars, CommandLine exception), pattern coverage
- [x] `test_service.py` — 13 tests: consumer config, process_message, DLQ routing, lifecycle (start/stop/close), constants
- [x] All 90 tests pass

## Completion Notes
- Full coverage of Sentinel structured parsing and regex fallback paths
- Injection protection verified for SQL, command, and prompt injection patterns
- All tests use mocked Kafka (no live broker needed)
- 90/90 tests pass, 294/294 total suite
