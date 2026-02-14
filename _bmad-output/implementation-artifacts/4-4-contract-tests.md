# Story 4.4: Contract Tests

## Status: done

## Description
Contract tests verifying 3+ realistic Sentinel payloads produce valid CanonicalAlert objects with parseable entities.

## Tasks
- [x] MDE PowerShell payload — multi-tactic, multi-technique, account+host+process entities
- [x] AAD IP Impossible Travel payload — 2 IPs with geo, medium severity
- [x] Analytics Rule Brute Force payload — critical severity, T1110.001
- [x] All payloads produce valid CanonicalAlert with required fields
- [x] entities_raw is valid JSON for all payloads
- [x] Round-trip: Sentinel → CanonicalAlert → EntityParser → entities extracted
- [x] Write 17 contract tests
- [x] All tests pass

## Completion Notes
- 3 realistic Sentinel payloads covering MDE, AAD IP, and custom analytics rules
- End-to-end round-trip test verifies entity parser integration
- Payload-specific assertions verify multi-tactics, IP extraction, severity values
