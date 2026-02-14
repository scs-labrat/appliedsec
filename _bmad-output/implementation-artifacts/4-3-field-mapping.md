# Story 4.3: Sentinel → CanonicalAlert Field Mapping

## Status: done

## Description
Complete field mapping from Sentinel SecurityAlert to CanonicalAlert schema.

## Tasks
- [x] SystemAlertId → alert_id
- [x] Source hardcoded to "sentinel"
- [x] TimeGenerated → timestamp (ISO 8601)
- [x] AlertName → title
- [x] Description → description
- [x] Severity → severity (lowercased, default "medium")
- [x] Tactics → tactics (comma-separated → list, stripped)
- [x] Techniques → techniques (comma-separated → list, stripped)
- [x] Entities → entities_raw (preserved as JSON string)
- [x] ProductName → product
- [x] TenantId → tenant_id (default "default")
- [x] Full event → raw_payload (for audit)
- [x] Write 16 field mapping tests
- [x] All tests pass

## Completion Notes
- Severity normalization handles missing, empty, and mixed-case inputs
- Tactics/techniques splitting handles trailing commas, whitespace, empty strings
- entities_raw is never parsed — preserved for entity parser service
