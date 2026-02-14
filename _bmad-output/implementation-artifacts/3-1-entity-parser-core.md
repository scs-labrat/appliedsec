# Story 3.1: Create Entity Parser Core

## Status: done

## Description
Entity parsing engine that extracts structured entities from alert data with type-specific parsers and regex fallback.

## Tasks
- [x] Create `entity_parser/parser.py` with `parse_alert_entities()` entry point
- [x] Implement type-specific parsers: account, host, IP, file, process, URL, DNS, filehash, mailbox
- [x] Implement `$id/$ref` resolution for entity cross-references (e.g. process → file)
- [x] Implement regex fallback IOC extraction (IPv4, SHA256, SHA1, domains)
- [x] Map Sentinel entity type names to EntityType enum
- [x] Populate `raw_iocs` flat list and `parse_errors` on all code paths
- [x] Reduced confidence scores (0.6–0.8) for regex-extracted entities
- [x] 21 Sentinel parsing tests + 12 regex fallback tests pass

## Completion Notes
- Parser handles structured JSON arrays (Sentinel) and falls back to regex for other sources
- All 9 entity types have dedicated parsers with proper validation
- Generic fallback parser for unhandled types (registry, security group, etc.)
