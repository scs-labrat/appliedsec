# ALUSKORT - Data Pipeline Design

**Project:** ALUSKORT - Autonomous SOC Agent Architecture
**Type:** Cloud-Neutral Security Data Pipeline
**Generated:** 2026-02-14
**Agent:** Omeriko (DP - Data Pipeline)
**Status:** Phase 1 - AI Architecture Design (v2.0 - Cloud-Neutral Pivot)

> See `docs/ai-system-design.md` for the full system architecture, adapter pattern, and orchestration design. This document covers the data pipeline: ingestion, parsing, normalisation, enrichment, and routing of security data through the message bus to agent-ready context packages.

---

## 1. Pipeline Overview

ALUSKORT's data pipeline is queue-centric, built around a message bus (Kafka / Redpanda / NATS) rather than cloud-specific triggers. All SIEM/XDR sources push through thin adapters into canonical topics. Three distinct pipeline paths exist, each with different latency requirements and parsing complexity:

```
MESSAGE BUS (Kafka / Redpanda / NATS)
    │
    ├──── PATH 1: ALERT PIPELINE (Real-time)
    │     Adapter → alerts.raw → Entity Parser Service
    │     → alerts.normalized → Enrichment Service
    │     → incidents.enriched → Priority Queue Router
    │     → jobs.llm.priority.{severity} → Agent Orchestrator
    │     Latency target: < 5 seconds (parse + enrich)
    │
    ├──── PATH 2: INVESTIGATION PIPELINE (On-demand)
    │     Agent Request → Adapter-Specific Query Module → Parse Results
    │     → Normalize across source schemas → Return to Agent
    │     Latency target: < 10 seconds per query
    │
    └──── PATH 3: INGESTION PIPELINE (Batch)
          TI Feeds / MITRE / CTEM / Playbooks → Parse → Embed → Index
          → Vector DB + Postgres
          Latency target: minutes (not latency-sensitive)
```

> **Why queue-centric instead of function-centric?** Azure Functions (or Lambda, Cloud Functions) tie your pipeline to a single cloud vendor's execution model, timeout limits, and cold-start behaviour. A message bus decouples producers (adapters) from consumers (microservices), enables replay from any offset, and allows independent scaling of each pipeline stage. Kafka retention means alerts survive consumer crashes — they accumulate in the topic instead of disappearing.

### Data Volume Estimates (per tenant, < 10 GB/day)

| Data Source | Estimated Daily Volume | Records/Day | Pipeline Topic |
|---|---|---|---|
| SIEM alerts (any source) | 10-100 MB | 100-1,000 alerts | `alerts.raw` |
| Incidents / cases | 1-10 MB | 10-100 incidents | `incidents.enriched` |
| Authentication logs | 1-3 GB | 100K-500K records | On-demand query via adapter |
| Network/firewall logs (CEF) | 2-4 GB | 500K-2M records | On-demand query via adapter |
| Endpoint telemetry | 1-3 GB | 200K-1M records | On-demand query via adapter |
| UEBA / behaviour signals | 10-50 MB | 1K-10K records | Enrichment lookup |
| Threat intelligence indicators | 1-10 MB | 1K-50K indicators | Redis IOC cache + Vector DB |
| CTEM findings | 10-100 MB | 100-10K findings | `ctem.raw.<source>` |

These volumes are per-tenant estimates. The message bus partitions by `tenant_id` to enable per-tenant scaling and isolation.

---

## 2. Canonical Alert Schema & Adapter Pattern

Before parsing entities, every alert from every source must be mapped to ALUSKORT's canonical schema. This is the adapter pattern defined in `docs/ai-system-design.md`.

### 2.1 CanonicalAlert and IngestAdapter

```python
"""
ALUSKORT Canonical Alert Schema
All SIEM/XDR adapters map their source format to this schema.
The canonical alert is the single input format for the entire pipeline.

See docs/ai-system-design.md Section 6.2 for the full adapter interface.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Optional


@dataclass
class CanonicalAlert:
    """ALUSKORT's internal alert representation.
    Every adapter maps its source format to this schema."""
    alert_id: str               # Source-specific alert ID
    source: str                 # "sentinel", "elastic", "splunk", etc.
    timestamp: str              # ISO 8601 UTC
    title: str
    description: str
    severity: str               # "critical", "high", "medium", "low", "informational"
    tactics: list[str]          # MITRE ATT&CK tactics
    techniques: list[str]       # MITRE technique IDs
    entities_raw: str           # Raw entities JSON (source-specific format)
    product: str                # Alert product name
    tenant_id: str              # Multi-tenant identifier
    raw_payload: dict           # Full original alert for audit


class IngestAdapter(ABC):
    """Base class for SIEM/XDR ingest adapters."""

    @abstractmethod
    def source_name(self) -> str:
        """Return the adapter's source identifier."""
        ...

    @abstractmethod
    def subscribe(self) -> None:
        """Start consuming events from the source."""
        ...

    @abstractmethod
    def to_canonical(self, raw_event: dict) -> Optional[CanonicalAlert]:
        """Convert a raw source event to a CanonicalAlert.
        Returns None if the event should be dropped (e.g., heartbeat)."""
        ...
```

### 2.2 Sentinel Adapter: SecurityAlert to CanonicalAlert

The Sentinel adapter demonstrates how source-specific fields map to the canonical schema. The `entities_raw` field preserves the raw Entities JSON string for downstream parsing by the entity parser service.

```python
"""
ALUSKORT Sentinel Adapter
Maps Microsoft Sentinel SecurityAlert to CanonicalAlert.
Azure SDK imports are confined to this adapter — they never appear in core pipeline code.
"""

from typing import Optional


class SentinelAdapter(IngestAdapter):
    """Microsoft Sentinel adapter - subscribes to SecurityAlert."""

    def source_name(self) -> str:
        return "sentinel"

    def subscribe(self) -> None:
        # Connect via Event Hub, webhook, or poll via Log Analytics API.
        # The connection method is adapter-internal — the pipeline only sees
        # CanonicalAlert objects on the alerts.raw topic.
        pass

    def to_canonical(self, raw_event: dict) -> Optional[CanonicalAlert]:
        return CanonicalAlert(
            alert_id=raw_event.get("SystemAlertId", ""),
            source="sentinel",
            timestamp=raw_event.get("TimeGenerated", ""),
            title=raw_event.get("AlertName", ""),
            description=raw_event.get("Description", ""),
            severity=raw_event.get("Severity", "medium").lower(),
            tactics=(
                raw_event.get("Tactics", "").split(",")
                if raw_event.get("Tactics") else []
            ),
            techniques=(
                raw_event.get("Techniques", "").split(",")
                if raw_event.get("Techniques") else []
            ),
            entities_raw=raw_event.get("Entities", "[]"),
            product=raw_event.get("ProductName", ""),
            tenant_id=raw_event.get("TenantId", "default"),
            raw_payload=raw_event,
        )
```

### 2.3 Elastic Adapter (Reference)

```python
"""
ALUSKORT Elastic SIEM Adapter
Maps Elastic detection alerts to CanonicalAlert.
"""

from typing import Optional


class ElasticAdapter(IngestAdapter):
    """Elastic SIEM adapter - subscribes to detection alerts."""

    def source_name(self) -> str:
        return "elastic"

    def subscribe(self) -> None:
        # Connect via Elastic webhook / Watcher / Kibana alerting
        pass

    def to_canonical(self, raw_event: dict) -> Optional[CanonicalAlert]:
        signal = raw_event.get("signal", {})
        rule = signal.get("rule", {})
        return CanonicalAlert(
            alert_id=raw_event.get("_id", ""),
            source="elastic",
            timestamp=raw_event.get("@timestamp", ""),
            title=rule.get("name", ""),
            description=rule.get("description", ""),
            severity=rule.get("severity", "medium"),
            tactics=(
                rule.get("threat", [{}])[0].get("tactic", {}).get("name", "").split(",")
                if rule.get("threat") else []
            ),
            techniques=[
                t.get("id", "")
                for threat in rule.get("threat", [])
                for t in threat.get("technique", [])
            ],
            entities_raw="[]",  # Elastic has no native Entities field;
                                # entity parser uses raw_payload fallback
            product="Elastic SIEM",
            tenant_id=raw_event.get("_index", "default"),
            raw_payload=raw_event,
        )
```

> **Why adapters instead of direct integration?** Every SIEM has a different alert schema, entity format, and API. Without adapters, the core pipeline would need `if source == "sentinel": ... elif source == "elastic": ...` branches everywhere. The adapter pattern confines all vendor-specific code to a single module per source. Adding a new SIEM means writing one adapter file, not modifying the entire pipeline.

---

## 3. Alert Entity Extraction

This is the most critical parsing problem. Alert sources store entities (users, hosts, IPs, files, processes) in varying formats. The entity parser service consumes from `alerts.raw` and produces parsed, normalised entities on `alerts.normalized`.

### 3.1 Entity Parser as a Microservice

```
alerts.raw (Kafka topic)
    │
    ▼
┌─────────────────────────────┐
│  Entity Parser Service      │
│  (Kubernetes deployment)    │
│                             │
│  Consumer group:            │
│    aluskort.entity-parser   │
│                             │
│  Input: CanonicalAlert      │
│  Output: CanonicalAlert +   │
│          AlertEntities      │
│                             │
│  Source-aware parsing:      │
│  - Sentinel: JSON Entities  │
│  - Elastic: raw_payload     │
│  - Splunk: notable event    │
└─────────────────────────────┘
    │
    ▼
alerts.normalized (Kafka topic)
```

The entity parser reads the `entities_raw` field from the `CanonicalAlert` and applies source-aware extraction. For Sentinel, this is the JSON `Entities` column. For Elastic, entities are extracted from the raw payload fields. The parser outputs the same `CanonicalAlert` enriched with a structured `AlertEntities` object.

### 3.2 The Entities Parsing Problem

Sentinel's `SecurityAlert` table stores entities as a **JSON array in a string field**. Each entity has a `$id`, `Type`, and type-specific properties. The schema varies by alert provider (Defender for Endpoint vs Defender for Identity vs analytics rules). Other SIEMs have their own entity formats — or none at all, requiring extraction from the raw payload.

**Example Sentinel SecurityAlert.Entities value:**
```json
[
  {
    "$id": "1",
    "Type": "account",
    "Name": "jsmith",
    "UPNSuffix": "contoso.com",
    "AadUserId": "a1b2c3d4-...",
    "IsDomainJoined": true,
    "DnsDomain": "contoso.com"
  },
  {
    "$id": "2",
    "Type": "host",
    "HostName": "WORKSTATION-42",
    "DnsDomain": "contoso.com",
    "OSFamily": "Windows",
    "OSVersion": "10.0.19045"
  },
  {
    "$id": "3",
    "Type": "ip",
    "Address": "203.0.113.42"
  },
  {
    "$id": "4",
    "Type": "file",
    "Name": "payload.exe",
    "Directory": "C:\\Users\\jsmith\\Downloads",
    "FileHashes": [
      {"Algorithm": "SHA256", "Value": "a1b2c3d4e5f6..."}
    ]
  },
  {
    "$id": "5",
    "Type": "process",
    "ProcessId": "4528",
    "CommandLine": "powershell.exe -enc SQBFAFgAIAAoA...",
    "ImageFile": {"$ref": "4"}
  }
]
```

### 3.3 Entity Parser

```python
"""
ALUSKORT Alert Entity Parser
Extracts and normalizes entities from alert sources.
Runs as a dedicated microservice consuming from alerts.raw topic.

The parser is source-aware: Sentinel entities come as a JSON array in
the entities_raw field; Elastic entities are extracted from the raw_payload;
other sources use the regex fallback.

Critical security note: All extracted values are treated as untrusted input.
Never interpolate directly into queries of any kind (KQL, EQL, SPL, SQL).
"""

import json
import re
import logging
from dataclasses import dataclass, field
from typing import Optional
from enum import Enum

logger = logging.getLogger(__name__)


class EntityType(Enum):
    ACCOUNT = "account"
    HOST = "host"
    IP = "ip"
    FILE = "file"
    PROCESS = "process"
    URL = "url"
    DNS = "dns"
    FILEHASH = "filehash"
    MAILBOX = "mailbox"
    MAILMESSAGE = "mailmessage"
    REGISTRY_KEY = "registry-key"
    REGISTRY_VALUE = "registry-value"
    SECURITY_GROUP = "security-group"
    AZURE_RESOURCE = "azure-resource"
    CLOUD_APPLICATION = "cloud-application"
    MALWARE = "malware"


@dataclass
class NormalizedEntity:
    """A cleaned, normalized entity extracted from an alert."""
    entity_type: EntityType
    primary_value: str           # The main identifier (UPN, hostname, IP, hash)
    properties: dict             # All properties for this entity
    confidence: float = 1.0      # How confident we are in the extraction
    source_id: Optional[str] = None  # $id from the original JSON


@dataclass
class AlertEntities:
    """All entities extracted from a single alert."""
    accounts: list[NormalizedEntity] = field(default_factory=list)
    hosts: list[NormalizedEntity] = field(default_factory=list)
    ips: list[NormalizedEntity] = field(default_factory=list)
    files: list[NormalizedEntity] = field(default_factory=list)
    processes: list[NormalizedEntity] = field(default_factory=list)
    urls: list[NormalizedEntity] = field(default_factory=list)
    dns_records: list[NormalizedEntity] = field(default_factory=list)
    file_hashes: list[NormalizedEntity] = field(default_factory=list)
    mailboxes: list[NormalizedEntity] = field(default_factory=list)
    other: list[NormalizedEntity] = field(default_factory=list)
    raw_iocs: list[str] = field(default_factory=list)  # Flat list of all IOC values
    parse_errors: list[str] = field(default_factory=list)

    @property
    def all_ips(self) -> list[str]:
        return [e.primary_value for e in self.ips]

    @property
    def all_hashes(self) -> list[str]:
        return [e.primary_value for e in self.file_hashes]

    @property
    def all_users(self) -> list[str]:
        return [e.primary_value for e in self.accounts]

    @property
    def all_hostnames(self) -> list[str]:
        return [e.primary_value for e in self.hosts]


# Validation patterns — reject values that don't match expected formats
VALIDATION_PATTERNS = {
    "ipv4": re.compile(r'^(?:\d{1,3}\.){3}\d{1,3}$'),
    "ipv6": re.compile(r'^[0-9a-fA-F:]+$'),
    "sha256": re.compile(r'^[a-fA-F0-9]{64}$'),
    "sha1": re.compile(r'^[a-fA-F0-9]{40}$'),
    "md5": re.compile(r'^[a-fA-F0-9]{32}$'),
    "domain": re.compile(r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'),
    "upn": re.compile(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'),
    "hostname": re.compile(r'^[a-zA-Z0-9][a-zA-Z0-9._-]{0,63}$'),
}

# Characters that should never appear in IOC values (query injection vectors)
DANGEROUS_CHARS = re.compile(r'[;|&`$(){}\[\]<>\'"]')

# Maximum field length to prevent memory abuse
MAX_FIELD_LENGTH = 2048


def sanitize_value(value: str, field_name: str = "") -> Optional[str]:
    """
    Sanitize an extracted entity value.
    Returns None if the value is suspicious or malformed.
    """
    if not isinstance(value, str):
        return str(value) if value is not None else None

    # Truncate oversized values
    if len(value) > MAX_FIELD_LENGTH:
        logger.warning(
            f"Truncated oversized field '{field_name}': {len(value)} chars"
        )
        value = value[:MAX_FIELD_LENGTH]

    # Check for query injection patterns
    if DANGEROUS_CHARS.search(value):
        # Allow semicolons in command lines but flag everything else
        if field_name not in ("CommandLine", "commandline", "command_line"):
            logger.warning(
                f"Dangerous characters in field '{field_name}': {value[:100]}"
            )
            # Don't reject — strip the dangerous chars and continue
            value = DANGEROUS_CHARS.sub('', value)

    return value.strip()


def validate_ip(ip: str) -> bool:
    """Validate an IP address format."""
    if VALIDATION_PATTERNS["ipv4"].match(ip):
        # Check octet ranges
        octets = ip.split('.')
        return all(0 <= int(o) <= 255 for o in octets)
    if VALIDATION_PATTERNS["ipv6"].match(ip):
        return True
    return False


def validate_hash(hash_value: str, algorithm: str) -> bool:
    """Validate a file hash format."""
    algo_lower = algorithm.lower()
    if algo_lower == "sha256":
        return bool(VALIDATION_PATTERNS["sha256"].match(hash_value))
    elif algo_lower == "sha1":
        return bool(VALIDATION_PATTERNS["sha1"].match(hash_value))
    elif algo_lower == "md5":
        return bool(VALIDATION_PATTERNS["md5"].match(hash_value))
    return False


def parse_alert_entities(entities_json: str) -> AlertEntities:
    """
    Parse the entities JSON string into normalized entities.

    This function handles the Sentinel-format JSON array (Type + properties).
    For other SIEM sources, adapters should either:
    - Map their entity format to the same JSON structure, or
    - Pass the raw_payload for regex fallback extraction.

    Handles:
    - Malformed JSON (graceful degradation)
    - Missing fields (optional extraction)
    - $ref references between entities (process -> file)
    - Multiple entity formats across alert providers
    - Input sanitization for all extracted values
    """
    result = AlertEntities()

    # Parse JSON safely
    try:
        entities = json.loads(entities_json)
    except (json.JSONDecodeError, TypeError) as e:
        result.parse_errors.append(f"Failed to parse Entities JSON: {e}")
        logger.warning(f"Malformed Entities JSON: {str(e)}")
        # Attempt regex fallback for IOCs in raw string
        result.raw_iocs = _extract_iocs_from_raw(entities_json or "")
        return result

    if not isinstance(entities, list):
        result.parse_errors.append(f"Entities is not a list: {type(entities)}")
        return result

    # Build $id lookup for reference resolution
    id_lookup = {}
    for entity in entities:
        if isinstance(entity, dict) and "$id" in entity:
            id_lookup[entity["$id"]] = entity

    # Parse each entity
    for entity in entities:
        if not isinstance(entity, dict):
            result.parse_errors.append(f"Non-dict entity: {type(entity)}")
            continue

        entity_type_raw = entity.get("Type", "").lower()

        try:
            if entity_type_raw == "account":
                _parse_account(entity, result)
            elif entity_type_raw == "host":
                _parse_host(entity, result)
            elif entity_type_raw == "ip":
                _parse_ip(entity, result)
            elif entity_type_raw == "file":
                _parse_file(entity, result, id_lookup)
            elif entity_type_raw == "process":
                _parse_process(entity, result, id_lookup)
            elif entity_type_raw == "url":
                _parse_url(entity, result)
            elif entity_type_raw in ("dns", "dnsresolution"):
                _parse_dns(entity, result)
            elif entity_type_raw == "filehash":
                _parse_filehash(entity, result)
            elif entity_type_raw in ("mailbox", "mailmessage"):
                _parse_mail(entity, result)
            else:
                # Unknown entity type — store as-is
                result.other.append(NormalizedEntity(
                    entity_type=EntityType.CLOUD_APPLICATION,
                    primary_value=str(entity.get("Name", entity.get("$id", "unknown"))),
                    properties=entity,
                    source_id=entity.get("$id"),
                ))
        except Exception as e:
            result.parse_errors.append(
                f"Error parsing entity type '{entity_type_raw}': {e}"
            )
            logger.error(f"Entity parse error: {e}", exc_info=True)

    # Build flat IOC list for quick lookups
    result.raw_iocs = (
        result.all_ips
        + result.all_hashes
        + [e.primary_value for e in result.urls]
        + [e.primary_value for e in result.dns_records]
    )

    return result


def _parse_account(entity: dict, result: AlertEntities) -> None:
    """Parse account entity (user/service principal)."""
    name = entity.get("Name", "")
    upn_suffix = entity.get("UPNSuffix", "")

    if name and upn_suffix:
        upn = f"{name}@{upn_suffix}"
    elif entity.get("AadUserId"):
        upn = entity["AadUserId"]
    else:
        upn = name or "unknown"

    upn = sanitize_value(upn, "UPN")
    if not upn:
        return

    result.accounts.append(NormalizedEntity(
        entity_type=EntityType.ACCOUNT,
        primary_value=upn,
        properties={
            "name": sanitize_value(name, "Name"),
            "upn_suffix": sanitize_value(upn_suffix, "UPNSuffix"),
            "aad_user_id": sanitize_value(entity.get("AadUserId", ""), "AadUserId"),
            "sid": sanitize_value(entity.get("Sid", ""), "Sid"),
            "is_domain_joined": entity.get("IsDomainJoined", False),
            "dns_domain": sanitize_value(entity.get("DnsDomain", ""), "DnsDomain"),
        },
        source_id=entity.get("$id"),
    ))


def _parse_host(entity: dict, result: AlertEntities) -> None:
    """Parse host entity."""
    hostname = entity.get("HostName", entity.get("NetBiosName", ""))
    hostname = sanitize_value(hostname, "HostName")
    if not hostname:
        return

    dns_domain = sanitize_value(entity.get("DnsDomain", ""), "DnsDomain")
    fqdn = f"{hostname}.{dns_domain}" if dns_domain else hostname

    result.hosts.append(NormalizedEntity(
        entity_type=EntityType.HOST,
        primary_value=fqdn,
        properties={
            "hostname": hostname,
            "dns_domain": dns_domain,
            "os_family": entity.get("OSFamily", ""),
            "os_version": entity.get("OSVersion", ""),
            "resource_id": sanitize_value(entity.get("AzureID", entity.get("ResourceId", "")), "ResourceId"),
            "edr_device_id": sanitize_value(
                entity.get("MdatpDeviceId", entity.get("agent.id", "")), "DeviceId"
            ),
        },
        source_id=entity.get("$id"),
    ))


def _parse_ip(entity: dict, result: AlertEntities) -> None:
    """Parse IP address entity."""
    address = entity.get("Address", "")
    address = sanitize_value(address, "Address")
    if not address or not validate_ip(address):
        result.parse_errors.append(f"Invalid IP address: {address}")
        return

    result.ips.append(NormalizedEntity(
        entity_type=EntityType.IP,
        primary_value=address,
        properties={
            "geo_country": entity.get("Location", {}).get("CountryCode", ""),
            "geo_city": entity.get("Location", {}).get("City", ""),
            "asn": entity.get("Location", {}).get("Asn", ""),
            "carrier": entity.get("Location", {}).get("Carrier", ""),
        },
        source_id=entity.get("$id"),
    ))


def _parse_file(entity: dict, result: AlertEntities, id_lookup: dict) -> None:
    """Parse file entity and extract file hashes."""
    filename = sanitize_value(entity.get("Name", ""), "FileName")
    directory = sanitize_value(entity.get("Directory", ""), "Directory")

    file_entity = NormalizedEntity(
        entity_type=EntityType.FILE,
        primary_value=filename or "unknown",
        properties={
            "directory": directory,
            "full_path": f"{directory}\\{filename}" if directory and filename else "",
            "size": entity.get("SizeInBytes"),
        },
        source_id=entity.get("$id"),
    )

    # Extract file hashes
    file_hashes = entity.get("FileHashes", [])
    if isinstance(file_hashes, list):
        for fh in file_hashes:
            if not isinstance(fh, dict):
                continue
            algo = fh.get("Algorithm", "")
            value = sanitize_value(fh.get("Value", ""), "FileHash")
            if value and validate_hash(value, algo):
                result.file_hashes.append(NormalizedEntity(
                    entity_type=EntityType.FILEHASH,
                    primary_value=value,
                    properties={
                        "algorithm": algo,
                        "associated_file": filename,
                    },
                    source_id=entity.get("$id"),
                ))
                file_entity.properties[f"hash_{algo.lower()}"] = value

    result.files.append(file_entity)


def _parse_process(entity: dict, result: AlertEntities, id_lookup: dict) -> None:
    """Parse process entity."""
    process_id = entity.get("ProcessId", "")
    command_line = entity.get("CommandLine", "")
    # CommandLine is allowed to have special chars — don't strip them
    # but do truncate for safety
    if isinstance(command_line, str) and len(command_line) > MAX_FIELD_LENGTH:
        command_line = command_line[:MAX_FIELD_LENGTH]

    # Resolve $ref to image file
    image_file = entity.get("ImageFile", {})
    if isinstance(image_file, dict) and "$ref" in image_file:
        ref_id = image_file["$ref"]
        referenced = id_lookup.get(ref_id, {})
        image_name = referenced.get("Name", "")
    else:
        image_name = image_file.get("Name", "") if isinstance(image_file, dict) else ""

    result.processes.append(NormalizedEntity(
        entity_type=EntityType.PROCESS,
        primary_value=sanitize_value(image_name, "ImageName") or str(process_id),
        properties={
            "process_id": str(process_id),
            "command_line": command_line,
            "image_name": sanitize_value(image_name, "ImageName"),
            "parent_process_id": entity.get("ParentProcessId", ""),
            "creation_time": entity.get("CreationTimeUtc", ""),
        },
        source_id=entity.get("$id"),
    ))


def _parse_url(entity: dict, result: AlertEntities) -> None:
    """Parse URL entity."""
    url = sanitize_value(entity.get("Url", ""), "Url")
    if not url:
        return

    result.urls.append(NormalizedEntity(
        entity_type=EntityType.URL,
        primary_value=url,
        properties={},
        source_id=entity.get("$id"),
    ))


def _parse_dns(entity: dict, result: AlertEntities) -> None:
    """Parse DNS resolution entity."""
    domain = sanitize_value(entity.get("DomainName", ""), "DomainName")
    if not domain:
        return

    result.dns_records.append(NormalizedEntity(
        entity_type=EntityType.DNS,
        primary_value=domain,
        properties={
            "resolved_ips": entity.get("IpAddresses", []),
        },
        source_id=entity.get("$id"),
    ))


def _parse_filehash(entity: dict, result: AlertEntities) -> None:
    """Parse standalone file hash entity."""
    algo = entity.get("Algorithm", "")
    value = sanitize_value(entity.get("Value", ""), "FileHash")
    if value and validate_hash(value, algo):
        result.file_hashes.append(NormalizedEntity(
            entity_type=EntityType.FILEHASH,
            primary_value=value,
            properties={"algorithm": algo},
            source_id=entity.get("$id"),
        ))


def _parse_mail(entity: dict, result: AlertEntities) -> None:
    """Parse mailbox or mail message entity."""
    if entity.get("Type", "").lower() == "mailbox":
        address = sanitize_value(
            entity.get("MailboxPrimaryAddress", ""), "MailboxPrimaryAddress"
        )
        if address:
            result.mailboxes.append(NormalizedEntity(
                entity_type=EntityType.MAILBOX,
                primary_value=address,
                properties={
                    "display_name": sanitize_value(
                        entity.get("DisplayName", ""), "DisplayName"
                    ),
                    "upn": sanitize_value(entity.get("Upn", ""), "Upn"),
                },
                source_id=entity.get("$id"),
            ))
    else:
        # Mail message
        message_id = sanitize_value(
            entity.get("InternetMessageId", ""), "InternetMessageId"
        )
        if message_id:
            result.other.append(NormalizedEntity(
                entity_type=EntityType.MAILMESSAGE,
                primary_value=message_id,
                properties={
                    "sender": sanitize_value(entity.get("Sender", ""), "Sender"),
                    "subject": sanitize_value(
                        entity.get("Subject", ""), "Subject"
                    ),
                    "recipient": sanitize_value(
                        entity.get("Recipient", ""), "Recipient"
                    ),
                    "delivery_action": entity.get("DeliveryAction", ""),
                },
                source_id=entity.get("$id"),
            ))


def _extract_iocs_from_raw(text: str) -> list[str]:
    """
    Fallback: extract IOCs from raw text when JSON parsing fails.
    Used as a degraded mode — less reliable than structured parsing.
    """
    iocs = []
    # IPv4
    for match in re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', text):
        if validate_ip(match):
            iocs.append(match)
    # SHA256
    iocs.extend(re.findall(r'\b[a-fA-F0-9]{64}\b', text))
    # SHA1
    iocs.extend(re.findall(r'\b[a-fA-F0-9]{40}\b', text))
    # Domains (conservative)
    iocs.extend(re.findall(
        r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+(?:com|net|org|io|ru|cn|xyz)\b',
        text
    ))
    return list(set(iocs))
```

### 3.4 Entity Parser Kafka Consumer

The entity parser runs as a Kafka consumer service, reading from `alerts.raw` and writing to `alerts.normalized`:

```python
"""
ALUSKORT Entity Parser Service
Kafka consumer that reads CanonicalAlert from alerts.raw,
parses entities, and publishes to alerts.normalized.
"""

import json
import logging
from confluent_kafka import Consumer, Producer, KafkaError

logger = logging.getLogger(__name__)


class EntityParserService:
    """Microservice that consumes raw alerts and produces normalized alerts."""

    def __init__(self, kafka_bootstrap: str, consumer_group: str = "aluskort.entity-parser"):
        self.consumer = Consumer({
            "bootstrap.servers": kafka_bootstrap,
            "group.id": consumer_group,
            "auto.offset.reset": "earliest",
            "enable.auto.commit": False,
        })
        self.producer = Producer({
            "bootstrap.servers": kafka_bootstrap,
        })
        self.consumer.subscribe(["alerts.raw"])

    def run(self) -> None:
        """Main consumer loop."""
        logger.info("Entity parser service started, consuming from alerts.raw")
        while True:
            msg = self.consumer.poll(timeout=1.0)
            if msg is None:
                continue
            if msg.error():
                if msg.error().code() == KafkaError._PARTITION_EOF:
                    continue
                logger.error(f"Consumer error: {msg.error()}")
                continue

            try:
                alert_data = json.loads(msg.value().decode("utf-8"))
                entities_raw = alert_data.get("entities_raw", "[]")

                # Parse entities from the raw JSON
                entities = parse_alert_entities(entities_raw)

                # Enrich the alert with parsed entities
                alert_data["parsed_entities"] = {
                    "accounts": [_entity_to_dict(e) for e in entities.accounts],
                    "hosts": [_entity_to_dict(e) for e in entities.hosts],
                    "ips": [_entity_to_dict(e) for e in entities.ips],
                    "files": [_entity_to_dict(e) for e in entities.files],
                    "processes": [_entity_to_dict(e) for e in entities.processes],
                    "urls": [_entity_to_dict(e) for e in entities.urls],
                    "dns_records": [_entity_to_dict(e) for e in entities.dns_records],
                    "file_hashes": [_entity_to_dict(e) for e in entities.file_hashes],
                    "mailboxes": [_entity_to_dict(e) for e in entities.mailboxes],
                    "other": [_entity_to_dict(e) for e in entities.other],
                    "raw_iocs": entities.raw_iocs,
                    "parse_errors": entities.parse_errors,
                }

                # Publish to alerts.normalized
                self.producer.produce(
                    topic="alerts.normalized",
                    key=alert_data.get("alert_id", "").encode("utf-8"),
                    value=json.dumps(alert_data).encode("utf-8"),
                )
                self.producer.flush()
                self.consumer.commit(msg)

                logger.info(
                    f"Parsed alert {alert_data.get('alert_id')}: "
                    f"{len(entities.raw_iocs)} IOCs extracted, "
                    f"{len(entities.parse_errors)} parse errors"
                )

            except Exception as e:
                logger.error(f"Error processing alert: {e}", exc_info=True)
                # On error, commit to avoid reprocessing loop
                # The alert is logged for manual review
                self.consumer.commit(msg)


def _entity_to_dict(entity: NormalizedEntity) -> dict:
    """Serialize a NormalizedEntity for JSON transport."""
    return {
        "entity_type": entity.entity_type.value,
        "primary_value": entity.primary_value,
        "properties": entity.properties,
        "confidence": entity.confidence,
        "source_id": entity.source_id,
    }
```

---

## 4. CommonSecurityLog (CEF) Parsing

CEF (Common Event Format) logs from firewalls, proxies, and network devices are queried on-demand during investigations. The schema is semi-structured with both standard and vendor-specific fields. In a multi-SIEM deployment, CEF records may come from Sentinel's `CommonSecurityLog`, Elastic's `cef-*` indices, or Splunk's `cef` sourcetype. The parser is SIEM-agnostic — it operates on the normalised record dict returned by any adapter's query module.

### 4.1 CEF Field Map

The important fields and what they mean for ALUSKORT agents:

| CEF Field | Common Column Name | Agent Use | Parsing Notes |
|---|---|---|---|
| Source Address | `SourceIP` / `src` | IOC correlation | Standard CEF field |
| Destination Address | `DestinationIP` / `dst` | IOC correlation | Standard CEF field |
| Source Port | `SourcePort` / `spt` | Context enrichment | Integer |
| Destination Port | `DestinationPort` / `dpt` | Context enrichment | Standard service mapping (443=HTTPS, etc.) |
| Device Action | `DeviceAction` / `act` | Firewall decision | "Allow", "Deny", "Drop", "Reset" — varies by vendor |
| Activity | `Activity` / `msg` | Event description | Vendor-specific free text |
| Device Vendor | `DeviceVendor` | Source identification | "Palo Alto Networks", "Fortinet", "Check Point", etc. |
| Device Product | `DeviceProduct` | Source identification | Product-specific parsing |
| Request URL | `RequestURL` / `request` | URL IOC extraction | May contain query strings with sensitive data |
| Request Method | `RequestMethod` | Context | HTTP method if web proxy |
| Additional Extensions | `AdditionalExtensions` / `cs*` | Vendor custom fields | Key=value pairs, vendor-specific |

### 4.2 Vendor-Specific Parsing

Different firewall vendors encode information differently in extension fields. The parser applies vendor-aware normalisation.

```python
"""
ALUSKORT CEF/CommonSecurityLog Parser
Vendor-aware parsing for firewall, proxy, and network device logs.
SIEM-agnostic: operates on normalised record dicts from any adapter's query module.
"""

import re
from dataclasses import dataclass
from typing import Optional


@dataclass
class NetworkEvent:
    """Normalized network event from CEF logs."""
    timestamp: str
    source_ip: str
    source_port: int
    destination_ip: str
    destination_port: int
    protocol: str
    action: str                  # Normalized: "allow", "deny", "drop", "reset"
    direction: str               # "inbound", "outbound", "internal"
    bytes_sent: int
    bytes_received: int
    url: Optional[str]
    application: Optional[str]   # Application/service name if available
    threat_name: Optional[str]   # IPS/IDS threat signature if triggered
    vendor: str
    product: str
    raw_activity: str


# Vendor-specific action normalization
ACTION_MAP = {
    # Palo Alto
    "allow": "allow", "deny": "deny", "drop": "drop",
    "drop-icmp": "drop", "reset-client": "reset", "reset-server": "reset",
    "reset-both": "reset",
    # Fortinet
    "accept": "allow", "close": "allow", "timeout": "drop",
    "ip-conn": "allow", "dns": "allow",
    # Check Point
    "Accept": "allow", "Drop": "drop", "Reject": "deny",
    "Block": "deny",
    # Generic
    "allowed": "allow", "blocked": "deny", "dropped": "drop",
    "rejected": "deny", "permitted": "allow",
}


def normalize_action(raw_action: str) -> str:
    """Normalize vendor-specific action to standard values."""
    return ACTION_MAP.get(raw_action, ACTION_MAP.get(raw_action.lower(), raw_action.lower()))


def parse_additional_extensions(ext_str: str) -> dict:
    """
    Parse the AdditionalExtensions field (key=value pairs).
    Format: "key1=value1;key2=value2" or "key1=value1 key2=value2"
    """
    result = {}
    if not ext_str:
        return result

    # Split on semicolons or spaces (vendor-dependent)
    pairs = re.split(r'[;\s]+', ext_str)
    for pair in pairs:
        if '=' in pair:
            key, _, value = pair.partition('=')
            result[key.strip()] = value.strip()

    return result


def classify_direction(
    source_ip: str, dest_ip: str, internal_ranges: list[str] | None = None
) -> str:
    """
    Classify traffic direction based on IP ranges.
    Default internal ranges: RFC1918 + RFC6598.
    """
    if internal_ranges is None:
        internal_ranges = ["10.", "172.16.", "172.17.", "172.18.", "172.19.",
                          "172.20.", "172.21.", "172.22.", "172.23.", "172.24.",
                          "172.25.", "172.26.", "172.27.", "172.28.", "172.29.",
                          "172.30.", "172.31.", "192.168.", "100.64."]

    src_internal = any(source_ip.startswith(r) for r in internal_ranges)
    dst_internal = any(dest_ip.startswith(r) for r in internal_ranges)

    if src_internal and dst_internal:
        return "internal"
    elif src_internal and not dst_internal:
        return "outbound"
    elif not src_internal and dst_internal:
        return "inbound"
    else:
        return "external-to-external"  # Unusual — may indicate misconfiguration


def parse_csl_record(record: dict) -> NetworkEvent:
    """
    Parse a single CEF/network log record into a normalized NetworkEvent.
    Input: dict from any adapter's query result (Sentinel, Elastic, Splunk).
    The adapter's query module is responsible for mapping source-specific
    column names to the standard keys used here.
    """
    source_ip = record.get("SourceIP", "")
    dest_ip = record.get("DestinationIP", "")

    # Parse AdditionalExtensions for vendor-specific fields
    extensions = parse_additional_extensions(
        record.get("AdditionalExtensions", "")
    )

    # Extract threat info (IPS/IDS alerts)
    threat_name = (
        extensions.get("cat", "")          # Palo Alto threat category
        or extensions.get("attack", "")     # Fortinet attack name
        or record.get("DeviceEventClassID", "")  # Generic threat ID
        or None
    )

    # Extract application name
    application = (
        extensions.get("app", "")           # Palo Alto application
        or extensions.get("appcat", "")      # Fortinet app category
        or record.get("ApplicationProtocol", "")
        or None
    )

    return NetworkEvent(
        timestamp=record.get("TimeGenerated", record.get("@timestamp", "")),
        source_ip=source_ip,
        source_port=int(record.get("SourcePort", 0) or 0),
        destination_ip=dest_ip,
        destination_port=int(record.get("DestinationPort", 0) or 0),
        protocol=record.get("Protocol", "").upper(),
        action=normalize_action(record.get("DeviceAction", "")),
        direction=classify_direction(source_ip, dest_ip),
        bytes_sent=int(record.get("SentBytes", 0) or 0),
        bytes_received=int(record.get("ReceivedBytes", 0) or 0),
        url=record.get("RequestURL"),
        application=application,
        threat_name=threat_name if threat_name else None,
        vendor=record.get("DeviceVendor", ""),
        product=record.get("DeviceProduct", ""),
        raw_activity=record.get("Activity", ""),
    )
```

---

## 5. UEBA / Behaviour Analytics Data

UEBA (User and Entity Behaviour Analytics) signals come from various sources depending on the deployed SIEM: Sentinel's `BehaviorAnalytics` table, Elastic's ML anomaly detection, or custom UEBA pipelines. The UEBA context extractor normalises these signals into a common format for the Reasoning Agent.

### 5.1 Key Fields (Sentinel BehaviorAnalytics Reference)

| Field | Type | Description | Agent Usage |
|---|---|---|---|
| `UserPrincipalName` | string | The user being analysed | Entity correlation |
| `SourceIPAddress` | string | IP of the activity | IOC correlation |
| `ActivityType` | string | "LogOn", "FailedLogOn", "ResourceAccess", etc. | Activity classification |
| `InvestigationPriority` | int (0-10) | Computed risk score | **Primary risk signal** for Reasoning Agent |
| `ActivityInsights` | dynamic (JSON) | Anomaly indicators per activity | Detailed anomaly context |
| `UsersInsights` | dynamic (JSON) | User-level behaviour baseline | Peer group comparison |
| `DevicesInsights` | dynamic (JSON) | Device-level baseline | Device behaviour context |

> **Note on multi-SIEM UEBA:** Different SIEMs compute behaviour scores differently. Sentinel uses `InvestigationPriority` (0-10). Elastic ML uses anomaly scores (0-100). The adapter's query module must map source-specific scores to the 0-10 range before passing to the UEBA context extractor.

### 5.2 ActivityInsights Subfields

The `ActivityInsights` column is a JSON object with boolean/integer anomaly indicators:

```json
{
    "FirstTimeUserConnectedViaCountry": true,
    "FirstTimeConnectionToApplication": true,
    "CountryUncommonlyConnectedFromAmongPeers": true,
    "FirstTimeUserAccessedResource": false,
    "ActivityAtypicalComparedToUserHistory": true,
    "ApplicationUncommonlyAccessedAmongPeers": false,
    "ActionUncommonlyPerformedByUser": true
}
```

### 5.3 UEBA Context Extractor

```python
"""
ALUSKORT UEBA Context Extractor
Interprets behaviour analytics results for the Reasoning Agent.
Source-agnostic: operates on normalised UEBA records from any adapter.
"""

from dataclasses import dataclass


@dataclass
class UEBAContext:
    """Structured UEBA context for a user/activity."""
    user: str
    source_ip: str
    investigation_priority: int  # 0-10
    risk_level: str              # "low", "medium", "high", "critical"
    anomalies: list[str]         # Human-readable anomaly descriptions
    is_first_time_country: bool
    is_first_time_app: bool
    is_atypical_for_user: bool
    is_uncommon_among_peers: bool
    raw_activity_insights: dict
    raw_users_insights: dict


# Map InvestigationPriority to risk levels
PRIORITY_TO_RISK = {
    range(0, 3): "low",
    range(3, 6): "medium",
    range(6, 8): "high",
    range(8, 11): "critical",
}


def priority_to_risk(priority: int) -> str:
    """Convert InvestigationPriority (0-10) to risk level."""
    for r, level in PRIORITY_TO_RISK.items():
        if priority in r:
            return level
    return "unknown"


# Human-readable descriptions for ActivityInsights fields
ANOMALY_DESCRIPTIONS = {
    "FirstTimeUserConnectedViaCountry": "User connected from a country for the first time",
    "FirstTimeConnectionToApplication": "User accessed this application for the first time",
    "CountryUncommonlyConnectedFromAmongPeers": "Connection from a country uncommon among the user's peer group",
    "FirstTimeUserAccessedResource": "User accessed this resource for the first time",
    "ActivityAtypicalComparedToUserHistory": "Activity is atypical compared to the user's baseline behaviour",
    "ApplicationUncommonlyAccessedAmongPeers": "Application is uncommon among the user's peer group",
    "ActionUncommonlyPerformedByUser": "This action type is unusual for this user",
    "FirstTimeUserUsedDevice": "User used this device for the first time",
    "DeviceUncommonlyUsedAmongPeers": "Device is uncommon among the user's peer group",
}


def extract_ueba_context(record: dict) -> UEBAContext:
    """
    Extract structured UEBA context from a behaviour analytics record.
    Input: dict from any adapter's query result. The adapter is responsible
    for mapping source-specific field names to the standard keys:
    - UserPrincipalName, SourceIPAddress, InvestigationPriority,
      ActivityInsights, UsersInsights
    """
    activity_insights = record.get("ActivityInsights", {})
    if isinstance(activity_insights, str):
        import json
        try:
            activity_insights = json.loads(activity_insights)
        except (json.JSONDecodeError, TypeError):
            activity_insights = {}

    users_insights = record.get("UsersInsights", {})
    if isinstance(users_insights, str):
        import json
        try:
            users_insights = json.loads(users_insights)
        except (json.JSONDecodeError, TypeError):
            users_insights = {}

    priority = int(record.get("InvestigationPriority", 0))

    # Build human-readable anomaly list
    anomalies = []
    for field_name, description in ANOMALY_DESCRIPTIONS.items():
        if activity_insights.get(field_name) is True:
            anomalies.append(description)

    return UEBAContext(
        user=record.get("UserPrincipalName", ""),
        source_ip=record.get("SourceIPAddress", ""),
        investigation_priority=priority,
        risk_level=priority_to_risk(priority),
        anomalies=anomalies,
        is_first_time_country=activity_insights.get(
            "FirstTimeUserConnectedViaCountry", False
        ),
        is_first_time_app=activity_insights.get(
            "FirstTimeConnectionToApplication", False
        ),
        is_atypical_for_user=activity_insights.get(
            "ActivityAtypicalComparedToUserHistory", False
        ),
        is_uncommon_among_peers=activity_insights.get(
            "CountryUncommonlyConnectedFromAmongPeers", False
        ),
        raw_activity_insights=activity_insights,
        raw_users_insights=users_insights,
    )
```

---

## 6. STIX/TAXII Normalization Pipeline

For ingesting threat intelligence feeds into the knowledge base (Vector DB + Redis IOC cache).

### 6.1 STIX 2.1 Object Types

| STIX Type | ALUSKORT Mapping | Storage Target |
|---|---|---|
| `indicator` | IOC document | Redis (exact match cache) + Vector DB (semantic search) |
| `malware` | Software/tool document | Vector DB |
| `threat-actor` | Group document | Vector DB |
| `attack-pattern` | MITRE technique reference | Postgres (taxonomy) + Vector DB |
| `campaign` | Campaign/report document | Vector DB |
| `vulnerability` | CVE document | Postgres + Vector DB |
| `relationship` | Link between objects | Stored as properties on parent |
| `report` | TI report document | Vector DB |

### 6.2 STIX-to-Document Converter

```python
"""
ALUSKORT STIX 2.1 to Document Converter
Transforms STIX bundles into documents for Vector DB indexing and
IOC records for Redis cache population.
"""

import re
from datetime import datetime
from typing import Optional


def stix_indicator_to_ioc_doc(indicator: dict) -> Optional[dict]:
    """
    Convert a STIX 2.1 Indicator object to an ALUSKORT IOC document.
    """
    pattern = indicator.get("pattern", "")
    indicator_type, indicator_value = _parse_stix_pattern(pattern)

    if not indicator_value:
        return None

    # Map STIX confidence (0-100) to ALUSKORT confidence (0-100)
    confidence = indicator.get("confidence", 50)

    # Extract MITRE technique references from kill_chain_phases
    mitre_techniques = []
    for phase in indicator.get("kill_chain_phases", []):
        if phase.get("kill_chain_name") == "mitre-attack":
            # Phase name format: "technique-id--technique-name"
            phase_name = phase.get("phase_name", "")
            mitre_match = re.search(r'[Tt]\d{4}(?:\.\d{3})?', phase_name)
            if mitre_match:
                mitre_techniques.append(mitre_match.group())

    # Determine severity from labels
    labels = indicator.get("labels", [])
    severity = "medium"
    if "malicious-activity" in labels:
        severity = "high"
    elif "anomalous-activity" in labels:
        severity = "medium"
    elif "benign" in labels:
        severity = "low"

    valid_from = indicator.get("valid_from", "")
    valid_until = indicator.get("valid_until", "")

    return {
        "doc_id": f"stix-{indicator.get('id', '')}",
        "doc_type": "threat_intel_ioc",
        "indicator_type": indicator_type,
        "indicator_value": indicator_value,
        "confidence": confidence,
        "severity": severity,
        "mitre_techniques": mitre_techniques,
        "description": indicator.get("description", ""),
        "first_seen": valid_from,
        "last_seen": valid_until,
        "expiry": valid_until,
        "sources": [
            indicator.get("created_by_ref", "unknown")
        ],
        "labels": labels,
        "tags": labels,
        "stix_id": indicator.get("id", ""),
        "metadata": {
            "source_format": "stix-2.1",
            "ingested_at": datetime.utcnow().isoformat(),
            "stix_created": indicator.get("created", ""),
            "stix_modified": indicator.get("modified", ""),
        }
    }


def _parse_stix_pattern(pattern: str) -> tuple[str, str]:
    """
    Parse a STIX 2.1 indicator pattern to extract the indicator type and value.

    Examples:
    [ipv4-addr:value = '203.0.113.42']
    [domain-name:value = 'evil.example.com']
    [file:hashes.'SHA-256' = 'a1b2c3...']
    [url:value = 'https://evil.example.com/payload']
    [email-addr:value = 'phish@evil.com']
    """
    pattern_maps = {
        r"ipv4-addr:value\s*=\s*'([^']+)'": "ipv4",
        r"ipv6-addr:value\s*=\s*'([^']+)'": "ipv6",
        r"domain-name:value\s*=\s*'([^']+)'": "domain",
        r"file:hashes\.'SHA-256'\s*=\s*'([^']+)'": "file_hash_sha256",
        r"file:hashes\.'SHA-1'\s*=\s*'([^']+)'": "file_hash_sha1",
        r"file:hashes\.'MD5'\s*=\s*'([^']+)'": "file_hash_md5",
        r"url:value\s*=\s*'([^']+)'": "url",
        r"email-addr:value\s*=\s*'([^']+)'": "email",
    }

    for regex, ioc_type in pattern_maps.items():
        match = re.search(regex, pattern, re.IGNORECASE)
        if match:
            return ioc_type, match.group(1)

    return "unknown", ""


def stix_bundle_to_docs(bundle: dict) -> list[dict]:
    """
    Convert a complete STIX 2.1 bundle to ALUSKORT documents.
    Output documents are stored in Vector DB for semantic retrieval and
    IOC indicators are cached in Redis for exact-match lookups.
    """
    docs = []
    objects = bundle.get("objects", [])

    # Build relationship map for enrichment
    relationships = {}
    for obj in objects:
        if obj.get("type") == "relationship":
            source = obj.get("source_ref", "")
            target = obj.get("target_ref", "")
            rel_type = obj.get("relationship_type", "")
            if source not in relationships:
                relationships[source] = []
            relationships[source].append({
                "target": target,
                "type": rel_type,
            })

    for obj in objects:
        obj_type = obj.get("type", "")

        if obj_type == "indicator":
            doc = stix_indicator_to_ioc_doc(obj)
            if doc:
                # Enrich with relationships
                rels = relationships.get(obj.get("id", ""), [])
                doc["associated_campaigns"] = [
                    r["target"] for r in rels if r["type"] == "indicates"
                ]
                docs.append(doc)

        elif obj_type == "threat-actor":
            docs.append({
                "doc_id": f"stix-{obj.get('id', '')}",
                "doc_type": "threat_intel_report",
                "title": f"Threat Actor: {obj.get('name', '')}",
                "summary": obj.get("description", ""),
                "threat_actors": [obj.get("name", "")],
                "aliases": obj.get("aliases", []),
                "target_sectors": [
                    r.get("identity_class", "")
                    for r in obj.get("resource_level", [])
                ] if isinstance(obj.get("resource_level"), list) else [],
                "source": "STIX Feed",
                "publish_date": obj.get("created", ""),
                "tags": obj.get("labels", []),
                "stix_id": obj.get("id", ""),
            })

        elif obj_type == "malware":
            docs.append({
                "doc_id": f"stix-{obj.get('id', '')}",
                "doc_type": "threat_intel_report",
                "title": f"Malware: {obj.get('name', '')}",
                "summary": obj.get("description", ""),
                "malware_types": obj.get("malware_types", []),
                "source": "STIX Feed",
                "publish_date": obj.get("created", ""),
                "tags": obj.get("labels", []) + obj.get("malware_types", []),
                "stix_id": obj.get("id", ""),
            })

    return docs
```

### 6.3 IOC Cache Population (Redis)

After STIX conversion, IOC indicators are pushed to Redis for fast exact-match lookups during alert enrichment:

```python
"""
ALUSKORT IOC Cache Manager
Populates and queries the Redis IOC cache from STIX/TI documents.
"""

import json
import logging
from typing import Optional

logger = logging.getLogger(__name__)


class IOCCache:
    """Redis-backed IOC exact match cache."""

    def __init__(self, redis_client, default_ttl_hours: int = 72):
        self.redis = redis_client
        self.default_ttl = default_ttl_hours * 3600

    def populate_from_stix_docs(self, docs: list[dict]) -> int:
        """
        Load STIX IOC documents into Redis cache.
        Returns the number of IOCs cached.
        """
        cached = 0
        pipe = self.redis.pipeline()

        for doc in docs:
            if doc.get("doc_type") != "threat_intel_ioc":
                continue

            ioc_type = doc.get("indicator_type", "")
            ioc_value = doc.get("indicator_value", "")
            if not ioc_value:
                continue

            cache_key = f"ioc:{ioc_type}:{ioc_value}"
            cache_value = json.dumps({
                "type": ioc_type,
                "value": ioc_value,
                "severity": doc.get("severity", "medium"),
                "confidence": doc.get("confidence", 50),
                "description": doc.get("description", "")[:500],
                "mitre_techniques": doc.get("mitre_techniques", []),
                "sources": doc.get("sources", []),
                "expiry": doc.get("expiry", ""),
            })

            pipe.setex(cache_key, self.default_ttl, cache_value)
            cached += 1

        pipe.execute()
        logger.info(f"Cached {cached} IOC indicators in Redis")
        return cached

    def lookup(self, ioc_value: str, ioc_type: str = "") -> Optional[dict]:
        """
        Look up an IOC in the Redis cache.
        If ioc_type is not specified, tries common types.
        """
        if ioc_type:
            result = self.redis.get(f"ioc:{ioc_type}:{ioc_value}")
            if result:
                return json.loads(result)
            return None

        # Try common IOC types
        for try_type in ["ipv4", "domain", "file_hash_sha256",
                         "file_hash_sha1", "file_hash_md5", "url", "email"]:
            result = self.redis.get(f"ioc:{try_type}:{ioc_value}")
            if result:
                return json.loads(result)

        return None
```

> **Why Redis for IOC lookups instead of Vector DB?** IOC matching is key-value: "does this exact IP/hash/domain appear in our threat intel?" Vector search is wrong for this — you don't want "semantically similar" IPs. Redis gives sub-millisecond exact match with TTL-based expiry for stale indicators. Vector DB is reserved for semantic retrieval: "find past incidents similar to this one" or "find playbooks relevant to this technique."

---

## 7. Safe Query Builders (Adapter-Specific)

Agents generate queries dynamically based on extracted IOCs. This is the most dangerous part of the investigation pipeline — **query injection is a real risk** if IOC values are interpolated directly into query strings.

Each SIEM adapter includes its own query builder with injection-safe patterns. The core pipeline does not execute queries directly; it delegates to the adapter's query module.

### 7.1 KQL Query Builder (Sentinel Adapter)

This query builder is **Sentinel-adapter-specific**. It is used only when the investigation target is a Sentinel workspace. Equivalent builders exist for Elastic (EQL/Lucene) and Splunk (SPL) in their respective adapter modules.

```python
"""
ALUSKORT Safe KQL Query Builder (Sentinel Adapter)
Generates parameterised KQL queries to prevent injection attacks.

CRITICAL: Never concatenate IOC values directly into KQL strings.
Always use let-bindings with quoted string literals.

NOTE: This module lives in services/adapters/sentinel/query_builder.py
It is NOT imported by core pipeline code.
"""

import re
from typing import Optional


class KQLInjectionError(Exception):
    """Raised when a potential KQL injection is detected."""
    pass


# Characters that MUST be escaped in KQL string literals
KQL_ESCAPE_MAP = {
    "\\": "\\\\",
    "'": "\\'",
    "\n": "\\n",
    "\r": "\\r",
    "\t": "\\t",
}

# Patterns that should never appear in IOC values used in queries
INJECTION_PATTERNS = [
    r'\.\s*drop\b',
    r'\.\s*delete\b',
    r'\.\s*set\b',
    r'\|\s*where\b.*\btrue\b',  # | where true (bypass filter)
    r';\s*\.',                   # statement terminator followed by command
    r'//.*\n',                   # line comment injection
    r'/\*',                      # block comment injection
]
_injection_re = re.compile('|'.join(INJECTION_PATTERNS), re.IGNORECASE)


def escape_kql_string(value: str) -> str:
    """
    Escape a string for safe use in KQL string literals.
    This handles the KQL string escaping rules.
    """
    for char, escape in KQL_ESCAPE_MAP.items():
        value = value.replace(char, escape)
    return value


def validate_ioc_for_query(value: str, ioc_type: str) -> str:
    """
    Validate and sanitize an IOC value before use in a KQL query.
    Raises KQLInjectionError if the value looks malicious.
    """
    # Check for injection patterns
    if _injection_re.search(value):
        raise KQLInjectionError(
            f"Potential KQL injection detected in {ioc_type}: {value[:100]}"
        )

    # Type-specific validation
    if ioc_type in ("ipv4", "ip"):
        if not re.match(r'^[\d.]+$', value):
            raise KQLInjectionError(f"Invalid IPv4 format: {value}")
    elif ioc_type in ("sha256", "file_hash_sha256"):
        if not re.match(r'^[a-fA-F0-9]{64}$', value):
            raise KQLInjectionError(f"Invalid SHA256 format: {value}")
    elif ioc_type in ("sha1", "file_hash_sha1"):
        if not re.match(r'^[a-fA-F0-9]{40}$', value):
            raise KQLInjectionError(f"Invalid SHA1 format: {value}")
    elif ioc_type in ("md5", "file_hash_md5"):
        if not re.match(r'^[a-fA-F0-9]{32}$', value):
            raise KQLInjectionError(f"Invalid MD5 format: {value}")
    elif ioc_type == "domain":
        if not re.match(
            r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$',
            value
        ):
            raise KQLInjectionError(f"Invalid domain format: {value}")

    return escape_kql_string(value)


def build_ioc_lookup_query(
    ioc_value: str,
    ioc_type: str,
    lookback_hours: int = 24,
    tables: Optional[list[str]] = None,
) -> str:
    """
    Build a safe KQL query to look up an IOC across multiple tables.

    Uses let-bindings to parameterise the IOC value, preventing injection.
    """
    safe_value = validate_ioc_for_query(ioc_value, ioc_type)

    if tables is None:
        tables = ["SigninLogs", "CommonSecurityLog", "SecurityAlert"]

    # Build union subqueries based on IOC type
    subqueries = []

    for table in tables:
        if ioc_type in ("ipv4", "ip"):
            subquery = _build_ip_subquery(table, lookback_hours)
        elif ioc_type in ("sha256", "sha1", "md5",
                          "file_hash_sha256", "file_hash_sha1", "file_hash_md5"):
            subquery = _build_hash_subquery(table, lookback_hours)
        elif ioc_type == "domain":
            subquery = _build_domain_subquery(table, lookback_hours)
        elif ioc_type == "email":
            subquery = _build_email_subquery(table, lookback_hours)
        else:
            subquery = _build_generic_subquery(table, lookback_hours)

        if subquery:
            subqueries.append(subquery)

    if not subqueries:
        return ""

    union_body = ",\n    ".join(subqueries)

    return f"""let targetIOC = '{safe_value}';
let lookback = {lookback_hours}h;
union
    {union_body}
| sort by TimeGenerated desc
| take 100"""


def _build_ip_subquery(table: str, lookback_hours: int) -> Optional[str]:
    """Build IP lookup subquery for a specific table."""
    ip_columns = {
        "SigninLogs": "IPAddress",
        "CommonSecurityLog": "SourceIP",  # Also check DestinationIP
        "SecurityAlert": "Entities",
        "DeviceNetworkEvents": "RemoteIP",
        "AzureDiagnostics": "CallerIPAddress",
        "AADNonInteractiveUserSignInLogs": "IPAddress",
    }
    col = ip_columns.get(table)
    if not col:
        return None

    if table == "CommonSecurityLog":
        return (f"({table}"
                f"\n        | where TimeGenerated > ago(lookback)"
                f"\n        | where SourceIP == targetIOC or DestinationIP == targetIOC"
                f"\n        | project TimeGenerated, SourceTable='{table}', "
                f"Detail=Activity, SourceIP, DestinationIP)")
    elif table == "SecurityAlert":
        return (f"({table}"
                f"\n        | where TimeGenerated > ago(lookback)"
                f"\n        | where Entities has targetIOC"
                f"\n        | project TimeGenerated, SourceTable='{table}', "
                f"Detail=AlertName)")
    else:
        return (f"({table}"
                f"\n        | where TimeGenerated > ago(lookback)"
                f"\n        | where {col} == targetIOC"
                f"\n        | project TimeGenerated, SourceTable='{table}', "
                f"Detail=tostring('{col}'))")


def _build_hash_subquery(table: str, lookback_hours: int) -> Optional[str]:
    """Build file hash lookup subquery."""
    hash_tables = {
        "SecurityAlert": (
            f"(SecurityAlert"
            f"\n        | where TimeGenerated > ago(lookback)"
            f"\n        | where Entities has targetIOC"
            f"\n        | project TimeGenerated, SourceTable='SecurityAlert', "
            f"Detail=AlertName)"
        ),
        "DeviceFileEvents": (
            f"(DeviceFileEvents"
            f"\n        | where TimeGenerated > ago(lookback)"
            f"\n        | where SHA256 == targetIOC or SHA1 == targetIOC or MD5 == targetIOC"
            f"\n        | project TimeGenerated, SourceTable='DeviceFileEvents', "
            f"Detail=FileName)"
        ),
        "ThreatIntelligenceIndicator": (
            f"(ThreatIntelligenceIndicator"
            f"\n        | where TimeGenerated > ago(30d)"
            f"\n        | where FileHashValue == targetIOC"
            f"\n        | project TimeGenerated, SourceTable='ThreatIntelligenceIndicator', "
            f"Detail=Description)"
        ),
    }
    return hash_tables.get(table)


def _build_domain_subquery(table: str, lookback_hours: int) -> Optional[str]:
    """Build domain lookup subquery."""
    domain_tables = {
        "CommonSecurityLog": (
            f"(CommonSecurityLog"
            f"\n        | where TimeGenerated > ago(lookback)"
            f"\n        | where RequestURL has targetIOC or DestinationHostName has targetIOC"
            f"\n        | project TimeGenerated, SourceTable='CommonSecurityLog', "
            f"Detail=Activity)"
        ),
        "DeviceNetworkEvents": (
            f"(DeviceNetworkEvents"
            f"\n        | where TimeGenerated > ago(lookback)"
            f"\n        | where RemoteUrl has targetIOC"
            f"\n        | project TimeGenerated, SourceTable='DeviceNetworkEvents', "
            f"Detail=RemoteUrl)"
        ),
        "ThreatIntelligenceIndicator": (
            f"(ThreatIntelligenceIndicator"
            f"\n        | where TimeGenerated > ago(30d)"
            f"\n        | where DomainName == targetIOC"
            f"\n        | project TimeGenerated, SourceTable='ThreatIntelligenceIndicator', "
            f"Detail=Description)"
        ),
    }
    return domain_tables.get(table)


def _build_email_subquery(table: str, lookback_hours: int) -> Optional[str]:
    """Build email address lookup subquery."""
    if table == "EmailEvents":
        return (f"(EmailEvents"
                f"\n        | where TimeGenerated > ago(lookback)"
                f"\n        | where SenderFromAddress == targetIOC or RecipientEmailAddress == targetIOC"
                f"\n        | project TimeGenerated, SourceTable='EmailEvents', "
                f"Detail=Subject)")
    return None


def _build_generic_subquery(table: str, lookback_hours: int) -> Optional[str]:
    """Fallback: search for IOC value in alert entities."""
    if table == "SecurityAlert":
        return (f"(SecurityAlert"
                f"\n        | where TimeGenerated > ago(lookback)"
                f"\n        | where Entities has targetIOC"
                f"\n        | project TimeGenerated, SourceTable='SecurityAlert', "
                f"Detail=AlertName)")
    return None
```

> **Why `let` bindings instead of f-string interpolation?** KQL `let` statements define the variable once at the top of the query. The variable reference (`targetIOC`) is substituted by the KQL engine, not by Python string formatting. Combined with input validation and escaping, this provides defense-in-depth against injection. An attacker who manages to inject `'; .drop table` into an IOC value would hit the single-quote escaping, the injection pattern regex, and the type-specific format validation before ever reaching KQL.

### 7.2 Equivalent Query Builders (Other Adapters)

Each adapter has its own query builder with equivalent injection protections:

| Adapter | Query Language | Builder Location | Injection Protection |
|---|---|---|---|
| **Sentinel** | KQL | `services/adapters/sentinel/query_builder.py` | `let`-bindings, format validation, pattern blocklist |
| **Elastic** | EQL / Lucene | `services/adapters/elastic/query_builder.py` | Parameterised queries via Elasticsearch DSL, input validation |
| **Splunk** | SPL | `services/adapters/splunk/query_builder.py` | `inputlookup` with validated CSV, format validation, pattern blocklist |

The core pipeline never imports these directly. The adapter's query module is called by the investigation pipeline via the adapter interface.

---

## 8. Alert Preprocessing Pipeline

The complete flow from raw alert (any source) to agent-ready context package, via the message bus.

```
Adapter (Sentinel / Elastic / Splunk / ...)
    │
    │ Publishes CanonicalAlert to:
    ▼
alerts.raw (Kafka topic)
    │
    │ Entity Parser Service consumes:
    ├── 1. PARSE ALERT METADATA
    │   Extract: title, severity, tactics, techniques,
    │   product, source, timestamp from CanonicalAlert
    │
    ├── 2. PARSE ENTITIES (Section 3)
    │   Extract: Accounts, Hosts, IPs, Files, Processes, URLs, Hashes
    │   Sanitize all values
    │   Resolve $ref cross-references
    │   Source-aware: Sentinel JSON, Elastic raw_payload, regex fallback
    │
    │ Publishes enriched alert to:
    ▼
alerts.normalized (Kafka topic)
    │
    │ Enrichment Service consumes:
    ├── 3. CHECK FP PATTERN STORE
    │   Query Postgres/Redis for matching FP patterns
    │   If match with confidence > 0.90:
    │       → Auto-close alert
    │       → Log decision to audit.events
    │       → STOP (no LLM call needed)
    │
    ├── 4. ENRICH ENTITIES
    │   For each extracted IOC:
    │       → Check Redis IOC cache (exact match, sub-ms)
    │       → Check Vector DB for TI context (semantic search if no exact match)
    │       → Query UEBA via adapter for involved users (Section 5)
    │       → Query Postgres/Graph DB for asset criticality
    │
    ├── 5. BUILD CONTEXT PACKAGE
    │   Assemble all parsed + enriched data into structured format
    │   for agent consumption (see below)
    │
    │ Publishes enriched incident to:
    ▼
incidents.enriched (Kafka topic)
    │
    │ Priority Queue Router reads severity and routes to:
    ▼
jobs.llm.priority.{critical|high|normal|low} (Kafka topics)
    │
    │ Agent Orchestrator consumes from priority queues:
    └── 6. DISPATCH TO AGENT
        Route to IOC Extractor → Context Enricher → Reasoning Agent
        (via LangGraph investigation graph)
        See docs/ai-system-design.md Section 4 for orchestration details
```

### 8.1 Priority Queue Routing

After enrichment, alerts are routed to severity-based LLM work queues. This prevents low-priority alert floods from starving critical investigations.

```python
"""
ALUSKORT Priority Queue Router
Routes enriched alerts to severity-appropriate LLM work queues.
See docs/ai-system-design.md Section 6.3 for QueueConfig and TENANT_QUOTAS.
"""

import json
import logging
from confluent_kafka import Consumer, Producer, KafkaError

logger = logging.getLogger(__name__)

# Severity to queue topic mapping
SEVERITY_QUEUE_MAP = {
    "critical": "jobs.llm.priority.critical",
    "high": "jobs.llm.priority.high",
    "medium": "jobs.llm.priority.normal",
    "low": "jobs.llm.priority.low",
    "informational": "jobs.llm.priority.low",
}


class PriorityQueueRouter:
    """Routes enriched incidents to severity-appropriate LLM queues."""

    def __init__(self, kafka_bootstrap: str):
        self.consumer = Consumer({
            "bootstrap.servers": kafka_bootstrap,
            "group.id": "aluskort.priority-router",
            "auto.offset.reset": "earliest",
            "enable.auto.commit": False,
        })
        self.producer = Producer({
            "bootstrap.servers": kafka_bootstrap,
        })
        self.consumer.subscribe(["incidents.enriched"])

    def run(self) -> None:
        """Main consumer loop — read enriched incidents, route to priority queues."""
        logger.info("Priority queue router started")
        while True:
            msg = self.consumer.poll(timeout=1.0)
            if msg is None:
                continue
            if msg.error():
                if msg.error().code() == KafkaError._PARTITION_EOF:
                    continue
                logger.error(f"Consumer error: {msg.error()}")
                continue

            try:
                incident = json.loads(msg.value().decode("utf-8"))
                severity = incident.get("severity", "medium").lower()
                target_topic = SEVERITY_QUEUE_MAP.get(severity, "jobs.llm.priority.normal")

                self.producer.produce(
                    topic=target_topic,
                    key=incident.get("alert_id", "").encode("utf-8"),
                    value=json.dumps(incident).encode("utf-8"),
                )
                self.producer.flush()
                self.consumer.commit(msg)

                logger.info(
                    f"Routed alert {incident.get('alert_id')} "
                    f"(severity={severity}) to {target_topic}"
                )

            except Exception as e:
                logger.error(f"Error routing incident: {e}", exc_info=True)
                self.consumer.commit(msg)
```

> **Why priority queues instead of flat rate limiting?** Flat rate limiting ("50 queries/5 minutes") is exploitable -- an attacker can flood low-severity alerts to starve critical ones. Priority queues ensure critical alerts always get processed first: the drain order is `critical > high > normal > low`. Under load, low-priority jobs can be delayed, batched, or downgraded to Tier 0 models. See `docs/ai-system-design.md` Section 6.3 for `QueueConfig` and `TENANT_QUOTAS` details.

### 8.2 Context Package Schema

The structured data package that the Reasoning Agent receives:

```python
@dataclass
class AlertContextPackage:
    """Complete context package for agent consumption."""

    # Alert metadata
    alert_id: str
    alert_name: str
    alert_severity: str          # "critical", "high", "medium", "low", "informational"
    alert_product: str           # Source product name (any SIEM)
    alert_source: str            # "sentinel", "elastic", "splunk", etc.
    tactics: list[str]           # MITRE tactics
    techniques: list[str]        # MITRE technique IDs
    timestamp: str
    description: str
    tenant_id: str               # Multi-tenant identifier

    # Parsed entities (Section 3 output)
    entities: AlertEntities

    # TI enrichment (from Redis IOC cache + Vector DB)
    ti_matches: list[dict]       # IOCs found in TI store
    ti_match_count: int

    # UEBA context (Section 5 output)
    ueba_context: list[UEBAContext]  # One per involved user

    # Organisational context (from Postgres + Graph DB)
    asset_criticality: dict[str, str]  # entity_name -> "critical"/"high"/"medium"/"low"
    is_vip_user: bool
    in_maintenance_window: bool

    # Knowledge retrieval (from Vector DB)
    relevant_playbooks: list[dict]     # From playbook collection
    relevant_mitre: list[dict]         # From ATT&CK/ATLAS collection
    similar_past_incidents: list[dict] # From incident memory

    # CTEM context (from Postgres, if available)
    ctem_exposures: list[dict]         # Related CTEM findings for affected assets

    # FP check result
    fp_pattern_match: Optional[dict]   # If matched, contains pattern details
    fp_confidence: float               # 0.0-1.0

    # Risk state (explicit — see docs/ai-system-design.md Section 9)
    risk_state: str                    # "unknown", "no_baseline", "low", "medium", "high"

    # Cost tracking
    queries_executed: int
    estimated_query_cost: str          # "low"/"medium"/"high"
```

---

## 9. Enrichment Service

The enrichment service consumes from `alerts.normalized` and produces `incidents.enriched`. It handles TI lookups, UEBA correlation, asset criticality, and FP pattern matching.

### 9.1 Enrichment Service Architecture

```
alerts.normalized (Kafka topic)
    │
    ▼
┌──────────────────────────────────────────────┐
│  Enrichment Service                          │
│  (Kubernetes deployment)                     │
│                                              │
│  Consumer group: aluskort.enrichment         │
│                                              │
│  Enrichment steps (parallel where possible): │
│  ┌─────────────┐  ┌──────────────────────┐   │
│  │ Redis IOC   │  │ UEBA Query           │   │
│  │ Cache Lookup│  │ (via adapter)        │   │
│  └──────┬──────┘  └──────────┬───────────┘   │
│         │                    │               │
│  ┌──────┴──────┐  ┌─────────┴────────────┐   │
│  │ Vector DB   │  │ Asset Criticality    │   │
│  │ TI Search   │  │ (Postgres/Graph DB)  │   │
│  └──────┬──────┘  └──────────┬───────────┘   │
│         │                    │               │
│         └────────┬───────────┘               │
│                  │                           │
│         ┌────────┴────────┐                  │
│         │ FP Pattern Check│                  │
│         │ (Redis/Postgres)│                  │
│         └────────┬────────┘                  │
│                  │                           │
│         ┌────────┴────────┐                  │
│         │ Build Context   │                  │
│         │ Package         │                  │
│         └─────────────────┘                  │
└──────────────────────────────────────────────┘
    │
    ▼
incidents.enriched (Kafka topic)
```

### 9.2 Enrichment Service Consumer

```python
"""
ALUSKORT Enrichment Service
Consumes parsed alerts from alerts.normalized, enriches with TI/UEBA/asset
context, and publishes to incidents.enriched.
"""

import json
import logging
from confluent_kafka import Consumer, Producer, KafkaError
from typing import Optional

logger = logging.getLogger(__name__)


class EnrichmentService:
    """Microservice that enriches parsed alerts with TI, UEBA, and asset context."""

    def __init__(
        self,
        kafka_bootstrap: str,
        ioc_cache,          # IOCCache instance (Redis)
        ueba_adapter,       # Adapter-specific UEBA query interface
        asset_store,        # Postgres/Graph DB asset lookup
        fp_store,           # FP pattern store (Redis/Postgres)
        vector_db,          # Vector DB for semantic TI search
    ):
        self.consumer = Consumer({
            "bootstrap.servers": kafka_bootstrap,
            "group.id": "aluskort.enrichment",
            "auto.offset.reset": "earliest",
            "enable.auto.commit": False,
        })
        self.producer = Producer({
            "bootstrap.servers": kafka_bootstrap,
        })
        self.consumer.subscribe(["alerts.normalized"])
        self.ioc_cache = ioc_cache
        self.ueba_adapter = ueba_adapter
        self.asset_store = asset_store
        self.fp_store = fp_store
        self.vector_db = vector_db

    def run(self) -> None:
        """Main consumer loop."""
        logger.info("Enrichment service started, consuming from alerts.normalized")
        while True:
            msg = self.consumer.poll(timeout=1.0)
            if msg is None:
                continue
            if msg.error():
                if msg.error().code() == KafkaError._PARTITION_EOF:
                    continue
                logger.error(f"Consumer error: {msg.error()}")
                continue

            try:
                alert_data = json.loads(msg.value().decode("utf-8"))
                enriched = self._enrich(alert_data)

                # Check for FP pattern match — short-circuit if high confidence
                fp_match = enriched.get("fp_pattern_match")
                if fp_match and enriched.get("fp_confidence", 0) > 0.90:
                    # Auto-close: publish to audit.events, skip LLM queue
                    self._publish_auto_close(enriched)
                    self.consumer.commit(msg)
                    continue

                # Publish enriched incident
                self.producer.produce(
                    topic="incidents.enriched",
                    key=alert_data.get("alert_id", "").encode("utf-8"),
                    value=json.dumps(enriched).encode("utf-8"),
                )
                self.producer.flush()
                self.consumer.commit(msg)

            except Exception as e:
                logger.error(f"Error enriching alert: {e}", exc_info=True)
                self.consumer.commit(msg)

    def _enrich(self, alert_data: dict) -> dict:
        """Apply all enrichment steps to a parsed alert."""
        parsed_entities = alert_data.get("parsed_entities", {})
        raw_iocs = parsed_entities.get("raw_iocs", [])

        # Step 1: IOC lookup in Redis cache
        ti_matches = []
        for ioc in raw_iocs:
            match = self.ioc_cache.lookup(ioc)
            if match:
                ti_matches.append(match)

        alert_data["ti_matches"] = ti_matches
        alert_data["ti_match_count"] = len(ti_matches)

        # Step 2: UEBA context for involved users
        ueba_contexts = []
        for account in parsed_entities.get("accounts", []):
            upn = account.get("primary_value", "")
            if upn:
                ueba_record = self.ueba_adapter.query_user(upn)
                if ueba_record:
                    ueba_ctx = extract_ueba_context(ueba_record)
                    ueba_contexts.append({
                        "user": ueba_ctx.user,
                        "risk_level": ueba_ctx.risk_level,
                        "investigation_priority": ueba_ctx.investigation_priority,
                        "anomalies": ueba_ctx.anomalies,
                    })

        alert_data["ueba_context"] = ueba_contexts

        # Step 3: Asset criticality
        asset_criticality = {}
        for host in parsed_entities.get("hosts", []):
            hostname = host.get("primary_value", "")
            if hostname:
                criticality = self.asset_store.get_criticality(hostname)
                if criticality:
                    asset_criticality[hostname] = criticality

        alert_data["asset_criticality"] = asset_criticality

        # Step 4: FP pattern check
        fp_match = self.fp_store.check_pattern(alert_data)
        alert_data["fp_pattern_match"] = fp_match.get("pattern") if fp_match else None
        alert_data["fp_confidence"] = fp_match.get("confidence", 0.0) if fp_match else 0.0

        return alert_data

    def _publish_auto_close(self, enriched: dict) -> None:
        """Publish auto-close decision to audit.events topic."""
        audit_event = {
            "event_type": "auto_close",
            "alert_id": enriched.get("alert_id"),
            "reason": "FP pattern match",
            "fp_pattern": enriched.get("fp_pattern_match"),
            "fp_confidence": enriched.get("fp_confidence"),
            "tenant_id": enriched.get("tenant_id"),
        }
        self.producer.produce(
            topic="audit.events",
            key=enriched.get("alert_id", "").encode("utf-8"),
            value=json.dumps(audit_event).encode("utf-8"),
        )
        self.producer.flush()
        logger.info(
            f"Auto-closed alert {enriched.get('alert_id')} "
            f"(FP confidence: {enriched.get('fp_confidence')})"
        )
```

---

## 10. CTEM Normaliser Service

The CTEM (Continuous Threat Exposure Management) normaliser is a dedicated microservice that consumes raw CTEM findings from source-specific topics and produces normalised findings on `ctem.normalized`.

```
ctem.raw.wiz          ──┐
ctem.raw.snyk         ──┼──► CTEM Normaliser Service ──► ctem.normalized
ctem.raw.garak        ──┤                                     │
ctem.raw.art          ──┘                                     ▼
                                                        Postgres
                                                    (ON CONFLICT upsert)
```

Each source has a per-source normaliser module (see `docs/ai-system-design.md` Section 14 for the microservices structure). The normaliser applies idempotent Postgres upserts keyed on `exposure_key` to prevent duplicate findings.

```python
"""
ALUSKORT CTEM Normaliser Service
Consumes raw CTEM findings from ctem.raw.<source> topics,
normalises them into a canonical exposure format, and upserts to Postgres.
"""

import json
import logging
from confluent_kafka import Consumer, KafkaError

logger = logging.getLogger(__name__)


class CTEMNormaliserService:
    """Microservice that normalises CTEM findings from multiple sources."""

    def __init__(self, kafka_bootstrap: str, postgres_pool):
        self.consumer = Consumer({
            "bootstrap.servers": kafka_bootstrap,
            "group.id": "aluskort.ctem-normaliser",
            "auto.offset.reset": "earliest",
            "enable.auto.commit": False,
        })
        self.postgres = postgres_pool
        # Subscribe to all ctem.raw.* topics using regex
        self.consumer.subscribe(["^ctem\\.raw\\..*"])

    def run(self) -> None:
        """Main consumer loop."""
        logger.info("CTEM normaliser started, consuming from ctem.raw.* topics")
        while True:
            msg = self.consumer.poll(timeout=1.0)
            if msg is None:
                continue
            if msg.error():
                if msg.error().code() == KafkaError._PARTITION_EOF:
                    continue
                logger.error(f"Consumer error: {msg.error()}")
                continue

            try:
                topic = msg.topic()
                source = topic.replace("ctem.raw.", "")  # e.g., "wiz", "snyk"
                finding = json.loads(msg.value().decode("utf-8"))

                # Normalise based on source
                normalised = self._normalise(source, finding)
                if normalised:
                    self._upsert(normalised)

                self.consumer.commit(msg)

            except Exception as e:
                logger.error(f"Error normalising CTEM finding: {e}", exc_info=True)
                self.consumer.commit(msg)

    def _normalise(self, source: str, finding: dict) -> dict | None:
        """Route to source-specific normaliser."""
        # Each source has its own normaliser in services/ctem_normaliser/normalisers/
        # This is a simplified dispatch; production uses dynamic module loading.
        normalisers = {
            "wiz": self._normalise_wiz,
            "snyk": self._normalise_snyk,
        }
        normaliser = normalisers.get(source)
        if normaliser:
            return normaliser(finding)
        logger.warning(f"No normaliser for CTEM source: {source}")
        return None

    def _normalise_wiz(self, finding: dict) -> dict:
        """Normalise a Wiz finding to canonical exposure format."""
        return {
            "exposure_key": f"wiz-{finding.get('id', '')}",
            "source": "wiz",
            "title": finding.get("title", ""),
            "severity": finding.get("severity", "medium").lower(),
            "affected_asset": finding.get("resource", {}).get("name", ""),
            "asset_type": finding.get("resource", {}).get("type", ""),
            "description": finding.get("description", ""),
            "remediation": finding.get("remediation", ""),
            "first_seen": finding.get("createdAt", ""),
            "last_seen": finding.get("updatedAt", ""),
            "status": finding.get("status", "open"),
        }

    def _normalise_snyk(self, finding: dict) -> dict:
        """Normalise a Snyk finding to canonical exposure format."""
        return {
            "exposure_key": f"snyk-{finding.get('id', '')}",
            "source": "snyk",
            "title": finding.get("title", ""),
            "severity": finding.get("severity", "medium").lower(),
            "affected_asset": finding.get("package", {}).get("name", ""),
            "asset_type": "dependency",
            "description": finding.get("description", ""),
            "remediation": finding.get("fixedIn", ""),
            "first_seen": finding.get("disclosed", ""),
            "last_seen": finding.get("updated", ""),
            "status": "open",
        }

    def _upsert(self, normalised: dict) -> None:
        """Idempotent upsert to Postgres, keyed on exposure_key."""
        # Uses ON CONFLICT (exposure_key) DO UPDATE
        # This prevents duplicate findings from re-ingestion
        with self.postgres.connection() as conn:
            with conn.cursor() as cur:
                cur.execute("""
                    INSERT INTO ctem_exposures
                        (exposure_key, source, title, severity,
                         affected_asset, asset_type, description,
                         remediation, first_seen, last_seen, status)
                    VALUES
                        (%(exposure_key)s, %(source)s, %(title)s, %(severity)s,
                         %(affected_asset)s, %(asset_type)s, %(description)s,
                         %(remediation)s, %(first_seen)s, %(last_seen)s, %(status)s)
                    ON CONFLICT (exposure_key)
                    DO UPDATE SET
                        severity = EXCLUDED.severity,
                        last_seen = EXCLUDED.last_seen,
                        status = EXCLUDED.status,
                        description = EXCLUDED.description,
                        remediation = EXCLUDED.remediation
                """, normalised)
            conn.commit()
```

---

## 11. Data Quality & Validation

### 11.1 Common Data Quality Issues

| Issue | Where It Occurs | Impact | Mitigation |
|---|---|---|---|
| **Empty Entities field** | Custom analytics rules, non-Sentinel sources | IOC Extractor gets nothing | Fall back to regex extraction from description / raw_payload |
| **Malformed JSON in Entities** | Rare, usually from third-party connectors | Parse failure | Graceful degradation to regex fallback |
| **Duplicate alerts** | SIEM fires multiple alerts for same event | Agent processes same IOC twice | Dedup by alert fingerprint (title + entities hash) within 5-min window, using Redis |
| **Stale TI data** | Expired indicators in Redis cache / Vector DB | False positive TI matches | Check TTL on Redis keys, `expiry` field on Vector DB docs |
| **Missing UEBA data** | UEBA not enabled, user not baselined, or adapter unavailable | No behavioural context | Handle gracefully - set `risk_state = "no_baseline"`, don't block processing |
| **CEF field inconsistency** | Different vendors use different field meanings | Misinterpretation of network events | Vendor-specific parsing (Section 4) |
| **Timezone issues** | Some sources send local time, not UTC | Timeline reconstruction errors | Normalise all timestamps to UTC, flag non-UTC sources |
| **Kafka consumer lag** | High alert volume, slow enrichment | Processing delay | Monitor consumer group lag, auto-scale enrichment service replicas |
| **Adapter outage** | SIEM API down or unreachable | No new alerts ingested | Health checks on adapters, alert on ingest gap > threshold |

### 11.2 Data Validation Pipeline

```python
"""
ALUSKORT Data Validation
Pre-flight checks before data enters the agent pipeline.
Runs within the Entity Parser Service before publishing to alerts.normalized.
"""

from dataclasses import dataclass


@dataclass
class ValidationResult:
    """Result of data validation."""
    valid: bool
    warnings: list[str]
    errors: list[str]
    data_quality_score: float  # 0.0-1.0


def validate_alert(alert: dict) -> ValidationResult:
    """
    Validate a CanonicalAlert record before processing.
    Returns quality score and any issues found.
    """
    warnings = []
    errors = []
    score = 1.0

    # Required fields (canonical schema)
    required = ["alert_id", "title", "timestamp"]
    for field_name in required:
        if not alert.get(field_name):
            errors.append(f"Missing required field: {field_name}")
            score -= 0.3

    # Source identification
    source = alert.get("source", "")
    if not source:
        warnings.append("Missing source field — cannot identify adapter")
        score -= 0.1

    # Entities quality
    entities_raw = alert.get("entities_raw", "")
    if not entities_raw or entities_raw == "[]":
        warnings.append("Empty entities_raw field - IOC extraction will use fallback")
        score -= 0.2
    elif not entities_raw.startswith("["):
        warnings.append("entities_raw doesn't look like JSON array")
        score -= 0.1

    # MITRE mapping
    tactics = alert.get("tactics", [])
    techniques = alert.get("techniques", [])
    if not tactics and not techniques:
        warnings.append("No MITRE tactics or techniques mapped to this alert")
        score -= 0.1

    # Severity
    severity = alert.get("severity", "")
    if severity not in ("critical", "high", "medium", "low", "informational"):
        warnings.append(f"Unexpected severity value: {severity}")

    # Timestamp validation
    timestamp = alert.get("timestamp", "")
    if timestamp and "T" not in str(timestamp):
        warnings.append("Timestamp may not be in ISO 8601 format")

    # Tenant ID
    tenant_id = alert.get("tenant_id", "")
    if not tenant_id:
        warnings.append("Missing tenant_id — will use 'default'")

    return ValidationResult(
        valid=len(errors) == 0,
        warnings=warnings,
        errors=errors,
        data_quality_score=max(0.0, score),
    )
```

---

## 12. Pipeline Infrastructure

### 12.1 Microservices Architecture

```
Kubernetes Cluster (or Nomad, or docker-compose for lab)
│
├── Adapters (one Deployment per SIEM source)
│   ├── sentinel-adapter
│   │   Subscribes to: Event Hub / Log Analytics polling
│   │   Publishes to: alerts.raw
│   │   Replicas: 1-2 (based on alert volume)
│   │
│   ├── elastic-adapter
│   │   Subscribes to: Elastic webhook / Watcher
│   │   Publishes to: alerts.raw
│   │   Replicas: 1-2
│   │
│   └── splunk-adapter (optional)
│       Subscribes to: Splunk webhook / HEC
│       Publishes to: alerts.raw
│       Replicas: 1-2
│
├── Entity Parser Service (Deployment)
│   Consumer group: aluskort.entity-parser
│   Consumes: alerts.raw
│   Publishes: alerts.normalized
│   Replicas: 2-4 (auto-scaled on consumer lag)
│
├── Enrichment Service (Deployment)
│   Consumer group: aluskort.enrichment
│   Consumes: alerts.normalized
│   Publishes: incidents.enriched, audit.events
│   Replicas: 2-4 (auto-scaled on consumer lag)
│   Dependencies: Redis, Postgres, Vector DB, UEBA adapter
│
├── Priority Queue Router (Deployment)
│   Consumer group: aluskort.priority-router
│   Consumes: incidents.enriched
│   Publishes: jobs.llm.priority.{critical,high,normal,low}
│   Replicas: 1-2
│
├── CTEM Normaliser (Deployment)
│   Consumer group: aluskort.ctem-normaliser
│   Consumes: ctem.raw.* (regex subscription)
│   Publishes: ctem.normalized
│   Writes: Postgres (ctem_exposures table)
│   Replicas: 1-2
│
├── TI Ingester (CronJob - hourly)
│   Pulls STIX/TAXII feeds
│   Converts to documents (Section 6)
│   Indexes into Vector DB + Redis IOC cache
│
├── MITRE Updater (CronJob - weekly)
│   Checks for new MITRE ATT&CK/ATLAS version
│   Full re-index if new version detected
│
└── Orchestrator + Agent Graph (Deployment)
    Consumer group: aluskort.orchestrator
    Consumes: jobs.llm.priority.{critical,high,normal,low}
    (Drain order: critical first, low last)
    Writes: Postgres (investigation state), audit.events
    See docs/ai-system-design.md Section 4
```

### 12.2 Message Bus Configuration

```
Message Bus (Kafka / Redpanda / NATS)
│
├── Topic: alerts.raw
│   Partitions: 4 (partitioned by tenant_id)
│   Retention: 7 days (enables replay for debugging)
│   Consumer groups: aluskort.entity-parser
│
├── Topic: alerts.normalized
│   Partitions: 4 (partitioned by tenant_id)
│   Retention: 7 days
│   Consumer groups: aluskort.enrichment
│
├── Topic: incidents.enriched
│   Partitions: 4 (partitioned by tenant_id)
│   Retention: 7 days
│   Consumer groups: aluskort.priority-router
│
├── Topic: jobs.llm.priority.critical
│   Partitions: 2
│   Retention: 3 days
│   Consumer groups: aluskort.orchestrator
│
├── Topic: jobs.llm.priority.high
│   Partitions: 2
│   Retention: 3 days
│   Consumer groups: aluskort.orchestrator
│
├── Topic: jobs.llm.priority.normal
│   Partitions: 4
│   Retention: 3 days
│   Consumer groups: aluskort.orchestrator
│
├── Topic: jobs.llm.priority.low
│   Partitions: 2
│   Retention: 3 days
│   Consumer groups: aluskort.orchestrator
│
├── Topic: ctem.raw.<source>
│   Partitions: 2 per source
│   Retention: 7 days
│   Consumer groups: aluskort.ctem-normaliser
│
├── Topic: ctem.normalized
│   Partitions: 2
│   Retention: 7 days
│
├── Topic: actions.pending
│   Partitions: 2
│   Retention: 7 days
│   Consumer groups: aluskort.response-agent
│
└── Topic: audit.events
    Partitions: 4
    Retention: 90 days (immutable audit trail)
    Consumer groups: aluskort.audit-writer (to Postgres for long-term storage)
```

> **Why 7-day retention on pipeline topics?** Unlike Event Hub's 1-day retention, multi-day retention enables replay from any offset for debugging, reprocessing after a bug fix, or backfilling after a consumer outage. The cost of retention is negligible for the data volumes involved (< 10 GB/day per tenant). The `audit.events` topic uses 90-day retention as the primary audit trail — long-term audit data is also written to Postgres.

### 12.3 Error Handling

| Failure | Detection | Recovery |
|---|---|---|
| **Adapter delivery failure** | Health check on adapter pod, ingest gap alert | Adapter restarts automatically (Kubernetes). Kafka retention preserves messages. Backfill via adapter's polling mode if gap detected. |
| **Entity parse failure** | `parse_errors` in AlertEntities, consumer error logs | Log error, continue with regex fallback IOC extraction. Alert is published to `alerts.normalized` with degraded quality score. |
| **Enrichment service crash** | Kafka consumer group lag spike, pod restart count | Kubernetes auto-restarts. Messages accumulate in `alerts.normalized` topic (7-day retention). On recovery, consumer resumes from last committed offset. |
| **Redis IOC cache unavailable** | Redis health check failure | Fall back to Postgres IOC lookup table. Higher latency but correct results. Log "REDIS_UNAVAILABLE" in enrichment output. |
| **Vector DB unavailable** | Vector DB health check failure | Skip semantic TI search, rely on Redis exact match only. Log "VECTOR_DB_UNAVAILABLE". Reduced enrichment quality but functional. |
| **UEBA adapter unreachable** | Query timeout to UEBA source | Set `risk_state = "no_baseline"` for all entities. Never treat absence of UEBA data as "low risk". |
| **TI feed unreachable** | HTTP timeout on STIX/TAXII endpoint | Use cached data in Redis/Vector DB, retry on next scheduled CronJob run |
| **LLM rate limit** | HTTP 429 from LLM provider | Exponential backoff with jitter. Messages stay in priority queue topic until processed. Per-tenant quota enforcement prevents starvation. |
| **Kafka broker down** | Broker health check, producer delivery failure | Kafka replication (min.insync.replicas=2). If all brokers down, adapters buffer locally and retry. |
| **Consumer group lag** | Consumer lag monitoring (Prometheus/Grafana) | Auto-scale consumer replicas. Alert if lag exceeds threshold (e.g., > 1000 messages for critical queue). |

---

## 13. Data Flow Summary

```
                          ALERT PIPELINE (real-time)

                  ┌──────────────────────────┐
                  │ SIEM Adapters            │
                  │ (Sentinel, Elastic, ...) │
                  └─────────┬────────────────┘
                            │ CanonicalAlert
                            ▼
                     alerts.raw (Kafka)
                            │
                            ▼
                  ┌──────────────────────────┐
                  │ Entity Parser Service    │
                  │                          │
                  │ parse_alert_entities()   │
                  │ Structured extraction    │
                  │ Input sanitization       │
                  │ validate_alert()         │
                  └─────────┬────────────────┘
                            │
                            ▼
                  alerts.normalized (Kafka)
                            │
                            ▼
                  ┌──────────────────────────┐
                  │ Enrichment Service       │
                  │                          │
                  │ Redis IOC cache lookup   │
                  │ Vector DB TI search      │
                  │ extract_ueba_context()   │
                  │ Asset criticality (PG)   │
                  │ FP pattern check         │
                  │ Build AlertContextPackage│
                  └─────────┬────────────────┘
                            │
                   ┌────────┴────────┐
                   │                 │
            FP match (>0.90)    No FP match
                   │                 │
                   ▼                 ▼
            audit.events      incidents.enriched (Kafka)
            (auto-close)             │
                                     ▼
                           ┌─────────────────────┐
                           │ Priority Queue      │
                           │ Router              │
                           └────┬────┬────┬──────┘
                                │    │    │
              ┌─────────────────┘    │    └─────────────────┐
              ▼                      ▼                      ▼
    jobs.llm.priority.    jobs.llm.priority.     jobs.llm.priority.
    critical              high/normal            low
              │                      │                      │
              └──────────┬───────────┘                      │
                         ▼                                  ▼
                  ┌──────────────────────────┐    (delayed/batched
                  │ Agent Orchestrator       │     under load)
                  │ (LangGraph)              │
                  │                          │
                  │ IOC Extractor            │
                  │ → Context Enricher       │
                  │ → Reasoning Agent        │
                  │ → Response Agent         │
                  │                          │
                  │ All LLM calls via        │
                  │ Context Gateway          │
                  └──────────────────────────┘


                       INVESTIGATION PIPELINE (on-demand)

Agent Request ──► Adapter Query Module
                        │
                        ├── validate_query() (guardrails)
                        ├── check_rate_limit() (per-tenant quota)
                        ├── estimate_query_cost()
                        │
                        └── Adapter-specific API call
                            (Sentinel: Log Analytics API + KQL,
                             Elastic: Search API + EQL/Lucene,
                             Splunk: Search API + SPL)
                            → Parse results (source-specific)
                            → Normalize (parse_csl_record, etc.)
                            → Return to Agent


                       INGESTION PIPELINE (batch)

STIX Feed ──CronJob──► TI Ingester
                        │
                        ├── stix_bundle_to_docs()
                        ├── chunk_ti_report() (for reports)
                        ├── generate_embeddings()
                        │
                        ├── Vector DB Indexer
                        │   → TI reports, malware profiles, threat actors
                        │
                        └── Redis IOC Cache
                            → Exact-match IOC indicators


                       CTEM PIPELINE (near-real-time)

CTEM Sources ──Webhook/Poll──► ctem.raw.<source> (Kafka)
                                    │
                                    ▼
                             ┌──────────────────┐
                             │ CTEM Normaliser   │
                             │ Service           │
                             └──────┬───────────┘
                                    │
                                    ▼
                             Postgres (upsert)
                             + ctem.normalized (Kafka)
```

---

## 14. Mapping from v1 (Azure-Specific) to v2 (Cloud-Neutral)

| v1 Component | v2 Replacement | Notes |
|---|---|---|
| Event Hub trigger | Kafka topic `alerts.raw` + adapter publish | Adapters connect to source natively; the pipeline sees only `CanonicalAlert` on the topic |
| Azure Functions (AlertTrigger) | Entity Parser Service (Kafka consumer) | Dedicated microservice, no cold starts, no timeout limits |
| Azure Functions (KQLQueryExecutor) | Adapter-specific query module | Each adapter has its own query builder and API client |
| Azure Functions (TIIngester) | TI Ingester CronJob | Kubernetes CronJob, pulls STIX/TAXII, populates Redis + Vector DB |
| Azure Functions (MITREUpdater) | MITRE Updater CronJob | Same logic, different execution model |
| Azure Functions (IncidentMemoryWriter) | Orchestrator writes to Postgres directly | Investigation state persisted in Postgres, not a separate function |
| Event Hub consumer group | Kafka consumer group | Same concept, different implementation |
| Log Analytics API (KQL execution) | Adapter query modules (KQL/EQL/SPL) | Query builders are adapter-specific; core pipeline is query-language-agnostic |
| Azure AI Search (TI index) | Vector DB (Qdrant/Weaviate/pgvector) + Redis | Split: Vector DB for semantic search, Redis for IOC exact match |
| Sentinel SecurityAlert table | `CanonicalAlert` via any adapter | All sources normalised to canonical schema before pipeline processing |
| Sentinel BehaviorAnalytics table | UEBA adapter query (any source) | `extract_ueba_context()` operates on normalised UEBA records |
| Sentinel CommonSecurityLog table | CEF records via adapter query | `parse_csl_record()` operates on normalised record dicts |
| Azure Storage (Durable Function state) | Postgres (investigation state) | Explicit `GraphState` persisted to Postgres |
| Azure Monitor alerts (error detection) | Prometheus + Grafana (consumer lag, health checks) | Cloud-neutral observability |

---

*Document generated by Omeriko (DP v2.0) for ALUSKORT project. Covers complete data pipeline from multi-SIEM adapters through message bus topics, entity parsing, enrichment, priority queue routing, and agent-ready context packages. See `docs/ai-system-design.md` for the full system architecture, LLM routing, orchestration, and guardrails design. Next recommended: TS (Training Strategy) for Foundation-Sec-8B fine-tuning on alert triage data.*
