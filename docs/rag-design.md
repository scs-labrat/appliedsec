# ALUSKORT - RAG Knowledge Base Design

**Project:** ALUSKORT - Autonomous SOC Agent Architecture
**Type:** Cloud-Neutral RAG & Retrieval Layer
**Generated:** 2026-02-14
**Agent:** Omeriko (KB - Knowledge Base Design)
**Status:** Phase 1 - AI Architecture Design (v2.0 - Cloud-Neutral Pivot)

> This document describes the **RAG knowledge base** that feeds ALUSKORT's reasoning agents.
> For the overall system architecture (orchestration, ingest adapters, LLM router, guardrails),
> see `docs/ai-system-design.md`.

---

## 1. Knowledge Domain Architecture

ALUSKORT's RAG serves four distinct agent personas, each with different retrieval needs. The knowledge base is partitioned into **five domains**, each with its own storage backend, chunking strategy, and update cadence. Unlike the v1 design that funnelled everything through a single Azure AI Search instance, v2 splits retrieval across purpose-built stores.

```
                        ALUSKORT KNOWLEDGE LAYER (v2.0)
    ┌─────────────────────────────────────────────────────────────────┐
    │                                                                 │
    │  VECTOR DB (Qdrant / Weaviate / pgvector)                       │
    │  ┌─────────────┐  ┌─────────────┐  ┌─────────────────┐         │
    │  │ MITRE       │  │ THREAT      │  │ PLAYBOOKS       │         │
    │  │ ATT&CK /    │  │ INTEL       │  │ & SOPs          │         │
    │  │ ATLAS       │  │ Collection  │  │ Collection      │         │
    │  │ Collection  │  │             │  │                 │         │
    │  │ Tactics     │  │ TI Report   │  │ IR Procedures   │         │
    │  │ Techniques  │  │ Chunks      │  │ Response Steps  │         │
    │  │ Groups      │  │ Campaign    │  │ Escalation      │         │
    │  │ Software    │  │ Summaries   │  │                 │         │
    │  │ Mitigations │  │             │  │                 │         │
    │  └──────┬──────┘  └──────┬──────┘  └────────┬────────┘         │
    │         │                │                   │                  │
    │  ┌──────┴────────────────┴───────────────────┴────────┐        │
    │  │           INCIDENT MEMORY Collection                │        │
    │  │  Past investigations (semantic search + time decay) │        │
    │  └────────────────────────────────────────────────────┘        │
    │                                                                 │
    │  POSTGRES (structured data + metadata)                          │
    │  ┌──────────────────────────────────────────────────────────┐   │
    │  │ mitre_techniques │ mitre_groups │ playbook_metadata      │   │
    │  │ incidents        │ alerts       │ org_context            │   │
    │  │ fp_patterns      │ taxonomy     │ exposure_records       │   │
    │  └──────────────────────────────────────────────────────────┘   │
    │                                                                 │
    │  REDIS / KeyDB (IOC exact match, hot cache)                     │
    │  ┌──────────────────────────────────────────────────────────┐   │
    │  │ ioc:ip:203.0.113.42 → {reputation, campaigns, ttl}     │   │
    │  │ ioc:hash:sha256:a1b2... → {malware_family, confidence}  │   │
    │  │ ioc:domain:evil.com → {ti_context, first_seen}          │   │
    │  │ fp:hot:<pattern_id> → {conditions, confidence, count}   │   │
    │  └──────────────────────────────────────────────────────────┘   │
    │                                                                 │
    │  OBJECT STORE (S3 / MinIO)                                      │
    │  ┌──────────────────────────────────────────────────────────┐   │
    │  │ TI report PDFs │ Model weights │ Raw forensic artifacts │   │
    │  └──────────────────────────────────────────────────────────┘   │
    └─────────────────────────────────────────────────────────────────┘
```

### Domain-to-Agent Mapping

| Knowledge Domain | Primary Consumer | Query Pattern | Storage Backend | Priority |
|---|---|---|---|---|
| **MITRE ATT&CK / ATLAS** | Reasoning Agent, IOC Extractor | "What technique matches this behaviour?" / "What are detection methods for T1059?" | Postgres (structured) + Vector DB (semantic) | Critical |
| **Threat Intelligence** | Context Enricher, Reasoning Agent | "Is this IOC associated with known campaigns?" / "What TTPs does APT29 use?" | Redis (IOC exact match) + Vector DB (report semantic) + Postgres (metadata) | Critical |
| **Playbooks & SOPs** | Reasoning Agent, Response Agent | "What's the procedure for handling a phishing incident?" / "Escalation criteria for ransomware?" | Postgres (metadata) + Vector DB (searchable content) | High |
| **Incident Memory** | Reasoning Agent, Triage Agent | "Have we seen this pattern before?" / "How did we handle similar alerts?" | Postgres (structured records) + Vector DB (semantic search) | High |
| **Organisational Context** | All agents | "Is this a critical asset?" / "Is this user a VIP?" / "Is this within a maintenance window?" | Postgres (or Neo4j for asset relationships) | Medium |

---

## 2. MITRE ATT&CK Index Design

### 2.1 Data Source

**Primary:** MITRE ATT&CK STIX 2.1 bundle from the official GitHub repository.
- Enterprise ATT&CK (primary)
- ICS ATT&CK (if OT/SCADA in scope)
- Mobile ATT&CK (if mobile endpoints in scope)
- MITRE ATLAS (AI/ML attack techniques)

**Format:** STIX 2.1 JSON bundles. Each object (technique, group, software, mitigation) is a STIX Domain Object (SDO).

**Ingestion endpoint:**
```
https://raw.githubusercontent.com/mitre-cti/enterprise-attack/master/enterprise-attack.json
```

### 2.2 Document Structure

MITRE ATT&CK is *not* a flat document corpus - it's a knowledge graph. Chunking it like prose destroys the relationships. Instead, we create **structured records in Postgres** (for exact-match and filtered queries) and **vector embeddings in the Vector DB** (for semantic search). Each entity is stored in both places.

**Technique Document Schema:**
```json
{
    "doc_id": "T1059.001",
    "doc_type": "mitre_technique",
    "tactic": ["Execution"],
    "technique_id": "T1059.001",
    "technique_name": "PowerShell",
    "parent_technique": "T1059 - Command and Scripting Interpreter",
    "description": "Adversaries may abuse PowerShell commands and scripts for execution...",
    "detection": "Monitor for loading of System.Management.Automation.dll...",
    "platforms": ["Windows"],
    "data_sources": ["Process: Process Creation", "Command: Command Execution", "Script: Script Execution"],
    "log_tables": ["SecurityEvent", "DeviceProcessEvents", "Syslog"],
    "detection_rules": ["Suspicious PowerShell Download", "Base64 Encoded PowerShell"],
    "mitigations": [
        {"id": "M1042", "name": "Disable or Remove Feature or Program", "description": "..."},
        {"id": "M1045", "name": "Code Signing", "description": "..."}
    ],
    "groups_using": ["APT29", "APT32", "Lazarus Group", "FIN7"],
    "software_using": ["Cobalt Strike", "Empire", "Mimikatz"],
    "related_techniques": ["T1059.003", "T1059.005", "T1059.007"],
    "kill_chain_phase": "execution",
    "severity_baseline": "high",
    "metadata": {
        "last_updated": "2026-01-15",
        "attack_version": "16.1",
        "source": "mitre-cti/enterprise-attack"
    }
}
```

> **Why not chunk the MITRE descriptions into overlapping 512-token windows?** Because MITRE techniques are already self-contained knowledge units. Chunking them fragments the relationship between detection guidance, mitigations, and threat group usage - exactly the context the Reasoning Agent needs in one retrieval hit. One technique = one document.

**Group Document Schema:**
```json
{
    "doc_id": "G0016",
    "doc_type": "mitre_group",
    "group_id": "G0016",
    "group_name": "APT29",
    "aliases": ["Cozy Bear", "The Dukes", "NOBELIUM", "Midnight Blizzard"],
    "description": "APT29 is a threat group attributed to Russia's Foreign Intelligence Service (SVR)...",
    "techniques_used": [
        {"id": "T1059.001", "name": "PowerShell", "usage": "APT29 has used PowerShell to..."},
        {"id": "T1566.001", "name": "Spearphishing Attachment", "usage": "..."}
    ],
    "software_used": ["S0154 - Cobalt Strike", "S0005 - FlawedGrace"],
    "target_sectors": ["Government", "Technology", "Think Tanks"],
    "references": ["https://attack.mitre.org/groups/G0016/"]
}
```

### 2.3 Postgres Table: MITRE Techniques

```sql
-- Postgres: structured MITRE technique store
-- Enables exact-match lookups by technique ID, tactic filtering, JOIN with groups/software

CREATE TABLE mitre_techniques (
    doc_id          TEXT PRIMARY KEY,       -- e.g. 'T1059.001'
    doc_type        TEXT NOT NULL DEFAULT 'mitre_technique',
    technique_id    TEXT NOT NULL UNIQUE,
    technique_name  TEXT NOT NULL,
    parent_technique TEXT,
    tactic          TEXT[] NOT NULL,         -- e.g. ARRAY['Execution']
    description     TEXT NOT NULL,
    detection       TEXT,
    platforms       TEXT[],                  -- e.g. ARRAY['Windows', 'Linux']
    data_sources    TEXT[],
    log_tables      TEXT[],                  -- SIEM-agnostic log table names
    kill_chain_phase TEXT,
    severity_baseline TEXT DEFAULT 'medium',
    groups_using    TEXT[],                  -- denormalised for fast retrieval
    software_using  TEXT[],
    related_techniques TEXT[],
    attack_version  TEXT,
    last_updated    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_mitre_technique_id ON mitre_techniques (technique_id);
CREATE INDEX idx_mitre_tactic ON mitre_techniques USING GIN (tactic);
CREATE INDEX idx_mitre_platforms ON mitre_techniques USING GIN (platforms);
CREATE INDEX idx_mitre_groups ON mitre_techniques USING GIN (groups_using);
CREATE INDEX idx_mitre_severity ON mitre_techniques (severity_baseline);

CREATE TABLE mitre_groups (
    doc_id          TEXT PRIMARY KEY,       -- e.g. 'G0016'
    doc_type        TEXT NOT NULL DEFAULT 'mitre_group',
    group_id        TEXT NOT NULL UNIQUE,
    group_name      TEXT NOT NULL,
    aliases         TEXT[],
    description     TEXT NOT NULL,
    techniques_used JSONB,                  -- array of {id, name, usage}
    software_used   TEXT[],
    target_sectors  TEXT[],
    references      TEXT[],
    last_updated    TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_mitre_group_name ON mitre_groups (group_name);
CREATE INDEX idx_mitre_group_aliases ON mitre_groups USING GIN (aliases);

CREATE TABLE mitre_mitigations (
    mitigation_id   TEXT PRIMARY KEY,       -- e.g. 'M1042'
    name            TEXT NOT NULL,
    description     TEXT NOT NULL,
    techniques_mitigated TEXT[],            -- technique IDs this mitigation applies to
    last_updated    TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Taxonomy store: ATT&CK + ATLAS IDs for validation (Context Gateway uses this)
CREATE TABLE taxonomy_ids (
    technique_id    TEXT PRIMARY KEY,       -- 'T1059.001' or 'AML.T0043'
    framework       TEXT NOT NULL,          -- 'attack' or 'atlas'
    name            TEXT NOT NULL,
    is_subtechnique BOOLEAN DEFAULT FALSE,
    parent_id       TEXT,
    deprecated      BOOLEAN DEFAULT FALSE,
    last_updated    TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
```

### 2.4 Vector DB Collection: MITRE Semantic Search

```python
"""
Qdrant collection configuration for MITRE ATT&CK / ATLAS semantic search.
Each technique/group is stored as a point with its embedding and metadata payload.
"""

MITRE_COLLECTION_CONFIG = {
    "collection_name": "aluskort-mitre",
    "vectors": {
        "size": 1024,        # Embedding dimensions (configurable per model)
        "distance": "Cosine",
    },
    "hnsw_config": {
        "m": 16,
        "ef_construct": 200,
    },
    "payload_schema": {
        "doc_id": "keyword",
        "doc_type": "keyword",          # 'mitre_technique', 'mitre_group', 'mitre_software'
        "technique_id": "keyword",
        "technique_name": "text",
        "tactic": "keyword",            # filterable
        "platforms": "keyword",         # filterable
        "severity_baseline": "keyword", # filterable
        "kill_chain_phase": "keyword",
        "groups_using": "keyword",
        "last_updated": "datetime",
    },
}
```

### 2.5 Detection Rule Mapping (Adapter-Based)

This is the bridge between MITRE knowledge and operational detection. For each technique, map which detection rules (from *any* SIEM) detect it. Unlike v1 which was Sentinel-specific, v2 uses adapter-based rule fetching.

```python
"""
Enrichment: map MITRE techniques to active detection rules from any SIEM.
Uses the adapter pattern — each SIEM provides its own rule-fetching logic.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass


@dataclass
class DetectionRule:
    """A detection rule from any SIEM/XDR platform."""
    rule_name: str
    rule_id: str
    severity: str
    tactics: list[str]
    source_platform: str  # 'sentinel', 'elastic', 'splunk', etc.


class DetectionRuleAdapter(ABC):
    """Base class for fetching detection rules from any SIEM."""

    @abstractmethod
    def source_name(self) -> str:
        """Return the adapter's source identifier."""
        ...

    @abstractmethod
    def fetch_rules(self) -> list[DetectionRule]:
        """Fetch all enabled detection rules from this SIEM."""
        ...


class SentinelRuleAdapter(DetectionRuleAdapter):
    """Fetch detection rules from Microsoft Sentinel."""

    def __init__(self, api_base: str, headers: dict):
        self.api_base = api_base
        self.headers = headers

    def source_name(self) -> str:
        return "sentinel"

    def fetch_rules(self) -> list[DetectionRule]:
        import requests
        rules_url = f"{self.api_base}/alertRules?api-version=2024-03-01"
        response = requests.get(rules_url, headers=self.headers)
        raw_rules = response.json().get("value", [])

        rules = []
        for rule in raw_rules:
            properties = rule.get("properties", {})
            if not properties.get("enabled", False):
                continue
            rules.append(DetectionRule(
                rule_name=properties.get("displayName", ""),
                rule_id=rule.get("name", ""),
                severity=properties.get("severity", ""),
                tactics=properties.get("tactics", []),
                source_platform="sentinel",
            ))
        return rules


class ElasticRuleAdapter(DetectionRuleAdapter):
    """Fetch detection rules from Elastic SIEM."""

    def __init__(self, base_url: str, api_key: str):
        self.base_url = base_url
        self.api_key = api_key

    def source_name(self) -> str:
        return "elastic"

    def fetch_rules(self) -> list[DetectionRule]:
        import requests
        headers = {"Authorization": f"ApiKey {self.api_key}"}
        response = requests.get(
            f"{self.base_url}/api/detection_engine/rules/_find?per_page=1000",
            headers=headers,
        )
        raw_rules = response.json().get("data", [])

        rules = []
        for rule in raw_rules:
            if not rule.get("enabled", False):
                continue
            tactics = []
            for threat in rule.get("threat", []):
                tactic_name = threat.get("tactic", {}).get("name", "")
                if tactic_name:
                    tactics.append(tactic_name)
            rules.append(DetectionRule(
                rule_name=rule.get("name", ""),
                rule_id=rule.get("id", ""),
                severity=rule.get("severity", ""),
                tactics=tactics,
                source_platform="elastic",
            ))
        return rules


def build_technique_rule_mapping(adapters: list[DetectionRuleAdapter]) -> dict:
    """
    Build a mapping of MITRE technique IDs to active detection rules
    across all connected SIEMs. This enriches the MITRE index with
    operational detection context regardless of which SIEM is deployed.
    """
    technique_to_rules: dict[str, list[dict]] = {}

    for adapter in adapters:
        rules = adapter.fetch_rules()
        for rule in rules:
            rule_info = {
                "rule_name": rule.rule_name,
                "rule_id": rule.rule_id,
                "severity": rule.severity,
                "tactics": rule.tactics,
                "source_platform": rule.source_platform,
            }
            # Map techniques from rule tactics to technique IDs
            # (actual mapping depends on SIEM metadata)
            for tactic in rule.tactics:
                if tactic not in technique_to_rules:
                    technique_to_rules[tactic] = []
                technique_to_rules[tactic].append(rule_info)

    return technique_to_rules
```

This mapping is injected into each technique document's `detection_rules` field during indexing. When the Reasoning Agent retrieves a technique, it immediately knows which SIEM rules cover it across *all* connected platforms - and which techniques have *no* detection coverage (hunting opportunities).

### 2.6 Update Strategy

| Trigger | Action |
|---|---|
| MITRE releases new ATT&CK version (quarterly) | Full re-index: Postgres upsert + Vector DB re-embed |
| SIEM detection rules change | Re-build technique-to-rule mapping via adapters |
| New threat group report published | Add/update group document in Postgres + Vector DB |
| Analyst feedback on technique relevance | Adjust `severity_baseline` field in Postgres |
| MITRE ATLAS update | Upsert ATLAS techniques into taxonomy + Vector DB |

---

## 3. Threat Intelligence Index Design

### 3.1 Data Sources

| Source | Format | Update Frequency | Content Type | Storage Target |
|---|---|---|---|---|
| **STIX/TAXII feeds** | STIX 2.1 | Continuous | IOCs (IPs, domains, hashes, URLs) | Redis (IOC cache) + Postgres (metadata) |
| **MISP** | STIX 2.1 / MISP JSON | Hourly | IOCs + context + galaxy clusters | Redis + Postgres |
| **AlienVault OTX** | OTX API / STIX | Hourly | Pulses (IOCs + descriptions) | Redis + Postgres |
| **CISA Advisories** | HTML / structured data | Daily | Vulnerability advisories, KEV catalogue | Postgres + Vector DB (report chunks) |
| **Commercial feeds** (if added) | Varies (API/STIX) | Varies | Rich context, actor profiles, campaign tracking | All stores as appropriate |
| **SIEM TI connectors** | Via adapter | Continuous | Platform-specific TI | Redis + Postgres |

### 3.2 Storage Split for Threat Intel

Threat intelligence spans three stores, each serving a different query pattern:

**Redis: IOC Exact Match (hot cache)**

IOCs are key-value data. Vector search is the wrong tool for "Is 203.0.113.42 malicious?" - that needs a sub-millisecond exact match.

```
# Redis key patterns for IOC lookup
ioc:ipv4:<ip_address>          → JSON: {confidence, severity, campaigns[], groups[], techniques[], first_seen, last_seen, sources[], ttl}
ioc:hash:sha256:<hash>         → JSON: {confidence, malware_family, campaigns[], first_seen, sources[]}
ioc:hash:sha1:<hash>           → JSON: {confidence, malware_family, sources[]}
ioc:hash:md5:<hash>            → JSON: {confidence, malware_family, sources[]}
ioc:domain:<domain>            → JSON: {confidence, severity, associated_campaigns[], ti_context, sources[]}
ioc:url:<url_sha256>           → JSON: {original_url, confidence, category, sources[]}
ioc:cve:<cve_id>               → JSON: {severity, cvss, affected_products[], exploit_available, kev_listed}

# TTL policy: IOCs expire based on source confidence
#   High confidence (>80): 30-day TTL
#   Medium confidence (50-80): 7-day TTL
#   Low confidence (<50): 24-hour TTL
# All IOCs re-validated on TTL expiry from upstream source
```

**Postgres: IOC Metadata & TI Reports (structured)**

```sql
-- Postgres: IOC metadata for structured queries and reporting
CREATE TABLE threat_intel_iocs (
    doc_id              TEXT PRIMARY KEY,
    indicator_type      TEXT NOT NULL,     -- 'ipv4', 'sha256', 'domain', etc.
    indicator_value     TEXT NOT NULL,
    confidence          INTEGER NOT NULL CHECK (confidence BETWEEN 0 AND 100),
    severity            TEXT,
    associated_campaigns TEXT[],
    associated_groups   TEXT[],
    mitre_techniques    TEXT[],
    first_seen          TIMESTAMPTZ,
    last_seen           TIMESTAMPTZ,
    sources             TEXT[] NOT NULL,
    context             TEXT,
    expiry              TIMESTAMPTZ,
    tags                TEXT[],
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE UNIQUE INDEX idx_ti_ioc_value ON threat_intel_iocs (indicator_type, indicator_value);
CREATE INDEX idx_ti_ioc_campaigns ON threat_intel_iocs USING GIN (associated_campaigns);
CREATE INDEX idx_ti_ioc_groups ON threat_intel_iocs USING GIN (associated_groups);
CREATE INDEX idx_ti_ioc_techniques ON threat_intel_iocs USING GIN (mitre_techniques);
CREATE INDEX idx_ti_ioc_expiry ON threat_intel_iocs (expiry);

-- TI reports: campaign-level intelligence
CREATE TABLE threat_intel_reports (
    doc_id              TEXT PRIMARY KEY,
    title               TEXT NOT NULL,
    source              TEXT NOT NULL,
    publish_date        TIMESTAMPTZ,
    summary             TEXT,
    threat_actors       TEXT[],
    mitre_techniques    TEXT[],
    target_sectors      TEXT[],
    iocs_referenced     TEXT[],            -- References to threat_intel_iocs.doc_id
    detection_guidance  TEXT,
    response_guidance   TEXT,
    tags                TEXT[],
    raw_artifact_path   TEXT,              -- S3/MinIO path to original PDF/HTML
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_ti_report_actors ON threat_intel_reports USING GIN (threat_actors);
CREATE INDEX idx_ti_report_techniques ON threat_intel_reports USING GIN (mitre_techniques);
CREATE INDEX idx_ti_report_date ON threat_intel_reports (publish_date DESC);
```

**Vector DB: TI Report Semantic Search**

```python
"""
Qdrant collection for threat intelligence report chunks.
Enables semantic search: "What campaigns target healthcare using supply chain attacks?"
"""

TI_COLLECTION_CONFIG = {
    "collection_name": "aluskort-threat-intel",
    "vectors": {
        "size": 1024,
        "distance": "Cosine",
    },
    "hnsw_config": {
        "m": 16,
        "ef_construct": 200,
    },
    "payload_schema": {
        "doc_id": "keyword",            # chunk ID
        "parent_doc_id": "keyword",     # original report ID
        "doc_type": "keyword",          # 'threat_intel_report_chunk'
        "section": "text",
        "threat_actors": "keyword",     # filterable
        "mitre_techniques": "keyword",  # filterable
        "publish_date": "datetime",     # filterable
        "source": "keyword",
        "iocs_in_chunk": "keyword",     # for reverse IOC -> chunk lookup
    },
}
```

### 3.3 Chunking Strategy for Threat Reports

Threat intelligence reports are the one domain where traditional chunking is needed. Reports can be 5-50 pages.

**Strategy: Section-aware chunking with IOC preservation**

```python
"""
TI Report Chunker for ALUSKORT RAG
Splits threat intelligence reports while preserving IOC context.
Chunks are stored in the Vector DB; metadata goes to Postgres.
"""

import re
from dataclasses import dataclass


@dataclass
class TIChunk:
    """A chunk of a threat intelligence report."""
    chunk_id: str
    parent_doc_id: str
    section: str
    content: str
    iocs_in_chunk: list[str]
    mitre_techniques_in_chunk: list[str]
    chunk_index: int
    total_chunks: int


# Regex patterns for IOC extraction during chunking
IOC_PATTERNS = {
    "ipv4": r'\b(?:\d{1,3}\.){3}\d{1,3}\b',
    "domain": r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b',
    "sha256": r'\b[a-fA-F0-9]{64}\b',
    "sha1": r'\b[a-fA-F0-9]{40}\b',
    "md5": r'\b[a-fA-F0-9]{32}\b',
    "cve": r'CVE-\d{4}-\d{4,7}',
    "mitre_technique": r'T\d{4}(?:\.\d{3})?',
    "email": r'\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b',
    "url": r'https?://[^\s<>"{}|\\^`\[\]]+',
}

# Common false positive domains to exclude
FP_DOMAINS = {
    "microsoft.com", "github.com", "google.com", "example.com",
    "windows.net", "azure.com", "office.com", "outlook.com",
    "amazonaws.com", "cloudfront.net", "googleapis.com",
}


def extract_iocs(text: str) -> list[str]:
    """Extract IOCs from text, filtering false positives."""
    iocs = []
    for ioc_type, pattern in IOC_PATTERNS.items():
        matches = re.findall(pattern, text)
        for match in matches:
            if ioc_type == "domain" and match.lower() in FP_DOMAINS:
                continue
            if ioc_type == "ipv4" and match.startswith(("10.", "192.168.", "172.")):
                continue  # Skip RFC1918
            iocs.append(f"{ioc_type}:{match}")
    return list(set(iocs))


def chunk_ti_report(
    doc_id: str,
    text: str,
    max_chunk_tokens: int = 512,
    overlap_tokens: int = 64,
) -> list[TIChunk]:
    """
    Chunk a threat intelligence report by sections.

    Strategy:
    1. Split on markdown headers (##, ###) to get semantic sections
    2. If a section exceeds max_chunk_tokens, split on paragraph boundaries
    3. Extract IOCs and MITRE references from each chunk
    4. Overlap preserves context at chunk boundaries

    Chunks are embedded and stored in the Vector DB (Qdrant).
    Parent report metadata stays in Postgres.
    """
    # Split into sections by markdown headers
    section_pattern = r'^(#{1,3})\s+(.+)$'
    lines = text.split('\n')
    sections = []
    current_section = "Introduction"
    current_content = []

    for line in lines:
        header_match = re.match(section_pattern, line)
        if header_match:
            if current_content:
                sections.append((current_section, '\n'.join(current_content)))
            current_section = header_match.group(2).strip()
            current_content = []
        else:
            current_content.append(line)

    if current_content:
        sections.append((current_section, '\n'.join(current_content)))

    # Chunk each section
    chunks = []
    chunk_index = 0

    for section_name, section_content in sections:
        # Rough token estimate: ~4 chars per token
        estimated_tokens = len(section_content) // 4

        if estimated_tokens <= max_chunk_tokens:
            # Section fits in one chunk
            iocs = extract_iocs(section_content)
            mitre_refs = re.findall(r'T\d{4}(?:\.\d{3})?', section_content)
            chunks.append(TIChunk(
                chunk_id=f"{doc_id}-chunk-{chunk_index}",
                parent_doc_id=doc_id,
                section=section_name,
                content=section_content.strip(),
                iocs_in_chunk=iocs,
                mitre_techniques_in_chunk=list(set(mitre_refs)),
                chunk_index=chunk_index,
                total_chunks=0,  # Set after all chunks created
            ))
            chunk_index += 1
        else:
            # Split on paragraph boundaries
            paragraphs = section_content.split('\n\n')
            current_chunk = []
            current_length = 0

            for para in paragraphs:
                para_tokens = len(para) // 4
                if current_length + para_tokens > max_chunk_tokens and current_chunk:
                    chunk_text = '\n\n'.join(current_chunk)
                    iocs = extract_iocs(chunk_text)
                    mitre_refs = re.findall(r'T\d{4}(?:\.\d{3})?', chunk_text)
                    chunks.append(TIChunk(
                        chunk_id=f"{doc_id}-chunk-{chunk_index}",
                        parent_doc_id=doc_id,
                        section=section_name,
                        content=chunk_text.strip(),
                        iocs_in_chunk=iocs,
                        mitre_techniques_in_chunk=list(set(mitre_refs)),
                        chunk_index=chunk_index,
                        total_chunks=0,
                    ))
                    chunk_index += 1

                    # Overlap: keep last paragraph as context bridge
                    current_chunk = [current_chunk[-1]] if current_chunk else []
                    current_length = len(current_chunk[0]) // 4 if current_chunk else 0

                current_chunk.append(para)
                current_length += para_tokens

            # Flush remaining
            if current_chunk:
                chunk_text = '\n\n'.join(current_chunk)
                iocs = extract_iocs(chunk_text)
                mitre_refs = re.findall(r'T\d{4}(?:\.\d{3})?', chunk_text)
                chunks.append(TIChunk(
                    chunk_id=f"{doc_id}-chunk-{chunk_index}",
                    parent_doc_id=doc_id,
                    section=section_name,
                    content=chunk_text.strip(),
                    iocs_in_chunk=iocs,
                    mitre_techniques_in_chunk=list(set(mitre_refs)),
                    chunk_index=chunk_index,
                    total_chunks=0,
                ))
                chunk_index += 1

    # Set total_chunks
    for chunk in chunks:
        chunk.total_chunks = len(chunks)

    return chunks
```

> **Why section-aware instead of fixed-size?** Security reports have distinct sections (Executive Summary, Technical Analysis, IOCs, Recommendations). A fixed 512-token window frequently splits IOC tables in half or separates detection guidance from the technique it describes. Section-aware chunking keeps semantically complete units together. Paragraph-level splitting is the fallback for oversized sections.

> **Why extract IOCs during chunking?** So we can build a reverse index: given an IOC, find all chunks that mention it. This is critical for the Context Enricher - when it encounters an IP in an alert, it can immediately retrieve all TI context mentioning that IP without relying solely on vector similarity. The IOC value goes to Redis for sub-millisecond exact match; the chunk goes to the Vector DB for semantic retrieval.

---

## 4. Playbooks & SOPs Index Design

### 4.1 Bootstrap Sources (Starting from Scratch)

Since no internal playbooks exist yet, bootstrap from high-quality public sources:

| Source | Content | Format |
|---|---|---|
| **CISA Incident Response Playbooks** | Federal IR procedures, ransomware response | PDF/HTML |
| **NIST SP 800-61r3** | Computer Security Incident Handling Guide | PDF |
| **SIEM Vendor Playbook Templates** | Vendor-provided response templates (Sentinel, Elastic, Splunk) | Varies |
| **Community Playbooks** | GitHub community-contributed playbooks | Markdown |
| **SANS Incident Handler's Handbook** | IR methodology and procedures | PDF |
| **ALUSKORT-generated playbooks** | Generated from incident investigations over time | Markdown (auto-generated) |

### 4.2 Playbook Document Schema

Playbooks are procedural - they describe a sequence of steps. The chunking must preserve step sequences, not split them.

**Postgres: Playbook metadata (structured queries, filtering)**

```sql
CREATE TABLE playbooks (
    doc_id              TEXT PRIMARY KEY,
    title               TEXT NOT NULL,
    category            TEXT NOT NULL,           -- 'email-threats', 'ransomware', etc.
    severity_applicable TEXT[] NOT NULL,
    trigger_conditions  JSONB,                   -- conditions that activate this playbook
    alert_products      TEXT[],                  -- products that generate matching alerts
    mitre_techniques    TEXT[] NOT NULL,
    escalation_criteria JSONB,
    resolution_criteria JSONB,
    source              TEXT DEFAULT 'manual',   -- 'manual', 'auto-generated', 'community'
    version             TEXT DEFAULT '1.0',
    review_status       TEXT DEFAULT 'draft',    -- 'draft', 'approved', 'deprecated'
    approved_by         TEXT,
    last_updated        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_playbook_category ON playbooks (category);
CREATE INDEX idx_playbook_techniques ON playbooks USING GIN (mitre_techniques);
CREATE INDEX idx_playbook_status ON playbooks (review_status);

-- Playbook steps stored separately for structured queries
CREATE TABLE playbook_steps (
    playbook_id     TEXT NOT NULL REFERENCES playbooks(doc_id),
    step_number     INTEGER NOT NULL,
    action          TEXT NOT NULL,
    description     TEXT NOT NULL,
    queries         JSONB,              -- SIEM-agnostic query templates
    automated       BOOLEAN DEFAULT FALSE,
    requires_approval BOOLEAN DEFAULT FALSE,
    approval_reason TEXT,
    assigned_agent  TEXT,               -- 'ioc_extractor', 'context_enricher', etc.
    PRIMARY KEY (playbook_id, step_number)
);
```

**Playbook JSON (for reference / Vector DB embedding):**
```json
{
    "doc_id": "playbook-phishing-response",
    "doc_type": "playbook",
    "title": "Phishing Incident Response Playbook",
    "category": "email-threats",
    "severity_applicable": ["medium", "high"],
    "trigger_conditions": [
        "Alert with tactic 'InitialAccess' and category 'phishing'",
        "Alert from email security product with phishing classification",
        "Manual escalation from analyst"
    ],
    "alert_products": [
        "Email Security Gateway",
        "Endpoint Detection and Response"
    ],
    "mitre_techniques": ["T1566.001", "T1566.002", "T1566.003"],
    "steps": [
        {
            "step": 1,
            "action": "Identify and scope",
            "description": "Determine the phishing email details: sender, subject, recipients, attachment/URL",
            "queries": [
                "SELECT * FROM email_events WHERE sender = '{sender}' AND timestamp > NOW() - INTERVAL '24 hours'"
            ],
            "automated": true,
            "agent": "ioc_extractor"
        },
        {
            "step": 2,
            "action": "Assess impact",
            "description": "Determine how many users received and interacted with the email",
            "queries": [
                "SELECT COUNT(DISTINCT recipient) AS recipients, COUNT(CASE WHEN clicked THEN 1 END) AS clicked FROM email_events WHERE message_id = '{message_id}'"
            ],
            "automated": true,
            "agent": "context_enricher"
        },
        {
            "step": 3,
            "action": "Contain",
            "description": "Purge email from all mailboxes, block sender domain, block URL/attachment hash",
            "automated": false,
            "requires_approval": true,
            "agent": "response_agent",
            "approval_reason": "Destructive action: email purge affects all recipients"
        }
    ],
    "escalation_criteria": [
        "More than 50 recipients clicked the link",
        "Executive/VIP targeted",
        "Credential harvesting confirmed",
        "Malware payload detected"
    ],
    "resolution_criteria": [
        "All malicious emails purged",
        "All affected credentials reset",
        "Sender domain blocked",
        "No evidence of lateral movement"
    ],
    "metadata": {
        "source": "ALUSKORT-generated",
        "last_updated": "2026-02-14",
        "version": "1.0",
        "review_status": "draft"
    }
}
```

> **Key design choice:** Playbooks are stored as single documents in the Vector DB, not chunked. A playbook is typically 1-3 pages. Splitting it loses the procedural flow. The Reasoning Agent needs the complete playbook in one retrieval to decide which steps apply and in what order. Metadata goes to Postgres for structured filtering (by category, technique, severity); the full text goes to the Vector DB for semantic search.

### 4.3 Playbook Generation from Incidents

As ALUSKORT processes incidents, it can **auto-generate playbook drafts** from successful investigation patterns:

```
Alert processed successfully
    |
    v
Extract investigation steps taken
    |
    v
Identify common pattern (similar to N past incidents)
    |
    v
Generate playbook draft (marked as "auto-generated, needs review")
    |
    v
Publish to Kafka topic: playbooks.draft
    |
    v
Analyst reviews via feedback dashboard
    |
    v
Approved playbook → Postgres (status: "approved") + Vector DB (re-embedded)
```

This creates a flywheel: ALUSKORT learns from its own investigations and codifies successful patterns into reusable playbooks.

---

## 5. Incident Memory Index Design

### 5.1 Purpose

Incident Memory is what makes ALUSKORT get smarter over time. Every investigation, decision, and outcome is stored and retrievable. This enables:

- "Have we seen this IP before?" (deduplication)
- "Last time we saw this pattern, it was a false positive" (historical context)
- "This is similar to the SolarWinds incident we handled in January" (pattern matching)
- "The analyst corrected our classification on this alert type" (feedback loop)

### 5.2 Postgres: Structured Incident Records

```sql
CREATE TABLE incident_memory (
    doc_id              TEXT PRIMARY KEY,
    incident_id         TEXT NOT NULL,
    alert_ids           TEXT[] NOT NULL,
    timestamp           TIMESTAMPTZ NOT NULL,
    tenant_id           TEXT NOT NULL DEFAULT 'default',

    -- Classification
    initial_classification TEXT,
    final_classification   TEXT,
    corrected_by          TEXT,           -- 'analyst_feedback', 'auto', etc.
    correction_reason     TEXT,

    -- Alert context
    alert_product       TEXT,
    alert_name          TEXT NOT NULL,
    alert_source        TEXT NOT NULL,     -- 'sentinel', 'elastic', 'splunk', etc.
    severity            TEXT NOT NULL,

    -- Entities (denormalised for fast filtering)
    entities            JSONB NOT NULL,    -- {users: [], devices: [], ips: [], processes: []}
    mitre_techniques    TEXT[],

    -- Investigation
    investigation_summary TEXT NOT NULL,
    decision_chain      JSONB,             -- [{agent, action, confidence}, ...]
    outcome             TEXT NOT NULL,      -- 'closed_true_positive', 'closed_false_positive', etc.

    -- Analyst feedback
    analyst_feedback    JSONB,             -- {correct: bool, rating: int, comment: str}
    lessons_learned     TEXT,

    -- Relationships
    similar_to          TEXT[],            -- doc_ids of similar past incidents

    tags                TEXT[],
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Partition by month for efficient time-range queries and archival
-- CREATE TABLE incident_memory_2026_02 PARTITION OF incident_memory
--     FOR VALUES FROM ('2026-02-01') TO ('2026-03-01');

CREATE INDEX idx_incident_timestamp ON incident_memory (timestamp DESC);
CREATE INDEX idx_incident_tenant ON incident_memory (tenant_id);
CREATE INDEX idx_incident_techniques ON incident_memory USING GIN (mitre_techniques);
CREATE INDEX idx_incident_outcome ON incident_memory (outcome);
CREATE INDEX idx_incident_alert_name ON incident_memory (alert_name);
CREATE INDEX idx_incident_entities ON incident_memory USING GIN (entities);
CREATE INDEX idx_incident_tags ON incident_memory USING GIN (tags);
```

**Vector DB: Incident Semantic Search**

```python
"""
Qdrant collection for incident memory semantic search.
Enables "find similar past incidents" via embedding similarity + metadata filtering.
"""

INCIDENT_MEMORY_COLLECTION_CONFIG = {
    "collection_name": "aluskort-incident-memory",
    "vectors": {
        "size": 1024,
        "distance": "Cosine",
    },
    "hnsw_config": {
        "m": 16,
        "ef_construct": 200,
    },
    "payload_schema": {
        "doc_id": "keyword",
        "tenant_id": "keyword",         # filterable: same-tenant boost
        "alert_name": "text",
        "alert_source": "keyword",
        "severity": "keyword",
        "outcome": "keyword",           # filterable: 'true_positive', 'false_positive'
        "mitre_techniques": "keyword",  # filterable
        "timestamp": "datetime",        # for recency decay scoring
        "tags": "keyword",
    },
}
```

### 5.3 Investigation Record Schema (Reference)

```json
{
    "doc_id": "inv-2026-02-14-001",
    "doc_type": "incident_memory",
    "incident_id": "INC-12345",
    "alert_ids": ["ALERT-67890", "ALERT-67891"],
    "timestamp": "2026-02-14T08:23:00Z",
    "tenant_id": "tenant-acme",
    "classification": {
        "initial": "true_positive",
        "final": "false_positive",
        "corrected_by": "analyst_feedback",
        "correction_reason": "Scheduled maintenance activity, not actual lateral movement"
    },
    "alert_product": "Endpoint Detection and Response",
    "alert_name": "Suspicious lateral movement detected",
    "alert_source": "sentinel",
    "severity": "high",
    "entities": {
        "users": ["admin@contoso.com"],
        "devices": ["SRV-DC01"],
        "ips": ["10.0.1.50", "10.0.1.51"],
        "processes": ["psexec.exe"]
    },
    "mitre_techniques": ["T1570", "T1021.002"],
    "investigation_summary": "ALUSKORT detected PsExec-based lateral movement from SRV-DC01 to SRV-APP01. Context Enricher confirmed both servers are in the same maintenance group. UEBA risk signal showed low risk score. Cross-referenced with change management schedule - confirmed planned patching activity.",
    "decision_chain": [
        {"agent": "ioc_extractor", "action": "Extracted source/dest IPs and process name", "confidence": 0.95},
        {"agent": "context_enricher", "action": "Queried UEBA - low risk score. Checked asset tags - both in maintenance group.", "confidence": 0.88},
        {"agent": "reasoning_agent", "action": "Correlated with change management window. Classified as false positive.", "confidence": 0.92},
        {"agent": "response_agent", "action": "Closed incident with detailed notes. No response action needed.", "confidence": 0.95}
    ],
    "outcome": "closed_false_positive",
    "analyst_feedback": {
        "correct": true,
        "rating": 5,
        "comment": "Good catch on the maintenance window correlation"
    },
    "lessons_learned": "PsExec during maintenance windows is expected. Consider adding maintenance window awareness to triage pipeline.",
    "similar_to": ["inv-2026-01-20-015", "inv-2026-02-01-003"],
    "tags": ["false-positive", "maintenance-window", "lateral-movement", "psexec"]
}
```

### 5.4 Time-Decayed Incident Scoring

Past incidents are ranked using a composite score that decays over time and boosts on tenant/technique match. This is the same scoring function defined in `docs/ai-system-design.md` Section 5.3.

```python
"""
ALUSKORT Incident Memory Scoring
Ranks past incidents by relevance using a composite score
that decays over time and boosts on tenant/technique match.
"""

import math
from dataclasses import dataclass


@dataclass
class IncidentScore:
    """Composite score for ranking past incidents."""
    vector_similarity: float  # 0.0-1.0, from Vector DB
    recency_decay: float      # 0.0-1.0, exponential decay
    tenant_match: float       # 0.0 or 1.0
    technique_overlap: float  # 0.0-1.0, Jaccard similarity of techniques
    composite: float = 0.0


# Weights (tune based on operational feedback)
ALPHA = 0.4   # vector similarity
BETA = 0.3    # recency
GAMMA = 0.15  # tenant match
DELTA = 0.15  # technique overlap

# Decay half-life in days
# exp(-0.023 * 30) ~ 0.5, so incidents from ~30 days ago score at half weight
LAMBDA = 0.023


def score_incident(
    vector_similarity: float,
    age_days: float,
    same_tenant: bool,
    technique_overlap: float,
) -> IncidentScore:
    """
    Compute composite relevance score for a past incident.

    score = alpha * vector_similarity
          + beta  * recency_decay
          + gamma * tenant_match
          + delta * technique_overlap

    recency_decay = exp(-lambda * age_in_days)

    A "deep history" toggle can extend the search window by setting
    BETA to 0.1 and redistributing weight to ALPHA for unusual investigations.
    """
    recency_decay = math.exp(-LAMBDA * age_days)
    tenant_match = 1.0 if same_tenant else 0.0

    composite = (
        ALPHA * vector_similarity
        + BETA * recency_decay
        + GAMMA * tenant_match
        + DELTA * technique_overlap
    )

    return IncidentScore(
        vector_similarity=vector_similarity,
        recency_decay=recency_decay,
        tenant_match=tenant_match,
        technique_overlap=technique_overlap,
        composite=composite,
    )
```

### 5.5 False Positive Pattern Store

A specialised sub-store within Incident Memory that tracks confirmed false positive patterns. FP patterns live in two places:

**Redis: Hot FP patterns (sub-millisecond matching at triage time)**

```
# Redis key patterns for FP pattern lookup
fp:hot:<pattern_id>  → JSON: {
    pattern_name, alert_names[], conditions: {process, time_window, asset_tag, ueba_risk},
    confidence_threshold, auto_close, occurrences, last_occurrence,
    approved_by, approval_date
}

# Lookup by alert name for fast matching during triage
fp:alert:<alert_name_hash>  → SET of pattern_ids that match this alert name
```

**Postgres: Approved FP patterns (full history, audit trail)**

```sql
CREATE TABLE fp_patterns (
    pattern_id          TEXT PRIMARY KEY,
    pattern_name        TEXT NOT NULL,
    alert_names         TEXT[] NOT NULL,
    conditions          JSONB NOT NULL,      -- {process, time_window, asset_tag, ueba_risk_threshold}
    confidence_threshold FLOAT NOT NULL DEFAULT 0.90,
    auto_close          BOOLEAN DEFAULT TRUE,
    occurrences         INTEGER DEFAULT 0,
    last_occurrence     TIMESTAMPTZ,
    approved_by         TEXT NOT NULL,
    approval_date       TIMESTAMPTZ NOT NULL,
    status              TEXT DEFAULT 'active', -- 'active', 'expired', 'revoked'
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_fp_alert_names ON fp_patterns USING GIN (alert_names);
CREATE INDEX idx_fp_status ON fp_patterns (status);
```

**FP Pattern Reference (JSON):**
```json
{
    "pattern_id": "fp-pattern-psexec-maintenance",
    "pattern_name": "PsExec during scheduled maintenance",
    "alert_names": ["Suspicious lateral movement detected", "PsExec activity on endpoint"],
    "conditions": {
        "process": "psexec.exe",
        "time_window": "maintenance_schedule",
        "asset_tag": "maintenance-group",
        "ueba_risk": "< 3"
    },
    "confidence_threshold": 0.90,
    "auto_close": true,
    "occurrences": 47,
    "last_occurrence": "2026-02-14",
    "approved_by": "analyst@soc.contoso.com",
    "approval_date": "2026-02-01"
}
```

The Triage Agent checks the Redis FP pattern store *before* running the full investigation pipeline. If a high-confidence FP pattern matches, the alert is auto-closed with a reference to the approved pattern. This dramatically reduces unnecessary LLM calls.

---

## 6. Organisational Context Index Design

### 6.1 Data Sources

| Source | Content | Integration Method |
|---|---|---|
| **Identity Provider** (Entra ID, Okta, etc.) | User profiles, group memberships, roles | IdP API (via adapter) |
| **Watchlists / custom lists** | VIP users, critical assets, maintenance windows | Config file, API, or Postgres direct |
| **CMDB / Asset Inventory** | Server roles, criticality tiers, network segments | API or CSV import |
| **Change Management** | Scheduled maintenance, deployments | ServiceNow/Jira API or manual |
| **Neo4j / Memgraph** (optional) | Asset relationships, zone graph | Graph DB API |

### 6.2 Postgres: Org Context Store

```sql
CREATE TABLE org_context (
    doc_id              TEXT PRIMARY KEY,
    entity_type         TEXT NOT NULL,          -- 'device', 'user', 'network_segment'
    entity_name         TEXT NOT NULL,
    criticality         TEXT DEFAULT 'medium',  -- 'critical', 'high', 'medium', 'low'
    role                TEXT,                   -- 'Domain Controller', 'Web Server', etc.
    network_segment     TEXT,
    owner               TEXT,
    business_unit       TEXT,
    maintenance_window  TEXT,                   -- cron-like or human-readable
    normal_services     TEXT[],
    normal_admin_users  TEXT[],
    alert_suppression_rules JSONB,
    tags                TEXT[],
    tenant_id           TEXT NOT NULL DEFAULT 'default',
    last_updated        TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_org_entity_name ON org_context (entity_name);
CREATE INDEX idx_org_entity_type ON org_context (entity_type);
CREATE INDEX idx_org_criticality ON org_context (criticality);
CREATE INDEX idx_org_tenant ON org_context (tenant_id);
CREATE INDEX idx_org_tags ON org_context USING GIN (tags);
```

**Org Context Reference (JSON):**
```json
{
    "doc_id": "asset-srv-dc01",
    "doc_type": "organisational_context",
    "entity_type": "device",
    "entity_name": "SRV-DC01",
    "criticality": "critical",
    "role": "Domain Controller",
    "network_segment": "10.0.1.0/24 - Server VLAN",
    "owner": "infra-team@contoso.com",
    "business_unit": "IT Infrastructure",
    "maintenance_window": "Sunday 02:00-06:00 UTC",
    "normal_services": ["Active Directory", "DNS", "LDAP", "Kerberos"],
    "normal_admin_users": ["admin@contoso.com", "svc-backup@contoso.com"],
    "alert_suppression_rules": [
        "Suppress PsExec alerts during maintenance window from admin@contoso.com"
    ],
    "tags": ["domain-controller", "tier-0", "critical-infrastructure"]
}
```

> **Why a separate table (not embedded in other stores)?** Organisational context changes frequently (new employees, server decommissions, maintenance schedule updates) but is small in volume. Keeping it in its own Postgres table allows fast, full re-ingestion without touching the much larger MITRE or TI stores. For environments that need asset-relationship graph queries (e.g., "what downstream systems does this server feed?"), the Neo4j graph described in `docs/ai-system-design.md` Section 8 supplements this table.

---

## 7. Storage Backend Configuration

### 7.1 Storage Architecture Summary

| Store | Document Count (Est.) | Update Frequency | Query Mode |
|---|---|---|---|
| **Postgres: mitre_techniques** | ~1,500 | Quarterly | Structured queries, JOINs, exact-match |
| **Postgres: threat_intel_iocs** | 10,000-100,000+ | Hourly/Daily | Structured queries, filtering |
| **Postgres: playbooks** | 50-500 (grows over time) | On change | Structured queries, filtering |
| **Postgres: incident_memory** | Grows continuously | Per-incident | Structured queries, time-range, filtering |
| **Postgres: org_context** | 100-5,000 | Daily | Keyword + filtering |
| **Vector DB: aluskort-mitre** | ~1,500 | Quarterly | Cosine similarity + metadata filters |
| **Vector DB: aluskort-threat-intel** | 10,000-100,000+ chunks | Hourly/Daily | Cosine similarity + metadata filters |
| **Vector DB: aluskort-playbooks** | 50-500 | On change | Cosine similarity |
| **Vector DB: aluskort-incident-memory** | Grows continuously | Per-incident | Cosine similarity + time decay + metadata |
| **Redis: IOC cache** | 50,000-500,000 keys | Continuous (TTL-based) | Exact key match, O(1) |
| **Redis: FP patterns** | 100-1,000 | On analyst approval | Exact key match, SET membership |

### 7.2 Search Strategy: Split Retrieval with Cross-Encoder Reranking

Every agent query follows this retrieval pipeline:

```
Agent Query (natural language or structured)
    |
    v
┌─────────────────────────────────────────┐
│ Step 1: Query Classification            │
│ Determine query type:                   │
│   - IOC lookup (exact match)  → Redis   │
│   - Technique lookup (ID)     → Postgres│
│   - Semantic question         → Vector  │
│   - Procedural (playbook)     → Vector  │
│   - Historical (memory)       → Vector  │
│   - Structured filter         → Postgres│
│   - Multi-store for complex queries     │
└─────────────────┬───────────────────────┘
                  |
                  v
┌─────────────────────────────────────────┐
│ Step 2: Store Routing                   │
│ Route to appropriate backend(s):        │
│   - "Is IP X malicious?" → Redis        │
│   - "What is T1059?" → Postgres         │
│   - "What technique does this match?"   │
│       → Vector DB (cosine similarity)   │
│   - "How to respond?" → Vector DB       │
│   - "Seen before?" → Vector DB + PG     │
│   - Complex → multi-store fan-out       │
└─────────────────┬───────────────────────┘
                  |
                  v
┌─────────────────────────────────────────┐
│ Step 3: Parallel Retrieval              │
│   Vector DB: cosine similarity search   │
│     + metadata filtering (tactic, date) │
│     Top-k = 20 candidates               │
│   Postgres: structured query            │
│     WHERE + JOIN + full-text if needed   │
│   Redis: exact key match                │
│     O(1) per IOC                        │
└─────────────────┬───────────────────────┘
                  |
                  v
┌─────────────────────────────────────────┐
│ Step 4: Reranking (optional)            │
│   Option A: Cross-encoder reranker      │
│     (e.g., ms-marco-MiniLM, BGE)       │
│     Reranks 20 → top 5 most relevant   │
│   Option B: Time-decayed scoring        │
│     (for incident memory queries)       │
│   Option C: No reranking (exact match)  │
└─────────────────┬───────────────────────┘
                  |
                  v
┌─────────────────────────────────────────┐
│ Step 5: Context Assembly                │
│   Deduplicate across stores             │
│   Attach source attribution             │
│   Format for LLM consumption            │
│   Enforce token budget (max 4096 tokens)│
└─────────────────┬───────────────────────┘
                  |
                  v
LLM (via Model Router: Tier 0 or Tier 1)
    Grounded response with citations
```

> **Why cross-encoder reranking instead of Azure Semantic Ranker?** The Azure Semantic Ranker was a proprietary Azure AI Search feature. A cross-encoder reranker achieves the same effect (re-scoring retrieved candidates with a more powerful model) but is vendor-neutral. Options include `cross-encoder/ms-marco-MiniLM-L-12-v2` from sentence-transformers (runs locally), Cohere Rerank API, or any similar service. For incident memory queries, the time-decayed composite scoring (Section 5.4) replaces the reranker role.

### 7.3 Query Examples by Agent

**IOC Extractor** — Redis exact match:
```python
"""When IOC Extractor finds an IP in an alert, check Redis TI cache first."""

import redis
import json

r = redis.Redis(host="redis", port=6379, db=0, decode_responses=True)


def lookup_ioc(indicator_type: str, indicator_value: str) -> dict | None:
    """Sub-millisecond IOC lookup from Redis cache."""
    key = f"ioc:{indicator_type}:{indicator_value}"
    result = r.get(key)
    if result:
        return json.loads(result)
    return None


# Example: check an IP found in an alert
ioc_context = lookup_ioc("ipv4", "203.0.113.42")
# Returns: {confidence: 85, severity: "high", campaigns: ["SolarWinds"], ...}
```

**Context Enricher** — Vector DB semantic search for campaign context:
```python
"""After IOC match, retrieve full campaign context from Vector DB."""

from qdrant_client import QdrantClient
from qdrant_client.models import Filter, FieldCondition, MatchValue

client = QdrantClient(host="qdrant", port=6333)


def search_ti_reports(query_vector: list[float], threat_actor: str = None, top_k: int = 5) -> list:
    """Semantic search for TI report chunks related to a campaign or technique."""
    filters = []
    if threat_actor:
        filters.append(
            FieldCondition(key="threat_actors", match=MatchValue(value=threat_actor))
        )

    search_filter = Filter(must=filters) if filters else None

    results = client.search(
        collection_name="aluskort-threat-intel",
        query_vector=query_vector,
        query_filter=search_filter,
        limit=top_k,
        with_payload=True,
    )
    return results


# Example: find reports about Midnight Blizzard
# (query_vector would come from the embedding pipeline)
# results = search_ti_reports(query_vector, threat_actor="Midnight Blizzard")
```

**Reasoning Agent** — multi-store query for investigation context:
```python
"""
Reasoning Agent needs MITRE context + playbook + history.
Fan out to multiple stores in parallel.
"""

import psycopg
from qdrant_client import QdrantClient
from qdrant_client.models import Filter, FieldCondition, MatchAny

# Postgres connection
pg_conn = psycopg.connect("postgresql://aluskort:pass@postgres:5432/aluskort")

# Qdrant client
qdrant = QdrantClient(host="qdrant", port=6333)


def investigate(alert_description: str, techniques: list[str], query_vector: list[float]):
    """Multi-store retrieval for a full investigation context."""

    # Query 1: Postgres — What MITRE techniques match these IDs?
    with pg_conn.cursor() as cur:
        cur.execute(
            """
            SELECT technique_id, technique_name, description, detection,
                   groups_using, severity_baseline
            FROM mitre_techniques
            WHERE technique_id = ANY(%s)
            """,
            (techniques,),
        )
        mitre_results = cur.fetchall()

    # Query 2: Vector DB — Semantic search for similar MITRE techniques
    mitre_semantic = qdrant.search(
        collection_name="aluskort-mitre",
        query_vector=query_vector,
        query_filter=Filter(must=[
            FieldCondition(key="doc_type", match=MatchAny(any=["mitre_technique"])),
        ]),
        limit=3,
        with_payload=True,
    )

    # Query 3: Vector DB — What's the response playbook?
    playbook_results = qdrant.search(
        collection_name="aluskort-playbooks",
        query_vector=query_vector,  # embed "respond to {alert_description}"
        limit=2,
        with_payload=True,
    )

    # Query 4: Vector DB — Have we seen this before? (with time decay)
    history_results = qdrant.search(
        collection_name="aluskort-incident-memory",
        query_vector=query_vector,
        query_filter=Filter(must=[
            FieldCondition(key="outcome", match=MatchAny(any=["closed_true_positive"])),
        ]),
        limit=5,
        with_payload=True,
    )
    # Apply time-decayed scoring (Section 5.4) to history_results

    return {
        "mitre_structured": mitre_results,
        "mitre_semantic": mitre_semantic,
        "playbooks": playbook_results,
        "history": history_results,
    }
```

---

## 8. Embedding Strategy

### 8.1 Model Selection (Vendor-Neutral)

ALUSKORT supports any embedding model via configuration. The embedding pipeline is not tied to Azure OpenAI or any specific vendor.

| Model | Dimensions | Use Case | Rationale |
|---|---|---|---|
| **OpenAI text-embedding-3-large** | 3072 (or reduced to 1024) | Cloud-hosted option, high quality | Best commercial quality, supports `dimensions` parameter for cost/quality tradeoff |
| **Cohere embed-v3** | 1024 | Alternative cloud-hosted | Strong multilingual support, good for international TI |
| **sentence-transformers (local)** | 768-1024 | Self-hosted, air-gapped environments | No API dependency, runs on GPU or CPU, models like `all-MiniLM-L6-v2` or `bge-large-en-v1.5` |
| **Foundation-Sec embeddings** (if available) | TBD | Security-domain-specific | Use if/when a high-quality security embedding model emerges from the Foundation-Sec family |

```python
"""
Embedding model configuration.
Select model via environment variable or config file.
"""

from dataclasses import dataclass


@dataclass
class EmbeddingConfig:
    """Configuration for the embedding pipeline."""
    provider: str          # 'openai', 'cohere', 'sentence-transformers', 'custom'
    model_name: str        # e.g. 'text-embedding-3-large', 'embed-v3', 'bge-large-en-v1.5'
    dimensions: int        # e.g. 1024, 3072
    api_base: str = ""     # API endpoint (for cloud providers)
    api_key: str = ""      # API key (from secrets manager, not hardcoded)
    batch_size: int = 32   # Max texts per API call
    local_model_path: str = ""  # Path to local model (for sentence-transformers)


# Default configurations per provider
EMBEDDING_CONFIGS = {
    "openai": EmbeddingConfig(
        provider="openai",
        model_name="text-embedding-3-large",
        dimensions=1024,  # Reduced from 3072 for cost/storage savings
        batch_size=16,
    ),
    "cohere": EmbeddingConfig(
        provider="cohere",
        model_name="embed-english-v3.0",
        dimensions=1024,
        batch_size=96,
    ),
    "local": EmbeddingConfig(
        provider="sentence-transformers",
        model_name="BAAI/bge-large-en-v1.5",
        dimensions=1024,
        batch_size=64,
        local_model_path="/models/bge-large-en-v1.5",
    ),
}
```

> **Why not a security-domain-specific embedding model?** As of 2026, no security-specific embedding model matches frontier commercial models on retrieval quality for mixed security content. A cross-encoder reranker (Section 7.2) compensates for domain-specific gaps. Revisit if a high-quality security embedding model emerges (e.g., from Foundation-Sec family).

### 8.2 What Gets Embedded

Not everything needs a vector. Use vectors for semantic search, keywords/exact-match for structured data.

| Field Type | Search Method | Store | Example |
|---|---|---|---|
| Free-text descriptions | **Vector (cosine similarity)** | Vector DB | Technique descriptions, report summaries |
| IOC values | **Exact match (key-value)** | Redis | IP addresses, hashes, domains |
| Technique IDs | **Exact match (indexed column)** | Postgres | T1059.001, CVE-2024-12345 |
| Tags and categories | **Filterable metadata** | Postgres + Vector DB payload | Tactics, platforms, severity |
| Dates | **Filterable, sortable** | Postgres + Vector DB payload | timestamp, last_updated |
| Procedural steps | **Vector + structured** | Vector DB + Postgres | Playbook step descriptions |

### 8.3 Embedding Pipeline

```python
"""
ALUSKORT Embedding Pipeline (Vendor-Neutral)
Generates embeddings for documents before storing in the Vector DB.
Supports multiple embedding providers via configuration.
"""

from dataclasses import dataclass
from typing import Protocol


class EmbeddingClient(Protocol):
    """Protocol for any embedding provider."""
    def embed(self, texts: list[str]) -> list[list[float]]:
        ...


class OpenAIEmbeddings:
    """OpenAI-compatible embedding client (works with OpenAI, Azure OpenAI, vLLM, etc.)."""

    def __init__(self, api_base: str, api_key: str, model: str, dimensions: int):
        from openai import OpenAI
        self.client = OpenAI(base_url=api_base, api_key=api_key)
        self.model = model
        self.dimensions = dimensions

    def embed(self, texts: list[str]) -> list[list[float]]:
        response = self.client.embeddings.create(
            input=texts,
            model=self.model,
            dimensions=self.dimensions,
        )
        return [item.embedding for item in response.data]


class SentenceTransformerEmbeddings:
    """Local sentence-transformers embedding client."""

    def __init__(self, model_path: str):
        from sentence_transformers import SentenceTransformer
        self.model = SentenceTransformer(model_path)

    def embed(self, texts: list[str]) -> list[list[float]]:
        embeddings = self.model.encode(texts, normalize_embeddings=True)
        return embeddings.tolist()


class CohereEmbeddings:
    """Cohere embedding client."""

    def __init__(self, api_key: str, model: str):
        import cohere
        self.client = cohere.Client(api_key)
        self.model = model

    def embed(self, texts: list[str]) -> list[list[float]]:
        response = self.client.embed(
            texts=texts,
            model=self.model,
            input_type="search_document",
        )
        return response.embeddings


def create_embedding_text(doc: dict) -> str:
    """
    Create the text to embed for a document.
    Concatenates the most semantically meaningful fields.
    Different strategy per doc_type.
    """
    doc_type = doc.get("doc_type", "")

    if doc_type == "mitre_technique":
        # Technique: name + description + detection guidance
        parts = [
            f"MITRE ATT&CK Technique {doc.get('technique_id', '')}: {doc.get('technique_name', '')}",
            doc.get("description", ""),
            f"Detection: {doc.get('detection', '')}",
            f"Platforms: {', '.join(doc.get('platforms', []))}",
            f"Used by: {', '.join(doc.get('groups_using', [])[:5])}",
        ]
        return '\n'.join(p for p in parts if p)

    elif doc_type == "mitre_group":
        parts = [
            f"Threat Group: {doc.get('group_name', '')}",
            f"Aliases: {', '.join(doc.get('aliases', []))}",
            doc.get("description", ""),
            f"Target sectors: {', '.join(doc.get('target_sectors', []))}",
        ]
        return '\n'.join(p for p in parts if p)

    elif doc_type == "threat_intel_report":
        parts = [
            doc.get("title", ""),
            doc.get("summary", ""),
            f"Threat actors: {', '.join(doc.get('threat_actors', []))}",
            f"MITRE techniques: {', '.join(doc.get('mitre_techniques', []))}",
            doc.get("detection_guidance", ""),
        ]
        return '\n'.join(p for p in parts if p)

    elif doc_type == "playbook":
        parts = [
            doc.get("title", ""),
            f"Category: {doc.get('category', '')}",
            f"MITRE techniques: {', '.join(doc.get('mitre_techniques', []))}",
        ]
        # Include step descriptions (but not queries - those are for exact search)
        for step in doc.get("steps", []):
            parts.append(f"Step {step['step']}: {step['action']} - {step['description']}")
        return '\n'.join(p for p in parts if p)

    elif doc_type == "incident_memory":
        parts = [
            f"Alert: {doc.get('alert_name', '')}",
            doc.get("investigation_summary", ""),
            f"Classification: {doc.get('classification', {}).get('final', '')}",
            doc.get("lessons_learned", ""),
        ]
        return '\n'.join(p for p in parts if p)

    else:
        # Fallback: concatenate all string fields
        return ' '.join(
            str(v) for v in doc.values()
            if isinstance(v, str) and len(v) > 10
        )


def generate_embeddings(
    client: EmbeddingClient,
    texts: list[str],
    batch_size: int = 32,
) -> list[list[float]]:
    """
    Generate embeddings in batches using any provider.
    The client handles provider-specific API details.
    """
    all_embeddings = []
    for i in range(0, len(texts), batch_size):
        batch = texts[i:i + batch_size]
        batch_embeddings = client.embed(batch)
        all_embeddings.extend(batch_embeddings)
    return all_embeddings
```

---

## 9. Retrieval Quality Assurance

### 9.1 Evaluation Dataset

Build a golden evaluation set of query-answer pairs for each domain:

| Domain | Query Example | Expected Top-1 Result | Metric |
|---|---|---|---|
| MITRE | "What technique involves PowerShell execution?" | T1059.001 | Hit@1 |
| MITRE | "How to detect credential dumping?" | T1003 (OS Credential Dumping) | Hit@3 |
| TI | "Is 203.0.113.42 a known malicious IP?" | Exact IOC match from Redis | Precision |
| TI | "What campaigns target healthcare?" | Relevant campaign report chunks | NDCG@5 |
| Playbook | "How to respond to ransomware?" | Ransomware IR playbook | Hit@1 |
| Memory | "Have we seen PsExec FP during maintenance?" | Relevant FP pattern | Hit@3 |

### 9.2 Quality Metrics

| Metric | Target | Measurement |
|---|---|---|
| **Hit@1** (exact match in top result) | > 85% | Automated eval on golden set |
| **Hit@3** (correct in top 3) | > 95% | Automated eval on golden set |
| **NDCG@5** (ranking quality) | > 0.80 | Automated eval on golden set |
| **IOC exact match recall** | 100% | All known IOCs retrievable by exact value from Redis |
| **Retrieval latency — Redis (p95)** | < 5ms | Prometheus/Grafana on Redis |
| **Retrieval latency — Vector DB (p95)** | < 100ms | Prometheus/Grafana on Qdrant |
| **Retrieval latency — Postgres (p95)** | < 50ms | `pg_stat_statements` monitoring |
| **Grounded answer accuracy** | > 90% | Manual review (weekly sample) |

### 9.3 Failure Modes and Mitigations

| Failure Mode | Detection | Mitigation |
|---|---|---|
| **Stale TI data** | IOC with expired TTL still in Redis | TTL enforcement in Redis, daily cleanup job in Postgres |
| **MITRE version drift** | New techniques not in index after ATT&CK release | Automated quarterly re-index triggered by MITRE release RSS. Publish to Kafka topic `knowledge.mitre.updated` |
| **Embedding model change** | Provider deprecates model version or dimensions change | Pin model version in config. Test new version on eval set before migration. Requires full re-embedding of all collections |
| **Vector DB size growth** (incident memory) | Query latency degradation | Archive incidents > 12 months to Postgres (cold storage), keep hot Vector DB collection < 100K points |
| **Retrieval hallucination** | LLM cites non-existent MITRE technique | Post-retrieval validation: verify technique ID against `taxonomy_ids` table in Postgres (Context Gateway handles this) |
| **Redis cache miss storm** | Burst of lookups for uncached IOCs | Read-through cache pattern: on miss, query Postgres, populate Redis with appropriate TTL |
| **Postgres connection exhaustion** | Connection pool saturated during high-volume ingestion | Use PgBouncer or equivalent connection pooler. Separate read/write pools |

---

## 10. Data Ingestion Pipeline Architecture

```
                    INGESTION PIPELINES
                    (Kafka-driven, containerised workers)

    ┌──────────────┐    ┌──────────────┐    ┌──────────────┐
    │ MITRE        │    │ THREAT       │    │ INCIDENT     │
    │ ATT&CK/ATLAS │    │ INTEL        │    │ MEMORY       │
    │ Ingester     │    │ Ingester     │    │ Ingester     │
    │              │    │              │    │              │
    │ Quarterly    │    │ Hourly       │    │ Real-time    │
    │ Full re-index│    │ Incremental  │    │ Per-incident │
    └──────┬───────┘    └──────┬───────┘    └──────┬───────┘
           │                   │                   │
           ▼                   ▼                   ▼
    ┌─────────────────────────────────────────────────────────┐
    │              DOCUMENT PROCESSOR                          │
    │                                                          │
    │  1. Parse source format (STIX, HTML, JSON)               │
    │  2. Extract metadata (IOCs, techniques, entities)        │
    │  3. Apply chunking strategy (per doc_type)               │
    │  4. Generate embedding text (create_embedding_text())    │
    │  5. Call embedding provider (vendor-neutral)             │
    │  6. Build storage payloads for each target store         │
    └──────────────────────┬──────────────────────────────────┘
                           │
                           ▼
    ┌─────────────────────────────────────────────────────────┐
    │              MULTI-STORE WRITER                          │
    │                                                          │
    │  ┌────────────┐  ┌────────────┐  ┌──────────────────┐   │
    │  │ Postgres   │  │ Vector DB  │  │ Redis            │   │
    │  │ Upsert     │  │ Upsert     │  │ SET with TTL     │   │
    │  │ (ON        │  │ (point     │  │                  │   │
    │  │  CONFLICT) │  │  upsert)   │  │                  │   │
    │  └────────────┘  └────────────┘  └──────────────────┘   │
    │                                                          │
    │  Object Store: raw artifacts (PDFs, model weights)       │
    │  Kafka: publish to knowledge.*.updated topics            │
    └─────────────────────────────────────────────────────────┘
```

### Kafka Topics for Knowledge Updates

```
Message Bus (Kafka / Redpanda / NATS)
│
├── knowledge.mitre.updated          # MITRE ATT&CK/ATLAS re-indexed
├── knowledge.ti.ioc.new             # New IOC ingested
├── knowledge.ti.report.new          # New TI report chunked and stored
├── knowledge.playbook.updated       # Playbook added/approved/deprecated
├── knowledge.incident.stored        # New incident record written to memory
├── knowledge.fp.approved            # New FP pattern approved by analyst
├── knowledge.org.updated            # Org context re-ingested
└── knowledge.embedding.reindex      # Trigger full re-embedding of a collection
```

### Update Cadence Summary

| Pipeline | Trigger | Volume | Stores Written |
|---|---|---|---|
| MITRE ATT&CK / ATLAS | Quarterly (or manual trigger) | ~1,500 docs full re-index | Postgres + Vector DB |
| Threat Intel - IOCs | Hourly (timer trigger) | 10-100 new IOCs/hour | Redis + Postgres |
| Threat Intel - Reports | Daily (timer trigger) | 1-10 reports/day | Postgres + Vector DB + Object Store (PDF) |
| Playbooks | On change (manual or CI/CD) | Handful at a time | Postgres + Vector DB |
| Incident Memory | Per-incident (event trigger) | 10-100 incidents/day | Postgres + Vector DB |
| Org Context | Daily (timer trigger) | Full re-index, small volume | Postgres |
| FP Patterns | On analyst approval | Low volume | Redis + Postgres |

---

## 11. Cost Estimation (Vendor-Neutral)

Costs are infrastructure-based, not tied to Azure AI Search tiers. Self-hosted options reduce to hardware + maintenance; managed services have their own pricing.

### Infrastructure Costs

| Component | Self-Hosted (Estimate) | Managed Service (Estimate) | Notes |
|---|---|---|---|
| **PostgreSQL** | $50-150/mo (dedicated VM or container) | $100-400/mo (RDS, Cloud SQL, etc.) | Scales with incident volume. Partitioning keeps queries fast |
| **Qdrant / Weaviate** | $50-200/mo (dedicated VM with 16GB+ RAM) | $100-500/mo (Qdrant Cloud, Weaviate Cloud) | Scales with vector count. < 500K vectors fits in 16GB RAM |
| **Redis / KeyDB** | $20-50/mo (2-4GB RAM) | $50-200/mo (ElastiCache, Memorystore, etc.) | IOC cache is small. 500K keys ~ 1GB RAM |
| **Object Store** | $5-20/mo (MinIO on local storage) | $5-50/mo (S3, GCS, etc.) | Low cost, mostly archival |
| **Kafka / Redpanda** | $50-150/mo (3-node cluster) | $100-500/mo (Confluent, Redpanda Cloud) | Right-size based on message throughput |

### Embedding Costs

| Operation | Volume | Cost (Est.) |
|---|---|---|
| Initial MITRE indexing | ~1,500 docs | < $1 (one-time, any provider) |
| Daily TI ingestion | ~500 docs/day | ~$0.30-0.50/day (cloud API) or $0/day (local model) |
| Per-incident embedding | ~100 incidents/day | ~$0.05-0.10/day |
| Query-time embeddings | ~1,000 queries/day | ~$0.05-0.10/day |
| **Monthly total (cloud API)** | | ~$15-25/mo |
| **Monthly total (self-hosted)** | | GPU amortisation only |

> **Cost is dominated by infrastructure (Postgres, Vector DB, Kafka), not embeddings.** Embedding costs are negligible compared to the storage and compute infrastructure. For cost-sensitive deployments, use pgvector (Postgres extension) to combine relational and vector storage in one database, eliminating the separate Vector DB cost.

---

*Document generated by Omeriko (KB v2.0) for ALUSKORT project. This design covers the complete RAG knowledge base architecture for the autonomous SOC agent, using cloud-neutral split retrieval. See `docs/ai-system-design.md` for the overall system design context. Next recommended: DP (Data Pipeline) to detail ingestion pipelines, or TS (Training Strategy) for fine-tuning.*
