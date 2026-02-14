"""Entity models for parsed alert entities."""

from __future__ import annotations

from enum import Enum
from typing import Any, Optional

from pydantic import BaseModel


class EntityType(str, Enum):
    """All entity types extracted from alerts."""

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
    CLOUD_APPLICATION = "cloud-application"
    MALWARE = "malware"


class NormalizedEntity(BaseModel):
    """A single normalised entity extracted from an alert."""

    entity_type: EntityType
    primary_value: str
    properties: dict[str, Any] = {}
    confidence: float = 1.0
    source_id: Optional[str] = None


class AlertEntities(BaseModel):
    """Typed container for all entities parsed from a single alert."""

    accounts: list[NormalizedEntity] = []
    hosts: list[NormalizedEntity] = []
    ips: list[NormalizedEntity] = []
    files: list[NormalizedEntity] = []
    processes: list[NormalizedEntity] = []
    urls: list[NormalizedEntity] = []
    dns_records: list[NormalizedEntity] = []
    file_hashes: list[NormalizedEntity] = []
    mailboxes: list[NormalizedEntity] = []
    other: list[NormalizedEntity] = []
    raw_iocs: list[str] = []
    parse_errors: list[str] = []
