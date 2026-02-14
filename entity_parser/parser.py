"""Entity parsing engine — Story 3.1.

Parses source-specific entity formats into normalised ``AlertEntities``.
Supports structured Sentinel-style JSON arrays and regex fallback for
other sources.
"""

from __future__ import annotations

import json
import logging
import re
from typing import Any

from shared.schemas.entity import AlertEntities, EntityType, NormalizedEntity

from entity_parser.validation import (
    sanitize_value,
    validate_hash,
    validate_ip,
)

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Regex fallback patterns for IOC extraction from raw text
# ---------------------------------------------------------------------------
_RE_IPV4 = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_RE_SHA256 = re.compile(r"\b[a-fA-F0-9]{64}\b")
_RE_SHA1 = re.compile(r"\b[a-fA-F0-9]{40}\b")
_RE_DOMAIN = re.compile(
    r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+"
    r"(?:com|net|org|io|ru|cn|xyz|gov|edu|mil|co|uk|de|fr|us|ca|au)\b"
)

# Sentinel entity type name → EntityType mapping
_TYPE_MAP: dict[str, EntityType] = {
    "account": EntityType.ACCOUNT,
    "host": EntityType.HOST,
    "ip": EntityType.IP,
    "file": EntityType.FILE,
    "process": EntityType.PROCESS,
    "url": EntityType.URL,
    "dns": EntityType.DNS,
    "filehash": EntityType.FILEHASH,
    "mailbox": EntityType.MAILBOX,
    "mailmessage": EntityType.MAILMESSAGE,
    "registrykey": EntityType.REGISTRY_KEY,
    "registryvalue": EntityType.REGISTRY_VALUE,
    "securitygroup": EntityType.SECURITY_GROUP,
    "cloudapplication": EntityType.CLOUD_APPLICATION,
    "malware": EntityType.MALWARE,
}


# ===== public entry point ===================================================

def parse_alert_entities(entities_raw: str, raw_payload: dict[str, Any] | None = None) -> AlertEntities:
    """Parse entities from *entities_raw* JSON string.

    Falls back to regex IOC extraction from *raw_payload* (or from
    *entities_raw* itself) when JSON parsing fails.
    """
    result = AlertEntities()

    # --- attempt structured parse ----------------------------------------
    if entities_raw and entities_raw.strip():
        try:
            entities_list = json.loads(entities_raw)
            if isinstance(entities_list, list):
                _parse_structured(entities_list, result)
            else:
                result.parse_errors.append("entities_raw is not a JSON array")
                _extract_iocs_from_raw(entities_raw, result)
        except json.JSONDecodeError as exc:
            result.parse_errors.append(f"entities_raw JSON error: {exc}")
            _extract_iocs_from_raw(entities_raw, result)
    else:
        # No structured entities — try regex on raw_payload
        if raw_payload:
            _extract_iocs_from_raw(json.dumps(raw_payload), result)

    return result


# ===== structured parsing ===================================================

def _parse_structured(entities: list[Any], result: AlertEntities) -> None:
    """Walk a Sentinel-style entity JSON array."""
    # Build $id → entity lookup for $ref resolution
    id_lookup: dict[str, dict[str, Any]] = {}
    for ent in entities:
        if isinstance(ent, dict) and "$id" in ent:
            id_lookup[ent["$id"]] = ent

    for raw in entities:
        if not isinstance(raw, dict):
            result.parse_errors.append(f"Non-dict entity skipped: {type(raw).__name__}")
            continue

        type_str = raw.get("Type", "").lower().strip()
        entity_type = _TYPE_MAP.get(type_str)
        if entity_type is None:
            result.parse_errors.append(f"Unknown entity type: {raw.get('Type')}")
            continue

        try:
            handler = _PARSERS.get(entity_type, _parse_generic)
            handler(raw, result, id_lookup)
        except Exception as exc:
            result.parse_errors.append(f"Error parsing {type_str}: {exc}")


# ===== type-specific parsers ================================================

def _parse_account(raw: dict, result: AlertEntities, id_lookup: dict) -> None:
    name = sanitize_value(raw.get("Name", ""), "Name")
    upn_suffix = sanitize_value(raw.get("UPNSuffix", ""), "UPNSuffix")
    aad_user_id = sanitize_value(raw.get("AadUserId", ""), "AadUserId")
    sid = sanitize_value(raw.get("Sid", ""), "Sid")

    if name and upn_suffix:
        primary = f"{name}@{upn_suffix}"
    elif aad_user_id:
        primary = aad_user_id
    elif name:
        primary = name
    else:
        result.parse_errors.append("Account entity missing Name and AadUserId")
        return

    entity = NormalizedEntity(
        entity_type=EntityType.ACCOUNT,
        primary_value=primary,
        properties={
            k: v for k, v in {
                "name": name,
                "upn_suffix": upn_suffix,
                "aad_user_id": aad_user_id,
                "sid": sid,
                "is_domain_joined": raw.get("IsDomainJoined"),
                "dns_domain": sanitize_value(raw.get("DnsDomain", ""), "DnsDomain"),
            }.items() if v is not None
        },
        source_id=raw.get("$id"),
    )
    result.accounts.append(entity)
    result.raw_iocs.append(primary)


def _parse_host(raw: dict, result: AlertEntities, id_lookup: dict) -> None:
    hostname = sanitize_value(raw.get("HostName", ""), "HostName")
    netbios = sanitize_value(raw.get("NetBiosName", ""), "NetBiosName")
    dns_domain = sanitize_value(raw.get("DnsDomain", ""), "DnsDomain")

    host = hostname or netbios
    if not host:
        result.parse_errors.append("Host entity missing HostName and NetBiosName")
        return

    primary = f"{host}.{dns_domain}" if dns_domain else host

    entity = NormalizedEntity(
        entity_type=EntityType.HOST,
        primary_value=primary,
        properties={
            k: v for k, v in {
                "hostname": host,
                "dns_domain": dns_domain,
                "os_family": raw.get("OSFamily"),
                "os_version": raw.get("OSVersion"),
                "resource_id": sanitize_value(raw.get("AzureID", ""), "AzureID"),
                "edr_device_id": sanitize_value(raw.get("MdatpDeviceId", ""), "MdatpDeviceId"),
            }.items() if v is not None
        },
        source_id=raw.get("$id"),
    )
    result.hosts.append(entity)
    result.raw_iocs.append(primary)


def _parse_ip(raw: dict, result: AlertEntities, id_lookup: dict) -> None:
    address = sanitize_value(raw.get("Address", ""), "Address")
    if not address:
        result.parse_errors.append("IP entity missing Address")
        return

    if not validate_ip(address):
        result.parse_errors.append(f"Invalid IP address: {address}")
        return

    props: dict[str, Any] = {}
    location = raw.get("Location")
    if isinstance(location, dict):
        for src, dst in (
            ("CountryCode", "geo_country"),
            ("City", "geo_city"),
            ("Asn", "asn"),
            ("Carrier", "carrier"),
        ):
            val = location.get(src)
            if val is not None:
                props[dst] = val

    entity = NormalizedEntity(
        entity_type=EntityType.IP,
        primary_value=address,
        properties=props,
        source_id=raw.get("$id"),
    )
    result.ips.append(entity)
    result.raw_iocs.append(address)


def _parse_file(raw: dict, result: AlertEntities, id_lookup: dict) -> None:
    name = sanitize_value(raw.get("Name", ""), "Name") or "unknown"
    directory = sanitize_value(raw.get("Directory", ""), "Directory")
    full_path = f"{directory}\\{name}" if directory else name

    entity = NormalizedEntity(
        entity_type=EntityType.FILE,
        primary_value=name,
        properties={
            k: v for k, v in {
                "directory": directory,
                "full_path": full_path,
                "size": raw.get("SizeInBytes"),
            }.items() if v is not None
        },
        source_id=raw.get("$id"),
    )
    result.files.append(entity)

    # Extract file hashes if present
    file_hashes = raw.get("FileHashes")
    if isinstance(file_hashes, list):
        for fh in file_hashes:
            if isinstance(fh, dict):
                _parse_filehash(fh, result, id_lookup)


def _parse_process(raw: dict, result: AlertEntities, id_lookup: dict) -> None:
    process_id = raw.get("ProcessId")
    command_line = sanitize_value(raw.get("CommandLine", ""), "CommandLine")

    # Resolve $ref to ImageFile
    image_name = None
    image_ref = raw.get("ImageFile")
    if isinstance(image_ref, dict) and "$ref" in image_ref:
        ref_entity = id_lookup.get(image_ref["$ref"])
        if ref_entity:
            image_name = sanitize_value(ref_entity.get("Name", ""), "Name")
    elif isinstance(image_ref, dict):
        image_name = sanitize_value(image_ref.get("Name", ""), "Name")

    primary = image_name or str(process_id) if process_id else "unknown"

    entity = NormalizedEntity(
        entity_type=EntityType.PROCESS,
        primary_value=primary,
        properties={
            k: v for k, v in {
                "process_id": process_id,
                "command_line": command_line,
                "image_name": image_name,
                "parent_process_id": raw.get("ParentProcessId"),
                "creation_time": raw.get("CreationTimeUtc"),
            }.items() if v is not None
        },
        source_id=raw.get("$id"),
    )
    result.processes.append(entity)


def _parse_url(raw: dict, result: AlertEntities, id_lookup: dict) -> None:
    url = sanitize_value(raw.get("Url", ""), "Url")
    if not url:
        result.parse_errors.append("URL entity missing Url")
        return

    entity = NormalizedEntity(
        entity_type=EntityType.URL,
        primary_value=url,
        properties={},
        source_id=raw.get("$id"),
    )
    result.urls.append(entity)
    result.raw_iocs.append(url)


def _parse_dns(raw: dict, result: AlertEntities, id_lookup: dict) -> None:
    domain = sanitize_value(raw.get("DomainName", ""), "DomainName")
    if not domain:
        result.parse_errors.append("DNS entity missing DomainName")
        return

    resolved = raw.get("IpAddresses", [])
    entity = NormalizedEntity(
        entity_type=EntityType.DNS,
        primary_value=domain,
        properties={"resolved_ips": resolved} if resolved else {},
        source_id=raw.get("$id"),
    )
    result.dns_records.append(entity)
    result.raw_iocs.append(domain)


def _parse_filehash(raw: dict, result: AlertEntities, id_lookup: dict) -> None:
    algorithm = raw.get("Algorithm", "")
    value = sanitize_value(raw.get("Value", ""), "Value")
    if not value:
        result.parse_errors.append("FileHash entity missing Value")
        return

    if not validate_hash(value, algorithm):
        result.parse_errors.append(f"Invalid hash ({algorithm}): {value[:20]}")
        return

    entity = NormalizedEntity(
        entity_type=EntityType.FILEHASH,
        primary_value=value.lower(),
        properties={"algorithm": algorithm} if algorithm else {},
        source_id=raw.get("$id"),
    )
    result.file_hashes.append(entity)
    result.raw_iocs.append(value.lower())


def _parse_mailbox(raw: dict, result: AlertEntities, id_lookup: dict) -> None:
    address = sanitize_value(
        raw.get("MailboxPrimaryAddress", ""), "MailboxPrimaryAddress"
    )
    if not address:
        result.parse_errors.append("Mailbox entity missing MailboxPrimaryAddress")
        return

    entity = NormalizedEntity(
        entity_type=EntityType.MAILBOX,
        primary_value=address,
        properties={
            k: v for k, v in {
                "display_name": sanitize_value(raw.get("DisplayName", ""), "DisplayName"),
                "upn": sanitize_value(raw.get("Upn", ""), "Upn"),
            }.items() if v is not None
        },
        source_id=raw.get("$id"),
    )
    result.mailboxes.append(entity)
    result.raw_iocs.append(address)


def _parse_generic(raw: dict, result: AlertEntities, id_lookup: dict) -> None:
    """Fallback parser for entity types without a specialised handler."""
    type_str = raw.get("Type", "unknown")
    entity_type = _TYPE_MAP.get(type_str.lower().strip(), EntityType.MALWARE)

    # Use the first non-empty string value as primary
    primary = None
    for key, val in raw.items():
        if key.startswith("$") or key == "Type":
            continue
        cleaned = sanitize_value(str(val), key) if val is not None else None
        if cleaned:
            primary = cleaned
            break

    if not primary:
        result.parse_errors.append(f"Generic entity ({type_str}) has no usable value")
        return

    entity = NormalizedEntity(
        entity_type=entity_type,
        primary_value=primary,
        properties={
            k: v for k, v in raw.items()
            if not k.startswith("$") and k != "Type"
        },
        source_id=raw.get("$id"),
    )
    result.other.append(entity)


# Handler dispatch table
_PARSERS: dict[EntityType, Any] = {
    EntityType.ACCOUNT: _parse_account,
    EntityType.HOST: _parse_host,
    EntityType.IP: _parse_ip,
    EntityType.FILE: _parse_file,
    EntityType.PROCESS: _parse_process,
    EntityType.URL: _parse_url,
    EntityType.DNS: _parse_dns,
    EntityType.FILEHASH: _parse_filehash,
    EntityType.MAILBOX: _parse_mailbox,
}


# ===== regex fallback =======================================================

def _extract_iocs_from_raw(text: str, result: AlertEntities) -> None:
    """Fallback: extract IOCs from raw text via regex."""
    seen: set[str] = set()

    for match in _RE_IPV4.findall(text):
        if validate_ip(match) and match not in seen:
            seen.add(match)
            result.ips.append(
                NormalizedEntity(
                    entity_type=EntityType.IP,
                    primary_value=match,
                    confidence=0.7,
                )
            )

    for match in _RE_SHA256.findall(text):
        val = match.lower()
        if val not in seen:
            seen.add(val)
            result.file_hashes.append(
                NormalizedEntity(
                    entity_type=EntityType.FILEHASH,
                    primary_value=val,
                    properties={"algorithm": "SHA256"},
                    confidence=0.8,
                )
            )

    for match in _RE_SHA1.findall(text):
        val = match.lower()
        # Skip if already captured as part of a sha256
        if val not in seen and not any(val in s for s in seen if len(s) == 64):
            seen.add(val)
            result.file_hashes.append(
                NormalizedEntity(
                    entity_type=EntityType.FILEHASH,
                    primary_value=val,
                    properties={"algorithm": "SHA1"},
                    confidence=0.7,
                )
            )

    for match in _RE_DOMAIN.findall(text):
        if match not in seen:
            seen.add(match)
            result.dns_records.append(
                NormalizedEntity(
                    entity_type=EntityType.DNS,
                    primary_value=match,
                    confidence=0.6,
                )
            )

    result.raw_iocs.extend(sorted(seen))
