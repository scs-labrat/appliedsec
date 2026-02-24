"""Hash chain computation and chain state management — Story 13.4.

Provides deterministic SHA-256 record hashing, genesis record creation,
event chaining, chain verification, and the :class:`ChainStateManager`.
"""

from __future__ import annotations

import hashlib
import json
import logging
import uuid
from datetime import datetime, timezone
from typing import Any

logger = logging.getLogger(__name__)

GENESIS_HASH = "0" * 64


def compute_record_hash(record_dict: dict[str, Any]) -> str:
    """Compute SHA-256 hex digest of the record excluding ``record_hash``."""
    d = {k: v for k, v in record_dict.items() if k != "record_hash"}
    canonical = json.dumps(d, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def create_genesis_record(tenant_id: str) -> dict[str, Any]:
    """Create a genesis record (sequence 0) for a new tenant."""
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
    record: dict[str, Any] = {
        "audit_id": str(uuid.uuid4()),
        "tenant_id": tenant_id,
        "sequence_number": 0,
        "previous_hash": GENESIS_HASH,
        "timestamp": now,
        "ingested_at": now,
        "event_type": "system.genesis",
        "event_category": "system",
        "severity": "info",
        "actor_type": "system",
        "actor_id": "audit-service",
        "actor_permissions": [],
        "investigation_id": "",
        "alert_id": "",
        "entity_ids": [],
        "context": {},
        "decision": {},
        "outcome": {},
        "record_version": "1.0",
        "source_service": "audit-service",
    }
    record["record_hash"] = compute_record_hash(record)
    return record


def chain_event(event: dict[str, Any], chain_state: dict[str, Any]) -> dict[str, Any]:
    """Chain an incoming event: assign sequence, link hash, compute record_hash."""
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
    record = dict(event)
    record["sequence_number"] = chain_state["last_sequence"] + 1
    record["previous_hash"] = chain_state["last_hash"]
    record["ingested_at"] = now
    record["record_hash"] = compute_record_hash(record)
    return record


def verify_chain(records: list[dict[str, Any]]) -> tuple[bool, list[str]]:
    """Verify a list of records forms a valid hash chain.

    Returns ``(is_valid, errors)`` where errors is a list of descriptions.
    """
    errors: list[str] = []
    if not records:
        return True, []

    sorted_recs = sorted(records, key=lambda r: r.get("sequence_number", 0))

    for i, rec in enumerate(sorted_recs):
        expected_hash = compute_record_hash(rec)
        if rec.get("record_hash") != expected_hash:
            errors.append(
                f"Record seq={rec.get('sequence_number')}: hash mismatch "
                f"(expected {expected_hash[:16]}..., got {str(rec.get('record_hash', ''))[:16]}...)"
            )

        if i > 0:
            prev = sorted_recs[i - 1]
            if rec.get("previous_hash") != prev.get("record_hash"):
                errors.append(
                    f"Record seq={rec.get('sequence_number')}: previous_hash does not link "
                    f"to seq={prev.get('sequence_number')} record_hash"
                )

            expected_seq = prev.get("sequence_number", 0) + 1
            if rec.get("sequence_number") != expected_seq:
                errors.append(
                    f"Sequence gap: expected {expected_seq}, got {rec.get('sequence_number')}"
                )

    return len(errors) == 0, errors


class ChainStateManager:
    """Manages per-tenant hash chain state in Postgres ``audit_chain_state``.

    Maintains an in-memory cache to avoid DB lookups on every event within
    the same service lifecycle.
    """

    def __init__(self, postgres_client: Any) -> None:
        self._db = postgres_client
        self._cache: dict[str, dict[str, Any]] = {}

    async def get_state(self, tenant_id: str) -> dict[str, Any] | None:
        """Read current chain head for tenant. Returns None if no chain exists."""
        if tenant_id in self._cache:
            return self._cache[tenant_id]
        row = await self._db.fetch_one(
            "SELECT tenant_id, last_sequence, last_hash, last_timestamp "
            "FROM audit_chain_state WHERE tenant_id = $1",
            tenant_id,
        )
        if row:
            state = dict(row)
            self._cache[tenant_id] = state
            return state
        return None

    async def update_state(
        self, tenant_id: str, sequence: int, hash_val: str, timestamp: str
    ) -> None:
        """Upsert chain head for tenant."""
        self._cache[tenant_id] = {
            "tenant_id": tenant_id,
            "last_sequence": sequence,
            "last_hash": hash_val,
            "last_timestamp": timestamp,
        }
        await self._db.execute(
            "INSERT INTO audit_chain_state (tenant_id, last_sequence, last_hash, last_timestamp, updated_at) "
            "VALUES ($1, $2, $3, $4, NOW()) "
            "ON CONFLICT (tenant_id) DO UPDATE SET "
            "last_sequence = $2, last_hash = $3, last_timestamp = $4, updated_at = NOW()",
            tenant_id,
            sequence,
            hash_val,
            timestamp,
        )

    async def ensure_genesis(self, tenant_id: str) -> dict[str, Any]:
        """Create genesis record if tenant has no chain state. Returns chain state."""
        state = await self.get_state(tenant_id)
        if state is not None:
            return state

        genesis = create_genesis_record(tenant_id)

        # C-02: Persist genesis record to audit_records table so chain
        # verification can find it — not just in chain_state.
        await self._db.execute(
            "INSERT INTO audit_records (audit_id, tenant_id, sequence_number, "
            "previous_hash, record_hash, timestamp, ingested_at, event_type, "
            "event_category, severity, actor_type, actor_id, record_version, "
            "source_service) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14) "
            "ON CONFLICT (audit_id) DO NOTHING",
            genesis["audit_id"], genesis["tenant_id"],
            genesis["sequence_number"], genesis["previous_hash"],
            genesis["record_hash"], genesis["timestamp"],
            genesis["ingested_at"], genesis["event_type"],
            genesis["event_category"], genesis["severity"],
            genesis["actor_type"], genesis["actor_id"],
            genesis["record_version"], genesis["source_service"],
        )

        await self.update_state(
            tenant_id,
            genesis["sequence_number"],
            genesis["record_hash"],
            genesis["timestamp"],
        )
        return {
            "tenant_id": tenant_id,
            "last_sequence": genesis["sequence_number"],
            "last_hash": genesis["record_hash"],
            "last_timestamp": genesis["timestamp"],
        }
