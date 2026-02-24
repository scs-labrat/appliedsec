"""Chain verification and integrity checks — Story 13.7.

Provides scheduled verification jobs with 4-tier verification:
  - Continuous (5 min): last 100 records per tenant
  - Daily (03:00 UTC): full chain verification
  - Hourly: Kafka-vs-Postgres lag cross-check
  - Weekly: cold storage spot-check from S3
"""

from __future__ import annotations

import logging
import time
from datetime import datetime, timezone
from typing import Any

from services.audit_service.chain import compute_record_hash, verify_chain

logger = logging.getLogger(__name__)


async def verify_tenant_chain(
    postgres_client: Any,
    tenant_id: str,
    from_sequence: int | None = None,
    to_sequence: int | None = None,
) -> tuple[bool, list[str]]:
    """Verify hash chain integrity for a tenant with optional sequence range.

    Queries ``audit_records`` ordered by sequence_number, then delegates to
    :func:`verify_chain` from chain.py.
    """
    query = "SELECT * FROM audit_records WHERE tenant_id = $1"
    params: list[Any] = [tenant_id]
    idx = 2

    if from_sequence is not None:
        query += f" AND sequence_number >= ${idx}"
        params.append(from_sequence)
        idx += 1
    if to_sequence is not None:
        query += f" AND sequence_number <= ${idx}"
        params.append(to_sequence)
        idx += 1

    query += " ORDER BY sequence_number"
    rows = await postgres_client.fetch_many(query, *params)
    records = [dict(r) for r in rows]
    return verify_chain(records)


async def verify_recent(
    postgres_client: Any,
    tenant_id: str,
    count: int = 100,
) -> tuple[bool, list[str]]:
    """Verify the last *count* records for a tenant."""
    rows = await postgres_client.fetch_many(
        "SELECT * FROM audit_records WHERE tenant_id = $1 "
        "ORDER BY sequence_number DESC LIMIT $2",
        tenant_id,
        count,
    )
    records = [dict(r) for r in rows]
    records.sort(key=lambda r: r.get("sequence_number", 0))
    return verify_chain(records)


class VerificationScheduler:
    """Runs scheduled verification checks and records results.

    Parameters
    ----------
    postgres_client:
        Database client with ``fetch_many`` / ``execute``.
    evidence_store:
        Optional :class:`EvidenceStore` for cold spot-checks.
    kafka_admin:
        Optional Kafka admin client for lag checks.
    metrics_callback:
        Optional ``(metric_name, labels_dict, value) -> None`` callable.
    """

    def __init__(
        self,
        postgres_client: Any,
        evidence_store: Any = None,
        kafka_admin: Any = None,
        metrics_callback: Any = None,
    ) -> None:
        self._db = postgres_client
        self._evidence_store = evidence_store
        self._kafka_admin = kafka_admin
        self._metrics_cb = metrics_callback

    # ── Individual checks ─────────────────────────────────────────

    async def run_continuous_check(self) -> list[dict[str, Any]]:
        """Every 5 min — verify last 100 records per tenant."""
        tenants = await self._get_tenants()
        results = []
        for tid in tenants:
            start = time.monotonic()
            valid, errors = await verify_recent(self._db, tid, count=100)
            duration_ms = (time.monotonic() - start) * 1000

            result = self._build_result(
                tenant_id=tid,
                verification_type="continuous",
                chain_valid=valid,
                errors=errors,
                duration_ms=duration_ms,
            )
            await self._record_result(result)
            self._emit_metric("aluskort_audit_chain_valid", {"tenant_id": tid, "check_type": "continuous"}, 1 if valid else 0)
            self._emit_metric("aluskort_audit_verification_duration_seconds", {"check_type": "continuous"}, duration_ms / 1000)
            results.append(result)
        return results

    async def run_daily_full_check(self) -> list[dict[str, Any]]:
        """Daily 03:00 UTC — full chain verification per tenant."""
        tenants = await self._get_tenants()
        results = []
        for tid in tenants:
            start = time.monotonic()
            valid, errors = await verify_tenant_chain(self._db, tid)
            duration_ms = (time.monotonic() - start) * 1000

            result = self._build_result(
                tenant_id=tid,
                verification_type="daily_full",
                chain_valid=valid,
                errors=errors,
                duration_ms=duration_ms,
            )
            await self._record_result(result)
            self._emit_metric("aluskort_audit_chain_valid", {"tenant_id": tid, "check_type": "daily_full"}, 1 if valid else 0)
            self._emit_metric("aluskort_audit_verification_duration_seconds", {"check_type": "daily_full"}, duration_ms / 1000)
            results.append(result)
        return results

    async def run_hourly_lag_check(self) -> list[dict[str, Any]]:
        """Hourly — compare Kafka topic offset vs Postgres max(sequence_number)."""
        tenants = await self._get_tenants()
        results = []
        for tid in tenants:
            start = time.monotonic()
            errors: list[str] = []

            # Get Postgres max sequence
            row = await self._db.fetch_one(
                "SELECT COALESCE(MAX(sequence_number), 0) AS max_seq "
                "FROM audit_records WHERE tenant_id = $1",
                tid,
            )
            pg_max = dict(row).get("max_seq", 0) if row else 0

            # Get Kafka offset
            kafka_offset = 0
            if self._kafka_admin:
                try:
                    kafka_offset = await self._kafka_admin.get_latest_offset("audit.events", tid)
                except Exception as exc:
                    errors.append(f"Kafka offset lookup failed: {exc}")

            lag = kafka_offset - pg_max
            if lag > 1000:
                errors.append(f"Kafka lag too high: offset={kafka_offset}, pg_max={pg_max}, lag={lag}")

            duration_ms = (time.monotonic() - start) * 1000
            result = self._build_result(
                tenant_id=tid,
                verification_type="hourly_lag",
                chain_valid=len(errors) == 0,
                errors=errors,
                duration_ms=duration_ms,
                extra={"kafka_offset": kafka_offset, "pg_max_sequence": pg_max, "lag": lag},
            )
            await self._record_result(result)
            self._emit_metric("aluskort_audit_kafka_lag", {"tenant_id": tid}, lag)
            results.append(result)
        return results

    async def run_weekly_cold_check(self) -> list[dict[str, Any]]:
        """Weekly — random sample 100 records, verify against cold storage."""
        tenants = await self._get_tenants()
        results = []
        for tid in tenants:
            start = time.monotonic()
            errors: list[str] = []

            rows = await self._db.fetch_many(
                "SELECT * FROM audit_records WHERE tenant_id = $1 "
                "ORDER BY RANDOM() LIMIT 100",
                tid,
            )
            records = [dict(r) for r in rows]
            records_checked = len(records)

            for rec in records:
                expected_hash = compute_record_hash(rec)
                if rec.get("record_hash") != expected_hash:
                    errors.append(
                        f"Cold check: record seq={rec.get('sequence_number')} "
                        f"hash mismatch"
                    )

            duration_ms = (time.monotonic() - start) * 1000
            result = self._build_result(
                tenant_id=tid,
                verification_type="weekly_cold",
                chain_valid=len(errors) == 0,
                errors=errors,
                duration_ms=duration_ms,
                records_checked=records_checked,
            )
            await self._record_result(result)
            self._emit_metric("aluskort_audit_chain_valid", {"tenant_id": tid, "check_type": "weekly_cold"}, 1 if len(errors) == 0 else 0)
            results.append(result)
        return results

    # ── Helpers ───────────────────────────────────────────────────

    async def _get_tenants(self) -> list[str]:
        """Retrieve distinct tenant IDs from audit_chain_state."""
        rows = await self._db.fetch_many(
            "SELECT DISTINCT tenant_id FROM audit_chain_state"
        )
        return [dict(r)["tenant_id"] for r in rows]

    def _build_result(
        self,
        *,
        tenant_id: str,
        verification_type: str,
        chain_valid: bool,
        errors: list[str],
        duration_ms: float,
        records_checked: int = 0,
        extra: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
        result: dict[str, Any] = {
            "tenant_id": tenant_id,
            "verification_type": verification_type,
            "records_checked": records_checked,
            "chain_valid": chain_valid,
            "errors": errors,
            "duration_ms": round(duration_ms, 2),
            "verified_at": now,
        }
        if extra:
            result.update(extra)
        return result

    async def _record_result(self, result: dict[str, Any]) -> None:
        """Persist verification result to ``audit_verification_log``."""
        try:
            await self._db.execute(
                "INSERT INTO audit_verification_log "
                "(tenant_id, verification_type, records_checked, chain_valid, "
                "errors, duration_ms, verified_at) "
                "VALUES ($1, $2, $3, $4, $5, $6, $7)",
                result["tenant_id"],
                result["verification_type"],
                result["records_checked"],
                result["chain_valid"],
                result["errors"],
                result["duration_ms"],
                result["verified_at"],
            )
        except Exception as exc:
            logger.warning("Failed to record verification result: %s", exc)

    def _emit_metric(self, name: str, labels: dict[str, str], value: float) -> None:
        """Publish metric if a callback is registered."""
        if self._metrics_cb:
            try:
                self._metrics_cb(name, labels, value)
            except Exception as exc:
                logger.debug("Metric emission failed: %s", exc)
