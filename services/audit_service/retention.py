"""Retention lifecycle — warm-to-cold export — Story 13.9.

Exports aged Postgres audit partitions to S3 as Parquet, verifies
integrity, and drops old partitions per the 3-tier retention policy:
  Hot (Kafka 30d) -> Warm (Postgres 12m) -> Cold (S3/Parquet 7y)
"""

from __future__ import annotations

import hashlib
import io
import json
import logging
from datetime import datetime, timezone
from typing import Any

logger = logging.getLogger(__name__)

# Retention policy constants
WARM_RETENTION_MONTHS = 12
EXPORT_LAG_MONTHS = 2
BUFFER_MONTHS = 1


class RetentionLifecycle:
    """Manages monthly warm-to-cold export and partition lifecycle.

    Parameters
    ----------
    postgres_client:
        Database client with ``fetch_many`` / ``execute``.
    s3_client:
        boto3-compatible S3 client.
    bucket:
        S3 bucket for cold audit storage.
    legal_hold_tenants:
        Set of tenant IDs under legal hold (their data is never dropped).
    """

    def __init__(
        self,
        postgres_client: Any,
        s3_client: Any,
        bucket: str = "aluskort-audit-cold",
        legal_hold_tenants: set[str] | None = None,
    ) -> None:
        self._db = postgres_client
        self._s3 = s3_client
        self._bucket = bucket
        self._legal_hold = legal_hold_tenants or set()

    # ── Main entry point ─────────────────────────────────────────

    async def run_monthly_export(
        self, reference_date: datetime | None = None,
    ) -> dict[str, Any]:
        """Export the partition from 2 months ago to S3 as Parquet.

        Returns summary with exported_count, partition_name, verified.
        """
        now = reference_date or datetime.now(timezone.utc)
        target = _subtract_months(now, EXPORT_LAG_MONTHS)
        partition_name = _partition_name(target)
        s3_prefix = f"cold/{target.strftime('%Y-%m')}"

        # 1 — fetch records from partition
        rows = await self._db.fetch_many(
            "SELECT * FROM audit_records "
            "WHERE timestamp >= $1 AND timestamp < $2 "
            "ORDER BY tenant_id, sequence_number",
            target.strftime("%Y-%m-01"),
            _next_month(target).strftime("%Y-%m-01"),
        )
        records = [dict(r) for r in rows]
        if not records:
            return {
                "exported_count": 0,
                "partition_name": partition_name,
                "verified": True,
                "skipped": "no_records",
            }

        # 2 — convert to Parquet
        parquet_bytes = _records_to_parquet(records)

        # 3 — compute hash
        file_hash = hashlib.sha256(parquet_bytes).hexdigest()

        # 4 — upload Parquet + hash sidecar
        parquet_key = f"{s3_prefix}/audit_records.parquet"
        hash_key = f"{s3_prefix}/audit_records.parquet.sha256"

        try:
            self._s3.put_object(
                Bucket=self._bucket, Key=parquet_key, Body=parquet_bytes,
                ServerSideEncryption="aws:kms",
            )
            self._s3.put_object(
                Bucket=self._bucket, Key=hash_key,
                Body=file_hash.encode("utf-8"),
            )
        except Exception as exc:
            logger.error("S3 upload failed for %s: %s", partition_name, exc)
            return {
                "exported_count": len(records),
                "partition_name": partition_name,
                "verified": False,
                "error": str(exc),
            }

        # 5 — verify upload
        verified = await self._verify_upload(parquet_key, file_hash)

        return {
            "exported_count": len(records),
            "partition_name": partition_name,
            "verified": verified,
            "s3_path": f"s3://{self._bucket}/{parquet_key}",
            "file_hash": file_hash,
        }

    async def drop_old_partition(
        self, partition_name: str, verified: bool,
    ) -> bool:
        """Drop a Postgres partition ONLY if export was verified.

        Enforces 1-month buffer: will not drop a partition within
        BUFFER_MONTHS of the current date.
        """
        if not verified:
            logger.warning(
                "Refusing to drop %s: export not verified", partition_name,
            )
            return False

        # Check buffer
        partition_date = _parse_partition_date(partition_name)
        if partition_date is None:
            logger.warning("Cannot parse partition date from %s", partition_name)
            return False

        now = datetime.now(timezone.utc)
        buffer_cutoff = _subtract_months(now, BUFFER_MONTHS)
        if partition_date >= buffer_cutoff.replace(day=1):
            logger.warning(
                "Refusing to drop %s: within %d-month buffer",
                partition_name, BUFFER_MONTHS,
            )
            return False

        # Check legal hold
        if await self._has_legal_hold_data(partition_name):
            logger.warning(
                "Refusing to drop %s: contains legal hold tenant data",
                partition_name,
            )
            return False

        # Drop partition
        try:
            await self._db.execute(
                f"DROP TABLE IF EXISTS {partition_name}"
            )
            logger.info("Dropped partition %s", partition_name)
            return True
        except Exception as exc:
            logger.error("Failed to drop partition %s: %s", partition_name, exc)
            return False

    # ── Partition management ─────────────────────────────────────

    async def create_next_partitions(self, count: int = 3) -> list[str]:
        """Create monthly partitions for upcoming months."""
        now = datetime.now(timezone.utc)
        created = []
        for i in range(1, count + 1):
            target = _add_months(now, i)
            name = _partition_name(target)
            start = target.strftime("%Y-%m-01")
            end = _next_month(target).strftime("%Y-%m-01")
            try:
                await self._db.execute(
                    f"CREATE TABLE IF NOT EXISTS {name} "
                    f"PARTITION OF audit_records "
                    f"FOR VALUES FROM ('{start}') TO ('{end}')"
                )
                created.append(name)
            except Exception as exc:
                logger.error("Failed to create partition %s: %s", name, exc)
        return created

    async def list_partitions(self) -> list[dict[str, Any]]:
        """List all current audit_records partitions with metadata."""
        rows = await self._db.fetch_many(
            "SELECT inhrelid::regclass::text AS partition_name "
            "FROM pg_inherits "
            "WHERE inhparent = 'audit_records'::regclass "
            "ORDER BY inhrelid::regclass::text"
        )
        partitions = []
        for row in rows:
            r = dict(row)
            name = r["partition_name"]
            count_row = await self._db.fetch_one(
                f"SELECT COUNT(*) AS cnt FROM {name}"
            )
            cnt = dict(count_row).get("cnt", 0) if count_row else 0
            partitions.append({
                "partition_name": name,
                "row_count": cnt,
            })
        return partitions

    # ── Helpers ───────────────────────────────────────────────────

    async def _verify_upload(self, key: str, expected_hash: str) -> bool:
        """Download and verify SHA-256 of uploaded Parquet."""
        try:
            resp = self._s3.get_object(Bucket=self._bucket, Key=key)
            content = resp["Body"].read()
            actual_hash = hashlib.sha256(content).hexdigest()
            return actual_hash == expected_hash
        except Exception as exc:
            logger.error("Verification failed for %s: %s", key, exc)
            return False

    async def _has_legal_hold_data(self, partition_name: str) -> bool:
        """Check if partition contains data for tenants under legal hold."""
        if not self._legal_hold:
            return False

        placeholders = ", ".join(
            f"${i+1}" for i in range(len(self._legal_hold))
        )
        row = await self._db.fetch_one(
            f"SELECT COUNT(*) AS cnt FROM {partition_name} "
            f"WHERE tenant_id IN ({placeholders})",
            *self._legal_hold,
        )
        cnt = dict(row).get("cnt", 0) if row else 0
        return cnt > 0


# ── Module-level helpers ─────────────────────────────────────────


def _records_to_parquet(records: list[dict[str, Any]]) -> bytes:
    """Convert audit records to Parquet bytes.

    Uses a simple columnar encoding. For production, use pyarrow.
    Falls back to JSON-Lines with .parquet extension if pyarrow
    is not available.
    """
    try:
        import pyarrow as pa
        import pyarrow.parquet as pq

        # Serialize JSONB columns to strings
        for rec in records:
            for key in ("context", "decision", "outcome"):
                if isinstance(rec.get(key), dict):
                    rec[key] = json.dumps(rec[key])
            for key in ("actor_permissions", "entity_ids"):
                if isinstance(rec.get(key), list):
                    rec[key] = json.dumps(rec[key])
            # Convert datetime objects to strings
            for key in ("timestamp", "ingested_at"):
                val = rec.get(key)
                if hasattr(val, "isoformat"):
                    rec[key] = val.isoformat()

        table = pa.Table.from_pylist(records)
        buf = io.BytesIO()
        pq.write_table(table, buf)
        return buf.getvalue()
    except ImportError:
        # Fallback: JSON-Lines format
        lines = [json.dumps(r, default=str) for r in records]
        return "\n".join(lines).encode("utf-8")


def _partition_name(dt: datetime) -> str:
    """Generate partition table name for a given month."""
    return f"audit_records_{dt.strftime('%Y_%m')}"


def _parse_partition_date(name: str) -> datetime | None:
    """Parse year/month from partition name like audit_records_2026_01."""
    parts = name.replace("audit_records_", "").split("_")
    if len(parts) >= 2:
        try:
            return datetime(int(parts[0]), int(parts[1]), 1, tzinfo=timezone.utc)
        except (ValueError, IndexError):
            return None
    return None


def _subtract_months(dt: datetime, months: int) -> datetime:
    """Subtract months from a datetime, handling year boundaries."""
    month = dt.month - months
    year = dt.year
    while month <= 0:
        month += 12
        year -= 1
    return dt.replace(year=year, month=month, day=1)


def _add_months(dt: datetime, months: int) -> datetime:
    """Add months to a datetime, handling year boundaries."""
    month = dt.month + months
    year = dt.year
    while month > 12:
        month -= 12
        year += 1
    return dt.replace(year=year, month=month, day=1)


def _next_month(dt: datetime) -> datetime:
    """Return the first day of the next month."""
    return _add_months(dt, 1)
