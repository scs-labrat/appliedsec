"""Evidence artifact store — Story 13.5.

Stores large audit payloads (LLM prompts, responses, retrieval context) in
S3/MinIO with SHA-256 content hashing and SSE-KMS encryption.
"""

from __future__ import annotations

import hashlib
import json
import logging
from datetime import datetime, timezone
from typing import Any

logger = logging.getLogger(__name__)

VALID_EVIDENCE_TYPES = frozenset({
    "llm_prompt",
    "llm_response",
    "retrieval_context",
    "raw_alert",
    "investigation_state",
})


class EvidenceStore:
    """Stores and retrieves evidence artifacts in S3/MinIO."""

    def __init__(self, s3_client: Any, bucket: str = "aluskort-audit-evidence") -> None:
        self._s3 = s3_client
        self._bucket = bucket

    async def store_evidence(
        self,
        tenant_id: str,
        audit_id: str,
        evidence_type: str,
        content: str | bytes,
    ) -> tuple[str, str]:
        """Store evidence and return ``(content_hash, s3_uri)``.

        Returns ``("", "")`` on failure (fail-open).
        """
        if isinstance(content, str):
            content_bytes = content.encode("utf-8")
        else:
            content_bytes = content

        content_hash = hashlib.sha256(content_bytes).hexdigest()

        now = datetime.now(timezone.utc)
        key = (
            f"{tenant_id}/{now.strftime('%Y')}/{now.strftime('%m')}/"
            f"{now.strftime('%d')}/{audit_id}/{evidence_type}.json"
        )
        s3_uri = f"s3://{self._bucket}/{key}"

        try:
            self._s3.put_object(
                Bucket=self._bucket,
                Key=key,
                Body=content_bytes,
                ServerSideEncryption="aws:kms",
            )
        except Exception as exc:
            logger.warning("Evidence store failed (fire-and-forget): %s", exc)
            return ("", "")

        return (content_hash, s3_uri)

    async def retrieve_evidence(self, s3_uri: str) -> bytes:
        """Download evidence from S3 URI."""
        bucket, key = self._parse_s3_uri(s3_uri)
        resp = self._s3.get_object(Bucket=bucket, Key=key)
        return resp["Body"].read()

    async def verify_evidence(self, s3_uri: str, expected_hash: str) -> bool:
        """Retrieve content and verify SHA-256 matches expected_hash."""
        content = await self.retrieve_evidence(s3_uri)
        actual_hash = hashlib.sha256(content).hexdigest()
        return actual_hash == expected_hash

    async def store_evidence_batch(
        self,
        tenant_id: str,
        audit_id: str,
        items: list[dict[str, Any]],
    ) -> list[tuple[str, str]]:
        """Store multiple evidence items for the same audit event.

        Each item dict must have ``evidence_type`` and ``content`` keys.
        """
        results = []
        for item in items:
            result = await self.store_evidence(
                tenant_id=tenant_id,
                audit_id=audit_id,
                evidence_type=item["evidence_type"],
                content=item["content"],
            )
            results.append(result)
        return results

    @staticmethod
    def build_evidence_refs(content_hashes: list[tuple[str, str]]) -> list[str]:
        """Format S3 URIs as ``evidence_refs`` for AuditContext."""
        return [uri for _, uri in content_hashes if uri]

    @staticmethod
    def _parse_s3_uri(s3_uri: str) -> tuple[str, str]:
        """Parse ``s3://bucket/key`` into ``(bucket, key)``."""
        path = s3_uri.replace("s3://", "")
        bucket, _, key = path.partition("/")
        return bucket, key
