"""Tests for EvidenceStore — Story 13.5."""

from __future__ import annotations

import hashlib
import io
from unittest.mock import MagicMock

import pytest

from services.audit_service.evidence import EvidenceStore


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_store() -> EvidenceStore:
    s3 = MagicMock()
    s3.put_object = MagicMock()
    s3.get_object = MagicMock()
    return EvidenceStore(s3, bucket="test-bucket")


# ---------------------------------------------------------------------------
# TestEvidenceStore (AC: 1, 2)
# ---------------------------------------------------------------------------

class TestEvidenceStore:
    """AC-1,2: store, retrieve, verify evidence with SHA-256 and SSE-KMS."""

    @pytest.mark.asyncio
    async def test_store_returns_hash_and_uri(self):
        store = _make_store()
        content_hash, s3_uri = await store.store_evidence(
            "t1", "audit-1", "llm_prompt", "prompt content"
        )
        assert len(content_hash) == 64
        assert s3_uri.startswith("s3://test-bucket/t1/")
        assert "llm_prompt.json" in s3_uri

    @pytest.mark.asyncio
    async def test_path_format_correct(self):
        store = _make_store()
        _, s3_uri = await store.store_evidence(
            "tenant-abc", "aud-123", "llm_response", "response data"
        )
        # s3://bucket/tenant/YYYY/MM/DD/audit_id/type.json
        parts = s3_uri.replace("s3://test-bucket/", "").split("/")
        assert parts[0] == "tenant-abc"
        assert len(parts[1]) == 4  # YYYY
        assert len(parts[2]) == 2  # MM
        assert len(parts[3]) == 2  # DD
        assert parts[4] == "aud-123"
        assert parts[5] == "llm_response.json"

    @pytest.mark.asyncio
    async def test_sse_kms_header_set(self):
        store = _make_store()
        await store.store_evidence("t1", "a1", "raw_alert", "data")
        call_kwargs = store._s3.put_object.call_args.kwargs
        assert call_kwargs["ServerSideEncryption"] == "aws:kms"

    @pytest.mark.asyncio
    async def test_content_hash_is_sha256(self):
        store = _make_store()
        content = "test content for hashing"
        expected = hashlib.sha256(content.encode("utf-8")).hexdigest()
        actual_hash, _ = await store.store_evidence("t1", "a1", "llm_prompt", content)
        assert actual_hash == expected

    @pytest.mark.asyncio
    async def test_retrieve_returns_content(self):
        store = _make_store()
        original = b"original content bytes"
        store._s3.get_object.return_value = {"Body": io.BytesIO(original)}
        content = await store.retrieve_evidence("s3://test-bucket/t1/2026/02/21/a1/llm_prompt.json")
        assert content == original

    @pytest.mark.asyncio
    async def test_verify_matches_hash(self):
        store = _make_store()
        content = b"verify me"
        expected_hash = hashlib.sha256(content).hexdigest()
        store._s3.get_object.return_value = {"Body": io.BytesIO(content)}
        result = await store.verify_evidence("s3://test-bucket/path", expected_hash)
        assert result is True

    @pytest.mark.asyncio
    async def test_verify_fails_on_tampered(self):
        store = _make_store()
        store._s3.get_object.return_value = {"Body": io.BytesIO(b"tampered")}
        result = await store.verify_evidence("s3://test-bucket/path", "wrong-hash")
        assert result is False

    @pytest.mark.asyncio
    async def test_bytes_content_stored(self):
        store = _make_store()
        content = b"raw bytes content"
        h, uri = await store.store_evidence("t1", "a1", "raw_alert", content)
        assert h == hashlib.sha256(content).hexdigest()
        assert uri != ""


# ---------------------------------------------------------------------------
# TestEvidenceStoreFailOpen (AC: 4)
# ---------------------------------------------------------------------------

class TestEvidenceStoreFailOpen:
    """AC-4: S3 failures return empty tuple, no exception."""

    @pytest.mark.asyncio
    async def test_s3_error_returns_empty(self):
        store = _make_store()
        store._s3.put_object.side_effect = Exception("connection refused")
        h, uri = await store.store_evidence("t1", "a1", "llm_prompt", "data")
        assert h == ""
        assert uri == ""

    @pytest.mark.asyncio
    async def test_s3_error_no_exception(self):
        store = _make_store()
        store._s3.put_object.side_effect = Exception("timeout")
        # Should not raise
        await store.store_evidence("t1", "a1", "llm_prompt", "data")


# ---------------------------------------------------------------------------
# TestBatchEvidence (AC: 3)
# ---------------------------------------------------------------------------

class TestBatchEvidence:
    """Batch evidence storage and evidence_refs building."""

    @pytest.mark.asyncio
    async def test_batch_stores_all_items(self):
        store = _make_store()
        items = [
            {"evidence_type": "llm_prompt", "content": "prompt"},
            {"evidence_type": "llm_response", "content": "response"},
            {"evidence_type": "retrieval_context", "content": "ctx"},
        ]
        results = await store.store_evidence_batch("t1", "a1", items)
        assert len(results) == 3
        assert all(h != "" for h, _ in results)

    @pytest.mark.asyncio
    async def test_batch_with_failure_partial(self):
        store = _make_store()
        call_count = 0
        original_put = store._s3.put_object

        def fail_on_second(*args, **kwargs):
            nonlocal call_count
            call_count += 1
            if call_count == 2:
                raise Exception("fail")
            return original_put(*args, **kwargs)

        store._s3.put_object.side_effect = fail_on_second
        items = [
            {"evidence_type": "llm_prompt", "content": "ok"},
            {"evidence_type": "llm_response", "content": "fail"},
            {"evidence_type": "raw_alert", "content": "ok"},
        ]
        results = await store.store_evidence_batch("t1", "a1", items)
        assert len(results) == 3
        # Second item should be ("", "")
        assert results[1] == ("", "")

    def test_build_evidence_refs(self):
        hashes = [
            ("hash1", "s3://bucket/path1"),
            ("", ""),  # failed item
            ("hash3", "s3://bucket/path3"),
        ]
        refs = EvidenceStore.build_evidence_refs(hashes)
        assert refs == ["s3://bucket/path1", "s3://bucket/path3"]
