"""Tests for AuditProducer integration in CTEM Normaliser — Story 13.8, Task 6.1."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock

import pytest

from ctem_normaliser.service import CTEMNormaliserService


class TestCTEMNormaliserAudit:
    """ctem.exposure_scored emitted after normalisation."""

    @pytest.mark.asyncio
    async def test_exposure_scored_emitted_on_process(self):
        """After successful normalisation, ctem.exposure_scored is emitted."""
        audit = MagicMock()
        repo = AsyncMock()
        repo.upsert = AsyncMock()
        producer = AsyncMock()
        producer.produce = AsyncMock()

        svc = CTEMNormaliserService(
            repository=repo,
            kafka_producer=producer,
            audit_producer=audit,
        )

        # Mock a normaliser
        mock_normaliser = MagicMock()
        mock_exposure = MagicMock()
        mock_exposure.exposure_key = "CVE-2024-1234"
        mock_exposure.severity = "high"
        mock_exposure.tenant_id = "t1"
        mock_normaliser.normalise.return_value = mock_exposure
        svc._normalisers["ctem.raw.wiz"] = mock_normaliser

        await svc.process_message("ctem.raw.wiz", {"test": True})

        scored_calls = [c for c in audit.emit.call_args_list
                        if c[1].get("event_type") == "ctem.exposure_scored"]
        assert len(scored_calls) == 1

    @pytest.mark.asyncio
    async def test_no_exception_when_audit_producer_is_none(self):
        """Backward compat: works without audit_producer."""
        repo = AsyncMock()
        repo.upsert = AsyncMock()
        producer = AsyncMock()
        producer.produce = AsyncMock()

        svc = CTEMNormaliserService(repository=repo, kafka_producer=producer)

        mock_normaliser = MagicMock()
        mock_exposure = MagicMock()
        mock_exposure.exposure_key = "CVE-2024-5678"
        mock_normaliser.normalise.return_value = mock_exposure
        svc._normalisers["ctem.raw.snyk"] = mock_normaliser

        result = await svc.process_message("ctem.raw.snyk", {"test": True})
        assert result is not None

    @pytest.mark.asyncio
    async def test_audit_failure_does_not_block(self):
        """Fire-and-forget: audit failure doesn't block normalisation."""
        audit = MagicMock()
        audit.emit.side_effect = Exception("Kafka down")
        repo = AsyncMock()
        repo.upsert = AsyncMock()
        producer = AsyncMock()
        producer.produce = AsyncMock()

        svc = CTEMNormaliserService(
            repository=repo, kafka_producer=producer, audit_producer=audit,
        )

        mock_normaliser = MagicMock()
        mock_exposure = MagicMock()
        mock_exposure.exposure_key = "CVE-2024-9999"
        mock_normaliser.normalise.return_value = mock_exposure
        svc._normalisers["ctem.raw.wiz"] = mock_normaliser

        result = await svc.process_message("ctem.raw.wiz", {"test": True})
        assert result is not None
