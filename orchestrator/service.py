"""Orchestrator Kafka service — consumes normalised alerts and runs investigations.

Consumes from ``alerts.normalized``, runs the full investigation graph
(IOC extraction → FP check → enrichment → reasoning → response),
and publishes results to ``investigations.completed``.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import signal
from typing import Any

from confluent_kafka import Consumer, KafkaError, KafkaException, Producer

logger = logging.getLogger(__name__)

TOPIC_NORMALIZED = "alerts.normalized"
TOPIC_COMPLETED = "investigations.completed"
TOPIC_DLQ = "alerts.normalized.dlq"
CONSUMER_GROUP = "aluskort.orchestrator"


class OrchestratorService:
    """Kafka consumer that drives the investigation graph."""

    def __init__(
        self,
        kafka_bootstrap: str,
        graph: Any,
        consumer_group: str = CONSUMER_GROUP,
    ) -> None:
        self._consumer = Consumer({
            "bootstrap.servers": kafka_bootstrap,
            "group.id": consumer_group,
            "auto.offset.reset": "earliest",
            "enable.auto.commit": False,
        })
        self._producer = Producer({
            "bootstrap.servers": kafka_bootstrap,
        })
        self._graph = graph
        self._running = False

    def start(self) -> None:
        self._consumer.subscribe([TOPIC_NORMALIZED])
        self._running = True
        logger.info("Orchestrator subscribed to %s", TOPIC_NORMALIZED)

    def stop(self) -> None:
        self._running = False

    def close(self) -> None:
        self.stop()
        self._producer.flush(timeout=5)
        self._consumer.close()

    async def process_message(self, raw_value: bytes) -> dict[str, Any]:
        """Deserialize alert and run investigation graph."""
        alert_data: dict[str, Any] = json.loads(raw_value.decode("utf-8"))

        alert_id = alert_data.get("alert_id", "")
        tenant_id = alert_data.get("tenant_id", "default")
        entities = alert_data.get("parsed_entities", alert_data.get("entities", {}))
        severity = alert_data.get("severity", "medium")
        alert_title = alert_data.get("title", alert_data.get("alert_name", ""))

        state = await self._graph.run(
            alert_id=alert_id,
            tenant_id=tenant_id,
            entities=entities,
            alert_title=alert_title,
            severity=severity,
        )

        return {
            "investigation_id": state.investigation_id,
            "alert_id": state.alert_id,
            "classification": state.classification,
            "confidence": state.confidence,
            "severity": state.severity,
            "state": state.state.value,
            "llm_calls": state.llm_calls,
            "total_cost_usd": state.total_cost_usd,
            "requires_human_approval": state.requires_human_approval,
        }

    def _send_to_dlq(self, raw_value: bytes, error: str) -> None:
        dlq_payload = json.dumps({
            "original": raw_value.decode("utf-8", errors="replace"),
            "error": error,
        }).encode("utf-8")
        self._producer.produce(topic=TOPIC_DLQ, value=dlq_payload)
        self._producer.flush(timeout=5)

    async def run(self) -> None:
        """Main consumer loop — blocks until stop() is called."""
        self.start()
        logger.info("Orchestrator service running")

        while self._running:
            msg = self._consumer.poll(timeout=1.0)
            if msg is None:
                continue
            if msg.error():
                if msg.error().code() == KafkaError._PARTITION_EOF:
                    continue
                logger.error("Consumer error: %s", msg.error())
                continue

            raw_value = msg.value()

            try:
                result = await self.process_message(raw_value)
            except Exception as exc:
                logger.error("Investigation failed: %s", exc, exc_info=True)
                self._send_to_dlq(raw_value, str(exc))
                self._consumer.commit(message=msg)
                continue

            # Publish completed investigation
            inv_id = result.get("investigation_id", "")
            try:
                self._producer.produce(
                    topic=TOPIC_COMPLETED,
                    key=inv_id.encode("utf-8") if inv_id else None,
                    value=json.dumps(result).encode("utf-8"),
                )
                self._producer.flush(timeout=5)
                self._consumer.commit(message=msg)
                logger.info(
                    "Investigation %s completed: %s (confidence=%.2f)",
                    inv_id, result.get("classification"), result.get("confidence", 0),
                )
            except KafkaException as exc:
                logger.error("Producer failed for %s: %s", inv_id, exc)


def _build_graph(kafka_bootstrap: str) -> Any:
    """Wire up the full investigation graph with all dependencies."""
    from unittest.mock import AsyncMock, MagicMock

    from orchestrator.graph import InvestigationGraph
    from orchestrator.persistence import InvestigationRepository

    from orchestrator.agents.ioc_extractor import IOCExtractorAgent
    from orchestrator.agents.context_enricher import ContextEnricherAgent
    from orchestrator.agents.ctem_correlator import CTEMCorrelatorAgent
    from orchestrator.agents.atlas_mapper import ATLASMapperAgent
    from orchestrator.agents.reasoning_agent import ReasoningAgent
    from orchestrator.agents.response_agent import ResponseAgent

    # --- Infrastructure clients ---
    postgres_dsn = os.environ.get("POSTGRES_DSN", "")
    db = None
    if postgres_dsn:
        try:
            from shared.db.postgres import PostgresClient
            db = PostgresClient(dsn=postgres_dsn)
        except Exception:
            logger.warning("Postgres unavailable", exc_info=True)

    redis_host = os.environ.get("REDIS_HOST", "localhost")
    redis_client = None
    try:
        from shared.db.redis_cache import RedisClient
        redis_client = RedisClient(host=redis_host)
    except Exception:
        logger.warning("Redis unavailable")

    qdrant_host = os.environ.get("QDRANT_HOST", "localhost")
    qdrant_client = None
    try:
        from shared.db.vector import QdrantWrapper
        qdrant_client = QdrantWrapper(host=qdrant_host)
    except Exception:
        logger.warning("Qdrant unavailable")

    # --- Context Gateway (LLM interface) ---
    api_key = os.environ.get("ANTHROPIC_API_KEY", "")
    gateway: Any = AsyncMock()
    if api_key:
        try:
            from context_gateway.anthropic_client import AluskortAnthropicClient
            from context_gateway.gateway import ContextGateway
            from context_gateway.spend_guard import SpendGuard

            client = AluskortAnthropicClient(api_key=api_key)
            gateway = ContextGateway(client=client, spend_guard=SpendGuard())
        except Exception:
            logger.warning("Context Gateway init failed — using mock", exc_info=True)

    # --- Audit ---
    audit = None
    try:
        from shared.audit.producer import AuditProducer
        audit = AuditProducer(kafka_bootstrap=kafka_bootstrap, service_name="orchestrator")
    except Exception:
        logger.warning("Audit producer unavailable")

    # --- Persistence & Agents ---
    mock = MagicMock()
    repo = InvestigationRepository(postgres_client=db or mock)
    ioc = IOCExtractorAgent(gateway=gateway, redis_client=redis_client or mock)
    enricher = ContextEnricherAgent(
        redis_client=redis_client or mock,
        postgres_client=db or mock,
        qdrant_client=qdrant_client or mock,
    )
    ctem = CTEMCorrelatorAgent(postgres_client=db or mock)
    atlas = ATLASMapperAgent(postgres_client=db or mock, qdrant_client=qdrant_client or mock)
    reasoning = ReasoningAgent(gateway=gateway)
    response = ResponseAgent(postgres_client=db or mock, audit_producer=audit)

    # --- FP short-circuit ---
    fp = None
    if redis_client:
        from orchestrator.fp_shortcircuit import FPShortCircuit
        fp = FPShortCircuit(redis_client=redis_client)

    graph = InvestigationGraph(
        repository=repo,
        ioc_extractor=ioc,
        context_enricher=enricher,
        ctem_correlator=ctem,
        atlas_mapper=atlas,
        reasoning_agent=reasoning,
        response_agent=response,
        fp_shortcircuit=fp,
        audit_producer=audit,
    )

    return graph


def main() -> None:
    """Entry point for ``python -m orchestrator.service``."""
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s — %(message)s",
    )

    kafka_bootstrap = os.environ.get("KAFKA_BOOTSTRAP_SERVERS", "localhost:9092")
    graph = _build_graph(kafka_bootstrap)
    service = OrchestratorService(kafka_bootstrap=kafka_bootstrap, graph=graph)

    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)

    # Graceful shutdown
    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(sig, service.stop)
        except NotImplementedError:
            # Windows doesn't support add_signal_handler
            signal.signal(sig, lambda *_: service.stop())

    try:
        loop.run_until_complete(service.run())
    finally:
        service.close()
        loop.close()
        logger.info("Orchestrator service stopped")


if __name__ == "__main__":
    main()
