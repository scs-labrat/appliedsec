"""Tests for Kafka topic definitions — Story 2.3."""

from __future__ import annotations

from infra.scripts.create_kafka_topics import (
    ALL_TOPICS,
    CTEM_TOPICS,
    CORE_TOPICS,
    DLQ_TOPICS,
    KNOWLEDGE_TOPICS,
    get_all_topic_definitions,
)


class TestTopicDefinitions:
    def test_total_topic_count(self):
        assert len(ALL_TOPICS) == len(CORE_TOPICS) + len(CTEM_TOPICS) + len(DLQ_TOPICS) + len(KNOWLEDGE_TOPICS)

    def test_no_duplicate_names(self):
        names = [t["name"] for t in ALL_TOPICS]
        assert len(names) == len(set(names))

    def test_all_topics_have_required_keys(self):
        for t in ALL_TOPICS:
            assert "name" in t
            assert "partitions" in t
            assert "retention_ms" in t
            assert t["partitions"] > 0
            assert t["retention_ms"] > 0


class TestCoreTopics:
    def test_alerts_raw_exists(self):
        names = {t["name"] for t in CORE_TOPICS}
        assert "alerts.raw" in names
        assert "alerts.normalized" in names
        assert "incidents.enriched" in names

    def test_priority_queues_exist(self):
        names = {t["name"] for t in CORE_TOPICS}
        assert "jobs.llm.priority.critical" in names
        assert "jobs.llm.priority.high" in names
        assert "jobs.llm.priority.normal" in names
        assert "jobs.llm.priority.low" in names

    def test_audit_events_90_day_retention(self):
        audit = next(t for t in CORE_TOPICS if t["name"] == "audit.events")
        assert audit["retention_ms"] == 90 * 86400_000

    def test_critical_queue_has_4_partitions(self):
        crit = next(t for t in CORE_TOPICS if t["name"] == "jobs.llm.priority.critical")
        assert crit["partitions"] == 4

    def test_low_queue_has_2_partitions(self):
        low = next(t for t in CORE_TOPICS if t["name"] == "jobs.llm.priority.low")
        assert low["partitions"] == 2


class TestCtemTopics:
    def test_all_ctem_raw_sources(self):
        names = {t["name"] for t in CTEM_TOPICS}
        expected_sources = {"wiz", "snyk", "garak", "art", "burp", "custom", "validation", "remediation"}
        for src in expected_sources:
            assert f"ctem.raw.{src}" in names

    def test_ctem_normalized_exists(self):
        names = {t["name"] for t in CTEM_TOPICS}
        assert "ctem.normalized" in names

    def test_ctem_30_day_retention(self):
        wiz = next(t for t in CTEM_TOPICS if t["name"] == "ctem.raw.wiz")
        assert wiz["retention_ms"] == 30 * 86400_000


class TestDlqTopics:
    def test_dlq_for_alerts_raw(self):
        names = {t["name"] for t in DLQ_TOPICS}
        assert "alerts.raw.dlq" in names

    def test_dlq_for_all_priority_queues(self):
        names = {t["name"] for t in DLQ_TOPICS}
        assert "jobs.llm.priority.critical.dlq" in names
        assert "jobs.llm.priority.high.dlq" in names
        assert "jobs.llm.priority.normal.dlq" in names
        assert "jobs.llm.priority.low.dlq" in names

    def test_dlq_for_ctem_normalized(self):
        names = {t["name"] for t in DLQ_TOPICS}
        assert "ctem.normalized.dlq" in names


class TestKnowledgeTopics:
    def test_knowledge_topics_exist(self):
        names = {t["name"] for t in KNOWLEDGE_TOPICS}
        assert "knowledge.mitre.updated" in names
        assert "knowledge.ti.ioc.new" in names
        assert "knowledge.ti.report.new" in names
        assert "knowledge.playbook.updated" in names
        assert "knowledge.incident.stored" in names
        assert "knowledge.fp.approved" in names


class TestGetAllTopicDefinitions:
    def test_returns_all(self):
        defs = get_all_topic_definitions()
        assert len(defs) == len(ALL_TOPICS)
