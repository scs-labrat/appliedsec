"""Kafka/Redpanda topic provisioning for ALUSKORT.

Usage:
    python -m infra.scripts.create_kafka_topics [--bootstrap-servers localhost:9092]
"""

from __future__ import annotations

import argparse
import logging
import sys

from confluent_kafka.admin import AdminClient, NewTopic

logger = logging.getLogger(__name__)

# -- Core pipeline topics --
CORE_TOPICS: list[dict] = [
    {"name": "alerts.raw", "partitions": 4, "retention_ms": 7 * 86400_000},
    {"name": "alerts.normalized", "partitions": 4, "retention_ms": 7 * 86400_000},
    {"name": "incidents.enriched", "partitions": 4, "retention_ms": 7 * 86400_000},
    {"name": "jobs.llm.priority.critical", "partitions": 4, "retention_ms": 3 * 86400_000},
    {"name": "jobs.llm.priority.high", "partitions": 4, "retention_ms": 3 * 86400_000},
    {"name": "jobs.llm.priority.normal", "partitions": 4, "retention_ms": 7 * 86400_000},
    {"name": "jobs.llm.priority.low", "partitions": 2, "retention_ms": 14 * 86400_000},
    {"name": "actions.pending", "partitions": 2, "retention_ms": 7 * 86400_000},
    {"name": "audit.events", "partitions": 4, "retention_ms": 90 * 86400_000},
]

# -- CTEM topics --
CTEM_TOPICS: list[dict] = [
    {"name": "ctem.raw.wiz", "partitions": 4, "retention_ms": 30 * 86400_000},
    {"name": "ctem.raw.snyk", "partitions": 2, "retention_ms": 30 * 86400_000},
    {"name": "ctem.raw.garak", "partitions": 2, "retention_ms": 30 * 86400_000},
    {"name": "ctem.raw.art", "partitions": 2, "retention_ms": 30 * 86400_000},
    {"name": "ctem.raw.burp", "partitions": 2, "retention_ms": 30 * 86400_000},
    {"name": "ctem.raw.custom", "partitions": 2, "retention_ms": 30 * 86400_000},
    {"name": "ctem.raw.validation", "partitions": 2, "retention_ms": 90 * 86400_000},
    {"name": "ctem.raw.remediation", "partitions": 2, "retention_ms": 90 * 86400_000},
    {"name": "ctem.normalized", "partitions": 4, "retention_ms": 30 * 86400_000},
]

# -- DLQ topics --
DLQ_TOPICS: list[dict] = [
    {"name": "alerts.raw.dlq", "partitions": 2, "retention_ms": 30 * 86400_000},
    {"name": "jobs.llm.priority.critical.dlq", "partitions": 2, "retention_ms": 30 * 86400_000},
    {"name": "jobs.llm.priority.high.dlq", "partitions": 2, "retention_ms": 30 * 86400_000},
    {"name": "jobs.llm.priority.normal.dlq", "partitions": 2, "retention_ms": 30 * 86400_000},
    {"name": "jobs.llm.priority.low.dlq", "partitions": 2, "retention_ms": 30 * 86400_000},
    {"name": "ctem.normalized.dlq", "partitions": 2, "retention_ms": 30 * 86400_000},
]

# -- Knowledge update topics --
KNOWLEDGE_TOPICS: list[dict] = [
    {"name": "knowledge.mitre.updated", "partitions": 1, "retention_ms": 7 * 86400_000},
    {"name": "knowledge.ti.ioc.new", "partitions": 2, "retention_ms": 7 * 86400_000},
    {"name": "knowledge.ti.report.new", "partitions": 2, "retention_ms": 7 * 86400_000},
    {"name": "knowledge.playbook.updated", "partitions": 1, "retention_ms": 7 * 86400_000},
    {"name": "knowledge.incident.stored", "partitions": 2, "retention_ms": 7 * 86400_000},
    {"name": "knowledge.fp.approved", "partitions": 1, "retention_ms": 7 * 86400_000},
]

ALL_TOPICS = CORE_TOPICS + CTEM_TOPICS + DLQ_TOPICS + KNOWLEDGE_TOPICS


def get_all_topic_definitions() -> list[dict]:
    """Return all topic definitions for programmatic access."""
    return list(ALL_TOPICS)


def create_topics(bootstrap_servers: str = "localhost:9092") -> dict[str, str]:
    """Create all Kafka topics. Returns {topic_name: status}."""
    admin = AdminClient({"bootstrap.servers": bootstrap_servers})

    # Check existing topics
    existing = set(admin.list_topics(timeout=10).topics.keys())
    results: dict[str, str] = {}

    new_topics = []
    for t in ALL_TOPICS:
        if t["name"] in existing:
            results[t["name"]] = "already_exists"
            continue
        new_topics.append(
            NewTopic(
                topic=t["name"],
                num_partitions=t["partitions"],
                replication_factor=1,
                config={"retention.ms": str(t["retention_ms"])},
            )
        )

    if not new_topics:
        logger.info("All %d topics already exist", len(ALL_TOPICS))
        return results

    futures = admin.create_topics(new_topics)
    for topic_name, future in futures.items():
        try:
            future.result()
            results[topic_name] = "created"
            logger.info("Created topic: %s", topic_name)
        except Exception as exc:
            results[topic_name] = f"error: {exc}"
            logger.error("Failed to create topic %s: %s", topic_name, exc)

    return results


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    parser = argparse.ArgumentParser(description="Create ALUSKORT Kafka topics")
    parser.add_argument(
        "--bootstrap-servers", default="localhost:9092", help="Kafka bootstrap servers"
    )
    args = parser.parse_args()

    results = create_topics(args.bootstrap_servers)
    created = sum(1 for v in results.values() if v == "created")
    existing = sum(1 for v in results.values() if v == "already_exists")
    errors = sum(1 for v in results.values() if v.startswith("error"))

    print(f"\nTopics: {created} created, {existing} already existed, {errors} errors")
    print(f"Total defined: {len(ALL_TOPICS)}")

    if errors:
        sys.exit(1)


if __name__ == "__main__":
    main()
