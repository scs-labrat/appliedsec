"""Qdrant collection initialisation for ALUSKORT.

Usage:
    python -m infra.scripts.init_qdrant [--host localhost] [--port 6333]
"""

from __future__ import annotations

import argparse
import logging

from qdrant_client import QdrantClient, models

logger = logging.getLogger(__name__)

# All ALUSKORT collections use same vector config
VECTOR_SIZE = 1024
HNSW_M = 16
HNSW_EF_CONSTRUCT = 200

COLLECTIONS = [
    {
        "name": "aluskort-mitre",
        "description": "MITRE ATT&CK / ATLAS technique semantic search",
    },
    {
        "name": "aluskort-threat-intel",
        "description": "Threat intelligence report chunks",
    },
    {
        "name": "aluskort-playbooks",
        "description": "Playbook semantic search",
    },
    {
        "name": "aluskort-incident-memory",
        "description": "Past incident investigation vectors",
    },
]


def get_collection_names() -> list[str]:
    """Return all collection names for programmatic access."""
    return [c["name"] for c in COLLECTIONS]


def init_collections(host: str = "localhost", port: int = 6333) -> dict[str, str]:
    """Create all Qdrant collections (idempotent). Returns {name: status}."""
    client = QdrantClient(host=host, port=port)
    existing = {c.name for c in client.get_collections().collections}
    results: dict[str, str] = {}

    for coll in COLLECTIONS:
        name = coll["name"]
        if name in existing:
            results[name] = "already_exists"
            logger.info("Collection '%s' already exists", name)
            continue

        client.create_collection(
            collection_name=name,
            vectors_config=models.VectorParams(
                size=VECTOR_SIZE,
                distance=models.Distance.COSINE,
            ),
            hnsw_config=models.HnswConfigDiff(
                m=HNSW_M,
                ef_construct=HNSW_EF_CONSTRUCT,
            ),
        )
        results[name] = "created"
        logger.info("Created collection '%s' (dim=%d, HNSW m=%d ef=%d)",
                     name, VECTOR_SIZE, HNSW_M, HNSW_EF_CONSTRUCT)

    client.close()
    return results


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    parser = argparse.ArgumentParser(description="Initialise ALUSKORT Qdrant collections")
    parser.add_argument("--host", default="localhost", help="Qdrant host")
    parser.add_argument("--port", type=int, default=6333, help="Qdrant port")
    args = parser.parse_args()

    results = init_collections(args.host, args.port)
    created = sum(1 for v in results.values() if v == "created")
    existing = sum(1 for v in results.values() if v == "already_exists")
    print(f"\nCollections: {created} created, {existing} already existed")


if __name__ == "__main__":
    main()
