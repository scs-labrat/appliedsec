"""Neo4j schema initialisation for ALUSKORT.

Creates uniqueness constraints and indexes for the asset/zone graph.

Usage:
    python -m infra.scripts.init_neo4j [--uri bolt://localhost:7687] [--user neo4j] [--password localdev]
"""

from __future__ import annotations

import argparse
import logging

from neo4j import GraphDatabase

logger = logging.getLogger(__name__)

# Uniqueness constraints for node types
CONSTRAINTS = [
    "CREATE CONSTRAINT asset_id_unique IF NOT EXISTS FOR (a:Asset) REQUIRE a.id IS UNIQUE",
    "CREATE CONSTRAINT zone_id_unique IF NOT EXISTS FOR (z:Zone) REQUIRE z.id IS UNIQUE",
    "CREATE CONSTRAINT model_id_unique IF NOT EXISTS FOR (m:Model) REQUIRE m.id IS UNIQUE",
    "CREATE CONSTRAINT finding_id_unique IF NOT EXISTS FOR (f:Finding) REQUIRE f.id IS UNIQUE",
    "CREATE CONSTRAINT tenant_id_unique IF NOT EXISTS FOR (t:Tenant) REQUIRE t.id IS UNIQUE",
]

# Indexes for common lookups
INDEXES = [
    "CREATE INDEX asset_name_idx IF NOT EXISTS FOR (a:Asset) ON (a.name)",
    "CREATE INDEX zone_consequence_idx IF NOT EXISTS FOR (z:Zone) ON (z.consequence_class)",
    "CREATE INDEX finding_severity_idx IF NOT EXISTS FOR (f:Finding) ON (f.severity)",
    "CREATE INDEX asset_tenant_idx IF NOT EXISTS FOR (a:Asset) ON (a.tenant_id)",
]

# Sample test data for smoke test
SAMPLE_DATA = [
    # Tenant
    "MERGE (t:Tenant {id: 'tenant-test', name: 'Test Tenant'})",
    # Zones
    "MERGE (z1:Zone {id: 'zone-safety', name: 'Safety Zone', consequence_class: 'safety_life'})",
    "MERGE (z2:Zone {id: 'zone-prod', name: 'Production Zone', consequence_class: 'equipment'})",
    "MERGE (z3:Zone {id: 'zone-office', name: 'Office Zone', consequence_class: 'downtime'})",
    # Connect zones
    "MATCH (z1:Zone {id: 'zone-safety'}), (z2:Zone {id: 'zone-prod'}) MERGE (z1)-[:CONNECTS_TO]->(z2)",
    # Assets
    "MERGE (a1:Asset {id: 'asset-scada-01', name: 'SCADA Controller 01', tenant_id: 'tenant-test'})",
    "MERGE (a2:Asset {id: 'asset-hmi-01', name: 'HMI Workstation 01', tenant_id: 'tenant-test'})",
    # Asset-Zone relationships
    "MATCH (a:Asset {id: 'asset-scada-01'}), (z:Zone {id: 'zone-safety'}) MERGE (a)-[:RESIDES_IN]->(z)",
    "MATCH (a:Asset {id: 'asset-hmi-01'}), (z:Zone {id: 'zone-prod'}) MERGE (a)-[:RESIDES_IN]->(z)",
    # Asset-Tenant relationships
    "MATCH (a:Asset {id: 'asset-scada-01'}), (t:Tenant {id: 'tenant-test'}) MERGE (a)-[:OWNED_BY]->(t)",
    "MATCH (a:Asset {id: 'asset-hmi-01'}), (t:Tenant {id: 'tenant-test'}) MERGE (a)-[:OWNED_BY]->(t)",
    # Model deployed to assets
    "MERGE (m:Model {id: 'model-anomaly-01', name: 'Anomaly Detection v1', version: '1.0'})",
    "MATCH (m:Model {id: 'model-anomaly-01'}), (a:Asset {id: 'asset-scada-01'}) MERGE (m)-[:DEPLOYS_TO]->(a)",
    "MATCH (m:Model {id: 'model-anomaly-01'}), (a:Asset {id: 'asset-hmi-01'}) MERGE (m)-[:DEPLOYS_TO]->(a)",
    # Finding
    "MERGE (f:Finding {id: 'finding-test-001', severity: 'high', description: 'Test finding'})",
    "MATCH (f:Finding {id: 'finding-test-001'}), (a:Asset {id: 'asset-scada-01'}) MERGE (f)-[:AFFECTS]->(a)",
]


def init_schema(
    uri: str = "bolt://localhost:7687",
    user: str = "neo4j",
    password: str = "localdev",
    load_sample_data: bool = False,
) -> dict[str, int]:
    """Create constraints and indexes. Returns counts."""
    driver = GraphDatabase.driver(uri, auth=(user, password))
    results = {"constraints": 0, "indexes": 0, "sample_records": 0}

    with driver.session() as session:
        for cypher in CONSTRAINTS:
            session.run(cypher)
            results["constraints"] += 1
            logger.info("Applied: %s", cypher[:60])

        for cypher in INDEXES:
            session.run(cypher)
            results["indexes"] += 1
            logger.info("Applied: %s", cypher[:60])

        if load_sample_data:
            for cypher in SAMPLE_DATA:
                session.run(cypher)
                results["sample_records"] += 1
            logger.info("Loaded %d sample data statements", results["sample_records"])

    driver.close()
    return results


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    parser = argparse.ArgumentParser(description="Initialise ALUSKORT Neo4j schema")
    parser.add_argument("--uri", default="bolt://localhost:7687", help="Neo4j URI")
    parser.add_argument("--user", default="neo4j", help="Neo4j user")
    parser.add_argument("--password", default="localdev", help="Neo4j password")
    parser.add_argument("--sample-data", action="store_true", help="Load sample test data")
    args = parser.parse_args()

    results = init_schema(args.uri, args.user, args.password, args.sample_data)
    print(f"\nSchema: {results['constraints']} constraints, "
          f"{results['indexes']} indexes, "
          f"{results['sample_records']} sample records")


if __name__ == "__main__":
    main()
