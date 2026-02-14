"""Async Neo4j client wrapper with consequence reasoning and static fallback."""

from __future__ import annotations

import logging
from typing import Any, Optional

import neo4j

logger = logging.getLogger(__name__)

# Static fallback when Neo4j is unavailable
ZONE_CONSEQUENCE_FALLBACK: dict[str, str] = {
    "safety_life": "CRITICAL",
    "equipment": "HIGH",
    "downtime": "MEDIUM",
    "data_loss": "LOW",
}

# Consequence reasoning Cypher from ai-system-design.md Section 8.2
CONSEQUENCE_QUERY = """\
MATCH (f:Finding {id: $finding_id})-[:AFFECTS]->(a:Asset)
OPTIONAL MATCH (a)<-[:DEPLOYS_TO]-(m:Model)-[:DEPLOYS_TO]->(downstream:Asset)-[:RESIDES_IN]->(z:Zone)
WITH f, a, collect(DISTINCT z.consequence_class) AS reachable_consequences
RETURN f.id AS finding_id,
       a.name AS directly_affected_asset,
       reachable_consequences,
       CASE
           WHEN 'safety_life' IN reachable_consequences THEN 'CRITICAL'
           WHEN 'equipment' IN reachable_consequences THEN 'HIGH'
           WHEN 'downtime' IN reachable_consequences THEN 'MEDIUM'
           ELSE 'LOW'
       END AS max_consequence_severity
"""


def _map_consequence_severity(consequences: list[str]) -> str:
    """Map reachable consequence classes to max severity."""
    if "safety_life" in consequences:
        return "CRITICAL"
    if "equipment" in consequences:
        return "HIGH"
    if "downtime" in consequences:
        return "MEDIUM"
    return "LOW"


def _fallback_consequence(zone_class: Optional[str] = None) -> str:
    """Static fallback when Neo4j is unavailable."""
    if zone_class is None:
        return "LOW"
    return ZONE_CONSEQUENCE_FALLBACK.get(zone_class, "LOW")


class Neo4jClient:
    """Async Neo4j wrapper with consequence reasoning and graceful degradation."""

    def __init__(
        self,
        *,
        uri: str = "bolt://localhost:7687",
        user: str = "neo4j",
        password: str = "",
        database: str = "neo4j",
        max_connection_pool_size: int = 50,
    ) -> None:
        self._uri = uri
        self._user = user
        self._password = password
        self._database = database
        self._max_pool = max_connection_pool_size
        self._driver: Optional[neo4j.AsyncDriver] = None

    async def connect(self) -> None:
        """Create the driver and verify connectivity."""
        self._driver = neo4j.AsyncGraphDatabase.driver(
            self._uri,
            auth=(self._user, self._password),
            max_connection_pool_size=self._max_pool,
        )
        await self._driver.verify_connectivity()
        logger.info("Neo4j connected (%s)", self._uri)

    async def close(self) -> None:
        """Close the driver gracefully."""
        if self._driver:
            await self._driver.close()
            self._driver = None
            logger.info("Neo4j driver closed")

    def _ensure_driver(self) -> neo4j.AsyncDriver:
        if self._driver is None:
            raise RuntimeError("Neo4jClient is not connected. Call connect() first.")
        return self._driver

    async def execute_query(
        self,
        cypher: str,
        params: Optional[dict[str, Any]] = None,
        database: Optional[str] = None,
    ) -> list[dict[str, Any]]:
        """Execute a Cypher query and return results as list of dicts."""
        driver = self._ensure_driver()
        db = database or self._database
        records, _, _ = await driver.execute_query(
            cypher, parameters_=params or {}, database_=db
        )
        return [dict(r) for r in records]

    async def get_consequence_severity(
        self, finding_id: str, zone_class: Optional[str] = None
    ) -> dict[str, Any]:
        """Get consequence severity for a finding via graph traversal.

        Falls back to static ZONE_CONSEQUENCE_FALLBACK when Neo4j is unavailable.
        """
        try:
            results = await self.execute_query(
                CONSEQUENCE_QUERY, params={"finding_id": finding_id}
            )
            if not results:
                severity = _fallback_consequence(zone_class)
                return {
                    "finding_id": finding_id,
                    "directly_affected_asset": None,
                    "reachable_consequences": [],
                    "max_consequence_severity": severity,
                    "fallback": True,
                }
            row = results[0]
            return {
                "finding_id": row.get("finding_id", finding_id),
                "directly_affected_asset": row.get("directly_affected_asset"),
                "reachable_consequences": row.get("reachable_consequences", []),
                "max_consequence_severity": row.get("max_consequence_severity", "LOW"),
                "fallback": False,
            }
        except Exception:
            logger.warning(
                "GRAPH_UNAVAILABLE: falling back to static zone-consequence mapping "
                "for finding %s",
                finding_id,
            )
            severity = _fallback_consequence(zone_class)
            return {
                "finding_id": finding_id,
                "directly_affected_asset": None,
                "reachable_consequences": [],
                "max_consequence_severity": severity,
                "fallback": True,
            }

    async def get_asset_graph(self, asset_id: str) -> dict[str, Any]:
        """Retrieve an asset's zone and relationship context."""
        cypher = """
        MATCH (a:Asset {id: $asset_id})
        OPTIONAL MATCH (a)-[:RESIDES_IN]->(z:Zone)
        OPTIONAL MATCH (a)-[:OWNED_BY]->(t:Tenant)
        RETURN a.id AS asset_id, a.name AS asset_name,
               z.name AS zone_name, z.consequence_class AS consequence_class,
               t.id AS tenant_id
        """
        results = await self.execute_query(cypher, params={"asset_id": asset_id})
        if not results:
            return {"asset_id": asset_id, "found": False}
        row = results[0]
        row["found"] = True
        return row

    async def health_check(self) -> bool:
        """Check Neo4j connectivity."""
        try:
            driver = self._ensure_driver()
            await driver.execute_query("RETURN 1", database_=self._database)
            return True
        except Exception:
            logger.warning("Neo4j health check failed", exc_info=True)
            return False

    async def __aenter__(self) -> Neo4jClient:
        await self.connect()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb) -> None:  # noqa: ANN001
        await self.close()
