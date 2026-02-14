"""Tests for Neo4j schema definitions — Story 2.5."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

from infra.scripts.init_neo4j import CONSTRAINTS, INDEXES, SAMPLE_DATA, init_schema


class TestSchemaDefinitions:
    def test_five_uniqueness_constraints(self):
        assert len(CONSTRAINTS) == 5

    def test_constraint_node_types(self):
        constraint_text = " ".join(CONSTRAINTS)
        assert "Asset" in constraint_text
        assert "Zone" in constraint_text
        assert "Model" in constraint_text
        assert "Finding" in constraint_text
        assert "Tenant" in constraint_text

    def test_all_constraints_are_unique(self):
        for c in CONSTRAINTS:
            assert "UNIQUE" in c

    def test_all_constraints_idempotent(self):
        for c in CONSTRAINTS:
            assert "IF NOT EXISTS" in c

    def test_indexes_defined(self):
        assert len(INDEXES) >= 3

    def test_all_indexes_idempotent(self):
        for idx in INDEXES:
            assert "IF NOT EXISTS" in idx

    def test_sample_data_has_nodes_and_relationships(self):
        text = " ".join(SAMPLE_DATA)
        assert "Tenant" in text
        assert "Zone" in text
        assert "Asset" in text
        assert "Model" in text
        assert "Finding" in text
        assert "RESIDES_IN" in text
        assert "DEPLOYS_TO" in text
        assert "AFFECTS" in text
        assert "OWNED_BY" in text
        assert "CONNECTS_TO" in text


class TestInitSchema:
    def test_runs_all_constraints_and_indexes(self):
        mock_driver = MagicMock()
        mock_session = MagicMock()
        mock_driver.session.return_value.__enter__ = MagicMock(return_value=mock_session)
        mock_driver.session.return_value.__exit__ = MagicMock(return_value=False)

        with patch("infra.scripts.init_neo4j.GraphDatabase.driver", return_value=mock_driver):
            results = init_schema(load_sample_data=False)

        assert results["constraints"] == 5
        assert results["indexes"] == len(INDEXES)
        assert results["sample_records"] == 0
        assert mock_session.run.call_count == 5 + len(INDEXES)

    def test_loads_sample_data_when_requested(self):
        mock_driver = MagicMock()
        mock_session = MagicMock()
        mock_driver.session.return_value.__enter__ = MagicMock(return_value=mock_session)
        mock_driver.session.return_value.__exit__ = MagicMock(return_value=False)

        with patch("infra.scripts.init_neo4j.GraphDatabase.driver", return_value=mock_driver):
            results = init_schema(load_sample_data=True)

        assert results["sample_records"] == len(SAMPLE_DATA)
        expected_calls = 5 + len(INDEXES) + len(SAMPLE_DATA)
        assert mock_session.run.call_count == expected_calls
