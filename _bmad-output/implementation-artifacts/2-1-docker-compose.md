# Story 2.1: Create Docker Compose for Local Dev

## Status: done

## Description
Docker Compose file that starts Kafka/Redpanda, Postgres, Redis, Qdrant, Neo4j, and MinIO for local development.

## Tasks
- [x] Create `docker-compose.yml` with all infrastructure services
- [x] Configure Redpanda on port 9092, Postgres on 5432, Redis on 6379, Qdrant on 6333, Neo4j on 7474/7687, MinIO on 9000/9001
- [x] Add volume mounts for data persistence (pgdata, qdrantdata, neo4jdata)
- [x] Add ALUSKORT services (entity-parser, context-gateway, llm-router, orchestrator, ctem-normaliser) under "services" profile
- [x] Add healthchecks for all infrastructure services
- [x] Add Postgres migration mount from `./infra/migrations`
- [x] Write tests in `tests/test_infra/test_docker_compose.py`
- [x] All 14 tests pass

## Completion Notes
- Created `docker-compose.yml` at project root
- All infrastructure services have healthchecks
- ALUSKORT services use `profiles: [services]` to avoid starting by default
- Postgres auto-loads DDL from `./infra/migrations` via `/docker-entrypoint-initdb.d/` mount
- 14/14 tests pass
