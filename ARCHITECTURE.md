# Architecture Overview

## Control plane
- FastAPI API and analyst UI
- JWT auth + RBAC
- OIDC/SAML provider registry
- Case/evidence/SLA management

## Data plane
- live packet sniffing
- Suricata EVE ingest
- Zeek JSON ingest
- Sigma simulation lab
- correlation into incidents/cases

## Trust plane
- local root CA bootstrap
- per-agent certificate issuance
- fingerprint truststore
- revocation flow

## Tenancy
- application-layer tenant scoping
- PostgreSQL row-level security policy migration in `alembic/versions/20260312_0005_enterprise_v5.py`

## Fanout and jobs
- websocket connections terminate on API nodes
- Redis pub/sub fans out alert and incident updates across replicas
- Celery handles stale agent marking, threat intel sync and certificate rotation candidate discovery
