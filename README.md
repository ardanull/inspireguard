# inspireGuard Enterprise SOC Platform v5

inspireGuard v5 is a live-ready defensive security platform built to look and feel like a senior/lead engineer project rather than a lab demo. It combines packet analysis, event ingestion, threat intel, incident correlation, case management, evidence handling, PKI-backed agent trust, SSO, distributed websocket streaming, Kubernetes deployment artifacts, and a Sigma-style rules laboratory.

## Highlights
- FastAPI control plane with RBAC, login and analyst workflow
- PostgreSQL-ready data model with Alembic migration and row-level security policy SQL
- Redis fanout for distributed websocket streams and Celery background jobs
- OIDC and SAML provider configuration flows
- Real local root CA generation and agent certificate issuance/revocation using `cryptography`
- Multi-agent enrollment, heartbeat and truststore handling
- Sigma-like parser and simulation lab for detection engineering
- Case management, SLA policies and filesystem-backed evidence locker with chain of custody metadata
- Suricata and Zeek ingest hooks
- Helm chart, Kubernetes manifests, Prometheus and OpenTelemetry starter configs

## Quick start
```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
uvicorn app.main:app --reload
```

Default admin:
- Email: `admin@inspireGuard.local`
- Password: `ChangeThisPassword!123`
