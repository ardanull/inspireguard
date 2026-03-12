from __future__ import annotations
from datetime import datetime, timedelta
from app.db.session import SessionLocal
from app.models.agent_certificate import AgentCertificate
from app.models.agent_node import AgentNode
from app.tasks.celery_app import celery_app
@celery_app.task(name='sentinelguard.jobs.sync_threat_intel')
def sync_threat_intel():
    return {'synced': True, 'provider': 'default-fixtures'}
@celery_app.task(name='sentinelguard.jobs.rotate_agent_certificates')
def rotate_agent_certificates(days_before_expiry: int = 7):
    db = SessionLocal()
    try:
        threshold = datetime.utcnow() + timedelta(days=days_before_expiry)
        candidates = list(db.query(AgentCertificate).filter(AgentCertificate.is_active.is_(True), AgentCertificate.expires_at <= threshold))
        return {'rotate_candidates': [row.agent_id for row in candidates], 'count': len(candidates)}
    finally:
        db.close()
@celery_app.task(name='sentinelguard.jobs.mark_stale_agents')
def mark_stale_agents(minutes_without_heartbeat: int = 10):
    db = SessionLocal()
    try:
        threshold = datetime.utcnow() - timedelta(minutes=minutes_without_heartbeat)
        candidates = list(db.query(AgentNode).filter(AgentNode.last_seen_at < threshold))
        for row in candidates: row.status = 'stale'
        db.commit()
        return {'stale_agents': [row.agent_id for row in candidates], 'count': len(candidates)}
    finally:
        db.close()
