from __future__ import annotations

import json
import secrets
from datetime import datetime, timedelta

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.agent_node import AgentNode

DEFAULT_POLICY = {
    'collection_interval_seconds': 5,
    'enabled_integrations': ['syslog', 'suricata', 'zeek'],
    'buffer_limit': 5000,
    'mtls_required': True,
}


class AgentService:
    def __init__(self, db: Session):
        self.db = db

    def enroll(self, agent_id: str, hostname: str, ip_address: str | None, version: str, capabilities: list[str], labels: list[str], tenant_id: int | None = None) -> AgentNode:
        row = self.db.scalar(select(AgentNode).where(AgentNode.agent_id == agent_id))
        if row is None:
            row = AgentNode(agent_id=agent_id, enrollment_token=secrets.token_urlsafe(32))
            self.db.add(row)
        row.tenant_id = tenant_id
        row.hostname = hostname
        row.ip_address = ip_address
        row.version = version
        row.capabilities_json = json.dumps(capabilities)
        row.labels_json = json.dumps(labels)
        row.policy_json = json.dumps(DEFAULT_POLICY)
        row.last_seen_at = datetime.utcnow()
        row.status = 'online'
        row.is_approved = True
        self.db.commit()
        self.db.refresh(row)
        return row

    def heartbeat(self, agent_id: str) -> AgentNode | None:
        row = self.db.scalar(select(AgentNode).where(AgentNode.agent_id == agent_id))
        if row is None:
            return None
        row.last_seen_at = datetime.utcnow()
        row.status = 'online'
        self.db.commit()
        self.db.refresh(row)
        return row

    def mark_stale_agents(self, stale_after_minutes: int = 5) -> int:
        threshold = datetime.utcnow() - timedelta(minutes=stale_after_minutes)
        rows = list(self.db.scalars(select(AgentNode).where(AgentNode.last_seen_at < threshold, AgentNode.status != 'offline')))
        for row in rows:
            row.status = 'offline'
        self.db.commit()
        return len(rows)

    def list_agents(self) -> list[AgentNode]:
        return list(self.db.scalars(select(AgentNode).order_by(AgentNode.last_seen_at.desc())))
