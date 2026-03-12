from __future__ import annotations
import json
from sqlalchemy import select
from sqlalchemy.orm import Session
from app.models.case import Case
from app.models.sla_policy import SLAPolicy
class CaseService:
    def __init__(self, db: Session):
        self.db = db
    def default_playbook(self, priority: str):
        return [
            {'step': 'validate scope', 'required': True},
            {'step': 'collect volatile artifacts', 'required': True},
            {'step': 'contain impacted asset', 'required': priority in {'high', 'critical'}},
            {'step': 'document stakeholder update', 'required': True},
        ]
    def create_case(self, title: str, priority: str = 'medium', incident_id: int | None = None, assignee_user_id: int | None = None, notes: str = '', tenant_id: int | None = None):
        row = Case(title=title, priority=priority, incident_id=incident_id, assignee_user_id=assignee_user_id, notes=notes, tenant_id=tenant_id, playbook_json=json.dumps(self.default_playbook(priority)))
        self.db.add(row)
        self.db.commit()
        self.db.refresh(row)
        return row
    def list_cases(self, tenant_id: int | None = None):
        stmt = select(Case).order_by(Case.updated_at.desc())
        if tenant_id is not None:
            stmt = stmt.where(Case.tenant_id == tenant_id)
        return list(self.db.scalars(stmt))
    def upsert_sla_policy(self, severity: str, acknowledge_minutes: int, contain_minutes: int, resolve_minutes: int, tenant_id: int | None = None):
        row = self.db.scalar(select(SLAPolicy).where(SLAPolicy.severity == severity, SLAPolicy.tenant_id == tenant_id, SLAPolicy.is_active.is_(True)))
        if row is None:
            row = SLAPolicy(severity=severity, acknowledge_minutes=acknowledge_minutes, contain_minutes=contain_minutes, resolve_minutes=resolve_minutes, tenant_id=tenant_id, is_active=True)
            self.db.add(row)
        else:
            row.acknowledge_minutes = acknowledge_minutes
            row.contain_minutes = contain_minutes
            row.resolve_minutes = resolve_minutes
        self.db.commit(); self.db.refresh(row)
        return row
    def list_sla_policies(self, tenant_id: int | None = None):
        stmt = select(SLAPolicy).where(SLAPolicy.is_active.is_(True))
        if tenant_id is not None:
            stmt = stmt.where(SLAPolicy.tenant_id == tenant_id)
        return list(self.db.scalars(stmt.order_by(SLAPolicy.severity.asc())))
