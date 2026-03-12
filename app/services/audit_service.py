from __future__ import annotations

import json
from sqlalchemy import desc, select
from sqlalchemy.orm import Session

from app.models.audit_log import AuditLog
from app.models.user import User


class AuditService:
    def __init__(self, db: Session):
        self.db = db

    def log(self, action: str, resource_type: str, resource_id: str | None = None, actor: User | None = None, outcome: str = 'success', details: dict | None = None, ip_address: str | None = None, tenant_id: int | None = None) -> AuditLog:
        row = AuditLog(
            tenant_id=tenant_id if tenant_id is not None else getattr(actor, 'tenant_id', None),
            actor_user_id=getattr(actor, 'id', None),
            actor_email=getattr(actor, 'email', None),
            action=action,
            resource_type=resource_type,
            resource_id=str(resource_id) if resource_id is not None else None,
            outcome=outcome,
            details_json=json.dumps(details or {}, ensure_ascii=False),
            ip_address=ip_address,
        )
        self.db.add(row)
        self.db.commit()
        self.db.refresh(row)
        return row

    def list_logs(self, limit: int = 100, tenant_id: int | None = None) -> list[AuditLog]:
        stmt = select(AuditLog).order_by(desc(AuditLog.created_at)).limit(limit)
        if tenant_id is not None:
            stmt = stmt.where(AuditLog.tenant_id == tenant_id)
        return list(self.db.scalars(stmt))
