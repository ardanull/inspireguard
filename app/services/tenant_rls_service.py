from __future__ import annotations
from sqlalchemy import text
from sqlalchemy.orm import Session
class TenantRLSService:
    def __init__(self, db: Session):
        self.db = db
    def set_current_tenant(self, tenant_id: int | None):
        bind = self.db.get_bind()
        if bind is None or bind.dialect.name != 'postgresql':
            return False
        self.db.execute(text("SELECT set_config('app.current_tenant_id', :tenant_id, false)"), {'tenant_id': str(tenant_id or 0)})
        return True
