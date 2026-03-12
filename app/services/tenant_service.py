from __future__ import annotations

import json
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.tenant import Tenant


class TenantService:
    def __init__(self, db: Session):
        self.db = db

    def ensure_default_tenant(self) -> Tenant:
        tenant = self.db.scalar(select(Tenant).where(Tenant.slug == 'default'))
        if tenant:
            return tenant
        tenant = Tenant(name='Default Tenant', slug='default', settings_json=json.dumps({'retention_days': 30}))
        self.db.add(tenant)
        self.db.commit()
        self.db.refresh(tenant)
        return tenant

    def create_tenant(self, name: str, slug: str, settings: dict | None = None) -> Tenant:
        if self.db.scalar(select(Tenant).where((Tenant.name == name) | (Tenant.slug == slug))):
            raise ValueError('Tenant already exists')
        tenant = Tenant(name=name, slug=slug, settings_json=json.dumps(settings or {}))
        self.db.add(tenant)
        self.db.commit()
        self.db.refresh(tenant)
        return tenant

    def list_tenants(self) -> list[Tenant]:
        return list(self.db.scalars(select(Tenant).order_by(Tenant.name.asc())))
