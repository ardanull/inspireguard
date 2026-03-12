from __future__ import annotations

import json
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.auth.security import create_token, hash_password, verify_password
from app.core.config import get_settings
from app.models.user import User
from app.services.tenant_service import TenantService

ROLE_PERMISSIONS = {
    'admin': ['alerts:read', 'alerts:write', 'incidents:write', 'agents:write', 'rules:write', 'users:write', 'tenants:write', 'audit:read'],
    'analyst': ['alerts:read', 'incidents:write', 'agents:read', 'rules:read', 'audit:read'],
    'viewer': ['alerts:read'],
}


class AuthService:
    def __init__(self, db: Session):
        self.db = db
        self.settings = get_settings()

    def ensure_default_admin(self) -> User:
        tenant = TenantService(self.db).ensure_default_tenant()
        user = self.db.scalar(select(User).where(User.email == self.settings.default_admin_email))
        if user:
            if user.tenant_id is None:
                user.tenant_id = tenant.id
                self.db.commit()
            return user
        user = User(
            email=self.settings.default_admin_email,
            full_name='Platform Administrator',
            password_hash=hash_password(self.settings.default_admin_password),
            role='admin',
            tenant_id=tenant.id,
            permissions_json=json.dumps(ROLE_PERMISSIONS['admin']),
            is_active=True,
        )
        self.db.add(user)
        self.db.commit()
        self.db.refresh(user)
        return user

    def authenticate(self, email: str, password: str) -> User | None:
        user = self.db.scalar(select(User).where(User.email == email))
        if not user or not user.is_active:
            return None
        if not verify_password(password, user.password_hash):
            return None
        return user

    def issue_tokens(self, user: User) -> dict:
        extra = {'tenant_id': user.tenant_id, 'permissions': json.loads(user.permissions_json or '[]')}
        return {
            'access_token': create_token(str(user.id), user.role, self.settings.access_token_expire_minutes, 'access', extra=extra),
            'refresh_token': create_token(str(user.id), user.role, self.settings.refresh_token_expire_minutes, 'refresh', extra=extra),
            'token_type': 'bearer',
            'user': {
                'id': user.id,
                'email': user.email,
                'full_name': user.full_name,
                'role': user.role,
                'tenant_id': user.tenant_id,
                'permissions': json.loads(user.permissions_json or '[]'),
            },
        }
