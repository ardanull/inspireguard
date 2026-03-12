from __future__ import annotations

import json
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.auth.security import hash_password
from app.models.user import User

ROLE_PERMISSIONS = {
    'admin': ['alerts:read', 'alerts:write', 'incidents:write', 'agents:write', 'rules:write', 'users:write', 'tenants:write', 'audit:read'],
    'analyst': ['alerts:read', 'incidents:write', 'agents:read', 'rules:read', 'audit:read'],
    'viewer': ['alerts:read'],
}


class UserService:
    def __init__(self, db: Session):
        self.db = db

    def create_user(self, email: str, full_name: str, password: str, role: str = 'viewer', tenant_id: int | None = None) -> User:
        if self.db.scalar(select(User).where(User.email == email)):
            raise ValueError('User already exists')
        if role not in ROLE_PERMISSIONS:
            raise ValueError('Invalid role')
        user = User(email=email, full_name=full_name, password_hash=hash_password(password), role=role, tenant_id=tenant_id, permissions_json=json.dumps(ROLE_PERMISSIONS[role]), is_active=True)
        self.db.add(user)
        self.db.commit()
        self.db.refresh(user)
        return user

    def list_users(self) -> list[User]:
        return list(self.db.scalars(select(User).order_by(User.created_at.desc())))
