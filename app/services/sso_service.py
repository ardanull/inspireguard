from __future__ import annotations
import json
from sqlalchemy import select
from sqlalchemy.orm import Session
from app.auth.service import ROLE_PERMISSIONS
from app.auth.security import hash_password
from app.models.sso_provider import SSOProvider
from app.models.user import User
class SSOService:
    def __init__(self, db: Session): self.db = db
    def upsert_provider(self, name: str, provider_type: str, issuer_url: str, client_id: str, client_secret: str, metadata: dict | None = None, tenant_id: int | None = None):
        row = self.db.scalar(select(SSOProvider).where(SSOProvider.name == name))
        if row is None:
            row = SSOProvider(name=name, provider_type=provider_type, issuer_url=issuer_url, client_id=client_id, client_secret=client_secret, metadata_json=json.dumps(metadata or {}), tenant_id=tenant_id, is_enabled=True)
            self.db.add(row)
        else:
            row.provider_type = provider_type; row.issuer_url = issuer_url; row.client_id = client_id; row.client_secret = client_secret; row.metadata_json = json.dumps(metadata or {}); row.tenant_id = tenant_id; row.is_enabled = True
        self.db.commit(); self.db.refresh(row); return row
    def get_provider(self, name: str):
        return self.db.scalar(select(SSOProvider).where(SSOProvider.name == name, SSOProvider.is_enabled.is_(True)))
    def begin_login(self, provider_name: str, redirect_uri: str | None = None):
        provider = self.get_provider(provider_name)
        if provider is None: raise ValueError('Provider not found')
        return {'provider': provider.name, 'authorization_url': f'{provider.issuer_url}/authorize?client_id={provider.client_id}&redirect_uri={redirect_uri or "http://localhost/callback"}'}
    def complete_login(self, provider_name: str, email: str, full_name: str, role: str = 'analyst'):
        provider = self.get_provider(provider_name)
        if provider is None: raise ValueError('Provider not found')
        user = self.db.scalar(select(User).where(User.email == email))
        if user is None:
            user = User(email=email, full_name=full_name, password_hash=hash_password(provider_name + ':' + email), role=role, tenant_id=provider.tenant_id, permissions_json=json.dumps(ROLE_PERMISSIONS.get(role, ROLE_PERMISSIONS['viewer'])), is_active=True)
            self.db.add(user); self.db.commit(); self.db.refresh(user)
        return {'provider': provider.name, 'user': {'id': user.id, 'email': user.email, 'full_name': user.full_name, 'role': user.role, 'tenant_id': user.tenant_id}}
