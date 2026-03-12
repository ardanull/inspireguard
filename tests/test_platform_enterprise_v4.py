from __future__ import annotations

from app.auth.security import decode_token
from app.auth.service import AuthService
from app.db.base import Base
from app.db.session import engine, SessionLocal
from app.services.audit_service import AuditService
from app.services.certificate_service import CertificateService
from app.services.rule_registry_service import RuleRegistryService
from app.services.sso_service import SSOService
from app.services.tenant_service import TenantService
from app.services.user_service import UserService


def setup_module(module):
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)


def test_default_admin_has_tenant():
    db = SessionLocal()
    try:
        user = AuthService(db).ensure_default_admin()
        assert user.tenant_id is not None
        tokens = AuthService(db).issue_tokens(user)
        payload = decode_token(tokens['access_token'])
        assert payload['tenant_id'] == user.tenant_id
    finally:
        db.close()


def test_tenant_audit_and_rule_versioning():
    db = SessionLocal()
    try:
        admin = AuthService(db).ensure_default_admin()
        tenant = TenantService(db).create_tenant('Blue Team', 'blue-team')
        AuditService(db).log('tenant.create', 'tenant', tenant.id, actor=admin)
        logs = AuditService(db).list_logs(limit=10)
        assert any(log.action == 'tenant.create' for log in logs)
        registry = RuleRegistryService(db)
        v1 = registry.create_version('rule-ssh', 'SSH Burst', 'high', 'title: SSH Burst')
        v2 = registry.create_version('rule-ssh', 'SSH Burst', 'critical', 'title: SSH Burst v2')
        active = registry.promote('rule-ssh', 2)
        assert active.version == 2 and active.is_active is True
        assert v1.version == 1 and v2.version == 2
    finally:
        db.close()


def test_certificate_issue_and_revoke():
    db = SessionLocal()
    try:
        cert = CertificateService(db).issue('agent-x')
        assert cert.fingerprint_sha256
        revoked = CertificateService(db).revoke(cert.fingerprint_sha256)
        assert revoked is not None and revoked.is_active is False
    finally:
        db.close()


def test_mock_sso_flow_creates_user():
    db = SessionLocal()
    try:
        tenant = TenantService(db).ensure_default_tenant()
        sso = SSOService(db)
        provider = sso.upsert_provider('okta-main', 'oidc', 'https://id.example.com', 'client', 'secret', tenant_id=tenant.id)
        begin = sso.begin_login(provider.name, 'http://localhost/callback')
        assert 'authorization_url' in begin
        result = sso.complete_login(provider.name, 'sso-user@example.com', 'SSO User', role='analyst')
        assert result['user']['tenant_id'] == tenant.id
        assert result['user']['email'] == 'sso-user@example.com'
    finally:
        db.close()
