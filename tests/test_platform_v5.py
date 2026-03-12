from __future__ import annotations
import base64
from pathlib import Path
from app.db.base import Base
from app.db.session import SessionLocal, engine
from app.services.case_service import CaseService
from app.services.certificate_service import CertificateService
from app.services.evidence_service import EvidenceService
from app.services.pki_service import PKIService
from app.services.sigma_lab_service import SigmaLabService
from app.services.sso_protocol_service import OIDCProtocolService, SAMLProtocolService
from app.services.sso_service import SSOService
from app.services.tenant_service import TenantService

def setup_module(module):
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)

def test_real_ca_and_agent_cert_issue():
    db = SessionLocal()
    try:
        ca_key, ca_cert = PKIService().ensure_ca()
        assert Path(ca_key).exists() and Path(ca_cert).exists()
        cert = CertificateService(db).issue('agent-live-1')
        assert 'BEGIN CERTIFICATE' in cert.certificate_pem
        assert len(cert.fingerprint_sha256) >= 32
    finally:
        db.close()

def test_sigma_lab_matches_event():
    result = SigmaLabService().simulate("""
title: Suspicious PowerShell
level: high
detection:
  selection:
    Image: '*powershell*'
    CommandLine: '*EncodedCommand*'
  condition: selection
""", [{'Image': 'cmd.exe', 'CommandLine': 'whoami'}, {'Image': 'C:/Windows/System32/WindowsPowerShell/v1.0/powershell.exe', 'CommandLine': 'powershell -EncodedCommand aQBlAHgA'}])
    assert result['match_count'] == 1
    assert result['matches'][0]['index'] == 1

def test_evidence_locker_chain_of_custody():
    db = SessionLocal()
    try:
        payload = base64.b64encode(b'forensic-artifact').decode('ascii')
        row = EvidenceService(db).store_b64('memory.txt', payload, actor_email='analyst@example.com')
        assert Path(row.storage_path).exists()
        assert row.sha256
    finally:
        db.close()

def test_sso_protocol_flows():
    db = SessionLocal()
    try:
        tenant = TenantService(db).ensure_default_tenant()
        provider = SSOService(db).upsert_provider('corp-oidc', 'oidc', 'https://login.example.com', 'client', 'secret', metadata={'authorize_url': 'https://login.example.com/authorize', 'token_url': 'https://login.example.com/token', 'userinfo_url': 'https://login.example.com/userinfo'}, tenant_id=tenant.id)
        authz = OIDCProtocolService().build_authorization_url({'client_id': provider.client_id, 'authorize_url': 'https://login.example.com/authorize'})
        assert 'authorization_url' in authz and 'state=' in authz['authorization_url']
        saml_req = SAMLProtocolService().build_authn_request({'entity_id': 'sentinelguard', 'sso_url': 'https://login.example.com/sso'}, 'https://sp.example.com/acs')
        assert saml_req['binding'] == 'HTTP-Redirect'
    finally:
        db.close()

def test_case_and_sla_policy():
    db = SessionLocal()
    try:
        service = CaseService(db)
        case = service.create_case('Privilege escalation investigation', priority='high')
        policy = service.upsert_sla_policy('high', 10, 60, 240)
        assert case.id is not None
        assert policy.severity == 'high'
    finally:
        db.close()
