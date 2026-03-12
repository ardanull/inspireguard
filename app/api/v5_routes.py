from __future__ import annotations
import json
from fastapi import APIRouter, Depends, HTTPException, Query, WebSocket, WebSocketDisconnect
from sqlalchemy.orm import Session
from app.api.deps import get_db
from app.auth.deps import get_current_user, require_role
from app.schemas.platform_v5 import CaseCreate, EvidenceCreate, OIDCProviderCreate, SAMLProviderCreate, SLAPolicyCreate, SigmaSimulationRequest
from app.services.audit_service import AuditService
from app.services.case_service import CaseService
from app.services.certificate_service import CertificateService
from app.services.evidence_service import EvidenceService
from app.services.sigma_lab_service import SigmaLabService
from app.services.sso_protocol_service import OIDCProtocolService, SAMLProtocolService
from app.services.sso_service import SSOService
from app.stream.manager import manager
v5_router = APIRouter(prefix='/api/v5', tags=['sentinelguard-v5'])
@v5_router.post('/cases')
def create_case(payload: CaseCreate, user=Depends(require_role('admin', 'analyst')), db: Session = Depends(get_db)):
    row = CaseService(db).create_case(payload.title, payload.priority, incident_id=payload.incident_id, assignee_user_id=payload.assignee_user_id, notes=payload.notes, tenant_id=user.tenant_id)
    AuditService(db).log('case.create', 'case', row.id, actor=user, details={'incident_id': payload.incident_id})
    return {'id': row.id, 'title': row.title, 'status': row.status, 'priority': row.priority}
@v5_router.get('/cases')
def list_cases(user=Depends(get_current_user), db: Session = Depends(get_db)):
    return [{'id': row.id, 'title': row.title, 'status': row.status, 'priority': row.priority, 'incident_id': row.incident_id} for row in CaseService(db).list_cases(tenant_id=user.tenant_id)]
@v5_router.post('/sla/policies')
def upsert_sla(payload: SLAPolicyCreate, user=Depends(require_role('admin')), db: Session = Depends(get_db)):
    row = CaseService(db).upsert_sla_policy(payload.severity, payload.acknowledge_minutes, payload.contain_minutes, payload.resolve_minutes, tenant_id=user.tenant_id)
    return {'id': row.id, 'severity': row.severity}
@v5_router.get('/sla/policies')
def list_sla(user=Depends(get_current_user), db: Session = Depends(get_db)):
    return [{'id': row.id, 'severity': row.severity, 'acknowledge_minutes': row.acknowledge_minutes, 'contain_minutes': row.contain_minutes, 'resolve_minutes': row.resolve_minutes} for row in CaseService(db).list_sla_policies(tenant_id=user.tenant_id)]
@v5_router.post('/evidence')
def add_evidence(payload: EvidenceCreate, user=Depends(require_role('admin', 'analyst')), db: Session = Depends(get_db)):
    row = EvidenceService(db).store_b64(payload.filename, payload.content_b64, content_type=payload.content_type, case_id=payload.case_id, tenant_id=user.tenant_id, actor_email=user.email)
    AuditService(db).log('evidence.store', 'evidence', row.id, actor=user, details={'sha256': row.sha256})
    return {'id': row.id, 'sha256': row.sha256, 'storage_path': row.storage_path}
@v5_router.get('/evidence')
def list_evidence(case_id: int | None = None, user=Depends(get_current_user), db: Session = Depends(get_db)):
    return [{'id': row.id, 'filename': row.filename, 'sha256': row.sha256, 'case_id': row.case_id, 'storage_path': row.storage_path} for row in EvidenceService(db).list_evidence(case_id=case_id, tenant_id=user.tenant_id)]
@v5_router.post('/sigma/simulate')
def sigma_simulate(payload: SigmaSimulationRequest, _: object = Depends(require_role('admin', 'analyst'))):
    return SigmaLabService().simulate(payload.rule_yaml, payload.events)
@v5_router.post('/sso/providers/oidc')
def create_oidc_provider(payload: OIDCProviderCreate, user=Depends(require_role('admin')), db: Session = Depends(get_db)):
    row = SSOService(db).upsert_provider(payload.name, 'oidc', payload.issuer, payload.client_id, payload.client_secret, metadata={'authorize_url': payload.authorize_url, 'token_url': payload.token_url, 'userinfo_url': payload.userinfo_url}, tenant_id=user.tenant_id)
    return {'id': row.id, 'name': row.name, 'type': row.provider_type}
@v5_router.post('/sso/providers/saml')
def create_saml_provider(payload: SAMLProviderCreate, user=Depends(require_role('admin')), db: Session = Depends(get_db)):
    row = SSOService(db).upsert_provider(payload.name, 'saml', payload.entity_id, payload.sso_url, 'x509-placeholder', metadata={'entity_id': payload.entity_id, 'sso_url': payload.sso_url, 'x509_cert': payload.x509_cert}, tenant_id=user.tenant_id)
    return {'id': row.id, 'name': row.name, 'type': row.provider_type}
@v5_router.get('/sso/oidc/{provider_name}/authorize')
def begin_oidc(provider_name: str, redirect_uri: str | None = None, db: Session = Depends(get_db), _: object = Depends(require_role('admin'))):
    provider = SSOService(db).get_provider(provider_name)
    if provider is None or provider.provider_type != 'oidc': raise HTTPException(status_code=404, detail='OIDC provider not found')
    meta = json.loads(provider.metadata_json or '{}'); meta['client_id'] = provider.client_id
    return OIDCProtocolService().build_authorization_url(meta, redirect_uri=redirect_uri)
@v5_router.get('/sso/saml/{provider_name}/request')
def begin_saml(provider_name: str, acs_url: str, db: Session = Depends(get_db), _: object = Depends(require_role('admin'))):
    provider = SSOService(db).get_provider(provider_name)
    if provider is None or provider.provider_type != 'saml': raise HTTPException(status_code=404, detail='SAML provider not found')
    return SAMLProtocolService().build_authn_request(json.loads(provider.metadata_json or '{}'), acs_url)
@v5_router.get('/truststore')
def truststore(_: object = Depends(require_role('admin', 'analyst')), db: Session = Depends(get_db)):
    rows = CertificateService(db).truststore()
    return [{'agent_id': row.agent_id, 'serial_number': row.serial_number, 'fingerprint_sha256': row.fingerprint_sha256, 'expires_at': row.expires_at.isoformat()} for row in rows]
@v5_router.get('/platform/features')
def platform_features(_: object = Depends(get_current_user)):
    return {'features': ['oidc', 'saml', 'mtls-pki', 'postgres-rls', 'redis-fanout', 'sigma-lab', 'case-management', 'evidence-locker', 'kubernetes', 'helm', 'observability']}
@v5_router.websocket('/ws/{channel}')
async def websocket_channel(websocket: WebSocket, channel: str):
    await manager.connect(channel, websocket)
    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        await manager.disconnect(channel, websocket)
