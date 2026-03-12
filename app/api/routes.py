from __future__ import annotations

import json
import tempfile
from pathlib import Path

from fastapi import APIRouter, Depends, File, Form, HTTPException, Query, Request, UploadFile, WebSocket, WebSocketDisconnect
from sqlalchemy.orm import Session

from app.api.deps import get_db
from app.auth.deps import get_current_user, require_permission, require_role
from app.auth.service import AuthService
from app.db.session import SessionLocal
from app.schemas.agent import AgentEnrollRequest, AgentHeartbeat, IncidentCommentCreate
from app.schemas.auth import LoginRequest, RegisterRequest
from app.schemas.rule_registry import RulePromoteRequest, RuleVersionCreate
from app.schemas.sso import SSOCompleteRequest, SSOProviderCreate
from app.schemas.tenant import TenantCreate
from app.services.agent_service import AgentService
from app.services.alert_service import AlertService
from app.services.asset_service import AssetService
from app.services.audit_service import AuditService
from app.services.certificate_service import CertificateService
from app.services.hunt_service import HuntService
from app.services.incident_service import IncidentService
from app.services.ingest_service import IngestService
from app.services.rule_registry_service import RuleRegistryService
from app.services.sniffer_service import SnifferService
from app.services.sso_service import SSOService
from app.services.tenant_service import TenantService
from app.services.threat_intel_service import ThreatIntelService
from app.services.user_service import UserService
from app.stream.manager import manager

router = APIRouter(prefix='/api/v1', tags=['sentinelguard-enterprise'])
sniffer_service = SnifferService()


def _ingest_event(event):
    if event is None:
        return
    db = SessionLocal()
    try:
        IngestService(db).handle_event(event)
    finally:
        db.close()


@router.post('/auth/login')
def login(payload: LoginRequest, db: Session = Depends(get_db)):
    service = AuthService(db)
    service.ensure_default_admin()
    user = service.authenticate(payload.email, payload.password)
    if user is None:
        raise HTTPException(status_code=401, detail='Invalid credentials')
    AuditService(db).log('auth.login', 'user', user.id, actor=user)
    return service.issue_tokens(user)


@router.post('/auth/register')
def register(payload: RegisterRequest, current_user=Depends(require_role('admin')), db: Session = Depends(get_db)):
    try:
        user = UserService(db).create_user(payload.email, payload.full_name, payload.password, payload.role, tenant_id=current_user.tenant_id)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    AuditService(db).log('user.create', 'user', user.id, actor=current_user, details={'email': user.email, 'role': user.role})
    return {'id': user.id, 'email': user.email, 'full_name': user.full_name, 'role': user.role, 'tenant_id': user.tenant_id}


@router.get('/users')
def list_users(_: object = Depends(require_role('admin')), db: Session = Depends(get_db)):
    return [{'id': u.id, 'email': u.email, 'full_name': u.full_name, 'role': u.role, 'is_active': u.is_active, 'tenant_id': u.tenant_id} for u in UserService(db).list_users()]


@router.get('/health')
def health(db: Session = Depends(get_db)):
    return {'status': 'ok', 'service': 'sentinelguard-enterprise', 'capabilities': ['live-sniffing', 'pcap-analysis', 'incident-correlation', 'threat-intel', 'rbac', 'celery-jobs', 'multi-agent-collectors', 'sigma-like-rules', 'suricata-zeek-ingest', 'websocket-stream', 'multi-tenant', 'audit-trail', 'sso-ready', 'agent-mtls'], 'asset_count': len(AssetService(db).list_assets(limit=1000))}


@router.get('/alerts')
def list_alerts(limit: int = Query(100, le=500), severity: str | None = None, detector: str | None = None, user=Depends(get_current_user), db: Session = Depends(get_db)):
    alerts = AlertService(db).list_alerts(limit=limit, severity=severity, detector=detector, tenant_id=user.tenant_id)
    return [{'id': a.id, 'created_at': a.created_at.isoformat(), 'tenant_id': a.tenant_id, 'detector': a.detector, 'severity': a.severity, 'status': a.status, 'src_ip': a.src_ip, 'dst_ip': a.dst_ip, 'incident_id': a.incident_id, 'title': a.title, 'description': a.description, 'fingerprint': a.fingerprint, 'sensor_id': a.sensor_id, 'metadata': json.loads(a.metadata_json or '{}')} for a in alerts]


@router.get('/incidents')
def list_incidents(limit: int = Query(100, le=500), status: str | None = None, user=Depends(get_current_user), db: Session = Depends(get_db)):
    incidents = IncidentService(db).list_incidents(limit=limit, status=status, tenant_id=user.tenant_id)
    return [{'id': item.id, 'created_at': item.created_at.isoformat(), 'updated_at': item.updated_at.isoformat(), 'tenant_id': item.tenant_id, 'status': item.status, 'severity': item.severity, 'title': item.title, 'summary': item.summary, 'source_key': item.source_key, 'src_ip': item.src_ip, 'alert_count': item.alert_count, 'triage_status': item.triage_status, 'assigned_user_id': item.assigned_user_id, 'tags': json.loads(item.tags_json or '[]'), 'runbook': json.loads(item.runbook_json or '[]')} for item in incidents]


@router.post('/incidents/{incident_id}/triage')
def update_incident_triage(incident_id: int, triage_status: str = Form(...), assigned_user_id: int | None = Form(default=None), current_user=Depends(require_role('admin', 'analyst')), db: Session = Depends(get_db)):
    try:
        row = IncidentService(db).update_triage(incident_id, triage_status, assigned_user_id)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    AuditService(db).log('incident.triage', 'incident', row.id, actor=current_user, details={'triage_status': triage_status, 'assigned_user_id': assigned_user_id})
    return {'id': row.id, 'triage_status': row.triage_status, 'assigned_user_id': row.assigned_user_id}


@router.post('/incidents/{incident_id}/comments')
def add_incident_comment(incident_id: int, payload: IncidentCommentCreate, user=Depends(get_current_user), db: Session = Depends(get_db)):
    row = IncidentService(db).add_comment(incident_id, user.id, payload.comment)
    AuditService(db).log('incident.comment', 'incident', incident_id, actor=user)
    return {'id': row.id, 'created_at': row.created_at.isoformat(), 'comment': row.comment}


@router.get('/incidents/{incident_id}/comments')
def list_incident_comments(incident_id: int, _: object = Depends(get_current_user), db: Session = Depends(get_db)):
    rows = IncidentService(db).list_comments(incident_id)
    return [{'id': row.id, 'created_at': row.created_at.isoformat(), 'author_user_id': row.author_user_id, 'comment': row.comment} for row in rows]


@router.get('/intel/indicators')
def list_indicators(limit: int = Query(100, le=500), _: object = Depends(get_current_user), db: Session = Depends(get_db)):
    intel = ThreatIntelService(db)
    intel.sync_defaults()
    rows = intel.list_indicators(limit=limit)
    return [{'id': row.id, 'type': row.type, 'value': row.value, 'severity': row.severity, 'confidence': row.confidence, 'source': row.source, 'description': row.description, 'tags': json.loads(row.tags_json or '[]')} for row in rows]


@router.get('/assets')
def list_assets(limit: int = Query(100, le=500), _: object = Depends(get_current_user), db: Session = Depends(get_db)):
    assets = AssetService(db).list_assets(limit=limit)
    return [{'id': item.id, 'tenant_id': item.tenant_id, 'ip_address': item.ip_address, 'hostname': item.hostname, 'owner': item.owner, 'criticality': item.criticality, 'environment': item.environment, 'tags': json.loads(item.tags_json or '[]')} for item in assets]


@router.get('/agents')
def list_agents(_: object = Depends(get_current_user), db: Session = Depends(get_db)):
    rows = AgentService(db).list_agents()
    return [{'id': row.id, 'tenant_id': row.tenant_id, 'agent_id': row.agent_id, 'hostname': row.hostname, 'ip_address': row.ip_address, 'version': row.version, 'status': row.status, 'last_seen_at': row.last_seen_at.isoformat(), 'capabilities': json.loads(row.capabilities_json or '[]'), 'labels': json.loads(row.labels_json or '[]'), 'policy': json.loads(row.policy_json or '{}')} for row in rows]


@router.post('/agents/enroll')
def enroll_agent(payload: AgentEnrollRequest, db: Session = Depends(get_db)):
    row = AgentService(db).enroll(payload.agent_id, payload.hostname, payload.ip_address, payload.version, payload.capabilities, payload.labels)
    cert = CertificateService(db).issue(agent_id=payload.agent_id, tenant_id=row.tenant_id)
    return {'id': row.id, 'agent_id': row.agent_id, 'approved': row.is_approved, 'status': row.status, 'certificate_fingerprint': cert.fingerprint_sha256}


@router.post('/agents/heartbeat')
def heartbeat(payload: AgentHeartbeat, db: Session = Depends(get_db)):
    row = AgentService(db).heartbeat(payload.agent_id)
    if row is None:
        raise HTTPException(status_code=404, detail='Agent not found')
    return {'agent_id': row.agent_id, 'status': row.status, 'last_seen_at': row.last_seen_at.isoformat()}


@router.get('/agents/{agent_id}/policy')
def get_agent_policy(agent_id: str, _: object = Depends(get_current_user), db: Session = Depends(get_db)):
    row = next((a for a in AgentService(db).list_agents() if a.agent_id == agent_id), None)
    if row is None:
        raise HTTPException(status_code=404, detail='Agent not found')
    return {'agent_id': row.agent_id, 'policy': json.loads(row.policy_json or '{}')}


@router.get('/truststore')
def truststore(_: object = Depends(require_role('admin', 'analyst')), db: Session = Depends(get_db)):
    rows = CertificateService(db).truststore()
    return [{'agent_id': row.agent_id, 'serial_number': row.serial_number, 'fingerprint_sha256': row.fingerprint_sha256, 'expires_at': row.expires_at.isoformat(), 'issued_by': row.issued_by} for row in rows]


@router.post('/truststore/revoke/{fingerprint}')
def revoke_certificate(fingerprint: str, user=Depends(require_role('admin')), db: Session = Depends(get_db)):
    row = CertificateService(db).revoke(fingerprint)
    if row is None:
        raise HTTPException(status_code=404, detail='Certificate not found')
    AuditService(db).log('certificate.revoke', 'agent_certificate', row.id, actor=user, details={'fingerprint': fingerprint})
    return {'revoked': True, 'fingerprint_sha256': row.fingerprint_sha256}


@router.get('/metrics/summary')
def metrics_summary(user=Depends(get_current_user), db: Session = Depends(get_db)):
    return {'alerts': AlertService(db).metrics_summary(tenant_id=user.tenant_id), 'incidents': IncidentService(db).incident_metrics(tenant_id=user.tenant_id), 'hunt': {'top_noisy_sources': HuntService(db).top_noisy_sources(limit=5)}, 'agents': {'count': len(AgentService(db).list_agents())}}


@router.post('/events')
def ingest_event(payload: dict, user=Depends(get_current_user), db: Session = Depends(get_db)):
    alerts = IngestService(db, tenant_id=user.tenant_id).ingest_raw_event(payload)
    return {'alerts_created': len(alerts), 'incident_ids': sorted({a.incident_id for a in alerts if a.incident_id})}


@router.post('/suricata/eve')
async def ingest_suricata(file: UploadFile = File(...), user=Depends(require_role('admin', 'analyst')), db: Session = Depends(get_db)):
    with tempfile.NamedTemporaryFile(delete=False, suffix='.json') as tmp:
        tmp.write(await file.read())
        path = tmp.name
    try:
        count = IngestService(db, tenant_id=user.tenant_id).ingest_suricata_file(path)
    finally:
        Path(path).unlink(missing_ok=True)
    return {'processed_events': count}


@router.post('/zeek/conn')
async def ingest_zeek(file: UploadFile = File(...), user=Depends(require_role('admin', 'analyst')), db: Session = Depends(get_db)):
    with tempfile.NamedTemporaryFile(delete=False, suffix='.json') as tmp:
        tmp.write(await file.read())
        path = tmp.name
    try:
        count = IngestService(db, tenant_id=user.tenant_id).ingest_zeek_file(path)
    finally:
        Path(path).unlink(missing_ok=True)
    return {'processed_events': count}


@router.post('/sniffer/start')
def start_sniffer(iface: str | None = None, _: object = Depends(require_role('admin', 'analyst'))):
    started = sniffer_service.start_live(_ingest_event, iface=iface)
    return {'started': started, 'running': sniffer_service.running}


@router.post('/sniffer/stop')
def stop_sniffer(_: object = Depends(require_role('admin', 'analyst'))):
    stopped = sniffer_service.stop_live()
    return {'stopped': stopped, 'running': sniffer_service.running}


@router.post('/pcap/analyze')
async def analyze_pcap(file: UploadFile = File(...), user=Depends(require_role('admin', 'analyst')), db: Session = Depends(get_db)):
    ingest = IngestService(db, tenant_id=user.tenant_id)
    suffix = Path(file.filename or 'capture.pcap').suffix or '.pcap'
    with tempfile.NamedTemporaryFile(delete=False, suffix=suffix) as tmp:
        tmp.write(await file.read())
        temp_path = tmp.name
    try:
        count = sniffer_service.analyze_pcap(temp_path, lambda event: None if event is None else ingest.handle_event(event))
    finally:
        Path(temp_path).unlink(missing_ok=True)
    return {'processed_packets': count}


@router.post('/tenants')
def create_tenant(payload: TenantCreate, user=Depends(require_permission('tenants:write')), db: Session = Depends(get_db)):
    try:
        tenant = TenantService(db).create_tenant(payload.name, payload.slug, payload.settings)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    AuditService(db).log('tenant.create', 'tenant', tenant.id, actor=user, details={'slug': tenant.slug})
    return {'id': tenant.id, 'name': tenant.name, 'slug': tenant.slug}


@router.get('/tenants')
def list_tenants(_: object = Depends(require_permission('tenants:write')), db: Session = Depends(get_db)):
    return [{'id': t.id, 'name': t.name, 'slug': t.slug, 'is_active': t.is_active} for t in TenantService(db).list_tenants()]


@router.get('/audit/logs')
def list_audit_logs(limit: int = Query(100, le=500), user=Depends(require_permission('audit:read')), db: Session = Depends(get_db)):
    rows = AuditService(db).list_logs(limit=limit, tenant_id=user.tenant_id)
    return [{'id': row.id, 'created_at': row.created_at.isoformat(), 'action': row.action, 'resource_type': row.resource_type, 'resource_id': row.resource_id, 'actor_email': row.actor_email, 'outcome': row.outcome, 'details': json.loads(row.details_json or '{}')} for row in rows]


@router.post('/rules/versions')
def create_rule_version(payload: RuleVersionCreate, user=Depends(require_role('admin', 'analyst')), db: Session = Depends(get_db)):
    row = RuleRegistryService(db).create_version(payload.rule_id, payload.title, payload.level, payload.rule_yaml, tenant_id=user.tenant_id, notes=payload.notes)
    AuditService(db).log('rule.version.create', 'rule_definition', row.id, actor=user, details={'rule_id': row.rule_id, 'version': row.version})
    return {'id': row.id, 'rule_id': row.rule_id, 'version': row.version, 'status': row.status}


@router.post('/rules/{rule_id}/promote')
def promote_rule(rule_id: str, payload: RulePromoteRequest, user=Depends(require_role('admin', 'analyst')), db: Session = Depends(get_db)):
    try:
        row = RuleRegistryService(db).promote(rule_id, payload.version)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    AuditService(db).log('rule.promote', 'rule_definition', row.id, actor=user, details={'rule_id': rule_id, 'version': payload.version})
    return {'rule_id': row.rule_id, 'version': row.version, 'is_active': row.is_active}


@router.get('/rules/versions')
def list_rule_versions(_: object = Depends(get_current_user), db: Session = Depends(get_db)):
    return [{'id': row.id, 'tenant_id': row.tenant_id, 'rule_id': row.rule_id, 'title': row.title, 'version': row.version, 'level': row.level, 'status': row.status, 'is_active': row.is_active} for row in RuleRegistryService(db).list_rules()]


@router.post('/sso/providers')
def create_sso_provider(payload: SSOProviderCreate, user=Depends(require_role('admin')), db: Session = Depends(get_db)):
    row = SSOService(db).upsert_provider(payload.name, payload.protocol, payload.issuer, payload.client_id, payload.client_secret, payload.metadata, tenant_id=payload.tenant_id or user.tenant_id, enabled=payload.enabled)
    AuditService(db).log('sso.provider.upsert', 'sso_provider', row.id, actor=user, details={'provider': row.name})
    return {'id': row.id, 'name': row.name, 'protocol': row.protocol, 'issuer': row.issuer, 'enabled': row.is_enabled}


@router.get('/sso/providers')
def list_sso_providers(_: object = Depends(require_role('admin', 'analyst')), db: Session = Depends(get_db)):
    rows = SSOService(db).list_providers()
    return [{'id': row.id, 'name': row.name, 'protocol': row.protocol, 'issuer': row.issuer, 'tenant_id': row.tenant_id, 'enabled': row.is_enabled} for row in rows]


@router.get('/sso/{provider_name}/begin')
def begin_sso(provider_name: str, redirect_uri: str, db: Session = Depends(get_db)):
    try:
        return SSOService(db).begin_login(provider_name, redirect_uri)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.post('/sso/{provider_name}/complete')
def complete_sso(provider_name: str, payload: SSOCompleteRequest, db: Session = Depends(get_db)):
    try:
        return SSOService(db).complete_login(provider_name, payload.email, payload.full_name, payload.role)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.get('/hunt/noisy-sources')
def noisy_sources(_: object = Depends(get_current_user), db: Session = Depends(get_db)):
    return HuntService(db).top_noisy_sources(limit=10)


@router.websocket('/ws/alerts')
async def ws_alerts(websocket: WebSocket):
    await manager.connect('alerts', websocket)
    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        await manager.disconnect('alerts', websocket)


@router.websocket('/ws/incidents')
async def ws_incidents(websocket: WebSocket):
    await manager.connect('incidents', websocket)
    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        await manager.disconnect('incidents', websocket)
