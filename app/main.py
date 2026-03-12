from __future__ import annotations
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
import app.models  # noqa: F401
from app.api.routes import router
from app.api.v5_routes import v5_router
from app.auth.service import AuthService
from app.core.config import get_settings
from app.core.logging import setup_logging
from app.db.base import Base
from app.db.session import SessionLocal, engine
from app.services.agent_service import AgentService
from app.services.alert_service import AlertService
from app.services.case_service import CaseService
from app.services.hunt_service import HuntService
from app.services.incident_service import IncidentService
from app.services.pki_service import PKIService
from app.services.sso_service import SSOService
from app.services.tenant_service import TenantService
from app.services.threat_intel_service import ThreatIntelService
from app.stream.manager import manager
settings = get_settings(); setup_logging(settings.log_level); Base.metadata.create_all(bind=engine)
app = FastAPI(title=settings.app_name, version='5.0.0', docs_url='/docs')
app.add_middleware(CORSMiddleware, allow_origins=['*'] if settings.cors_origins == '*' else settings.cors_origins.split(','), allow_credentials=True, allow_methods=['*'], allow_headers=['*'])
app.include_router(router); app.include_router(v5_router)
app.mount('/static', StaticFiles(directory='app/static'), name='static')
templates = Jinja2Templates(directory='app/templates')
@app.on_event('startup')
async def bootstrap_default_state():
    PKIService().ensure_ca(); await manager.start()
    db = SessionLocal()
    try:
        tenant = TenantService(db).ensure_default_tenant(); AuthService(db).ensure_default_admin(); ThreatIntelService(db).sync_defaults(); AgentService(db); SSOService(db); CaseService(db).upsert_sla_policy('critical', 5, 30, 120, tenant_id=tenant.id)
    finally:
        db.close()
@app.get('/', response_class=HTMLResponse, include_in_schema=False)
def home(request: Request):
    db = SessionLocal()
    try:
        alerts = AlertService(db); incidents = IncidentService(db); intel = ThreatIntelService(db); intel.sync_defaults(); cases = CaseService(db)
        return templates.TemplateResponse('dashboard.html', {'request': request, 'alerts': alerts.list_alerts(limit=20), 'metrics': {'alerts': alerts.metrics_summary(), 'incidents': incidents.incident_metrics(), 'noisy': HuntService(db).top_noisy_sources(limit=5), 'cases': len(cases.list_cases())}, 'incidents': incidents.list_incidents(limit=10), 'indicators': intel.list_indicators(limit=10), 'agents': AgentService(db).list_agents(), 'cases': cases.list_cases(), 'default_admin_email': settings.default_admin_email})
    finally:
        db.close()
