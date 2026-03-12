from __future__ import annotations
from pydantic import BaseModel, Field
class CaseCreate(BaseModel):
    incident_id: int | None = None
    title: str
    priority: str = 'medium'
    assignee_user_id: int | None = None
    notes: str = ''
class EvidenceCreate(BaseModel):
    case_id: int | None = None
    filename: str
    content_type: str = 'application/octet-stream'
    content_b64: str
class SLAPolicyCreate(BaseModel):
    severity: str
    acknowledge_minutes: int = Field(ge=1)
    contain_minutes: int = Field(ge=1)
    resolve_minutes: int = Field(ge=1)
class SigmaSimulationRequest(BaseModel):
    rule_yaml: str
    events: list[dict]
class OIDCProviderCreate(BaseModel):
    name: str
    issuer: str
    client_id: str
    client_secret: str
    authorize_url: str
    token_url: str
    userinfo_url: str
class SAMLProviderCreate(BaseModel):
    name: str
    entity_id: str
    sso_url: str
    x509_cert: str
