from pydantic import BaseModel


class SSOProviderCreate(BaseModel):
    name: str
    protocol: str = 'oidc'
    issuer: str
    client_id: str
    client_secret: str
    metadata: dict = {}
    tenant_id: int | None = None
    enabled: bool = True


class SSOCompleteRequest(BaseModel):
    email: str
    full_name: str
    role: str = 'viewer'
