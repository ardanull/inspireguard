from __future__ import annotations
from datetime import datetime, timedelta
from sqlalchemy import select
from sqlalchemy.orm import Session
from app.models.agent_certificate import AgentCertificate
from app.services.pki_service import PKIService
class CertificateService:
    def __init__(self, db: Session):
        self.db = db
        self.pki = PKIService()
    def issue(self, agent_id: str, tenant_id: int | None = None, validity_days: int = 90) -> AgentCertificate:
        serial, fingerprint, cert_pem, key_pem, ca_pem = self.pki.issue_agent_certificate(agent_id, validity_days)
        row = AgentCertificate(tenant_id=tenant_id, agent_id=agent_id, serial_number=serial, fingerprint_sha256=fingerprint, certificate_pem=cert_pem, private_key_pem=key_pem, issued_by='SentinelGuard Enterprise Root CA', expires_at=datetime.utcnow() + timedelta(days=validity_days), is_active=True)
        self.db.add(row)
        self.db.commit()
        self.db.refresh(row)
        row.ca_bundle_pem = ca_pem
        return row
    def revoke(self, fingerprint: str) -> AgentCertificate | None:
        row = self.db.scalar(select(AgentCertificate).where(AgentCertificate.fingerprint_sha256 == fingerprint, AgentCertificate.is_active.is_(True)))
        if row is None:
            return None
        row.is_active = False
        row.revoked_at = datetime.utcnow()
        self.db.commit()
        self.db.refresh(row)
        return row
    def truststore(self, tenant_id: int | None = None):
        stmt = select(AgentCertificate).where(AgentCertificate.is_active.is_(True))
        if tenant_id is not None:
            stmt = stmt.where(AgentCertificate.tenant_id == tenant_id)
        return list(self.db.scalars(stmt))
