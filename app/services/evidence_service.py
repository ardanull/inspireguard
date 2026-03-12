from __future__ import annotations
import base64, hashlib, json
from datetime import datetime
from pathlib import Path
from sqlalchemy import select
from sqlalchemy.orm import Session
from app.core.config import get_settings
from app.models.evidence import Evidence
class EvidenceService:
    def __init__(self, db: Session):
        self.db = db
        self.base_dir = Path(get_settings().evidence_dir)
        self.base_dir.mkdir(parents=True, exist_ok=True)
    def store_b64(self, filename: str, content_b64: str, content_type: str = 'application/octet-stream', case_id: int | None = None, tenant_id: int | None = None, actor_email: str | None = None):
        payload = base64.b64decode(content_b64.encode('utf-8'))
        sha = hashlib.sha256(payload).hexdigest()
        path = self.base_dir / sha[:2] / sha
        path.parent.mkdir(parents=True, exist_ok=True)
        if not path.exists():
            path.write_bytes(payload)
        existing = self.db.scalar(select(Evidence).where(Evidence.sha256 == sha))
        if existing:
            return existing
        chain = [{'ts': datetime.utcnow().isoformat(), 'action': 'stored', 'actor': actor_email or 'system'}]
        row = Evidence(tenant_id=tenant_id, case_id=case_id, filename=filename, content_type=content_type, sha256=sha, storage_path=str(path), chain_of_custody_json=json.dumps(chain))
        self.db.add(row)
        self.db.commit()
        self.db.refresh(row)
        return row
    def list_evidence(self, case_id: int | None = None, tenant_id: int | None = None):
        stmt = select(Evidence)
        if case_id is not None:
            stmt = stmt.where(Evidence.case_id == case_id)
        if tenant_id is not None:
            stmt = stmt.where(Evidence.tenant_id == tenant_id)
        return list(self.db.scalars(stmt.order_by(Evidence.created_at.desc())))
