from __future__ import annotations
from datetime import datetime
from sqlalchemy import DateTime, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column
from app.db.base import Base
class Evidence(Base):
    __tablename__ = 'evidence'
    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, index=True)
    tenant_id: Mapped[int | None] = mapped_column(Integer, nullable=True, index=True)
    case_id: Mapped[int | None] = mapped_column(Integer, nullable=True, index=True)
    filename: Mapped[str] = mapped_column(String(255))
    content_type: Mapped[str] = mapped_column(String(120), default='application/octet-stream')
    sha256: Mapped[str] = mapped_column(String(128), unique=True, index=True)
    storage_path: Mapped[str] = mapped_column(Text)
    chain_of_custody_json: Mapped[str] = mapped_column(Text, default='[]')
