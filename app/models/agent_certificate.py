from __future__ import annotations

from datetime import datetime

from sqlalchemy import Boolean, DateTime, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base


class AgentCertificate(Base):
    __tablename__ = "agent_certificates"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, index=True)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, index=True)
    tenant_id: Mapped[int | None] = mapped_column(Integer, nullable=True, index=True)
    agent_id: Mapped[str] = mapped_column(String(120), index=True)
    serial_number: Mapped[str] = mapped_column(String(120), unique=True, index=True)
    fingerprint_sha256: Mapped[str] = mapped_column(String(128), unique=True, index=True)
    certificate_pem: Mapped[str] = mapped_column(Text)
    private_key_pem: Mapped[str] = mapped_column(Text)
    issued_by: Mapped[str] = mapped_column(String(120), default='SentinelGuard Local CA')
    expires_at: Mapped[datetime] = mapped_column(DateTime, index=True)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True, index=True)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, index=True)
