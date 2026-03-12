from __future__ import annotations
from datetime import datetime
from sqlalchemy import Boolean, DateTime, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column
from app.db.base import Base
class SSOProvider(Base):
    __tablename__ = 'sso_providers'
    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, index=True)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, index=True)
    tenant_id: Mapped[int | None] = mapped_column(Integer, nullable=True, index=True)
    name: Mapped[str] = mapped_column(String(120), unique=True, index=True)
    provider_type: Mapped[str] = mapped_column(String(40), default='oidc', index=True)
    issuer_url: Mapped[str] = mapped_column(String(255))
    client_id: Mapped[str] = mapped_column(String(255))
    client_secret: Mapped[str] = mapped_column(String(255))
    metadata_json: Mapped[str] = mapped_column(Text, default='{}')
    is_enabled: Mapped[bool] = mapped_column(Boolean, default=True, index=True)
