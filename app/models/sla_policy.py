from __future__ import annotations
from datetime import datetime
from sqlalchemy import Boolean, DateTime, Integer, String
from sqlalchemy.orm import Mapped, mapped_column
from app.db.base import Base
class SLAPolicy(Base):
    __tablename__ = 'sla_policies'
    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, index=True)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, index=True)
    tenant_id: Mapped[int | None] = mapped_column(Integer, nullable=True, index=True)
    severity: Mapped[str] = mapped_column(String(20), index=True)
    acknowledge_minutes: Mapped[int] = mapped_column(Integer, default=15)
    contain_minutes: Mapped[int] = mapped_column(Integer, default=60)
    resolve_minutes: Mapped[int] = mapped_column(Integer, default=240)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, index=True)
