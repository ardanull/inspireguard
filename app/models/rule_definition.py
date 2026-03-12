from __future__ import annotations

from datetime import datetime

from sqlalchemy import Boolean, DateTime, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base


class RuleDefinition(Base):
    __tablename__ = "rule_definitions"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, index=True)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, index=True)
    tenant_id: Mapped[int | None] = mapped_column(Integer, nullable=True, index=True)
    rule_id: Mapped[str] = mapped_column(String(120), index=True)
    title: Mapped[str] = mapped_column(String(255))
    version: Mapped[int] = mapped_column(Integer, default=1, index=True)
    level: Mapped[str] = mapped_column(String(20), default='medium', index=True)
    status: Mapped[str] = mapped_column(String(20), default='draft', index=True)
    is_active: Mapped[bool] = mapped_column(Boolean, default=False, index=True)
    rule_yaml: Mapped[str] = mapped_column(Text)
    notes: Mapped[str] = mapped_column(Text, default='')
