from __future__ import annotations
from datetime import datetime
from sqlalchemy import DateTime, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column
from app.db.base import Base
class Case(Base):
    __tablename__ = 'cases'
    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, index=True)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, index=True)
    tenant_id: Mapped[int | None] = mapped_column(Integer, nullable=True, index=True)
    incident_id: Mapped[int | None] = mapped_column(Integer, nullable=True, index=True)
    title: Mapped[str] = mapped_column(String(200), index=True)
    status: Mapped[str] = mapped_column(String(40), default='open', index=True)
    priority: Mapped[str] = mapped_column(String(20), default='medium', index=True)
    assignee_user_id: Mapped[int | None] = mapped_column(Integer, nullable=True, index=True)
    playbook_json: Mapped[str] = mapped_column(Text, default='[]')
    notes: Mapped[str] = mapped_column(Text, default='')
