from __future__ import annotations

from datetime import datetime

from sqlalchemy import Boolean, DateTime, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base


class AgentNode(Base):
    __tablename__ = "agent_nodes"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, index=True)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    tenant_id: Mapped[int | None] = mapped_column(Integer, nullable=True, index=True)
    agent_id: Mapped[str] = mapped_column(String(120), unique=True, index=True)
    hostname: Mapped[str] = mapped_column(String(255), index=True)
    ip_address: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    version: Mapped[str] = mapped_column(String(40), default="1.0.0")
    status: Mapped[str] = mapped_column(String(30), default="online", index=True)
    capabilities_json: Mapped[str] = mapped_column(Text, default="[]")
    labels_json: Mapped[str] = mapped_column(Text, default="[]")
    policy_json: Mapped[str] = mapped_column(Text, default='{}')
    last_seen_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, index=True)
    enrollment_token: Mapped[str] = mapped_column(String(128), default="")
    is_approved: Mapped[bool] = mapped_column(Boolean, default=False, index=True)
