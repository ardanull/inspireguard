from __future__ import annotations

from datetime import datetime

from sqlalchemy import DateTime, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base


class ThreatIndicator(Base):
    __tablename__ = "threat_indicators"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, index=True)
    tenant_id: Mapped[int | None] = mapped_column(Integer, nullable=True, index=True)
    type: Mapped[str] = mapped_column(String(30), index=True)
    value: Mapped[str] = mapped_column(String(255), unique=True, index=True)
    severity: Mapped[str] = mapped_column(String(20), default="medium", index=True)
    confidence: Mapped[int] = mapped_column(Integer, default=50)
    source: Mapped[str] = mapped_column(String(100), default="local_feed")
    description: Mapped[str] = mapped_column(Text, default="")
    tags_json: Mapped[str] = mapped_column(Text, default="[]")
