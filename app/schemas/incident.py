from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, ConfigDict


class IncidentRead(BaseModel):
    id: int
    created_at: datetime
    updated_at: datetime
    status: str
    severity: str
    title: str
    summary: str
    source_key: str
    src_ip: str | None = None
    alert_count: int
    first_seen_at: datetime
    last_seen_at: datetime
    tags: list[str] = []

    model_config = ConfigDict(from_attributes=True)
