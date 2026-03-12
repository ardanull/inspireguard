from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict


class AlertBase(BaseModel):
    detector: str
    severity: str
    src_ip: str
    dst_ip: str | None = None
    title: str
    description: str
    fingerprint: str
    metadata: dict[str, Any] = {}


class AlertCreate(AlertBase):
    pass


class AlertRead(AlertBase):
    id: int
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)
