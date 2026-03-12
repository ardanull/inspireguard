from __future__ import annotations

from typing import Any

from pydantic import BaseModel


class AgentEnrollRequest(BaseModel):
    agent_id: str
    hostname: str
    ip_address: str | None = None
    version: str = "1.0.0"
    capabilities: list[str] = []
    labels: list[str] = []


class AgentHeartbeat(BaseModel):
    agent_id: str
    metrics: dict[str, Any] = {}


class IncidentCommentCreate(BaseModel):
    comment: str
