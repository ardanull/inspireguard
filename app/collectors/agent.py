from __future__ import annotations

import os
import platform
import socket
import time
import uuid
from typing import Any

import requests


class SentinelAgent:
    def __init__(self, server_url: str, agent_id: str | None = None):
        self.server_url = server_url.rstrip("/")
        self.agent_id = agent_id or os.getenv("SENTINEL_AGENT_ID") or f"agent-{uuid.uuid4().hex[:12]}"
        self.hostname = socket.gethostname()

    def enroll(self) -> dict[str, Any]:
        payload = {
            "agent_id": self.agent_id,
            "hostname": self.hostname,
            "ip_address": socket.gethostbyname(self.hostname),
            "version": "3.0.0",
            "capabilities": ["heartbeat", "json-event-forward", "pcap-capture"],
            "labels": [platform.system().lower(), platform.machine().lower()],
        }
        return requests.post(f"{self.server_url}/api/v1/agents/enroll", json=payload, timeout=10).json()

    def heartbeat(self) -> dict[str, Any]:
        payload = {"agent_id": self.agent_id, "metrics": {"time": time.time()}}
        return requests.post(f"{self.server_url}/api/v1/agents/heartbeat", json=payload, timeout=10).json()

    def submit_event(self, event: dict[str, Any]) -> dict[str, Any]:
        return requests.post(f"{self.server_url}/api/v1/events", json=event, timeout=10).json()
