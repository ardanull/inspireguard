from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from time import time
from typing import Any


@dataclass
class PacketEvent:
    timestamp: float = field(default_factory=time)
    protocol: str = ""
    src_ip: str = ""
    dst_ip: str = ""
    src_port: int | None = None
    dst_port: int | None = None
    tcp_flags: str | None = None
    dns_query: str | None = None
    icmp_type: int | None = None
    length: int | None = None
    sensor: str | None = None
    event_source: str = "sensor"
    event_type: str = "network"
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class DetectorAlert:
    detector: str
    severity: str
    src_ip: str
    title: str
    description: str
    fingerprint: str
    dst_ip: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)


class BaseDetector(ABC):
    name = "base"

    def __init__(self, thresholds: dict[str, Any], cooldown_seconds: int = 20):
        self.thresholds = thresholds
        self.cooldown_seconds = cooldown_seconds
        self.last_alert_at: dict[str, float] = {}

    def can_emit(self, fingerprint: str, timestamp: float | None = None) -> bool:
        now = timestamp if timestamp is not None else time()
        previous = self.last_alert_at.get(fingerprint, 0.0)
        if now - previous >= self.cooldown_seconds:
            self.last_alert_at[fingerprint] = now
            return True
        return False

    @abstractmethod
    def process(self, event: PacketEvent) -> list[DetectorAlert]:
        raise NotImplementedError
