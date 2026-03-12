from __future__ import annotations

import logging
from typing import Iterable

from app.core.config import load_yaml_config
from app.detectors.base import DetectorAlert, PacketEvent
from app.detectors.network import (
    AuthBruteforceDetector,
    BeaconingDetector,
    DnsExfiltrationDetector,
    IcmpFloodDetector,
    PortScanDetector,
    SynFloodDetector,
)
from app.services.rule_service import SigmaLikeRuleEngine

logger = logging.getLogger(__name__)


class DetectionService:
    def __init__(self):
        config = load_yaml_config()
        thresholds = config.get("thresholds", {})
        cooldown = config.get("app", {}).get("alert_cooldown_seconds", 20)
        self.detectors = [
            PortScanDetector(thresholds.get("port_scan", {"window_seconds": 10, "unique_ports_threshold": 20}), cooldown),
            SynFloodDetector(thresholds.get("syn_flood", {"window_seconds": 5, "packet_threshold": 100}), cooldown),
            IcmpFloodDetector(thresholds.get("icmp_flood", {"window_seconds": 5, "packet_threshold": 50}), cooldown),
            DnsExfiltrationDetector(thresholds.get("dns_exfiltration", {"window_seconds": 30, "long_query_threshold": 12, "avg_query_length_threshold": 45}), cooldown),
            BeaconingDetector(thresholds.get("beaconing", {"min_events": 5, "interval_tolerance_seconds": 1.5}), cooldown),
            AuthBruteforceDetector(thresholds.get("auth_bruteforce", {"window_seconds": 30, "attempts_threshold": 12, "watched_ports": [22, 3389]}), cooldown),
        ]
        self.rule_engine = SigmaLikeRuleEngine()

    def process(self, event: PacketEvent) -> list[DetectorAlert]:
        alerts: list[DetectorAlert] = []
        for detector in self.detectors:
            try:
                alerts.extend(detector.process(event))
            except Exception as exc:
                logger.exception("Detector %s failed: %s", detector.name, exc)
        alerts.extend(self.rule_engine.evaluate(event))
        return alerts

    def process_many(self, events: Iterable[PacketEvent]) -> list[DetectorAlert]:
        results: list[DetectorAlert] = []
        for event in events:
            results.extend(self.process(event))
        return results
