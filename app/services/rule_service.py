from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

from app.detectors.base import DetectorAlert, PacketEvent


class SigmaLikeRuleEngine:
    def __init__(self, rules_dir: str = "rules"):
        self.rules_dir = Path(rules_dir)
        self.rules = self._load_rules()

    def _load_rules(self) -> list[dict[str, Any]]:
        if not self.rules_dir.exists():
            return []
        rules = []
        for path in sorted(self.rules_dir.glob("*.yml")) + sorted(self.rules_dir.glob("*.yaml")):
            with path.open("r", encoding="utf-8") as f:
                content = yaml.safe_load(f) or {}
                if content:
                    rules.append(content)
        return rules

    def _matches(self, event: PacketEvent, detection: dict[str, Any]) -> bool:
        for field_name, expected in detection.items():
            value = getattr(event, field_name, None)
            if isinstance(expected, list):
                if value not in expected:
                    return False
            elif isinstance(expected, dict):
                op = expected.get("op")
                target = expected.get("value")
                if op == "contains":
                    if value is None or str(target) not in str(value):
                        return False
                elif op == "gte":
                    if value is None or value < target:
                        return False
                else:
                    return False
            else:
                if value != expected:
                    return False
        return True

    def evaluate(self, event: PacketEvent) -> list[DetectorAlert]:
        results: list[DetectorAlert] = []
        for rule in self.rules:
            if self._matches(event, rule.get("detection", {})):
                fingerprint = f"sigma:{rule.get('id','rule')}:{event.src_ip}:{event.dst_ip}:{event.dst_port}"
                results.append(
                    DetectorAlert(
                        detector=f"sigma_{rule.get('id', 'rule')}",
                        severity=rule.get("level", "medium"),
                        src_ip=event.src_ip,
                        dst_ip=event.dst_ip,
                        title=rule.get("title", "Sigma-like rule match"),
                        description=rule.get("description", "Rule matched incoming event."),
                        fingerprint=fingerprint,
                        metadata={"rule_id": rule.get("id"), "tags": rule.get("tags", [])},
                    )
                )
        return results
