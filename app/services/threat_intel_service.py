from __future__ import annotations

import json
from functools import lru_cache

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.config import load_yaml_config
from app.models.threat_indicator import ThreatIndicator


DEFAULT_FEED = [
    {
        "type": "ip",
        "value": "203.0.113.50",
        "severity": "high",
        "confidence": 90,
        "source": "curated_local",
        "description": "Known repeated scan origin in the lab feed.",
        "tags": ["scanner", "external"],
    },
    {
        "type": "ip",
        "value": "198.51.100.77",
        "severity": "critical",
        "confidence": 95,
        "source": "curated_local",
        "description": "High-confidence malicious control endpoint in the local feed.",
        "tags": ["c2", "high_risk"],
    },
]


@lru_cache(maxsize=1)
def _config_feed() -> list[dict]:
    config = load_yaml_config()
    return config.get("threat_intel", {}).get("seed_indicators", DEFAULT_FEED)


class ThreatIntelService:
    def __init__(self, db: Session):
        self.db = db

    def sync_defaults(self) -> int:
        created = 0
        for item in _config_feed():
            existing = self.db.scalar(select(ThreatIndicator).where(ThreatIndicator.value == item["value"]))
            if existing:
                continue
            self.db.add(
                ThreatIndicator(
                    type=item["type"],
                    value=item["value"],
                    severity=item.get("severity", "medium"),
                    confidence=item.get("confidence", 50),
                    source=item.get("source", "local_feed"),
                    description=item.get("description", ""),
                    tags_json=json.dumps(item.get("tags", [])),
                )
            )
            created += 1
        self.db.commit()
        return created

    def lookup_ip(self, ip_address: str | None) -> ThreatIndicator | None:
        if not ip_address:
            return None
        return self.db.scalar(select(ThreatIndicator).where(ThreatIndicator.type == "ip", ThreatIndicator.value == ip_address))

    def list_indicators(self, limit: int = 100) -> list[ThreatIndicator]:
        return list(self.db.scalars(select(ThreatIndicator).order_by(ThreatIndicator.confidence.desc()).limit(limit)))
