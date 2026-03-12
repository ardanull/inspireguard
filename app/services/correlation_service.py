from __future__ import annotations

import json
from collections import Counter, defaultdict
from datetime import datetime, timedelta

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.alert import Alert
from app.models.incident import Incident


class CorrelationService:
    def __init__(self, db: Session):
        self.db = db

    def detector_burst(self, src_ip: str, lookback_minutes: int = 10, threshold: int = 3) -> Incident | None:
        since = datetime.utcnow() - timedelta(minutes=lookback_minutes)
        alerts = list(self.db.scalars(select(Alert).where(Alert.src_ip == src_ip, Alert.created_at >= since).order_by(Alert.created_at.desc())))
        detectors = Counter(a.detector for a in alerts)
        if len(detectors) < threshold:
            return None
        existing = self.db.scalar(select(Incident).where(Incident.source_key == f'correlation:{src_ip}:burst'))
        summary = f'Multiple detector burst observed from {src_ip}: {dict(detectors)}'
        if existing:
            existing.summary = summary
            existing.alert_count = len(alerts)
            existing.last_seen_at = datetime.utcnow()
            existing.tags_json = json.dumps(sorted(set(json.loads(existing.tags_json or '[]')) | {'multi-stage', 'correlated'}))
            self.db.commit()
            self.db.refresh(existing)
            return existing
        incident = Incident(
            tenant_id=alerts[0].tenant_id if alerts else None,
            severity='critical' if len(detectors) >= 4 else 'high',
            title=f'Multi-stage activity from {src_ip}',
            summary=summary,
            source_key=f'correlation:{src_ip}:burst',
            src_ip=src_ip,
            alert_count=len(alerts),
            first_seen_at=alerts[-1].created_at if alerts else datetime.utcnow(),
            last_seen_at=datetime.utcnow(),
            tags_json=json.dumps(['multi-stage', 'correlated']),
            runbook_json=json.dumps(['Validate scope', 'Check lateral movement', 'Escalate to incident commander', 'Contain source host']),
        )
        self.db.add(incident)
        self.db.commit()
        self.db.refresh(incident)
        return incident
