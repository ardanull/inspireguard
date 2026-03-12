from __future__ import annotations

import json
from collections import Counter
from datetime import datetime, timedelta

from sqlalchemy import desc, func, select
from sqlalchemy.orm import Session

from app.models.alert import Alert
from app.schemas.alert import AlertCreate


class AlertService:
    def __init__(self, db: Session):
        self.db = db

    def create_alert(self, payload: AlertCreate, tenant_id: int | None = None) -> Alert:
        model = Alert(
            tenant_id=tenant_id,
            detector=payload.detector,
            severity=payload.severity,
            status='new',
            src_ip=payload.src_ip,
            dst_ip=payload.dst_ip,
            title=payload.title,
            description=payload.description,
            fingerprint=payload.fingerprint,
            metadata_json=json.dumps(payload.metadata, ensure_ascii=False),
            sensor_id=payload.metadata.get('sensor') if payload.metadata else None,
            raw_event_json=json.dumps(payload.metadata.get('raw_event', {}), ensure_ascii=False) if payload.metadata else '{}',
        )
        self.db.add(model)
        self.db.commit()
        self.db.refresh(model)
        return model

    def list_alerts(self, limit: int = 100, severity: str | None = None, detector: str | None = None, tenant_id: int | None = None) -> list[Alert]:
        stmt = select(Alert).order_by(desc(Alert.created_at)).limit(limit)
        if tenant_id is not None:
            stmt = stmt.where(Alert.tenant_id == tenant_id)
        if severity:
            stmt = stmt.where(Alert.severity == severity)
        if detector:
            stmt = stmt.where(Alert.detector == detector)
        return list(self.db.scalars(stmt))

    def get_alert(self, alert_id: int) -> Alert | None:
        return self.db.get(Alert, alert_id)

    def metrics_summary(self, tenant_id: int | None = None) -> dict:
        base = select(Alert)
        total_stmt = select(func.count(Alert.id))
        if tenant_id is not None:
            total_stmt = total_stmt.where(Alert.tenant_id == tenant_id)
        total = self.db.scalar(total_stmt) or 0
        severity_stmt = select(Alert.severity, func.count(Alert.id)).group_by(Alert.severity)
        detector_stmt = select(Alert.detector, func.count(Alert.id)).group_by(Alert.detector)
        status_stmt = select(Alert.status, func.count(Alert.id)).group_by(Alert.status)
        top_stmt = select(Alert.src_ip, func.count(Alert.id)).group_by(Alert.src_ip).order_by(desc(func.count(Alert.id))).limit(5)
        corr_stmt = select(func.count(Alert.id)).where(Alert.incident_id.is_not(None))
        if tenant_id is not None:
            severity_stmt = severity_stmt.where(Alert.tenant_id == tenant_id)
            detector_stmt = detector_stmt.where(Alert.tenant_id == tenant_id)
            status_stmt = status_stmt.where(Alert.tenant_id == tenant_id)
            top_stmt = top_stmt.where(Alert.tenant_id == tenant_id)
            corr_stmt = corr_stmt.where(Alert.tenant_id == tenant_id)
        by_severity = Counter(dict(self.db.execute(severity_stmt).all()))
        by_detector = Counter(dict(self.db.execute(detector_stmt).all()))
        by_status = Counter(dict(self.db.execute(status_stmt).all()))
        since = datetime.utcnow() - timedelta(hours=24)
        last_stmt = select(func.count(Alert.id)).where(Alert.created_at >= since)
        if tenant_id is not None:
            last_stmt = last_stmt.where(Alert.tenant_id == tenant_id)
        last_24h = self.db.scalar(last_stmt) or 0
        top_sources = self.db.execute(top_stmt).all()
        correlated = self.db.scalar(corr_stmt) or 0
        return {'total_alerts': total, 'alerts_last_24h': last_24h, 'correlated_alerts': correlated, 'by_severity': dict(by_severity), 'by_detector': dict(by_detector), 'by_status': dict(by_status), 'top_sources': [{'src_ip': src_ip, 'count': count} for src_ip, count in top_sources]}
