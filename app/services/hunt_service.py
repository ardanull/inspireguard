from __future__ import annotations

from sqlalchemy import desc, func, select
from sqlalchemy.orm import Session

from app.models.alert import Alert


class HuntService:
    def __init__(self, db: Session):
        self.db = db

    def top_noisy_sources(self, limit: int = 10) -> list[dict]:
        rows = self.db.execute(
            select(Alert.src_ip, func.count(Alert.id).label("count"))
            .group_by(Alert.src_ip)
            .order_by(desc(func.count(Alert.id)))
            .limit(limit)
        ).all()
        return [{"src_ip": src, "alert_count": count} for src, count in rows]

    def detector_matrix(self) -> list[dict]:
        rows = self.db.execute(
            select(Alert.detector, Alert.severity, func.count(Alert.id))
            .group_by(Alert.detector, Alert.severity)
            .order_by(Alert.detector)
        ).all()
        return [{"detector": d, "severity": s, "count": c} for d, s, c in rows]
