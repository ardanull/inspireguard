from __future__ import annotations

import json
from collections import Counter
from datetime import datetime, timedelta

from sqlalchemy import desc, func, select
from sqlalchemy.orm import Session

from app.models.alert import Alert
from app.models.incident import Incident
from app.models.incident_comment import IncidentComment
from app.services.notification_service import NotificationService

SEVERITY_RANK = {'low': 1, 'medium': 2, 'high': 3, 'critical': 4}
RUNBOOKS = {
    'port_scan': ['Validate source asset', 'Review firewall logs', 'Block source if malicious', 'Document findings'],
    'syn_flood': ['Check edge protections', 'Assess service health', 'Enable rate limits', 'Open incident bridge'],
}


class IncidentService:
    def __init__(self, db: Session):
        self.db = db
        self.notify = NotificationService()

    def correlate_alert(self, alert: Alert) -> Incident:
        source_key = f'{alert.src_ip}:{alert.detector}'
        incident = self.db.scalar(select(Incident).where(Incident.source_key == source_key))
        if incident is None and alert.src_ip:
            incident = self.db.scalar(select(Incident).where(Incident.src_ip == alert.src_ip, Incident.status == 'open').order_by(Incident.updated_at.desc()))
        now = datetime.utcnow()
        created = False
        if incident is None:
            incident = Incident(
                tenant_id=alert.tenant_id,
                severity=alert.severity,
                title=f"{alert.detector.replace('_', ' ').title()} activity from {alert.src_ip}",
                summary=alert.description,
                source_key=source_key,
                src_ip=alert.src_ip,
                alert_count=1,
                first_seen_at=now,
                last_seen_at=now,
                tags_json=json.dumps([alert.detector, alert.severity]),
                runbook_json=json.dumps(RUNBOOKS.get(alert.detector, ['Assess context', 'Assign analyst', 'Contain if needed', 'Close with notes'])),
            )
            self.db.add(incident)
            self.db.flush()
            created = True
        else:
            incident.alert_count += 1
            incident.last_seen_at = now
            incident.summary = alert.description
            if SEVERITY_RANK.get(alert.severity, 0) > SEVERITY_RANK.get(incident.severity, 0):
                incident.severity = alert.severity
            current_tags = set(json.loads(incident.tags_json or '[]'))
            current_tags.update([alert.detector, alert.severity])
            incident.tags_json = json.dumps(sorted(current_tags))
        alert.incident_id = incident.id
        self.db.commit()
        self.db.refresh(incident)
        event_type = 'incident.created' if created else 'incident.updated'
        self.notify.publish_incident({'type': event_type, 'incident_id': incident.id, 'severity': incident.severity, 'src_ip': incident.src_ip, 'title': incident.title, 'triage_status': incident.triage_status})
        return incident

    def list_incidents(self, limit: int = 100, status: str | None = None, tenant_id: int | None = None) -> list[Incident]:
        stmt = select(Incident).order_by(desc(Incident.updated_at)).limit(limit)
        if tenant_id is not None:
            stmt = stmt.where(Incident.tenant_id == tenant_id)
        if status:
            stmt = stmt.where(Incident.status == status)
        return list(self.db.scalars(stmt))

    def get_incident(self, incident_id: int) -> Incident | None:
        return self.db.get(Incident, incident_id)

    def update_triage(self, incident_id: int, triage_status: str, assigned_user_id: int | None = None) -> Incident:
        incident = self.db.get(Incident, incident_id)
        if incident is None:
            raise ValueError('Incident not found')
        incident.triage_status = triage_status
        if assigned_user_id is not None:
            incident.assigned_user_id = assigned_user_id
        self.db.commit()
        self.db.refresh(incident)
        self.notify.publish_incident({'type': 'incident.triage', 'incident_id': incident.id, 'triage_status': incident.triage_status, 'assigned_user_id': incident.assigned_user_id})
        return incident

    def add_comment(self, incident_id: int, author_user_id: int, comment: str) -> IncidentComment:
        row = IncidentComment(incident_id=incident_id, author_user_id=author_user_id, comment=comment)
        self.db.add(row)
        self.db.commit()
        self.db.refresh(row)
        return row

    def list_comments(self, incident_id: int) -> list[IncidentComment]:
        return list(self.db.scalars(select(IncidentComment).where(IncidentComment.incident_id == incident_id).order_by(IncidentComment.created_at.desc())))

    def incident_metrics(self, tenant_id: int | None = None) -> dict:
        open_stmt = select(func.count(Incident.id)).where(Incident.status == 'open')
        if tenant_id is not None:
            open_stmt = open_stmt.where(Incident.tenant_id == tenant_id)
        open_count = self.db.scalar(open_stmt) or 0
        since = datetime.utcnow() - timedelta(hours=24)
        last_stmt = select(func.count(Incident.id)).where(Incident.created_at >= since)
        sev_stmt = select(Incident.severity, func.count(Incident.id)).group_by(Incident.severity)
        triage_stmt = select(Incident.triage_status, func.count(Incident.id)).group_by(Incident.triage_status)
        if tenant_id is not None:
            last_stmt = last_stmt.where(Incident.tenant_id == tenant_id)
            sev_stmt = sev_stmt.where(Incident.tenant_id == tenant_id)
            triage_stmt = triage_stmt.where(Incident.tenant_id == tenant_id)
        last_24h = self.db.scalar(last_stmt) or 0
        by_severity = Counter(dict(self.db.execute(sev_stmt).all()))
        by_triage = Counter(dict(self.db.execute(triage_stmt).all()))
        return {'open_incidents': open_count, 'incidents_last_24h': last_24h, 'by_severity': dict(by_severity), 'by_triage': dict(by_triage)}
