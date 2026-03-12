from __future__ import annotations

import logging

from sqlalchemy.orm import Session

from app.integrations.suricata.parser import parse_eve_json_lines
from app.integrations.zeek.parser import parse_zeek_json_lines
from app.schemas.alert import AlertCreate
from app.services.alert_service import AlertService
from app.services.asset_service import AssetService
from app.services.correlation_service import CorrelationService
from app.services.detection_service import DetectionService
from app.services.incident_service import IncidentService
from app.services.notification_service import NotificationService
from app.services.threat_intel_service import ThreatIntelService

logger = logging.getLogger(__name__)

SEVERITY_RANK = {'low': 1, 'medium': 2, 'high': 3, 'critical': 4}


class IngestService:
    def __init__(self, db: Session, tenant_id: int | None = None):
        self.db = db
        self.tenant_id = tenant_id
        self.detection = DetectionService()
        self.alerts = AlertService(db)
        self.assets = AssetService(db)
        self.incidents = IncidentService(db)
        self.correlation = CorrelationService(db)
        self.intel = ThreatIntelService(db)
        self.notify = NotificationService()
        self.intel.sync_defaults()

    def _enrich_metadata(self, alert, indicator, src_asset, dst_asset, event) -> dict:
        metadata = dict(alert.metadata)
        metadata['source_asset'] = src_asset.ip_address if src_asset else None
        metadata['destination_asset'] = dst_asset.ip_address if dst_asset else None
        metadata['sensor'] = getattr(event, 'sensor', None)
        metadata['event_source'] = getattr(event, 'event_source', None)
        metadata['event_type'] = getattr(event, 'event_type', None)
        metadata['raw_event'] = {
            'protocol': getattr(event, 'protocol', None),
            'src_ip': getattr(event, 'src_ip', None),
            'dst_ip': getattr(event, 'dst_ip', None),
            'src_port': getattr(event, 'src_port', None),
            'dst_port': getattr(event, 'dst_port', None),
            'metadata': getattr(event, 'metadata', {}),
        }
        if indicator:
            metadata['threat_intel'] = {'matched': True, 'indicator': indicator.value, 'severity': indicator.severity, 'confidence': indicator.confidence, 'source': indicator.source}
        return metadata

    def handle_event(self, event):
        emitted = []
        src_asset = self.assets.upsert_ip(getattr(event, 'src_ip', None))
        dst_asset = self.assets.upsert_ip(getattr(event, 'dst_ip', None))
        indicator = self.intel.lookup_ip(getattr(event, 'src_ip', None))
        for alert in self.detection.process(event):
            enriched_metadata = self._enrich_metadata(alert, indicator, src_asset, dst_asset, event)
            severity = alert.severity
            title = alert.title
            description = alert.description
            if indicator and SEVERITY_RANK.get(indicator.severity, 0) > SEVERITY_RANK.get(alert.severity, 0):
                severity = indicator.severity
                title = f'Threat Intel Match | {alert.title}'
                description = f'{alert.description} Matched local threat intel for {indicator.value}.'
            payload = AlertCreate(detector=alert.detector, severity=severity, src_ip=alert.src_ip, dst_ip=alert.dst_ip, title=title, description=description, fingerprint=alert.fingerprint, metadata=enriched_metadata)
            created = self.alerts.create_alert(payload, tenant_id=self.tenant_id)
            incident = self.incidents.correlate_alert(created)
            created.status = 'correlated'
            created.incident_id = incident.id
            self.db.commit()
            self.db.refresh(created)
            self.correlation.detector_burst(created.src_ip)
            emitted.append(created)
            self.notify.publish_alert({'type': 'alert.created', 'alert_id': created.id, 'severity': created.severity, 'detector': created.detector, 'src_ip': created.src_ip, 'incident_id': created.incident_id, 'title': created.title})
            logger.warning('%s | %s | %s', severity.upper(), alert.detector, description)
        return emitted

    def ingest_raw_event(self, payload: dict) -> list:
        from app.detectors.base import PacketEvent
        event = PacketEvent(**payload)
        return self.handle_event(event)

    def ingest_suricata_file(self, path: str) -> int:
        count = 0
        for event in parse_eve_json_lines(path):
            self.handle_event(event)
            count += 1
        return count

    def ingest_zeek_file(self, path: str) -> int:
        count = 0
        for event in parse_zeek_json_lines(path):
            self.handle_event(event)
            count += 1
        return count
