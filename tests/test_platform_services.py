from __future__ import annotations

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

import app.models  # noqa: F401
from app.db.base import Base
from app.detectors.base import PacketEvent
from app.services.ingest_service import IngestService
from app.services.incident_service import IncidentService
from app.services.threat_intel_service import ThreatIntelService


def make_db():
    engine = create_engine("sqlite:///:memory:", future=True)
    TestingSessionLocal = sessionmaker(bind=engine, autocommit=False, autoflush=False, future=True)
    Base.metadata.create_all(bind=engine)
    return TestingSessionLocal()


def test_threat_intel_match_escalates_alert():
    db = make_db()
    ingest = IngestService(db)
    for port in range(1, 25):
        ingest.handle_event(PacketEvent(protocol="TCP", src_ip="203.0.113.50", dst_ip="10.0.0.10", dst_port=port, tcp_flags="S", timestamp=100 + port * 0.1))

    alerts = ingest.alerts.list_alerts(limit=10)
    assert alerts
    assert alerts[0].severity in {"high", "critical"}
    assert alerts[0].incident_id is not None


def test_incident_correlation_groups_repeated_alerts():
    db = make_db()
    ingest = IngestService(db)
    now = 1000.0
    for i in range(25):
        ingest.handle_event(PacketEvent(protocol="TCP", src_ip="10.0.0.99", dst_ip="10.0.0.10", dst_port=i + 1, tcp_flags="S", timestamp=now + i * 0.1))
    for i in range(25):
        ingest.handle_event(PacketEvent(protocol="TCP", src_ip="10.0.0.99", dst_ip="10.0.0.20", dst_port=i + 200, tcp_flags="S", timestamp=now + 30 + i * 0.1))

    incidents = IncidentService(db).list_incidents(limit=10)
    assert len(incidents) == 1
    assert incidents[0].alert_count >= 2


def test_threat_intel_defaults_seeded():
    db = make_db()
    intel = ThreatIntelService(db)
    created = intel.sync_defaults()
    assert created >= 0
    assert intel.lookup_ip("198.51.100.77") is not None
