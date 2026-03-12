from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from time import time

from app.db.base import Base
from app.db.session import SessionLocal, engine
from app.detectors.base import PacketEvent
from app.services.ingest_service import IngestService

Base.metadata.create_all(bind=engine)

db = SessionLocal()
ingest = IngestService(db)
now = time()

# Port scan
for port in range(1, 25):
    ingest.handle_event(PacketEvent(timestamp=now + port * 0.1, protocol="TCP", src_ip="10.10.10.5", dst_ip="192.168.1.10", dst_port=port, tcp_flags="S"))

# SYN flood
for i in range(110):
    ingest.handle_event(PacketEvent(timestamp=now + i * 0.01, protocol="TCP", src_ip="172.16.0.8", dst_ip="192.168.1.15", dst_port=443, tcp_flags="S"))

# ICMP flood
for i in range(55):
    ingest.handle_event(PacketEvent(timestamp=now + i * 0.03, protocol="ICMP", src_ip="172.16.0.9", dst_ip="192.168.1.1", icmp_type=8))

# DNS exfiltration
for i in range(13):
    query = ("a" * 55) + f"{i}.corp.example.com"
    ingest.handle_event(PacketEvent(timestamp=now + i * 1.0, protocol="DNS", src_ip="10.20.30.40", dst_ip="8.8.8.8", dst_port=53, dns_query=query))

# Beaconing
for i in range(6):
    ingest.handle_event(PacketEvent(timestamp=now + i * 10, protocol="TCP", src_ip="192.168.50.15", dst_ip="104.26.1.10", dst_port=443, tcp_flags="PA"))

# Brute force
for i in range(14):
    ingest.handle_event(PacketEvent(timestamp=now + i * 0.5, protocol="TCP", src_ip="192.168.99.5", dst_ip="192.168.1.22", dst_port=22, tcp_flags="S"))

print("Demo alerts seeded successfully.")
db.close()
