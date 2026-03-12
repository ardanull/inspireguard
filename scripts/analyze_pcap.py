from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import argparse

from app.db.base import Base
from app.db.session import SessionLocal, engine
from app.services.ingest_service import IngestService
from app.services.sniffer_service import SnifferService


def main():
    parser = argparse.ArgumentParser(description="Analyze a PCAP with SentinelGuard")
    parser.add_argument("--pcap", required=True, help="Path to PCAP file")
    args = parser.parse_args()

    Base.metadata.create_all(bind=engine)
    db = SessionLocal()
    ingest = IngestService(db)
    service = SnifferService()
    count = service.analyze_pcap(args.pcap, lambda event: None if event is None else ingest.handle_event(event))
    print(f"Processed packets: {count}")
    db.close()


if __name__ == "__main__":
    main()
