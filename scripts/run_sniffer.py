from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import argparse
import time

from app.db.base import Base
from app.db.session import SessionLocal, engine
from app.services.ingest_service import IngestService
from app.services.sniffer_service import SnifferService


def main():
    parser = argparse.ArgumentParser(description="Run SentinelGuard live sniffer")
    parser.add_argument("--iface", required=False, help="Network interface to sniff")
    args = parser.parse_args()

    Base.metadata.create_all(bind=engine)
    db = SessionLocal()
    ingest = IngestService(db)
    service = SnifferService()
    service.start_live(lambda event: None if event is None else ingest.handle_event(event), iface=args.iface)
    print("Sniffer running. Press Ctrl+C to stop.")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        service.stop_live()
    finally:
        db.close()


if __name__ == "__main__":
    main()
