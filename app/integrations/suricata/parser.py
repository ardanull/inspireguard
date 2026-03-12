from __future__ import annotations

import json
from pathlib import Path

from app.detectors.base import PacketEvent


def parse_eve_json_lines(path: str) -> list[PacketEvent]:
    events: list[PacketEvent] = []
    for line in Path(path).read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        row = json.loads(line)
        proto = str(row.get("proto", "")).upper()
        alert = row.get("alert", {})
        events.append(
            PacketEvent(
                protocol=proto or "SURICATA",
                src_ip=row.get("src_ip", ""),
                dst_ip=row.get("dest_ip", ""),
                src_port=row.get("src_port"),
                dst_port=row.get("dest_port"),
                length=row.get("payload_printable") and len(row.get("payload_printable")) or row.get("pkt_len"),
                sensor=row.get("host"),
                event_source="suricata",
                event_type=alert.get("category") or row.get("event_type", "alert"),
                metadata={"signature": alert.get("signature"), "severity": alert.get("severity")},
            )
        )
    return events
