from __future__ import annotations

import json
from pathlib import Path

from app.detectors.base import PacketEvent


def parse_zeek_json_lines(path: str) -> list[PacketEvent]:
    events: list[PacketEvent] = []
    for line in Path(path).read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        row = json.loads(line)
        events.append(
            PacketEvent(
                protocol=str(row.get("proto", "")).upper(),
                src_ip=row.get("id.orig_h", ""),
                dst_ip=row.get("id.resp_h", ""),
                src_port=row.get("id.orig_p"),
                dst_port=row.get("id.resp_p"),
                length=row.get("orig_bytes"),
                sensor=row.get("peer_descr"),
                event_source="zeek",
                event_type=row.get("service", "conn"),
                metadata={"conn_state": row.get("conn_state"), "history": row.get("history")},
            )
        )
    return events
