from __future__ import annotations

import logging
import threading
from pathlib import Path

from scapy.all import rdpcap, sniff

from app.core.config import load_yaml_config
from app.services.packet_parser import packet_to_event

logger = logging.getLogger(__name__)


class SnifferService:
    def __init__(self):
        self._thread: threading.Thread | None = None
        self._stop_event = threading.Event()
        self._running = False

    @property
    def running(self) -> bool:
        return self._running

    def start_live(self, callback, iface: str | None = None) -> bool:
        if self._running:
            return False
        config = load_yaml_config().get("sniffer", {})
        bpf_filter = config.get("bpf_filter", "ip")
        interface = iface or config.get("default_interface")
        self._stop_event.clear()

        def _runner():
            self._running = True
            logger.info("Starting live sniffing on iface=%s filter=%s", interface, bpf_filter)
            try:
                sniff(
                    iface=interface,
                    filter=bpf_filter,
                    prn=lambda pkt: callback(packet_to_event(pkt)),
                    store=False,
                    stop_filter=lambda _: self._stop_event.is_set(),
                )
            finally:
                self._running = False
                logger.info("Sniffer stopped")

        self._thread = threading.Thread(target=_runner, daemon=True)
        self._thread.start()
        return True

    def stop_live(self) -> bool:
        if not self._running:
            return False
        self._stop_event.set()
        return True

    def analyze_pcap(self, path: str, callback) -> int:
        file_path = Path(path)
        if not file_path.exists():
            raise FileNotFoundError(path)
        count = 0
        for packet in rdpcap(str(file_path)):
            event = packet_to_event(packet)
            if event:
                callback(event)
                count += 1
        return count
