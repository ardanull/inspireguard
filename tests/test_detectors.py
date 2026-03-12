from app.detectors.base import PacketEvent
from app.detectors.network import (
    AuthBruteforceDetector,
    BeaconingDetector,
    DnsExfiltrationDetector,
    IcmpFloodDetector,
    PortScanDetector,
    SynFloodDetector,
)


def test_port_scan_detector_emits_alert():
    detector = PortScanDetector({"window_seconds": 10, "unique_ports_threshold": 5}, cooldown_seconds=0)
    alerts = []
    for idx, port in enumerate([21, 22, 23, 80, 443]):
        alerts.extend(detector.process(PacketEvent(timestamp=1.0 + idx, protocol="TCP", src_ip="1.1.1.1", dst_ip="2.2.2.2", dst_port=port, tcp_flags="S")))
    assert alerts
    assert alerts[-1].detector == "port_scan"


def test_syn_flood_detector_emits_alert():
    detector = SynFloodDetector({"window_seconds": 5, "packet_threshold": 3}, cooldown_seconds=0)
    alerts = []
    for i in range(3):
        alerts.extend(detector.process(PacketEvent(timestamp=1.0 + i, protocol="TCP", src_ip="1.1.1.1", dst_ip="2.2.2.2", dst_port=443, tcp_flags="S")))
    assert alerts


def test_icmp_flood_detector_emits_alert():
    detector = IcmpFloodDetector({"window_seconds": 5, "packet_threshold": 3}, cooldown_seconds=0)
    alerts = []
    for i in range(3):
        alerts.extend(detector.process(PacketEvent(timestamp=1.0 + i, protocol="ICMP", src_ip="1.1.1.1", dst_ip="2.2.2.2", icmp_type=8)))
    assert alerts


def test_dns_exfil_detector_emits_alert():
    detector = DnsExfiltrationDetector({"window_seconds": 30, "long_query_threshold": 3, "avg_query_length_threshold": 10}, cooldown_seconds=0)
    alerts = []
    for i in range(3):
        alerts.extend(detector.process(PacketEvent(timestamp=1.0 + i, protocol="DNS", src_ip="1.1.1.1", dst_ip="8.8.8.8", dns_query=("a" * 20) + str(i))))
    assert alerts


def test_beaconing_detector_emits_alert():
    detector = BeaconingDetector({"min_events": 5, "interval_tolerance_seconds": 0.5}, cooldown_seconds=0)
    alerts = []
    for i in range(5):
        alerts.extend(detector.process(PacketEvent(timestamp=10.0 * i, protocol="TCP", src_ip="1.1.1.1", dst_ip="2.2.2.2", dst_port=443, tcp_flags="PA")))
    assert alerts


def test_auth_bruteforce_detector_emits_alert():
    detector = AuthBruteforceDetector({"window_seconds": 30, "attempts_threshold": 3, "watched_ports": [22]}, cooldown_seconds=0)
    alerts = []
    for i in range(3):
        alerts.extend(detector.process(PacketEvent(timestamp=1.0 + i, protocol="TCP", src_ip="1.1.1.1", dst_ip="2.2.2.2", dst_port=22, tcp_flags="S")))
    assert alerts
