from __future__ import annotations

from collections import defaultdict
from statistics import mean

from app.detectors.base import BaseDetector, DetectorAlert, PacketEvent
from app.utils.time_window import SlidingWindow


class PortScanDetector(BaseDetector):
    name = "port_scan"

    def __init__(self, thresholds: dict, cooldown_seconds: int = 20):
        super().__init__(thresholds, cooldown_seconds)
        window = thresholds["window_seconds"]
        self.history = defaultdict(lambda: SlidingWindow(window))
        self.unique_ports_threshold = thresholds["unique_ports_threshold"]

    def process(self, event: PacketEvent) -> list[DetectorAlert]:
        if event.protocol != "TCP" or event.dst_port is None or not event.src_ip:
            return []
        bucket = self.history[event.src_ip]
        bucket.add(event.dst_port, event.timestamp)
        unique_ports = sorted(set(bucket.values()))
        if len(unique_ports) < self.unique_ports_threshold:
            return []
        fingerprint = f"{self.name}:{event.src_ip}"
        if not self.can_emit(fingerprint, event.timestamp):
            return []
        return [
            DetectorAlert(
                detector=self.name,
                severity="high",
                src_ip=event.src_ip,
                dst_ip=event.dst_ip,
                title="Port scan suspected",
                description=f"Host contacted {len(unique_ports)} unique destination ports within the configured window.",
                fingerprint=fingerprint,
                metadata={"unique_ports": unique_ports[:100], "count": len(unique_ports)},
            )
        ]


class SynFloodDetector(BaseDetector):
    name = "syn_flood"

    def __init__(self, thresholds: dict, cooldown_seconds: int = 20):
        super().__init__(thresholds, cooldown_seconds)
        self.history = defaultdict(lambda: SlidingWindow(thresholds["window_seconds"]))
        self.packet_threshold = thresholds["packet_threshold"]

    def process(self, event: PacketEvent) -> list[DetectorAlert]:
        if event.protocol != "TCP" or event.tcp_flags != "S":
            return []
        bucket = self.history[event.src_ip]
        bucket.add(1, event.timestamp)
        if bucket.count() < self.packet_threshold:
            return []
        fingerprint = f"{self.name}:{event.src_ip}"
        if not self.can_emit(fingerprint, event.timestamp):
            return []
        return [
            DetectorAlert(
                detector=self.name,
                severity="critical",
                src_ip=event.src_ip,
                dst_ip=event.dst_ip,
                title="SYN flood suspected",
                description=f"Host sent {bucket.count()} SYN packets inside the configured window.",
                fingerprint=fingerprint,
                metadata={"syn_packets": bucket.count()},
            )
        ]


class IcmpFloodDetector(BaseDetector):
    name = "icmp_flood"

    def __init__(self, thresholds: dict, cooldown_seconds: int = 20):
        super().__init__(thresholds, cooldown_seconds)
        self.history = defaultdict(lambda: SlidingWindow(thresholds["window_seconds"]))
        self.packet_threshold = thresholds["packet_threshold"]

    def process(self, event: PacketEvent) -> list[DetectorAlert]:
        if event.protocol != "ICMP" or event.icmp_type != 8:
            return []
        bucket = self.history[event.src_ip]
        bucket.add(1, event.timestamp)
        if bucket.count() < self.packet_threshold:
            return []
        fingerprint = f"{self.name}:{event.src_ip}"
        if not self.can_emit(fingerprint, event.timestamp):
            return []
        return [
            DetectorAlert(
                detector=self.name,
                severity="high",
                src_ip=event.src_ip,
                dst_ip=event.dst_ip,
                title="ICMP flood suspected",
                description=f"Host sent {bucket.count()} ICMP echo requests inside the configured window.",
                fingerprint=fingerprint,
                metadata={"icmp_echo_requests": bucket.count()},
            )
        ]


class DnsExfiltrationDetector(BaseDetector):
    name = "dns_exfiltration"

    def __init__(self, thresholds: dict, cooldown_seconds: int = 20):
        super().__init__(thresholds, cooldown_seconds)
        self.history = defaultdict(lambda: SlidingWindow(thresholds["window_seconds"]))
        self.long_query_threshold = thresholds["long_query_threshold"]
        self.avg_query_length_threshold = thresholds["avg_query_length_threshold"]

    def process(self, event: PacketEvent) -> list[DetectorAlert]:
        if event.protocol != "DNS" or not event.dns_query or not event.src_ip:
            return []
        query = event.dns_query.rstrip(".")
        if len(query) < self.avg_query_length_threshold:
            return []
        bucket = self.history[event.src_ip]
        bucket.add(query, event.timestamp)
        lengths = [len(v) for v in bucket.values()]
        long_queries = [v for v in bucket.values() if len(v) >= self.avg_query_length_threshold]
        if len(long_queries) < self.long_query_threshold:
            return []
        fingerprint = f"{self.name}:{event.src_ip}"
        if not self.can_emit(fingerprint, event.timestamp):
            return []
        return [
            DetectorAlert(
                detector=self.name,
                severity="medium",
                src_ip=event.src_ip,
                dst_ip=event.dst_ip,
                title="Possible DNS exfiltration",
                description="High volume of unusually long DNS queries detected from a single host.",
                fingerprint=fingerprint,
                metadata={
                    "long_query_count": len(long_queries),
                    "average_length": round(mean(lengths), 2) if lengths else 0,
                    "sample_queries": long_queries[:5],
                },
            )
        ]


class BeaconingDetector(BaseDetector):
    name = "beaconing"

    def __init__(self, thresholds: dict, cooldown_seconds: int = 20):
        super().__init__(thresholds, cooldown_seconds)
        self.min_events = thresholds["min_events"]
        self.interval_tolerance_seconds = thresholds["interval_tolerance_seconds"]
        self.history = defaultdict(lambda: SlidingWindow(3600))

    def process(self, event: PacketEvent) -> list[DetectorAlert]:
        if event.protocol not in {"TCP", "UDP", "DNS"} or not event.src_ip or not event.dst_ip:
            return []
        key = f"{event.src_ip}->{event.dst_ip}:{event.dst_port or 0}"
        bucket = self.history[key]
        bucket.add(event.timestamp, event.timestamp)
        timestamps = list(bucket.values())
        if len(timestamps) < self.min_events:
            return []
        intervals = [round(timestamps[i] - timestamps[i - 1], 2) for i in range(1, len(timestamps))]
        if not intervals:
            return []
        baseline = mean(intervals)
        if any(abs(x - baseline) > self.interval_tolerance_seconds for x in intervals):
            return []
        fingerprint = f"{self.name}:{key}"
        if not self.can_emit(fingerprint, event.timestamp):
            return []
        return [
            DetectorAlert(
                detector=self.name,
                severity="medium",
                src_ip=event.src_ip,
                dst_ip=event.dst_ip,
                title="Beaconing pattern suspected",
                description="Traffic exhibits near-constant periodic intervals consistent with beaconing.",
                fingerprint=fingerprint,
                metadata={"intervals": intervals[-10:], "baseline_interval": round(baseline, 2)},
            )
        ]


class AuthBruteforceDetector(BaseDetector):
    name = "auth_bruteforce"

    def __init__(self, thresholds: dict, cooldown_seconds: int = 20):
        super().__init__(thresholds, cooldown_seconds)
        self.history = defaultdict(lambda: SlidingWindow(thresholds["window_seconds"]))
        self.attempts_threshold = thresholds["attempts_threshold"]
        self.watched_ports = set(thresholds["watched_ports"])

    def process(self, event: PacketEvent) -> list[DetectorAlert]:
        if event.protocol != "TCP" or event.dst_port not in self.watched_ports:
            return []
        if event.tcp_flags not in {"S", "PA", "A"}:
            return []
        key = f"{event.src_ip}:{event.dst_port}"
        bucket = self.history[key]
        bucket.add(event.dst_port, event.timestamp)
        if bucket.count() < self.attempts_threshold:
            return []
        fingerprint = f"{self.name}:{key}"
        if not self.can_emit(fingerprint, event.timestamp):
            return []
        return [
            DetectorAlert(
                detector=self.name,
                severity="medium",
                src_ip=event.src_ip,
                dst_ip=event.dst_ip,
                title="Sensitive service brute-force suspected",
                description=f"Repeated attempts observed towards service port {event.dst_port}.",
                fingerprint=fingerprint,
                metadata={"attempts": bucket.count(), "service_port": event.dst_port},
            )
        ]
