from __future__ import annotations

from scapy.layers.dns import DNS, DNSQR
from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.packet import Packet

from app.detectors.base import PacketEvent


def packet_to_event(packet: Packet) -> PacketEvent | None:
    if not packet.haslayer(IP):
        return None

    event = PacketEvent(
        protocol="IP",
        src_ip=packet[IP].src,
        dst_ip=packet[IP].dst,
        length=len(packet),
        timestamp=float(getattr(packet, "time", 0.0) or 0.0),
    )

    if packet.haslayer(TCP):
        tcp = packet[TCP]
        event.protocol = "TCP"
        event.src_port = int(tcp.sport)
        event.dst_port = int(tcp.dport)
        event.tcp_flags = str(tcp.flags)
    elif packet.haslayer(UDP):
        udp = packet[UDP]
        event.protocol = "UDP"
        event.src_port = int(udp.sport)
        event.dst_port = int(udp.dport)
    elif packet.haslayer(ICMP):
        icmp = packet[ICMP]
        event.protocol = "ICMP"
        event.icmp_type = int(icmp.type)

    if packet.haslayer(DNS) and packet.haslayer(DNSQR):
        event.protocol = "DNS"
        event.dns_query = packet[DNSQR].qname.decode(errors="ignore")
        if packet.haslayer(UDP):
            event.src_port = int(packet[UDP].sport)
            event.dst_port = int(packet[UDP].dport)

    return event
