"""Protocol-specific field extraction module."""

from typing import Any, Dict
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.l2 import Ether

# Scapy flag letters mapped to contract names, in TCP header bit order.
_TCP_FLAG_NAMES = (
    ("F", "FIN"),
    ("S", "SYN"),
    ("R", "RST"),
    ("P", "PSH"),
    ("A", "ACK"),
    ("U", "URG"),
    ("E", "ECE"),
    ("C", "CWR"),
    ("N", "NS"),
)

# Maximum number of payload bytes kept in packet_dict for signature matching.
PAYLOAD_CAPTURE_LIMIT = 512


def _format_tcp_flags(flags_val: Any) -> str | None:
    """Format TCP flags as comma-separated names (e.g., 'SYN', 'SYN,ACK', 'PSH,ACK')."""
    if flags_val is None:
        return None
    letters = str(flags_val).strip()
    names = [name for letter, name in _TCP_FLAG_NAMES if letter in letters]
    return ",".join(names) if names else None


def _payload_bytes(layer: Any) -> bytes:
    """Return the full payload bytes carried by a layer (empty if none)."""
    payload = getattr(layer, "payload", None)
    return bytes(payload) if payload is not None else b""


def parse_ethernet(packet: Any) -> Dict[str, str | None]:
    """Extract Ethernet fields (src_mac, dst_mac). Returns None if Ethernet layer absent."""
    if packet is not None and hasattr(packet, "haslayer") and packet.haslayer(Ether):
        ether_layer = packet[Ether]
        src = getattr(ether_layer, "src", None)
        dst = getattr(ether_layer, "dst", None)
        return {
            "src_mac": str(src) if src is not None else None,
            "dst_mac": str(dst) if dst is not None else None,
        }
    return {
        "src_mac": None,
        "dst_mac": None,
    }


def parse_ip(packet: Any) -> Dict[str, Any]:
    """Extract IP layer fields (src_ip, dst_ip, ttl, packet_length). Total packet_length is len(packet)."""
    src_ip = ""
    dst_ip = ""
    ttl: int | None = None
    packet_length = len(packet) if packet is not None else 0

    if packet is not None and hasattr(packet, "haslayer") and packet.haslayer(IP):
        ip_layer = packet[IP]
        src_ip = str(getattr(ip_layer, "src", ""))
        dst_ip = str(getattr(ip_layer, "dst", ""))
        raw_ttl = getattr(ip_layer, "ttl", None)
        if raw_ttl is not None:
            try:
                ttl = int(raw_ttl)
            except (ValueError, TypeError):
                ttl = None

    return {
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "ttl": ttl,
        "packet_length": packet_length,
    }


def parse_tcp(packet: Any) -> Dict[str, Any]:
    """Extract TCP layer fields (src_port, dst_port, flags, payload_size, payload)."""
    if packet is not None and hasattr(packet, "haslayer") and packet.haslayer(TCP):
        tcp_layer = packet[TCP]
        src_port = int(getattr(tcp_layer, "sport", 0))
        dst_port = int(getattr(tcp_layer, "dport", 0))
        raw_flags = getattr(tcp_layer, "flags", None)
        flags = _format_tcp_flags(raw_flags)

        payload = _payload_bytes(tcp_layer)

        return {
            "src_port": src_port,
            "dst_port": dst_port,
            "flags": flags,
            "payload_size": len(payload),
            "payload": payload[:PAYLOAD_CAPTURE_LIMIT],
            "icmp_type": None,
            "icmp_code": None,
        }

    return {
        "src_port": None,
        "dst_port": None,
        "flags": None,
        "payload_size": 0,
        "payload": b"",
        "icmp_type": None,
        "icmp_code": None,
    }


def parse_udp(packet: Any) -> Dict[str, Any]:
    """Extract UDP layer fields (src_port, dst_port, payload_size, payload)."""
    if packet is not None and hasattr(packet, "haslayer") and packet.haslayer(UDP):
        udp_layer = packet[UDP]
        src_port = int(getattr(udp_layer, "sport", 0))
        dst_port = int(getattr(udp_layer, "dport", 0))

        payload = _payload_bytes(udp_layer)

        return {
            "src_port": src_port,
            "dst_port": dst_port,
            "flags": None,
            "payload_size": len(payload),
            "payload": payload[:PAYLOAD_CAPTURE_LIMIT],
            "icmp_type": None,
            "icmp_code": None,
        }

    return {
        "src_port": None,
        "dst_port": None,
        "flags": None,
        "payload_size": 0,
        "payload": b"",
        "icmp_type": None,
        "icmp_code": None,
    }


def parse_icmp(packet: Any) -> Dict[str, Any]:
    """Extract ICMP layer fields (payload_size, payload, icmp_type, icmp_code)."""
    payload = b""
    icmp_type: int | None = None
    icmp_code: int | None = None

    if packet is not None and hasattr(packet, "haslayer") and packet.haslayer(ICMP):
        icmp_layer = packet[ICMP]
        raw_type = getattr(icmp_layer, "type", None)
        raw_code = getattr(icmp_layer, "code", None)
        
        if raw_type is not None:
            try:
                icmp_type = int(raw_type)
            except (ValueError, TypeError):
                icmp_type = None

        if raw_code is not None:
            try:
                icmp_code = int(raw_code)
            except (ValueError, TypeError):
                icmp_code = None

        payload = _payload_bytes(icmp_layer)

    return {
        "src_port": None,
        "dst_port": None,
        "flags": None,
        "payload_size": len(payload),
        "payload": payload[:PAYLOAD_CAPTURE_LIMIT],
        "icmp_type": icmp_type,
        "icmp_code": icmp_code,
    }
