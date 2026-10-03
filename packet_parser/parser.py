"""Main entry point for packet parsing."""

from datetime import datetime, timezone
from typing import Any, Dict

from packet_parser.exceptions import PacketParsingError, UnsupportedProtocolError
from packet_parser.protocols import (
    parse_ethernet,
    parse_icmp,
    parse_ip,
    parse_tcp,
    parse_udp,
)
from packet_parser.validators import (
    has_icmp_layer,
    has_tcp_layer,
    has_udp_layer,
    validate_packet,
)


def parse_packet(packet: Any) -> Dict[str, Any]:
    """Parse a Scapy packet into a standardized packet_dict (see docs/CONTRACTS.md).

    Args:
        packet: Scapy packet object.

    Returns:
        Dict[str, Any]: Standardized packet dictionary containing:
            - timestamp: timezone-aware UTC datetime
            - src_mac: str | None
            - dst_mac: str | None
            - src_ip: str
            - dst_ip: str
            - src_port: int | None
            - dst_port: int | None
            - protocol: str ("TCP", "UDP", "ICMP")
            - flags: str | None (comma-separated names, e.g. "SYN,ACK")
            - ttl: int | None
            - packet_length: int
            - payload_size: int
            - payload: bytes (first PAYLOAD_CAPTURE_LIMIT bytes)
            - icmp_type: int | None
            - icmp_code: int | None

    Raises:
        PacketParsingError: If packet is invalid or unparseable.
        UnsupportedProtocolError: If packet uses an unsupported protocol or lacks IPv4.
    """
    # 1. Validate packet (raises PacketParsingError or UnsupportedProtocolError)
    validate_packet(packet)

    # 2. Extract and normalize timestamp to timezone-aware UTC datetime
    timestamp = datetime.now(timezone.utc)
    if hasattr(packet, "time") and packet.time is not None:
        try:
            timestamp = datetime.fromtimestamp(float(packet.time), tz=timezone.utc)
        except (ValueError, TypeError, OverflowError):
            timestamp = datetime.now(timezone.utc)

    # 3. Extract Ethernet layer (nullable src_mac/dst_mac)
    eth_info = parse_ethernet(packet)

    # 4. Extract IP layer (src_ip, dst_ip, nullable ttl, total packet_length)
    ip_info = parse_ip(packet)

    # 5. Determine protocol and extract transport/ICMP layer fields
    protocol = ""
    transport_info = {
        "src_port": None,
        "dst_port": None,
        "flags": None,
        "payload_size": 0,
        "payload": b"",
        "icmp_type": None,
        "icmp_code": None,
    }

    if has_tcp_layer(packet):
        protocol = "TCP"
        transport_info = parse_tcp(packet)
    elif has_udp_layer(packet):
        protocol = "UDP"
        transport_info = parse_udp(packet)
    elif has_icmp_layer(packet):
        protocol = "ICMP"
        transport_info = parse_icmp(packet)
    else:
        raise UnsupportedProtocolError("No supported transport protocol layer (TCP, UDP, ICMP) found in packet")

    # 6. Build standard dictionary contract
    packet_dict = {
        "timestamp": timestamp,
        "src_mac": eth_info["src_mac"],
        "dst_mac": eth_info["dst_mac"],
        "src_ip": ip_info["src_ip"],
        "dst_ip": ip_info["dst_ip"],
        "src_port": transport_info["src_port"],
        "dst_port": transport_info["dst_port"],
        "protocol": protocol,
        "flags": transport_info["flags"],
        "ttl": ip_info["ttl"],
        "packet_length": ip_info["packet_length"],
        "payload_size": transport_info["payload_size"],
        "payload": transport_info["payload"],
        "icmp_type": transport_info["icmp_type"],
        "icmp_code": transport_info["icmp_code"],
    }

    return packet_dict
