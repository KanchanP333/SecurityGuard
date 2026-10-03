"""Packet validation utilities."""

from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.l2 import Ether

from packet_parser.exceptions import PacketParsingError, UnsupportedProtocolError


def has_ether_layer(packet) -> bool:
    """Check if packet has Ethernet layer."""
    if packet is None or not hasattr(packet, "haslayer"):
        return False
    return bool(packet.haslayer(Ether))


def has_ip_layer(packet) -> bool:
    """Check if packet has IPv4 layer."""
    if packet is None or not hasattr(packet, "haslayer"):
        return False
    return bool(packet.haslayer(IP))


def has_tcp_layer(packet) -> bool:
    """Check if packet has TCP layer."""
    if packet is None or not hasattr(packet, "haslayer"):
        return False
    return bool(packet.haslayer(TCP))


def has_udp_layer(packet) -> bool:
    """Check if packet has UDP layer."""
    if packet is None or not hasattr(packet, "haslayer"):
        return False
    return bool(packet.haslayer(UDP))


def has_icmp_layer(packet) -> bool:
    """Check if packet has ICMP layer."""
    if packet is None or not hasattr(packet, "haslayer"):
        return False
    return bool(packet.haslayer(ICMP))


def is_supported_protocol(packet) -> bool:
    """Check if packet contains IPv4 + one of TCP, UDP, ICMP."""
    if packet is None or not hasattr(packet, "haslayer"):
        return False
    if not has_ip_layer(packet):
        return False
    return has_tcp_layer(packet) or has_udp_layer(packet) or has_icmp_layer(packet)


def validate_packet(packet) -> None:
    """Validate packet format and supported protocols (IPv4 + TCP/UDP/ICMP).

    Raises:
        PacketParsingError: If packet is None or invalid scapy object.
        UnsupportedProtocolError: If packet uses an unsupported protocol or lacks IPv4.
    """
    if packet is None:
        raise PacketParsingError("Packet is None")
    if not hasattr(packet, "haslayer"):
        raise PacketParsingError("Invalid packet object: missing Scapy layer methods")
    if not has_ip_layer(packet):
        raise UnsupportedProtocolError("Packet lacks IPv4 layer")
    if not is_supported_protocol(packet):
        raise UnsupportedProtocolError("Packet protocol is not supported (must be TCP, UDP, or ICMP)")
