"""Unit tests for packet validators."""

import pytest
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.inet6 import IPv6
from scapy.layers.l2 import Ether, ARP

from packet_parser.exceptions import PacketParsingError, UnsupportedProtocolError
from packet_parser.validators import (
    has_ether_layer,
    has_icmp_layer,
    has_ip_layer,
    has_tcp_layer,
    has_udp_layer,
    is_supported_protocol,
    validate_packet,
)


def test_has_ether_layer():
    pkt_ether = Ether() / IP() / TCP()
    pkt_raw_ip = IP() / TCP()

    assert has_ether_layer(pkt_ether) is True
    assert has_ether_layer(pkt_raw_ip) is False
    assert has_ether_layer(None) is False
    assert has_ether_layer("invalid") is False


def test_has_ip_layer():
    pkt_ipv4 = Ether() / IP(src="192.168.1.10", dst="192.168.1.1") / TCP()
    pkt_ipv6 = Ether() / IPv6(src="fe80::1", dst="fe80::2") / UDP()
    pkt_arp = Ether() / ARP()

    assert has_ip_layer(pkt_ipv4) is True
    # IPv6 is unsupported in this version
    assert has_ip_layer(pkt_ipv6) is False
    assert has_ip_layer(pkt_arp) is False
    assert has_ip_layer(None) is False


def test_has_transport_layers():
    pkt_tcp = IP() / TCP(sport=1234, dport=80)
    pkt_udp = IP() / UDP(sport=1234, dport=53)
    pkt_icmp = IP() / ICMP()

    assert has_tcp_layer(pkt_tcp) is True
    assert has_tcp_layer(pkt_udp) is False
    assert has_udp_layer(pkt_udp) is True
    assert has_udp_layer(pkt_tcp) is False
    assert has_icmp_layer(pkt_icmp) is True
    assert has_icmp_layer(pkt_tcp) is False


def test_is_supported_protocol():
    pkt_tcp = Ether() / IP() / TCP()
    pkt_udp = Ether() / IP() / UDP()
    pkt_icmp = Ether() / IP() / ICMP()
    pkt_arp = Ether() / ARP()
    pkt_no_eth = IP() / TCP()

    assert is_supported_protocol(pkt_tcp) is True
    assert is_supported_protocol(pkt_udp) is True
    assert is_supported_protocol(pkt_icmp) is True
    assert is_supported_protocol(pkt_no_eth) is True
    assert is_supported_protocol(pkt_arp) is False
    assert is_supported_protocol(None) is False


def test_validate_packet_success():
    pkt = Ether() / IP() / TCP()
    validate_packet(pkt)

    pkt_raw = IP() / TCP()
    validate_packet(pkt_raw)


def test_validate_packet_exceptions():
    with pytest.raises(PacketParsingError):
        validate_packet(None)

    with pytest.raises(PacketParsingError):
        validate_packet("not a scapy packet")

    pkt_arp = Ether() / ARP()
    with pytest.raises(UnsupportedProtocolError):
        validate_packet(pkt_arp)
