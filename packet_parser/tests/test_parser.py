"""Comprehensive end-to-end unit tests for parse_packet covering all 14 test cases."""

from datetime import datetime, timezone
import pytest
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.inet6 import IPv6
from scapy.layers.l2 import Ether, ARP
from scapy.packet import Raw

from packet_parser.exceptions import PacketParsingError, UnsupportedProtocolError
from packet_parser.parser import parse_packet
from packet_parser.protocols import PAYLOAD_CAPTURE_LIMIT


REQUIRED_CONTRACT_KEYS = {
    "timestamp",
    "src_mac",
    "dst_mac",
    "src_ip",
    "dst_ip",
    "src_port",
    "dst_port",
    "protocol",
    "flags",
    "ttl",
    "packet_length",
    "payload_size",
    "payload",
    "icmp_type",
    "icmp_code",
}


# 1. TCP SYN
def test_case_1_tcp_syn():
    pkt = Ether(src="AA:BB:CC:DD:EE:FF", dst="11:22:33:44:55:66") / IP(src="192.168.1.10", dst="192.168.1.20", ttl=64) / TCP(sport=49152, dport=80, flags="S")
    res = parse_packet(pkt)

    assert res["protocol"] == "TCP"
    assert res["flags"] == "SYN"
    assert res["src_port"] == 49152
    assert res["dst_port"] == 80
    assert res["payload_size"] == 0


# 2. TCP ACK
def test_case_2_tcp_ack():
    pkt = Ether() / IP(src="192.168.1.10", dst="192.168.1.20") / TCP(sport=49152, dport=80, flags="A")
    res = parse_packet(pkt)

    assert res["protocol"] == "TCP"
    assert res["flags"] == "ACK"


# 3. TCP packet with payload
def test_case_3_tcp_with_payload():
    payload = b"POST /api HTTP/1.1\r\n\r\n"
    pkt = Ether() / IP(src="192.168.1.10", dst="192.168.1.20") / TCP(sport=49152, dport=80, flags="PA") / Raw(load=payload)
    res = parse_packet(pkt)

    assert res["protocol"] == "TCP"
    assert res["flags"] == "PSH,ACK"
    assert res["payload_size"] == len(payload)
    assert res["payload"] == payload


# 4. UDP packet
def test_case_4_udp_packet():
    pkt = Ether() / IP(src="10.0.0.1", dst="8.8.8.8") / UDP(sport=53000, dport=53)
    res = parse_packet(pkt)

    assert res["protocol"] == "UDP"
    assert res["src_port"] == 53000
    assert res["dst_port"] == 53
    assert res["flags"] is None
    assert res["payload_size"] == 0


# 5. UDP packet with payload
def test_case_5_udp_with_payload():
    payload = b"\x00\x01DNSQueryData"
    pkt = Ether() / IP(src="10.0.0.1", dst="8.8.8.8") / UDP(sport=53000, dport=53) / Raw(load=payload)
    res = parse_packet(pkt)

    assert res["protocol"] == "UDP"
    assert res["payload_size"] == len(payload)


# 6. ICMP Echo Request
def test_case_6_icmp_echo_request():
    payload = b"ABCDEF"
    pkt = Ether(src="AA:BB:CC:DD:EE:FF", dst="11:22:33:44:55:66") / IP(src="192.168.1.10", dst="192.168.1.20", ttl=64) / ICMP(type=8, code=0) / Raw(load=payload)
    res = parse_packet(pkt)

    assert res["protocol"] == "ICMP"
    assert res["icmp_type"] == 8
    assert res["icmp_code"] == 0
    assert res["payload_size"] == len(payload)


# 7. ICMP Echo Reply
def test_case_7_icmp_echo_reply():
    pkt = Ether() / IP(src="192.168.1.20", dst="192.168.1.10") / ICMP(type=0, code=0)
    res = parse_packet(pkt)

    assert res["protocol"] == "ICMP"
    assert res["icmp_type"] == 0
    assert res["icmp_code"] == 0


# 8. Unsupported protocol (ARP, IPv6)
def test_case_8_unsupported_protocol():
    pkt_arp = Ether() / ARP()
    with pytest.raises(UnsupportedProtocolError):
        parse_packet(pkt_arp)

    pkt_ipv6 = Ether() / IPv6() / TCP()
    with pytest.raises(UnsupportedProtocolError):
        parse_packet(pkt_ipv6)


# 9. Packet without Ethernet
def test_case_9_packet_without_ethernet():
    pkt_raw = IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=1234, dport=80)
    res = parse_packet(pkt_raw)

    assert res["src_mac"] is None
    assert res["dst_mac"] is None
    assert res["src_ip"] == "10.0.0.1"
    assert res["dst_ip"] == "10.0.0.2"
    assert res["protocol"] == "TCP"


# 10. Invalid / non-Scapy input
def test_case_10_invalid_non_scapy_input():
    with pytest.raises(PacketParsingError):
        parse_packet(None)

    with pytest.raises(PacketParsingError):
        parse_packet(12345)

    with pytest.raises(PacketParsingError):
        parse_packet("invalid packet string")


# 11. Timestamp normalization to UTC datetime
def test_case_11_timestamp_normalization():
    pkt = Ether() / IP() / TCP()
    res = parse_packet(pkt)

    assert isinstance(res["timestamp"], datetime)
    assert res["timestamp"].tzinfo is not None
    assert res["timestamp"].tzinfo == timezone.utc


# 12. Required keys always present
def test_case_12_required_keys_always_present():
    pkt = Ether() / IP() / UDP()
    res = parse_packet(pkt)

    assert set(res.keys()) == REQUIRED_CONTRACT_KEYS


# 13. TCP/UDP ports are None for ICMP
def test_case_13_ports_are_none_for_icmp():
    pkt = Ether() / IP() / ICMP(type=8, code=0)
    res = parse_packet(pkt)

    assert res["src_port"] is None
    assert res["dst_port"] is None


# 14. ICMP type/code are None for TCP/UDP
def test_case_14_icmp_fields_none_for_tcp_udp():
    pkt_tcp = Ether() / IP() / TCP()
    res_tcp = parse_packet(pkt_tcp)
    assert res_tcp["icmp_type"] is None
    assert res_tcp["icmp_code"] is None

    pkt_udp = Ether() / IP() / UDP()
    res_udp = parse_packet(pkt_udp)
    assert res_udp["icmp_type"] is None
    assert res_udp["icmp_code"] is None


# 15. TCP flags use comma-separated names in header bit order
def test_case_15_tcp_flag_names():
    cases = {"SA": "SYN,ACK", "FA": "FIN,ACK", "R": "RST", "": None}
    for scapy_flags, expected in cases.items():
        res = parse_packet(Ether() / IP() / TCP(flags=scapy_flags))
        assert res["flags"] == expected


# 16. Payload is truncated to PAYLOAD_CAPTURE_LIMIT, payload_size is not
def test_case_16_payload_truncated():
    payload = b"A" * (PAYLOAD_CAPTURE_LIMIT + 100)
    res = parse_packet(Ether() / IP() / TCP() / Raw(load=payload))

    assert res["payload_size"] == len(payload)
    assert res["payload"] == payload[:PAYLOAD_CAPTURE_LIMIT]
