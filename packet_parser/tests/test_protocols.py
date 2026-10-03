"""Unit tests for protocol field extractions."""

from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.l2 import Ether
from scapy.packet import Raw

from packet_parser.protocols import (
    parse_ethernet,
    parse_icmp,
    parse_ip,
    parse_tcp,
    parse_udp,
)


def test_parse_ethernet():
    pkt = Ether(src="00:11:22:33:44:55", dst="66:77:88:99:AA:BB") / IP() / TCP()
    res = parse_ethernet(pkt)
    assert res["src_mac"] == "00:11:22:33:44:55"
    assert res["dst_mac"] == "66:77:88:99:AA:BB"

    pkt_no_eth = IP() / TCP()
    res_no_eth = parse_ethernet(pkt_no_eth)
    assert res_no_eth["src_mac"] is None
    assert res_no_eth["dst_mac"] is None


def test_parse_ip():
    pkt_v4 = Ether() / IP(src="10.0.0.1", dst="10.0.0.2", ttl=128) / TCP()
    res_v4 = parse_ip(pkt_v4)
    assert res_v4["src_ip"] == "10.0.0.1"
    assert res_v4["dst_ip"] == "10.0.0.2"
    assert res_v4["ttl"] == 128
    assert res_v4["packet_length"] == len(pkt_v4)


def test_parse_tcp():
    payload_data = b"Hello, World!"
    pkt_syn = Ether() / IP() / TCP(sport=54321, dport=80, flags="S") / Raw(load=payload_data)
    res_syn = parse_tcp(pkt_syn)
    assert res_syn["src_port"] == 54321
    assert res_syn["dst_port"] == 80
    assert res_syn["flags"] == "SYN"
    assert res_syn["payload_size"] == len(payload_data)
    assert res_syn["payload"] == payload_data
    assert res_syn["icmp_type"] is None
    assert res_syn["icmp_code"] is None


def test_parse_udp():
    payload_data = b"DNS Query Data"
    pkt = Ether() / IP() / UDP(sport=53, dport=12345) / Raw(load=payload_data)
    res = parse_udp(pkt)
    assert res["src_port"] == 53
    assert res["dst_port"] == 12345
    assert res["flags"] is None
    assert res["payload_size"] == len(payload_data)
    assert res["icmp_type"] is None
    assert res["icmp_code"] is None


def test_parse_icmp():
    payload_data = b"Ping payload"
    pkt_echo = Ether() / IP() / ICMP(type=8, code=0) / Raw(load=payload_data)
    res_echo = parse_icmp(pkt_echo)
    assert res_echo["src_port"] is None
    assert res_echo["dst_port"] is None
    assert res_echo["flags"] is None
    assert res_echo["payload_size"] == len(payload_data)
    assert res_echo["payload"] == payload_data
    assert res_echo["icmp_type"] == 8
    assert res_echo["icmp_code"] == 0

    pkt_reply = Ether() / IP() / ICMP(type=0, code=0)
    res_reply = parse_icmp(pkt_reply)
    assert res_reply["icmp_type"] == 0
    assert res_reply["icmp_code"] == 0
