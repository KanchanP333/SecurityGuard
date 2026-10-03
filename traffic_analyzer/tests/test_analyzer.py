"""Tests for timestamps, the module-level API and the parser → analyzer path."""

from datetime import datetime, timezone

from scapy.layers.inet import IP, TCP

import traffic_analyzer
from packet_parser import parse_packet
from traffic_analyzer import TrafficAnalyzer
from traffic_analyzer.tests.helpers import BASE_TIME, packet


def test_accepts_epoch_and_iso_timestamps():
    analyzer = TrafficAnalyzer()
    epoch = packet()
    epoch["timestamp"] = BASE_TIME
    iso = packet(t=1.0)
    iso["timestamp"] = datetime.fromtimestamp(BASE_TIME + 1.0, tz=timezone.utc).isoformat()

    analyzer.analyze(epoch)
    flow = analyzer.analyze(iso)
    assert flow["duration"] == 1.0


def test_module_level_api_and_reset():
    traffic_analyzer.configure(window_seconds=30)
    flow = traffic_analyzer.analyze(packet())
    assert flow["src_window"]["window_seconds"] == 30
    assert traffic_analyzer.get_stats()["total_packets"] == 1
    assert len(traffic_analyzer.get_flows()) == 1

    traffic_analyzer.reset()
    assert traffic_analyzer.get_stats()["total_packets"] == 0
    assert traffic_analyzer.analyze(packet())["src_window"]["window_seconds"] == 30
    traffic_analyzer.configure()


def test_parsed_scapy_packets():
    analyzer = TrafficAnalyzer()
    for port in range(1, 11):
        pkt = IP(src="192.168.1.50", dst="192.168.1.1") / TCP(sport=50000 + port, dport=port, flags="S")
        pkt.time = BASE_TIME + port * 0.01
        flow = analyzer.analyze(parse_packet(pkt))

    assert flow["flow_id"] == "TCP:192.168.1.50:50010->192.168.1.1:10"
    assert flow["src_window"]["unique_dst_ports"] == 10
    assert flow["src_window"]["syn_count"] == 10
