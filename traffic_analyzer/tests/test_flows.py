"""Unit tests for per-flow tracking."""

from datetime import datetime

from traffic_analyzer import TrafficAnalyzer, make_flow_id
from traffic_analyzer.tests.helpers import BASE_TIME, packet


def test_flow_id_format():
    assert make_flow_id("TCP", "10.0.0.5", 51432, "10.0.0.1", 80) == "TCP:10.0.0.5:51432->10.0.0.1:80"
    assert make_flow_id("ICMP", "10.0.0.5", None, "10.0.0.1", None) == "ICMP:10.0.0.5->10.0.0.1"


def test_packets_of_same_flow_are_aggregated():
    analyzer = TrafficAnalyzer()
    analyzer.analyze(packet(t=0.0, flags="SYN", length=60))
    analyzer.analyze(packet(t=0.5, flags="ACK", length=60))
    flow = analyzer.analyze(packet(t=2.0, flags="PSH,ACK", length=200))

    assert flow["flow_id"] == "TCP:10.0.0.5:40000->10.0.0.1:80"
    assert flow["packet_count"] == 3
    assert flow["bytes"] == 320
    assert flow["syn_count"] == 1
    assert flow["ack_count"] == 2
    assert flow["duration"] == 2.0
    assert flow["pps"] == 1.5
    assert isinstance(flow["first_seen"], datetime)
    assert flow["first_seen"].timestamp() == BASE_TIME


def test_pps_has_one_second_floor():
    analyzer = TrafficAnalyzer()
    analyzer.analyze(packet(t=0.0))
    flow = analyzer.analyze(packet(t=0.001))
    assert flow["pps"] == 2.0


def test_synack_is_not_counted_as_syn():
    analyzer = TrafficAnalyzer()
    flow = analyzer.analyze(packet(flags="SYN,ACK"))
    assert flow["syn_count"] == 0
    assert flow["ack_count"] == 1


def test_different_ports_are_different_flows():
    analyzer = TrafficAnalyzer()
    first = analyzer.analyze(packet(src_port=40000))
    second = analyzer.analyze(packet(src_port=40001))
    assert first["flow_id"] != second["flow_id"]
    assert second["packet_count"] == 1
    assert len(analyzer.get_flows()) == 2


def test_idle_flow_restarts_after_timeout():
    analyzer = TrafficAnalyzer(flow_timeout_seconds=10)
    analyzer.analyze(packet(t=0))
    flow = analyzer.analyze(packet(t=11))
    assert flow["packet_count"] == 1
    assert flow["duration"] == 0.0


def test_idle_flows_are_evicted():
    analyzer = TrafficAnalyzer(flow_timeout_seconds=10)
    analyzer.analyze(packet(t=0, src_port=1111))
    analyzer.analyze(packet(t=20, src_port=2222))
    assert [f["src_port"] for f in analyzer.get_flows()] == [2222]


def test_max_flows_evicts_least_recent():
    analyzer = TrafficAnalyzer(max_flows=2)
    for port in (1, 2, 3):
        analyzer.analyze(packet(src_port=port))
    assert [f["src_port"] for f in analyzer.get_flows()] == [3, 2]


def test_get_flows_most_recent_first_and_limited():
    analyzer = TrafficAnalyzer()
    for i, port in enumerate((1, 2, 3)):
        analyzer.analyze(packet(t=i, src_port=port))
    analyzer.analyze(packet(t=5, src_port=1))
    assert [f["src_port"] for f in analyzer.get_flows(limit=2)] == [1, 3]
