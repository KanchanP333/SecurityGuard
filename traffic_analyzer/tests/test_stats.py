"""Unit tests for global traffic statistics."""

from traffic_analyzer import TrafficAnalyzer
from traffic_analyzer.tests.helpers import BASE_TIME, packet


def test_empty_stats():
    stats = TrafficAnalyzer().get_stats()
    assert stats["total_packets"] == 0
    assert stats["pps"] == 0.0
    assert stats["history"] == []
    assert stats["first_seen"] is None


def test_totals_protocols_and_top_talkers():
    analyzer = TrafficAnalyzer()
    for _ in range(3):
        analyzer.analyze(packet(src_ip="10.0.0.5", length=100))
    analyzer.analyze(packet(protocol="UDP", src_ip="10.0.0.6", dst_ip="8.8.8.8", length=50))
    analyzer.analyze(packet(protocol="ICMP", src_ip="10.0.0.6", length=50))

    stats = analyzer.get_stats()
    assert stats["total_packets"] == 5
    assert stats["total_bytes"] == 400
    assert stats["protocols"] == {"TCP": 3, "UDP": 1, "ICMP": 1}
    assert stats["top_sources"][0] == {"ip": "10.0.0.5", "packets": 3}
    assert stats["top_destinations"][0] == {"ip": "10.0.0.1", "packets": 4}
    assert stats["active_flows"] == 3


def test_history_fills_quiet_seconds_with_zeros():
    analyzer = TrafficAnalyzer()
    analyzer.analyze(packet(t=0, length=10))
    analyzer.analyze(packet(t=0.5, length=10))
    analyzer.analyze(packet(t=3, length=10))

    history = analyzer.get_stats()["history"]
    assert [h["packets"] for h in history] == [2, 0, 0, 1]
    assert [h["bytes"] for h in history] == [20, 0, 0, 10]


def test_pps_over_recent_seconds():
    analyzer = TrafficAnalyzer()
    for i in range(50):
        analyzer.analyze(packet(t=i * 0.1, length=100))

    stats = analyzer.get_stats()
    assert stats["pps"] == 10.0
    assert stats["bps"] == 1000.0


def test_pps_drops_when_traffic_stops():
    analyzer = TrafficAnalyzer()
    for i in range(10):
        analyzer.analyze(packet(t=i * 0.1))
    assert analyzer.get_stats(now=BASE_TIME + 60)["pps"] == 0.0
