"""Unit tests for per-source sliding windows."""

from traffic_analyzer import TrafficAnalyzer
from traffic_analyzer.tests.helpers import packet


def test_port_scan_spread_over_many_flows():
    analyzer = TrafficAnalyzer()
    for port in range(1, 101):
        flow = analyzer.analyze(packet(t=port * 0.01, src_port=40000 + port, dst_port=port, flags="SYN"))

    window = flow["src_window"]
    assert flow["packet_count"] == 1
    assert window["unique_dst_ports"] == 100
    assert window["syn_count"] == 100
    assert window["ack_count"] == 0
    assert window["packet_count"] == 100


def test_replies_do_not_count_as_contacted_ports():
    analyzer = TrafficAnalyzer()
    for port in range(50000, 50050):
        flow = analyzer.analyze(packet(src_ip="10.0.0.1", dst_ip="10.0.0.9", src_port=80, dst_port=port, flags="SYN,ACK"))
    assert flow["src_window"]["unique_dst_ports"] == 0


def test_udp_ports_count_as_contacted():
    analyzer = TrafficAnalyzer()
    for port in (53, 123, 161):
        flow = analyzer.analyze(packet(protocol="UDP", dst_port=port))
    assert flow["src_window"]["unique_dst_ports"] == 3


def test_unique_dst_ips():
    analyzer = TrafficAnalyzer()
    for host in range(1, 6):
        flow = analyzer.analyze(packet(protocol="ICMP", dst_ip=f"10.0.1.{host}"))
    assert flow["src_window"]["unique_dst_ips"] == 5
    assert flow["src_window"]["icmp_count"] == 5


def test_icmp_burst_pps():
    analyzer = TrafficAnalyzer()
    for i in range(25):
        flow = analyzer.analyze(packet(t=i * 0.004, protocol="ICMP"))
    assert flow["src_window"]["pps"] == 25.0
    assert flow["src_window"]["icmp_pps"] == 25.0
    assert flow["pps"] == 25.0


def test_icmp_pps_ignores_other_protocols():
    analyzer = TrafficAnalyzer()
    for i in range(10):
        analyzer.analyze(packet(t=i * 0.01, protocol="TCP", src_port=40000 + i))
    for i in range(5):
        flow = analyzer.analyze(packet(t=0.5 + i * 0.01, protocol="ICMP"))
    assert flow["src_window"]["pps"] == 15.0
    assert flow["src_window"]["icmp_pps"] == 5.0


def test_steady_traffic_pps():
    analyzer = TrafficAnalyzer()
    for i in range(30):
        flow = analyzer.analyze(packet(t=i * 2.0, protocol="ICMP"))
    # 0.5 pps sampled over 5 s: 2 or 3 packets.
    assert 0.4 <= flow["src_window"]["pps"] <= 0.6
    assert flow["src_window"]["packet_count"] == 30


def test_earlier_activity_does_not_dilute_a_new_burst():
    analyzer = TrafficAnalyzer()
    for i in range(5):
        analyzer.analyze(packet(t=float(i), protocol="ICMP"))
    for i in range(250):
        flow = analyzer.analyze(packet(t=30 + i * 0.004, protocol="ICMP"))
    assert flow["src_window"]["icmp_pps"] == 50.0
    assert flow["src_window"]["icmp_count"] == 255


def test_old_activity_leaves_the_window():
    analyzer = TrafficAnalyzer(window_seconds=10)
    for port in range(1, 6):
        analyzer.analyze(packet(t=0, dst_port=port, src_port=40000 + port))
    flow = analyzer.analyze(packet(t=15, dst_port=99, src_port=41000))

    window = flow["src_window"]
    assert window["window_seconds"] == 10
    assert window["packet_count"] == 1
    assert window["syn_count"] == 1
    assert window["unique_dst_ports"] == 1


def test_sources_are_tracked_separately():
    analyzer = TrafficAnalyzer()
    analyzer.analyze(packet(src_ip="10.0.0.5", dst_port=1))
    analyzer.analyze(packet(src_ip="10.0.0.5", dst_port=2, src_port=40001))
    flow = analyzer.analyze(packet(src_ip="10.0.0.6", dst_port=3))
    assert flow["src_window"]["unique_dst_ports"] == 1
    assert flow["src_window"]["packet_count"] == 1


def test_quiet_sources_are_evicted():
    analyzer = TrafficAnalyzer(window_seconds=10)
    analyzer.analyze(packet(t=0, src_ip="10.0.0.5"))
    analyzer.analyze(packet(t=30, src_ip="10.0.0.6"))
    assert len(analyzer._sources) == 1


def test_max_sources_cap():
    analyzer = TrafficAnalyzer(max_sources=2)
    for host in range(1, 4):
        analyzer.analyze(packet(src_ip=f"10.0.0.{host}"))
    assert len(analyzer._sources) == 2
