"""Tests for the dispatcher: alert format, enabled detectors, cooldowns and the full pipeline."""

from scapy.layers.inet import ICMP, IP, TCP

from configuration import Config, merge_config, set_config
from detection_engine import engine
from packet_parser import parse_packet
from traffic_analyzer import TrafficAnalyzer
from traffic_analyzer.tests.helpers import BASE_TIME, packet

CONTRACT_FIELDS = {
    "alert_id", "timestamp", "rule", "attack_type", "severity", "confidence",
    "src_ip", "dst_ip", "dst_port", "protocol", "flow_id", "description",
}

ICMP_BURST = [packet(t=i * 0.004, protocol="ICMP") for i in range(25)]


def test_alert_has_contract_fields(pipeline):
    alert = pipeline().feed(ICMP_BURST)[0]
    assert set(alert) == CONTRACT_FIELDS
    assert alert["alert_id"] is None
    assert alert["rule"] == "icmp_flood"
    assert alert["flow_id"] == "ICMP:10.0.0.5->10.0.0.1"
    assert alert["timestamp"].endswith("+00:00")
    assert alert["severity"] in {"Low", "Medium", "High", "Critical"}


def test_enabled_detectors_come_from_settings(pipeline):
    assert pipeline({"detection": {"enabled": ["port_scan"]}}).feed(ICMP_BURST) == []


def test_explicit_enabled_list_overrides_settings(pipeline):
    p = pipeline({"detection": {"enabled": ["port_scan"]}})
    assert [a["rule"] for a in p.feed(ICMP_BURST, enabled=["icmp_flood"])] == ["icmp_flood"]


def test_unknown_detector_names_are_ignored(pipeline):
    assert [a["rule"] for a in pipeline().feed(ICMP_BURST, enabled=["nope", "icmp_flood"])] == ["icmp_flood"]


def test_cooldown_suppresses_repeats_until_it_expires(pipeline):
    p = pipeline({"detection": {"alert_cooldown_seconds": 60}})
    assert len(p.feed(ICMP_BURST, enabled=["icmp_flood"])) == 1
    later = [packet(t=30 + i * 0.004, protocol="ICMP") for i in range(25)]
    assert p.feed(later, enabled=["icmp_flood"]) == []
    much_later = [packet(t=100 + i * 0.004, protocol="ICMP") for i in range(25)]
    assert len(p.feed(much_later, enabled=["icmp_flood"])) == 1


def test_cooldown_is_per_source(pipeline):
    p = pipeline()
    other = [packet(t=i * 0.004, protocol="ICMP", src_ip="10.0.0.99") for i in range(25)]
    alerts = p.feed(ICMP_BURST + other, enabled=["icmp_flood"])
    assert [a["src_ip"] for a in alerts] == ["10.0.0.5", "10.0.0.99"]


def test_zero_cooldown_alerts_every_time(pipeline):
    alerts = pipeline({"detection": {"alert_cooldown_seconds": 0}}).feed(ICMP_BURST, enabled=["icmp_flood"])
    assert len(alerts) == 6


def test_reset_clears_detector_state(pipeline):
    p = pipeline()
    ssh = [packet(t=i, src_port=50000 + i, dst_port=22, flags="SYN") for i in range(4)]
    p.feed(ssh, enabled=["brute_force"])
    engine.reset()
    # Without the reset this fifth attempt would reach the threshold of 5.
    assert p.feed([packet(t=5, src_port=50010, dst_port=22, flags="SYN")], enabled=["brute_force"]) == []


def test_reset_clears_cooldowns(pipeline):
    p = pipeline()
    assert len(p.feed(ICMP_BURST, enabled=["icmp_flood"])) == 1
    burst_at_30s = [packet(t=30 + i * 0.004, protocol="ICMP", src_ip="10.0.0.5") for i in range(200)]
    assert p.feed(burst_at_30s[:100], enabled=["icmp_flood"]) == []
    engine.reset()
    assert len(p.feed(burst_at_30s[100:], enabled=["icmp_flood"])) == 1


def test_uses_shared_config_when_no_settings_given():
    set_config(merge_config(Config(), {"detection": {"enabled": ["icmp_flood"], "icmp_flood": {"pps_threshold": 10}}}))
    try:
        analyzer = TrafficAnalyzer()
        alerts = []
        for pkt in [packet(t=i * 0.01, protocol="ICMP") for i in range(12)]:
            alerts += engine.run_engine(pkt, analyzer.analyze(pkt))
    finally:
        set_config(Config())
    assert [a["rule"] for a in alerts] == ["icmp_flood"]


def test_full_pipeline_from_scapy_packets():
    analyzer = TrafficAnalyzer()
    settings = Config().detection
    scapy_packets = (
        [IP(src="10.0.0.5", dst="10.0.0.1") / TCP(sport=40000 + p, dport=p, flags="S") for p in range(1, 30)]
        + [IP(src="10.0.0.7", dst="10.0.0.2") / TCP(sport=50000 + i, dport=22, flags="S") for i in range(6)]
        + [IP(src="10.0.0.8", dst="10.0.0.1") / ICMP() for _ in range(25)]
    )
    alerts = []
    for i, pkt in enumerate(scapy_packets):
        pkt.time = BASE_TIME + i * 0.004
        packet_dict = parse_packet(pkt)
        alerts += engine.run_engine(packet_dict, analyzer.analyze(packet_dict), settings=settings)

    found = {(a["rule"], a["src_ip"]) for a in alerts}
    assert ("port_scan", "10.0.0.5") in found
    assert ("brute_force", "10.0.0.7") in found
    assert ("icmp_flood", "10.0.0.8") in found
    assert len(alerts) == len(found)
