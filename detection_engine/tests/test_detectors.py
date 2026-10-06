"""Behaviour tests for each detector, driven through the analyzer and engine."""

from traffic_analyzer.tests.helpers import packet


def rules(alerts):
    return [a["rule"] for a in alerts]


# --- port scan ----------------------------------------------------------------


def scan(ports, t0=0.0, src_ip="10.0.0.5"):
    return [packet(t=t0 + i * 0.01, src_ip=src_ip, src_port=40000 + i, dst_port=p, flags="SYN") for i, p in enumerate(ports)]


def test_port_scan_detected_at_threshold(pipeline):
    p = pipeline()
    alerts = []
    for i, pkt in enumerate(scan(range(1, 11))):
        new = p.feed([pkt], enabled=["port_scan"])
        if new:
            alerts.append((i, new[0]))

    assert len(alerts) == 1
    index, alert = alerts[0]
    assert index == 6
    assert alert["attack_type"] == "Port Scan"
    assert alert["severity"] == "Medium"
    assert "7 distinct destination ports" in alert["description"]


def test_port_scan_severity_scales(pipeline):
    alerts = pipeline({"detection": {"alert_cooldown_seconds": 0}}).feed(scan(range(1, 22)), enabled=["port_scan"])
    assert alerts[-1]["severity"] == "Critical"
    assert alerts[-1]["confidence"] == 0.99


def test_port_scan_threshold_from_config(pipeline):
    p = pipeline({"detection": {"port_scan": {"unique_ports_threshold": 20}}})
    assert p.feed(scan(range(1, 11)), enabled=["port_scan"]) == []


def test_server_replies_are_not_a_port_scan(pipeline):
    replies = [packet(src_ip="10.0.0.1", dst_ip="10.0.0.9", src_port=80, dst_port=50000 + i, flags="SYN,ACK") for i in range(50)]
    assert pipeline().feed(replies, enabled=["port_scan"]) == []


# --- SYN flood ----------------------------------------------------------------


def test_syn_flood_with_random_source_ports(pipeline):
    flood = [packet(t=i * 0.01, src_port=30000 + i, dst_port=80, flags="SYN") for i in range(15)]
    alerts = pipeline().feed(flood, enabled=["syn_flood"])
    assert rules(alerts) == ["syn_flood"]
    assert "10 SYN packets, 0 ACK packets" in alerts[0]["description"]


def test_normal_connections_are_not_a_syn_flood(pipeline):
    traffic = []
    for i in range(15):
        traffic.append(packet(t=i, src_port=30000 + i, dst_port=443, flags="SYN"))
        traffic.append(packet(t=i + 0.01, src_port=30000 + i, dst_port=443, flags="ACK"))
    assert pipeline().feed(traffic, enabled=["syn_flood"]) == []


def test_syn_flood_ignores_non_tcp(pipeline):
    pings = [packet(t=i * 0.01, protocol="ICMP") for i in range(30)]
    assert pipeline().feed(pings, enabled=["syn_flood"]) == []


# --- ICMP flood ---------------------------------------------------------------


def test_icmp_flood_detected(pipeline):
    pings = [packet(t=i * 0.004, protocol="ICMP") for i in range(25)]
    alerts = pipeline().feed(pings, enabled=["icmp_flood"])
    assert rules(alerts) == ["icmp_flood"]
    assert alerts[0]["protocol"] == "ICMP"


def test_normal_ping_is_not_a_flood(pipeline):
    pings = [packet(t=float(i), protocol="ICMP") for i in range(60)]
    assert pipeline().feed(pings, enabled=["icmp_flood"]) == []


def test_icmp_threshold_from_config(pipeline):
    pings = [packet(t=i * 0.004, protocol="ICMP") for i in range(25)]
    assert pipeline({"detection": {"icmp_flood": {"pps_threshold": 100}}}).feed(pings, enabled=["icmp_flood"]) == []


# --- brute force --------------------------------------------------------------


def attempts(count, port=22, spacing=1.0, flags="SYN"):
    return [packet(t=i * spacing, src_port=50000 + i, dst_port=port, flags=flags) for i in range(count)]


def test_ssh_brute_force(pipeline):
    alerts = pipeline().feed(attempts(6), enabled=["brute_force"])
    assert rules(alerts) == ["brute_force"]
    assert "Repeated SSH connection attempts detected (5 attempts" in alerts[0]["description"]


def test_brute_force_ignores_other_ports_and_non_syn(pipeline):
    p = pipeline()
    assert p.feed(attempts(10, port=80), enabled=["brute_force"]) == []
    assert p.feed(attempts(10, flags="PSH,ACK"), enabled=["brute_force"]) == []


def test_brute_force_attempts_outside_window_do_not_count(pipeline):
    assert pipeline().feed(attempts(10, spacing=20.0), enabled=["brute_force"]) == []


def test_brute_force_ports_from_config(pipeline):
    p = pipeline({"detection": {"brute_force": {"ports": [2222]}}})
    assert p.feed(attempts(6, port=22), enabled=["brute_force"]) == []
    alerts = p.feed(attempts(6, port=2222), enabled=["brute_force"])
    assert "port 2222 connection attempts" in alerts[0]["description"]


# --- custom rules -------------------------------------------------------------


def custom(**rules_config):
    return {"detection": {"custom_rules": rules_config, "alert_cooldown_seconds": 0}}


def test_blocked_port(pipeline):
    alerts = pipeline(custom(blocked_ports=[8080])).feed([packet(dst_port=8080, flags="ACK")], enabled=["custom_rules"])
    assert alerts[0]["description"] == "Blocked port matched: 8080."
    assert alerts[0]["severity"] == "High"


def test_blocked_ips(pipeline):
    p = pipeline(custom(blocked_ips=["203.0.113.7"]))
    assert p.feed([packet(src_ip="203.0.113.7")], enabled=["custom_rules"])[0]["description"] == "Blocked source IP matched: 203.0.113.7."
    assert p.feed([packet(dst_ip="203.0.113.7")], enabled=["custom_rules"])[0]["description"] == "Blocked destination IP matched: 203.0.113.7."


def test_blocked_protocol(pipeline):
    alerts = pipeline(custom(blocked_protocols=["icmp"])).feed([packet(protocol="ICMP")], enabled=["custom_rules"])
    assert alerts[0]["description"] == "Blocked protocol matched: ICMP."


def test_suspicious_port_only_on_connection_attempts(pipeline):
    p = pipeline(custom())
    assert p.feed([packet(dst_port=4444, flags="ACK")], enabled=["custom_rules"]) == []
    alerts = p.feed([packet(dst_port=4444, flags="SYN")], enabled=["custom_rules"])
    assert alerts[0]["description"] == "Connection attempt to suspicious port 4444."
    assert p.feed([packet(protocol="UDP", dst_port=31337)], enabled=["custom_rules"])


def test_no_custom_rule_match(pipeline):
    assert pipeline(custom()).feed([packet(dst_port=443)], enabled=["custom_rules"]) == []


# --- signatures ---------------------------------------------------------------


def with_payload(data: bytes, **kwargs):
    pkt = packet(flags="PSH,ACK", **kwargs)
    pkt["payload"] = data
    pkt["payload_size"] = len(data)
    return pkt


SIGNATURES = {"detection": {"signatures": [
    {"name": "Path traversal", "pattern": "../../", "severity": "High"},
    {"name": "SQL injection", "pattern": r"union\s+select", "regex": True, "severity": "critical"},
]}}


def test_substring_signature_is_case_insensitive(pipeline):
    alerts = pipeline(SIGNATURES).feed([with_payload(b"GET /files/../../ETC/passwd HTTP/1.1")], enabled=["signatures"])
    assert alerts[0]["description"] == "Payload matched signature 'Path traversal'."
    assert alerts[0]["severity"] == "High"
    assert alerts[0]["attack_type"] == "Signature Match"


def test_regex_signature(pipeline):
    alerts = pipeline(SIGNATURES).feed([with_payload(b"id=1 UNION   SELECT password")], enabled=["signatures"])
    assert alerts[0]["description"] == "Payload matched signature 'SQL injection'."
    assert alerts[0]["severity"] == "Critical"


def test_no_signature_match_or_payload(pipeline):
    p = pipeline(SIGNATURES)
    assert p.feed([with_payload(b"GET /index.html HTTP/1.1")], enabled=["signatures"]) == []
    assert p.feed([packet()], enabled=["signatures"]) == []
