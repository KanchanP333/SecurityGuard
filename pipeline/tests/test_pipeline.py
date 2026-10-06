"""Tests for the pipeline runner: PCAP replay, live capture (with a fake sniffer) and hooks."""

import json

import pytest
import scapy.sendrecv
from scapy.layers.inet import ICMP, IP, TCP
from scapy.layers.inet6 import IPv6
from scapy.layers.l2 import ARP, Ether
from scapy.utils import wrpcap

import main
from configuration import Config, merge_config
from logger_sqlite import Database
from packet_capture import capture
from pipeline import Pipeline

BASE_TIME = 1_790_000_000.0


def timed(packets, spacing=0.002):
    for i, pkt in enumerate(packets):
        pkt.time = BASE_TIME + i * spacing
    return packets


def attack_packets():
    return timed(
        [Ether() / IP(src="10.0.0.5", dst="10.0.0.1") / TCP(sport=40000 + p, dport=p, flags="S") for p in range(1, 11)]
        + [Ether() / IP(src="10.0.0.8", dst="10.0.0.1") / ICMP() for _ in range(30)]
        + [Ether() / IPv6() / TCP(), Ether() / ARP()]
    )


@pytest.fixture
def attack_pcap(tmp_path):
    path = tmp_path / "attack.pcap"
    wrpcap(str(path), attack_packets())
    return path


@pytest.fixture
def config():
    # A fixed interface name keeps capture.initialize() from probing the machine's interfaces.
    return merge_config(Config(), {"capture": {"interface": "lo", "packet_limit": 5}})


@pytest.fixture(autouse=True)
def fresh_capture(monkeypatch):
    monkeypatch.setattr(capture, "STATE", capture.CaptureState())
    monkeypatch.setattr(capture, "validate_interface", lambda name: True)


# --- PCAP replay --------------------------------------------------------------


def test_run_pcap_processes_every_packet(config, attack_pcap):
    alerts = []
    stats = Pipeline(config, on_alert=alerts.append).run_pcap(attack_pcap)

    # packet_limit 5 is far smaller than the file, so this also checks replay waits for the consumer.
    assert stats.processed == 40
    assert stats.skipped == 2
    assert stats.errors == 0
    assert {a["rule"] for a in alerts} == {"port_scan", "syn_flood", "icmp_flood"}
    assert stats.alerts == len(alerts)
    assert stats.alerts_by_rule["port_scan"] == 1
    assert stats.finished_at is not None


def test_on_packet_hook_receives_packet_and_flow(config, attack_pcap):
    seen = []
    Pipeline(config, on_packet=lambda packet_dict, flow: seen.append((packet_dict["protocol"], flow["flow_id"]))).run_pcap(attack_pcap)
    assert len(seen) == 40
    assert seen[0] == ("TCP", "TCP:10.0.0.5:40001->10.0.0.1:1")


def test_failing_hook_does_not_stop_pipeline(config, attack_pcap):
    def broken(_alert):
        raise RuntimeError("boom")

    stats = Pipeline(config, on_alert=broken).run_pcap(attack_pcap)
    assert stats.processed == 40
    assert stats.alerts >= 3


def test_detection_settings_come_from_config(attack_pcap):
    config = merge_config(Config(), {"capture": {"interface": "lo"}, "detection": {"enabled": ["icmp_flood"]}})
    alerts = []
    Pipeline(config, on_alert=alerts.append).run_pcap(attack_pcap)
    assert {a["rule"] for a in alerts} == {"icmp_flood"}


def test_runs_are_independent(config, attack_pcap):
    first = Pipeline(config).run_pcap(attack_pcap).alerts
    # Cooldowns from the first run must not suppress alerts in the second.
    assert Pipeline(config).run_pcap(attack_pcap).alerts == first


def test_missing_pcap_raises_and_pipeline_stops(config, tmp_path):
    pipeline = Pipeline(config)
    with pytest.raises(FileNotFoundError):
        pipeline.run_pcap(tmp_path / "missing.pcap")
    assert not pipeline.running


def test_process_single_packet(config):
    pipeline = Pipeline(config)
    assert pipeline.process(Ether() / ARP()) == []
    assert pipeline.process("not a packet") == []
    assert (pipeline.stats.skipped, pipeline.stats.errors) == (1, 1)


# --- live capture (fake sniffer) ----------------------------------------------


class FakeSniffer:
    packets = []
    error = None

    def __init__(self, prn, **kwargs):
        self.prn = prn
        self.kwargs = kwargs
        self.exception = None
        self.running = False

    def start(self):
        self.running = True
        if FakeSniffer.error is not None:
            self.exception = FakeSniffer.error
            return
        self.continue_sniff = True
        for pkt in FakeSniffer.packets:
            self.prn(pkt)

    def stop(self):
        self.running = False


@pytest.fixture
def fake_sniffer(monkeypatch):
    FakeSniffer.packets = []
    FakeSniffer.error = None
    monkeypatch.setattr(scapy.sendrecv, "AsyncSniffer", FakeSniffer)
    return FakeSniffer


def test_live_capture(config, fake_sniffer):
    fake_sniffer.packets = attack_packets()
    config = merge_config(config, {"capture": {"packet_limit": 0}})
    alerts = []
    pipeline = Pipeline(config, on_alert=alerts.append)

    started = pipeline.start_live()
    assert started["running"] is True
    assert started["interface"] == "lo"
    stats = pipeline.stop()

    assert stats.processed == 40
    assert {a["rule"] for a in alerts} == {"port_scan", "syn_flood", "icmp_flood"}
    assert not pipeline.running
    assert capture.STATE.running is False


def test_live_capture_without_permission(config, fake_sniffer):
    fake_sniffer.error = PermissionError("Operation not permitted")
    pipeline = Pipeline(config)

    with pytest.raises(PermissionError, match="root/Administrator"):
        pipeline.start_live()
    assert not pipeline.running
    assert capture.STATE.running is False


def test_start_twice_is_refused(config, fake_sniffer):
    pipeline = Pipeline(config)
    pipeline.start_live()
    try:
        with pytest.raises(RuntimeError, match="already running"):
            pipeline.start_live()
    finally:
        pipeline.stop()


# --- command line -------------------------------------------------------------


def run_cli(args, capsys):
    code = main.main(args)
    out, err = capsys.readouterr()
    return code, out, err


@pytest.fixture
def cli_config(tmp_path):
    path = tmp_path / "ids.yaml"
    path.write_text(f"capture:\n  interface: lo\nlogging:\n  db_path: {tmp_path / 'ids.db'}\n", encoding="utf-8")
    return str(path)


def test_cli_stores_packets_and_alerts(attack_pcap, cli_config, tmp_path, capsys):
    code, out, _ = run_cli(["--pcap", str(attack_pcap), "--config", cli_config], capsys)
    assert code == 0
    assert f"Stored in         : {tmp_path / 'ids.db'}" in out

    with Database(tmp_path / "ids.db") as db:
        assert db.count_packets() == 40
        alerts = db.query_alerts()
        assert {a["rule"] for a in alerts} == {"port_scan", "syn_flood", "icmp_flood"}
        assert all(a["status"] == "new" for a in alerts)


def test_cli_json_alerts_include_alert_id(attack_pcap, cli_config, capsys):
    _, out, _ = run_cli(["--pcap", str(attack_pcap), "--config", cli_config, "--json"], capsys)
    assert all(isinstance(json.loads(line)["alert_id"], int) for line in out.splitlines())


def test_cli_no_db(attack_pcap, cli_config, tmp_path, capsys):
    code, out, _ = run_cli(["--pcap", str(attack_pcap), "--config", cli_config, "--no-db"], capsys)
    assert code == 0
    assert "Stored in" not in out
    assert not (tmp_path / "ids.db").exists()


def test_cli_pcap_prints_alerts_and_summary(attack_pcap, cli_config, capsys):
    code, out, _ = run_cli(["--pcap", str(attack_pcap), "--config", cli_config], capsys)
    assert code == 0
    assert "Port Scan" in out
    assert "10.0.0.5 -> 10.0.0.1:" in out
    assert "Packets processed : 40" in out
    assert "Packets skipped   : 2" in out


def test_cli_json_output(attack_pcap, cli_config, capsys):
    code, out, _ = run_cli(["--pcap", str(attack_pcap), "--config", cli_config, "--json"], capsys)
    alerts = [json.loads(line) for line in out.splitlines()]
    assert code == 0
    assert {a["rule"] for a in alerts} == {"port_scan", "syn_flood", "icmp_flood"}
    assert "Summary" not in out


def test_cli_config_error(tmp_path, capsys):
    bad = tmp_path / "bad.yaml"
    bad.write_text("dashboard:\n  port: 0\n", encoding="utf-8")
    code, _, err = run_cli(["--pcap", "x.pcap", "--config", str(bad)], capsys)
    assert code == 2
    assert "dashboard.port" in err


def test_cli_missing_pcap(tmp_path, cli_config, capsys):
    code, _, err = run_cli(["--pcap", str(tmp_path / "missing.pcap"), "--config", cli_config], capsys)
    assert code == 1
    assert "PCAP file not found" in err


def test_cli_live_without_permission(cli_config, fake_sniffer, capsys):
    fake_sniffer.error = PermissionError("Operation not permitted")
    code, _, err = run_cli(["--config", cli_config, "--duration", "0"], capsys)
    assert code == 1
    assert "root/Administrator" in err
