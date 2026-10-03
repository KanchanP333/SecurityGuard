"""Unit tests for capture configuration, queueing and PCAP replay."""

import pytest
from scapy.layers.inet import IP, TCP
from scapy.utils import wrpcap

from configuration import CaptureSettings, Config, set_config
from packet_capture import capture


@pytest.fixture(autouse=True)
def fresh_state(monkeypatch):
	monkeypatch.setattr(capture, "STATE", capture.CaptureState())
	for name in ("CAPTURE_INTERFACE", "CAPTURE_FILTER", "CAPTURE_QUEUE_SIZE", "DEFAULT_INTERFACE"):
		monkeypatch.delenv(name, raising=False)
	monkeypatch.setattr(capture, "validate_interface", lambda name: name in {"eth0", "wlan0"})
	monkeypatch.setattr(capture, "get_default_interface", lambda: "eth0")


def test_reads_capture_settings():
	snapshot = capture.initialize(CaptureSettings(interface="wlan0", filter="tcp or icmp", packet_limit=50))

	assert snapshot == {"interface": "wlan0", "filter": "tcp or icmp", "queue_size": 50, "running": False}
	assert capture.get_packet_queue().maxsize == 50


def test_uses_shared_config_by_default():
	set_config(Config(capture=CaptureSettings(interface="wlan0", packet_limit=7)))
	try:
		snapshot = capture.initialize()
	finally:
		set_config(Config())
	assert snapshot["interface"] == "wlan0"
	assert snapshot["queue_size"] == 7


def test_env_overrides_settings(monkeypatch):
	monkeypatch.setenv("CAPTURE_INTERFACE", "eth0")
	monkeypatch.setenv("CAPTURE_FILTER", "udp")
	monkeypatch.setenv("CAPTURE_QUEUE_SIZE", "5")
	snapshot = capture.initialize(CaptureSettings(interface="wlan0", filter="tcp", packet_limit=50))

	assert snapshot["interface"] == "eth0"
	assert snapshot["filter"] == "udp"
	assert snapshot["queue_size"] == 5


def test_unknown_interface_falls_back_to_default():
	assert capture.initialize(CaptureSettings(interface="Wi-Fi"))["interface"] == "eth0"


def test_empty_interface_auto_detects():
	assert capture.initialize(CaptureSettings(interface=""))["interface"] == "eth0"


def test_empty_filter_means_no_filter():
	assert capture.initialize(CaptureSettings(filter=""))["filter"] is None


def test_invalid_filter_raises():
	with pytest.raises(ValueError):
		capture.initialize(CaptureSettings(filter="port 99999"))


def test_capture_packet_drops_when_queue_full():
	capture.initialize(CaptureSettings(packet_limit=1))
	pkt = IP() / TCP()

	capture.capture_packet(pkt)
	capture.capture_packet(pkt)

	assert capture.get_packet_queue().qsize() == 1
	assert capture.STATE.dropped == 1


def test_replay_pcap_queues_all_packets(tmp_path):
	capture.initialize(CaptureSettings(packet_limit=0))
	pcap_path = tmp_path / "replay.pcap"
	packets = [IP(dst=f"10.0.0.{i}") / TCP(dport=80) for i in range(1, 6)]
	wrpcap(str(pcap_path), packets)

	count = capture.replay_pcap(pcap_path)

	queue = capture.get_packet_queue()
	assert count == 5
	assert [queue.get_nowait()[IP].dst for _ in range(5)] == [f"10.0.0.{i}" for i in range(1, 6)]
	assert capture.STATE.running is False
	assert capture.STATE.stop_event.is_set()
	assert capture.STATE.source == "pcap"


def test_replay_refused_while_running(tmp_path):
	capture.STATE.running = True
	with pytest.raises(RuntimeError):
		capture.replay_pcap(tmp_path / "any.pcap")
