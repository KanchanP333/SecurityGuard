"""Unit tests for capture configuration, queueing and PCAP replay."""

import pytest
from scapy.layers.inet import IP, TCP
from scapy.utils import wrpcap

from packet_capture import capture


@pytest.fixture(autouse=True)
def fresh_state(monkeypatch):
	monkeypatch.setattr(capture, "STATE", capture.CaptureState())
	for name in ("CAPTURE_CONFIG", "CAPTURE_INTERFACE", "CAPTURE_FILTER", "CAPTURE_QUEUE_SIZE", "DEFAULT_INTERFACE"):
		monkeypatch.delenv(name, raising=False)
	monkeypatch.setattr(capture, "validate_interface", lambda name: name in {"eth0", "wlan0"})
	monkeypatch.setattr(capture, "get_default_interface", lambda: "eth0")


@pytest.fixture
def config_file(tmp_path, monkeypatch):
	def write(text):
		path = tmp_path / "capture.yaml"
		path.write_text(text, encoding="utf-8")
		monkeypatch.setenv("CAPTURE_CONFIG", str(path))
		return path

	return write


def test_reads_yaml_config(config_file):
	config_file("capture:\n  interface: wlan0\n  filter: tcp or icmp\n  packet_limit: 50\n")
	snapshot = capture.initialize()

	assert snapshot == {"interface": "wlan0", "filter": "tcp or icmp", "queue_size": 50, "running": False}
	assert capture.get_packet_queue().maxsize == 50


def test_env_overrides_yaml(config_file, monkeypatch):
	config_file("capture:\n  interface: wlan0\n  filter: tcp\n  packet_limit: 50\n")
	monkeypatch.setenv("CAPTURE_INTERFACE", "eth0")
	monkeypatch.setenv("CAPTURE_FILTER", "udp")
	monkeypatch.setenv("CAPTURE_QUEUE_SIZE", "5")
	snapshot = capture.initialize()

	assert snapshot["interface"] == "eth0"
	assert snapshot["filter"] == "udp"
	assert snapshot["queue_size"] == 5


def test_unknown_interface_falls_back_to_default(config_file):
	config_file("capture:\n  interface: Wi-Fi\n")
	assert capture.initialize()["interface"] == "eth0"


def test_empty_filter_means_no_filter(config_file):
	config_file('capture:\n  filter: ""\n')
	assert capture.initialize()["filter"] is None


def test_invalid_filter_raises(config_file):
	config_file("capture:\n  filter: port 99999\n")
	with pytest.raises(ValueError):
		capture.initialize()


def test_capture_packet_drops_when_queue_full(config_file):
	config_file("capture:\n  packet_limit: 1\n")
	capture.initialize()
	pkt = IP() / TCP()

	capture.capture_packet(pkt)
	capture.capture_packet(pkt)

	assert capture.get_packet_queue().qsize() == 1
	assert capture.STATE.dropped == 1


def test_replay_pcap_queues_all_packets(config_file, tmp_path):
	config_file("capture:\n  packet_limit: 0\n")
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
