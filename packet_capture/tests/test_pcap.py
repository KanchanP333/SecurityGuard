"""Unit tests for PCAP reading helpers."""

import pytest
from scapy.layers.inet import IP, TCP, UDP
from scapy.utils import wrpcap

from packet_capture.pcap import iter_pcap, load_pcap


@pytest.fixture
def pcap_file(tmp_path):
	path = tmp_path / "sample.pcap"
	wrpcap(str(path), [IP(dst="10.0.0.1") / TCP(dport=80), IP(dst="10.0.0.2") / UDP(dport=53)])
	return path


def test_load_pcap(pcap_file):
	packets = load_pcap(pcap_file)
	assert len(packets) == 2
	assert packets[0][IP].dst == "10.0.0.1"


def test_iter_pcap(pcap_file):
	packets = list(iter_pcap(pcap_file))
	assert [p[IP].dst for p in packets] == ["10.0.0.1", "10.0.0.2"]


def test_missing_file_raises(tmp_path):
	with pytest.raises(FileNotFoundError):
		load_pcap(tmp_path / "missing.pcap")
	with pytest.raises(FileNotFoundError):
		list(iter_pcap(tmp_path / "missing.pcap"))
