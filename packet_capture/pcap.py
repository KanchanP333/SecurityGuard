"""Offline packet replay helpers."""

from __future__ import annotations

from importlib import import_module
from pathlib import Path


def load_pcap(pcap_file: str | Path) -> list[object]:
	"""Load packets from a PCAP file and return them as Scapy Packet objects."""

	path = Path(pcap_file)
	if not path.exists():
		raise FileNotFoundError(f"PCAP file not found: {path}")

	rdpcap = import_module("scapy.utils").rdpcap
	return list(rdpcap(str(path)))


def replay_pcap(pcap_file: str | Path) -> list[object]:
	"""Return packets from a PCAP file for offline replay workflows."""

	return load_pcap(pcap_file)
