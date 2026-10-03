"""Offline PCAP reading helpers."""

from __future__ import annotations

from importlib import import_module
from pathlib import Path
from typing import Iterator


def _require_file(pcap_file: str | Path) -> Path:
	path = Path(pcap_file)
	if not path.exists():
		raise FileNotFoundError(f"PCAP file not found: {path}")
	return path


def load_pcap(pcap_file: str | Path) -> list[object]:
	"""Load all packets from a PCAP file into memory as Scapy Packet objects."""

	path = _require_file(pcap_file)
	rdpcap = import_module("scapy.utils").rdpcap
	return list(rdpcap(str(path)))


def iter_pcap(pcap_file: str | Path) -> Iterator[object]:
	"""Yield packets from a PCAP file one at a time, without loading the whole file."""

	path = _require_file(pcap_file)
	PcapReader = import_module("scapy.utils").PcapReader
	with PcapReader(str(path)) as reader:
		yield from reader
