"""Unit tests for capture statistics."""

from scapy.layers.inet import IP, TCP

from packet_capture.stats import get_stats, reset_stats, update_stats


def test_reset_stats():
	update_stats(IP() / TCP())
	stats = reset_stats()
	assert stats == {"packets": 0, "bytes": 0, "start_time": None, "running_time": 0}


def test_update_stats_counts_packets_and_bytes():
	reset_stats()
	pkt = IP() / TCP()
	update_stats(pkt)
	stats = update_stats(pkt)

	assert stats["packets"] == 2
	assert stats["bytes"] == 2 * len(pkt)
	assert stats["start_time"] is not None


def test_update_stats_handles_none():
	reset_stats()
	stats = update_stats(None)
	assert stats["packets"] == 1
	assert stats["bytes"] == 0


def test_get_stats_returns_copy():
	reset_stats()
	snapshot = get_stats()
	snapshot["packets"] = 999
	assert get_stats()["packets"] == 0
