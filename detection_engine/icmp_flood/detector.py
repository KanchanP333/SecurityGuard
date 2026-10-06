"""ICMP flood detector."""

#This file implements an ICMP flood detector that checks the ICMP packet rate of each source IP address, as measured by the traffic analyzer.
#The rate comes from packet timestamps, so offline PCAP replay gives the same result as live capture.
#If the rate exceeds the configured threshold, it generates an alert with severity and confidence scores based on the rate of packets.

from __future__ import annotations

from typing import Any


def _score_alert(rate: float, threshold: float) -> dict[str, Any]:
	severity = "Medium"
	if rate >= threshold * 3:
		severity = "Critical"
	elif rate >= threshold * 2:
		severity = "High"
	confidence = min(0.7 + (rate - threshold) / threshold * 0.1, 0.99)
	return {"severity": severity, "confidence": confidence}


def detect(packet_dict: dict[str, Any], flow_object: dict[str, Any], settings: Any) -> dict[str, Any] | None:
	if packet_dict.get("protocol") != "ICMP":
		return None

	window = flow_object.get("src_window") or {}
	rate = float(window.get("icmp_pps", 0.0))
	threshold = settings.icmp_flood.pps_threshold
	if rate < threshold:
		return None

	return {
		"attack_type": "ICMP Flood",
		**_score_alert(rate, threshold),
		"description": f"ICMP packet rate of {rate:.2f} packets per second exceeded the threshold of {threshold:g}.",
		"dedup_key": packet_dict.get("src_ip"),
	}
