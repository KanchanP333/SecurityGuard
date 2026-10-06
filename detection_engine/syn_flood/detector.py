"""SYN flood detector."""

#This file implements a SYN flood detector based on the traffic analyzer's per-source sliding window.
#If a source sends more SYN packets than the configured threshold within the window while completing few handshakes (ACK packets at or below the ACK threshold), it generates an alert with severity and confidence scores based on the SYN/ACK imbalance.
#The window spans all of the source's connections, so floods that randomise the source port are still counted.

from __future__ import annotations

from typing import Any


def _score_alert(syn_count: int, ack_count: int, syn_threshold: int, ack_threshold: int) -> dict[str, Any]:
	imbalance = max(syn_count - ack_count, 0)
	severity = "Medium"
	if syn_count >= syn_threshold * 3 and ack_count <= 1:
		severity = "Critical"
	elif syn_count >= syn_threshold * 2 and ack_count <= ack_threshold:
		severity = "High"
	confidence = min(0.72 + (imbalance - syn_threshold) * 0.02, 0.99)
	return {"severity": severity, "confidence": max(confidence, 0.72)}


def detect(packet_dict: dict[str, Any], flow_object: dict[str, Any], settings: Any) -> dict[str, Any] | None:
	if packet_dict.get("protocol") != "TCP":
		return None

	window = flow_object.get("src_window") or {}
	syn_count = int(window.get("syn_count", 0))
	ack_count = int(window.get("ack_count", 0))
	config = settings.syn_flood
	if syn_count < config.syn_threshold or ack_count > config.ack_threshold:
		return None

	return {
		"attack_type": "SYN Flood",
		**_score_alert(syn_count, ack_count, config.syn_threshold, config.ack_threshold),
		"description": f"High SYN volume in the last {window.get('window_seconds')}s ({syn_count} SYN packets, {ack_count} ACK packets).",
		"dedup_key": packet_dict.get("src_ip"),
	}
