"""Brute force detector focused on SSH."""

#This file is for brute force detection, specifically targeting SSH connections. 
#It monitors the number of connection attempts from a source IP to a destination IP on the SSH port (22). 
#If the number of attempts exceeds a defined threshold, it generates an alert with severity and confidence scores based on the number of attempts.

from __future__ import annotations

from typing import Any


brute_force_tracker: dict[str, dict[str, Any]] = {}
SSH_PORT = 22
BRUTE_FORCE_THRESHOLD = 5


def _score_alert(attempt_count: int) -> dict[str, Any]:
	severity = "Medium"
	if attempt_count >= BRUTE_FORCE_THRESHOLD * 3:
		severity = "Critical"
	elif attempt_count >= BRUTE_FORCE_THRESHOLD * 2:
		severity = "High"
	confidence = min(0.74 + max(attempt_count - BRUTE_FORCE_THRESHOLD, 0) * 0.04, 0.99)
	return {"severity": severity, "confidence": confidence}


def _build_alert(packet_dict: dict[str, Any], attempt_count: int) -> dict[str, Any]:
	scoring = _score_alert(attempt_count)
	tracker_key = f"{str(packet_dict.get('src_ip', '')).strip() or 'unknown'}->{str(packet_dict.get('dst_ip', '')).strip() or 'unknown'}:{SSH_PORT}"
	brute_force_tracker.setdefault(tracker_key, {}).update({"last_assessment": scoring})
	return {
		"src_ip": packet_dict.get("src_ip"),
		"dst_ip": packet_dict.get("dst_ip"),
		"attack_type": "Brute Force",
		"severity": scoring["severity"],
		"confidence": scoring["confidence"],
		"description": f"Repeated SSH connection attempts detected ({attempt_count} attempts).",
	}


def detect(packet_dict: dict[str, Any] | None, flow_object: dict[str, Any] | None) -> dict[str, Any] | None:
	packet = packet_dict or {}
	flow = flow_object or {}
	protocol = str(packet.get("protocol", "")).upper()
	dst_port = packet.get("dst_port")
	if protocol != "TCP" or int(dst_port or 0) != SSH_PORT:
		return None

	flags = str(packet.get("flags", "")).upper()
	src_ip = str(packet.get("src_ip", "")).strip() or "unknown"
	dst_ip = str(packet.get("dst_ip", "")).strip() or "unknown"
	key = f"{src_ip}->{dst_ip}:{SSH_PORT}"
	tracker = brute_force_tracker.setdefault(key, {"attempt_count": 0, "alerted": False})

	if "SYN" in flags or not flags:
		tracker["attempt_count"] += 1

	tracker["attempt_count"] = max(
		tracker["attempt_count"],
		int(flow.get("packet_count", tracker["attempt_count"]) or tracker["attempt_count"]),
	)

	if tracker["attempt_count"] >= BRUTE_FORCE_THRESHOLD and not tracker["alerted"]:
		tracker["alerted"] = True
		return _build_alert(packet, tracker["attempt_count"])

	return None
