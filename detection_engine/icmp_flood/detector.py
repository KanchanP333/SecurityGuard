"""ICMP flood detector."""

#This file implements an ICMP flood detector that monitors the rate of ICMP packets from each source IP address.
#If the rate exceeds a defined threshold, it generates an alert with severity and confidence scores based on the rate of packets.


from __future__ import annotations

from collections import deque
from datetime import datetime, timezone
from time import monotonic
from typing import Any


icmp_tracker: dict[str, dict[str, Any]] = {}
ICMP_RATE_THRESHOLD = 20.0
RATE_WINDOW_SECONDS = 1.0


def _score_alert(rate: float) -> dict[str, Any]:
	severity = "Medium"
	if rate >= ICMP_RATE_THRESHOLD * 3:
		severity = "Critical"
	elif rate >= ICMP_RATE_THRESHOLD * 2:
		severity = "High"
	confidence = min(0.7 + max(rate - ICMP_RATE_THRESHOLD, 0) * 0.01, 0.99)
	return {"severity": severity, "confidence": confidence}


def _build_alert(packet_dict: dict[str, Any], rate: float) -> dict[str, Any]:
	scoring = _score_alert(rate)
	src_key = str(packet_dict.get("src_ip", "")).strip() or "unknown"
	icmp_tracker.setdefault(src_key, {}).update({"last_assessment": scoring})
	return {
		"timestamp": packet_dict.get("timestamp") or datetime.now(timezone.utc).isoformat(),
		"source_ip": packet_dict.get("src_ip"),
		"destination_ip": packet_dict.get("dst_ip"),
		"attack_type": "ICMP Flood",
		"severity": scoring["severity"],
		"confidence": scoring["confidence"],
		"description": f"ICMP packet rate exceeded the threshold at {rate:.2f} packets per second.",
	}


def detect(packet_dict: dict[str, Any] | None, flow_object: dict[str, Any] | None) -> dict[str, Any] | None:
	packet = packet_dict or {}
	flow = flow_object or {}
	protocol = str(packet.get("protocol", "")).upper()
	if protocol != "ICMP":
		return None

	src_ip = str(packet.get("src_ip", "")).strip() or "unknown"
	tracker = icmp_tracker.setdefault(src_ip, {"timestamps": deque(), "alerted": False})
	current_time = monotonic()
	timestamps: deque[float] = tracker["timestamps"]
	timestamps.append(current_time)
	while timestamps and current_time - timestamps[0] > RATE_WINDOW_SECONDS:
		timestamps.popleft()

	packet_count = int(flow.get("packet_count", len(timestamps)) or len(timestamps))
	duration = float(flow.get("duration", RATE_WINDOW_SECONDS) or RATE_WINDOW_SECONDS)
	if duration <= 0:
		duration = RATE_WINDOW_SECONDS
	rate = max(packet_count / duration, len(timestamps) / RATE_WINDOW_SECONDS)
	tracker["last_rate"] = rate

	if rate >= ICMP_RATE_THRESHOLD and not tracker["alerted"]:
		tracker["alerted"] = True
		return _build_alert(packet, rate)

	return None
