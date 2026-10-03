"""SYN flood detector."""

#This file implements a SYN flood detector that monitors TCP SYN and ACK packets from each source IP address to each destination IP address.
#If the number of SYN packets exceeds a defined threshold and the number of ACK packets is below a defined threshold, it generates an alert with severity and confidence scores based on the number of SYN and ACK packets.

from __future__ import annotations

from typing import Any


syn_tracker: dict[str, dict[str, Any]] = {}
SYN_THRESHOLD = 10
ACK_THRESHOLD = 2


def _score_alert(syn_count: int, ack_count: int) -> dict[str, Any]:
	imbalance = max(syn_count - ack_count, 0)
	severity = "Medium"
	if syn_count >= SYN_THRESHOLD * 3 and ack_count <= 1:
		severity = "Critical"
	elif syn_count >= SYN_THRESHOLD * 2 and ack_count <= ACK_THRESHOLD:
		severity = "High"
	confidence = min(0.72 + (imbalance * 0.02), 0.99)
	return {"severity": severity, "confidence": confidence}


def _build_alert(packet_dict: dict[str, Any], syn_count: int, ack_count: int) -> dict[str, Any]:
	scoring = _score_alert(syn_count, ack_count)
	tracker_key = f"{str(packet_dict.get('src_ip', '')).strip() or 'unknown'}->{str(packet_dict.get('dst_ip', '')).strip() or 'unknown'}"
	syn_tracker.setdefault(tracker_key, {}).update({"last_assessment": scoring})
	return {
		"src_ip": packet_dict.get("src_ip"),
		"dst_ip": packet_dict.get("dst_ip"),
		"attack_type": "SYN Flood",
		"severity": scoring["severity"],
		"confidence": scoring["confidence"],
		"description": f"High SYN volume detected ({syn_count} SYN packets, {ack_count} ACK packets).",
	}


def detect(packet_dict: dict[str, Any] | None, flow_object: dict[str, Any] | None) -> dict[str, Any] | None:
	packet = packet_dict or {}
	flow = flow_object or {}
	protocol = str(packet.get("protocol", "")).upper()
	flags = str(packet.get("flags", "")).upper()
	if protocol != "TCP":
		return None

	src_ip = str(packet.get("src_ip", "")).strip()
	dst_ip = str(packet.get("dst_ip", "")).strip()
	key = f"{src_ip}->{dst_ip}" if src_ip or dst_ip else "unknown"
	tracker = syn_tracker.setdefault(key, {"syn_count": 0, "ack_count": 0, "alerted": False})

	if "SYN" in flags and "ACK" not in flags:
		tracker["syn_count"] += 1
	if "ACK" in flags:
		tracker["ack_count"] += 1

	tracker["syn_count"] = max(tracker["syn_count"], int(flow.get("syn_count", tracker["syn_count"]) or tracker["syn_count"]))
	tracker["ack_count"] = max(tracker["ack_count"], int(flow.get("ack_count", tracker["ack_count"]) or tracker["ack_count"]))

	if tracker["syn_count"] >= SYN_THRESHOLD and tracker["ack_count"] <= ACK_THRESHOLD and not tracker["alerted"]:
		tracker["alerted"] = True
		return _build_alert(packet, tracker["syn_count"], tracker["ack_count"])

	return None
