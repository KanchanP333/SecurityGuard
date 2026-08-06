"""Port scan detector."""

#This file implements a port scan detector that monitors TCP SYN packets from each source IP address.
#If the number of unique destination ports accessed by a source IP exceeds a defined threshold, it generates an alert with severity and confidence scores based on the number of unique ports accessed.

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any


port_scan_tracker: dict[str, dict[str, Any]] = {}
PORT_SCAN_THRESHOLD = 7


def _score_alert(port_count: int) -> dict[str, Any]:
	over_threshold = max(port_count - PORT_SCAN_THRESHOLD, 0)
	severity = "Medium"
	if port_count >= PORT_SCAN_THRESHOLD * 3:
		severity = "Critical"
	elif port_count >= PORT_SCAN_THRESHOLD * 2:
		severity = "High"
	confidence = min(0.75 + (over_threshold * 0.05), 0.99)
	return {"severity": severity, "confidence": confidence}


def _build_alert(packet_dict: dict[str, Any], port_count: int) -> dict[str, Any]:
	scoring = _score_alert(port_count)
	tracker = port_scan_tracker.setdefault(str(packet_dict.get("src_ip", "")).strip() or "unknown", {})
	tracker["last_assessment"] = scoring
	return {
		"timestamp": packet_dict.get("timestamp") or datetime.now(timezone.utc).isoformat(),
		"source_ip": packet_dict.get("src_ip"),
		"destination_ip": packet_dict.get("dst_ip"),
		"attack_type": "Port Scan",
		"severity": scoring["severity"],
		"confidence": scoring["confidence"],
		"description": f"Multiple TCP SYN packets were sent to {port_count} unique destination ports.",
	}


def detect(packet_dict: dict[str, Any] | None, flow_object: dict[str, Any] | None) -> dict[str, Any] | None:
	packet = packet_dict or {}
	flow = flow_object or {}
	protocol = str(packet.get("protocol", "")).upper()
	flags = str(packet.get("flags", "")).upper()
	if protocol != "TCP" or "SYN" not in flags or "ACK" in flags:
		return None

	src_ip = str(packet.get("src_ip", "")).strip()
	dst_port = packet.get("dst_port")
	if not src_ip or dst_port is None:
		return None

	tracker = port_scan_tracker.setdefault(src_ip, {"destination_ports": set(), "alerted": False})
	destination_ports = tracker["destination_ports"]
	if dst_port not in destination_ports:
		destination_ports.add(dst_port)

	flow_unique_ports = int(flow.get("unique_ports", 0) or 0)
	port_count = max(len(destination_ports), flow_unique_ports)
	if port_count >= PORT_SCAN_THRESHOLD and not tracker["alerted"]:
		tracker["alerted"] = True
		tracker["last_count"] = port_count
		return _build_alert(packet, port_count)

	tracker["last_count"] = port_count
	return None
