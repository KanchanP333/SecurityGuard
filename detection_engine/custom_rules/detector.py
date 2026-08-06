"""Custom rules detector."""

#This file implements a custom rules detector that allows users to define specific rules for detecting network traffic based on blocked ports,IPs, and protocols. 
#It maintains an in-memory tracker for each source IP to monitor matches against the defined rules. 
#When a match is detected, it generates an alert with a severity and confidence score based on the type of rule matched.
 
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any


custom_rules_tracker: dict[str, dict[str, Any]] = {}
blocked_ports: set[int] = set()
blocked_ips: set[str] = set()
blocked_protocols: set[str] = set()


def _score_alert(reason: str) -> dict[str, Any]:
	severity = "Medium"
	confidence = 0.8
	if "port" in reason.lower():
		severity = "High"
		confidence = 0.9
	elif "protocol" in reason.lower():
		severity = "High"
		confidence = 0.88
	elif "ip" in reason.lower():
		confidence = 0.87
	return {"severity": severity, "confidence": confidence}


def set_rules(
	*,
	ports: set[int] | None = None,
	ips: set[str] | None = None,
	protocols: set[str] | None = None,
) -> None:
	"""Set the in-memory custom rules used by this detector."""

	global blocked_ports, blocked_ips, blocked_protocols
	if ports is not None:
		blocked_ports = {int(port) for port in ports}
	if ips is not None:
		blocked_ips = {str(ip).strip() for ip in ips if str(ip).strip()}
	if protocols is not None:
		blocked_protocols = {str(protocol).upper() for protocol in protocols if str(protocol).strip()}


def _build_alert(packet_dict: dict[str, Any], reason: str) -> dict[str, Any]:
	scoring = _score_alert(reason)
	tracker_key = str(packet_dict.get("src_ip", "")).strip() or "unknown"
	custom_rules_tracker.setdefault(tracker_key, {}).update({"last_assessment": scoring})
	return {
		"timestamp": packet_dict.get("timestamp") or datetime.now(timezone.utc).isoformat(),
		"source_ip": packet_dict.get("src_ip"),
		"destination_ip": packet_dict.get("dst_ip"),
		"attack_type": "Custom Rule",
		"severity": scoring["severity"],
		"confidence": scoring["confidence"],
		"description": reason,
	}


def detect(packet_dict: dict[str, Any] | None, flow_object: dict[str, Any] | None) -> dict[str, Any] | None:
	packet = packet_dict or {}
	protocol = str(packet.get("protocol", "")).upper()
	src_ip = str(packet.get("src_ip", "")).strip()
	dst_ip = str(packet.get("dst_ip", "")).strip()
	dst_port_raw = packet.get("dst_port")
	try:
		dst_port = int(dst_port_raw) if dst_port_raw is not None else None
	except (TypeError, ValueError):
		dst_port = None

	tracker = custom_rules_tracker.setdefault(src_ip or "unknown", {"matches": 0, "alerted": False})
	if dst_port is not None and dst_port in blocked_ports:
		tracker["matches"] += 1
		tracker["last_reason"] = f"Blocked port matched: {dst_port}."
		return _build_alert(packet, tracker["last_reason"])

	if src_ip and src_ip in blocked_ips:
		tracker["matches"] += 1
		tracker["last_reason"] = f"Blocked source IP matched: {src_ip}."
		return _build_alert(packet, tracker["last_reason"])

	if dst_ip and dst_ip in blocked_ips:
		tracker["matches"] += 1
		tracker["last_reason"] = f"Blocked destination IP matched: {dst_ip}."
		return _build_alert(packet, tracker["last_reason"])

	if protocol and protocol in blocked_protocols:
		tracker["matches"] += 1
		tracker["last_reason"] = f"Blocked protocol matched: {protocol}."
		return _build_alert(packet, tracker["last_reason"])

	return None
