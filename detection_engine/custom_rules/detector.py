"""Custom rules detector."""

#This file implements a custom rules detector driven by the detection.custom_rules section of the configuration.
#It flags traffic to blocked ports, from or to blocked IPs, using blocked protocols, and connection attempts to suspicious ports (common backdoor and botnet ports).
#When a rule matches, it generates an alert with a severity and confidence score based on the type of rule matched.

from __future__ import annotations

from typing import Any


def _alert(reason: str, severity: str, confidence: float, dedup_key: str) -> dict[str, Any]:
	return {
		"attack_type": "Custom Rule",
		"severity": severity,
		"confidence": confidence,
		"description": reason,
		"dedup_key": dedup_key,
	}


def detect(packet_dict: dict[str, Any], flow_object: dict[str, Any], settings: Any) -> dict[str, Any] | None:
	rules = settings.custom_rules
	protocol = packet_dict.get("protocol")
	src_ip = packet_dict.get("src_ip")
	dst_ip = packet_dict.get("dst_ip")
	dst_port = packet_dict.get("dst_port")

	if dst_port is not None and dst_port in rules.blocked_ports:
		return _alert(f"Blocked port matched: {dst_port}.", "High", 0.9, f"{src_ip}:port:{dst_port}")

	if src_ip and src_ip in rules.blocked_ips:
		return _alert(f"Blocked source IP matched: {src_ip}.", "Medium", 0.87, f"{src_ip}:src")

	if dst_ip and dst_ip in rules.blocked_ips:
		return _alert(f"Blocked destination IP matched: {dst_ip}.", "Medium", 0.87, f"{src_ip}:dst:{dst_ip}")

	if protocol and protocol in rules.blocked_protocols:
		return _alert(f"Blocked protocol matched: {protocol}.", "High", 0.88, f"{src_ip}:protocol:{protocol}")

	if dst_port is not None and dst_port in rules.suspicious_ports:
		flags = set((packet_dict.get("flags") or "").split(","))
		is_attempt = protocol == "UDP" or ("SYN" in flags and "ACK" not in flags)
		if is_attempt:
			return _alert(f"Connection attempt to suspicious port {dst_port}.", "Medium", 0.7, f"{src_ip}:suspicious:{dst_port}")

	return None
