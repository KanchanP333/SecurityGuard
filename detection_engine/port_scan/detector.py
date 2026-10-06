"""Port scan detector."""

#This file implements a port scan detector based on the traffic analyzer's per-source sliding window.
#If a source IP makes connection attempts to more distinct destination ports than the configured threshold within the window, it generates an alert with severity and confidence scores based on the number of ports.
#The window spans all of the source's connections, so scans that use a new source port for every probe are still counted.

from __future__ import annotations

from typing import Any


def _score_alert(port_count: int, threshold: int) -> dict[str, Any]:
	severity = "Medium"
	if port_count >= threshold * 3:
		severity = "Critical"
	elif port_count >= threshold * 2:
		severity = "High"
	confidence = min(0.75 + (port_count - threshold) * 0.05, 0.99)
	return {"severity": severity, "confidence": confidence}


def detect(packet_dict: dict[str, Any], flow_object: dict[str, Any], settings: Any) -> dict[str, Any] | None:
	window = flow_object.get("src_window") or {}
	port_count = int(window.get("unique_dst_ports", 0))
	threshold = settings.port_scan.unique_ports_threshold
	if port_count < threshold:
		return None

	return {
		"attack_type": "Port Scan",
		**_score_alert(port_count, threshold),
		"description": f"Connection attempts to {port_count} distinct destination ports in the last {window.get('window_seconds')}s.",
		"dedup_key": packet_dict.get("src_ip"),
	}
