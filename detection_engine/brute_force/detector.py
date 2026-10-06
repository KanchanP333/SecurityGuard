"""Brute force detector for login services (SSH, FTP, Telnet, RDP by default)."""

#This file implements brute force detection for the service ports listed in the configuration.
#It counts new connection attempts (TCP SYN without ACK) from each source IP to each destination IP and service port within a sliding time window.
#If the number of attempts reaches the configured threshold, it generates an alert with severity and confidence scores based on the number of attempts.

from __future__ import annotations

from collections import OrderedDict, deque
from datetime import datetime
import time
from typing import Any


SERVICE_NAMES = {21: "FTP", 22: "SSH", 23: "Telnet", 3389: "RDP"}
MAX_TRACKED_KEYS = 50_000
MAX_ATTEMPTS_PER_KEY = 10_000

# "src->dst:port" -> timestamps (epoch seconds) of recent connection attempts, least recently updated first.
attempt_tracker: OrderedDict[str, deque[float]] = OrderedDict()


def reset() -> None:
	attempt_tracker.clear()


def _epoch(value: Any) -> float:
	if isinstance(value, datetime):
		return value.timestamp()
	if isinstance(value, (int, float)):
		return float(value)
	return time.time()


def _score_alert(attempt_count: int, threshold: int) -> dict[str, Any]:
	severity = "Medium"
	if attempt_count >= threshold * 3:
		severity = "Critical"
	elif attempt_count >= threshold * 2:
		severity = "High"
	confidence = min(0.74 + (attempt_count - threshold) * 0.04, 0.99)
	return {"severity": severity, "confidence": confidence}


def _evict(now: float, window_seconds: float) -> None:
	while attempt_tracker:
		oldest = next(iter(attempt_tracker.values()))
		if (oldest and now - oldest[-1] <= window_seconds) and len(attempt_tracker) <= MAX_TRACKED_KEYS:
			break
		attempt_tracker.popitem(last=False)


def detect(packet_dict: dict[str, Any], flow_object: dict[str, Any], settings: Any) -> dict[str, Any] | None:
	config = settings.brute_force
	dst_port = packet_dict.get("dst_port")
	if packet_dict.get("protocol") != "TCP" or dst_port not in config.ports:
		return None

	flags = set((packet_dict.get("flags") or "").split(","))
	if "SYN" not in flags or "ACK" in flags:
		return None

	now = _epoch(packet_dict.get("timestamp"))
	key = f"{packet_dict.get('src_ip')}->{packet_dict.get('dst_ip')}:{dst_port}"
	attempts = attempt_tracker.get(key)
	if attempts is None:
		attempts = deque(maxlen=MAX_ATTEMPTS_PER_KEY)
		attempt_tracker[key] = attempts
	else:
		attempt_tracker.move_to_end(key)

	attempts.append(now)
	while attempts and now - attempts[0] > config.window_seconds:
		attempts.popleft()
	_evict(now, config.window_seconds)

	attempt_count = len(attempts)
	if attempt_count < config.attempts_threshold:
		return None

	service = SERVICE_NAMES.get(dst_port, f"port {dst_port}")
	return {
		"attack_type": "Brute Force",
		**_score_alert(attempt_count, config.attempts_threshold),
		"description": f"Repeated {service} connection attempts detected ({attempt_count} attempts in the last {config.window_seconds}s).",
		"dedup_key": key,
	}
