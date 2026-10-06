"""Detection engine dispatcher."""

#This file serves as the main dispatcher for the detection engine. It manages the loading and execution of the detector modules: port scan, SYN flood, ICMP flood, brute force, custom rules and signatures.
#The dispatcher runs the detectors enabled in the configuration against each packet_dict and flow_object (see docs/CONTRACTS.md), passing them the detection settings.
#It fills the shared alert fields and applies a per-alert cooldown, so an ongoing attack produces one alert per cooldown period instead of one per packet.

from __future__ import annotations

from datetime import datetime, timezone
from importlib import util
from pathlib import Path
import time
from types import ModuleType
from typing import Any, Iterable

from configuration import DetectionSettings, get_config


def _detector_path(*candidates: str) -> Path:
	base_path = Path(__file__).resolve().parent
	for candidate in candidates:
		candidate_path = base_path / candidate / "detector.py"
		if candidate_path.exists():
			return candidate_path
	raise FileNotFoundError(f"Unable to locate detector path for: {', '.join(candidates)}")


_DETECTOR_FILES = {
	"port_scan": _detector_path("port_scan", "port-scan"),
	"syn_flood": _detector_path("syn_flood", "syn-flood"),
	"icmp_flood": _detector_path("icmp_flood", "icmp-flood"),
	"brute_force": _detector_path("brute_force", "brute-force"),
	"custom_rules": _detector_path("custom_rules", "custom-rules"),
	"signatures": _detector_path("signatures"),
}

_MODULE_CACHE: dict[str, ModuleType] = {}

# (rule, dedup_key) -> packet time (epoch seconds) of the last alert raised for it.
_LAST_ALERT: dict[tuple[str, str], float] = {}
_MAX_COOLDOWN_ENTRIES = 50_000


def _load_detector_module(detector_name: str) -> ModuleType:
	"""Load and cache a detector module from its file path."""

	if detector_name in _MODULE_CACHE:
		return _MODULE_CACHE[detector_name]

	detector_path = _DETECTOR_FILES[detector_name]
	spec = util.spec_from_file_location(f"detection_engine_{detector_name}", detector_path)
	if spec is None or spec.loader is None:
		raise ImportError(f"Unable to load detector: {detector_name}")

	module = util.module_from_spec(spec)
	spec.loader.exec_module(module)
	_MODULE_CACHE[detector_name] = module
	return module


def reset() -> None:
	"""Clear cooldowns and all detector state (used between PCAP runs and in tests)."""

	_LAST_ALERT.clear()
	for module in _MODULE_CACHE.values():
		reset_detector = getattr(module, "reset", None)
		if callable(reset_detector):
			reset_detector()


def _epoch(value: Any) -> float:
	if isinstance(value, datetime):
		return value.timestamp()
	if isinstance(value, (int, float)):
		return float(value)
	return time.time()


def _iso_timestamp(value: Any) -> str:
	"""Convert a packet timestamp (datetime, epoch seconds, or ISO string) to an ISO 8601 UTC string."""

	if isinstance(value, datetime):
		return value.astimezone(timezone.utc).isoformat()
	if isinstance(value, (int, float)):
		return datetime.fromtimestamp(value, tz=timezone.utc).isoformat()
	if isinstance(value, str) and value:
		return value
	return datetime.now(timezone.utc).isoformat()


def _in_cooldown(key: tuple[str, str], now: float, cooldown_seconds: float) -> bool:
	"""Return True if this alert was already raised within the cooldown; otherwise record it."""

	last = _LAST_ALERT.get(key)
	if last is not None and 0 <= now - last < cooldown_seconds:
		return True

	_LAST_ALERT[key] = now
	if len(_LAST_ALERT) > _MAX_COOLDOWN_ENTRIES:
		for stale_key in [k for k, t in _LAST_ALERT.items() if now - t >= cooldown_seconds]:
			del _LAST_ALERT[stale_key]
	return False


def _finalize_alert(
	alert: dict[str, Any],
	detector_name: str,
	packet_data: dict[str, Any],
	flow_data: dict[str, Any],
) -> dict[str, Any]:
	"""Fill the shared alert_object fields (see docs/CONTRACTS.md) that detectors leave out."""

	alert.setdefault("alert_id", None)
	alert["timestamp"] = _iso_timestamp(alert.get("timestamp") or packet_data.get("timestamp"))
	alert["rule"] = detector_name
	alert.setdefault("src_ip", packet_data.get("src_ip"))
	alert.setdefault("dst_ip", packet_data.get("dst_ip"))
	alert.setdefault("dst_port", packet_data.get("dst_port"))
	alert.setdefault("protocol", packet_data.get("protocol"))
	alert.setdefault("flow_id", flow_data.get("flow_id"))
	alert["confidence"] = round(float(alert.get("confidence", 0.0)), 2)
	return alert


def _normalize_enabled_detectors(enabled_detectors: Iterable[str]) -> list[str]:
	ordered_detectors: list[str] = []
	for detector_name in enabled_detectors:
		if detector_name in _DETECTOR_FILES and detector_name not in ordered_detectors:
			ordered_detectors.append(detector_name)
	return ordered_detectors


def run_engine(
	packet_dict: dict[str, Any] | None,
	flow_object: dict[str, Any] | None,
	enabled_detectors: Iterable[str] | None = None,
	settings: DetectionSettings | None = None,
) -> list[dict[str, Any]]:
	"""Run enabled detectors against a packet and its flow object and collect alerts.

	settings defaults to the shared configuration (get_config().detection), and
	enabled_detectors defaults to settings.enabled.
	"""

	if settings is None:
		settings = get_config().detection
	if enabled_detectors is None:
		enabled_detectors = settings.enabled

	packet_data = packet_dict or {}
	flow_data = flow_object or {}
	now = _epoch(packet_data.get("timestamp"))
	alerts: list[dict[str, Any]] = []

	for detector_name in _normalize_enabled_detectors(enabled_detectors):
		module = _load_detector_module(detector_name)
		detect = getattr(module, "detect", None)
		if not callable(detect):
			continue
		alert = detect(packet_data, flow_data, settings)
		if alert is None:
			continue

		dedup_key = str(alert.pop("dedup_key", None) or packet_data.get("src_ip") or "")
		if _in_cooldown((detector_name, dedup_key), now, settings.alert_cooldown_seconds):
			continue
		alerts.append(_finalize_alert(alert, detector_name, packet_data, flow_data))

	return alerts


def process_packet(
	packet_dict: dict[str, Any] | None,
	flow_object: dict[str, Any] | None,
	enabled_detectors: Iterable[str] | None = None,
	settings: DetectionSettings | None = None,
) -> list[dict[str, Any]]:
	"""Alias for run_engine for callers that prefer dispatcher-style naming."""

	return run_engine(packet_dict, flow_object, enabled_detectors, settings)


def dispatch(
	packet_dict: dict[str, Any] | None,
	flow_object: dict[str, Any] | None,
	enabled_detectors: Iterable[str] | None = None,
	settings: DetectionSettings | None = None,
) -> list[dict[str, Any]]:
	"""Alias for run_engine."""

	return run_engine(packet_dict, flow_object, enabled_detectors, settings)


if __name__ == "__main__":
	print("Detection engine dispatcher is ready.")
