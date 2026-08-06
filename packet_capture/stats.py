"""Capture statistics helpers."""

from __future__ import annotations

from copy import deepcopy
from datetime import datetime, timezone
from typing import Any

_DEFAULT_STATS: dict[str, Any] = {
	"packets": 0,
	"bytes": 0,
	"start_time": None,
	"running_time": 0,
}

_STATS: dict[str, Any] = deepcopy(_DEFAULT_STATS)


def update_stats(packet: Any) -> dict[str, Any]:
	"""Update capture statistics from a packet-like object."""

	if _STATS["start_time"] is None:
		_STATS["start_time"] = datetime.now(timezone.utc)

	packet_length = 0
	if packet is not None:
		if hasattr(packet, "__len__"):
			try:
				packet_length = len(packet)
			except TypeError:
				packet_length = 0
		elif hasattr(packet, "payload"):
			payload = getattr(packet, "payload")
			if hasattr(payload, "__len__"):
				try:
					packet_length = len(payload)
				except TypeError:
					packet_length = 0

	_STATS["packets"] += 1
	_STATS["bytes"] += packet_length
	_STATS["running_time"] = int(
		(datetime.now(timezone.utc) - _STATS["start_time"]).total_seconds()
	)
	return get_stats()


def reset_stats() -> dict[str, Any]:
	"""Reset capture statistics to their initial values."""

	_STATS.clear()
	_STATS.update(deepcopy(_DEFAULT_STATS))
	return get_stats()


def get_stats() -> dict[str, Any]:
	"""Return a snapshot of the current capture statistics."""

	return deepcopy(_STATS)
