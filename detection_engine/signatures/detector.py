"""Signature matching detector."""

#This file implements payload signature matching using the detection.signatures list in the configuration.
#Each signature is either a plain substring or a regular expression (regex: true), matched case-insensitively against the first bytes of the packet payload (packet_dict["payload"]).
#The first matching signature generates an alert with the severity configured for that signature.

from __future__ import annotations

from functools import lru_cache
import re
from typing import Any, Callable


@lru_cache(maxsize=512)
def _matcher(pattern: str, regex: bool) -> Callable[[bytes, bytes], bool]:
	"""Return a function taking (payload, lowercased payload) that reports whether the signature matches."""

	if regex:
		compiled = re.compile(pattern.encode(), re.IGNORECASE)
		return lambda payload, _lowered: compiled.search(payload) is not None
	needle = pattern.encode().lower()
	return lambda _payload, lowered: needle in lowered


def detect(packet_dict: dict[str, Any], flow_object: dict[str, Any], settings: Any) -> dict[str, Any] | None:
	payload = packet_dict.get("payload") or b""
	if not payload or not settings.signatures:
		return None

	lowered = payload.lower()
	for signature in settings.signatures:
		if _matcher(signature.pattern, signature.regex)(payload, lowered):
			return {
				"attack_type": "Signature Match",
				"severity": signature.severity,
				"confidence": 0.9,
				"description": f"Payload matched signature '{signature.name}'.",
				"dedup_key": f"{packet_dict.get('src_ip')}:{signature.name}",
			}

	return None
