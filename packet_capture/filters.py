"""BPF filter helpers."""

from __future__ import annotations

import ipaddress
import re

_ACTIVE_FILTER: str | None = None

_CONNECTORS = {"and", "or"}
_PREFIXES = {"not"}
_PROTOCOLS = {"tcp", "udp", "icmp", "arp", "ip", "ip6", "ipv6"}


def _is_port(value: str) -> bool:
	# Return True when the provided value is a valid port number (1-65535).
	try:
		port = int(value)
	except ValueError:
		return False
	return 1 <= port <= 65535


def _is_ip_address(value: str) -> bool:
	# Return True when the provided value is a valid IPv4 or IPv6 address.
	try:
		ipaddress.ip_address(value)
	except ValueError:
		return False
	return True


def _is_hostname(value: str) -> bool:
	# Return True when the provided value is a valid hostname.
	if not value or len(value) > 253:
		return False

	pattern = re.compile(r"^(?=.{1,253}$)(?!-)([A-Za-z0-9-]{1,63})(?<!-)(\.[A-Za-z0-9-]{1,63})*$")
	return bool(pattern.match(value))


def _is_address(value: str) -> bool:
	# Return True when the provided value is a valid IP address or hostname.
	return _is_ip_address(value) or _is_hostname(value)


def _consume_clause(tokens: list[str], start_index: int) -> int:
	# Consume a single clause from the token list starting at the given index.
	index = start_index
	if index < len(tokens) and tokens[index].lower() in _PREFIXES:
		index += 1

	if index >= len(tokens):
		raise ValueError("Incomplete filter expression")

	token = tokens[index].lower()
	if token in _PROTOCOLS:
		return index + 1

	if token == "port":
		if index + 1 >= len(tokens) or not _is_port(tokens[index + 1]):
			raise ValueError("Invalid port filter")
		return index + 2

	if token == "host":
		if index + 1 >= len(tokens) or not _is_address(tokens[index + 1]):
			raise ValueError("Invalid host filter")
		return index + 2

	if token in {"src", "dst"}:
		if index + 2 >= len(tokens):
			raise ValueError("Incomplete source/destination filter")
		next_token = tokens[index + 1].lower()
		value = tokens[index + 2]
		if next_token == "port" and _is_port(value):
			return index + 3
		if next_token == "host" and _is_address(value):
			return index + 3
		raise ValueError("Invalid source/destination filter")

	raise ValueError(f"Unsupported filter token: {tokens[index]}")


def validate_filter(filter_expression: str) -> bool:
	"""Return True when the filter expression matches the supported BPF subset."""

	if not isinstance(filter_expression, str):
		return False

	tokens = filter_expression.strip().split()
	if not tokens:
		return False

	index = 0
	try:
		while index < len(tokens):
			index = _consume_clause(tokens, index)
			if index >= len(tokens):
				break
			connector = tokens[index].lower()
			if connector not in _CONNECTORS:
				return False
			index += 1
			if index >= len(tokens):
				return False
		return True
	except ValueError:
		return False


def set_filter(filter_expression: str) -> str:
	"""Validate and store the active filter expression."""

	global _ACTIVE_FILTER
	if not isinstance(filter_expression, str) or not filter_expression.strip():
		_ACTIVE_FILTER = None
		return ""

	if not validate_filter(filter_expression):
		raise ValueError(f"Invalid filter expression: {filter_expression}")

	_ACTIVE_FILTER = filter_expression.strip()
	return _ACTIVE_FILTER


def get_filter() -> str | None:
	"""Return the currently active filter expression."""

	return _ACTIVE_FILTER
