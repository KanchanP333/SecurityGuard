"""Network interface discovery helpers."""

from __future__ import annotations

import json
import os
import socket
import subprocess
from typing import Any


def _run_powershell_json(command: str) -> Any:
	"""Run a PowerShell command and parse JSON output when available."""

	completed = subprocess.run(
		[
			"powershell",
			"-NoProfile",
			"-ExecutionPolicy",
			"Bypass",
			"-Command",
			command,
		],
		capture_output=True,
		text=True,
		check=False,
	)
	output = completed.stdout.strip()
	if not output:
		return []

	try:
		return json.loads(output)
	except json.JSONDecodeError:
		return []


def _normalize_name(name: str) -> str:
	"""Normalize a platform-specific interface label for display and matching."""

	cleaned = name.strip()
	if "loopback" in cleaned.lower():
		return "Loopback"
	return cleaned


def _discover_windows_interfaces() -> list[str]:
	"""Discover interfaces using PowerShell on Windows."""

	command = (
		"Get-NetAdapter | Select-Object Name, Status | ConvertTo-Json -Compress"
	)
	data = _run_powershell_json(command)

	if isinstance(data, dict):
		data = [data]

	interfaces: list[str] = []
	for item in data:
		if not isinstance(item, dict):
			continue
		name = item.get("Name")
		if isinstance(name, str) and name.strip():
			interfaces.append(_normalize_name(name))

	return interfaces


def _discover_socket_interfaces() -> list[str]:
	"""Discover interfaces using the standard library fallback."""

	interfaces: list[str] = []
	if hasattr(socket, "if_nameindex"):
		try:
			for _, name in socket.if_nameindex():
				if isinstance(name, str) and name.strip():
					interfaces.append(_normalize_name(name))
		except OSError:
			pass

	return interfaces


def list_interfaces() -> list[str]:
	"""Return the available interface names."""

	interfaces = _discover_windows_interfaces()
	if not interfaces:
		interfaces = _discover_socket_interfaces()

	seen: set[str] = set()
	unique_interfaces: list[str] = []
	for interface in interfaces:
		if interface not in seen:
			seen.add(interface)
			unique_interfaces.append(interface)

	return unique_interfaces


def validate_interface(interface: str) -> bool:
	"""Return True when the provided interface name exists."""

	if not isinstance(interface, str):
		return False

	normalized = interface.strip().lower()
	if not normalized:
		return False

	return any(name.lower() == normalized for name in list_interfaces())


def get_default_interface() -> str | None:
	"""Return the configured interface, or the first valid interface available."""

	configured_interface = os.environ.get("DEFAULT_INTERFACE", "").strip()
	if configured_interface and validate_interface(configured_interface):
		return configured_interface

	interfaces = list_interfaces()
	if not interfaces:
		return None

	for interface in interfaces:
		if interface.lower() != "loopback":
			return interface

	return interfaces[0]


def get_interface_info(interface: str) -> dict[str, str] | None:
	"""Return basic information for a validated interface name."""

	if not validate_interface(interface):
		return None

	return {
		"name": interface.strip(),
		"status": "available",
		"default": str(get_default_interface() == interface.strip()).lower(),
	}


def _main() -> None:
	interfaces = list_interfaces()
	print("Available Interfaces:")
	print("---------------------")
	for interface in interfaces:
		print(interface)


if __name__ == "__main__":
	_main()
