"""Live packet capture engine."""

from __future__ import annotations

from importlib import import_module
from pathlib import Path
import os
from dataclasses import dataclass, field
from queue import Full, Queue
from threading import Event
from typing import Any

from filters import get_filter, set_filter, validate_filter
from interface import get_default_interface, validate_interface
from stats import update_stats


@dataclass
class CaptureConfig:
	"""Runtime capture configuration."""

	interface: str | None = None
	filter_expression: str = ""
	queue_size: int = 0


@dataclass
class CaptureState:
	"""Mutable runtime state for the active capture session."""

	config: CaptureConfig = field(default_factory=CaptureConfig)
	running: bool = False
	stop_event: Event = field(default_factory=Event)
	sniffer: Any = None
	packet_queue: Queue[Any] = field(default_factory=Queue)


STATE = CaptureState()
_DEFAULT_CONFIG_PATHS = (
	Path(__file__).resolve().parent.parent / "Configuration" / "capture.yaml",
	Path(__file__).resolve().parent / "capture.yaml",
)


def _read_int_env(name: str, default: int) -> int:
	value = os.environ.get(name, "").strip()
	if not value:
		return default

	try:
		return max(0, int(value))
	except ValueError:
		return default


def _read_int(value: Any, default: int) -> int:
	try:
		return max(0, int(value))
	except (TypeError, ValueError):
		return default


def _load_yaml_config() -> dict[str, Any]:
	"""Load the capture YAML config from the first available search path."""

	config_path = os.environ.get("CAPTURE_CONFIG", "").strip()
	search_paths = [Path(config_path)] if config_path else list(_DEFAULT_CONFIG_PATHS)
	try:
		yaml = import_module("yaml")
	except ModuleNotFoundError:
		return {}

	for path in search_paths:
		if not path or not path.exists():
			continue
		try:
			with path.open("r", encoding="utf-8") as handle:
				loaded = yaml.safe_load(handle)
		except (OSError, yaml.YAMLError):
			return {}

		return loaded if isinstance(loaded, dict) else {}

	return {}


def _read_config() -> CaptureConfig:
	"""Read capture configuration from YAML and environment variables."""

	loaded_config = _load_yaml_config().get("capture", {})
	if not isinstance(loaded_config, dict):
		loaded_config = {}

	interface = os.environ.get("CAPTURE_INTERFACE", "").strip()
	if not interface:
		interface = str(loaded_config.get("interface", "") or "").strip()
	if not interface:
		interface = os.environ.get("DEFAULT_INTERFACE", "").strip()
	if not interface:
		interface = get_default_interface() or ""
	if interface and not validate_interface(interface):
		raise ValueError(f"Invalid capture interface: {interface}")

	filter_expression = os.environ.get("CAPTURE_FILTER", "").strip()
	if not filter_expression:
		filter_expression = str(loaded_config.get("filter", "") or "").strip()
	if filter_expression and not validate_filter(filter_expression):
		raise ValueError(f"Invalid capture filter: {filter_expression}")

	queue_size = _read_int_env("CAPTURE_QUEUE_SIZE", 0)
	if queue_size == 0:
		queue_size = _read_int(loaded_config.get("packet_limit", 0), 0)
	return CaptureConfig(
		interface=interface or None,
		filter_expression=filter_expression,
		queue_size=queue_size,
	)


def initialize() -> dict[str, Any]:
	"""Initialize the capture subsystem and load the active configuration."""

	STATE.config = _read_config()
	if STATE.config.filter_expression:
		set_filter(STATE.config.filter_expression)
	else:
		set_filter("")

	STATE.stop_event.clear()
	STATE.running = False
	STATE.sniffer = None
	STATE.packet_queue = Queue(maxsize=STATE.config.queue_size) if STATE.config.queue_size else Queue()

	return {
		"interface": STATE.config.interface,
		"filter": get_filter(),
		"queue_size": STATE.config.queue_size,
		"running": STATE.running,
	}


def capture_packet(packet: Any) -> Any:
	"""Update stats and forward a captured packet to the processing queue."""

	debug_capture = True

	print("=" * 40)
	print(type(packet))

	try:
		if debug_capture:
			print(packet.summary())
	except Exception as exc:
		print(exc)

	update_stats(packet)

	try:
		STATE.packet_queue.put_nowait(packet)
	except Full:
		print("Packet dropped - queue full")

	print("Queue Size:", STATE.packet_queue.qsize())
	return packet


def start_capture() -> dict[str, Any]:
	"""Start live sniffing in the background."""

	if STATE.running:
		return {
			"running": True,
			"interface": STATE.config.interface,
			"filter": get_filter(),
		}

	if STATE.config.interface is None and STATE.config.filter_expression == "" and STATE.config.queue_size == 0:
		initialize()

	STATE.stop_event.clear()
	STATE.running = True
	scapy_sendrecv = import_module("scapy.sendrecv")
	AsyncSniffer = scapy_sendrecv.AsyncSniffer
	STATE.sniffer = AsyncSniffer(
		iface=STATE.config.interface,
		filter=STATE.config.filter_expression or None,
		store=False,
		prn=capture_packet,
	)
	STATE.sniffer.start()

	return {
		"running": STATE.running,
		"interface": STATE.config.interface,
		"filter": get_filter(),
	}


def stop_capture() -> dict[str, Any]:
	"""Stop the active sniffing session."""

	if STATE.sniffer is not None:
		STATE.sniffer.stop()
		STATE.sniffer = None

	STATE.stop_event.set()
	STATE.running = False

	return {
		"running": STATE.running,
		"interface": STATE.config.interface,
		"filter": get_filter(),
	}


def get_packet_queue() -> Queue[Any]:
	"""Return the queue used to forward captured packets."""

	return STATE.packet_queue


def _format_configuration(config: CaptureConfig) -> str:
	lines = [
		"Configuration Loaded",
		f"Interface : {config.interface or 'None'}",
		f"Filter    : {config.filter_expression or 'None'}",
		f"Packet Limit : {config.queue_size}",
	]
	return "\n".join(lines)


def _main() -> None:
	try:
		config_snapshot = initialize()
	except ValueError as exc:
		print("Configuration Loaded")
		print("Interface : None")
		print("Filter    : None")
		print("Packet Limit : 0")
		print(f"Configuration Error: {exc}")
		return

	print(_format_configuration(STATE.config))


if __name__ == "__main__":
	_main()
