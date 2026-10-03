"""Live packet capture engine."""

from __future__ import annotations

from importlib import import_module
import logging
from pathlib import Path
import os
from dataclasses import dataclass, field
from queue import Full, Queue
from threading import Event
from typing import Any

from packet_capture.filters import get_filter, set_filter, validate_filter
from packet_capture.interface import get_default_interface, validate_interface
from packet_capture.pcap import iter_pcap
from packet_capture.stats import update_stats

logger = logging.getLogger(__name__)


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
	initialized: bool = False
	running: bool = False
	source: str | None = None
	dropped: int = 0
	stop_event: Event = field(default_factory=Event)
	sniffer: Any = None
	packet_queue: Queue[Any] = field(default_factory=Queue)


STATE = CaptureState()
_DEFAULT_CONFIG_PATHS = (
	Path(__file__).resolve().parent.parent / "configuration" / "capture.yaml",
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
		logger.warning("PyYAML is not installed; capture.yaml is ignored")
		return {}

	for path in search_paths:
		if not path or not path.exists():
			continue
		try:
			with path.open("r", encoding="utf-8") as handle:
				loaded = yaml.safe_load(handle)
		except (OSError, yaml.YAMLError) as exc:
			logger.warning("Unable to read %s: %s", path, exc)
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
	if interface and not validate_interface(interface):
		fallback = get_default_interface()
		logger.warning("Interface %r not found; falling back to %r", interface, fallback)
		interface = fallback or ""
	if not interface:
		interface = get_default_interface() or ""

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
	STATE.initialized = True
	STATE.running = False
	STATE.source = None
	STATE.dropped = 0
	STATE.sniffer = None
	STATE.packet_queue = Queue(maxsize=STATE.config.queue_size) if STATE.config.queue_size else Queue()

	return {
		"interface": STATE.config.interface,
		"filter": get_filter(),
		"queue_size": STATE.config.queue_size,
		"running": STATE.running,
	}


def capture_packet(packet: Any, block: bool = False) -> Any:
	"""Update stats and forward a captured packet to the processing queue.

	Live capture uses block=False so a slow consumer drops packets instead of
	stalling the sniffer. PCAP replay uses block=True so no packets are lost.
	"""

	if logger.isEnabledFor(logging.DEBUG):
		try:
			logger.debug("Captured %s", packet.summary())
		except Exception as exc:
			logger.debug("Captured unprintable packet: %s", exc)

	update_stats(packet)

	try:
		STATE.packet_queue.put(packet, block=block)
	except Full:
		STATE.dropped += 1
		logger.debug("Packet dropped - queue full (%d dropped)", STATE.dropped)

	return packet


def start_capture() -> dict[str, Any]:
	"""Start live sniffing in the background."""

	if STATE.running:
		return {
			"running": True,
			"interface": STATE.config.interface,
			"filter": get_filter(),
		}

	if not STATE.initialized:
		initialize()

	STATE.stop_event.clear()
	STATE.running = True
	STATE.source = "live"
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


def replay_pcap(pcap_file: str | Path) -> int:
	"""Feed packets from a PCAP file into the capture queue, like a live capture.

	Blocks until the whole file is queued or stop_capture() is called, and
	returns the number of packets queued. Run it in a thread when a consumer
	is draining the queue concurrently. stop_event is set when replay ends so
	consumers know no more packets are coming.
	"""

	if STATE.running:
		raise RuntimeError("A capture is already running")
	if not STATE.initialized:
		initialize()

	STATE.stop_event.clear()
	STATE.running = True
	STATE.source = "pcap"
	count = 0
	try:
		for packet in iter_pcap(pcap_file):
			if STATE.stop_event.is_set():
				break
			capture_packet(packet, block=True)
			count += 1
	finally:
		STATE.running = False
		STATE.stop_event.set()

	logger.info("Replayed %d packets from %s", count, pcap_file)
	return count


def stop_capture() -> dict[str, Any]:
	"""Stop the active sniffing session or PCAP replay."""

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
	logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")
	try:
		initialize()
	except ValueError as exc:
		print(f"Configuration Error: {exc}")
		return

	print(_format_configuration(STATE.config))


if __name__ == "__main__":
	_main()
