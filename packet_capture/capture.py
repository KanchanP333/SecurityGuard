"""Live packet capture engine."""

from __future__ import annotations

from importlib import import_module
import logging
from pathlib import Path
import os
from dataclasses import dataclass, field
from queue import Full, Queue
from threading import Event
import time
from typing import Any

from configuration import CaptureSettings, get_config
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


def _read_int_env(name: str, default: int) -> int:
	value = os.environ.get(name, "").strip()
	if not value:
		return default

	try:
		return max(0, int(value))
	except ValueError:
		return default


def _read_config(settings: CaptureSettings | None = None) -> CaptureConfig:
	"""Read capture configuration from the config manager, with environment variable overrides."""

	if settings is None:
		settings = get_config().capture

	interface = os.environ.get("CAPTURE_INTERFACE", "").strip()
	if not interface:
		interface = settings.interface
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
		filter_expression = settings.filter
	if filter_expression and not validate_filter(filter_expression):
		raise ValueError(f"Invalid capture filter: {filter_expression}")

	queue_size = _read_int_env("CAPTURE_QUEUE_SIZE", 0)
	if queue_size == 0:
		queue_size = settings.packet_limit
	return CaptureConfig(
		interface=interface or None,
		filter_expression=filter_expression,
		queue_size=queue_size,
	)


def initialize(settings: CaptureSettings | None = None) -> dict[str, Any]:
	"""Initialize the capture subsystem from the given settings, or the shared config."""

	STATE.config = _read_config(settings)
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
	stalling the sniffer. PCAP replay waits for queue space instead (see replay_pcap).
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


def _wait_for_sniffer(sniffer: Any, timeout: float = 3.0) -> None:
	"""Wait until the background sniffer has opened its socket.

	Scapy runs the sniffer in a thread and only stores errors (e.g. missing
	root/Administrator rights, unknown interface) on the sniffer object, so
	check for them here and raise them in the caller instead of failing silently.
	"""

	deadline = time.monotonic() + timeout
	while time.monotonic() < deadline:
		if sniffer.exception is not None:
			error = sniffer.exception
			if isinstance(error, PermissionError):
				raise PermissionError("Live capture needs root/Administrator rights (run with sudo, or as Administrator with Npcap on Windows)") from error
			raise RuntimeError(f"Live capture failed to start: {error}") from error
		if hasattr(sniffer, "continue_sniff"):
			return
		time.sleep(0.02)
	logger.warning("Sniffer did not report ready within %.1fs; continuing", timeout)


def start_capture() -> dict[str, Any]:
	"""Start live sniffing in the background.

	Raises PermissionError without capture rights, or RuntimeError if the
	sniffer fails to start for another reason.
	"""

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
	try:
		_wait_for_sniffer(STATE.sniffer)
	except Exception:
		STATE.sniffer = None
		STATE.running = False
		STATE.source = None
		raise

	return {
		"running": STATE.running,
		"interface": STATE.config.interface,
		"filter": get_filter(),
	}


def _queue_until_stopped(packet: Any) -> bool:
	"""Queue a replayed packet, waiting for space. Returns False if replay was stopped while waiting."""

	update_stats(packet)
	while True:
		try:
			STATE.packet_queue.put(packet, timeout=0.2)
			return True
		except Full:
			if STATE.stop_event.is_set():
				return False


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
			if STATE.stop_event.is_set() or not _queue_until_stopped(packet):
				break
			count += 1
	finally:
		STATE.running = False
		STATE.stop_event.set()

	logger.info("Replayed %d packets from %s", count, pcap_file)
	return count


def stop_capture() -> dict[str, Any]:
	"""Stop the active sniffing session or PCAP replay."""

	if STATE.sniffer is not None:
		sniffer, STATE.sniffer = STATE.sniffer, None
		try:
			if sniffer.running:
				sniffer.stop()
		except Exception as exc:
			logger.warning("Sniffer stopped with an error: %s", exc)

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
