"""Pipeline runner: capture → parse → analyze → detect, for live capture or PCAP replay."""

from __future__ import annotations

from collections import Counter
from dataclasses import asdict, dataclass, field
import logging
from pathlib import Path
from queue import Empty
import threading
import time
from typing import Any, Callable

from configuration import Config, get_config
from detection_engine import engine
from packet_capture import capture
from packet_parser import PacketParsingError, UnsupportedProtocolError, parse_packet
from traffic_analyzer import TrafficAnalyzer

logger = logging.getLogger(__name__)

PacketHook = Callable[[dict[str, Any], dict[str, Any]], None]
AlertHook = Callable[[dict[str, Any]], None]


@dataclass
class PipelineStats:
    """Counters for one pipeline run."""

    processed: int = 0  # packets parsed and analyzed
    skipped: int = 0  # unsupported packets (ARP, IPv6, ...)
    errors: int = 0  # packets that raised while being processed
    alerts: int = 0
    alerts_by_rule: Counter = field(default_factory=Counter)
    started_at: float | None = None
    finished_at: float | None = None

    def as_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["alerts_by_rule"] = dict(self.alerts_by_rule)
        end = self.finished_at or time.time()
        data["elapsed_seconds"] = round(end - self.started_at, 3) if self.started_at else 0.0
        return data


class Pipeline:
    """Runs captured packets through the parser, traffic analyzer and detection engine.

    Hooks let later modules plug in without changing this class:
      on_packet(packet_dict, flow_object) — e.g. the SQLite logger storing packets
      on_alert(alert_object)              — e.g. the Alert Manager
    Hook errors are logged and never stop the pipeline.
    """

    def __init__(
        self,
        config: Config | None = None,
        on_packet: PacketHook | None = None,
        on_alert: AlertHook | None = None,
    ) -> None:
        self.config = config or get_config()
        self.analyzer = TrafficAnalyzer(**asdict(self.config.traffic))
        self.on_packet = on_packet
        self.on_alert = on_alert
        self.stats = PipelineStats()
        self._stop_requested = threading.Event()
        self._worker: threading.Thread | None = None
        self._mode: str | None = None

    # --- per-packet processing -------------------------------------------------

    def process(self, packet: Any) -> list[dict[str, Any]]:
        """Process one Scapy packet synchronously and return the alerts it raised."""
        try:
            packet_dict = parse_packet(packet)
        except UnsupportedProtocolError:
            self.stats.skipped += 1
            return []
        except PacketParsingError as exc:
            self.stats.errors += 1
            logger.debug("Unparseable packet: %s", exc)
            return []

        try:
            flow_object = self.analyzer.analyze(packet_dict)
            alerts = engine.run_engine(packet_dict, flow_object, settings=self.config.detection)
        except Exception:
            self.stats.errors += 1
            logger.exception("Error while analyzing packet")
            return []

        self.stats.processed += 1
        self._call_hook(self.on_packet, packet_dict, flow_object)
        for alert in alerts:
            self.stats.alerts += 1
            self.stats.alerts_by_rule[alert["rule"]] += 1
            self._call_hook(self.on_alert, alert)
        return alerts

    @staticmethod
    def _call_hook(hook: Callable[..., None] | None, *args: Any) -> None:
        if hook is None:
            return
        try:
            hook(*args)
        except Exception:
            logger.exception("Pipeline hook %r failed", hook)

    # --- worker ---------------------------------------------------------------

    def _start(self, mode: str) -> None:
        if self.running:
            raise RuntimeError("Pipeline is already running")
        engine.reset()
        capture.initialize(self.config.capture)
        self.stats = PipelineStats(started_at=time.time())
        self._stop_requested.clear()
        self._mode = mode
        self._worker = threading.Thread(target=self._consume, name="ids-pipeline", daemon=True)
        self._worker.start()

    def _consume(self) -> None:
        queue = capture.get_packet_queue()
        while True:
            try:
                packet = queue.get(timeout=0.2)
            except Empty:
                if self._stop_requested.is_set() or (self._mode == "pcap" and capture.STATE.stop_event.is_set()):
                    break
                continue
            self.process(packet)
        self.stats.finished_at = time.time()

    @property
    def running(self) -> bool:
        return self._worker is not None and self._worker.is_alive()

    # --- public API -----------------------------------------------------------

    def run_pcap(self, pcap_file: str | Path) -> PipelineStats:
        """Replay a PCAP file through the pipeline and block until every packet is processed."""
        self._start("pcap")
        try:
            capture.replay_pcap(pcap_file)
        finally:
            self._join()
        return self.stats

    def start_live(self) -> dict[str, Any]:
        """Start live capture in the background. Raises PermissionError without capture rights."""
        self._start("live")
        try:
            return capture.start_capture()
        except Exception:
            self._stop_requested.set()
            self._join()
            raise

    def stop(self) -> PipelineStats:
        """Stop capture, process any packets still queued, and return the run's stats."""
        capture.stop_capture()
        self._join()
        return self.stats

    def _join(self) -> None:
        if self._mode == "live":
            self._stop_requested.set()
        if self._worker is not None:
            self._worker.join()
            self._worker = None
        self._mode = None
