"""Traffic analyzer: turns packet_dicts into flow_objects (see docs/CONTRACTS.md)."""

from __future__ import annotations

from datetime import datetime, timezone
import threading
import time
from typing import Any

from traffic_analyzer.flows import Flow, FlowTable
from traffic_analyzer.stats import TrafficStats
from traffic_analyzer.windows import SourceWindows


def _to_epoch(value: Any) -> float:
    """Convert a packet timestamp (datetime, epoch number or ISO string) to epoch seconds."""
    if isinstance(value, datetime):
        if value.tzinfo is None:
            value = value.replace(tzinfo=timezone.utc)
        return value.timestamp()
    if isinstance(value, (int, float)):
        return float(value)
    if isinstance(value, str) and value:
        try:
            return _to_epoch(datetime.fromisoformat(value))
        except ValueError:
            pass
    return time.time()


def _utc(timestamp: float) -> datetime:
    return datetime.fromtimestamp(timestamp, tz=timezone.utc)


def _flow_dict(flow: Flow) -> dict[str, Any]:
    return {
        "flow_id": flow.flow_id,
        "protocol": flow.protocol,
        "src_ip": flow.src_ip,
        "dst_ip": flow.dst_ip,
        "src_port": flow.src_port,
        "dst_port": flow.dst_port,
        "first_seen": _utc(flow.first_seen),
        "last_seen": _utc(flow.last_seen),
        "duration": flow.duration,
        "packet_count": flow.packet_count,
        "bytes": flow.bytes,
        "pps": flow.pps,
        "syn_count": flow.syn_count,
        "ack_count": flow.ack_count,
    }


class TrafficAnalyzer:
    """Tracks flows, per-source windows and global stats. Safe to read from other threads."""

    def __init__(
        self,
        window_seconds: int = 60,
        flow_timeout_seconds: float = 120.0,
        max_flows: int = 100_000,
        max_sources: int = 100_000,
    ) -> None:
        self.window_seconds = int(window_seconds)
        self._flows = FlowTable(flow_timeout_seconds, max_flows)
        self._sources = SourceWindows(self.window_seconds, max_sources)
        self._stats = TrafficStats()
        self._lock = threading.Lock()

    def analyze(self, packet_dict: dict[str, Any]) -> dict[str, Any]:
        """Record a parsed packet and return its flow_object."""
        timestamp = _to_epoch(packet_dict.get("timestamp"))
        protocol = str(packet_dict.get("protocol") or "")
        flags = set((packet_dict.get("flags") or "").split(","))
        is_syn = "SYN" in flags and "ACK" not in flags
        is_ack = "ACK" in flags

        # Only connection attempts count towards unique_dst_ports, so replies
        # from a busy server to many client ports don't look like a scan.
        dst_port = packet_dict.get("dst_port")
        attempt_port = dst_port if (is_syn or protocol == "UDP") else None

        with self._lock:
            flow = self._flows.update(packet_dict, timestamp, is_syn, is_ack)
            src_window = self._sources.update(
                str(packet_dict.get("src_ip") or ""),
                timestamp,
                str(packet_dict.get("dst_ip") or ""),
                attempt_port,
                is_syn,
                is_ack,
                protocol == "ICMP",
            )
            self._stats.add(timestamp, packet_dict)

        flow_object = _flow_dict(flow)
        flow_object["src_window"] = src_window
        return flow_object

    def get_stats(self, now: float | None = None, top_n: int = 10) -> dict[str, Any]:
        """Return global traffic stats. Pass now=time.time() for live capture."""
        with self._lock:
            return self._stats.snapshot(len(self._flows), now, top_n)

    def get_flows(self, limit: int = 100) -> list[dict[str, Any]]:
        """Return active flows, most recently updated first."""
        with self._lock:
            return [_flow_dict(flow) for flow in self._flows.recent(limit)]


_DEFAULT = TrafficAnalyzer()


def configure(**settings: Any) -> TrafficAnalyzer:
    """Replace the shared analyzer with one using the given settings (clears all state)."""
    global _DEFAULT
    _DEFAULT = TrafficAnalyzer(**settings)
    return _DEFAULT


def reset() -> None:
    """Clear all flows and stats, keeping the current settings."""
    configure(
        window_seconds=_DEFAULT.window_seconds,
        flow_timeout_seconds=_DEFAULT._flows.timeout_seconds,
        max_flows=_DEFAULT._flows.max_flows,
        max_sources=_DEFAULT._sources.max_sources,
    )


def analyze(packet_dict: dict[str, Any]) -> dict[str, Any]:
    return _DEFAULT.analyze(packet_dict)


def get_stats(now: float | None = None, top_n: int = 10) -> dict[str, Any]:
    return _DEFAULT.get_stats(now, top_n)


def get_flows(limit: int = 100) -> list[dict[str, Any]]:
    return _DEFAULT.get_flows(limit)
