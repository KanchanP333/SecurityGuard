"""Flow table: per-connection statistics keyed by flow_id."""

from __future__ import annotations

from collections import OrderedDict
from dataclasses import dataclass
from itertools import islice
from typing import Any


def make_flow_id(
    protocol: str,
    src_ip: str,
    src_port: int | None,
    dst_ip: str,
    dst_port: int | None,
) -> str:
    """Build a directional flow id, e.g. 'TCP:10.0.0.5:51432->10.0.0.1:80' or 'ICMP:10.0.0.5->10.0.0.1'."""
    if src_port is None or dst_port is None:
        return f"{protocol}:{src_ip}->{dst_ip}"
    return f"{protocol}:{src_ip}:{src_port}->{dst_ip}:{dst_port}"


@dataclass(slots=True)
class Flow:
    """Statistics for one directional flow. Times are epoch seconds (packet time)."""

    flow_id: str
    protocol: str
    src_ip: str
    dst_ip: str
    src_port: int | None
    dst_port: int | None
    first_seen: float
    last_seen: float
    packet_count: int = 0
    bytes: int = 0
    syn_count: int = 0
    ack_count: int = 0

    @property
    def duration(self) -> float:
        return max(self.last_seen - self.first_seen, 0.0)

    @property
    def pps(self) -> float:
        # A 1s floor stops two packets close together from reading as a flood.
        return self.packet_count / max(self.duration, 1.0)


class FlowTable:
    """Tracks active flows, evicting idle ones and capping total memory.

    Flows are kept in least-recently-updated order, so expiry only looks at
    the front of the table instead of scanning every flow.
    """

    def __init__(self, timeout_seconds: float = 120.0, max_flows: int = 100_000) -> None:
        self.timeout_seconds = float(timeout_seconds)
        self.max_flows = int(max_flows)
        self._flows: OrderedDict[str, Flow] = OrderedDict()

    def __len__(self) -> int:
        return len(self._flows)

    def update(self, packet: dict[str, Any], timestamp: float, is_syn: bool, is_ack: bool) -> Flow:
        """Add a packet to its flow (creating it if needed) and return the flow."""
        protocol = str(packet.get("protocol") or "")
        src_ip = str(packet.get("src_ip") or "")
        dst_ip = str(packet.get("dst_ip") or "")
        src_port = packet.get("src_port")
        dst_port = packet.get("dst_port")
        flow_id = make_flow_id(protocol, src_ip, src_port, dst_ip, dst_port)

        flow = self._flows.get(flow_id)
        if flow is not None and timestamp - flow.last_seen > self.timeout_seconds:
            # Same 5-tuple after a long idle gap: treat it as a new flow.
            del self._flows[flow_id]
            flow = None

        if flow is None:
            flow = Flow(
                flow_id=flow_id,
                protocol=protocol,
                src_ip=src_ip,
                dst_ip=dst_ip,
                src_port=src_port,
                dst_port=dst_port,
                first_seen=timestamp,
                last_seen=timestamp,
            )
            self._flows[flow_id] = flow
        else:
            self._flows.move_to_end(flow_id)

        flow.last_seen = max(flow.last_seen, timestamp)
        flow.packet_count += 1
        flow.bytes += int(packet.get("packet_length") or 0)
        if is_syn:
            flow.syn_count += 1
        if is_ack:
            flow.ack_count += 1

        self.expire(timestamp)
        return flow

    def expire(self, now: float) -> int:
        """Remove flows idle longer than the timeout, and the oldest flows above max_flows."""
        cutoff = now - self.timeout_seconds
        removed = 0
        while self._flows:
            oldest = next(iter(self._flows.values()))
            if oldest.last_seen >= cutoff and len(self._flows) <= self.max_flows:
                break
            self._flows.popitem(last=False)
            removed += 1
        return removed

    def recent(self, limit: int) -> list[Flow]:
        """Return up to `limit` flows, most recently updated first."""
        return list(islice(reversed(self._flows.values()), max(limit, 0)))
