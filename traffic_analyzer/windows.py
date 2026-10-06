"""Per-source sliding window statistics."""

from __future__ import annotations

from collections import Counter, OrderedDict, deque
from dataclasses import dataclass, field
from typing import Any

# Packet rates in src_window are measured over this many recent seconds.
RATE_SECONDS = 5


@dataclass(slots=True)
class _Bucket:
    """Activity from one source during one whole second."""

    second: int
    first_ts: float
    packet_count: int = 0
    syn_count: int = 0
    ack_count: int = 0
    icmp_count: int = 0
    dst_ports: Counter = field(default_factory=Counter)
    dst_ips: Counter = field(default_factory=Counter)


class _SourceWindow:
    """Running totals for one source IP over the last `window_seconds`.

    Activity is grouped into 1-second buckets, so memory is bounded by the
    window length rather than by the packet rate.
    """

    __slots__ = ("buckets", "packet_count", "syn_count", "ack_count", "icmp_count", "dst_ports", "dst_ips", "last_seen")

    def __init__(self) -> None:
        self.buckets: deque[_Bucket] = deque()
        self.packet_count = 0
        self.syn_count = 0
        self.ack_count = 0
        self.icmp_count = 0
        self.dst_ports: Counter = Counter()
        self.dst_ips: Counter = Counter()
        self.last_seen = 0.0

    def add(
        self,
        timestamp: float,
        dst_ip: str,
        dst_port: int | None,
        is_syn: bool,
        is_ack: bool,
        is_icmp: bool,
    ) -> None:
        second = int(timestamp)
        if self.buckets and self.buckets[-1].second >= second:
            # Slightly out-of-order packets are counted in the newest bucket.
            bucket = self.buckets[-1]
        else:
            bucket = _Bucket(second=second, first_ts=timestamp)
            self.buckets.append(bucket)

        bucket.packet_count += 1
        self.packet_count += 1
        if is_syn:
            bucket.syn_count += 1
            self.syn_count += 1
        if is_ack:
            bucket.ack_count += 1
            self.ack_count += 1
        if is_icmp:
            bucket.icmp_count += 1
            self.icmp_count += 1
        if dst_port is not None:
            bucket.dst_ports[dst_port] += 1
            self.dst_ports[dst_port] += 1
        if dst_ip:
            bucket.dst_ips[dst_ip] += 1
            self.dst_ips[dst_ip] += 1

        self.last_seen = max(self.last_seen, timestamp)

    def expire(self, now: float, window_seconds: int) -> None:
        """Drop buckets that fall outside the window ending at `now`."""
        cutoff = int(now) - window_seconds
        while self.buckets and self.buckets[0].second <= cutoff:
            bucket = self.buckets.popleft()
            self.packet_count -= bucket.packet_count
            self.syn_count -= bucket.syn_count
            self.ack_count -= bucket.ack_count
            self.icmp_count -= bucket.icmp_count
            _subtract(self.dst_ports, bucket.dst_ports)
            _subtract(self.dst_ips, bucket.dst_ips)

    def _recent_rates(self) -> tuple[float, float]:
        """Packets/sec and ICMP packets/sec over the last RATE_SECONDS.

        The divisor is RATE_SECONDS, or the time since the oldest packet still in
        the window if that is shorter (minimum 1 s), so a brand-new burst shows its
        real rate and older quiet periods don't dilute a new flood.
        """
        if not self.buckets:
            return 0.0, 0.0
        oldest_recent_second = int(self.last_seen) - RATE_SECONDS
        packets = icmp = 0
        for bucket in reversed(self.buckets):
            if bucket.second <= oldest_recent_second:
                break
            packets += bucket.packet_count
            icmp += bucket.icmp_count
        span = min(float(RATE_SECONDS), max(self.last_seen - self.buckets[0].first_ts, 1.0))
        return packets / span, icmp / span

    def snapshot(self, window_seconds: int) -> dict[str, Any]:
        pps, icmp_pps = self._recent_rates()
        return {
            "window_seconds": window_seconds,
            "packet_count": self.packet_count,
            "pps": pps,
            "syn_count": self.syn_count,
            "ack_count": self.ack_count,
            "icmp_count": self.icmp_count,
            "icmp_pps": icmp_pps,
            "unique_dst_ports": len(self.dst_ports),
            "unique_dst_ips": len(self.dst_ips),
        }


def _subtract(totals: Counter, removed: Counter) -> None:
    for key, count in removed.items():
        remaining = totals[key] - count
        if remaining > 0:
            totals[key] = remaining
        else:
            del totals[key]


class SourceWindows:
    """Sliding windows for every active source IP, evicting sources that go quiet."""

    def __init__(self, window_seconds: int = 60, max_sources: int = 100_000) -> None:
        self.window_seconds = int(window_seconds)
        self.max_sources = int(max_sources)
        self._sources: OrderedDict[str, _SourceWindow] = OrderedDict()

    def __len__(self) -> int:
        return len(self._sources)

    def update(
        self,
        src_ip: str,
        timestamp: float,
        dst_ip: str,
        dst_port: int | None,
        is_syn: bool,
        is_ack: bool,
        is_icmp: bool,
    ) -> dict[str, Any]:
        """Record a packet from `src_ip` and return its current window snapshot.

        `dst_port` should only be passed for connection attempts (see analyzer),
        so that unique_dst_ports reflects ports the source tried to reach.
        """
        window = self._sources.get(src_ip)
        if window is None:
            window = _SourceWindow()
            self._sources[src_ip] = window
        else:
            self._sources.move_to_end(src_ip)

        window.add(timestamp, dst_ip, dst_port, is_syn, is_ack, is_icmp)
        window.expire(timestamp, self.window_seconds)
        snapshot = window.snapshot(self.window_seconds)
        self._evict(timestamp)
        return snapshot

    def _evict(self, now: float) -> None:
        cutoff = now - self.window_seconds
        while self._sources:
            oldest = next(iter(self._sources.values()))
            if oldest.last_seen >= cutoff and len(self._sources) <= self.max_sources:
                break
            self._sources.popitem(last=False)
