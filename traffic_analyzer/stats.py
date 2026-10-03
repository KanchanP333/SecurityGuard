"""Global traffic statistics for the dashboard."""

from __future__ import annotations

from collections import Counter, deque
from datetime import datetime, timezone
from typing import Any

HISTORY_SECONDS = 300
PPS_WINDOW_SECONDS = 5
# Top-talker counters are trimmed to the busiest IPs when they grow past this size.
MAX_TRACKED_IPS = 50_000
TRIMMED_IPS = 10_000


def _iso(timestamp: float | None) -> str | None:
    if timestamp is None:
        return None
    return datetime.fromtimestamp(timestamp, tz=timezone.utc).isoformat()


class TrafficStats:
    """Totals, protocol mix, top talkers and a per-second packet/byte history."""

    def __init__(self) -> None:
        self.total_packets = 0
        self.total_bytes = 0
        self.protocols: Counter = Counter()
        self.sources: Counter = Counter()
        self.destinations: Counter = Counter()
        # Each entry is [second, packets, bytes]; seconds with no traffic are recorded as zeros.
        self.history: deque[list[int]] = deque(maxlen=HISTORY_SECONDS)
        self.first_seen: float | None = None
        self.last_seen: float | None = None

    def add(self, timestamp: float, packet: dict[str, Any]) -> None:
        length = int(packet.get("packet_length") or 0)
        self.total_packets += 1
        self.total_bytes += length
        self.protocols[str(packet.get("protocol") or "OTHER")] += 1
        self._count_ip(self.sources, packet.get("src_ip"))
        self._count_ip(self.destinations, packet.get("dst_ip"))

        if self.first_seen is None:
            self.first_seen = timestamp
        self.last_seen = timestamp if self.last_seen is None else max(self.last_seen, timestamp)

        bucket = self._history_bucket(int(timestamp))
        bucket[1] += 1
        bucket[2] += length

    def _history_bucket(self, second: int) -> list[int]:
        if self.history and self.history[-1][0] >= second:
            return self.history[-1]
        if self.history:
            start = max(self.history[-1][0] + 1, second - HISTORY_SECONDS + 1)
            for missing in range(start, second):
                self.history.append([missing, 0, 0])
        bucket = [second, 0, 0]
        self.history.append(bucket)
        return bucket

    @staticmethod
    def _count_ip(counter: Counter, ip: Any) -> None:
        if not ip:
            return
        counter[ip] += 1
        if len(counter) > MAX_TRACKED_IPS:
            busiest = counter.most_common(TRIMMED_IPS)
            counter.clear()
            counter.update(dict(busiest))

    def _recent_rates(self, now: float) -> tuple[float, float]:
        """Packets and bytes per second over the last PPS_WINDOW_SECONDS before `now`."""
        if not self.history or self.first_seen is None:
            return 0.0, 0.0
        current = int(now)
        oldest = current - PPS_WINDOW_SECONDS + 1
        packets = sum(b[1] for b in self.history if oldest <= b[0] <= current)
        byte_count = sum(b[2] for b in self.history if oldest <= b[0] <= current)
        span = min(PPS_WINDOW_SECONDS, max(current - int(self.first_seen) + 1, 1))
        return packets / span, byte_count / span

    def snapshot(self, active_flows: int, now: float | None = None, top_n: int = 10) -> dict[str, Any]:
        """Return a JSON-friendly summary. `now` defaults to the last packet time (use time.time() for live capture)."""
        reference = now if now is not None else (self.last_seen or 0.0)
        pps, bps = self._recent_rates(reference)
        return {
            "total_packets": self.total_packets,
            "total_bytes": self.total_bytes,
            "pps": round(pps, 2),
            "bps": round(bps, 2),
            "active_flows": active_flows,
            "protocols": dict(self.protocols),
            "top_sources": [{"ip": ip, "packets": n} for ip, n in self.sources.most_common(top_n)],
            "top_destinations": [{"ip": ip, "packets": n} for ip, n in self.destinations.most_common(top_n)],
            "first_seen": _iso(self.first_seen),
            "last_seen": _iso(self.last_seen),
            "history": [{"time": _iso(s), "packets": p, "bytes": b} for s, p, b in self.history],
        }
