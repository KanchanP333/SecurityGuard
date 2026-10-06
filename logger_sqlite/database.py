"""SQLite storage for packets, alerts and events (schema: docs/CONTRACTS.md §4)."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
import logging
from pathlib import Path
import sqlite3
import threading
import time
from typing import Any, Iterable

logger = logging.getLogger(__name__)

SCHEMA_VERSION = 1
ALERT_STATUSES = ("new", "acknowledged", "resolved")
SEVERITIES = ("Low", "Medium", "High", "Critical")

_SCHEMA = """
CREATE TABLE IF NOT EXISTS packets (
    id            INTEGER PRIMARY KEY,
    timestamp     TEXT NOT NULL,
    src_mac       TEXT,
    dst_mac       TEXT,
    src_ip        TEXT,
    dst_ip        TEXT,
    src_port      INTEGER,
    dst_port      INTEGER,
    protocol      TEXT,
    flags         TEXT,
    ttl           INTEGER,
    packet_length INTEGER,
    payload_size  INTEGER,
    icmp_type     INTEGER,
    icmp_code     INTEGER,
    stored_at     TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_packets_timestamp ON packets (timestamp);
CREATE INDEX IF NOT EXISTS idx_packets_stored_at ON packets (stored_at);
CREATE INDEX IF NOT EXISTS idx_packets_src_ip ON packets (src_ip);
CREATE INDEX IF NOT EXISTS idx_packets_dst_ip ON packets (dst_ip);

CREATE TABLE IF NOT EXISTS alerts (
    id          INTEGER PRIMARY KEY,
    timestamp   TEXT NOT NULL,
    rule        TEXT NOT NULL,
    attack_type TEXT NOT NULL,
    severity    TEXT NOT NULL,
    confidence  REAL,
    src_ip      TEXT,
    dst_ip      TEXT,
    dst_port    INTEGER,
    protocol    TEXT,
    flow_id     TEXT,
    description TEXT,
    status      TEXT NOT NULL DEFAULT 'new'
);
CREATE INDEX IF NOT EXISTS idx_alerts_timestamp ON alerts (timestamp);
CREATE INDEX IF NOT EXISTS idx_alerts_src_ip ON alerts (src_ip);
CREATE INDEX IF NOT EXISTS idx_alerts_rule ON alerts (rule);
CREATE INDEX IF NOT EXISTS idx_alerts_severity ON alerts (severity);

CREATE TABLE IF NOT EXISTS events (
    id        INTEGER PRIMARY KEY,
    timestamp TEXT NOT NULL,
    level     TEXT NOT NULL,
    source    TEXT,
    message   TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events (timestamp);
"""

PACKET_COLUMNS = (
    "timestamp", "src_mac", "dst_mac", "src_ip", "dst_ip", "src_port", "dst_port",
    "protocol", "flags", "ttl", "packet_length", "payload_size", "icmp_type", "icmp_code",
)
ALERT_COLUMNS = (
    "timestamp", "rule", "attack_type", "severity", "confidence", "src_ip", "dst_ip",
    "dst_port", "protocol", "flow_id", "description", "status",
)


def to_iso(value: Any) -> str | None:
    """Normalize a datetime, epoch number or ISO string to an ISO 8601 UTC string."""
    if value is None or value == "":
        return None
    if isinstance(value, datetime):
        if value.tzinfo is None:
            value = value.replace(tzinfo=timezone.utc)
        # Fixed precision keeps stored strings sortable and comparable as text.
        return value.astimezone(timezone.utc).isoformat(timespec="microseconds")
    if isinstance(value, (int, float)):
        return to_iso(datetime.fromtimestamp(value, tz=timezone.utc))
    if isinstance(value, str):
        return to_iso(datetime.fromisoformat(value))
    raise TypeError(f"Unsupported timestamp: {value!r}")


def _as_list(value: str | Iterable[str] | None) -> list[str] | None:
    if value is None:
        return None
    return [value] if isinstance(value, str) else list(value)


class _Filters:
    """Builds a WHERE clause from optional filters."""

    def __init__(self) -> None:
        self.clauses: list[str] = []
        self.params: list[Any] = []

    def equals(self, column: str, value: Any) -> None:
        if value is not None:
            self.clauses.append(f"{column} = ?")
            self.params.append(value)

    def one_of(self, column: str, values: list[Any] | None) -> None:
        if values:
            self.clauses.append(f"{column} IN ({', '.join('?' * len(values))})")
            self.params.extend(values)

    def either(self, columns: tuple[str, str], value: Any) -> None:
        if value is not None:
            self.clauses.append(f"({columns[0]} = ? OR {columns[1]} = ?)")
            self.params.extend([value, value])

    def time_range(self, since: Any, until: Any) -> None:
        if since is not None:
            self.clauses.append("timestamp >= ?")
            self.params.append(to_iso(since))
        if until is not None:
            self.clauses.append("timestamp < ?")
            self.params.append(to_iso(until))

    @property
    def sql(self) -> str:
        return f" WHERE {' AND '.join(self.clauses)}" if self.clauses else ""


class Database:
    """Thread-safe SQLite store for packets, alerts and events.

    Each thread gets its own connection; WAL mode lets the dashboard read while
    the pipeline writes. Packets are buffered and written in batches; alerts
    and events are written immediately. Call close() (or use `with`) to flush.
    """

    def __init__(
        self,
        path: str | Path,
        batch_size: int = 500,
        flush_interval: float = 1.0,
        retention_days: int = 0,
    ) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.batch_size = max(int(batch_size), 1)
        self.flush_interval = float(flush_interval)
        self.retention_days = int(retention_days)

        self._local = threading.local()
        self._connections: list[sqlite3.Connection] = []
        self._connections_lock = threading.Lock()
        self._buffer: list[tuple[Any, ...]] = []
        self._buffer_lock = threading.Lock()
        self._last_flush = time.monotonic()
        self._last_purge = 0.0
        self._closed = False

        with self._connect() as conn:
            conn.executescript(_SCHEMA)
            conn.execute(f"PRAGMA user_version = {SCHEMA_VERSION}")
        self.purge_old_packets()

    @classmethod
    def from_settings(cls, settings: Any) -> "Database":
        """Create from configuration LoggingSettings."""
        return cls(settings.resolved_db_path(), retention_days=settings.packet_retention_days)

    # --- connections ----------------------------------------------------------

    def _connect(self) -> sqlite3.Connection:
        if self._closed:
            raise RuntimeError("Database is closed")
        conn = getattr(self._local, "conn", None)
        if conn is None:
            conn = sqlite3.connect(self.path, timeout=10.0, check_same_thread=False)
            conn.row_factory = sqlite3.Row
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("PRAGMA synchronous=NORMAL")
            self._local.conn = conn
            with self._connections_lock:
                self._connections.append(conn)
        return conn

    def close(self) -> None:
        """Flush buffered packets and close every connection."""
        if self._closed:
            return
        self.flush()
        self._closed = True
        with self._connections_lock:
            for conn in self._connections:
                conn.close()
            self._connections.clear()

    def __enter__(self) -> "Database":
        return self

    def __exit__(self, *exc: Any) -> None:
        self.close()

    # --- packets --------------------------------------------------------------

    def insert_packet(self, packet_dict: dict[str, Any], flow_object: dict[str, Any] | None = None) -> None:
        """Buffer a packet for storage. The signature matches the pipeline's on_packet hook."""
        now = to_iso(datetime.now(timezone.utc))
        values = dict(packet_dict)
        values["timestamp"] = to_iso(values.get("timestamp")) or now
        row = (*(values.get(column) for column in PACKET_COLUMNS), now)
        with self._buffer_lock:
            self._buffer.append(row)
            due = len(self._buffer) >= self.batch_size or time.monotonic() - self._last_flush >= self.flush_interval
        if due:
            self.flush()

    def flush(self) -> int:
        """Write buffered packets now. Returns how many were written."""
        with self._buffer_lock:
            rows, self._buffer = self._buffer, []
            self._last_flush = time.monotonic()
        if rows:
            columns = (*PACKET_COLUMNS, "stored_at")
            placeholders = ", ".join("?" * len(columns))
            with self._connect() as conn:
                conn.executemany(f"INSERT INTO packets ({', '.join(columns)}) VALUES ({placeholders})", rows)
        if self.retention_days and time.monotonic() - self._last_purge >= 3600:
            self.purge_old_packets()
        return len(rows)

    def query_packets(
        self,
        ip: str | None = None,
        src_ip: str | None = None,
        dst_ip: str | None = None,
        port: int | None = None,
        protocol: str | None = None,
        since: Any = None,
        until: Any = None,
        limit: int = 100,
        offset: int = 0,
    ) -> list[dict[str, Any]]:
        """Return stored packets, newest first. `ip`/`port` match either source or destination."""
        self.flush()
        filters = self._packet_filters(ip, src_ip, dst_ip, port, protocol, since, until)
        sql = f"SELECT * FROM packets{filters.sql} ORDER BY timestamp DESC, id DESC LIMIT ? OFFSET ?"
        rows = self._connect().execute(sql, [*filters.params, limit, offset]).fetchall()
        return [dict(row) for row in rows]

    def count_packets(self, **filters: Any) -> int:
        self.flush()
        built = self._packet_filters(**filters)
        return self._connect().execute(f"SELECT COUNT(*) FROM packets{built.sql}", built.params).fetchone()[0]

    @staticmethod
    def _packet_filters(ip=None, src_ip=None, dst_ip=None, port=None, protocol=None, since=None, until=None) -> _Filters:
        filters = _Filters()
        filters.either(("src_ip", "dst_ip"), ip)
        filters.equals("src_ip", src_ip)
        filters.equals("dst_ip", dst_ip)
        filters.either(("src_port", "dst_port"), port)
        filters.equals("protocol", protocol.upper() if protocol else None)
        filters.time_range(since, until)
        return filters

    def purge_old_packets(self, now: datetime | None = None) -> int:
        """Delete packets stored more than retention_days ago (no-op when 0). Alerts are never purged.

        Age is measured from when the packet was stored, not its capture time,
        so packets from an old PCAP file aren't deleted as soon as they're saved.
        """
        self._last_purge = time.monotonic()
        if not self.retention_days:
            return 0
        cutoff = (now or datetime.now(timezone.utc)) - timedelta(days=self.retention_days)
        with self._connect() as conn:
            deleted = conn.execute("DELETE FROM packets WHERE stored_at < ?", (to_iso(cutoff),)).rowcount
        if deleted:
            logger.info("Purged %d packets older than %d days", deleted, self.retention_days)
        return deleted

    # --- alerts ---------------------------------------------------------------

    def insert_alert(self, alert: dict[str, Any]) -> int:
        """Store an alert_object and return its new alert_id (also set on the dict)."""
        values = dict(alert)
        values["timestamp"] = to_iso(values.get("timestamp")) or to_iso(datetime.now(timezone.utc))
        values["status"] = values.get("status") or "new"
        if values["status"] not in ALERT_STATUSES:
            raise ValueError(f"Invalid alert status: {values['status']!r}")
        row = [values.get(column) for column in ALERT_COLUMNS]
        placeholders = ", ".join("?" * len(ALERT_COLUMNS))
        with self._connect() as conn:
            alert_id = conn.execute(f"INSERT INTO alerts ({', '.join(ALERT_COLUMNS)}) VALUES ({placeholders})", row).lastrowid
        alert["alert_id"] = alert_id
        alert["status"] = values["status"]
        return alert_id

    def get_alert(self, alert_id: int) -> dict[str, Any] | None:
        row = self._connect().execute("SELECT * FROM alerts WHERE id = ?", (alert_id,)).fetchone()
        return self._alert_dict(row) if row else None

    def update_alert_status(self, alert_id: int, status: str) -> bool:
        """Set an alert's status ('new', 'acknowledged' or 'resolved'). Returns False if no such alert."""
        if status not in ALERT_STATUSES:
            raise ValueError(f"Invalid alert status: {status!r} (expected one of {', '.join(ALERT_STATUSES)})")
        with self._connect() as conn:
            return conn.execute("UPDATE alerts SET status = ? WHERE id = ?", (status, alert_id)).rowcount == 1

    def query_alerts(
        self,
        severity: str | Iterable[str] | None = None,
        rule: str | Iterable[str] | None = None,
        status: str | Iterable[str] | None = None,
        ip: str | None = None,
        since: Any = None,
        until: Any = None,
        limit: int = 100,
        offset: int = 0,
    ) -> list[dict[str, Any]]:
        """Return alerts, newest first. `ip` matches source or destination."""
        filters = self._alert_filters(severity, rule, status, ip, since, until)
        sql = f"SELECT * FROM alerts{filters.sql} ORDER BY timestamp DESC, id DESC LIMIT ? OFFSET ?"
        rows = self._connect().execute(sql, [*filters.params, limit, offset]).fetchall()
        return [self._alert_dict(row) for row in rows]

    def count_alerts(self, **filters: Any) -> int:
        built = self._alert_filters(**filters)
        return self._connect().execute(f"SELECT COUNT(*) FROM alerts{built.sql}", built.params).fetchone()[0]

    @staticmethod
    def _alert_filters(severity=None, rule=None, status=None, ip=None, since=None, until=None) -> _Filters:
        filters = _Filters()
        filters.one_of("severity", _as_list(severity))
        filters.one_of("rule", _as_list(rule))
        filters.one_of("status", _as_list(status))
        filters.either(("src_ip", "dst_ip"), ip)
        filters.time_range(since, until)
        return filters

    @staticmethod
    def _alert_dict(row: sqlite3.Row) -> dict[str, Any]:
        data = dict(row)
        data["alert_id"] = data.pop("id")
        return data

    # --- events ---------------------------------------------------------------

    def log_event(self, level: str, source: str, message: str, timestamp: Any = None) -> int:
        """Store a system event, e.g. log_event('WARNING', 'packet_capture', 'Queue full')."""
        with self._connect() as conn:
            return conn.execute(
                "INSERT INTO events (timestamp, level, source, message) VALUES (?, ?, ?, ?)",
                (to_iso(timestamp) or to_iso(datetime.now(timezone.utc)), level.upper(), source, message),
            ).lastrowid

    def recent_events(self, limit: int = 100, level: str | Iterable[str] | None = None, since: Any = None) -> list[dict[str, Any]]:
        filters = _Filters()
        levels = _as_list(level)
        filters.one_of("level", [lvl.upper() for lvl in levels] if levels else None)
        filters.time_range(since, None)
        rows = self._connect().execute(
            f"SELECT * FROM events{filters.sql} ORDER BY timestamp DESC, id DESC LIMIT ?", [*filters.params, limit]
        ).fetchall()
        return [dict(row) for row in rows]

    # --- summaries ------------------------------------------------------------

    def alert_summary(self, since: Any = None, until: Any = None, top_n: int = 10) -> dict[str, Any]:
        """Alert totals by severity, rule and status, plus the top source IPs."""
        filters = _Filters()
        filters.time_range(since, until)
        conn = self._connect()

        def grouped(column: str) -> dict[str, int]:
            sql = f"SELECT {column}, COUNT(*) FROM alerts{filters.sql} GROUP BY {column}"
            return {key: count for key, count in conn.execute(sql, filters.params).fetchall()}

        by_severity = {severity: 0 for severity in SEVERITIES}
        by_severity.update(grouped("severity"))
        top_sources = conn.execute(
            f"SELECT src_ip, COUNT(*) AS n FROM alerts{filters.sql} GROUP BY src_ip ORDER BY n DESC, src_ip LIMIT ?",
            [*filters.params, top_n],
        ).fetchall()
        return {
            "total": sum(by_severity.values()),
            "by_severity": by_severity,
            "by_rule": grouped("rule"),
            "by_status": grouped("status"),
            "top_sources": [{"ip": ip, "alerts": n} for ip, n in top_sources],
        }

    def traffic_summary(self, since: Any = None, until: Any = None, top_n: int = 10) -> dict[str, Any]:
        """Stored packet totals, protocol mix and top talkers."""
        self.flush()
        filters = _Filters()
        filters.time_range(since, until)
        conn = self._connect()
        total, total_bytes = conn.execute(
            f"SELECT COUNT(*), COALESCE(SUM(packet_length), 0) FROM packets{filters.sql}", filters.params
        ).fetchone()
        protocols = conn.execute(f"SELECT protocol, COUNT(*) FROM packets{filters.sql} GROUP BY protocol", filters.params).fetchall()

        def top(column: str) -> list[dict[str, Any]]:
            rows = conn.execute(
                f"SELECT {column}, COUNT(*) AS n FROM packets{filters.sql} GROUP BY {column} ORDER BY n DESC, {column} LIMIT ?",
                [*filters.params, top_n],
            ).fetchall()
            return [{"ip": ip, "packets": n} for ip, n in rows]

        return {
            "total_packets": total,
            "total_bytes": total_bytes,
            "protocols": {protocol: n for protocol, n in protocols},
            "top_sources": top("src_ip"),
            "top_destinations": top("dst_ip"),
        }

    def alerts_per_day(self, days: int = 30, now: datetime | None = None) -> list[dict[str, Any]]:
        """Alert counts per UTC day for the last `days` days, including days with none."""
        end = (now or datetime.now(timezone.utc)).astimezone(timezone.utc).date()
        start = end - timedelta(days=days - 1)
        rows = self._connect().execute(
            "SELECT substr(timestamp, 1, 10) AS day, COUNT(*) FROM alerts WHERE timestamp >= ? GROUP BY day",
            (start.isoformat(),),
        ).fetchall()
        counts = {day: n for day, n in rows}
        return [
            {"date": (start + timedelta(days=i)).isoformat(), "alerts": counts.get((start + timedelta(days=i)).isoformat(), 0)}
            for i in range(days)
        ]


class DatabaseLogHandler(logging.Handler):
    """logging handler that stores records in the events table (e.g. WARNING and above)."""

    def __init__(self, database: Database, level: int = logging.WARNING) -> None:
        super().__init__(level)
        self.database = database
        self._local = threading.local()

    def emit(self, record: logging.LogRecord) -> None:
        if getattr(self._local, "busy", False):
            return  # a database error while logging must not recurse
        self._local.busy = True
        try:
            self.database.log_event(record.levelname, record.name, record.getMessage(), record.created)
        except Exception:
            self.handleError(record)
        finally:
            self._local.busy = False
