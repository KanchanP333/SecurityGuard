"""Unit tests for the SQLite database layer."""

from datetime import datetime, timedelta, timezone
import logging
import sqlite3
import threading

import pytest

from configuration import Config, merge_config
from logger_sqlite import Database, DatabaseLogHandler, to_iso
from traffic_analyzer.tests.helpers import BASE_TIME, packet

T0 = datetime.fromtimestamp(BASE_TIME, tz=timezone.utc)


@pytest.fixture
def db(tmp_path):
    database = Database(tmp_path / "ids.db", batch_size=1000, flush_interval=3600)
    yield database
    database.close()


def alert(t=0.0, rule="port_scan", severity="Medium", src_ip="10.0.0.5", dst_ip="10.0.0.1", **extra):
    data = {
        "alert_id": None,
        "timestamp": (T0 + timedelta(seconds=t)).isoformat(),
        "rule": rule,
        "attack_type": rule.replace("_", " ").title(),
        "severity": severity,
        "confidence": 0.8,
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "dst_port": 80,
        "protocol": "TCP",
        "flow_id": "TCP:10.0.0.5:40000->10.0.0.1:80",
        "description": "test",
    }
    data.update(extra)
    return data


# --- setup ----------------------------------------------------------------------


def test_creates_schema_and_parent_folder(tmp_path):
    path = tmp_path / "nested" / "dir" / "ids.db"
    with Database(path):
        pass
    conn = sqlite3.connect(path)
    tables = {row[0] for row in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    assert {"packets", "alerts", "events"} <= tables
    assert conn.execute("PRAGMA user_version").fetchone()[0] == 1
    assert conn.execute("PRAGMA journal_mode").fetchone()[0] == "wal"


def test_reopening_keeps_data(tmp_path):
    with Database(tmp_path / "ids.db") as first:
        first.insert_alert(alert())
    with Database(tmp_path / "ids.db") as second:
        assert second.count_alerts() == 1


def test_from_settings(tmp_path):
    config = merge_config(Config(), {"logging": {"db_path": str(tmp_path / "x.db"), "packet_retention_days": 3}})
    with Database.from_settings(config.logging) as database:
        assert database.path == tmp_path / "x.db"
        assert database.retention_days == 3


def test_closed_database_refuses_use(db):
    db.close()
    with pytest.raises(RuntimeError):
        db.insert_alert(alert())


def test_to_iso_normalizes_formats():
    expected = "2026-09-21T14:13:20.000000+00:00"
    assert to_iso(T0) == expected
    assert to_iso(BASE_TIME) == expected
    assert to_iso("2026-09-21T14:13:20+00:00") == expected
    assert to_iso(datetime(2026, 9, 21, 14, 13, 20)) == expected
    assert to_iso(None) is None


# --- packets --------------------------------------------------------------------


def test_packets_are_buffered_until_flush(db, tmp_path):
    db.insert_packet(packet())
    raw = sqlite3.connect(tmp_path / "ids.db")
    assert raw.execute("SELECT COUNT(*) FROM packets").fetchone()[0] == 0
    assert db.flush() == 1
    assert raw.execute("SELECT COUNT(*) FROM packets").fetchone()[0] == 1


def test_batch_size_triggers_flush(tmp_path):
    with Database(tmp_path / "ids.db", batch_size=3, flush_interval=3600) as database:
        for i in range(3):
            database.insert_packet(packet(t=i))
        raw = sqlite3.connect(tmp_path / "ids.db")
        assert raw.execute("SELECT COUNT(*) FROM packets").fetchone()[0] == 3


def test_close_flushes(tmp_path):
    database = Database(tmp_path / "ids.db", batch_size=1000, flush_interval=3600)
    database.insert_packet(packet())
    database.close()
    assert sqlite3.connect(tmp_path / "ids.db").execute("SELECT COUNT(*) FROM packets").fetchone()[0] == 1


def test_stored_packet_fields(db):
    db.insert_packet(packet(t=1.5, flags="SYN,ACK", length=74), {"flow_id": "ignored"})
    stored = db.query_packets()[0]
    assert stored["timestamp"] == "2026-09-21T14:13:21.500000+00:00"
    assert stored["flags"] == "SYN,ACK"
    assert stored["packet_length"] == 74
    assert stored["dst_port"] == 80
    assert "payload" not in stored
    assert stored["stored_at"] > stored["timestamp"]


def test_query_packets_filters_and_order(db):
    db.insert_packet(packet(t=0, src_ip="10.0.0.5", dst_ip="10.0.0.1", dst_port=80))
    db.insert_packet(packet(t=1, src_ip="10.0.0.1", dst_ip="10.0.0.5", src_port=80, dst_port=40000, flags="SYN,ACK"))
    db.insert_packet(packet(t=2, protocol="UDP", src_ip="10.0.0.9", dst_ip="8.8.8.8", dst_port=53))
    db.insert_packet(packet(t=3, protocol="ICMP", src_ip="10.0.0.9", dst_ip="10.0.0.5"))

    assert [p["timestamp"][17:19] for p in db.query_packets()] == ["23", "22", "21", "20"]
    assert len(db.query_packets(ip="10.0.0.5")) == 3
    assert len(db.query_packets(src_ip="10.0.0.9")) == 2
    assert len(db.query_packets(dst_ip="8.8.8.8")) == 1
    assert len(db.query_packets(port=80)) == 2
    assert len(db.query_packets(protocol="udp")) == 1
    assert len(db.query_packets(since=T0 + timedelta(seconds=1), until=T0 + timedelta(seconds=3))) == 2
    assert len(db.query_packets(limit=2, offset=1)) == 2
    assert db.count_packets(src_ip="10.0.0.9") == 2
    assert db.count_packets() == 4


def test_retention_uses_storage_time_not_capture_time(tmp_path):
    with Database(tmp_path / "ids.db", retention_days=7) as database:
        database.insert_packet(packet())  # captured long ago (2026-09-21)
        database.flush()
        assert database.purge_old_packets() == 0
        assert database.count_packets() == 1
        assert database.purge_old_packets(now=datetime.now(timezone.utc) + timedelta(days=8)) == 1
        assert database.count_packets() == 0


def test_zero_retention_keeps_everything(db):
    db.insert_packet(packet())
    db.flush()
    assert db.purge_old_packets(now=datetime.now(timezone.utc) + timedelta(days=365)) == 0


# --- alerts ---------------------------------------------------------------------


def test_insert_alert_sets_id_and_status(db):
    data = alert()
    alert_id = db.insert_alert(data)
    assert data["alert_id"] == alert_id
    assert data["status"] == "new"
    stored = db.get_alert(alert_id)
    assert stored["alert_id"] == alert_id
    assert stored["rule"] == "port_scan"
    assert stored["timestamp"] == "2026-09-21T14:13:20.000000+00:00"
    assert "id" not in stored


def test_get_missing_alert(db):
    assert db.get_alert(999) is None


def test_update_alert_status(db):
    alert_id = db.insert_alert(alert())
    assert db.update_alert_status(alert_id, "acknowledged") is True
    assert db.get_alert(alert_id)["status"] == "acknowledged"
    assert db.update_alert_status(999, "resolved") is False
    with pytest.raises(ValueError):
        db.update_alert_status(alert_id, "deleted")


def test_query_alerts_filters(db):
    db.insert_alert(alert(t=0, rule="port_scan", severity="Medium", src_ip="10.0.0.5"))
    db.insert_alert(alert(t=1, rule="port_scan", severity="Critical", src_ip="10.0.0.5"))
    db.insert_alert(alert(t=2, rule="icmp_flood", severity="High", src_ip="10.0.0.8", dst_ip="10.0.0.5"))
    resolved = db.insert_alert(alert(t=3, rule="brute_force", severity="High", src_ip="10.0.0.7"))
    db.update_alert_status(resolved, "resolved")

    assert [a["rule"] for a in db.query_alerts()] == ["brute_force", "icmp_flood", "port_scan", "port_scan"]
    assert len(db.query_alerts(severity="High")) == 2
    assert len(db.query_alerts(severity=["High", "Critical"])) == 3
    assert len(db.query_alerts(rule="port_scan")) == 2
    assert len(db.query_alerts(status="new")) == 3
    assert len(db.query_alerts(ip="10.0.0.5")) == 3
    assert len(db.query_alerts(since=T0 + timedelta(seconds=2))) == 2
    assert db.count_alerts(rule=["port_scan", "icmp_flood"]) == 3


# --- events ---------------------------------------------------------------------


def test_events(db):
    db.log_event("info", "pipeline", "started", timestamp=T0)
    db.log_event("WARNING", "packet_capture", "queue full", timestamp=T0 + timedelta(seconds=1))
    events = db.recent_events()
    assert [e["message"] for e in events] == ["queue full", "started"]
    assert events[1]["level"] == "INFO"
    assert [e["message"] for e in db.recent_events(level="warning")] == ["queue full"]


def test_log_handler_stores_warnings(db):
    log = logging.getLogger("securityguard.test")
    handler = DatabaseLogHandler(db)
    log.addHandler(handler)
    try:
        log.info("ignored")
        log.warning("disk almost full")
    finally:
        log.removeHandler(handler)
    events = db.recent_events()
    assert len(events) == 1
    assert (events[0]["level"], events[0]["source"], events[0]["message"]) == ("WARNING", "securityguard.test", "disk almost full")


# --- summaries ------------------------------------------------------------------


def test_alert_summary(db):
    db.insert_alert(alert(severity="Medium", rule="port_scan", src_ip="10.0.0.5"))
    db.insert_alert(alert(severity="High", rule="port_scan", src_ip="10.0.0.5"))
    db.insert_alert(alert(severity="High", rule="icmp_flood", src_ip="10.0.0.8"))
    summary = db.alert_summary()
    assert summary["total"] == 3
    assert summary["by_severity"] == {"Low": 0, "Medium": 1, "High": 2, "Critical": 0}
    assert summary["by_rule"] == {"port_scan": 2, "icmp_flood": 1}
    assert summary["by_status"] == {"new": 3}
    assert summary["top_sources"][0] == {"ip": "10.0.0.5", "alerts": 2}


def test_traffic_summary(db):
    db.insert_packet(packet(length=100))
    db.insert_packet(packet(length=100))
    db.insert_packet(packet(protocol="UDP", src_ip="10.0.0.9", length=50))
    summary = db.traffic_summary()
    assert summary["total_packets"] == 3
    assert summary["total_bytes"] == 250
    assert summary["protocols"] == {"TCP": 2, "UDP": 1}
    assert summary["top_sources"][0] == {"ip": "10.0.0.5", "packets": 2}


def test_alerts_per_day_fills_gaps(db):
    db.insert_alert(alert(t=0))
    db.insert_alert(alert(t=60))
    db.insert_alert(alert(t=2 * 86400))
    days = db.alerts_per_day(days=4, now=T0 + timedelta(days=2))
    assert days == [
        {"date": "2026-09-20", "alerts": 0},
        {"date": "2026-09-21", "alerts": 2},
        {"date": "2026-09-22", "alerts": 0},
        {"date": "2026-09-23", "alerts": 1},
    ]


# --- threads --------------------------------------------------------------------


def test_concurrent_writer_and_reader(db):
    errors = []

    def write():
        try:
            for i in range(2000):
                db.insert_packet(packet(t=i * 0.001))
            db.flush()
        except Exception as exc:
            errors.append(exc)

    def read():
        try:
            for _ in range(50):
                db.query_packets(limit=10)
                db.alert_summary()
        except Exception as exc:
            errors.append(exc)

    threads = [threading.Thread(target=write), threading.Thread(target=read), threading.Thread(target=read)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert errors == []
    assert db.count_packets() == 2000
