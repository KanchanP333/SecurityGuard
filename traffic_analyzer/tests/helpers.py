"""Builders for packet_dict test inputs."""

from datetime import datetime, timezone

BASE_TIME = 1_790_000_000.0


def packet(
    t: float = 0.0,
    protocol: str = "TCP",
    src_ip: str = "10.0.0.5",
    dst_ip: str = "10.0.0.1",
    src_port: int | None = 40000,
    dst_port: int | None = 80,
    flags: str | None = "SYN",
    length: int = 60,
) -> dict:
    """Return a packet_dict at BASE_TIME + t seconds."""
    if protocol == "ICMP":
        src_port = dst_port = None
        flags = None
    elif protocol == "UDP":
        flags = None
    return {
        "timestamp": datetime.fromtimestamp(BASE_TIME + t, tz=timezone.utc),
        "src_mac": None,
        "dst_mac": None,
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "src_port": src_port,
        "dst_port": dst_port,
        "protocol": protocol,
        "flags": flags,
        "ttl": 64,
        "packet_length": length,
        "payload_size": 0,
        "payload": b"",
        "icmp_type": 8 if protocol == "ICMP" else None,
        "icmp_code": 0 if protocol == "ICMP" else None,
    }
