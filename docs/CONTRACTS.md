# Module Contracts

The data formats passed between SecurityGuard modules. Any change here must be agreed by Person A and Person B.

```text
Capture ──Scapy Packet──▶ Parser ──packet_dict──▶ Analyzer ──packet_dict + flow_object──▶ Detection
Detection ──alert_object──▶ Alert Manager ──▶ Database (alert_id assigned) / Dashboard
```

---

## 1. `packet_dict` — Packet Parser → Analyzer, Detection, Database

Produced by `packet_parser.parse_packet(packet)`. Only IPv4 + TCP/UDP/ICMP packets are parsed; everything else raises `UnsupportedProtocolError`, and callers should skip those packets.

| Key | Type | Notes |
|---|---|---|
| `timestamp` | `datetime` (UTC, tz-aware) | Taken from the packet's capture time, so it's also correct for PCAP replay |
| `src_mac`, `dst_mac` | `str \| None` | `None` when there is no Ethernet layer |
| `src_ip`, `dst_ip` | `str` | |
| `src_port`, `dst_port` | `int \| None` | `None` for ICMP |
| `protocol` | `str` | `"TCP"`, `"UDP"` or `"ICMP"` |
| `flags` | `str \| None` | TCP only. Comma-separated names in header bit order: `FIN,SYN,RST,PSH,ACK,URG,ECE,CWR,NS`. e.g. `"SYN"`, `"SYN,ACK"`, `"PSH,ACK"`. `None` for UDP/ICMP or no flags |
| `ttl` | `int \| None` | |
| `packet_length` | `int` | Full frame length in bytes |
| `payload_size` | `int` | Full L4 payload length |
| `payload` | `bytes` | First 512 bytes of the L4 payload (`PAYLOAD_CAPTURE_LIMIT`). Used for signature matching. Not stored in the database |
| `icmp_type`, `icmp_code` | `int \| None` | ICMP only |

To check flags, split rather than doing a substring match: `"SYN" in set((flags or "").split(","))`.

---

## 2. `flow_object` — Traffic Analyzer → Detection

Returned by the Traffic Analyzer for every packet. It describes the packet's flow (directional 5-tuple) plus a sliding window of activity from the packet's source IP.

| Key | Type | Notes |
|---|---|---|
| `flow_id` | `str` | `"TCP:10.0.0.5:51432->10.0.0.1:80"`; ICMP: `"ICMP:10.0.0.5->10.0.0.1"` |
| `protocol`, `src_ip`, `dst_ip`, `src_port`, `dst_port` | as in `packet_dict` | |
| `first_seen`, `last_seen` | `datetime` (UTC) | Packet timestamps, not the wall clock |
| `duration` | `float` | Seconds, `last_seen - first_seen` |
| `packet_count` | `int` | Packets in this flow |
| `bytes` | `int` | Sum of `packet_length` |
| `pps` | `float` | `packet_count / max(duration, 1.0)`. The 1s floor stops two quick packets from reading as a flood |
| `syn_count` | `int` | Packets with SYN and without ACK |
| `ack_count` | `int` | Packets with ACK |
| `src_window` | `dict` | Activity from `src_ip` over the last `window_seconds` (all flows): |
| `src_window.window_seconds` | `int` | From config, default 60 |
| `src_window.packet_count` | `int` | |
| `src_window.pps` | `float` | Recent packet rate (see below) |
| `src_window.syn_count`, `src_window.ack_count` | `int` | |
| `src_window.icmp_count` | `int` | |
| `src_window.icmp_pps` | `float` | Recent ICMP packet rate (see below) |
| `src_window.unique_dst_ports` | `int` | Distinct destination ports of connection attempts (TCP SYN without ACK, and UDP). Replies are excluded, so a busy server isn't mistaken for a scanner |
| `src_window.unique_dst_ips` | `int` | Distinct destination hosts contacted |

`src_window` counts are kept in 1-second buckets and cover the whole window. The rates (`pps`, `icmp_pps`) only cover the **last 5 seconds**: packets in the last 5 s divided by 5, or by the time since the source's oldest packet in the window if that is shorter (minimum 1 s). A new burst therefore shows its real rate, and earlier quiet periods don't dilute a flood. A flood shorter than 5 s from an already-known source is under-measured by up to 5×.

The analyzer also provides `get_stats()` (global totals, pps/bps over the last 5 s, protocol mix, top 10 source/destination IPs, active flow count, per-second history for the last 300 s) and `get_flows(limit)` (active flows, newest first, without `src_window`) for the API and dashboard.

Use the per-flow fields for single-connection behaviour. Use `src_window` for attacks that span many connections (port scan, SYN flood with random source ports, ICMP flood).

---

## 3. `alert_object` — Detection → Alert Manager → Database / Dashboard

Detectors have the signature `detect(packet_dict, flow_object, settings: DetectionSettings) -> dict | None` and return only the fields they know (`attack_type`, `severity`, `confidence`, `description`, optionally `src_ip`/`dst_ip`), plus an optional internal `dedup_key`. `detection_engine.engine.run_engine(packet_dict, flow_object, enabled_detectors=None, settings=None)` fills in the rest, so every alert leaving the engine has all fields below.

**Cooldown:** the engine raises at most one alert per (`rule`, `dedup_key`) every `detection.alert_cooldown_seconds`, measured in packet time. `dedup_key` defaults to `src_ip`; brute force uses `src->dst:port`, custom rules and signatures include the matched rule. `engine.reset()` clears cooldowns and detector state.

| Key | Type | Set by | Notes |
|---|---|---|---|
| `alert_id` | `int \| None` | Alert Manager | `None` until stored; then the database row id |
| `timestamp` | `str` | Engine | ISO 8601 UTC from the packet time, e.g. `"2026-09-24T10:15:02.123456+00:00"` |
| `rule` | `str` | Engine | Detector id: `port_scan`, `syn_flood`, `icmp_flood`, `brute_force`, `custom_rules` (matches config keys) |
| `attack_type` | `str` | Detector | Display name, e.g. `"Port Scan"` |
| `severity` | `str` | Detector, may be raised by Alert Manager | `"Low"`, `"Medium"`, `"High"`, `"Critical"` |
| `confidence` | `float` | Detector | 0.0–1.0, rounded to 2 decimals |
| `src_ip`, `dst_ip` | `str \| None` | Engine/Detector | |
| `dst_port` | `int \| None` | Engine | |
| `protocol` | `str \| None` | Engine | |
| `flow_id` | `str \| None` | Engine | Links to the flow that triggered it |
| `description` | `str` | Detector | Human-readable explanation |
| `status` | `str` | Alert Manager | `"new"`, `"acknowledged"`, `"resolved"` |

---

## 4. Database tables (Person A, Module 3)

Column names match the contract keys. Timestamps are stored as ISO 8601 UTC `TEXT`.

- **packets**: `id`, `timestamp`, `src_mac`, `dst_mac`, `src_ip`, `dst_ip`, `src_port`, `dst_port`, `protocol`, `flags`, `ttl`, `packet_length`, `payload_size`, `icmp_type`, `icmp_code`
- **alerts**: `id` (→ `alert_id`), `timestamp`, `rule`, `attack_type`, `severity`, `confidence`, `src_ip`, `dst_ip`, `dst_port`, `protocol`, `flow_id`, `description`, `status`
- **events**: `id`, `timestamp`, `level` (`INFO`/`WARNING`/`ERROR`), `source` (module name), `message`

---

## 5. Configuration file — `configuration/ids.yaml`

Loaded by `configuration.load_config()` into a typed `Config` object (`config.detection.port_scan.unique_ports_threshold`, etc.). Every setting is optional: missing settings use the defaults below.

- **Location:** `configuration/ids.yaml`, or the path in the `IDS_CONFIG` environment variable.
- **Validation:** unknown keys, wrong types and out-of-range values raise `ConfigError` naming the exact setting, e.g. `detection.brute_force.ports[1]: port must be 1-65535`.
- **Shared instance:** `get_config()` / `set_config()` / `reload_config()`. The dashboard applies partial changes with `merge_config(config, changes)` and writes them with `save_config(config)` (atomic; comments in the file are not kept).
- **Capture overrides:** `CAPTURE_INTERFACE`, `CAPTURE_FILTER` and `CAPTURE_QUEUE_SIZE` environment variables still override the `capture` section.

```yaml
capture:
  interface: Wi-Fi          # empty = auto-detect
  filter: ""                # BPF subset; "tcp" alone hides ICMP/UDP from detection
  packet_limit: 1000        # capture queue size, 0 = unbounded

traffic:
  window_seconds: 60        # src_window length
  flow_timeout_seconds: 120 # idle flows are evicted after this

detection:
  enabled: [port_scan, syn_flood, icmp_flood, brute_force, custom_rules]
  alert_cooldown_seconds: 300
  port_scan:    { unique_ports_threshold: 7 }
  syn_flood:    { syn_threshold: 10, ack_threshold: 2 }
  icmp_flood:   { pps_threshold: 20 }
  brute_force:  { attempts_threshold: 5, window_seconds: 60, ports: [22, 21, 23, 3389] }
  custom_rules:
    blocked_ports: []
    suspicious_ports: [23, 2323, 4444, 5555, 6667, 31337]
    blocked_ips: []
    blocked_protocols: []
  signatures: []            # [{name, pattern, regex (default false = substring), severity}] matched against packet_dict.payload

logging:
  enabled: true
  db_path: data/ids.db
  store_packets: true

dashboard:
  host: 127.0.0.1
  port: 5000
```
