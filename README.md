# SecurityGuard

A simplified but realistic **network intrusion detection system (IDS)** written in Python. It captures traffic live or from PCAP files, tracks flows, detects common attacks, and reports alerts. The aim is breadth with a readable codebase, not a replacement for Snort or Suricata.

> **Status:** the detection pipeline works end to end from the command line (capture → parse → analyze → detect → alerts), and packets and alerts are stored in SQLite. The Alert Manager, the Flask dashboard and reporting are in progress. See [docs/ROADMAP.md](docs/ROADMAP.md).

## Features

**Working now**

- Live capture (Scapy) with BPF filters, or offline analysis of PCAP files
- Parsing of Ethernet, IPv4, TCP, UDP and ICMP into a standard packet format
- Flow tracking plus per-source sliding windows (rates, SYN/ACK counts, distinct ports and hosts)
- Detection of:
  - port scans
  - SYN floods
  - ICMP floods
  - brute force against SSH, FTP, Telnet and RDP
  - blocked ports, IPs and protocols
  - connections to suspicious backdoor ports
  - payload signatures (substring or regex)
- Alert severity (Medium → High → Critical) that escalates as an attack grows, with a cooldown so an ongoing attack doesn't flood you with alerts
- One validated YAML config for all settings
- SQLite storage of packets, alerts and warning events (`data/ids.db` by default), with automatic cleanup of old packets

**Planned:** alert history, correlation and export, a Flask dashboard (live traffic, alerts, statistics, packet viewer, settings), CSV/PDF reports, and attack-simulation tooling with accuracy metrics.

## How it works

```text
Network interface / PCAP file
        │  Scapy packets
        ▼
Packet Capture ──▶ Packet Parser ──▶ Traffic Analyzer ──▶ Detection Engine ──▶ Alerts
                    packet_dict        + flow_object        alert_object
```

Each arrow is a documented data format. See [docs/CONTRACTS.md](docs/CONTRACTS.md) before changing what a module produces or consumes.

## Getting started

Requires **Python 3.10+** (developed on 3.12).

### Linux / WSL

```bash
python3 -m venv ids
source ids/bin/activate
pip install -r requirements.txt
```

### Windows

1. Install [Npcap](https://npcap.com/) and tick **"WinPcap API-compatible mode"**. Scapy needs it for live capture.
2. Then:

```powershell
python -m venv ids
ids\Scripts\activate
pip install -r requirements.txt
```

## Usage

Analyze a PCAP file. This needs no special rights:

```bash
python main.py --pcap capture.pcap
```

Capture live traffic. This needs **root** on Linux (use the venv's Python, since `sudo` doesn't keep the activated venv), or a terminal opened **as Administrator** on Windows:

```bash
sudo ids/bin/python main.py --duration 60
```

```bash
sudo ids/bin/python main.py --interface eth0 --filter "tcp or icmp"
```

List the interfaces you can capture on:

```bash
python main.py --list-interfaces
```

| Option | Description |
|---|---|
| `--pcap FILE` | Analyze a PCAP file instead of live traffic |
| `-i`, `--interface NAME` | Live capture interface (default: from config, or auto-detected) |
| `-f`, `--filter EXPR` | BPF capture filter, e.g. `"tcp or icmp"` |
| `-d`, `--duration SECONDS` | Stop live capture after this long (default: until Ctrl+C) |
| `-c`, `--config FILE` | Use a different config file |
| `--json` | Print alerts as JSON lines (for scripts) |
| `--no-db` | Don't store packets and alerts in the database |
| `--list-interfaces` | List capture interfaces and exit |
| `-v`, `--verbose` | Debug logging |

Example output:

```text
[2026-09-21T14:13:21.014000+00:00] MEDIUM   Port Scan        10.0.0.66 -> 192.168.1.10:7  Connection attempts to 7 distinct destination ports in the last 60s. (confidence 0.75)
[2026-09-21T14:13:31.399994+00:00] MEDIUM   Brute Force      10.0.0.88 -> 192.168.1.10:22  Repeated SSH connection attempts detected (5 attempts in the last 60s). (confidence 0.74)
[2026-09-21T14:13:38.010022+00:00] HIGH     Signature Match  10.0.0.55 -> 192.168.1.10:80  Payload matched signature 'Path traversal'. (confidence 0.90)

Summary
  Packets processed : 689
  Packets skipped   : 20 (unsupported protocols)
  Errors            : 0
  Alerts            : 14
  Stored in         : data/ids.db
```

> **WSL note:** WSL 2 runs in a virtual machine, so live capture on `eth0` only sees WSL's own traffic, not your Windows host's Wi-Fi. To monitor the host's network, run SecurityGuard on Windows itself.

## Configuration

All settings are in [`configuration/ids.yaml`](configuration/ids.yaml). Every setting is optional; anything left out uses its default. To use another file, pass `--config` or set the `IDS_CONFIG` environment variable.

| Section | Controls |
|---|---|
| `capture` | Interface, BPF filter, capture queue size |
| `traffic` | Sliding-window length, idle-flow timeout |
| `detection` | Which detectors are enabled, alert cooldown, per-detector thresholds, blocked/suspicious ports and IPs, payload signatures |
| `logging` | SQLite database path, whether packets are stored, how many days to keep them |
| `dashboard` | Host and port for the web UI *(used from Phase 9)* |

The signature detector is off by default. To turn it on, add `signatures` to `detection.enabled` and define some patterns:

```yaml
detection:
  enabled: [port_scan, syn_flood, icmp_flood, brute_force, custom_rules, signatures]
  signatures:
    - {name: "Path traversal", pattern: "../../", severity: High}
    - {name: "SQL injection", pattern: "union\\s+select", regex: true, severity: Critical}
```

The config is checked on load. A typo or bad value stops the program with an error naming the exact setting, e.g. `detection.brute_force.ports[1]: port must be 1-65535`. The full reference is in [docs/CONTRACTS.md §5](docs/CONTRACTS.md).

## Project structure

| Folder | Module | Owner | Status |
|---|---|---|---|
| `packet_capture/` | Live capture, PCAP replay, filters, interfaces | Person A | ✅ |
| `packet_parser/` | Scapy packet → `packet_dict` | Person B | ✅ |
| `traffic_analyzer/` | Flows, per-source windows, traffic stats | Person B | ✅ |
| `detection_engine/` | Dispatcher + one folder per detector | Person A | ✅ |
| `configuration/` | Config manager and `ids.yaml` | Person A | ✅ |
| `pipeline/`, `main.py` | Pipeline runner and command line | Person A | ✅ |
| `logger_sqlite/` | SQLite storage and queries | Person A | ✅ |
| `alert_manager/` | Alert history, correlation, export | Person B | ⬜ |
| `dashboard_flask/` | REST API and web dashboard | Person B | ⬜ |
| `reporting/` | Summaries, CSV/PDF reports | Person A | ⬜ |
| `testing_utilities/` | Attack simulation, accuracy metrics | Person A | ⬜ |
| `docs/` | [CONTRACTS.md](docs/CONTRACTS.md) (data formats), [ROADMAP.md](docs/ROADMAP.md) (plan and progress) | Both | |

## Running the tests

```bash
python -m pytest
```

Each module has its own `tests/` folder. The tests use generated packets and temporary PCAP files, so they need no network access or root rights.

## Team

| | Role | Modules |
|---|---|---|
| **Person A** | Detection & Backend | Packet Capture, Detection Engine, Database, Testing |
| **Person B** | Processing & Frontend | Packet Parser, Alert Manager, API, Dashboard |

Tasks in the roadmap carry these labels, so either person can see what's theirs and pick up where the other left off.

## Responsible use

Only capture or test traffic on networks you own or have explicit permission to monitor. Run attack simulations against your own machines or an isolated lab network.
