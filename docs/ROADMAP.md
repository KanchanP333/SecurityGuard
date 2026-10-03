# SecurityGuard Roadmap

A simplified but realistic network IDS (Scapy + SQLite + Flask). Data formats: [CONTRACTS.md](CONTRACTS.md).

**Legend:** ✅ done · 🟡 in progress · ⬜ not started
**Owners:** **A** = Person A (Detection & Backend) · **B** = Person B (Processing & Frontend)
*(proposed)* = the module was not assigned in the original split; the owner listed is a suggestion.
*(by B for A)* = Person B did Person A's work while they were away. Person A should review it on return.

```text
Network / PCAP
   │
   ▼
Packet Capture ........ A   ✅ (Phase 2 fixes done)
   │
   ▼
Packet Parser ......... B   ✅
   │
   ▼
Traffic Analyzer ...... B   ✅ (proposed)
   │
   ▼
Detection Engine ...... A   ✅ (refinement pending)
   │
   ▼
Alert Manager ......... B   ⬜
   ├──▶ SQLite DB ..... A   ⬜
   └──▶ Flask API ..... B   ⬜ ──▶ Dashboard ... B ⬜

Config Manager ........ A   ✅ (proposed)
Pipeline Runner ....... A   ⬜ (proposed)
Reporting ............. A   ⬜ (proposed)
Testing ............... A   ⬜
```

---

## Phase 0 — Foundation ✅

| # | Owner | Status | Task |
|---|---|---|---|
| 0.1 | A | ✅ | Project folder structure (snake_case) |
| 0.2 | A | ✅ | Packet Capture: live sniffing (`AsyncSniffer`), capture queue, BPF filter validation, interface discovery, stats, PCAP loading |
| 0.3 | A | ✅ | Detection Engine: dispatcher + port scan, SYN flood, ICMP flood, brute force, custom rules detectors |
| 0.4 | B | ✅ | Packet Parser: Scapy packet → `packet_dict`, validators, exceptions, 27 unit tests |
| 0.5 | B | ✅ | `.gitignore`; stopped tracking `.pyc` files |

## Phase 1 — Agree on data formats

| # | Owner | Status | Task |
|---|---|---|---|
| 1.1 | B | ✅ | Write `docs/CONTRACTS.md` (`packet_dict`, `flow_object`, `alert_object`, DB tables, config file) |
| 1.2 | B | ✅ | Parser follows the format: TCP flags as names (`"SYN,ACK"`), adds `payload` (first 512 bytes) |
| 1.3 | A *(by B for A)* | ✅ | Detectors use `src_ip`/`dst_ip`; engine fills `rule`, `timestamp` (ISO), `dst_port`, `protocol`, `flow_id`, `alert_id`; `custom_rules` on by default. Fixes the flags mismatch that stopped all TCP detectors from firing |
| 1.4 | A | ⬜ | Person A reviews `CONTRACTS.md` and the changes in 1.3 |

## Phase 2 — Fix the capture module (A) ✅ *(by B for A)*

| # | Owner | Status | Task |
|---|---|---|---|
| 2.1 | A *(by B for A)* | ✅ | Package imports in `capture.py`; run it with `python -m packet_capture.capture` |
| 2.2 | A *(by B for A)* | ✅ | Config path now `configuration/capture.yaml`; PyYAML added (it was missing, so the YAML was silently ignored) |
| 2.3 | A *(by B for A)* | ✅ | Debug `print`s replaced with `logging`; dropped packets counted in `STATE.dropped` |
| 2.4 | A *(by B for A)* | ✅ | `capture.replay_pcap(path)` streams a PCAP into the same queue as live capture (blocking, no drops; sets `stop_event` when done). `pcap.py` now has `load_pcap` and streaming `iter_pcap` |
| 2.5 | A *(by B for A)* | ✅ | Default capture filter is empty, so ICMP/UDP reach the detectors |
| 2.6 | A *(by B for A)* | ✅ | Unknown interface (e.g. `Wi-Fi` on Linux) falls back to auto-detection with a warning; auto-detection skips Linux `lo`; PowerShell discovery only runs on Windows (it crashed on WSL) |
| 2.7 | A *(by B for A)* | ✅ | 43 unit tests in `packet_capture/tests/` (filters, stats, PCAP, interface, config, queueing, replay) |

## Phase 3 — Traffic Analyzer (B, proposed) → `traffic_analyzer/` ✅

| # | Owner | Status | Task |
|---|---|---|---|
| 3.1 | B | ✅ | Flow table keyed by `flow_id`; `analyze(packet_dict) -> flow_object` (`flows.py`, `analyzer.py`) |
| 3.2 | B | ✅ | Per-source sliding window (`src_window`) in 1-second buckets: pps, SYN/ACK/ICMP counts, unique dst ports/IPs (`windows.py`) |
| 3.3 | B | ✅ | Packet timestamps used throughout, so PCAP replay gives the same results as live capture |
| 3.4 | B | ✅ | Idle-flow eviction, quiet-source eviction, caps of 100k flows / 100k sources |
| 3.5 | B | ✅ | `get_stats()`: totals, pps/bps, protocol mix, top talkers, 5-minute per-second history; `get_flows()` for the API (`stats.py`) |
| 3.6 | B | ✅ | 27 unit tests in `traffic_analyzer/tests/` |

## Phase 4 — Configuration Manager (A, proposed) → `configuration/` ✅ *(by B for A)*

| # | Owner | Status | Task |
|---|---|---|---|
| 4.1 | A *(by B for A)* | ✅ | `configuration/ids.yaml` using the schema in CONTRACTS.md §5 (`capture.yaml` removed) |
| 4.2 | A *(by B for A)* | ✅ | `load_config() -> Config` (typed dataclasses), defaults for every setting, strict validation with errors that name the setting (`config.py`) |
| 4.3 | A *(by B for A)* | ✅ | `merge_config()` for partial updates and atomic `save_config()` for the dashboard settings page |
| 4.4 | A *(by B for A)* | ✅ | Capture reads `config.capture`; the analyzer takes `TrafficAnalyzer(**asdict(config.traffic))`. Detection thresholds are connected in **5.3**, the logger in **Phase 7**, the runner passes it all through in **Phase 6** |
| 4.5 | A *(by B for A)* | ✅ | 39 unit tests in `configuration/tests/` |

## Phase 5 — Detection engine refinement (A)

| # | Owner | Status | Task |
|---|---|---|---|
| 5.1 | A | ⬜ | Detectors read `flow_object` (`src_window` for port scan / SYN flood / ICMP flood) instead of keeping their own counters |
| 5.2 | A | ⬜ | ICMP flood: drop the `monotonic()` wall clock (wrong for PCAP replay) and use the analyzer's rate |
| 5.3 | A | ⬜ | Thresholds come from config instead of module constants; engine takes `enabled` from config |
| 5.4 | A | ⬜ | Re-alerting: `alerted` is currently set once per key forever and trackers never expire. Add a cooldown, state expiry, and a `reset()` for tests |
| 5.5 | A | ⬜ | Brute force: configurable service ports (SSH, FTP, Telnet, RDP) and a time window |
| 5.6 | A | ⬜ | Suspicious-port detection via `custom_rules.suspicious_ports` |
| 5.7 | A | ⬜ | Signature matching: new `signatures` detector that matches config patterns against `packet_dict.payload` |
| 5.8 | A | ⬜ | Unit tests for each detector and the engine (there are none today) |

## Phase 6 — Pipeline runner (A, proposed) → `main.py`

| # | Owner | Status | Task |
|---|---|---|---|
| 6.1 | A | ⬜ | Worker loop: capture queue → parse (skip unsupported) → analyze → detect → Alert Manager |
| 6.2 | A | ⬜ | CLI: `--config`, `--interface`, `--pcap <file>` |
| 6.3 | A | ⬜ | Clean shutdown (Ctrl+C stops the sniffer, flushes the DB) |

**🎯 Milestone 1:** an attack PCAP replayed through `main.py` prints correct alerts.

## Phase 7 — Database layer (A, Module 3) → `logger_sqlite/`

| # | Owner | Status | Task |
|---|---|---|---|
| 7.1 | A | ⬜ | Schema (CONTRACTS.md §4): `packets`, `alerts`, `events`, with indexes on `timestamp`, `src_ip`, `rule`, `severity` |
| 7.2 | A | ⬜ | `insert_alert(alert) -> alert_id`, `insert_packet(packet_dict)`, `log_event(level, source, message)` |
| 7.3 | A | ⬜ | Queries: recent alerts; filter by severity/rule/IP/time range; packet search; aggregates for stats |
| 7.4 | A | ⬜ | Thread safety (single writer thread or per-thread connections) and batched packet inserts |
| 7.5 | A | ⬜ | Retention / cleanup of old packets |
| 7.6 | A | ⬜ | Unit tests against a temporary database |

## Phase 8 — Alert Manager (B, Module 2) → `alert_manager/`

| # | Owner | Status | Task |
|---|---|---|---|
| 8.1 | B | ⬜ | `handle_alert(alert_object)`: entry point called by the pipeline |
| 8.2 | B | ⬜ | De-duplication and correlation: suppress repeats inside the cooldown; merge overlaps (a port scan currently also fires `syn_flood`) |
| 8.3 | B | ⬜ | Severity policy: escalate repeat offenders or multiple attack types from the same source |
| 8.4 | B | ⬜ | Store via DB layer (gets `alert_id`), set `status = "new"`; acknowledge/resolve functions |
| 8.5 | B | ⬜ | In-memory recent-alerts buffer + subscriber callbacks for live dashboard updates |
| 8.6 | B | ⬜ | Alert history and CSV/JSON export |
| 8.7 | B | ⬜ | Unit tests (stub the DB layer until Phase 7 is done) |

**🎯 Milestone 2:** alerts from live capture are stored in SQLite with ids and statuses.

## Phase 9 — API layer (B, Module 3) → `dashboard_flask/api/`

| # | Owner | Status | Task |
|---|---|---|---|
| 9.1 | B | ⬜ | Flask app factory; runs the pipeline in a background thread |
| 9.2 | B | ⬜ | `GET /api/stats`, `GET /api/alerts` (filters: severity, rule, ip, since), `POST /api/alerts/<id>/ack` |
| 9.3 | B | ⬜ | `GET /api/packets` (search/filter), `GET /api/flows` |
| 9.4 | B | ⬜ | `GET/PUT /api/config`, `POST /api/capture/start`, `POST /api/capture/stop` |
| 9.5 | B | ⬜ | `GET /api/alerts/export?format=csv\|json` |
| 9.6 | B | ⬜ | Live stream: `GET /api/stream` (Server-Sent Events) |
| 9.7 | B | ⬜ | Tests with Flask's test client |

## Phase 10 — Dashboard (B, Module 4) → `dashboard_flask/`

| # | Owner | Status | Task |
|---|---|---|---|
| 10.1 | B | ⬜ | Base layout and navigation |
| 10.2 | B | ⬜ | Live traffic monitor: packets/sec graph, top source/destination IPs, protocol mix |
| 10.3 | B | ⬜ | Alerts page: live list, severity colours, acknowledge/resolve |
| 10.4 | B | ⬜ | Statistics page |
| 10.5 | B | ⬜ | Packet viewer (search and filter) |
| 10.6 | B | ⬜ | Detection settings / configuration page (enable rules, thresholds, interface) |
| 10.7 | B | ⬜ | History page (past alerts, date range) |

**🎯 Milestone 3:** running `main.py` + dashboard shows live traffic and alerts in the browser.

## Phase 11 — Reporting (A, proposed) → `reporting/`

| # | Owner | Status | Task |
|---|---|---|---|
| 11.1 | A | ⬜ | Detection summary JSON: total packets, alerts by severity and by rule |
| 11.2 | A | ⬜ | Traffic summary: volume over time, top talkers, protocol mix |
| 11.3 | A | ⬜ | CSV export and PDF export (`reportlab`) |
| 11.4 | A | ⬜ | Historical analytics: alerts per day, top attacking IPs |
| 11.5 | B | ⬜ | Reports page / download buttons in the dashboard |

## Phase 12 — Testing module (A, Module 4) → `testing_utilities/`

| # | Owner | Status | Task |
|---|---|---|---|
| 12.1 | A | ⬜ | Scapy attack generators that write labelled PCAPs offline: port scan, SYN flood, ICMP flood, SSH brute force, plus benign traffic |
| 12.2 | A | ⬜ | Replay harness: PCAP → pipeline → collected alerts |
| 12.3 | A | ⬜ | Accuracy metrics: TP/FP/FN, precision, recall per rule |
| 12.4 | A | ⬜ | Performance metrics: packets/sec throughput, per-stage latency |
| 12.5 | A | ⬜ | Optional lab validation with nmap / hping3 / hydra, only against machines you own, in an isolated VM network |

## Phase 13 — Wrap-up (both)

| # | Owner | Status | Task |
|---|---|---|---|
| 13.1 | B | ⬜ | `README.md`: setup, running (root/Administrator; Npcap on Windows), screenshots |
| 13.2 | A | 🟡 | `requirements.txt`: scapy, pyyaml, pytest added; add flask, reportlab when those phases start |
| 13.3 | A+B | ⬜ | End-to-end demo script and sample PCAPs |
| 13.4 | A+B | ⬜ | Final project report / presentation |

---

## Suggested order while one person covers both roles

1. ~~Phase 2~~ ✅ → ~~Phase 3~~ ✅ → ~~Phase 4~~ ✅ → **Phase 5** (detector refinement) → **Phase 6** (runner) — reaches Milestone 1.
2. **Phase 7** (DB) → **Phase 8** (Alert Manager) — Milestone 2.
3. **Phase 9** (API) → **Phase 10** (Dashboard) — Milestone 3.
4. **Phase 12** (testing) and **Phase 11** (reporting), then **Phase 13**.

## Handoff notes for Person A

- Changes made to your modules while you were away: **1.3** (alert field names, shared fields filled by `engine.py`, `custom_rules` enabled by default; details in `CONTRACTS.md` §3), **all of Phase 2** (capture fixes) and **all of Phase 4** (Configuration Manager; `capture.yaml` became `ids.yaml`, and `CAPTURE_CONFIG` was replaced by `IDS_CONFIG`). Note `pcap.replay_pcap` was replaced by `capture.replay_pcap`, which feeds the capture queue.
- Your next modules in the original split: **Phase 7** (Database layer) and **Phase 12** (Testing). The *(proposed)* items (Config Manager, Pipeline Runner, Reporting) are open for discussion.
- Mark tasks ✅ in this file as they are finished, so both of you can see the current state.
