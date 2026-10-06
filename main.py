"""SecurityGuard command line: run the IDS on live traffic or a PCAP file.

Examples:
    python main.py --pcap capture.pcap
    sudo ids/bin/python main.py --interface eth0 --duration 60
    python main.py --list-interfaces
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
import time
from typing import Any

from configuration import ConfigError, load_config, merge_config, set_config
from packet_capture.interface import list_interfaces
from pipeline import Pipeline, PipelineStats

SEVERITY_WIDTH = len("Critical")


def format_alert(alert: dict[str, Any]) -> str:
    target = alert.get("dst_ip") or "-"
    if alert.get("dst_port") is not None:
        target = f"{target}:{alert['dst_port']}"
    return (
        f"[{alert['timestamp']}] {alert['severity'].upper():<{SEVERITY_WIDTH}} "
        f"{alert['attack_type']:<16} {alert.get('src_ip') or '-'} -> {target}  "
        f"{alert['description']} (confidence {alert['confidence']:.2f})"
    )


def format_summary(stats: PipelineStats) -> str:
    data = stats.as_dict()
    lines = [
        "",
        "Summary",
        f"  Packets processed : {data['processed']}",
        f"  Packets skipped   : {data['skipped']} (unsupported protocols)",
        f"  Errors            : {data['errors']}",
        f"  Alerts            : {data['alerts']}",
    ]
    for rule, count in sorted(data["alerts_by_rule"].items()):
        lines.append(f"    {rule:<14} {count}")
    lines.append(f"  Elapsed           : {data['elapsed_seconds']:.2f}s")
    return "\n".join(lines)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="SecurityGuard network intrusion detection system")
    source = parser.add_mutually_exclusive_group()
    source.add_argument("--pcap", metavar="FILE", help="analyze a PCAP file instead of live traffic")
    source.add_argument("--list-interfaces", action="store_true", help="list capture interfaces and exit")
    parser.add_argument("--interface", "-i", help="live capture interface (overrides the config)")
    parser.add_argument("--filter", "-f", help="BPF capture filter (overrides the config)")
    parser.add_argument("--duration", "-d", type=float, metavar="SECONDS", help="stop live capture after this many seconds")
    parser.add_argument("--config", "-c", metavar="FILE", help="config file (default: configuration/ids.yaml or $IDS_CONFIG)")
    parser.add_argument("--json", action="store_true", help="print alerts as JSON lines")
    parser.add_argument("--verbose", "-v", action="store_true", help="show debug logging")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.WARNING,
        format="%(levelname)s %(name)s: %(message)s",
    )

    if args.list_interfaces:
        for name in list_interfaces():
            print(name)
        return 0

    try:
        config = load_config(args.config)
        overrides = {key: value for key, value in (("interface", args.interface), ("filter", args.filter)) if value is not None}
        if overrides:
            config = merge_config(config, {"capture": overrides})
    except ConfigError as exc:
        print(f"Configuration error: {exc}", file=sys.stderr)
        return 2
    set_config(config)

    def print_alert(alert: dict[str, Any]) -> None:
        print(json.dumps(alert) if args.json else format_alert(alert), flush=True)

    pipeline = Pipeline(config, on_alert=print_alert)

    if args.pcap:
        try:
            stats = pipeline.run_pcap(args.pcap)
        except FileNotFoundError as exc:
            print(exc, file=sys.stderr)
            return 1
        except KeyboardInterrupt:
            stats = pipeline.stop()
    else:
        try:
            started = pipeline.start_live()
        except (PermissionError, RuntimeError, ValueError) as exc:
            print(exc, file=sys.stderr)
            return 1
        if not args.json:
            print(f"Capturing on {started['interface']} (filter: {started['filter'] or 'none'}). Press Ctrl+C to stop.", flush=True)
        try:
            deadline = time.monotonic() + args.duration if args.duration else None
            while deadline is None or time.monotonic() < deadline:
                time.sleep(0.2)
        except KeyboardInterrupt:
            pass
        stats = pipeline.stop()

    if not args.json:
        print(format_summary(stats))
    return 0


if __name__ == "__main__":
    sys.exit(main())
