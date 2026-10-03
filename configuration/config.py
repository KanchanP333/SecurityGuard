"""Configuration manager: load, validate, update and save configuration/ids.yaml."""

from __future__ import annotations

import copy
from dataclasses import asdict, dataclass, field, fields, is_dataclass
import ipaddress
import logging
import os
from pathlib import Path
import re
import tempfile
import threading
from typing import Any, get_args, get_origin, get_type_hints

import yaml

logger = logging.getLogger(__name__)

PROJECT_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_CONFIG_PATH = PROJECT_ROOT / "configuration" / "ids.yaml"
CONFIG_PATH_ENV = "IDS_CONFIG"

KNOWN_DETECTORS = ("port_scan", "syn_flood", "icmp_flood", "brute_force", "custom_rules", "signatures")
SEVERITIES = ("Low", "Medium", "High", "Critical")
PROTOCOLS = ("TCP", "UDP", "ICMP")


class ConfigError(ValueError):
    """Raised when the configuration file is missing required structure or has invalid values."""


# --- validation helpers -------------------------------------------------------


def _check(condition: bool, path: str, message: str) -> None:
    if not condition:
        raise ConfigError(f"{path}: {message}")


def _check_positive(value: float, path: str) -> None:
    _check(value > 0, path, f"must be greater than 0 (got {value})")


def _check_ports(ports: list[int], path: str) -> None:
    for i, port in enumerate(ports):
        _check(1 <= port <= 65535, f"{path}[{i}]", f"port must be 1-65535 (got {port})")


# --- settings -----------------------------------------------------------------


@dataclass
class CaptureSettings:
    interface: str = ""  # empty = auto-detect
    filter: str = ""  # BPF subset, validated by packet_capture.filters
    packet_limit: int = 1000  # capture queue size, 0 = unbounded

    def validate(self, path: str) -> None:
        _check(self.packet_limit >= 0, f"{path}.packet_limit", "must be 0 or more")


@dataclass
class TrafficSettings:
    window_seconds: int = 60
    flow_timeout_seconds: int = 120

    def validate(self, path: str) -> None:
        _check_positive(self.window_seconds, f"{path}.window_seconds")
        _check_positive(self.flow_timeout_seconds, f"{path}.flow_timeout_seconds")


@dataclass
class PortScanSettings:
    unique_ports_threshold: int = 7

    def validate(self, path: str) -> None:
        _check_positive(self.unique_ports_threshold, f"{path}.unique_ports_threshold")


@dataclass
class SynFloodSettings:
    syn_threshold: int = 10
    ack_threshold: int = 2

    def validate(self, path: str) -> None:
        _check_positive(self.syn_threshold, f"{path}.syn_threshold")
        _check(self.ack_threshold >= 0, f"{path}.ack_threshold", "must be 0 or more")


@dataclass
class IcmpFloodSettings:
    pps_threshold: float = 20.0

    def validate(self, path: str) -> None:
        _check_positive(self.pps_threshold, f"{path}.pps_threshold")


@dataclass
class BruteForceSettings:
    attempts_threshold: int = 5
    ports: list[int] = field(default_factory=lambda: [22, 21, 23, 3389])

    def validate(self, path: str) -> None:
        _check_positive(self.attempts_threshold, f"{path}.attempts_threshold")
        _check_ports(self.ports, f"{path}.ports")


@dataclass
class CustomRulesSettings:
    blocked_ports: list[int] = field(default_factory=list)
    suspicious_ports: list[int] = field(default_factory=lambda: [23, 2323, 4444, 5555, 6667, 31337])
    blocked_ips: list[str] = field(default_factory=list)
    blocked_protocols: list[str] = field(default_factory=list)

    def validate(self, path: str) -> None:
        _check_ports(self.blocked_ports, f"{path}.blocked_ports")
        _check_ports(self.suspicious_ports, f"{path}.suspicious_ports")
        for i, ip in enumerate(self.blocked_ips):
            try:
                ipaddress.ip_address(ip)
            except ValueError:
                raise ConfigError(f"{path}.blocked_ips[{i}]: not a valid IP address ({ip!r})") from None
        self.blocked_protocols = [p.upper() for p in self.blocked_protocols]
        for i, protocol in enumerate(self.blocked_protocols):
            _check(protocol in PROTOCOLS, f"{path}.blocked_protocols[{i}]", f"must be one of {', '.join(PROTOCOLS)}")


@dataclass
class Signature:
    name: str = ""
    pattern: str = ""
    regex: bool = False  # False = plain substring match
    severity: str = "Medium"

    def validate(self, path: str) -> None:
        _check(bool(self.name.strip()), f"{path}.name", "is required")
        _check(bool(self.pattern), f"{path}.pattern", "is required")
        self.severity = self.severity.strip().capitalize()
        _check(self.severity in SEVERITIES, f"{path}.severity", f"must be one of {', '.join(SEVERITIES)}")
        if self.regex:
            try:
                re.compile(self.pattern.encode())
            except re.error as exc:
                raise ConfigError(f"{path}.pattern: invalid regex ({exc})") from None


@dataclass
class DetectionSettings:
    enabled: list[str] = field(default_factory=lambda: ["port_scan", "syn_flood", "icmp_flood", "brute_force", "custom_rules"])
    alert_cooldown_seconds: int = 300
    port_scan: PortScanSettings = field(default_factory=PortScanSettings)
    syn_flood: SynFloodSettings = field(default_factory=SynFloodSettings)
    icmp_flood: IcmpFloodSettings = field(default_factory=IcmpFloodSettings)
    brute_force: BruteForceSettings = field(default_factory=BruteForceSettings)
    custom_rules: CustomRulesSettings = field(default_factory=CustomRulesSettings)
    signatures: list[Signature] = field(default_factory=list)

    def validate(self, path: str) -> None:
        for i, name in enumerate(self.enabled):
            _check(name in KNOWN_DETECTORS, f"{path}.enabled[{i}]", f"unknown detector {name!r} (known: {', '.join(KNOWN_DETECTORS)})")
        self.enabled = list(dict.fromkeys(self.enabled))
        _check(self.alert_cooldown_seconds >= 0, f"{path}.alert_cooldown_seconds", "must be 0 or more")


@dataclass
class LoggingSettings:
    enabled: bool = True
    db_path: str = "data/ids.db"  # relative paths are relative to the project root
    store_packets: bool = True

    def validate(self, path: str) -> None:
        _check(bool(self.db_path.strip()), f"{path}.db_path", "is required")

    def resolved_db_path(self) -> Path:
        db_path = Path(self.db_path)
        return db_path if db_path.is_absolute() else PROJECT_ROOT / db_path


@dataclass
class DashboardSettings:
    host: str = "127.0.0.1"
    port: int = 5000

    def validate(self, path: str) -> None:
        _check(bool(self.host.strip()), f"{path}.host", "is required")
        _check(1 <= self.port <= 65535, f"{path}.port", "must be 1-65535")


@dataclass
class Config:
    capture: CaptureSettings = field(default_factory=CaptureSettings)
    traffic: TrafficSettings = field(default_factory=TrafficSettings)
    detection: DetectionSettings = field(default_factory=DetectionSettings)
    logging: LoggingSettings = field(default_factory=LoggingSettings)
    dashboard: DashboardSettings = field(default_factory=DashboardSettings)


# --- dict <-> Config ----------------------------------------------------------


def _type_name(value: Any) -> str:
    return "null" if value is None else type(value).__name__


def _convert(expected: Any, value: Any, path: str) -> Any:
    if is_dataclass(expected):
        return _build(expected, {} if value is None else value, path)

    if get_origin(expected) is list:
        (item_type,) = get_args(expected)
        if value is None:
            return []
        _check(isinstance(value, list), path, f"expected a list, got {_type_name(value)}")
        return [_convert(item_type, item, f"{path}[{i}]") for i, item in enumerate(value)]

    if expected is bool:
        _check(isinstance(value, bool), path, f"expected true/false, got {_type_name(value)}")
        return value
    if expected is int:
        _check(isinstance(value, int) and not isinstance(value, bool), path, f"expected a whole number, got {_type_name(value)}")
        return value
    if expected is float:
        _check(isinstance(value, (int, float)) and not isinstance(value, bool), path, f"expected a number, got {_type_name(value)}")
        return float(value)
    if expected is str:
        if value is None:
            return ""
        _check(isinstance(value, str), path, f"expected text, got {_type_name(value)}")
        return value.strip()

    raise TypeError(f"Unsupported config field type at {path}: {expected!r}")


def _build(cls: type, data: Any, path: str) -> Any:
    _check(isinstance(data, dict), path or "config", f"expected a mapping, got {_type_name(data)}")
    names = [f.name for f in fields(cls)]
    unknown = sorted(set(data) - set(names))
    _check(not unknown, path or "config", f"unknown setting(s): {', '.join(map(str, unknown))}")

    hints = get_type_hints(cls)
    kwargs = {
        name: _convert(hints[name], data[name], f"{path}.{name}" if path else name)
        for name in names
        if name in data
    }
    instance = cls(**kwargs)
    validate = getattr(instance, "validate", None)
    if validate is not None:
        validate(path)
    return instance


def config_from_dict(data: dict[str, Any] | None) -> Config:
    """Build and validate a Config from a plain dict (missing settings use defaults)."""
    return _build(Config, data or {}, "")


def config_to_dict(config: Config) -> dict[str, Any]:
    """Return the configuration as plain dicts and lists (JSON/YAML friendly)."""
    return asdict(config)


def _deep_merge(base: dict[str, Any], changes: dict[str, Any]) -> dict[str, Any]:
    merged = copy.deepcopy(base)
    for key, value in changes.items():
        if isinstance(value, dict) and isinstance(merged.get(key), dict):
            merged[key] = _deep_merge(merged[key], value)
        else:
            merged[key] = copy.deepcopy(value)
    return merged


def merge_config(config: Config, changes: dict[str, Any]) -> Config:
    """Return a new validated Config with a partial update applied (e.g. from the dashboard).

    Nested sections are merged; lists are replaced.
    """
    _check(isinstance(changes, dict), "config", "changes must be a mapping")
    return config_from_dict(_deep_merge(config_to_dict(config), changes))


# --- files --------------------------------------------------------------------


def config_path(path: str | Path | None = None) -> Path:
    """Return the config file path: the argument, else $IDS_CONFIG, else configuration/ids.yaml."""
    if path:
        return Path(path)
    env_path = os.environ.get(CONFIG_PATH_ENV, "").strip()
    return Path(env_path) if env_path else DEFAULT_CONFIG_PATH


def load_config(path: str | Path | None = None) -> Config:
    """Load and validate the config file. A missing file gives the default configuration."""
    file_path = config_path(path)
    if not file_path.exists():
        logger.info("No config file at %s; using defaults", file_path)
        return Config()

    try:
        with file_path.open("r", encoding="utf-8") as handle:
            data = yaml.safe_load(handle)
    except yaml.YAMLError as exc:
        raise ConfigError(f"{file_path}: invalid YAML ({exc})") from None

    try:
        return config_from_dict(data)
    except ConfigError as exc:
        raise ConfigError(f"{file_path}: {exc}") from None


_HEADER = "# SecurityGuard configuration. Field reference: docs/CONTRACTS.md section 5.\n"


def save_config(config: Config, path: str | Path | None = None) -> Path:
    """Validate and write the config to disk atomically. Comments in the file are not preserved."""
    config = config_from_dict(config_to_dict(config))
    file_path = config_path(path)
    file_path.parent.mkdir(parents=True, exist_ok=True)
    text = _HEADER + yaml.safe_dump(config_to_dict(config), sort_keys=False, default_flow_style=False)

    fd, tmp_name = tempfile.mkstemp(dir=file_path.parent, prefix=".ids-", suffix=".yaml")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(text)
        os.replace(tmp_name, file_path)
    except BaseException:
        Path(tmp_name).unlink(missing_ok=True)
        raise
    return file_path


# --- shared instance ----------------------------------------------------------

_CURRENT: Config | None = None
_LOCK = threading.Lock()


def get_config() -> Config:
    """Return the shared configuration, loading it on first use."""
    global _CURRENT
    with _LOCK:
        if _CURRENT is None:
            _CURRENT = load_config()
        return _CURRENT


def set_config(config: Config) -> None:
    """Replace the shared configuration (e.g. after the dashboard saves changes)."""
    global _CURRENT
    with _LOCK:
        _CURRENT = config


def reload_config(path: str | Path | None = None) -> Config:
    """Reload the shared configuration from disk."""
    config = load_config(path)
    set_config(config)
    return config
