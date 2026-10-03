"""Unit tests for the configuration manager."""

from dataclasses import asdict

import pytest

import traffic_analyzer
from configuration import (
    DEFAULT_CONFIG_PATH,
    Config,
    ConfigError,
    config_from_dict,
    config_to_dict,
    get_config,
    load_config,
    merge_config,
    reload_config,
    save_config,
    set_config,
)


@pytest.fixture(autouse=True)
def isolated(monkeypatch, tmp_path):
    monkeypatch.setenv("IDS_CONFIG", str(tmp_path / "ids.yaml"))
    yield
    set_config(Config())


def write(tmp_path, text):
    path = tmp_path / "ids.yaml"
    path.write_text(text, encoding="utf-8")
    return path


# --- loading ------------------------------------------------------------------


def test_shipped_config_file_is_valid_and_matches_defaults():
    assert load_config(DEFAULT_CONFIG_PATH) == Config()


def test_missing_file_gives_defaults(tmp_path):
    assert load_config(tmp_path / "missing.yaml") == Config()


def test_empty_file_gives_defaults(tmp_path):
    assert load_config(write(tmp_path, "")) == Config()


def test_partial_file_keeps_other_defaults(tmp_path):
    config = load_config(write(tmp_path, "detection:\n  port_scan:\n    unique_ports_threshold: 20\n"))
    assert config.detection.port_scan.unique_ports_threshold == 20
    assert config.detection.syn_flood.syn_threshold == 10
    assert config.capture.packet_limit == 1000


def test_empty_section_gives_defaults(tmp_path):
    config = load_config(write(tmp_path, "traffic:\ndetection:\n  port_scan:\n"))
    assert config.traffic.window_seconds == 60
    assert config.detection.port_scan.unique_ports_threshold == 7


def test_int_accepted_for_float_field():
    config = config_from_dict({"detection": {"icmp_flood": {"pps_threshold": 50}}})
    assert config.detection.icmp_flood.pps_threshold == 50.0
    assert isinstance(config.detection.icmp_flood.pps_threshold, float)


def test_signatures_are_parsed_and_normalized():
    config = config_from_dict({"detection": {"signatures": [{"name": "SQLi", "pattern": "UNION SELECT", "severity": "high"}]}})
    signature = config.detection.signatures[0]
    assert (signature.name, signature.pattern, signature.regex, signature.severity) == ("SQLi", "UNION SELECT", False, "High")


def test_protocols_are_uppercased():
    config = config_from_dict({"detection": {"custom_rules": {"blocked_protocols": ["icmp"]}}})
    assert config.detection.custom_rules.blocked_protocols == ["ICMP"]


def test_duplicate_enabled_detectors_are_removed():
    config = config_from_dict({"detection": {"enabled": ["port_scan", "port_scan", "syn_flood"]}})
    assert config.detection.enabled == ["port_scan", "syn_flood"]


def test_resolved_db_path_is_relative_to_project_root():
    path = Config().logging.resolved_db_path()
    assert path.is_absolute()
    assert path.parts[-2:] == ("data", "ids.db")


# --- validation errors name the exact setting ----------------------------------


@pytest.mark.parametrize(
    ("data", "message"),
    [
        ({"capture": {"interfce": "eth0"}}, "capture: unknown setting(s): interfce"),
        ({"detection": {"port_scan": {"unique_ports_threshold": 0}}}, "detection.port_scan.unique_ports_threshold: must be greater than 0"),
        ({"detection": {"port_scan": {"unique_ports_threshold": "seven"}}}, "expected a whole number, got str"),
        ({"detection": {"port_scan": {"unique_ports_threshold": True}}}, "expected a whole number, got bool"),
        ({"detection": {"syn_flood": {"syn_threshold": 1.5}}}, "detection.syn_flood.syn_threshold: expected a whole number"),
        ({"detection": {"enabled": ["port_scan", "teleport"]}}, "detection.enabled[1]: unknown detector 'teleport'"),
        ({"detection": {"enabled": "port_scan"}}, "detection.enabled: expected a list, got str"),
        ({"detection": {"brute_force": {"ports": [22, 70000]}}}, "detection.brute_force.ports[1]: port must be 1-65535"),
        ({"detection": {"custom_rules": {"blocked_ips": ["10.0.0.300"]}}}, "detection.custom_rules.blocked_ips[0]: not a valid IP address"),
        ({"detection": {"custom_rules": {"blocked_protocols": ["GRE"]}}}, "detection.custom_rules.blocked_protocols[0]: must be one of"),
        ({"detection": {"signatures": [{"name": "x", "pattern": "a", "severity": "Severe"}]}}, "detection.signatures[0].severity"),
        ({"detection": {"signatures": [{"name": "x", "pattern": "(", "regex": True}]}}, "detection.signatures[0].pattern: invalid regex"),
        ({"detection": {"signatures": [{"pattern": "abc"}]}}, "detection.signatures[0].name: is required"),
        ({"logging": {"enabled": "yes"}}, "logging.enabled: expected true/false, got str"),
        ({"dashboard": {"port": 0}}, "dashboard.port: must be 1-65535"),
        ({"traffic": 5}, "traffic: expected a mapping, got int"),
        ({"capture": {"packet_limit": -1}}, "capture.packet_limit: must be 0 or more"),
        ({"unknown_section": {}}, "config: unknown setting(s): unknown_section"),
    ],
)
def test_invalid_values_are_rejected(data, message):
    with pytest.raises(ConfigError) as excinfo:
        config_from_dict(data)
    assert message in str(excinfo.value)


def test_load_error_includes_file_path(tmp_path):
    path = write(tmp_path, "dashboard:\n  port: 99999\n")
    with pytest.raises(ConfigError, match=r"ids\.yaml: dashboard\.port"):
        load_config(path)


def test_invalid_yaml_is_reported(tmp_path):
    with pytest.raises(ConfigError, match="invalid YAML"):
        load_config(write(tmp_path, "capture: [unclosed\n"))


def test_config_error_is_a_value_error():
    assert issubclass(ConfigError, ValueError)


# --- updating and saving ------------------------------------------------------


def test_merge_config_applies_partial_update():
    updated = merge_config(Config(), {"detection": {"syn_flood": {"syn_threshold": 50}, "enabled": ["syn_flood"]}})
    assert updated.detection.syn_flood.syn_threshold == 50
    assert updated.detection.syn_flood.ack_threshold == 2
    assert updated.detection.enabled == ["syn_flood"]
    assert updated.capture == Config().capture


def test_merge_config_does_not_modify_original():
    original = Config()
    merge_config(original, {"traffic": {"window_seconds": 5}})
    assert original.traffic.window_seconds == 60


def test_merge_config_validates():
    with pytest.raises(ConfigError):
        merge_config(Config(), {"traffic": {"window_seconds": -5}})


def test_save_and_load_round_trip(tmp_path):
    config = merge_config(Config(), {
        "capture": {"interface": "eth0", "filter": "tcp or icmp"},
        "detection": {"signatures": [{"name": "Traversal", "pattern": "../..", "severity": "Critical"}]},
    })
    path = save_config(config)

    assert path == tmp_path / "ids.yaml"
    assert path.read_text(encoding="utf-8").startswith("# SecurityGuard configuration.")
    assert load_config() == config
    assert not list(tmp_path.glob(".ids-*"))


def test_save_rejects_invalid_config(tmp_path):
    config = Config()
    config.dashboard.port = 0
    with pytest.raises(ConfigError):
        save_config(config)
    assert not (tmp_path / "ids.yaml").exists()


# --- shared instance ----------------------------------------------------------


def test_get_config_loads_once_and_reload_refreshes(tmp_path):
    set_config(None)
    write(tmp_path, "dashboard:\n  port: 8080\n")
    assert get_config().dashboard.port == 8080

    write(tmp_path, "dashboard:\n  port: 9090\n")
    assert get_config().dashboard.port == 8080
    assert reload_config().dashboard.port == 9090
    assert get_config().dashboard.port == 9090


# --- wiring -------------------------------------------------------------------


def test_traffic_settings_configure_the_analyzer():
    config = merge_config(Config(), {"traffic": {"window_seconds": 15, "flow_timeout_seconds": 30}})
    analyzer = traffic_analyzer.TrafficAnalyzer(**asdict(config.traffic))
    assert analyzer.window_seconds == 15


def test_config_to_dict_is_plain_data():
    data = config_to_dict(Config())
    assert data["detection"]["brute_force"]["ports"] == [22, 21, 23, 3389]
    assert isinstance(data["detection"]["port_scan"], dict)
