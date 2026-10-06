"""Shared fixtures: drive packet_dicts through the traffic analyzer and the detection engine."""

from __future__ import annotations

from typing import Any

import pytest

from configuration import Config, merge_config
from detection_engine import engine
from traffic_analyzer import TrafficAnalyzer


class Pipeline:
    """Analyzer + engine with a given configuration. Collects every alert raised."""

    def __init__(self, changes: dict[str, Any] | None = None) -> None:
        self.config = merge_config(Config(), changes or {})
        self.analyzer = TrafficAnalyzer(window_seconds=self.config.traffic.window_seconds)
        self.alerts: list[dict[str, Any]] = []

    def feed(self, packets, enabled=None) -> list[dict[str, Any]]:
        new_alerts = []
        for packet_dict in packets:
            flow = self.analyzer.analyze(packet_dict)
            new_alerts += engine.run_engine(packet_dict, flow, enabled, self.config.detection)
        self.alerts += new_alerts
        return new_alerts


@pytest.fixture(autouse=True)
def clean_engine():
    engine.reset()
    yield
    engine.reset()


@pytest.fixture
def pipeline():
    return Pipeline
