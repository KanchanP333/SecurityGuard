"""Unit tests for interface discovery helpers."""

import os

import pytest

from packet_capture import interface


@pytest.fixture
def fake_interfaces(monkeypatch):
	monkeypatch.delenv("DEFAULT_INTERFACE", raising=False)
	monkeypatch.setattr(interface, "_discover_windows_interfaces", lambda: [])
	monkeypatch.setattr(interface, "_discover_socket_interfaces", lambda: ["Loopback", "eth0", "eth0", "wlan0"])


@pytest.mark.skipif(os.name == "nt", reason="non-Windows behaviour")
def test_powershell_skipped_off_windows():
	assert interface._run_powershell_json("Get-NetAdapter") == []


def test_list_interfaces_deduplicates(fake_interfaces):
	assert interface.list_interfaces() == ["Loopback", "eth0", "wlan0"]


def test_validate_interface_is_case_insensitive(fake_interfaces):
	assert interface.validate_interface("ETH0") is True
	assert interface.validate_interface("Wi-Fi") is False
	assert interface.validate_interface("") is False


def test_default_interface_skips_loopback(fake_interfaces):
	assert interface.get_default_interface() == "eth0"


def test_default_interface_skips_linux_loopback(monkeypatch):
	monkeypatch.delenv("DEFAULT_INTERFACE", raising=False)
	monkeypatch.setattr(interface, "_discover_windows_interfaces", lambda: [])
	monkeypatch.setattr(interface, "_discover_socket_interfaces", lambda: ["lo", "eth0"])
	assert interface.get_default_interface() == "eth0"


def test_default_interface_uses_env_when_valid(fake_interfaces, monkeypatch):
	monkeypatch.setenv("DEFAULT_INTERFACE", "wlan0")
	assert interface.get_default_interface() == "wlan0"
