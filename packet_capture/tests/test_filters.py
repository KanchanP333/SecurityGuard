"""Unit tests for BPF filter validation."""

import pytest

from packet_capture.filters import get_filter, set_filter, validate_filter


@pytest.mark.parametrize(
	"expression",
	[
		"tcp",
		"tcp or udp or icmp",
		"not icmp",
		"port 80",
		"host 10.0.0.1 and port 22",
		"host example.com",
		"src host 192.168.1.5",
		"dst port 443",
		"tcp and not port 22",
	],
)
def test_valid_filters(expression):
	assert validate_filter(expression) is True


@pytest.mark.parametrize(
	"expression",
	[
		"",
		"   ",
		"port 0",
		"port 99999",
		"tcp and",
		"tcp udp",
		"foo",
		"host bad_host!",
		"src port",
		None,
	],
)
def test_invalid_filters(expression):
	assert validate_filter(expression) is False


def test_set_and_get_filter():
	assert set_filter("  tcp or udp ") == "tcp or udp"
	assert get_filter() == "tcp or udp"


def test_empty_filter_clears_active_filter():
	set_filter("tcp")
	assert set_filter("") == ""
	assert get_filter() is None


def test_set_invalid_filter_raises():
	with pytest.raises(ValueError):
		set_filter("port 99999")
