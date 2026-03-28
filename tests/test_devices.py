"""Tests for pcap_parser.devices module."""

import pandas as pd
import pytest

from pcap_parser.devices import aggregate_devices, _first_non_empty, _format_bytes


class TestAggregateDevices:
    @pytest.fixture
    def parsed_csv(self, tmp_path):
        """Create a CSV that mimics pcap-parse output with multiple devices."""
        data = {
            "frame.time_epoch": [1000.0, 1000.1, 1000.2, 1000.3, 1000.4],
            "eth.src": ["AA:BB:CC:DD:EE:01"] * 3 + ["AA:BB:CC:DD:EE:02"] * 2,
            "eth.src.oui_resolved": ["Apple, Inc."] * 3 + ["Google, Inc."] * 2,
            "ip.src": ["192.168.1.10"] * 3 + ["192.168.1.20"] * 2,
            "ip.dst": ["93.184.216.34"] * 3 + ["142.250.80.46"] * 2,
            "frame.len": [100, 200, 300, 150, 250],
            "dst_hostname": ["example.com"] * 3 + ["google.com"] * 2,
            "dhcp_hostname": ["macbook", "", "", "pixel-6", ""],
            "http.user_agent": [None] * 3 + ["Mozilla/5.0 (Linux; Android 12)", None],
        }
        df = pd.DataFrame(data)
        csv_path = str(tmp_path / "parsed.csv")
        df.to_csv(csv_path, index=False)
        return csv_path

    def test_finds_correct_device_count(self, parsed_csv):
        devices = aggregate_devices(parsed_csv)
        assert len(devices) == 2

    def test_sorted_by_traffic_descending(self, parsed_csv):
        devices = aggregate_devices(parsed_csv)
        assert devices[0]["byte_count"] >= devices[1]["byte_count"]

    def test_device_has_expected_fields(self, parsed_csv):
        devices = aggregate_devices(parsed_csv)
        device = devices[0]
        assert "mac" in device
        assert "ips" in device
        assert "oui_vendor" in device
        assert "dhcp_hostname" in device
        assert "packet_count" in device
        assert "byte_count" in device
        assert "top_destinations" in device

    def test_extracts_oui_vendor(self, parsed_csv):
        devices = aggregate_devices(parsed_csv)
        vendors = {d["oui_vendor"] for d in devices}
        assert "Apple, Inc." in vendors
        assert "Google, Inc." in vendors

    def test_extracts_dhcp_hostname(self, parsed_csv):
        devices = aggregate_devices(parsed_csv)
        hostnames = {d["dhcp_hostname"] for d in devices}
        assert "macbook" in hostnames
        assert "pixel-6" in hostnames

    def test_calculates_byte_count(self, parsed_csv):
        devices = aggregate_devices(parsed_csv)
        apple_device = next(d for d in devices if d["oui_vendor"] == "Apple, Inc.")
        assert apple_device["byte_count"] == 600
        assert apple_device["packet_count"] == 3


class TestFormatBytes:
    def test_bytes(self):
        assert _format_bytes(500) == "500.0 B"

    def test_kilobytes(self):
        assert _format_bytes(2048) == "2.0 KB"

    def test_megabytes(self):
        assert _format_bytes(1048576) == "1.0 MB"


class TestFirstNonEmpty:
    def test_returns_first_value(self):
        group = pd.DataFrame({"col": ["", "hello", "world"]})
        assert _first_non_empty(group, "col") == "hello"

    def test_returns_empty_for_missing_column(self):
        group = pd.DataFrame({"other": [1, 2]})
        assert _first_non_empty(group, "col") == ""

    def test_returns_empty_for_all_empty(self):
        group = pd.DataFrame({"col": ["", "", ""]})
        assert _first_non_empty(group, "col") == ""
