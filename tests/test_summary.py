"""Tests for pcap_parser.summary module."""

import pandas as pd
import pytest

from pcap_parser.summary import summarize, _format_bytes, _format_duration


class TestSummarize:
    @pytest.fixture
    def parsed_csv(self, tmp_path):
        """Create a CSV that mimics pcap-parse output."""
        data = {
            "frame.time_epoch": [1000.0, 1000.5, 1001.0, 1002.0, 1003.0],
            "eth.src": ["AA:BB:CC:DD:EE:01"] * 3 + ["AA:BB:CC:DD:EE:02"] * 2,
            "ip.src": ["192.168.1.10"] * 3 + ["192.168.1.20"] * 2,
            "ip.dst": ["93.184.216.34"] * 3 + ["142.250.80.46"] * 2,
            "_ws.col.Protocol": ["TCP", "TCP", "DNS", "TLS", "TCP"],
            "frame.len": [100, 200, 50, 300, 150],
            "dst_hostname": ["example.com", "example.com", "", "google.com", "google.com"],
        }
        df = pd.DataFrame(data)
        csv_path = str(tmp_path / "parsed.csv")
        df.to_csv(csv_path, index=False)
        return csv_path

    def test_total_packets(self, parsed_csv):
        stats = summarize(parsed_csv)
        assert stats["total_packets"] == 5

    def test_total_bytes(self, parsed_csv):
        stats = summarize(parsed_csv)
        assert stats["total_bytes"] == 800

    def test_device_count(self, parsed_csv):
        stats = summarize(parsed_csv)
        assert stats["device_count"] == 2

    def test_time_range(self, parsed_csv):
        stats = summarize(parsed_csv)
        assert stats["start_ts"] == 1000.0
        assert stats["end_ts"] == 1003.0
        assert stats["duration"] == 3.0

    def test_protocols(self, parsed_csv):
        stats = summarize(parsed_csv)
        assert "TCP" in stats["protocols"]
        assert stats["protocols"]["TCP"] == 3

    def test_top_destinations(self, parsed_csv):
        stats = summarize(parsed_csv)
        assert "example.com" in stats["top_destinations"]
        assert "google.com" in stats["top_destinations"]

    def test_top_talkers(self, parsed_csv):
        stats = summarize(parsed_csv)
        assert "192.168.1.10" in stats["top_talkers"]


class TestFormatBytes:
    def test_bytes(self):
        assert _format_bytes(500) == "500.0 B"

    def test_kilobytes(self):
        assert _format_bytes(2048) == "2.0 KB"

    def test_megabytes(self):
        assert _format_bytes(1048576) == "1.0 MB"


class TestFormatDuration:
    def test_seconds(self):
        assert _format_duration(30) == "30.0s"

    def test_minutes(self):
        assert _format_duration(120) == "2.0m"

    def test_hours(self):
        assert _format_duration(7200) == "2.0h"

    def test_days(self):
        assert _format_duration(172800) == "2.0d"
