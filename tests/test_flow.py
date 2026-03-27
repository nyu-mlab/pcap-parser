"""Tests for pcap_parser.flow module."""

import os

import pandas as pd
import pytest

from pcap_parser.flow import extract_main_domain, get_src_port, get_dst_port, process_pcap_data


class TestExtractMainDomain:
    def test_extracts_domain(self):
        assert extract_main_domain("www.example.com") == "example.com"

    def test_extracts_from_subdomain(self):
        assert extract_main_domain("api.sub.example.co.uk") == "example.co.uk"

    def test_empty_string_returns_empty(self):
        assert extract_main_domain("") == ""

    def test_none_returns_empty(self):
        result = extract_main_domain(None)
        assert result == "" or result is None

    def test_invalid_hostname(self):
        result = extract_main_domain("not a hostname!!!")
        assert isinstance(result, (str, type(None)))


class TestGetPorts:
    def test_get_src_port_tcp(self):
        row = pd.Series({"tcp.srcport": 80, "udp.srcport": float("nan")})
        assert get_src_port(row) == 80

    def test_get_src_port_udp(self):
        row = pd.Series({"tcp.srcport": float("nan"), "udp.srcport": 53})
        assert get_src_port(row) == 53

    def test_get_dst_port_tcp(self):
        row = pd.Series({"tcp.dstport": 443, "udp.dstport": float("nan")})
        assert get_dst_port(row) == 443

    def test_get_dst_port_udp(self):
        row = pd.Series({"tcp.dstport": float("nan"), "udp.dstport": 5353})
        assert get_dst_port(row) == 5353


class TestProcessPcapData:
    @pytest.fixture
    def parsed_csv(self, tmp_path):
        """Create a CSV that mimics parse.py output."""
        data = {
            "frame.time_epoch": [1000.0, 1000.1, 1000.2, 1000.3, 1000.5],
            "ip.src": ["192.168.1.10"] * 5,
            "ip.dst": ["93.184.216.34"] * 5,
            "tcp.srcport": [54321] * 5,
            "tcp.dstport": [80] * 5,
            "udp.srcport": [float("nan")] * 5,
            "udp.dstport": [float("nan")] * 5,
            "_ws.col.protocol": ["TCP"] * 5,
            "frame.len": [54, 54, 100, 100, 100],
            "src_hostname": [""] * 5,
            "dst_hostname": ["example.com"] * 5,
            "dhcp_hostname": [""] * 5,
            "http.user_agent": [None] * 5,
            "eth.src.oui_resolved": ["SomeVendor"] * 5,
        }
        df = pd.DataFrame(data)
        csv_path = str(tmp_path / "parsed.csv")
        df.to_csv(csv_path, index=False)
        return csv_path

    def test_produces_output_csv(self, parsed_csv, tmp_path):
        output_csv = str(tmp_path / "flows.csv")
        process_pcap_data(parsed_csv, output_csv)
        assert os.path.exists(output_csv)

    def test_aggregates_into_flows(self, parsed_csv, tmp_path):
        output_csv = str(tmp_path / "flows.csv")
        process_pcap_data(parsed_csv, output_csv)
        flows = pd.read_csv(output_csv)
        # 5 packets with same src/dst/port/protocol -> 1 flow
        assert len(flows) == 1

    def test_flow_has_expected_columns(self, parsed_csv, tmp_path):
        output_csv = str(tmp_path / "flows.csv")
        process_pcap_data(parsed_csv, output_csv)
        flows = pd.read_csv(output_csv)
        expected = [
            "start_ts", "end_ts", "ip.src", "ip.dst",
            "src_port", "dst_port", "_ws.col.protocol",
            "byte_count", "packet_count",
        ]
        for col in expected:
            assert col in flows.columns, f"missing column: {col}"

    def test_flow_stats_are_correct(self, parsed_csv, tmp_path):
        output_csv = str(tmp_path / "flows.csv")
        process_pcap_data(parsed_csv, output_csv)
        flows = pd.read_csv(output_csv)
        flow = flows.iloc[0]
        assert flow["packet_count"] == 5
        assert flow["byte_count"] == 54 + 54 + 100 + 100 + 100
