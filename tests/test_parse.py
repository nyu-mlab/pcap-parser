"""Tests for pcap_parser.parse module."""

import os
import shutil
import tempfile

import pandas as pd
import pytest

from pcap_parser.parse import run_tshark, reverse_dns, extract_dhcp_mapping, enrich_hostnames

FIXTURES_DIR = os.path.join(os.path.dirname(__file__), "fixtures")
SAMPLE_PCAP = os.path.join(FIXTURES_DIR, "sample.pcap")


@pytest.fixture
def tshark_available():
    if not shutil.which("tshark"):
        pytest.skip("tshark not installed")


class TestRunTshark:
    def test_parses_sample_pcap(self, tshark_available):
        df = run_tshark(SAMPLE_PCAP)
        assert df is not None
        assert isinstance(df, pd.DataFrame)
        assert len(df) > 0

    def test_has_expected_columns(self, tshark_available):
        df = run_tshark(SAMPLE_PCAP)
        assert "ip.src" in df.columns
        assert "ip.dst" in df.columns
        assert "frame.time_epoch" in df.columns
        assert "frame.len" in df.columns
        assert "source_file" in df.columns

    def test_contains_dns_traffic(self, tshark_available):
        df = run_tshark(SAMPLE_PCAP)
        dns_rows = df[df["dns.qry.name"].notna()]
        assert len(dns_rows) > 0
        assert "example.com" in dns_rows["dns.qry.name"].values

    def test_contains_tcp_traffic(self, tshark_available):
        df = run_tshark(SAMPLE_PCAP)
        tcp_rows = df[df["tcp.srcport"].notna()]
        assert len(tcp_rows) > 0

    def test_source_file_column(self, tshark_available):
        df = run_tshark(SAMPLE_PCAP)
        assert all(df["source_file"] == "sample.pcap")

    def test_nonexistent_file_returns_none(self, tshark_available):
        result = run_tshark("/tmp/nonexistent.pcap")
        assert result is None


class TestReverseDns:
    def test_empty_string_returns_empty(self):
        assert reverse_dns("") == ""

    def test_none_returns_empty(self):
        assert reverse_dns(None) == ""

    def test_nan_string_returns_empty(self):
        assert reverse_dns("nan") == ""

    def test_non_string_returns_empty(self):
        assert reverse_dns(123) == ""


class TestExtractDhcpMapping:
    def test_returns_empty_dict_when_no_dhcp_column(self):
        df = pd.DataFrame({"ip.src": ["192.168.1.1"]})
        assert extract_dhcp_mapping(df) == {}

    def test_extracts_mapping_when_present(self):
        df = pd.DataFrame({
            "ip.src": ["192.168.1.10", "192.168.1.20"],
            "bootp.option.hostname": ["my-laptop", None],
        })
        mapping = extract_dhcp_mapping(df)
        assert mapping["192.168.1.10"] == "my-laptop"
        assert "192.168.1.20" not in mapping


class TestEnrichHostnames:
    def test_adds_hostname_columns(self, tshark_available):
        import shelve
        df = run_tshark(SAMPLE_PCAP)

        with tempfile.TemporaryDirectory() as tmpdir:
            shelve_path = os.path.join(tmpdir, "test_cache")
            with shelve.open(shelve_path) as ip_shelve:
                enriched = enrich_hostnames(df, ip_shelve)
                assert "src_hostname" in enriched.columns
                assert "dst_hostname" in enriched.columns

    def test_resolves_dns_hostnames(self, tshark_available):
        import shelve
        df = run_tshark(SAMPLE_PCAP)

        with tempfile.TemporaryDirectory() as tmpdir:
            shelve_path = os.path.join(tmpdir, "test_cache")
            with shelve.open(shelve_path) as ip_shelve:
                enriched = enrich_hostnames(df, ip_shelve)
                # the dns response maps 93.184.216.34 -> example.com
                dst_hosts = enriched[enriched["ip.dst"] == "93.184.216.34"]["dst_hostname"]
                assert any("example.com" in str(h) for h in dst_hosts)
