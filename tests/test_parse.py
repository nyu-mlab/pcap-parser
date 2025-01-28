import unittest
from unittest.mock import patch, MagicMock
import os
import pandas as pd
from io import StringIO
from parse import run_tshark, main

class TestParseScript(unittest.TestCase):

    @patch("subprocess.Popen")
    def test_run_tshark_valid_output(self, mock_popen):
        mock_process = MagicMock()
        mock_popen.return_value = mock_process
        mock_process.communicate.return_value = (
            b"frame.time_epoch,ip.src,ip.dst\n12345,192.168.1.1,8.8.8.8\n", b""
        )
        mock_process.returncode = 0

        pcap_file = "mock.pcap"
        result = run_tshark(pcap_file)

        self.assertIsInstance(result, pd.DataFrame)
        self.assertEqual(len(result), 1)
        self.assertEqual(result.iloc[0]["ip.src"], "192.168.1.1")
        self.assertEqual(result.iloc[0]["ip.dst"], "8.8.8.8")

    @patch("subprocess.Popen")
    def test_run_tshark_empty_output(self, mock_popen):
        mock_process = MagicMock()
        mock_popen.return_value = mock_process
        mock_process.communicate.return_value = (b"", b"")
        mock_process.returncode = 0

        pcap_file = "empty.pcap"
        result = run_tshark(pcap_file)

        self.assertIsNone(result)

    @patch("subprocess.Popen")
    def test_run_tshark_error(self, mock_popen):
        mock_process = MagicMock()
        mock_popen.return_value = mock_process
        mock_process.communicate.return_value = (b"", b"Error parsing pcap")
        mock_process.returncode = 1

        pcap_file = "error.pcap"
        result = run_tshark(pcap_file)

        self.assertIsNone(result)

    @patch("parse.run_tshark")
    @patch("builtins.print")
    def test_main_valid_file(self, mock_print, mock_run_tshark):
        mock_df = pd.DataFrame({
            "frame.time_epoch": [12345],
            "ip.src": ["192.168.1.1"],
            "ip.dst": ["8.8.8.8"],
            "dns.qry.name": [None],
            "dns.a": [None],
            "tls.handshake.extensions_server_name": [None],
        })
        mock_run_tshark.return_value = mock_df

        with open("temp.pcap", "w") as f:
            f.write("mock data")

        with patch("sys.argv", ["parse.py", "output.csv", "temp.pcap"]):
            main()

        mock_print.assert_any_call("Parsing pcap file: temp.pcap")
        self.assertTrue(os.path.exists("output.csv"))

        output_df = pd.read_csv("output.csv")
        self.assertEqual(len(output_df), 1)
        self.assertEqual(output_df.iloc[0]["ip.src"], "192.168.1.1")
        self.assertEqual(output_df.iloc[0]["ip.dst"], "8.8.8.8")

        os.remove("temp.pcap")
        os.remove("output.csv")

    def test_main_invalid_arguments(self):
        with patch("sys.argv", ["parse.py"]):
            with patch("builtins.print") as mock_print:
                main()
                mock_print.assert_any_call(
                    "Usage: python parse.py <output_csv_file> <path_to_pcap_file_or_directory>"
                )

    @patch("parse.run_tshark")
    @patch("builtins.print")
    def test_main_no_pcap_files(self, mock_print, mock_run_tshark):
        with patch("os.path.isdir", return_value=True):
            with patch("glob.glob", return_value=[]):
                with patch("sys.argv", ["parse.py", "output.csv", "empty_dir"]):
                    main()
                    mock_print.assert_any_call("No pcap files found.")

    @patch("os.path.isdir")
    @patch("os.path.isfile")
    @patch("builtins.print")
    def test_main_invalid_path(self, mock_print, mock_isfile, mock_isdir):
        mock_isdir.return_value = False
        mock_isfile.return_value = False
        with patch("sys.argv", ["parse.py", "output.csv", "invalid_path"]):
            main()
            mock_print.assert_any_call("No valid pcap files found at the specified path: invalid_path")

if __name__ == "__main__":
    unittest.main()
