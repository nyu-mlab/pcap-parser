import unittest
from unittest.mock import patch
import pandas as pd
import os
from io import StringIO
from flow import process_pcap_data, extract_main_domain, main

class TestFlowScript(unittest.TestCase):

    def setUp(self):
        # sample input data
        self.sample_csv = """frame.time_epoch,ip.src,ip.dst,tcp.srcport,tcp.dstport,udp.srcport,udp.dstport,_ws.col.Protocol,frame.len,src_hostname,dst_hostname
1685000000,192.168.1.1,8.8.8.8,12345,80,,,TCP,150,example.com,google.com
1685000001,192.168.1.1,8.8.8.8,12345,80,,,TCP,200,example.com,google.com
1685000002,192.168.1.2,8.8.8.8,12346,443,,,TLSv1.2,300,example.org,google.com
1685000003,192.168.1.1,8.8.8.8,,,,53,UDP,100,example.com,google.com
"""
        self.input_file = "test_input.csv"
        self.output_file = "test_output.csv"

        # write sample data to a temporary csv file
        with open(self.input_file, "w") as f:
            f.write(self.sample_csv)

    def tearDown(self):
        if os.path.exists(self.input_file):
            os.remove(self.input_file)
        if os.path.exists(self.output_file):
            os.remove(self.output_file)

    def test_extract_main_domain(self):
        self.assertEqual(extract_main_domain("example.com"), "example.com")
        self.assertEqual(extract_main_domain("subdomain.example.com"), "example.com")
        self.assertEqual(extract_main_domain(""), None)
        self.assertEqual(extract_main_domain(None), None)

def test_process_pcap_data(self):
    sample_csv = """frame.time_epoch,ip.src,ip.dst,tcp.srcport,tcp.dstport,udp.srcport,udp.dstport,_ws.col.Protocol,frame.len,src_hostname,dst_hostname
    1685000000,192.168.1.1,8.8.8.8,12345,80,,,TCP,150,example.com,google.com
    1685000001,192.168.1.1,8.8.8.8,12345,80,,,TCP,200,example.com,google.com
    1685000002,192.168.1.2,8.8.8.8,12346,443,,,TLSv1.2,300,example.org,google.com
    1685000003,192.168.1.1,8.8.8.8,,,,53,UDP,100,example.com,google.com
    """
    with open(self.input_file, "w") as f:
        f.write(sample_csv)

    process_pcap_data(self.input_file, self.output_file)

    output_df = pd.read_csv(self.output_file)

    self.assertEqual(len(output_df), 3)  # 3 flows: one TCP, one TLSv1.2, one UDP
    self.assertEqual(output_df.loc[0, "ip.src"], "192.168.1.1")
    self.assertEqual(output_df.loc[0, "byte_count"], 350)  # 150 + 200 for the first TCP flow
    self.assertAlmostEqual(output_df.loc[0, "avg_inter_arrival_time"], 1.0)
    self.assertEqual(output_df.loc[0, "src_main_domain"], "example.com")
    self.assertEqual(output_df.loc[0, "dst_main_domain"], "google.com")


    @patch("builtins.print")
    def test_main_invalid_arguments(self, mock_print):
        with patch("sys.argv", ["flow.py"]):
            with self.assertRaises(SystemExit):
                main()
            mock_print.assert_any_call("Usage: python flow.py <input_csv_file> <output_csv_file>")

    def test_empty_input(self):
        empty_file = "empty.csv"
        with open(empty_file, "w") as f:
            f.write("") 

        process_pcap_data(empty_file, self.output_file)

        with open(self.output_file, "r") as f:
            output_content = f.read()
        self.assertEqual(output_content.strip(), "") 

        os.remove(empty_file)

if __name__ == "__main__":
    unittest.main()