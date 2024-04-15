"""
Parses given pcap files, fills in the hostnames, and outputs the results to a
csv file.

Usage:
    python parse.py <output_csv_file> <pcap_file> [<pcap_file> ...]

Example:
    python parse.py output.csv input_1.pcap input_2.pcap

OR:
    python parse.py output.csv *.pcap

This script uses tshark to parse the pcap files. Make sure that Wireshark is
installed. This script only works on macOS.

TODO:
    - Add support for dealing with ARP spoofing (e.g., as a result of output
      from IoT Inspector.)

"""
import subprocess
import pandas as pd
from io import StringIO
import sys
import os


# Define the path to tshark within the Wireshark.app package
TSHARK_PATH = "/Applications/Wireshark.app/Contents/MacOS/tshark"


def main():

    # Parse the command line arguments
    if len(sys.argv) < 3:
        print("Usage: python parse.py <output_csv_file> <pcap_file> [<pcap_file> ...]")
        return

    output_csv_file = sys.argv[1]
    pcap_files = sys.argv[2:]

    # Check that each of the pcap files exists
    for pcap_file in pcap_files:
        if not os.path.exists(pcap_file):
            print(f"Error: pcap file not found: {pcap_file}")
            return

    # Process each pcap file and concatenate the resultant DataFrames
    df_list = []
    for pcap_file in pcap_files:
        print(f"Parsing pcap file: {pcap_file}")
        df = run_tshark(pcap_file)
        if df is not None:
            df_list.append(df)

    if len(df_list) == 0:
        print("Failed to parse any pcap files.")
        return

    # Combine into a single DataFrame
    combined_df = pd.concat(df_list).sort_values(by='frame.time_epoch')

    # Maps IP addresses to hostnames
    ip_hostname_dict = {}

    # Extract all IP -> hostname mappings from SNI fields
    sni_df = combined_df[
        combined_df['tls.handshake.extensions_server_name'].notna()
    ]
    for (_, row) in sni_df.iterrows():
        ip = row['ip.dst']
        hostname = row['tls.handshake.extensions_server_name']
        ip_hostname_dict[ip] = hostname

    # Extract all IP -> hostname mappings from DNS fields
    dns_df = combined_df[
        combined_df['dns.qry.name'].notna() &
        combined_df['dns.a'].notna()
    ]
    for (_, row) in dns_df.iterrows():
        for ip in row['dns.a'].split(','):
            hostname = row['dns.qry.name']
            ip_hostname_dict[ip] = hostname

    # Remove the SNI and DNS fields
    del combined_df['tls.handshake.extensions_server_name']
    del combined_df['dns.qry.name']
    del combined_df['dns.a']

    # Fill in the hostnames for each IP address
    combined_df['src_hostname'] = combined_df['ip.src'].map(
        lambda x: ip_hostname_dict.get(x, None)
    )
    combined_df['dst_hostname'] = combined_df['ip.dst'].map(
        lambda x: ip_hostname_dict.get(x, None)
    )

    # Write the results to a CSV file
    combined_df.to_csv(output_csv_file, index=False)


def run_tshark(pcap_file):
    """
    Run tshark on a pcap file and return the output as a Pandas DataFrame.

    """

    # Define the fields to extract
    fields = [
        'frame.time_epoch',
        'eth.src', 'eth.dst',
        'ip.src', 'ip.dst',
        'tcp.srcport', 'tcp.dstport',
        'udp.srcport', 'udp.dstport',
        '_ws.col.Protocol', 'frame.len',
        'dns.qry.name', 'dns.a',
        'tls.handshake.extensions_server_name'
    ]

    # Create the command to run tshark
    command = [
        TSHARK_PATH,
        '-r', pcap_file,
        '-T', 'fields',
        '-E', 'header=y',
        '-E', 'separator=,',
        '-E', 'quote=d',
        '-E', 'occurrence=a',
        '-2',
        '-R', 'not tcp.analysis.retransmission'
    ]

    for field in fields:
        command += ['-e', field]

    # Run the tshark command and capture the output
    process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    output, error = process.communicate()

    if process.returncode != 0:
        print(f"Error running tshark on pcap file: {pcap_file}")
        print(error.decode())
        return None

    # Decode the output and read it into a Pandas DataFrame
    output = output.decode()
    data = StringIO(output)
    df = pd.read_csv(data)

    # Make sure the ports are integers
    port_columns = ['tcp.srcport', 'tcp.dstport', 'udp.srcport', 'udp.dstport']
    for column in port_columns:
        if column in df:
            df[column] = df[column].fillna(0).astype(int)

    return df


if __name__ == "__main__":
    main()