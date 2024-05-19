"""
Parses pcap files specified by the user, either as individual files or all files in a directory,
fills in the hostnames, and outputs the results to a csv file.

Usage:
    python parse.py <output_csv_file> <path_to_pcap_file_or_directory>

Examples:
    python parse.py output.csv /path/to/single.pcap
    python parse.py output.csv /path/to/pcap_files

This script uses tshark to parse the pcap files, and verifies that tshark is installed and executable.

This script works on macOS and Linux.

TODO:
    - Add support for dealing with ARP spoofing (e.g., as a result of output from IoT Inspector.)
"""
import subprocess
import pandas as pd
from io import StringIO
import sys
import os
import glob
import platform
import shutil

operating_system = platform.system()
operating_system_release = platform.release()

# check things are working - uncomment for debugging
# print(f'OS appears to be {operating_system}, release version {operating_system_release}\n')

if operating_system == "Darwin" or operating_system == "Linux":
    tshark_exists = shutil.which('tshark')
    if tshark_exists and os.access(tshark_exists, os.X_OK) == True:
        TSHARK_PATH = tshark_exists
    else:
        sys.exit("Verify that tshark is installed, and that tshark is executable.")
else:
    sys.exit("This script requires either MacOS or Linux.")

def main():
    # Parse the command line arguments
    if len(sys.argv) != 3:
        print("Usage: python parse.py <output_csv_file> <path_to_pcap_file_or_directory>")
        return

    output_csv_file = sys.argv[1]
    pcap_path = sys.argv[2]

    # Check if the path is a directory or a single file
    if os.path.isdir(pcap_path):
        pcap_files = glob.glob(os.path.join(pcap_path, '*.pcap'))
    elif os.path.isfile(pcap_path) and pcap_path.endswith('.pcap'):
        pcap_files = [pcap_path]
    else:
        print(f"No valid pcap files found at the specified path: {pcap_path}")
        return

    if not pcap_files:
        print("No pcap files found.")
        return

    # Process each pcap file and concatenate the resultant DataFrames
    df_list = []
    for pcap_file in pcap_files:
        print(f"Parsing pcap file: {pcap_file}")
        df = run_tshark(pcap_file)
        if df is not None:
            df_list.append(df)

    if not df_list:
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
    df = pd.read_csv(data, low_memory=False)

    # Make sure the ports are integers
    port_columns = ['tcp.srcport', 'tcp.dstport', 'udp.srcport', 'udp.dstport']
    for column in port_columns:
        if column in df:
            df[column] = df[column].fillna(0).astype(int)

    return df


if __name__ == "__main__":
    main()
