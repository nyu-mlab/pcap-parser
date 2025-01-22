"""
Parses pcap files specified by the user, either as individual files or all files in a directory,
fills in the hostnames, and outputs the results to a csv file.

Usage:
    python parse.py <output_csv_file> <path_to_pcap_file_or_directory>

Examples:
    python parse.py output.csv /path/to/single.pcap
    python parse.py output.csv /path/to/pcap_files

This script uses tshark to parse the pcap files, and verifies that tshark is installed. This script works for *nix.


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
import shelve
import socket

if platform.system() == "Darwin":
    # Define the path to tshark within the Wireshark.app package
    TSHARK_PATH = "/Applications/Wireshark.app/Contents/MacOS/tshark"
elif os.name == "posix":
    assert (TSHARK_PATH := shutil.which("tshark", os.X_OK)), "couldn't find tshark"
else:
    sys.exit("This script requires *nix.")

unresolvable_ips = []  # List to keep track of unresolvable IP addresses

def main():
    # Parse the command line arguments
    ip_shelve_path = 'ip_hostname_db'
    with shelve.open(ip_shelve_path) as ip_shelve:
        if len(sys.argv) != 3:
            print("Usage: python parse.py <output_csv_file> <path_to_pcap_file_or_directory>")
            return

        output_csv_file = sys.argv[1]
        pcap_path = sys.argv[2]

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
            df = run_tshark(pcap_file, ip_shelve)
            if df is not None:
                df_list.append(df)

        if not df_list:
            print("Failed to parse any pcap files.")
            return

        combined_df = pd.concat(df_list).sort_values(by='frame.time_epoch')
        combined_df.to_csv(output_csv_file, index=False)
        print(f"Output file created: {output_csv_file}")
        if unresolvable_ips:
            print("Unresolvable IP addresses:", unresolvable_ips)

def run_tshark(pcap_file, ip_shelve):
    """
    Run tshark on a pcap file and return the output as a Pandas DataFrame.
    """
    command = [TSHARK_PATH, '-r', pcap_file, '-T', 'fields', '-E', 'header=y', '-E', 'separator=,', '-E', 'quote=d', '-E', 'occurrence=a', '-2', '-R', 'not tcp.analysis.retransmission']
    fields = ['frame.time_epoch', 'eth.src', 'eth.dst', 'ip.src', 'ip.dst', 'tcp.srcport', 'tcp.dstport', 'udp.srcport', 'udp.dstport', '_ws.col.Protocol', 'frame.len', 'dns.qry.name', 'dns.a', 'tls.handshake.extensions_server_name']
    for field in fields:
        command += ['-e', field]
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
    update_ip_hostname_mappings(df, ip_shelve)
    return df

def update_ip_hostname_mappings(df, ip_shelve):
    dns_df = df[df['dns.qry.name'].notna() & df['dns.a'].notna()]
    for _, row in dns_df.iterrows():
        ips = row['dns.a'].split(',')
        for ip in ips:
            ip_shelve[ip] = row['dns.qry.name']

    sni_df = df[df['tls.handshake.extensions_server_name'].notna()]
    for _, row in sni_df.iterrows():
        ip_shelve[row['ip.dst']] = row['tls.handshake.extensions_server_name']

    df['src_hostname'] = df['ip.src'].map(lambda x: ip_shelve.get(str(x), reverse_dns(str(x)) if x else ''))
    df['dst_hostname'] = df['ip.dst'].map(lambda x: ip_shelve.get(str(x), reverse_dns(str(x)) if x else ''))
    df.drop(['dns.qry.name', 'dns.a', 'tls.handshake.extensions_server_name'], axis=1, inplace=True)

def reverse_dns(ip_address):
    """
    Attempts to resolve an IP address to a hostname using a reverse DNS lookup; 
    This function is used as a fallback mechanism in the event that an IP address does not have a corresponding hostname entry in the shelve database.
    """
    if not ip_address or not isinstance(ip_address, str):
        return ''
    try:
        hostname = socket.gethostbyaddr(ip_address)[0]
        return hostname
    except (socket.herror, socket.gaierror):
        return ''

if __name__ == "__main__":
    main()