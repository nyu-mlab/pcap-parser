"""
Processes and aggregates network flow data from a CSV file generated by the parse.py script.

This script is intended to be run after parse.py, which produces a CSV file with detailed network traffic data
The script filters network traffic for TCP, TLSv1.2, and UDP, and groups packets into flows based on connection details, calculates flow statistics, and extracts initial hostnames. The aggregated data is then saved to a new CSV file.

Usage:
    python flow.py <input_csv_file> <output_csv_file>

Example:
    python flow.py output_from_parse.csv aggregated_flows.csv

Note:
    The script is platform-independent but requires Python and pandas to be installed. Make sure file paths and permissions are correctly configured according to your operating system's requirements.

"""

import pandas as pd
import sys
import tldextract

def extract_main_domain(hostname):
    try:
        extracted = tldextract.extract(hostname) # Extracts registered domain: main domain and TLD
        return f"{extracted.domain}.{extracted.suffix}"
    except:
        return None

def process_pcap_data(input_csv, output_csv):
    df = pd.read_csv(input_csv)
    df['frame.time_epoch'] = pd.to_datetime(df['frame.time_epoch'], unit='s') # Convert to timestamps

    df = df[df['_ws.col.Protocol'].isin(['TCP', 'TLSv1.2', 'UDP'])] # Filtering out non-IP/TCP/UDP protocols for accurate flow information

    # Sort by grouping columns and timestamp for accurate inter-arrival times
    df = df.sort_values(by=['ip.src', 'ip.dst', 'tcp.srcport', 'tcp.dstport', 'udp.srcport', 'udp.dstport', '_ws.col.Protocol', 'frame.time_epoch'])
    grouped = df.groupby(['ip.src', 'ip.dst', 'tcp.srcport', 'tcp.dstport', 'udp.srcport', 'udp.dstport', '_ws.col.Protocol'])
    # Calculating inter-arrival times within each flow
    df['inter_arrival_time'] = df.groupby(['ip.src', 'ip.dst', 'tcp.srcport', 'tcp.dstport', 'udp.srcport', 'udp.dstport', '_ws.col.Protocol'])['frame.time_epoch'].diff().dt.total_seconds()

    # Apply domain extraction to hostname columns
    df['src_main_domain'] = df['src_hostname'].apply(extract_main_domain)
    df['dst_main_domain'] = df['dst_hostname'].apply(extract_main_domain)

    # Aggregate data for each flow
    flows = grouped.agg(
        start_ts=('frame.time_epoch', 'min'),
        end_ts=('frame.time_epoch', 'max'),
        byte_count=('frame.len', 'sum'),
        packet_count=('frame.len', 'size'),
        avg_inter_arrival_time=('inter_arrival_time', 'mean'),  # Calculate average inter-arrival time
        src_hostname=('src_hostname', 'first'),
        dst_hostname=('dst_hostname', 'first'),
        src_main_domain=('src_main_domain', 'first'),
        dst_main_domain=('dst_main_domain', 'first')
    )
    flows.reset_index(inplace=True)

    # Specify order
    columns_order = ['start_ts', 'end_ts', 'ip.src', 'ip.dst', 'tcp.srcport', 'tcp.dstport', 'udp.srcport', 'udp.dstport', '_ws.col.Protocol', 'byte_count', 'packet_count', 'avg_inter_arrival_time', 'src_hostname', 'dst_hostname', 'src_main_domain', 'dst_main_domain']
    flows = flows[columns_order]
    flows.to_csv(output_csv, index=False)

def main():
    if len(sys.argv) != 3:
        print("Usage: python flow.py <input_csv_file> <output_csv_file>")
        sys.exit(1)

    input_csv_file = sys.argv[1]
    output_csv_file = sys.argv[2]

    process_pcap_data(input_csv_file, output_csv_file)

if __name__ == "__main__":
    main()
