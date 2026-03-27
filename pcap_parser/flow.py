"""
Aggregate parsed packet csv into network flows.

Takes the csv output from pcap-parse and groups packets into flows based on
connection tuples, calculating statistics like byte counts, packet counts,
and inter-arrival times.

Usage:
    pcap-flow parsed_packets.csv flows.csv
"""

import argparse
import pandas as pd
import sys
import tldextract

def extract_main_domain(hostname):
    try:
        extracted = tldextract.extract(str(hostname))
        return f"{extracted.domain}.{extracted.suffix}" if extracted.suffix else ''
    except (ValueError, AttributeError):
        return None

def get_src_port(row):
    return row['tcp.srcport'] if pd.notna(row['tcp.srcport']) else row['udp.srcport']

def get_dst_port(row):
    return row['tcp.dstport'] if pd.notna(row['tcp.dstport']) else row['udp.dstport']

def process_pcap_data(input_csv, output_csv):
    df = pd.read_csv(input_csv)
    df['frame.time_epoch'] = pd.to_datetime(df['frame.time_epoch'], unit='s', errors='coerce')

    df = df[df['_ws.col.Protocol'].isin(['TCP', 'TLSv1.2', 'UDP', 'TLS', 'DNS'])]

    # Combine ports
    df['src_port'] = df.apply(get_src_port, axis=1)
    df['dst_port'] = df.apply(get_dst_port, axis=1)

    # Drop if missing core fields
    df = df.dropna(subset=['ip.src', 'ip.dst', 'src_port', 'dst_port', '_ws.col.Protocol'])

    # Sort
    df = df.sort_values(by=[
        'ip.src', 'ip.dst', 'src_port', 'dst_port',
        '_ws.col.Protocol', 'frame.time_epoch'
    ])

    # Inter-arrival time
    df['inter_arrival_time'] = df.groupby([
        'ip.src', 'ip.dst', 'src_port', 'dst_port', '_ws.col.Protocol'
    ])['frame.time_epoch'].diff().dt.total_seconds()

    # Domain extraction
    df['src_main_domain'] = df['src_hostname'].apply(extract_main_domain)
    df['dst_main_domain'] = df['dst_hostname'].apply(extract_main_domain)

    # Group into flows
    grouped = df.groupby([
        'ip.src', 'ip.dst', 'src_port', 'dst_port', '_ws.col.Protocol'
    ])

    flows = grouped.agg(
        start_ts=('frame.time_epoch', 'min'),
        end_ts=('frame.time_epoch', 'max'),
        byte_count=('frame.len', 'sum'),
        packet_count=('frame.len', 'size'),
        avg_inter_arrival_time=('inter_arrival_time', 'mean'),
        src_hostname=('src_hostname', 'first'),
        dst_hostname=('dst_hostname', 'first'),
        dhcp_hostname=('dhcp_hostname', 'first'),
        src_main_domain=('src_main_domain', 'first'),
        dst_main_domain=('dst_main_domain', 'first'),
        user_agent_info=('http.user_agent', 'first'),
        oui_vendor=('eth.src.oui_resolved', 'first')
    ).reset_index()

    flows = flows[[
        'start_ts', 'end_ts', 'ip.src', 'ip.dst',
        'src_port', 'dst_port', '_ws.col.Protocol',
        'byte_count', 'packet_count', 'avg_inter_arrival_time',
        'src_hostname', 'dst_hostname', 'dhcp_hostname',
        'src_main_domain', 'dst_main_domain',
        'user_agent_info', 'oui_vendor'
    ]]

    flows.to_csv(output_csv, index=False)
    print(f"[✓] Done. Saved {len(flows)} flows to {output_csv}")

def main():
    parser = argparse.ArgumentParser(
        description="aggregate parsed packet csv into network flows"
    )
    parser.add_argument("input", help="path to the parsed csv file (output of pcap-parse)")
    parser.add_argument("output", help="path for the output flows csv file")
    args = parser.parse_args()

    process_pcap_data(args.input, args.output)

if __name__ == "__main__":
    main()
