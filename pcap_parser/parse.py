"""
Parse pcap files and extract enriched packet data to csv.

Requires tshark (part of wireshark) to be installed and available in PATH.

Usage:
    pcap-parse output.csv /path/to/capture.pcap
    pcap-parse output.csv /path/to/pcap_directory/
    pcap-parse --cache-dir /tmp output.csv /path/to/capture.pcap
"""
import argparse
import subprocess
import pandas as pd
import os
import sys
import glob
import shutil
import socket
from io import StringIO
import shelve
from collections import Counter

def _find_tshark():
    path = shutil.which("tshark")
    if not path:
        sys.exit("tshark not found in PATH. install wireshark: https://www.wireshark.org/download.html")
    return path

FIELDS = [
    'frame.time_epoch',
    'eth.src', 'eth.src.oui_resolved', 'eth.dst',
    'ip.src', 'ip.dst',
    'tcp.srcport', 'tcp.dstport',
    'udp.srcport', 'udp.dstport',
    '_ws.col.Protocol', 'frame.len',
    'dns.qry.name', 'dns.a',
    'tls.handshake.extensions_server_name',
    'http.user_agent',
    'bootp.option.hostname'
]

def reverse_dns(ip, unresolvable_ips=None):
    if not ip or not isinstance(ip, str) or ip.lower() == 'nan':
        return ''
    try:
        return socket.gethostbyaddr(ip)[0]
    except (socket.herror, socket.gaierror):
        if unresolvable_ips is not None:
            unresolvable_ips.add(ip)
        return ''

def run_tshark(pcap_file, tshark_path=None):
    tshark_path = tshark_path or _find_tshark()
    cmd = [
        tshark_path, '-r', pcap_file, '-T', 'fields',
        '-E', 'header=y', '-E', 'separator=,', '-E', 'quote=d',
        '-E', 'occurrence=a', '-2', '-R', 'not tcp.analysis.retransmission'
    ]
    for field in FIELDS:
        cmd += ['-e', field]

    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    out, err = proc.communicate()

    if proc.returncode != 0 or not out:
        print(f"[!] Failed to parse {pcap_file}")
        print(err.decode())
        return None

    df = pd.read_csv(StringIO(out.decode()), low_memory=False)
    df['source_file'] = os.path.basename(pcap_file)
    return df

def extract_dhcp_mapping(df):
    """
    Returns: dict mapping ip.src → bootp.option.hostname
    """
    if 'bootp.option.hostname' not in df.columns:
        return {}
    
    dhcp_rows = df[df['bootp.option.hostname'].notna()]
    mapping = {}
    for _, row in dhcp_rows.iterrows():
        key = str(row.get('ip.src'))
        value = str(row.get('bootp.option.hostname')).strip()
        if key and value:
            mapping[key] = value
    return mapping

def enrich_hostnames(df, ip_shelve, unresolvable_ips=None):
    dns_df = df[df['dns.qry.name'].notna() & df['dns.a'].notna()]
    for _, row in dns_df.iterrows():
        for ip in str(row['dns.a']).split(','):
            ip = ip.strip()
            if ip:
                ip_shelve[ip] = row['dns.qry.name']

    sni_df = df[df['tls.handshake.extensions_server_name'].notna()]
    for _, row in sni_df.iterrows():
        ip = row.get('ip.dst')
        if pd.notna(ip):
            ip_shelve[ip] = row['tls.handshake.extensions_server_name']

    df['src_hostname'] = df['ip.src'].map(lambda x: ip_shelve.get(str(x), reverse_dns(str(x), unresolvable_ips)) if pd.notna(x) else '')
    df['dst_hostname'] = df['ip.dst'].map(lambda x: ip_shelve.get(str(x), reverse_dns(str(x), unresolvable_ips)) if pd.notna(x) else '')

    df.drop(['dns.qry.name', 'dns.a', 'tls.handshake.extensions_server_name'], axis=1, inplace=True, errors='ignore')
    return df

def extract_dhcp_hostnames(pcap_file, tshark_path=None):
    tshark_path = tshark_path or _find_tshark()
    try:
        cmd = [
            tshark_path, "-r", pcap_file,
            "-Y", "bootp.option.hostname",
            "-T", "fields", "-e", "bootp.option.hostname"
        ]
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        out, err = proc.communicate()

        if proc.returncode != 0:
            print(f"[!] Warning: tshark exited with code {proc.returncode}")
            print(err.decode())

        hostnames = [line.strip() for line in out.decode().splitlines() if line.strip()]
        counts = Counter(hostnames)

        if counts:
            print(f"\n[✓] DHCP Hostnames in {pcap_file}:\n")
            for hostname, count in counts.most_common():
                print(f"{count:>4} {hostname}")
        else:
            print(f"[!] No DHCP hostnames found in {pcap_file}")

    except Exception as e:
        print(f"[!] Error running tshark on {pcap_file}: {e}")

def main():
    parser = argparse.ArgumentParser(
        description="parse pcap files and extract enriched packet data to csv"
    )
    parser.add_argument("output", help="path for the output csv file")
    parser.add_argument("input", help="path to a pcap file or directory of pcap files")
    parser.add_argument("--cache-dir", default=".", help="directory for the hostname cache (default: current directory)")
    args = parser.parse_args()

    output_csv = args.output
    input_path = args.input
    tshark_path = _find_tshark()
    ip_shelve_path = os.path.join(args.cache_dir, 'ip_hostname_cache')

    if os.path.isdir(input_path):
        pcap_files = glob.glob(os.path.join(input_path, '*.pcap')) + glob.glob(os.path.join(input_path, '*.pcapng'))
    elif os.path.isfile(input_path) and (input_path.endswith('.pcap') or input_path.endswith('.pcapng')):
        pcap_files = [input_path]
    else:
        print("No valid .pcap or .pcapng files found.")
        return

    if not pcap_files:
        print("No .pcap files found.")
        return

    unresolvable_ips = set()
    df_list = []
    with shelve.open(ip_shelve_path) as ip_shelve:
        for pcap_file in pcap_files:
            extract_dhcp_hostnames(pcap_file, tshark_path)
            print(f"[+] Parsing: {pcap_file}")
            df = run_tshark(pcap_file, tshark_path)
            if df is not None:
                dhcp_map = extract_dhcp_mapping(df) # extract DHCP map and enrich
                df = enrich_hostnames(df, ip_shelve, unresolvable_ips)
                df['dhcp_hostname'] = df['ip.src'].map(lambda x: dhcp_map.get(str(x), '')) # add dhcp_hostname column (if map exists)
                if 'bootp.option.hostname' in df.columns:
                    df.drop(['bootp.option.hostname'], axis=1, inplace=True)

                df_list.append(df)

    if not df_list:
        print("No data extracted.")
        return

    final_df = pd.concat(df_list).sort_values(by='frame.time_epoch')
    final_df.to_csv(output_csv, index=False)
    print(f"[✓] Done. Output written to: {output_csv}")

    if unresolvable_ips:
        print(f"[!] Unresolvable IPs: {len(unresolvable_ips)}")

if __name__ == "__main__":
    main()
