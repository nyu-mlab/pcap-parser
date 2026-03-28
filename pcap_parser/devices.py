"""
List devices found in parsed pcap data.

Groups packets by source MAC address and summarizes each device's metadata
including IPs, OUI vendor, DHCP hostname, top destinations, and traffic volume.

Usage:
    pcap-devices parsed_packets.csv
    pcap-devices parsed_packets.csv --identify
    pcap-devices parsed_packets.csv --json
"""

import argparse
import json
import sys
import urllib.request
import urllib.error

import pandas as pd


DEVID_API_URL = "https://rameen-mahmood--dev-id-predict.modal.run"
DEVID_API_KEY = "momo"


def aggregate_devices(input_csv):
    """Group parsed packet CSV by source MAC and return per-device summaries."""
    df = pd.read_csv(input_csv)

    if "eth.src" not in df.columns:
        print("[!] No eth.src column found. Is this a pcap-parse output file?")
        sys.exit(1)

    df = df[df["eth.src"].notna()]

    devices = []
    for mac, group in df.groupby("eth.src"):
        ips = group["ip.src"].dropna().unique().tolist()
        oui = _first_non_empty(group, "eth.src.oui_resolved")
        dhcp = _first_non_empty(group, "dhcp_hostname")
        user_agent = _first_non_empty(group, "http.user_agent")

        dst_hosts = group["dst_hostname"].dropna()
        dst_hosts = dst_hosts[dst_hosts != ""]
        top_destinations = dst_hosts.value_counts().head(5).index.tolist()

        packet_count = len(group)
        byte_count = int(group["frame.len"].sum()) if "frame.len" in group.columns else 0

        devices.append({
            "mac": mac,
            "ips": ips,
            "oui_vendor": oui,
            "dhcp_hostname": dhcp,
            "user_agent": user_agent,
            "top_destinations": top_destinations,
            "packet_count": packet_count,
            "byte_count": byte_count,
        })

    devices.sort(key=lambda d: d["byte_count"], reverse=True)
    return devices


def identify_device(device):
    """Call the dev-id Modal API to predict device vendor."""
    fields = {
        "DHCP Hostname": device.get("dhcp_hostname") or "unknown",
        "Remote Hostnames": ", ".join(device.get("top_destinations") or []) or "unknown",
        "User Agent": device.get("user_agent") or "unknown",
        "OUI": device.get("oui_vendor") or "unknown",
    }

    payload = json.dumps({
        "mac_address": device.get("mac", ""),
        "fields": fields,
    }).encode()

    req = urllib.request.Request(
        DEVID_API_URL,
        data=payload,
        headers={
            "Content-Type": "application/json",
            "x-api-key": DEVID_API_KEY,
        },
    )

    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            result = json.loads(resp.read().decode())
            return {
                "vendor": result.get("vendor", "unknown"),
                "explanation": result.get("explanation", ""),
                "source": result.get("source", ""),
            }
    except (urllib.error.URLError, json.JSONDecodeError) as e:
        return {"vendor": "unknown", "explanation": str(e), "source": "error"}


def _first_non_empty(group, column):
    """Return the first non-empty value from a column, or empty string."""
    if column not in group.columns:
        return ""
    vals = group[column].dropna()
    vals = vals[vals.astype(str).str.strip() != ""]
    return str(vals.iloc[0]) if len(vals) > 0 else ""


def _format_bytes(n):
    """Format byte count as human-readable string."""
    for unit in ["B", "KB", "MB", "GB"]:
        if n < 1024:
            return f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} TB"


def print_devices(devices, identify=False):
    """Print device table to stdout."""
    if not devices:
        print("[!] No devices found.")
        return

    if identify:
        print(f"[+] Identifying {len(devices)} devices via dev-id API...")

    for i, device in enumerate(devices):
        identification = None
        if identify:
            identification = identify_device(device)

        print()
        print(f"  Device {i + 1}")
        print(f"  {'=' * 50}")
        print(f"  MAC:            {device['mac']}")
        if device["oui_vendor"]:
            print(f"  OUI Vendor:     {device['oui_vendor']}")
        if device["dhcp_hostname"]:
            print(f"  DHCP Hostname:  {device['dhcp_hostname']}")
        if device["ips"]:
            print(f"  IPs:            {', '.join(device['ips'][:5])}")
        if device["user_agent"]:
            ua = device["user_agent"]
            if len(ua) > 80:
                ua = ua[:77] + "..."
            print(f"  User-Agent:     {ua}")
        print(f"  Packets:        {device['packet_count']:,}")
        print(f"  Traffic:        {_format_bytes(device['byte_count'])}")
        if device["top_destinations"]:
            print(f"  Top Hosts:      {', '.join(device['top_destinations'][:3])}")

        if identification:
            vendor = identification["vendor"]
            source = identification["source"]
            explanation = identification["explanation"]
            print(f"  Identified As:  {vendor.strip()} (via {source})")
            if explanation:
                if len(explanation) > 100:
                    explanation = explanation[:97] + "..."
                print(f"  Explanation:    {explanation}")

    print()
    print(f"  Total: {len(devices)} devices")
    print()


def main():
    parser = argparse.ArgumentParser(
        description="list devices found in parsed pcap data"
    )
    parser.add_argument("input", help="path to the parsed csv file (output of pcap-parse)")
    parser.add_argument("--identify", action="store_true",
                        help="identify devices using the dev-id LLM API")
    parser.add_argument("--json", action="store_true", dest="output_json",
                        help="output as json instead of formatted table")
    args = parser.parse_args()

    devices = aggregate_devices(args.input)

    if args.output_json:
        if args.identify:
            for device in devices:
                device["identification"] = identify_device(device)
        print(json.dumps(devices, indent=2))
    else:
        print_devices(devices, identify=args.identify)


if __name__ == "__main__":
    main()
