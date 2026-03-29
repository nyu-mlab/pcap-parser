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
from rich.console import Console
from rich.table import Table


DEVID_API_URL = "https://rameen-mahmood--dev-id-predict.modal.run"
DEVID_API_KEY = "momo"

console = Console()


def aggregate_devices(input_csv):
    """Group parsed packet CSV by source MAC and return per-device summaries."""
    df = pd.read_csv(input_csv)

    if "eth.src" not in df.columns:
        console.print("[bold red][!] No eth.src column found. Is this a pcap-parse output file?[/]")
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
    """Print device table to stdout using rich."""
    if not devices:
        console.print("[bold yellow][!] No devices found.[/]")
        return

    if identify:
        console.print(f"\n[bold cyan][+] Identifying {len(devices)} devices via device ID API...[/]\n")

    table = Table(
        title="Devices",
        show_header=True,
        header_style="bold cyan",
        border_style="dim",
        title_style="bold white",
    )

    table.add_column("#", style="dim", width=3)
    table.add_column("MAC Address", style="bold")
    table.add_column("Vendor", style="green")
    table.add_column("Hostname", style="yellow")
    table.add_column("IPs", style="white")
    table.add_column("Packets", justify="right", style="white")
    table.add_column("Traffic", justify="right", style="magenta")
    table.add_column("Top Destinations", style="cyan")
    if identify:
        table.add_column("Identified As", style="bold green")

    for i, device in enumerate(devices):
        ips = ", ".join(device["ips"][:3])
        if len(device["ips"]) > 3:
            ips += f" (+{len(device['ips']) - 3})"

        destinations = ", ".join(device["top_destinations"][:3])

        row = [
            str(i + 1),
            device["mac"],
            device["oui_vendor"] or "-",
            device["dhcp_hostname"] or "-",
            ips or "-",
            f"{device['packet_count']:,}",
            _format_bytes(device["byte_count"]),
            destinations or "-",
        ]

        if identify:
            identification = identify_device(device)
            vendor = identification["vendor"].strip()
            source = identification["source"]
            row.append(f"{vendor} ({source})")

        table.add_row(*row)

    console.print(table)
    console.print(f"\n  [bold]{len(devices)}[/] devices found\n")


def main():
    parser = argparse.ArgumentParser(
        description="list devices found in parsed pcap data"
    )
    parser.add_argument("input", help="path to the parsed csv file (output of pcap-parse)")
    parser.add_argument("--identify", action="store_true",
                        help="identify devices using the device ID LLM API")
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
