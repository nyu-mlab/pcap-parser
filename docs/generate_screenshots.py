"""Generate SVG screenshots of CLI output for the README."""

import sys
sys.path.insert(0, ".")

from rich.console import Console

# Generate pcap-summary screenshot
from pcap_parser.summary import summarize, print_summary

console = Console(record=True, width=80)

# Use a richer fake dataset for the screenshot
import pandas as pd
import tempfile, os

# Create realistic-looking parsed CSV
data = {
    "frame.time_epoch": [1737100812.0 + i * 0.5 for i in range(50)],
    "eth.src": (
        ["AA:BB:CC:11:22:33"] * 20
        + ["DD:EE:FF:44:55:66"] * 15
        + ["11:22:33:AA:BB:CC"] * 10
        + ["44:55:66:DD:EE:FF"] * 5
    ),
    "eth.src.oui_resolved": (
        ["Apple, Inc."] * 20
        + ["Google, Inc."] * 15
        + ["Amazon Technologies Inc."] * 10
        + ["Samsung Electronics"] * 5
    ),
    "ip.src": (
        ["192.168.1.10"] * 20
        + ["192.168.1.20"] * 15
        + ["192.168.1.30"] * 10
        + ["192.168.1.40"] * 5
    ),
    "ip.dst": (
        ["17.253.144.10"] * 5
        + ["142.250.80.46"] * 10
        + ["93.184.216.34"] * 5
        + ["142.250.80.46"] * 8
        + ["54.239.28.85"] * 7
        + ["54.239.28.85"] * 10
        + ["104.16.132.229"] * 5
    ),
    "_ws.col.Protocol": (
        ["TLS"] * 15
        + ["TCP"] * 12
        + ["DNS"] * 10
        + ["UDP"] * 8
        + ["HTTP"] * 5
    ),
    "frame.len": [
        150, 1200, 800, 54, 300, 1400, 600, 200, 54, 1000,
        800, 1200, 150, 300, 54, 600, 1400, 200, 800, 1000,
        54, 300, 1200, 150, 800, 600, 1400, 200, 54, 1000,
        300, 800, 1200, 150, 54, 600, 1400, 200, 1000, 800,
        300, 150, 54, 1200, 600, 1400, 200, 800, 1000, 54,
    ],
    "dst_hostname": (
        ["icloud.com"] * 5
        + ["google.com"] * 10
        + ["example.com"] * 5
        + ["youtube.com"] * 8
        + ["amazon.com"] * 7
        + ["amazonaws.com"] * 10
        + ["cloudflare.com"] * 5
    ),
    "dhcp_hostname": (
        ["macbook-pro"] * 20
        + ["pixel-7"] * 15
        + ["echo-dot"] * 10
        + ["galaxy-s23"] * 5
    ),
    "http.user_agent": [None] * 50,
}

df = pd.DataFrame(data)
with tempfile.NamedTemporaryFile(suffix=".csv", delete=False) as f:
    df.to_csv(f.name, index=False)
    tmp_csv = f.name

# Capture summary
from pcap_parser.summary import summarize as _summarize
from pcap_parser.summary import (
    _format_bytes, _format_timestamp, _format_duration,
)
from rich.table import Table
from rich.panel import Panel
from rich.text import Text

stats = _summarize(tmp_csv)

overview = Text()
overview.append("  Packets:    ", style="dim")
overview.append(f"{stats['total_packets']:,}\n", style="bold white")
overview.append("  Traffic:    ", style="dim")
overview.append(f"{_format_bytes(stats['total_bytes'])}\n", style="bold magenta")
overview.append("  Devices:    ", style="dim")
overview.append(f"{stats['device_count']}\n", style="bold cyan")
overview.append("  Time Range: ", style="dim")
overview.append(
    f"{_format_timestamp(stats['start_ts'])} to {_format_timestamp(stats['end_ts'])}",
    style="white",
)
overview.append(f" ({_format_duration(stats['duration'])})\n", style="dim")

console.print()
console.print(Panel(overview, title="[bold]Capture Overview[/]", border_style="cyan"))

if stats["protocols"]:
    proto_table = Table(show_header=True, header_style="bold cyan", border_style="dim")
    proto_table.add_column("Protocol", style="bold")
    proto_table.add_column("Packets", justify="right", style="white")
    proto_table.add_column("Share", justify="right", style="dim")
    total = stats["total_packets"]
    for proto, count in stats["protocols"].items():
        pct = f"{count / total * 100:.1f}%"
        proto_table.add_row(str(proto), f"{count:,}", pct)
    console.print(Panel(proto_table, title="[bold]Protocols[/]", border_style="green"))

if stats["top_talkers"]:
    talker_table = Table(show_header=True, header_style="bold cyan", border_style="dim")
    talker_table.add_column("Source IP", style="bold")
    talker_table.add_column("Traffic", justify="right", style="magenta")
    for ip, bytes_sent in stats["top_talkers"].items():
        talker_table.add_row(str(ip), _format_bytes(bytes_sent))
    console.print(Panel(talker_table, title="[bold]Top Talkers[/]", border_style="yellow"))

destinations = stats["top_destinations"] or stats["top_dst_ips"]
if destinations:
    dest_table = Table(show_header=True, header_style="bold cyan", border_style="dim")
    dest_table.add_column("Destination", style="bold")
    dest_table.add_column("Packets", justify="right", style="white")
    for dest, count in list(destinations.items())[:5]:
        dest_table.add_row(str(dest), f"{count:,}")
    console.print(Panel(dest_table, title="[bold]Top Destinations[/]", border_style="magenta"))

console.print()
console.save_svg("docs/images/pcap-summary.svg", title="pcap-summary")
print("Saved docs/images/pcap-summary.svg")

# Generate pcap-devices screenshot
console2 = Console(record=True, width=90)

from pcap_parser.devices import aggregate_devices, _format_bytes as _fmt

devices = aggregate_devices(tmp_csv)

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

for i, device in enumerate(devices):
    ips = ", ".join(device["ips"][:3])
    destinations = ", ".join(device["top_destinations"][:3])
    table.add_row(
        str(i + 1),
        device["mac"],
        device["oui_vendor"] or "-",
        device["dhcp_hostname"] or "-",
        ips or "-",
        f"{device['packet_count']:,}",
        _fmt(device["byte_count"]),
        destinations or "-",
    )

console2.print(table)
console2.print(f"\n  [bold]{len(devices)}[/] devices found\n")
console2.save_svg("docs/images/pcap-devices.svg", title="pcap-devices")
print("Saved docs/images/pcap-devices.svg")

os.unlink(tmp_csv)
