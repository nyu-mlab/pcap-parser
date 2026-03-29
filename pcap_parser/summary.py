"""
Print a quick overview of parsed pcap data.

Shows device count, protocol breakdown, top talkers, top destinations,
and capture time range.

Usage:
    pcap-summary parsed_packets.csv
"""

import argparse
from datetime import datetime

import pandas as pd
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text


console = Console()


def _format_bytes(n):
    """Format byte count as human-readable string."""
    for unit in ["B", "KB", "MB", "GB"]:
        if n < 1024:
            return f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} TB"


def _format_timestamp(epoch):
    """Format epoch timestamp as readable datetime."""
    try:
        return datetime.fromtimestamp(epoch).strftime("%Y-%m-%d %H:%M:%S")
    except (ValueError, OSError, TypeError):
        return str(epoch)


def _format_duration(seconds):
    """Format duration in seconds as human-readable string."""
    if seconds < 60:
        return f"{seconds:.1f}s"
    elif seconds < 3600:
        return f"{seconds / 60:.1f}m"
    elif seconds < 86400:
        return f"{seconds / 3600:.1f}h"
    return f"{seconds / 86400:.1f}d"


def summarize(input_csv):
    """Generate summary statistics from parsed pcap CSV."""
    df = pd.read_csv(input_csv)

    total_packets = len(df)
    total_bytes = int(df["frame.len"].sum()) if "frame.len" in df.columns else 0

    # time range
    start_ts = None
    end_ts = None
    duration = 0
    if "frame.time_epoch" in df.columns:
        epochs = df["frame.time_epoch"].dropna()
        if len(epochs) > 0:
            start_ts = epochs.min()
            end_ts = epochs.max()
            duration = end_ts - start_ts

    # device count
    device_count = 0
    if "eth.src" in df.columns:
        device_count = df["eth.src"].nunique()

    # protocol breakdown - handle both column name variants
    proto_col = None
    if "_ws.col.Protocol" in df.columns:
        proto_col = "_ws.col.Protocol"
    elif "_ws.col.protocol" in df.columns:
        proto_col = "_ws.col.protocol"

    protocols = {}
    if proto_col:
        protocols = df[proto_col].value_counts().head(8).to_dict()

    # top talkers (by bytes sent)
    top_talkers = {}
    if "ip.src" in df.columns and "frame.len" in df.columns:
        top_talkers = df.groupby("ip.src")["frame.len"].sum().sort_values(
            ascending=False
        ).head(5).to_dict()

    # top destinations
    top_destinations = {}
    if "dst_hostname" in df.columns:
        dst = df["dst_hostname"].dropna()
        dst = dst[dst.astype(str).str.strip() != ""]
        if len(dst) > 0:
            top_destinations = dst.value_counts().head(8).to_dict()

    # top destination IPs (fallback if no hostnames)
    top_dst_ips = {}
    if not top_destinations and "ip.dst" in df.columns:
        top_dst_ips = df["ip.dst"].value_counts().head(8).to_dict()

    return {
        "total_packets": total_packets,
        "total_bytes": total_bytes,
        "start_ts": start_ts,
        "end_ts": end_ts,
        "duration": duration,
        "device_count": device_count,
        "protocols": protocols,
        "top_talkers": top_talkers,
        "top_destinations": top_destinations,
        "top_dst_ips": top_dst_ips,
    }


def print_summary(stats):
    """Print summary using rich panels and tables."""
    # overview panel
    overview = Text()
    overview.append("  Packets:    ", style="dim")
    overview.append(f"{stats['total_packets']:,}\n", style="bold white")
    overview.append("  Traffic:    ", style="dim")
    overview.append(f"{_format_bytes(stats['total_bytes'])}\n", style="bold magenta")
    overview.append("  Devices:    ", style="dim")
    overview.append(f"{stats['device_count']}\n", style="bold cyan")
    if stats["start_ts"] is not None:
        overview.append("  Time Range: ", style="dim")
        overview.append(
            f"{_format_timestamp(stats['start_ts'])} to {_format_timestamp(stats['end_ts'])}",
            style="white",
        )
        overview.append(f" ({_format_duration(stats['duration'])})\n", style="dim")

    console.print()
    console.print(Panel(overview, title="[bold]Capture Overview[/]", border_style="cyan"))

    # protocol breakdown
    if stats["protocols"]:
        proto_table = Table(
            show_header=True,
            header_style="bold cyan",
            border_style="dim",
        )
        proto_table.add_column("Protocol", style="bold")
        proto_table.add_column("Packets", justify="right", style="white")
        proto_table.add_column("Share", justify="right", style="dim")
        total = stats["total_packets"]
        for proto, count in stats["protocols"].items():
            pct = f"{count / total * 100:.1f}%"
            proto_table.add_row(str(proto), f"{count:,}", pct)
        console.print(Panel(proto_table, title="[bold]Protocols[/]", border_style="green"))

    # top talkers
    if stats["top_talkers"]:
        talker_table = Table(
            show_header=True,
            header_style="bold cyan",
            border_style="dim",
        )
        talker_table.add_column("Source IP", style="bold")
        talker_table.add_column("Traffic", justify="right", style="magenta")
        for ip, bytes_sent in stats["top_talkers"].items():
            talker_table.add_row(str(ip), _format_bytes(bytes_sent))
        console.print(Panel(talker_table, title="[bold]Top Talkers[/]", border_style="yellow"))

    # top destinations
    destinations = stats["top_destinations"] or stats["top_dst_ips"]
    if destinations:
        dest_table = Table(
            show_header=True,
            header_style="bold cyan",
            border_style="dim",
        )
        label = "Destination" if stats["top_destinations"] else "Destination IP"
        dest_table.add_column(label, style="bold")
        dest_table.add_column("Packets", justify="right", style="white")
        for dest, count in destinations.items():
            dest_table.add_row(str(dest), f"{count:,}")
        console.print(Panel(dest_table, title="[bold]Top Destinations[/]", border_style="magenta"))

    console.print()


def main():
    parser = argparse.ArgumentParser(
        description="print a quick summary of parsed pcap data"
    )
    parser.add_argument("input", help="path to the parsed csv file (output of pcap-parse)")
    args = parser.parse_args()

    stats = summarize(args.input)
    print_summary(stats)


if __name__ == "__main__":
    main()
