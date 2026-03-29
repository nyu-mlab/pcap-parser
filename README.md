# pcap-parser

[![PyPI](https://img.shields.io/pypi/v/pcap-extract)](https://pypi.org/project/pcap-extract/)
[![CI](https://github.com/nyu-mlab/pcap-parser/actions/workflows/ci-parse.yml/badge.svg)](https://github.com/nyu-mlab/pcap-parser/actions/workflows/ci-parse.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

Extract devices, flows, and hostnames from pcap files.

## Quick Start

```bash
pip install pcap-extract
```

Parse a capture and get an instant overview:

```bash
pcap-parse output.csv capture.pcap
pcap-summary output.csv
```

```
╭──────────────────────────── Capture Overview ────────────────────────────╮
│   Packets:    12,847                                                     │
│   Traffic:    8.3 MB                                                     │
│   Devices:    14                                                         │
│   Time Range: 2025-01-15 09:00:12 to 2025-01-15 09:30:45 (30.6m)        │
╰──────────────────────────────────────────────────────────────────────────╯
╭──────────────────────────────── Protocols ────────────────────────────────╮
│ ┏━━━━━━━━━━┳━━━━━━━━━┳━━━━━━━┓                                           │
│ ┃ Protocol ┃ Packets ┃ Share ┃                                           │
│ ┡━━━━━━━━━━╇━━━━━━━━━╇━━━━━━━┩                                           │
│ │ TCP      │   8,421 │ 65.5% │                                           │
│ │ TLS      │   2,103 │ 16.4% │                                           │
│ │ DNS      │   1,547 │ 12.0% │                                           │
│ │ UDP      │     776 │  6.0% │                                           │
│ └──────────┴─────────┴───────┘                                           │
╰──────────────────────────────────────────────────────────────────────────╯
```

List devices on the network:

```bash
pcap-devices output.csv
```

```
                               Devices
┏━━━┳━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━┳━━━━━━━━━━━━━┳━━━━━━━━━┳━━━━━━━━━┓
┃ # ┃ MAC Address       ┃ Vendor       ┃ Hostname    ┃ Packets ┃ Traffic ┃
┡━━━╇━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━╇━━━━━━━━━━━━━╇━━━━━━━━━╇━━━━━━━━━┩
│ 1 │ AA:BB:CC:11:22:33 │ Apple, Inc.  │ macbook-pro │   4,521 │ 3.2 MB  │
│ 2 │ AA:BB:CC:44:55:66 │ Google, Inc. │ pixel-6     │   2,847 │ 1.8 MB  │
│ 3 │ AA:BB:CC:77:88:99 │ Amazon.com   │ echo-dot    │     892 │ 412.0 KB│
└───┴───────────────────┴──────────────┴─────────────┴─────────┴─────────┘
```

Identify unknown devices with a fine-tuned LLM:

```bash
pcap-devices output.csv --identify
```

## Features

- Parse `.pcap` and `.pcapng` files using tshark
- Instant capture summaries with protocol breakdown, top talkers, and top destinations
- Per-device traffic profiles with OUI vendor, DHCP hostname, and traffic volume
- LLM-powered device identification via [IoT Inspector](https://github.com/nyu-mlab/iot-inspector-client)
- Hostname enrichment from DNS, TLS SNI, DHCP, and reverse DNS
- Flow aggregation with packet counts, byte counts, and inter-arrival times
- JSON output for all commands (`--json`)

## Requirements

- Python 3.9+
- [tshark](https://www.wireshark.org/download.html) (comes with Wireshark)

## Installation

```bash
pip install pcap-extract
```

Or for development:

```bash
git clone https://github.com/nyu-mlab/pcap-parser.git
cd pcap-parser
pip install -e ".[dev]"
```

## Usage

### Parse pcap files

```bash
pcap-parse output.csv capture.pcap
pcap-parse output.csv /path/to/pcap_directory/
```

### Get a quick summary

```bash
pcap-summary output.csv
```

### List devices

```bash
pcap-devices output.csv
pcap-devices output.csv --identify    # LLM-powered device identification
pcap-devices output.csv --json        # machine-readable output
```

### Aggregate into flows

```bash
pcap-flow output.csv flows.csv
```

### Output columns

`pcap-parse` produces a CSV with columns including:

| Column | Description |
|--------|-------------|
| `frame.time_epoch` | Packet timestamp |
| `ip.src` / `ip.dst` | Source and destination IPs |
| `tcp.srcport` / `tcp.dstport` | TCP ports |
| `udp.srcport` / `udp.dstport` | UDP ports |
| `_ws.col.Protocol` | Protocol (TCP, UDP, DNS, TLS, etc.) |
| `frame.len` | Packet length in bytes |
| `src_hostname` / `dst_hostname` | Resolved hostnames |
| `dhcp_hostname` | DHCP-advertised hostname |
| `eth.src.oui_resolved` | Device vendor from MAC OUI |
| `http.user_agent` | HTTP user-agent string |

## Running tests

```bash
pytest tests/ -v
```

## Contributing

Contributions are welcome. See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## License

MIT - see [LICENSE](LICENSE) for details.
