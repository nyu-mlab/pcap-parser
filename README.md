# pcap-parser

[![PyPI](https://img.shields.io/pypi/v/pcap-extract)](https://pypi.org/project/pcap-extract/)
[![CI](https://github.com/nyu-mlab/pcap-parser/actions/workflows/ci-parse.yml/badge.svg)](https://github.com/nyu-mlab/pcap-parser/actions/workflows/ci-parse.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

Python tool to parse pcap files and extract flow-related network traffic information. Extracts hostnames from DNS, TLS SNI, DHCP, and reverse DNS lookups, then aggregates packets into flows with statistics.

## Features

- Parse `.pcap` and `.pcapng` files using tshark
- Hostname enrichment from DNS queries, TLS SNI, DHCP, and reverse DNS
- Device metadata extraction (OUI vendor, HTTP user-agent)
- Flow aggregation with packet counts, byte counts, and inter-arrival times
- Device discovery with per-device traffic summaries
- LLM-powered device identification via [IoT Inspector](https://github.com/nyu-mlab/iot-inspector-client)
- Domain extraction from hostnames
- Persistent IP-to-hostname cache across runs

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

Parse a single file:

```bash
pcap-parse output.csv /path/to/capture.pcap
```

Parse all pcap files in a directory:

```bash
pcap-parse output.csv /path/to/pcap_directory/
```

### Aggregate into flows

After parsing, aggregate packets into flows:

```bash
pcap-flow output.csv aggregated_flows.csv
```

### List devices

List all devices found in the capture:

```bash
pcap-devices output.csv
```

Identify devices using a fine-tuned LLM:

```bash
pcap-devices output.csv --identify
```

Output as JSON:

```bash
pcap-devices output.csv --json
```

### Output

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

`pcap-flow` aggregates these into flows with start/end timestamps, byte counts, packet counts, and average inter-arrival times.

## Running tests

```bash
pytest tests/ -v
```

## Contributing

Contributions are welcome. See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## License

MIT - see [LICENSE](LICENSE) for details.
