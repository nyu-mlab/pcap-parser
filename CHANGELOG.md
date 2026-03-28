# Changelog

## v0.1.0 (2026-03-28)

Initial release.

- Parse pcap/pcapng files using tshark and extract enriched packet data to CSV
- Aggregate packets into network flows with statistics
- Hostname enrichment from DNS, TLS SNI, DHCP, and reverse DNS
- Device metadata extraction (OUI vendor, HTTP user-agent)
- CLI commands: `pcap-parse` and `pcap-flow`
- Published to PyPI as `pcap-extract`
