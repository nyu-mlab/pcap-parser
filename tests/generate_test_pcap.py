"""Generate a minimal test pcap file with DNS and TCP traffic for testing."""

from scapy.all import (
    Ether, IP, UDP, TCP, DNS, DNSQR, DNSRR,
    wrpcap,
)

packets = []

# DNS query + response: example.com -> 93.184.216.34
dns_query = (
    Ether(src="aa:bb:cc:dd:ee:01", dst="aa:bb:cc:dd:ee:02")
    / IP(src="192.168.1.10", dst="8.8.8.8")
    / UDP(sport=12345, dport=53)
    / DNS(
        rd=1,
        qd=DNSQR(qname="example.com"),
    )
)
packets.append(dns_query)

dns_response = (
    Ether(src="aa:bb:cc:dd:ee:02", dst="aa:bb:cc:dd:ee:01")
    / IP(src="8.8.8.8", dst="192.168.1.10")
    / UDP(sport=53, dport=12345)
    / DNS(
        aa=1,
        qd=DNSQR(qname="example.com"),
        an=DNSRR(rrname="example.com", rdata="93.184.216.34"),
    )
)
packets.append(dns_response)

# TCP SYN to example.com
tcp_syn = (
    Ether(src="aa:bb:cc:dd:ee:01", dst="aa:bb:cc:dd:ee:02")
    / IP(src="192.168.1.10", dst="93.184.216.34")
    / TCP(sport=54321, dport=80, flags="S")
)
packets.append(tcp_syn)

# TCP SYN-ACK
tcp_synack = (
    Ether(src="aa:bb:cc:dd:ee:02", dst="aa:bb:cc:dd:ee:01")
    / IP(src="93.184.216.34", dst="192.168.1.10")
    / TCP(sport=80, dport=54321, flags="SA")
)
packets.append(tcp_synack)

# TCP ACK
tcp_ack = (
    Ether(src="aa:bb:cc:dd:ee:01", dst="aa:bb:cc:dd:ee:02")
    / IP(src="192.168.1.10", dst="93.184.216.34")
    / TCP(sport=54321, dport=80, flags="A")
)
packets.append(tcp_ack)

# A few more TCP data packets for flow aggregation
for i in range(3):
    data_pkt = (
        Ether(src="aa:bb:cc:dd:ee:01", dst="aa:bb:cc:dd:ee:02")
        / IP(src="192.168.1.10", dst="93.184.216.34")
        / TCP(sport=54321, dport=80, flags="A")
        / (b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
    )
    packets.append(data_pkt)

wrpcap("tests/fixtures/sample.pcap", packets)
print(f"wrote {len(packets)} packets to tests/fixtures/sample.pcap")
