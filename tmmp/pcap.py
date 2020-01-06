"""
Helper to write captured data to a pcap as a TCP stream.

The TCP sequence numbers will not be the real ones and are randomly chosen
for each stream.
"""

from io import BytesIO
from random import randint
from typing import Iterable, Tuple

from scapy.all import PcapWriter
from scapy.layers.l2 import Ether
from scapy.layers.inet6 import IPv6, TCP


class PacketWriter:
    client_ip_base: IPv6
    server_ip_base: IPv6

    client_seq: int
    server_seq: int

    client_port: int
    server_port: int

    out: PcapWriter

    tcp_handshake: bool

    def __init__(self,
                 client: Tuple[str, int],
                 server: Tuple[str, int],
                 out_writer: PcapWriter):

        self.client_ip_base = IPv6()
        self.client_ip_base.src = client[0]
        self.client_ip_base.dst = server[0]

        self.server_ip_base = IPv6()
        self.server_ip_base.src = server[0]
        self.server_ip_base.dst = client[0]

        self.out = out_writer

        self.client_port = client[1]
        self.server_port = server[1]

        self.client_seq = randint(1, 2 ** 32 - 1)
        self.server_seq = randint(1, 2 ** 32 - 1)

        self.tcp_handshake = False

    def write_handshake(self):
        self.tcp_handshake = True

        self.write_packets((
            self.client_ip_base / TCP(
                sport=self.client_port,
                dport=self.server_port,
                seq=self.client_seq-1,
                flags="S"
            ),
            self.server_ip_base / TCP(
                sport=self.server_port,
                dport=self.client_port,
                seq=self.server_seq-1,
                ack=self.client_seq,
                flags="SA"
            ),
            self.client_ip_base / TCP(
                sport=self.client_port,
                dport=self.server_port,
                seq=self.client_seq,
                ack=self.server_seq,
                flags="A"
            )
        ))

    def server(self, data: bytes):
        if not self.tcp_handshake:
            self.write_handshake()

        seq = self.server_seq
        self.server_seq = (seq + len(data)) & 0xff_ff_ff_ff

        self.write_packets((
            self.server_ip_base / TCP(
                 sport=self.server_port,
                 dport=self.client_port,
                 seq=seq,
                 ack=self.client_seq,
                 flags="A") / data,
            self.client_ip_base / TCP (
                sport=self.client_port,
                dport=self.server_port,
                seq=self.client_seq,
                ack=self.server_seq,
                flags="A"
            )
        ))

    def client(self, data: bytes):
        if not self.tcp_handshake:
            self.write_handshake()

        seq = self.client_seq
        self.client_seq = (seq + len(data)) & 0xff_ff_ff_ff

        self.write_packets((
            self.client_ip_base / TCP(
                sport=self.client_port,
                dport=self.server_port,
                seq=seq,
                ack=self.server_seq,
                flags="A") / data,
            self.server_ip_base / TCP(
                sport=self.server_port,
                dport=self.client_port,
                seq=self.server_seq,
                ack=self.client_seq,
                flags="A"
            )
        ))

    def write_packet(self, packet: IPv6):
        self.write_packets((packet,))

    def write_packets(self, packets: Iterable[IPv6]):
        self.out.write(map(lambda p: Ether() / p, packets))


if __name__ == "__main__":
    p = PacketWriter(("2a0d:5940:1:91::2", 1337),
                     ("2a00:1450:4005:80b::2003", 80))
    p.client(
        b"GET / HTTP/1.0\r\n"
        b"Connection: close\r\n"
        b"Host: google.com\r\n"
        b"\r\n"
    )
    p.server(
        b"HTTP/1.0 302 Found\r\n"
        b"Location: https://www.google.com/\r\n"
        b"\r\n"
    )

