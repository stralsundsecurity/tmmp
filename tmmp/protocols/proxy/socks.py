from asyncio import AbstractEventLoop
from io import BytesIO
from ipaddress import ip_address
from socket import socket, AF_INET, AF_INET6, IPPROTO_TCP
from struct import pack, unpack
from typing import Any, Mapping, Tuple

from ._empty import EMPTY_RESPONSE
from .abc import ProxyProtocol


SOCKS4_SUCCESS = b"\x5a"
SOCKS4_REJECT = b"\x5b"
# 2 + 4 arbitrary bytes (they could be everything).
SOCKS4_PADDING = 2 * b"\x00" + 4 * b"\xff"

SOCKS5_SUCCESS = b"\x00"
SOCKS5_EREJECT = b"\x01"
SOCKS5_ERULES = b"\x02"
SOCKS5_EPROTOCOL = b"\x07"

SOCKS5_PADDING = b"\x00" + b"\x01" + 4*b"\xff" + 2*b"\xff"


class SocksProxy(ProxyProtocol):
    def __init__(self,loop: AbstractEventLoop):
        self.loop = loop

    @staticmethod
    def new(configuration: Mapping[str, Any], loop: AbstractEventLoop) \
            -> ProxyProtocol:
        """Creates a new SOCKS4/4a/5 proxy."""
        return SocksProxy(loop)

    async def proxy_handshake(self, connection: socket) \
            -> Tuple[Tuple[str, int], socket]:
        """Handle an accepted connection. """
        packet = await self.loop.sock_recv(connection, 1024)
        socks_ver = packet[0]
        if socks_ver == 4:
            command = packet[1]

            if command != 0x01:  # 0x01 == TCP client
                await self.loop.sock_sendall(connection, b"\x00" + SOCKS4_REJECT + SOCKS4_PADDING)
                return EMPTY_RESPONSE

            port = unpack("!H", packet[2:4])[0]
            ip = str(ip_address(packet[4:8]))

            end_of_uid = packet.index(b"\x00", 8)  # SOCKS4 has a user id

            if ip.startswith("0.0.0"):  # SOCKS4a with name resolution is used.
                domain_end = packet.index(b"\x00", end_of_uid+1)
                ip = packet[end_of_uid+1:domain_end].decode()

            s = socket()
            s.setblocking(False)

            # Note: Linters might detect a type mismatch in the next line.
            #       They complain about the second argument of sock_connect.
            #       In this case, they are wrong.
            #       The second argument is taking a (str, int)-tuple,
            #       and not a str!
            await self.loop.sock_connect(s, (ip, port))
            out_ip, out_port = s.getsockname()

            # Instead of padding send
            await self.loop.sock_sendall(
                connection,
                b"\x00" + SOCKS4_SUCCESS +
                pack("!H", out_port) + ip_address(out_ip).packed
            )

            return (ip, port), s

        elif socks_ver == 5:
            auth_methods_length = packet[1]

            # 0 = No authentication
            if b"\x00" not in packet[2:2+auth_methods_length]:
                await self.loop.sock_sendall(connection, b"\x05" + b"\xff")
                return EMPTY_RESPONSE

            # Return no authentication was selected
            await self.loop.sock_sendall(connection, b"\x05" + b"\x00")

            socks_packet = BytesIO(await self.loop.sock_recv(connection, 1024))
            if socks_packet.read(1) != b"\x05":  # Not SOCKS5
                await self.loop.sock_sendall(connection, b"\x05" + SOCKS5_EPROTOCOL + SOCKS5_EPROTOCOL)
                return EMPTY_RESPONSE

            command = socks_packet.read(1)
            if command in (b"\x03", b"\x04"):  # TCP server, UDP client
                await self.loop.sock_sendall(connection, b"\x05" + SOCKS5_ERULES + SOCKS5_EPROTOCOL)
                return EMPTY_RESPONSE

            socks_packet.read(1)  # Reserved byte
            address_type = socks_packet.read(1)

            if address_type == b"\x01":  # IPv4
                address = str(
                    ip_address(socks_packet.read(4))
                )
                socket_family = AF_INET
            elif address_type == b"\x03":  # DNS
                domain_size = socks_packet.read(1)[0]
                domain = socks_packet.read(domain_size).decode()
                info = (await self.loop.getaddrinfo(domain, 0, proto=IPPROTO_TCP))[0]
                address = info[-1][0]
                socket_family = info[0]

            elif address_type == b"\x04":  # IPv6
                address = str(ip_address(socks_packet.read(16)))
                socket_family = AF_INET6
            else:
                await self.loop.sock_sendall(connection, b"\x05" + SOCKS5_ERULES + SOCKS5_EPROTOCOL)
                return EMPTY_RESPONSE

            port = unpack("!H", socks_packet.read(2))[0]

            s = socket(socket_family)
            s.setblocking(False)

            # Linters can be wrong about the following line:
            await self.loop.sock_connect(s, (address, port))

            if socket_family == AF_INET6:
                out_ip, out_port, _, _ = s.getsockname()
            else:
                out_ip, out_port = s.getsockname()

            await self.loop.sock_sendall(
                connection,
                b"\x05" +
                SOCKS5_SUCCESS +
                b"\x00" +  # Reserved
                (b"\x01" if socket_family == AF_INET else b"\x04") +
                ip_address(out_ip).packed +
                pack("!H", out_port)
            )
            return (address, port), s

        else:
            # Socks response "request rejected or failed"
            await self.loop.sock_sendall(connection, b"\x00" + SOCKS4_REJECT + SOCKS4_PADDING)
            return EMPTY_RESPONSE
