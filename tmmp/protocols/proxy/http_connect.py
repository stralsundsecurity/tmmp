from asyncio import AbstractEventLoop
from socket import socket, IPPROTO_TCP
from typing import Any, Mapping, Tuple

from .abc import ProxyProtocol
from ._empty import EMPTY_RESPONSE


class HttpConnectProxy(ProxyProtocol):
    def __init__(self, loop: AbstractEventLoop):
        self.loop = loop

    @staticmethod
    def new(configuration: Mapping[str, Any], loop: AbstractEventLoop) \
            -> ProxyProtocol:
        """Creates a new simple proxy."""
        return HttpConnectProxy(loop)

    async def proxy_handshake(self, connection: socket) -> Tuple[Tuple[str, int], socket]:
        """Handle an accepted connection. """
        http_packet = await  self.loop.sock_recv(connection, 9000)

        connect_line = http_packet.splitlines(False)[0]
        verb, host, protocol = connect_line.split(b' ')

        if verb.upper() != b"CONNECT":
            await self.loop.sock_sendall(
                connection,
                b"HTTP/1.0 405 Invalid Request\r\n"
                b"Content-Type: text/plain; charset=us-ascii\r\n"
                b"Content-Length: 31\r\n"
                b"Connection: Close\r\n"
                b"\r\n"
                b"This proxy only allows CONNECT."
            )
            return EMPTY_RESPONSE

        host, port = host.split(b":")
        port = int(port)

        info = (await self.loop.getaddrinfo(host, 0, proto=IPPROTO_TCP))[0]
        address = info[-1][0]
        socket_family = info[0]

        s = socket(socket_family)
        s.setblocking(False)
        await self.loop.sock_connect(s, (address, port))
        await self.loop.sock_sendall(connection, b"HTTP/1.1 200 OK\r\n\r\n")
        return (host, port), s

