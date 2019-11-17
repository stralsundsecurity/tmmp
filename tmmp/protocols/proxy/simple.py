from asyncio import AbstractEventLoop
from socket import socket, AF_INET, AF_INET6, IPPROTO_TCP
from typing import Any, Mapping, Tuple

from .abc import ProxyABC
from tmmp.util.ip import is_ipv4, is_ipv6


class SimpleProxy(ProxyABC):
    def __init__(self, remote: Tuple[str, int], loop: AbstractEventLoop):
        self.remote = remote
        self.loop = loop

    @staticmethod
    def new(configuration: Mapping[str, Any], loop: AbstractEventLoop) \
            -> ProxyABC:
        """Creates a new simple proxy."""
        return SimpleProxy(configuration["remote"], loop)

    async def proxy_handshake(self, connection: socket) \
            -> Tuple[Tuple[str, int], socket]:
        """Handle an accepted connection."""
        if is_ipv4(self.remote[0]):
            s = socket(AF_INET)
            remote = self.remote
        elif is_ipv6(self.remote[0]):
            s = socket(AF_INET6)
            remote = self.remote
        else:
            info = (await self.loop.getaddrinfo(*self.remote, proto=IPPROTO_TCP))[0]
            s = socket(*info[:2])
            remote = info[-1][:2]

        s.setblocking(False)
        await self.loop.sock_connect(s, remote)

        return self.remote, s
