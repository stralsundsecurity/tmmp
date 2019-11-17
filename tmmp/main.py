"""
Module containing the interactive script.
"""
import asyncio
import socket

from .aiosock import AioSocket
from .configuration import Configuration, Provider
from .certificate import SelfSignedCertificateManager
from .protocols.application import TlsProtocol
from .tunnel import Tunnel
from tmmp.protocols.proxy import ProxyABC, EMPTY_RESPONSE, HttpConnectProxy, SocksProxy

config = Configuration()
config.providers[Provider.CERTIFICATE_MANAGER] = SelfSignedCertificateManager(config)
config.application_protocols.append(TlsProtocol(config))


async def mainloop(sock):
    loop = asyncio.get_event_loop()
    while True:
        connection, _ = await loop.sock_accept(sock)

        loop.create_task(do_proxy_stuff(loop, connection))


async def do_proxy_stuff(loop, connection):
    proxy: ProxyABC = SocksProxy.new({}, loop)

    _, remote = await proxy.proxy_handshake(connection)
    if remote == EMPTY_RESPONSE:
        return

    tunnel = Tunnel(AioSocket(connection), AioSocket(remote),
                    protocols=config.application_protocols, loop=loop)
    tunnel.schedule()


async def transfer(loop, socka, sockb):
    while True:
        data = await loop.sock_recv(sockb, 1024)
        try:
            print(sockb.getpeername()[0], "->", socka.getpeername()[0], len(data))
        except OSError:
            return

        if not data:
            return

        await loop.sock_sendall(
            socka, data
        )


def main():
    s = socket.socket(socket.AF_INET6)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(('::', 1234))
    s.listen(1024)
    s.setblocking(False)

    loop = asyncio.get_event_loop()
    loop.run_until_complete(mainloop(s))

