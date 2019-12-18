import asyncio
import functools
import socket
import ssl

from typing import Tuple

from tmmp.aiosock.abc import AbstractAioSocket
from tmmp.util.tls.masterkey import get_ssl_master_key


class AioTlsSocket(AbstractAioSocket):
    """
    Low-level TLS socket for AsyncIO.

    As the great 'asyncio' library only provides a fairly high level TLS interface,
    this Implementation allows a low level way which allows to pre-read packet data,
    before passing them to OpenSSL.
    """
    internal_blocksize = 1024

    def __init__(self,
                 abstract_socket: AbstractAioSocket,
                 context: ssl.SSLContext = ssl.create_default_context(),
                 server_side: bool = False,
                 server_hostname: str = None,
                 loop: asyncio.AbstractEventLoop = None):

        self.incoming = ssl.MemoryBIO()
        self.outgoing = ssl.MemoryBIO()

        self.client_random = None
        self.master_secret = None

        self.abstract_socket = abstract_socket
        self.server_side = server_side

        self.tls: ssl.SSLObject = context.wrap_bio(self.incoming, self.outgoing, server_side, server_hostname)

        self.wrapped = False

        if loop is None:
            self.loop: asyncio.AbstractEventLoop = asyncio.get_event_loop()
        else:
            self.loop: asyncio.AbstractEventLoop = loop

    async def connect(self, address: Tuple[str, int]):
        await self.abstract_socket.connect(address)
        await self.handshake()

    async def handshake(self):
        """Does the TLS handshake.

        Bidirectional calls will occur."""
        if not self.wrapped:
            await self._communicate(self.tls.do_handshake)
            self.client_random, self.master_secret = get_ssl_master_key(self.tls)

            self.wrapped = True

    async def _communicate(self, action):
        """Does the desired action until SSLWant*Error won't occur anymore.

        If they do, self._send() and self._recv() will be called.
        """
        # print(action, self.server_side)
        while True:

            try:
                return action()
            except ssl.SSLWantReadError:
                # May indicate data hasn't been transferred to the server yet.
                await self._send()
                await self._recv()
            except ssl.SSLWantWriteError:
                # await self._recv()
                await self._send()

    async def _recv(self):
        data = await self.abstract_socket.recv(self.internal_blocksize)
        #if data:
        #if True:
        self.incoming.write(data)
        # return len(data)

    async def _send(self):
        data = self.outgoing.read()
        await self.abstract_socket.sendall(data)

    def push_data(self, data):
        """Injects data into the internal read buffer."""
        self.incoming.write(data)

    async def close(self) -> AbstractAioSocket:
        await self._communicate(self.tls.unwrap)
        return self.abstract_socket

    async def recv(self, size):
        if not self.wrapped:
            await self.handshake()

        # if not await self._recv():
        #     return b''
        return await self._communicate(functools.partial(self.tls.read, size))

    async def sendall(self, data):
        if not self.wrapped:
            await self.handshake()

        # print(data)
        await self._communicate(functools.partial(self.tls.write, data))
        await self._send()

    def get_real_socket(self) -> socket:
        return self.abstract_socket.get_real_socket()
