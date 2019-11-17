import asyncio
from socket import socket
from typing import Tuple

from .abc import AbstractAioSocket


class AioSocket(AbstractAioSocket):
    connected = False

    def __init__(self, sock: socket = None, *args, loop: asyncio.AbstractEventLoop = None, **kwargs):
        if sock is None:
            self.sock: socket = socket(*args, **kwargs)
        else:
            self.sock: socket = sock
        self.sock.setblocking(False)

        if loop is None:
            self.loop = asyncio.get_event_loop()
        else:
            self.loop = loop

    async def connect(self, address: Tuple[str, int]):
        if self.connected:
            raise ValueError("Connect cannot be called twice.")

        # The annotation should be Tuple[str, int], but is incorrectly str.
        await self.loop.sock_connect(self.sock, address)

    async def handshake(self) -> None:
        """
        NOOP for simple sockets.

        :return: None.
        """
        pass

    async def recv(self, amount: int) -> bytes:
        """
        Receive date.

        :param amount: Count of bytes to receive.
        :return: The received data.
        """
        return await self.loop.sock_recv(self.sock, amount)

    async def sendall(self, data: bytes) -> None:
        """
        Send data. Guarantees all data is really sent.

        :param data: The Date to send.
        :return: None.
        """
        return await self.loop.sock_sendall(self.sock, data)

    def get_real_socket(self) -> socket:
        return self.sock

