
from abc import abstractmethod, ABC
from socket import socket
from typing import Tuple, Union


class AbstractAioSocket(ABC):
    @abstractmethod
    async def connect(self, address: Tuple[str, int]):
        """Connect to the given address."""
        ...

    @abstractmethod
    async def handshake(self) -> None:
        """
        Perform any handshake if needed. Can be a no-op for less complicated protocols.
        :return: None.
        """
        ...

    @abstractmethod
    async def recv(self, nbytes: int) -> bytes:
        """
        Receive date.

        :param nbytes: Maximum amount of bytes to receive in a single call.
        :return: The received data.
        """
        ...

    @abstractmethod
    async def sendall(self, data: bytes) -> None:
        """
        Send data. Guarantees all data is really sent.

        :param data: The Date to send.
        :return: None.
        """
        ...

    @abstractmethod
    def get_real_socket(self) -> socket:
        """
        :return: Get the underlying (real) socket or None.
        """
        ...

