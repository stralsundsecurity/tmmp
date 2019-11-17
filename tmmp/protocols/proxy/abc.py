from abc import ABC, abstractmethod
from asyncio import AbstractEventLoop
from socket import socket
from typing import Any, Mapping, Tuple


class ProxyABC(ABC):
    @staticmethod
    @abstractmethod
    def new(configuration: Mapping[str, Any], loop: AbstractEventLoop) \
            -> "ProxyABC":
        """Creates a new proxy."""
        raise NotImplementedError("This is an empty abstract method.")

    @abstractmethod
    async def proxy_handshake(self, connection: socket) \
            -> Tuple[Tuple[str, int], socket]:
        """Handle an accepted connection and do the proxy protocol.

        This method returns the upstream (hostname, port)-tuple and
        the upstream connection.
        """
        raise NotImplementedError("This is an empty abstract method.")
