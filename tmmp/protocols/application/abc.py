from abc import abstractmethod, ABC
from asyncio import AbstractEventLoop
from typing import Union, Tuple

from ...aiosock.socket import AbstractAioSocket


class ApplicationProtocol(ABC):
    """
    A protocol "wrapper" which wraps connections to a new protocol.

    To let the tunnel now, when to wrap a connection, there are
    methods to check if a protocol is a server or client packet.
    """
    @staticmethod
    @abstractmethod
    def get_protocol_name() -> str:
        raise NotImplementedError("This ABC does not implement any methods.")

    @staticmethod
    @abstractmethod
    def is_protocol_packet(packet: bytes) -> bool:
        raise NotImplementedError("This ABC does not implement any methods.")

    @abstractmethod
    async def wrap_connection(self, packet: bytes, up: AbstractAioSocket, down: AbstractAioSocket,
                              loop: AbstractEventLoop) -> \
            Tuple[AbstractAioSocket, AbstractAioSocket]:
        raise NotImplementedError("This ABC does not implement any methods.")
