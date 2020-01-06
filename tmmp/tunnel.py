from asyncio import get_event_loop, sleep, wait_for, AbstractEventLoop, Lock, \
    TimeoutError
from io import BytesIO
from pathlib import Path
from time import time
from typing import Collection

from .aiosock.abc import AbstractAioSocket
from .defaults import PCAP_PATH
from .pcap import PacketWriter
from .protocols.application.abc import ApplicationProtocol

from scapy.all import PcapWriter


class Tunnel:
    active: bool
    protocols: Collection[ApplicationProtocol]
    maximum_protocol_depth = 1
    protocol_depth = 0
    client_active: bool = True
    server_active: bool = True
    writer: PacketWriter
    pcap_filename: Path

    def __init__(self, client: AbstractAioSocket, server: AbstractAioSocket,
                 protocols: Collection[ApplicationProtocol] = (),
                 loop: AbstractEventLoop = None, write_to: PcapWriter = None):

        self.client = client
        self.server = server

        self.client_to_server = Lock()
        self.server_to_client = Lock()

        self.active = True
        self.protocols = protocols

        self.loop = loop
        if loop is None:
            self.loop = get_event_loop()

        server_info = Tunnel.ip_to_ipv6(
            server.get_real_socket().getpeername()[0]
        ), server.get_real_socket().getpeername()[1]
        client_info = Tunnel.ip_to_ipv6(
            client.get_real_socket().getpeername()[0]
        ), client.get_real_socket().getpeername()[1]

        if write_to is None:
            write_to = PcapWriter(BytesIO())

        self.writer = PacketWriter(
            client_info,
            server_info,
            write_to
        )

    def schedule(self):
        self.loop.create_task(self.communicate_client_to_server())
        self.loop.create_task(self.communicate_server_to_client())

    async def communicate_client_to_server(self):
        while self.active:
            async with self.client_to_server:
                try:
                    # Wait 20ms for packet
                    data = await wait_for(self.client.recv(9000), .02)
                except TimeoutError:  # Can happen
                    continue
                except:  # TODO: Be more specific
                    self.active = False
                    raise

                # print("C:", data)

                # Todo: Uhm... make it better.
                do_not_send = False
                if self.protocol_depth < self.maximum_protocol_depth:

                    for protocol in self.protocols:
                        if protocol.is_protocol_packet(data):
                            # Avoid any communication
                            try:
                                async with self.server_to_client:
                                    self.client, self.server = \
                                        await protocol.wrap_connection(
                                            data,
                                            self.client,
                                            self.server,
                                            self.loop
                                        )
                            except Exception:  # Todo...
                                self.active = False
                                raise

                            self.protocol_depth += 1
                            do_not_send = True
                            break
                    if do_not_send:
                        continue

                if data:
                    # self.client_active = True
                    await self.server.sendall(data)
                    self.writer.server(data)

                else:
                    self.active = False

        self.client.get_real_socket().close()

    async def communicate_server_to_client(self):
        while self.active:
            async with self.server_to_client:
                try:
                    # Wait 20ms for transmission
                    # (this means the lock will be released at least every 20ms)
                    data = await wait_for(self.server.recv(9000), .02)
                except TimeoutError:  # Can happen
                    continue
                except:  # TODO: Be more specific
                    self.active = False
                    raise

                if data:
                    await self.client.sendall(data)
                    self.writer.client(data)

                else:
                    self.active = False

        self.server.get_real_socket().close()


    @staticmethod
    def new_pcap_name(source: str, dest: str) -> Path:
        rel_name = (
            f"{str(time()).replace('.', '-')}"
            f" "
            f"{source.replace(':','-')}"
            f" "
            f"{dest.replace(':','-')}"
            f".pcap"
        )

        return Path(PCAP_PATH).joinpath(rel_name)

    @staticmethod
    def ip_to_ipv6(ip: str) -> str:
        if ":" not in ip:
            return "::ffff:"+ip
        return ip
