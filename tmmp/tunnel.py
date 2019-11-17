from asyncio import get_event_loop, wait_for, AbstractEventLoop, Lock, TimeoutError
from typing import Collection

from .aiosock.abc import AbstractAioSocket
from .protocols.application.abc import ApplicationProtocol


class Tunnel:
    active: bool
    protocols: Collection[ApplicationProtocol]
    maximum_protocol_depth = 1
    protocol_depth = 0
    client_active: bool = True
    server_active: bool = True

    def __init__(self, client: AbstractAioSocket, server: AbstractAioSocket,
                 protocols: Collection[ApplicationProtocol] = (), loop: AbstractAioSocket = None):
        self.client = client
        self.server = server

        self.client_to_server = Lock()
        self.server_to_client = Lock()

        self.active = True
        self.protocols = protocols

        self.loop = loop
        if loop is None:
            self.loop = get_event_loop()

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
                            async with self.server_to_client:  # Avoid communication
                                self.client, self.server = await protocol.wrap_connection(
                                    data, self.client, self.server, self.loop)
                            self.protocol_depth += 1
                            do_not_send = True
                            break
                    if do_not_send:
                        continue

                if self.protocol_depth and data:
                    print("↑ ", data)

                if data:
                    # self.client_active = True
                    await self.server.sendall(data)

                    if self.protocol_depth and data:
                        print("↑ ✓")
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
                if self.protocol_depth and data:
                    # print("↓", data)
                    ...

                if data:
                    await self.client.sendall(data)
                    if self.protocol_depth and data:
                        print("↓ ✓")
                else:
                    self.active = False

        self.server.get_real_socket().close()
