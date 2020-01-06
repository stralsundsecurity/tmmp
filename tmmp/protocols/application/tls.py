from asyncio import AbstractEventLoop
from ssl import SSLContext, PROTOCOL_SSLv23, OP_NO_SSLv3, \
    _create_unverified_context
from struct import unpack
from typing import Tuple

from .abc import ApplicationProtocol
from ...aiosock.abc import AbstractAioSocket
from ...aiosock.tls import AioTlsSocket
from ...configuration import Configurable, Provider
from ...certificate.abc import CertificateManager
from ...util.tls.sni import get_sni_from_handshake


class TlsProtocol(ApplicationProtocol, Configurable):
    certificate_manager: CertificateManager

    def __init__(self, configuration, providers):
        # Only for Pycharm linter
        Configurable.__init__(self, configuration, providers)

        self.ciphers = configuration.get(

            "tls", {}).get("ciphers", "ALL")
        self.certificate_manager = \
            providers[Provider.CERTIFICATE_MANAGER]

    @staticmethod
    def get_protocol_name() -> str:
        return "TLS"

    @staticmethod
    def is_protocol_packet(packet: bytes) -> bool:
        if len(packet) < 50:  # TODO: Find better value.
            return False

        return all((
            packet[0] == 0x16,
            packet[1] == 3,
            packet[2] in (0, 1, 2, 3),  # SSL 3.0 to 1.3 (theoretically)
            len(packet)-5 == unpack("!H", packet[3:5])[0]
        ))

    async def wrap_connection(self,
                              packet: bytes,
                              up: AbstractAioSocket,
                              down: AbstractAioSocket,
                              loop: AbstractEventLoop) -> \
            Tuple[AbstractAioSocket, AbstractAioSocket]:
        print("Wrapping connection...")
        # TODO: What to do, if sni returns 'None'?
        sni = get_sni_from_handshake(packet)

        print("Wrapping Server")
        new_down: AbstractAioSocket = AioTlsSocket(
            down, _create_unverified_context(PROTOCOL_SSLv23),
            server_hostname=sni, loop=loop
        )
        await new_down.handshake()

        certificate_file = self.certificate_manager.get_certificate(sni)
        ctx = SSLContext(PROTOCOL_SSLv23)
        ctx.set_ciphers(self.ciphers)
        ctx.load_cert_chain(certificate_file, certificate_file,
                            self.certificate_manager.get_certificate_password())
        print("Wrapping Client")
        new_up = AioTlsSocket(up, ctx, True, loop=loop)
        new_up.push_data(packet)
        await new_up.handshake()
        print("Done")

        return new_up, new_down
