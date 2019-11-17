"""
Utility module to parse and manipulate TLS packets.
"""

from io import BytesIO
from struct import unpack
from typing import Union


def get_sni_from_handshake(packet: bytes) -> Union[str, None]:
    """Get the SNI from a handshake packet."""
    packet = BytesIO(packet)

    if packet.read(1) != bytes([22]):
        raise AssertionError("Packet is not a Handshake message.")

    outer_version = packet.read(2)
    if outer_version[0] == 2:  # == SSL 2.0 packet (no SNI support)
        return None

    packet.read(2)  # Total TLS packet length

    if packet.read(1) != bytes([1]):
        raise AssertionError("Packet is not a Client Hello.")

    packet.read(3)  # Client Hello Length

    version = packet.read(2)
    if version[0] != 3:  # == SSL 2.0
        return None

    packet.read(32)  # Client Random
    session_id_length = packet.read(1)[0]
    if session_id_length:
        packet.read(session_id_length)  # Session id

    cipher_length = unpack("!H", packet.read(2))[0]
    packet.read(cipher_length)  # Cipher Suites

    compression_length = packet.read(1)[0]
    packet.read(compression_length)  # Compression methods (most times only null)

    # print(binascii.hexlify(packet.read(16)))

    extension_length = unpack("!H", packet.read(2))[0]
    return get_sni_from_extensions(packet.read(extension_length))


def get_sni_from_extensions(extensions: bytes) -> Union[str, None]:
    """Get the SNI from the extension data of a TLS packet."""
    extensions = BytesIO(extensions)
    while True:
        type_bytes = extensions.read(2)

        if not type_bytes:  # End of buffer
            return None

        extension_type = unpack("!H", type_bytes)[0]
        extension_length = unpack("!H", extensions.read(2))[0]
        extension = extensions.read(extension_length)

        if extension_type != 0:  # server_name == 0
            continue

        if extension[2] != 0:  # host_name == 0
            continue

        return extension[5:].decode()
