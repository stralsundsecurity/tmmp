"""
Module containing the interactive script.
"""
import asyncio
import io
import socket
import sys
import time

from typing import List

from .aiosock import AioSocket
from .configuration import Provider
from .certificate import SelfSignedCertificateManager
from .parse_config import parse_config
from .protocols.application import TlsProtocol
from .protocols.proxy import ProxyProtocol, EMPTY_RESPONSE, SocksProxy
from .tunnel import Tunnel

from aiofile import AIOFile
from scapy.all import PcapWriter

USAGE = """\
usage: tmmp (--help | --example | config_file)
Try `tmmp --help' for more information."""

HELP = f"""
 --- TLS Man-in-the-Middle Proxy (TMMP) ---
{USAGE}

The proxy is configured with a configuration file in the TOML format
(similar to an INI file, see https://github.com/toml-lang/toml).

Get an example configuration with `tmmp --example'.

Configurable options are:

-- Section "server"
listen: IPv6(!) address where to listen on. To listen on \
IPv4, use ::ffff:ipv4 (default "::" = all interfaces dualstack).
port: Port to listen on (default 1234)

-- Section "proxy"
protocol: Which protocol to use (e.g. socks, http, simple; default "socks").
protocol_class: Alternatively describe python class to use in the form \
"module.sub:class".

Depending on the protocol (or class) chosen, it may require additional options.

-- Section "application"
max_depth: How many times protocols in protocols (e.g. TLS in TLS) is allowed \
(default 2).
protocols: List of application protocols by name (default ["tls"]).
protocols_class: List of application protocols (default not set).

-- Section "tls"
ciphers: Which ciphers to allow on the listening side \
(default "ALL", this is intentionally insecure).

-- Section "providers"
certificates: Values possible are "selfsigned" or "ca" (default "selfsigned").\
 If "ca" is used, "cacert" must be set.
selfsigned_cn: To what value the CN of the issue field should be set.

In the future, it will be possible to set server side verification and \
outgoing ciphers.
"""

EXAMPLE = """\
[server]
listen = "::"
port = 1234

[proxy]
protocol = "socks"
# protocol_class = "tmmp.protocols.proxy:SocksProxy"

[application]
protocols = [ "tls" ]
# protocols_class = [ "tmmp.protocols.application:TlsProtocol" ]

[tls]
ciphers = "ALL"

[providers]
certificates = "selfsigned"
"""


def command_line(argv: List[str] = sys.argv):
    if len(argv) != 2 or argv[1].startswith("-"):
        print(USAGE.format(name=argv[0]))
        sys.exit(-1)

    if argv[1].lower() in ("-h", "--help"):
        print(HELP)
        sys.exit(0)
    elif argv[1].lower() in ("-e", "--example"):
        print(EXAMPLE)
        sys.exit(0)

    return parse_config(sys.argv[1])


async def mainloop(sock, config, providers):
    loop = asyncio.get_event_loop()
    buffer = io.BytesIO()
    writer = PcapWriter(buffer, sync=True)

    loop.create_task(
        buffer_to_file(f"pcap/{int(time.time())}.pcap", buffer)
    )

    while True:
        connection, _ = await loop.sock_accept(sock)

        loop.create_task(
            do_proxy_stuff(loop, connection, config, providers, writer))


async def do_proxy_stuff(loop, connection, config, providers,
                         write_to: PcapWriter):
    proxy: ProxyProtocol = providers[Provider.PROXY_PROTOCOL].new({}, loop)

    _, remote = await proxy.proxy_handshake(connection)
    if remote == EMPTY_RESPONSE:
        return

    tunnel = Tunnel(AioSocket(connection), AioSocket(remote),
                    protocols=providers[Provider.APPLICATION_PROTOCOLS],
                    loop=loop, write_to=write_to)
    tunnel.schedule()


async def buffer_to_file(filename, buffer):
    """Writes the PCAP every .2 seconds to avoid synchronous writes."""
    file = None

    async with AIOFile(str(filename), 'ab') as pcap:
        while True:
            await asyncio.sleep(1)

            b = buffer.getvalue()
            buffer.truncate(0)
            buffer.seek(0)

            if not b:
                print("No data.")
                continue

            print(f"Has {len(b)} bytes.")

            await pcap.write(b)
            # await pcap.fsync()


def main():
    config, providers = command_line()

    s = socket.socket(socket.AF_INET6)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(('::', 1234))
    s.listen(1024)
    s.setblocking(False)

    loop = asyncio.get_event_loop()
    loop.run_until_complete(mainloop(s, config, providers))
