"""
Module containing the interactive script.
"""
import asyncio
import socket
import sys

from typing import List

from .aiosock import AioSocket
from .configuration import Configuration, Provider
from .certificate import SelfSignedCertificateManager
from .protocols.application import TlsProtocol
from .protocols.proxy import ProxyABC, EMPTY_RESPONSE, HttpConnectProxy, SocksProxy
from .tunnel import Tunnel

config = Configuration()
config.providers[Provider.CERTIFICATE_MANAGER] = SelfSignedCertificateManager(config)
config.application_protocols.append(TlsProtocol(config))


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


def command_line(argv: List[str] = sys.argv) -> Configuration:
    if len(argv) != 2 or argv[1].startswith("-"):
        print(USAGE.format(name=argv[0]))
        sys.exit(-1)

    if argv[1].lower() in ("-h", "--help"):
        print(HELP)
        sys.exit(0)
    elif argv[1].lower() in ("-e", "--example"):
        print(EXAMPLE)
        sys.exit(0)

    return Configuration.parse(sys.argv[1])


async def mainloop(sock):
    loop = asyncio.get_event_loop()
    while True:
        connection, _ = await loop.sock_accept(sock)

        loop.create_task(do_proxy_stuff(loop, connection))


async def do_proxy_stuff(loop, connection):
    proxy: ProxyABC = SocksProxy.new({}, loop)

    _, remote = await proxy.proxy_handshake(connection)
    if remote == EMPTY_RESPONSE:
        return

    tunnel = Tunnel(AioSocket(connection), AioSocket(remote),
                    protocols=config.application_protocols, loop=loop)
    tunnel.schedule()


async def transfer(loop, socka, sockb):
    while True:
        data = await loop.sock_recv(sockb, 1024)
        try:
            print(sockb.getpeername()[0], "->", socka.getpeername()[0], len(data))
        except OSError:
            return

        if not data:
            return

        await loop.sock_sendall(
            socka, data
        )


def main():
    conf = command_line()
    provider_conf = conf.configuration.get("providers", {})
    if provider_conf.get("certificates", "selfsigned") == "selfsigned":
        conf.providers[Provider.CERTIFICATE_MANAGER] = SelfSignedCertificateManager(conf)
    else:
        raise NotImplementedError(
            f"Certificate provider not implemented: {provider_conf['certificates']}")

    s = socket.socket(socket.AF_INET6)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(('::', 1234))
    s.listen(1024)
    s.setblocking(False)

    loop = asyncio.get_event_loop()
    loop.run_until_complete(mainloop(s))

