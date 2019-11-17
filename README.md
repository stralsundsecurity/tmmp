# TLS MitM Proxy (TMMP)

This is a TLS proxy with MitM capabilities.

Currently support proxy protocols are:
 * Raw (statically configured upstream address)
 * SOCKS4/4a/5
 * HTTP-CONNECT
 
At this time, this proxy is statically configured to generate self-signed certificates
"on-the-fly" and listens on port 1234 on all network interfaces.

IPv6 is supported.

At least 50 Mbps can be proxied.

It can be run with `python3 -m tmmp`. The module "cryptography" is required.

## Architecture

There are a few abstractions layers defined in this project:

- "aiosock": Low-level socket-like interfaces, but all methods are awaitable.
Each protocol (only TLS to this date) has an own implementation. 
- "protocols.proxy": Proxy protocol implementations (HTTP-CONNECT, SOCKS, etc.)
- "protocols.application": Thos indicicate when to switch the underlying "aiosock" to a different one.

The main "entrypoint" in in "main.py", the logic of each connection is in "tunnel.py".

## Future features

- Configurable (TOML configuration file)
- Use a CA certificate to generate certificates.
- Make the issuer name configurable (currently static to "TLS Breaker Proxy").
- Better logging
- Actually catch exceptions in coroutines (currently coroutines are canceled)