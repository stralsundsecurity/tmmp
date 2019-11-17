import ipaddress


def is_ipv4(candidate: str) -> bool:
    try:
        ipaddress.IPv4Address(str)
    except ipaddress.AddressValueError:
        return False
    else:
        return True


def is_ipv6(candidate: str) -> bool:
    try:
        ipaddress.IPv6Address(str)
    except ipaddress.AddressValueError:
        return False
    else:
        return True
