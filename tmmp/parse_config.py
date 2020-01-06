from os import PathLike
from typing import Any, Iterable, MutableMapping, Tuple, Type, TypeVar, Union

import toml

from .certificate import CertificateManager
from .configuration import Configurable, Provider
from .protocols.proxy import ProxyProtocol
from .protocols.application import ApplicationProtocol

T = TypeVar("T")

CLASSES = {
    "tls": "tmmp.protocols.application:TlsProtocol",
    "http": "tmmp.protocols.proxy:HttpConnectProxy",
    "simple": "tmmp.protocols.proxy:SimpleProxy",
    "socks": "tmmp.protocols.proxy:SocksProxy",
    "selfsigned": "tmmp.certificate:SelfSignedCertificateManager"
}


def get_class_by_name(path: str) -> type:
    """Returns a class from a string like module.sub:classname."""
    if path in CLASSES.keys():
        return get_class_by_name(CLASSES[path])

    module, classname = path.split(":")
    imported = __import__(module)

    for submod in module.split(".")[1:]:
        imported = getattr(imported, submod)

    return getattr(imported, classname)


def parse_config(filename: Union[str, PathLike]) -> \
        Tuple[MutableMapping[str, Any], MutableMapping[Provider, Any]]:
    """Parses a config and returns parsed and loaded protocol classes."""
    with open(filename, encoding='utf-8') as conf_file:
        configuration: MutableMapping[str, Any] = toml.load(conf_file)

    providers: MutableMapping[Provider, Any] = dict()
    providers[Provider.CERTIFICATE_MANAGER] = _init_class_by_name_and_config(
        configuration.get("providers", {}).get(
            "certificates", "selfsigned"),
        configuration,
        providers,
        CertificateManager
    )

    providers[Provider.APPLICATION_PROTOCOLS] = [
        p for p in _get_protocol_classes(
            configuration.get("application", {}),
            configuration,
            providers,
            ApplicationProtocol,
        )
    ]

    providers[Provider.PROXY_PROTOCOL] = get_class_by_name(
        configuration.get("proxy", {}).get("protocol", "http")
    )

    return configuration, providers


def _get_protocol_classes(configpart: MutableMapping,
                          configobj: MutableMapping[str, Any],
                          providers: MutableMapping[Provider, Any],
                          classcheck: Type[T]) -> Iterable[T]:
    for protocol in configpart.get('protocols', ()):
        yield _init_class_by_name_and_config(
            protocol,
            configobj,
            providers,
            classcheck
        )


def _init_class_by_name_and_config(
        classname: str,
        configobj: MutableMapping[str, Any],
        providers: MutableMapping[Provider, Any],
        classcheck: Type[T]) -> T:
    class_ = get_class_by_name(classname)

    if not issubclass(class_, classcheck):
        raise TypeError(f"Class {class_} is not subclassed "
                        f"from {classcheck}")

    if issubclass(class_, Configurable):
        return class_(configobj, providers)
    else:
        return class_()
