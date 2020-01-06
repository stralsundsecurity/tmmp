from enum import Enum


class Provider(str, Enum):
    CERTIFICATE_MANAGER = "cert_manager"
    APPLICATION_PROTOCOLS = "application_protocols"
    PROXY_PROTOCOL = "proxy_protocol"
