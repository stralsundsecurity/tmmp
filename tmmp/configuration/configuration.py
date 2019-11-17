from typing import Any, List, MutableMapping

from .providers import Provider

class Configuration:
    """Provides the TLS proxy configuraiton."""
    configuration: MutableMapping[str, MutableMapping[str, Any]]
    providers: MutableMapping[Provider, Any]
    application_protocols: List

    def __init__(self):
        self.configuration = {}
        self.providers = {}
        self.application_protocols = []