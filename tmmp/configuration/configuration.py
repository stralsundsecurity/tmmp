from pathlib import Path
from typing import Any, List, MutableMapping, Union

import toml

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

    @classmethod
    def parse(cls: 'Configuration', filename: Union[str, Path]):
        obj = Configuration()

        with open(filename, encoding='utf-8') as conf_file:
            obj.configuration = configuration = toml.load(conf_file)

        return obj
