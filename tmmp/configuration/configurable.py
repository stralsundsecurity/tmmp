from abc import abstractmethod, ABC
from typing import Any, MutableMapping, TypeVar

from .providers import Provider



class Configurable(ABC):
    """Baseclass to tell if something expects a parsed configuration"""
    @abstractmethod
    def __init__(self, configuration: MutableMapping[str, Any],
                 providers: MutableMapping[Provider, Any]):
        ...
