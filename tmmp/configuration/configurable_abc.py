from abc import abstractmethod, ABC

from .configuration import Configuration


class Configurable(ABC):
    @abstractmethod
    def __init__(self, configuration: Configuration):
        ...
