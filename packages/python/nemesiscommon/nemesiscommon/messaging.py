# Standard Libraries
from abc import ABC, abstractmethod
from types import TracebackType
from typing import Any, Callable, Coroutine, Optional, Type, TypeVar

# 3rd Party Libraries
import google.protobuf.message

T = TypeVar("T")


class MessageQueueProducerInterface(ABC):
    @abstractmethod
    async def Send(self, message: bytes) -> None:
        raise NotImplementedError

    @abstractmethod
    async def Close(self) -> None:
        raise NotImplementedError

    @abstractmethod
    async def __aenter__(self):
        raise NotImplementedError

    @abstractmethod
    async def __aexit__(
        self,
        exc_type: Optional[Type[BaseException]],
        exc_val: Optional[BaseException],
        exc_tb: Optional[TracebackType],
    ) -> None:
        raise NotImplementedError


class MessageQueueConsumerInterface(ABC):
    @abstractmethod
    async def Read(
        self,
        worker: Callable[[google.protobuf.message.Message], Coroutine[Any, Any, None]],
    ) -> None:
        raise NotImplementedError

    @abstractmethod
    async def Close(self) -> None:
        raise NotImplementedError

    @abstractmethod
    async def __aenter__(self):
        raise NotImplementedError

    @abstractmethod
    async def __aexit__(
        self,
        exc_type: Optional[Type[BaseException]],
        exc_val: Optional[BaseException],
        exc_tb: Optional[TracebackType],
    ) -> None:
        raise NotImplementedError
