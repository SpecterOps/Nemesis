# Standard Libraries
import tempfile
import uuid
from abc import ABC, abstractmethod
from types import TracebackType
from typing import Optional, Type


class StorageInterface(ABC):
    @abstractmethod
    async def download(self, file_name: uuid.UUID, delete: bool = True) -> tempfile._TemporaryFileWrapper:
        raise NotImplementedError

    @abstractmethod
    async def upload(self, file_path: str) -> uuid.UUID:
        raise NotImplementedError

    @abstractmethod
    async def exists(self, file_name: str) -> bool:
        raise NotImplementedError

    @abstractmethod
    async def delete_all_files(self) -> bool:
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
