# Standard Libraries
import os
import uuid
from types import TracebackType
from typing import Optional, Type


class TempFile:
    path: str
    name: uuid.UUID

    def __init__(self, data_dir: str = "/tmp") -> None:
        # generate a random file name in the supplied data directory
        self.name = uuid.uuid4()
        self.path = f"{data_dir}/{self.name}"

    async def __aenter__(self):
        return self

    async def __aexit__(
        self,
        exc_type: Optional[Type[BaseException]],
        exc_val: Optional[BaseException],
        exc_tb: Optional[TracebackType],
    ) -> None:
        # remove the temp file if it exists
        if os.path.exists(self.path):
            os.remove(self.path)
