# Standard Libraries
import ntpath
import tempfile
import uuid
from tempfile import NamedTemporaryFile
from typing import Dict, List, NamedTuple

# 3rd Party Libraries
from nemesiscommon.storage import StorageInterface


class MemoryStorage(StorageInterface):
    def __init__(self, assessment_id: str = 'testing'):
        self._files: Dict[str, bytes] = {}
        self.assessment_id = assessment_id

    async def upload(self, file_path: str) -> uuid.UUID:
        new_file_uuid = uuid.uuid4()

        with open(file_path, 'rb') as f:
            self._files[str(new_file_uuid)] = f.read()

        return new_file_uuid

    async def upload_bytes_by_key(self, file_uuid: uuid.UUID, bytes: bytes) -> None:
        self._files[str(file_uuid)] = bytes

    async def download(self, file_name: uuid.UUID) -> tempfile._TemporaryFileWrapper:
        with NamedTemporaryFile(delete=False) as f:
            f.write(self._files[str(file_name)])
            f.seek(0)
            f.flush()
            return f

    async def exists(self, file_name: str) -> bool:
        return file_name in self._files

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        pass

class StorageNop(StorageInterface):
    async def upload(self, file_path: str) -> uuid.UUID:
        return uuid.UUID()

    async def download(self, file_name: uuid.UUID) -> tempfile._TemporaryFileWrapper:
        return NamedTemporaryFile()

    async def exists(self, file_name: str) -> bool:
        return True

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        pass