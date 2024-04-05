# Standard Libraries
import logging
import os
from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from typing import Any, NewType, Optional
from uuid import UUID
import aiofiles

# 3rd Party Libraries
import httpx
from pydantic import PositiveInt

logger = logging.getLogger("NemesisConnector")


NemesisFileId = NewType("NemesisFileId", UUID)
NemesisMessageId = NewType("NemesisMessageId", UUID)


@dataclass
class FileUploadRequest:
    file_path: str


@dataclass
class FileUploadResponse:
    object_id: NemesisFileId


class NemesisAgent(Enum):
    COBALTSTRIKE_BEACON = "cobaltstrike_beacon"
    MANUAL = "manual"  # For manually uploaded data
    MERLIN = "merlin"
    METASPLOIT_METERPRETER = "metasploit_meterpreter"
    MYTHIC = "mythic"
    SLIVER = "sliver"
    STAGE1 = "stage1"


class NemesisDataType(Enum):
    FileData = "file_data"


@dataclass
class Metadata:
    agent_id: str
    agent_type: str
    automated: bool
    data_type: NemesisDataType
    expiration: datetime
    source: str
    project: str
    timestamp: datetime

    def to_dict(self) -> dict[str, Any]:
        out = {
            "agent_id": self.agent_id,
            "agent_type": self.agent_type,
            "automated": self.automated,
            "data_type": self.data_type.value,
            "expiration": convert_to_nemesis_timestamp(self.expiration),
            "source": self.source,
            "project": self.project,
            "timestamp": convert_to_nemesis_timestamp(self.timestamp),
        }
        return out


def convert_to_nemesis_timestamp(timestamp: datetime) -> str:
    """Converts a datetime object to a Nemesis timestamp.

    Args:
        timestamp (datetime): The timestamp to convert

    Returns:
        str: The timestamp in Nemesis format
    """
    return timestamp.strftime("%Y-%m-%dT%H:%M:%S.000Z")


@dataclass
class FileData:
    path: str
    size: PositiveInt
    object_id: NemesisFileId


@dataclass
class FileDataRequest:
    metadata: Metadata
    data: list[FileData]


@dataclass
class DataResponse:
    object_id: NemesisMessageId


class NemesisApiClient:
    client: httpx.AsyncClient

    FILE_ENDPOINT = "/file"
    DATA_ENDPOINT = "/data"

    def __init__(self, url: str, client: Optional[httpx.AsyncClient]) -> None:
        """Create a new Nemesis API HTTP client.

        Args:
            url (str): Base URL to the Nemesis API. Example: https://nemesis.example.com/api/
            auth (Optional[httpx.Auth]): Authentication to use for the API
        """
        if client:
            self.client = client
        else:
            self.client = httpx.AsyncClient(base_url=url)
        headers = {"Content-Type": "application/octet-stream"}
        self.client.headers.update(headers)

    async def send_file(self, r: FileUploadRequest) -> FileUploadResponse:
        """Uploads a file to Nemesis and returns a Nemesis file object UUID.

        Args:
            data (FileDataRequest): API request parameters

        Raises:
            httpx.HttpStatusError: An exception containing information about HTTP error code and response body

        Returns:
            FileUploadResponse: Structure containing the fild object UUID
        """
        if not os.path.isfile(r.file_path):
            raise Exception(f"File {r.file_path} does not exist")

        del self.client.headers["Content-Type"]

        with open(r.file_path, 'rb') as file:
            files = {'file': (r.file_path.split('/')[-1], file)}
            #files = {'file': open(r.file_path, 'rb')}
            resp = await self.client.post(self.FILE_ENDPOINT, files=files)

        resp.raise_for_status()

        obj = resp.json()
        return FileUploadResponse(NemesisFileId(obj["object_id"]))

    async def send_file_data(self, data: FileDataRequest) -> DataResponse:
        """Uploads a file_data object to Nemesis and returns a Nemesis file object UUID.

        Args:
            data (FileDataRequest): file_data object to up send to Nemesis

        Raises:
            httpx.HttpStatusError: An exception containing information about HTTP error code and response body

        Returns:
            DataResponse: Structure containing the object_id of the data message
        """

        json = {
            "metadata": {
                "agent_id": data.metadata.agent_id,
                "agent_type": data.metadata.agent_type,
                "automated": data.metadata.automated,
                "data_type": data.metadata.data_type.value,
                "expiration": convert_to_nemesis_timestamp(data.metadata.expiration),
                "source": data.metadata.source,
                "project": data.metadata.project,
                "timestamp": convert_to_nemesis_timestamp(data.metadata.timestamp),
            },
            "data": [],
        }

        for d in data.data:
            json["data"].append(
                {
                    "path": d.path,
                    "size": d.size,
                    "object_id": d.object_id,
                }
            )

        resp = await self.client.post(self.DATA_ENDPOINT, json=json)

        resp.raise_for_status()

        obj = resp.json()
        return DataResponse(NemesisMessageId(obj["object_id"]))
