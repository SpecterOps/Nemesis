# Standard Libraries
import asyncio
import logging
import os
from dataclasses import dataclass
from datetime import datetime, timedelta
from enum import Enum
from typing import Any, NewType, Optional
from urllib.parse import urlparse
from uuid import UUID

# Outflank Stage1 Libraries
from outflank_stage1 import Config
from outflank_stage1.bot import BaseBot
from outflank_stage1.implant import Implant
from outflank_stage1.services.implant_service import ImplantService
from outflank_stage1.task import BaseTask

# 3rd Party Libraries
from pip._internal import main as pipmain

# Hard code creds if you don't want to bother editing OST's docker-compose file
# os.environ["NEMESIS_URL"] = "http://192.168.230.42:8080/api/"
# os.environ["NEMESIS_USERNAME"] = "nemesis"
# os.environ["NEMESIS_PASSWORD"] = "Password123"
# os.environ["NEMESIS_PROJECT"] = "ACME"
# os.environ["NEMESIS_EXPIRATION_DAYS"] = "365"
# os.environ["NEMESIS_LOG_LEVEL"] = "DEBUG"

# Ugly hack so we don't have to customize stage1's docker container
# Assumes the docker container has internet access so it can install pip packages
packages = ["httpx", "dynaconf", "pydantic"]
res = pipmain(
    ["--disable-pip-version-check", "install", "--root-user-action=ignore"] + packages
)
if res != 0:
    raise Exception(
        "NemesisConnector was unable to install pip dependencies. Exiting..."
    )

# 3rd Party Libraries
import httpx  # noqa
from dynaconf import Dynaconf, Validator  # noqa
from dynaconf.base import Settings  # noqa
from pydantic.types import PositiveInt  # noqa


def is_uri(value: str) -> bool:
    if value is None:
        return False
    try:
        url = urlparse(value)
        if url.scheme == "" or url.netloc == "":
            return False
        if url.scheme.lower() not in ["http", "https"]:
            return False

        return True
    except ValueError:
        return False


# set environment variables
validators = [
    Validator("URL", "USERNAME", "PASSWORD", must_exist=True),
    Validator(
        "url",
        condition=is_uri,
        messages={"condition": "Invalid/missing protocol scheme and/or hostname"},
    ),
]
settings: Settings = Dynaconf(envvar_prefix="NEMESIS", validators=validators)  # type: ignore
settings.validators.validate()


@dataclass
class NemesisConnectorConfig:
    url: str
    username: str
    password: str
    project: str
    expiration_days: PositiveInt = 365
    log_level: str = "INFO"


cfg = NemesisConnectorConfig(
    url=settings.get("URL"),
    username=settings.get("username"),
    password=settings.get("password"),
    project=settings.get("project"),
    expiration_days=settings.get("expiration_days", 365),
    log_level=settings.get("log_level", "INFO"),
)

logger = logging.getLogger("NemesisConnector")
queue = asyncio.Queue()


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
            # "source": self.source,
            "project": self.project,
            "timestamp": convert_to_nemesis_timestamp(self.timestamp),
        }
        return out


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
    client: httpx.Client

    FILE_ENDPOINT = "/file"
    DATA_ENDPOINT = "/data"

    def __init__(
        self,
        url: str,
        auth: Optional[httpx.Auth] = None,
        transport: Optional[httpx.BaseTransport] = httpx.HTTPTransport(retries=5),
    ) -> None:
        """Create a new Nemesis API HTTP client.

        Args:
            url (str): Base URL to the Nemesis API. Example: https://nemesis.example.com/api/
            auth (Optional[httpx.Auth]): Authentication to use for the API
        """

        self.client = httpx.Client(base_url=url, auth=auth, transport=transport)
        headers = {"Content-Type": "application/octet-stream"}
        self.client.headers.update(headers)

    def send_file(self, r: FileUploadRequest) -> FileUploadResponse:
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

        # TODO: Stream the file instead of reading all bytes into memory
        with open(r.file_path, "rb") as f:
            data = f.read()
            resp = self.client.post(self.FILE_ENDPOINT, content=data)

        resp.raise_for_status()

        obj = resp.json()
        return FileUploadResponse(NemesisFileId(obj["object_id"]))

    def send_file_data(self, data: FileDataRequest) -> DataResponse:
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
                # "source": data.metadata.source,
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

        resp = self.client.post(self.DATA_ENDPOINT, json=json)

        resp.raise_for_status()

        obj = resp.json()
        return DataResponse(NemesisMessageId(obj["object_id"]))


# coroutine to consume work
async def consumer(queue):
    while True:
        task: BaseTask = await queue.get()

        print(task)


def loop_in_thread(loop):
    asyncio.set_event_loop(loop)
    loop.run_until_complete(consumer(queue))


# loop = asyncio.get_event_loop()
# t = threading.Thread(target=loop_in_thread, args=(loop,))
# t.start()


@dataclass
class DownloadedFile:
    """Represents a file that was downloaded from the implant.

    Attributes:
        file_uid (str): Unique name of the file on the current machines disk
        path (str): The path of the file on the implant
        timestamp (datetime): When the file was downloaded.

    """

    filename_on_disk: str
    path: str
    timestamp: datetime


def convert_to_nemesis_timestamp(timestamp: datetime) -> str:
    """Converts a datetime object to a Nemesis timestamp.

    Args:
        timestamp (datetime): The timestamp to convert

    Returns:
        str: The timestamp in Nemesis format
    """
    return timestamp.strftime("%Y-%m-%dT%H:%M:%S.000Z")


class NemesisConnector(BaseBot):
    _implant_service: ImplantService
    _logger: logging.Logger

    def __init__(self):
        super().__init__()

        logging.getLogger().setLevel(logging.DEBUG)

        self._logger = logging.getLogger(__name__)
        self._logger.setLevel(logging.DEBUG)
        for handler in logger.handlers:
            handler.setLevel(logging.DEBUG)

        self._logger.info("Log level: %s", cfg.log_level)
        self._implant_service = ImplantService()
        self._logger.info("Nemesis Connector is running")

    def get_download_disk_filepath(
        self, path: str, timestamp: datetime
    ) -> Optional[str]:
        """Returns the path to the downloaded file on disk.

        Args:
            path (str): Path of the file on the implant
            timestamp (datetime): Timestamp of when the task request was sent (NOT the task response timestamp)

        Raises:
            Exception: If it cannot access the Downlaods API
            Exception: If more than one download is returned

        Returns:
            str: The path to the downloaded file on disk
        """
        resp = httpx.get(Config.URL_API + "/api/downloads")

        if resp.status_code != 200:
            raise Exception(
                f"Unexpected status code {resp.status_code} when getting downloads"
            )

        timestampStr = timestamp.isoformat()
        downloads = resp.json()
        download = [
            x for x in downloads if x["path"] == path and x["timestamp"] == timestampStr
        ]

        if len(download) == 0:
            self._logger.error(
                f"No download found for str path '{path}' and timestamp '{timestampStr}'"
            )
            return None

        if len(download) > 1:
            raise Exception(
                f"More than one download found for the path '{path} and timestamp '{timestampStr}'"
            )

        return Config.PATH_SHARED + "/downloads/" + download[0]["uid"]

    def on_task_response(self, task: BaseTask):
        # Throwing this onto a queue because these callback functions are synchronous and we don't want to backup other messages

        if task.get_name() != "download":
            return

        # Obtain/validate required fields
        response_timestamp = task.get_response_timestamp()
        if not response_timestamp:
            self._logger.error("No response timestamp in download response")
            return

        implant_uid = task.get_implant_uid()
        if not implant_uid:
            self._logger.error("No implant UID in download response")
            return

        filename = task.get_response()
        if not filename:
            self._logger.error("No filename in download response")
            return

        file_size = task.get_response_bytes_total()
        if not file_size:
            self._logger.error("No file_size in download response")
            return

        timestamp = task.get_timestamp()
        if not timestamp:
            self._logger.error("No timestamp in download response")
            return

        implant = self._implant_service.get_by_uid(implant_uid)
        if not implant:
            self._logger.error(f"No implant found for UID '{implant_uid}'")
            return

        hostname = implant.get_hostname()
        if not hostname:
            self._logger.error(f"No hostname found for implant UID '{implant_uid}'")
            return

        # Now process the response
        download = self.get_download_disk_filepath(filename, timestamp)
        if not download:
            self._logger.error(
                f"No download found for the filename '{filename}' and timestamp '{timestamp}'"
            )
            return

        try:
            client = NemesisApiClient(
                cfg.url, httpx.BasicAuth(cfg.username, cfg.password)
            )
            fileUploadResp = client.send_file(FileUploadRequest(download))

            self._logger.info(
                f"Uploaded file '{filename}' to nemesis! File ID: {fileUploadResp.object_id}. Sending file data message..."
            )

            m = Metadata(
                agent_id=implant_uid,
                agent_type=NemesisAgent.STAGE1.value,
                automated=True,
                data_type=NemesisDataType.FileData,
                expiration=(response_timestamp + timedelta(days=cfg.expiration_days)),
                source=hostname,
                project=cfg.project,
                timestamp=response_timestamp,
            )

            file_data = FileData(
                path=filename, size=file_size, object_id=fileUploadResp.object_id
            )
            fdReq = FileDataRequest(metadata=m, data=[file_data])

            fdResp = client.send_file_data(fdReq)

            self._logger.info(
                f"Sent file_data message to nemesis! Message ID: {fdResp.object_id}"
            )

        except httpx.HTTPStatusError as e:
            self._logger.exception(
                f"Error sending file data message. Response body: {e.response.text} Exception: {e}"
            )

    def on_new_implant(self, implant: Implant):
        self._logger.info(f"New implant: {implant.get_hostname()} ({implant.get_ip()})")
