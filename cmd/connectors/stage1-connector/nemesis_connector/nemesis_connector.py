# Standard Libraries
import asyncio
import logging
import os
import requests
import ntpath
import re
import time
from dataclasses import dataclass, asdict
from datetime import datetime, timedelta
from enum import Enum
from typing import Any, NewType, Optional
from urllib.parse import urlparse
from uuid import UUID
import redis

# Outflank Stage1 Libraries
from outflank_stage1 import Config
from outflank_stage1.bot import BaseBot
from outflank_stage1.implant import Implant
from outflank_stage1.services.implant_service import ImplantService
from outflank_stage1.task import BaseTask
from outflank_stage1.task.tasks import PwdTask
from outflank_stage1.services.task_service import TaskService
# 3rd Party Libraries
from pip._internal import main as pipmain

# # Hard code creds if you don't want to bother editing OST's docker-compose file
# os.environ["NEMESIS_URL"] = "https://192.168.80.128:8080/api/"
# os.environ["NEMESIS_USERNAME"] = "nemesis"
# os.environ["NEMESIS_PASSWORD"] = "Qwerty12345"
# os.environ["NEMESIS_PROJECT"] = "ASSESS-TEST"
# os.environ["NEMESIS_EXPIRATION_DAYS"] = "365"
# os.environ["NEMESIS_LOG_LEVEL"] = "DEBUG"
# # os.environ["CLEAR_REDIS"] = "True" # true if you want to clear the redis backend DB for reprocessing

# Ugly hack so we don't have to customize stage1's docker container
# Assumes the docker container has internet access so it can install pip packages
packages = ["httpx", "dynaconf", "pydantic"]
res = pipmain(["--disable-pip-version-check", "install", "--root-user-action=ignore"] + packages)
if res != 0:
    raise Exception("NemesisConnector was unable to install pip dependencies. Exiting...")

# 3rd Party Libraries
import httpx  # noqa
from dynaconf import Dynaconf, Validator  # noqa
from dynaconf.base import Settings  # noqa
from pydantic.types import PositiveInt  # noqa

rconn = redis.Redis(host='redis', db=13)
if "CLEAR_REDIS" in os.environ and os.environ["CLEAR_REDIS"].lower().startswith("t"):
    for key in rconn.keys('*'):
        rconn.delete(key)

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


def parse_size(size):
    units = {"B": 1, "KB": 2**10, "MB": 2**20, "GB": 2**30, "TB": 2**40}
    size = size.upper()
    if not re.match(r' ', size):
        size = re.sub(r'([KMGT]?B)', r' \1', size)
    number, unit = [string.strip() for string in size.split()]
    return int(float(number)*units[unit])


# set environment variables
validators = [
    Validator("URL", "USERNAME", "PASSWORD", must_exist=True),
    Validator("url", condition=is_uri, messages={"condition": "Invalid/missing protocol scheme and/or hostname"})
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
    FileInformation = "file_information"


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


@dataclass
class FileInformation:
    type: str
    creation_time: datetime
    access_time: datetime
    modification_time: datetime
    size: int
    path: str
    asdict


@dataclass
class FileInformationRequest:
    metadata: Metadata
    data: list[FileInformation]


class NemesisApiClient:
    client: httpx.Client

    FILE_ENDPOINT = "/file"
    DATA_ENDPOINT = "/data"

    def __init__(self, url: str, auth: Optional[httpx.Auth] = None, transport: Optional[httpx.BaseTransport] = httpx.HTTPTransport(retries=5)) -> None:
        """Create a new Nemesis API HTTP client.

        Args:
            url (str): Base URL to the Nemesis API. Example: https://nemesis.example.com/api/
            auth (Optional[httpx.Auth]): Authentication to use for the API
        """

        self.client = httpx.Client(base_url=url, auth=auth, transport=transport, verify=False)
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

    def send_file_information(self, data: FileInformationRequest):
        """Uploads a file_formation object to Nemesis and returns a Nemesis UUID.

        Args:
            data (FileInformationRequest): file_information object to up send to Nemesis

        Raises:
            httpx.HttpStatusError: An exception containing information about HTTP error code and response body

        """

        if data.data and len(data.data) > 0:
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
                "data": [asdict(d) for d in data.data],
            }

            resp = self.client.post(self.DATA_ENDPOINT, json=json)

            resp.raise_for_status()
            obj = resp.json()

            return DataResponse(NemesisMessageId(obj["object_id"]))


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


def parse_ls_line(target_dir: str, line: str) -> FileInformation:
    """Converts a directory listing line to a FileInformation dataclass.

    Args:
        target_dir (str): The resolved target directory the object is in
        line (str): The object (file/folder)

    Returns:
        FileInformation: The constructed file information dataclass
    """
    try:
        if "<DIR>" in line:
            parts = line.split("<DIR>")
            name = parts[-1].strip()
            timestamp = parts[0].strip()
            nemesis_timestamp = datetime.strptime(timestamp, "%d/%m/%Y %H:%M").strftime("%Y-%m-%dT%H:%M:%S.000Z")
            path = f"{target_dir}{name}"
            if not (name == "." or name == ".."):
                return FileInformation(
                    type="folder",
                    modification_time=nemesis_timestamp,
                    creation_time=datetime(1970, 1, 1).strftime("%Y-%m-%dT%H:%M:%S.000Z"),
                    access_time=datetime(1970, 1, 1).strftime("%Y-%m-%dT%H:%M:%S.000Z"),
                    size=0,
                    path=path
                )
        else:
            parts = line.split("\t")
            timestamp = parts[0].strip()
            size = parts[1].strip()
            parsed_size = parse_size(size)
            name = parts[2].strip()
            path = f"{target_dir}{name}"
            nemesis_timestamp = datetime.strptime(timestamp, "%d/%m/%Y %H:%M").strftime("%Y-%m-%dT%H:%M:%S.000Z")
            return FileInformation(
                type="file",
                modification_time=nemesis_timestamp,
                creation_time=datetime(1970, 1, 1).strftime("%Y-%m-%dT%H:%M:%S.000Z"),
                access_time=datetime(1970, 1, 1).strftime("%Y-%m-%dT%H:%M:%S.000Z"),
                size=parsed_size,
                path=path
            )
    except Exception as e:
        print(f"Error parsing line '{line}' : {e}")

def parse_ls_line2(target_dir: str, line: str) -> FileInformation:
    """Converts a directory listing line to a FileInformation dataclass.

    Args:
        target_dir (str): The resolved target directory the object is in
        line (str): The object (file/folder)

    Returns:
        FileInformation: The constructed file information dataclass
    """
    try:
        parts = line.split("|")
        if len(parts) == 5:
            nemesis_created_timestamp = datetime.strptime(parts[0].strip(), "%m/%d/%Y %H:%M:%S").strftime("%Y-%m-%dT%H:%M:%S.000Z")
            nemesis_written_timestamp = datetime.strptime(parts[1].strip(), "%m/%d/%Y %H:%M:%S").strftime("%Y-%m-%dT%H:%M:%S.000Z")
            nemesis_accessed_timestamp = datetime.strptime(parts[2].strip(), "%m/%d/%Y %H:%M:%S").strftime("%Y-%m-%dT%H:%M:%S.000Z")
            name = parts[-1].strip()
            path = f"{target_dir}{name}"

            if "<dir>" in line or "<junction>" in line:
                if not (name == "." or name == ".."):
                    return FileInformation(
                        type="folder",
                        creation_time=nemesis_created_timestamp,
                        access_time=nemesis_accessed_timestamp,
                        modification_time=nemesis_written_timestamp,
                        size=0,
                        path=path
                    )
            else:
                size = parts[3].strip()
                return FileInformation(
                    type="file",
                    creation_time=nemesis_created_timestamp,
                    access_time=nemesis_accessed_timestamp,
                    modification_time=nemesis_written_timestamp,
                    size=size,
                    path=path
                )
    except Exception as e:
        print(f"Error parsing line '{line}' : {e}")

def parse_ls_output(cwd: str, text: str):
    """Converts a directory listing to an array of file FileInformation.

    Args:
        cwd (str): The current working directory.
        text (str): The output of ls
    """
    target_dir = ""
    ls_type = "1" # 1 is normal, 2 is customized

    for line in text.split("\n")[0:3]:
        if line.startswith("Directory of "):
            target_dir = line[13:]
        if line.startswith("Contents of "):
            target_dir = line[12:]
            ls_type = "2"

    if ls_type == "1":
        if ntpath.isabs(target_dir):
            target_dir = target_dir.replace("\\", "/")
        else:
            target_dir = ntpath.realpath(f"{cwd}\\{target_dir}").replace("\\", "/")

        if not target_dir.endswith("/"):
            target_dir = f"{target_dir}/"

        listings = []
        for line in text.split("\n"):
            if len(line.split("\t")) == 3:
                listing = parse_ls_line(target_dir, line)
                if listing:
                    listings.append(listing)

        return listings
    else:
        target_dir = target_dir.replace("\\", "/")
        if not target_dir.endswith("/"):
            target_dir = f"{target_dir}/"

        listings = []
        for line in text.split("\n"):
            if len(line.split("|")) == 5:
                listing = parse_ls_line2(target_dir, line)
                if listing:
                    listings.append(listing)

        return listings

class NemesisConnector(BaseBot):
    _implant_service: ImplantService
    _logger: logging.Logger
    _task_service: TaskService
    _current_working_directories: dict

    def __init__(self):
        super().__init__()

        logging.getLogger().setLevel(logging.DEBUG)

        self._logger = logging.getLogger(__name__)
        self._logger.setLevel(logging.DEBUG)
        for handler in logger.handlers:
            handler.setLevel(logging.DEBUG)

        self._logger.info("Log level: %s", cfg.log_level)
        self._implant_service = ImplantService()
        self._task_service = TaskService()

        self._current_working_directories = {}
        self._logger.info("Sleeping until services startup...")
        time.sleep(15)

        implants = self._implant_service.get_all_implants()
        for implant in implants:
            implant_uid = implant.get_uid()
            hostname = implant.get_hostname()
            # no no, definitely not a hack to get historical task information :)
            resp = requests.get(f"http://api/api/implants/{implant_uid}")
            if resp.status_code == 200:
                json_resp = resp.json()

                self._current_working_directories[implant_uid] = ""

                if "tasks" in json_resp:
                    for task in json_resp["tasks"]:
                        if task["response"]:
                            if task["name"] == "pwd":
                                self._current_working_directories[implant_uid] = task["response"]
                            elif task["name"] == "cd" and (task["response"] == "Command succeeded"):
                                target_dir = task["run_arguments"][0].replace("/", "\\")
                                if not target_dir.endswith("\\"):
                                    target_dir = f"{target_dir}\\"
                                if ntpath.isabs(target_dir):
                                    if target_dir.startswith("\\"):
                                        # handle cases like "cd \temp"
                                        cwd = self._current_working_directories[implant_uid]
                                        prev_drive = ntpath.splitdrive(cwd)
                                        self._current_working_directories[implant_uid] = f"{prev_drive}\\{target_dir}"
                                    else:
                                        self._current_working_directories[implant_uid] = target_dir
                                else:
                                    cwd = self._current_working_directories[implant_uid]
                                    path_resolved = ntpath.realpath(f"{cwd}\\{target_dir}")
                                    if not path_resolved.endswith("\\"):
                                        path_resolved = f"{path_resolved}\\"
                                    self._current_working_directories[implant_uid] = path_resolved
                            elif task["name"] == "download":
                                task_uid = task["uid"]
                                if rconn.get(task_uid):
                                    self._logger.info(f"Download {task_uid} already processed!")
                                else:
                                    response_timestamp = datetime.fromisoformat(task["response_timestamp"])
                                    filename = task["response"]
                                    timestamp = datetime.fromisoformat(task["timestamp"])
                                    download = self.get_download_disk_filepath(filename, timestamp)
                                    if download and os.path.isfile(download):
                                        try:
                                            file_size = os.stat(download).st_size
                                            client = NemesisApiClient(cfg.url, httpx.BasicAuth(cfg.username, cfg.password))
                                            fileUploadResp = client.send_file(FileUploadRequest(download))
                                            self._logger.info(f"[Startup] Uploaded file '{filename}' to nemesis! File ID: {fileUploadResp.object_id}. Sending file data message...")

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

                                            file_data = FileData(path=filename, size=file_size, object_id=fileUploadResp.object_id)
                                            fdReq = FileDataRequest(metadata=m, data=[file_data])

                                            fdResp = client.send_file_data(fdReq)

                                            self._logger.info(f"[Startup] Sent file_data message to nemesis! Message ID: {fdResp.object_id}")
                                            rconn.set(task_uid, 1)
                                        except httpx.HTTPStatusError as e:
                                            self._logger.exception(f"[Startup] Error sending file data message. Response body: {e.response.text} Exception: {e}")
                                    else:
                                        self._logger.info(f"[Startup] Download {task_uid} doesn't exist on disk!")

                            elif task["name"] == "ls" and not task["response"].startswith("[Error"):
                                task_uid = task["uid"]
                                if rconn.get(task_uid):
                                    self._logger.info(f"Listing {task_uid} already processed!")
                                else:
                                    response_timestamp = datetime.fromisoformat(task["response_timestamp"])
                                    filename = task["response"]
                                    timestamp = datetime.fromisoformat(task["timestamp"])
                                    ls_output = task["response"]

                                    if not ls_output.startswith("[Error"):
                                        try:
                                            client = NemesisApiClient(cfg.url, httpx.BasicAuth(cfg.username, cfg.password))

                                            m = Metadata(
                                                agent_id=implant_uid,
                                                agent_type=NemesisAgent.STAGE1.value,
                                                automated=True,
                                                data_type=NemesisDataType.FileInformation,
                                                expiration=(response_timestamp + timedelta(days=cfg.expiration_days)),
                                                source=hostname,
                                                project=cfg.project,
                                                timestamp=response_timestamp,
                                            )

                                            cwd = self._current_working_directories[implant_uid]
                                            run_args = task["run_arguments"]

                                            if len(run_args) > 0:
                                                ls_arg = run_args[0].replace("/", "\\")
                                                ls_working_directory = ""
                                                if ntpath.isabs(ls_arg):
                                                    ls_working_directory = ls_arg
                                                else:
                                                    ls_working_directory = ntpath.realpath(f"{cwd}\\{ls_arg}")
                                                if not ls_working_directory.endswith("\\"):
                                                    ls_working_directory = f"{ls_working_directory}\\"

                                                file_information = parse_ls_output(ls_working_directory, ls_output)
                                                fiReq = FileInformationRequest(metadata=m, data=file_information)
                                                fiResp = client.send_file_information(fiReq)
                                                self._logger.info(f"Sent file_data message to nemesis! Message ID: {fiResp}")
                                                rconn.set(task_uid, 1)
                                        except httpx.HTTPStatusError as e:
                                            self._logger.exception(f"Error sending file data message. Response body: {e.response.text} Exception: {e}")

                # if we get to this point and there hasn't been a PWD, task one up
                if not self._current_working_directories[implant_uid]:
                    self._task_service.schedule_task(implant_uid=implant.get_uid(), task=PwdTask())

        self._logger.info("Nemesis Connector is running")

    def get_download_disk_filepath(self, path: str, timestamp: datetime) -> Optional[str]:
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
            raise Exception(f"Unexpected status code {resp.status_code} when getting downloads")

        timestampStr = timestamp.isoformat()
        downloads = resp.json()
        download = [x for x in downloads if x["path"] == path and x["timestamp"] == timestampStr]

        if len(download) == 0:
            self._logger.error(f"No download found for str path '{path}' and timestamp '{timestampStr}'")
            return None

        if len(download) > 1:
            raise Exception(f"More than one download found for the path '{path} and timestamp '{timestampStr}'")

        return Config.PATH_SHARED + "/downloads/" + download[0]["uid"]

    def handle_cwd_response(self, task: BaseTask):
        # Obtain/validate required fields
        task_uid = task.get_uid()
        if not task_uid:
            self._logger.error(f"No task_uid found for in cwd response")
            return
        rconn.set(task_uid, 1)

        response_timestamp = task.get_response_timestamp()
        if not response_timestamp:
            self._logger.error("No response timestamp in cwd response")
            return

        implant_uid = task.get_implant_uid()
        if not implant_uid:
            self._logger.error("No implant UID in cwd response")
            return

        cwd_output = task.get_response()
        if not cwd_output:
            self._logger.error("No data in cwd response")
            return

        timestamp = task.get_timestamp()
        if not timestamp:
            self._logger.error("No timestamp in cwd response")
            return

        implant = self._implant_service.get_by_uid(implant_uid)
        if not implant:
            self._logger.error(f"No implant found for UID '{implant_uid}'")
            return

        self._logger.info(f"Setting cwd for {implant_uid} to '{cwd_output}'")
        self._current_working_directories[implant_uid] = cwd_output


    def handle_ls_response(self, task: BaseTask):
        # Obtain/validate required fields

        task_uid = task.get_uid()
        if not task_uid:
            self._logger.error(f"No task_uid found for in ls response")
            return
        rconn.set(task_uid, 1)

        response_timestamp = task.get_response_timestamp()
        if not response_timestamp:
            self._logger.error("No response timestamp in ls response")
            return

        implant_uid = task.get_implant_uid()
        if not implant_uid:
            self._logger.error("No implant UID in ls response")
            return

        ls_output = task.get_response()
        if not ls_output:
            self._logger.error("No data in ls response")
            return

        timestamp = task.get_timestamp()
        if not timestamp:
            self._logger.error("No timestamp in ls response")
            return

        implant = self._implant_service.get_by_uid(implant_uid)
        if not implant:
            self._logger.error(f"No implant found for UID '{implant_uid}'")
            return

        hostname = implant.get_hostname()
        if not hostname:
            self._logger.error(f"No hostname found for implant UID '{implant_uid}'")
            return

        if not implant_uid in self._current_working_directories:
            self._logger.error(f"CWD not set for '{implant_uid}'")
            return

        if not ls_output.startswith("[Error"):
            try:
                client = NemesisApiClient(cfg.url, httpx.BasicAuth(cfg.username, cfg.password))

                m = Metadata(
                    agent_id=implant_uid,
                    agent_type=NemesisAgent.STAGE1.value,
                    automated=True,
                    data_type=NemesisDataType.FileInformation,
                    expiration=(response_timestamp + timedelta(days=cfg.expiration_days)),
                    source=hostname,
                    project=cfg.project,
                    timestamp=response_timestamp,
                )

                cwd = self._current_working_directories[implant_uid]
                run_args = task.get_run_arguments()

                if len(run_args) > 0:
                    ls_arg = run_args[0].replace("/", "\\")
                    ls_working_directory = ""
                    if ntpath.isabs(ls_arg):
                        ls_working_directory = ls_arg
                    else:
                        ls_working_directory = ntpath.realpath(f"{cwd}\\{ls_arg}")
                    if not ls_working_directory.endswith("\\"):
                        ls_working_directory = f"{ls_working_directory}\\"

                    file_information = parse_ls_output(ls_working_directory, ls_output)
                    fiReq = FileInformationRequest(metadata=m, data=file_information)
                    fiResp = client.send_file_information(fiReq)
                    self._logger.info(f"Sent file_data message to nemesis! Message ID: {fiResp}")

            except httpx.HTTPStatusError as e:
                self._logger.exception(f"Error sending file data message. Response body: {e.response.text} Exception: {e}")

    def handle_download_response(self, task: BaseTask):

        task_uid = task.get_uid()
        if not task_uid:
            self._logger.error(f"No task_uid found for in download response")
            return
        rconn.set(task_uid, 1)

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
            self._logger.error(f"No download found for the filename '{filename}' and timestamp '{timestamp}'")
            return

        try:
            client = NemesisApiClient(cfg.url, httpx.BasicAuth(cfg.username, cfg.password))
            fileUploadResp = client.send_file(FileUploadRequest(download))
            self._logger.info(f"Uploaded file '{filename}' to nemesis! File ID: {fileUploadResp.object_id}. Sending file data message...")

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

            file_data = FileData(path=filename, size=file_size, object_id=fileUploadResp.object_id)
            fdReq = FileDataRequest(metadata=m, data=[file_data])

            fdResp = client.send_file_data(fdReq)

            self._logger.info(f"Sent file_data message to nemesis! Message ID: {fdResp.object_id}")

        except httpx.HTTPStatusError as e:
            self._logger.exception(f"Error sending file data message. Response body: {e.response.text} Exception: {e}")

    def on_task_response(self, task: BaseTask):
        # Throwing this onto a queue because these callback functions are synchronous and we don't want to backup other messages

        if task.get_name() == "ls":
            self.handle_ls_response(task)
        elif task.get_name() == "download":
            self.handle_download_response(task)
        elif task.get_name() == "pwd":
            self.handle_cwd_response(task)

    def on_new_implant(self, implant: Implant):
        self._logger.info(f"New implant: {implant.get_hostname()} ({implant.get_ip()})")
        self._task_service.schedule_task(implant_uid=implant.get_uid(), task=PwdTask())
