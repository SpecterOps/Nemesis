# Standard Libraries
import glob
import os
import uuid

# 3rd Party Libraries
import structlog
import uvicorn
import yara
from fastapi import FastAPI, File, UploadFile
from fastapi.responses import Response
from fastapi import APIRouter
from nemesiscommon.nemesis_tempfile import TempFile
from nemesiscommon.storage import StorageInterface
from nemesiscommon.tasking import TaskInterface
from prometheus_async import aio
from prometheus_client import Summary

logger = structlog.get_logger(module=__name__)


class YaraApi(TaskInterface):
    storage: StorageInterface
    api_port: int
    data_download_dir: str
    log_level: str

    def __init__(self, storage: StorageInterface, api_port: int, data_download_dir: str, log_level: str) -> None:
        self.storage = storage
        self.api_port = api_port
        self.data_download_dir = data_download_dir
        self.log_level = log_level

    async def run(self) -> None:
        app = FastAPI()
        routes = YaraApiRoutes(self.storage, self.data_download_dir)
        app.include_router(routes.router)
        server_config = uvicorn.Config(
            app,
            host="0.0.0.0",
            port=self.api_port,
            log_level=self.log_level.lower(),
        )
        server = uvicorn.Server(server_config)
        logger.info("Starting YaraAPI", port=self.api_port)
        await server.serve()


class YaraApiRoutes():
    storage: StorageInterface
    data_download_dir: str

    def __init__(self, storage: StorageInterface, data_download_dir: str) -> None:
        super().__init__()
        self.storage = storage
        self.data_download_dir = data_download_dir

        # load up the Yara rules
        yara_file_paths = glob.glob("./enrichment/lib/public_yara/**/*.yara", recursive=True) + glob.glob("./enrichment/lib/public_yara/**/*.yar", recursive=True)
        yara_files = {}

        for yara_file_path in yara_file_paths:
            try:
                yara_files[yara_file_path.split("/")[-1]] = yara_file_path
            except:
                continue

        self.yara_rules = yara.compile(filepaths=yara_files)

        self.router = APIRouter()
        self.router.add_api_route("/", self.home, methods=["GET"])
        self.router.add_api_route("/ready", self.ready, methods=["GET"])
        self.router.add_api_route("/file", self.yara_file, methods=["POST"])

        logger.info("YaraAPI initialization completed")

    async def home(self):
        return Response()

    async def ready(self):
        """Used for readiness probes."""
        return Response()

    @aio.time(Summary("file", "Time spent scanning raw file bytes with Yara"))  # type: ignore
    async def yara_file(self, file: UploadFile = File(...)):
        """Scan submitted file bytes with all current Yara rules."""

        await logger.adebug("Yara /file endpoint called")

        try:
            async with TempFile(self.data_download_dir) as temp_file:
                file_bytes = await file.read()

                # write the posted file out to a temp file
                with open(temp_file.path, "wb") as f:
                    f.write(file_bytes)

                return await self.yara_opsec_scan(temp_file.path)
        except Exception as e:
            await logger.aexception(e, message="yara_file error")
            return {"error": f"yara_file error: {e}"}

    async def yara_opsec_scan(self, file: str | uuid.UUID):
        """Scans the given file path or file UUID with all current yara OPSEC rules.

        Any matches are returned. If the file doesn't exist, we attempt to
        download it the Nemesis datastore.
        """

        # check if the file is a string or UUID

        if isinstance(file, str):
            if os.path.exists(file):
                try:
                    return {"yara_matches": [f"{match}" for match in self.yara_rules.match(file)]}
                except Exception as e:
                    await logger.aexception(e, message="yara_opsec_scan error", file_path=file)
                    return {"error": f"yara_opsec_scan error for {file} : {e}"}
        elif isinstance(file, uuid.UUID):
            try:
                with await self.storage.download(file) as temp_file:
                    return {"yara_matches": [f"{match}" for match in self.yara_rules.match(temp_file.name)]}
            except Exception as e:
                await logger.aexception(e, message="yara_opsec_scan error", file_path=file)
                return {"error": f"yara_opsec_scan error for {file} : {e}"}
        else:
            raise ValueError(f"file must be a string or UUID, but got a '{type(file)}'. Value: '{file}'")
