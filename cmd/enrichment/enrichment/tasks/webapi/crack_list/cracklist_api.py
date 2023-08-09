# Standard Libraries
import uuid
from pathlib import Path

# 3rd Party Libraries
import structlog
import uvicorn
from enrichment.tasks.webapi.crack_list.client_wordlists import ClientWordlists
from fastapi import FastAPI
from fastapi.responses import Response
from fastapi_class.decorators import get, post
from fastapi_class.routable import Routable
from nemesiscommon.storage import StorageInterface
from nemesiscommon.tasking import TaskInterface
from prometheus_async import aio
from prometheus_client import Summary
from pydantic import BaseModel

logger = structlog.get_logger(module=__name__)


class CrackListApi(TaskInterface):
    storage: StorageInterface
    log_level: str

    def __init__(self, storage: StorageInterface, log_level: str) -> None:
        self.storage = storage
        self.log_level = log_level

    async def run(self) -> None:
        app = FastAPI()
        routes = CrackListApiRoutes(self.storage)
        app.include_router(routes.router)
        # TODO: do we need to set the port as an env var?
        server_config = uvicorn.Config(app, host="0.0.0.0", port=9900, log_level=self.log_level.lower())
        server = uvicorn.Server(server_config)
        await server.serve()


class UploadRequest(BaseModel):
    object_id: uuid.UUID
    client_id: str


class CrackListApiRoutes(Routable):
    """Inherits from Routable."""

    storage: StorageInterface
    client_wordlists: ClientWordlists

    def __init__(self, storage: StorageInterface) -> None:
        super().__init__()
        self.storage = storage
        self.client_wordlists = ClientWordlists()

    @get("/")
    async def home(self):
        return Response()

    @get("/ready")
    async def ready(self):
        """
        Used for readiness probes.
        """
        return Response()

    @aio.time(Summary("wordlist_add", "Time spent adding a document to the wordlist"))  # type: ignore
    @post("/add")
    async def root_post(self, request: UploadRequest, length_filter: bool = False):
        try:
            await logger.adebug("Got request", request=request)
            with await self.storage.download(request.object_id) as temp_file:
                data = Path(temp_file.name).read_text()
                self.client_wordlists.add_file(request.client_id, data, length_filter)
        except Exception as e:
            return {"error": str(e)}

    @aio.time(Summary("wordlist_retrieve", "Time spent retrieving the wordlist"))  # type: ignore
    @get("/client/{client_id}")
    def root_get(self, client_id: str, count: int = 10):
        try:
            ret = self.client_wordlists.get_as_file(client_id, count=count)
            return Response(ret, media_type="text/plain")
        except Exception as e:
            return {"error": str(e)}
