# Standard Libraries
import json
import os
import shutil
import subprocess
import uuid

# 3rd Party Libraries
import structlog
from dotnet.settings import DotnetSettings
from fastapi.responses import Response
from fastapi_class.decorators import get, post
from fastapi_class.routable import Routable
from nemesiscommon.storage import StorageInterface
from prometheus_async import aio
from prometheus_client import Summary
from pydantic import BaseModel

logger = structlog.get_logger(module=__name__)


class ProcessRequest(BaseModel):
    object_id: uuid.UUID


class DotnetAPI(Routable):
    cfg: DotnetSettings
    storage: StorageInterface

    def __init__(self, cfg: DotnetSettings, storage: StorageInterface) -> None:
        super().__init__()
        self.cfg = cfg
        self.storage = storage

    @get("/")
    async def home(self):
        return Response()

    @get("/ready")
    async def ready(self):
        """
        Used for readiness probes.
        """
        return Response()

    @aio.time(Summary("process_file", "Time spent processing a file"))  # type: ignore
    @post("/process")
    async def process(self, request: ProcessRequest):
        """
        Combines the /decompile and /analysis endpoints,
        so we only have to download/decrypt the binary once.
        """

        tmp_dir_decompilation = f"{self.cfg.data_download_dir}/{uuid.uuid4()}"
        tmp_dir_analysis = f"{self.cfg.data_download_dir}/{uuid.uuid4()}"

        nemesis_uuid = request.object_id
        await logger.adebug("Dotnet /process route called", request=request)

        try:
            with await self.storage.download(nemesis_uuid) as temp_file:
                temp_name = os.path.basename(temp_file.name)
                results = {}

                # create the temp directories and copy/move our downloaded file to there
                # TODO: Use the tempfile python module instead
                os.mkdir(tmp_dir_decompilation)
                os.mkdir(f"{tmp_dir_decompilation}/source/")
                os.mkdir(tmp_dir_analysis)
                shutil.copy(temp_file.name, tmp_dir_decompilation)
                shutil.copy(temp_file.name, tmp_dir_analysis)  # this is a move so we don't have to delete the original later

                # decompile the assembly to a ./source/ project using ilSpy
                p_ilspy = subprocess.Popen(
                    [
                        "/usr/local/bin/ilspycmd",
                        f"{tmp_dir_decompilation}/{temp_name}",
                        "-p",
                        "-o",
                        f"{tmp_dir_decompilation}/source/",
                    ]
                )

                # examine the assembly
                #   TODO: work out how to call the method directly from Python w/o subprocess
                p_inspect_assembly = subprocess.Popen(
                    [
                        "dotnet",
                        "dotnet/services/InspectAssembly/InspectAssembly.dll",
                        f"{tmp_dir_analysis}/{temp_name}",
                    ],
                    stdout=subprocess.PIPE,
                )

                # wait for both processes to complete
                p_ilspy.wait()
                analysis_output = p_inspect_assembly.communicate()[0]
                await logger.adebug("analysis_output", output=analysis_output)
                results["analysis"] = json.loads(analysis_output)

                # zip up the decompiled source
                shutil.make_archive(f"{tmp_dir_decompilation}/source", "zip", f"{tmp_dir_decompilation}/source/")

                # rename the source archive to our new UUID and upload it to S3
                shutil.move(f"{tmp_dir_decompilation}/source.zip", f"{tmp_dir_decompilation}/{temp_name}")

                # not using a TempFile here since we're removing the entire directories later
                file_uuid = await self.storage.upload(f"{tmp_dir_decompilation}/{temp_name}")
                results["decompilation"] = {"object_id": file_uuid}

                return results

        except Exception as e:
            await logger.aerror("exception on dotnet /process route", exception=e)
            return {"error": f"exception running /process container code : {e}"}

        finally:
            if tmp_dir_decompilation and os.path.exists(tmp_dir_decompilation):
                shutil.rmtree(tmp_dir_decompilation, ignore_errors=True)
            if tmp_dir_analysis and os.path.exists(tmp_dir_analysis):
                shutil.rmtree(tmp_dir_analysis, ignore_errors=True)
