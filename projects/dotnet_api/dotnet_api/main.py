import json
import os
import shutil
import subprocess
import uuid

import structlog
from common.dependency_checks import check_file_exists, find_missing_path_dependencies
from common.storage import StorageMinio
from fastapi import FastAPI, HTTPException
from fastapi.responses import JSONResponse
from dapr.clients import DaprClient

INSPECT_ASSEMBLY_PATH = os.getenv("INSPECT_ASSEMBLY_PATH", "/opt/InspectAssembly/InspectAssembly.dll")

logger = structlog.get_logger(module=__name__)

find_missing_path_dependencies(["ilspycmd", "dotnet"], raise_error=True)
check_file_exists(INSPECT_ASSEMBLY_PATH)

app = FastAPI()
storage = StorageMinio()


def process_dotnet(path: str) -> dict:
    """Processes a .NET assembly file by decompiling it and analyzing it."""
    # Create unique temporary directories for decompilation and analysis
    temp_dir_decompilation = f"/tmp/{uuid.uuid4()}"
    temp_dir_analysis = f"/tmp/{uuid.uuid4()}"

    try:
        # Create necessary directories
        os.makedirs(f"{temp_dir_decompilation}/source/", exist_ok=True)
        os.makedirs(temp_dir_analysis, exist_ok=True)

        # Copy the file to both directories
        filename = os.path.basename(path)
        shutil.copy(path, temp_dir_decompilation)
        shutil.copy(path, temp_dir_analysis)

        results = {}

        # Decompile the assembly using ilSpy
        decompile_result = subprocess.run(
            [
                "ilspycmd",
                f"{temp_dir_decompilation}/{filename}",
                "-p",
                "-o",
                f"{temp_dir_decompilation}/source/",
            ],
            capture_output=True,
            check=True,
        )
        logger.debug(f"Decompilation result: {decompile_result}")

        try:
            # Analyze the assembly
            logger.debug("Calling InspectAssembly", target=f"{temp_dir_analysis}/{filename}")

            logger.debug(f"inspect_assembly_path: {INSPECT_ASSEMBLY_PATH}")

            analysis_result = subprocess.run(
                [
                    "dotnet",
                    INSPECT_ASSEMBLY_PATH,
                    f"{temp_dir_analysis}/{filename}",
                ],
                capture_output=True,
                check=True,
            )
            logger.info(f"InspectAssembly result: {analysis_result}")
        except Exception as e:
            logger.exception("Exception running InspectAssembly", error=str(e))
            raise

        # Parse analysis output
        analysis_output = analysis_result.stdout.decode("utf-8")
        results["inspect_assembly"] = json.loads(analysis_output)

        # Create zip of decompiled source
        shutil.make_archive(f"{temp_dir_decompilation}/source", "zip", f"{temp_dir_decompilation}/source/")

        # Prepare the source archive
        shutil.move(f"{temp_dir_decompilation}/source.zip", f"{temp_dir_decompilation}/{filename}")

        # Upload the decompiled source archive
        with open(f"{temp_dir_decompilation}/{filename}", "rb") as f:
            file_uuid = storage.upload_file(f"{temp_dir_decompilation}/{filename}")
            results["decompilation"] = {"object_id": file_uuid}

        return results

    except subprocess.CalledProcessError as e:
        # Access the captured output
        stderr_output = e.stderr
        stdout_output = e.stdout
        return_code = e.returncode

        import traceback

        logger.error(
            "CalledProcessError in process_dotnet",
            exception=str(e),
            traceback=traceback.format_exc(),
            stderr=stderr_output,
            stdout=stdout_output,
            return_code=return_code,
        )

        raise HTTPException(status_code=500, detail=f"Dotnet processing failed: {e.stderr.decode('utf-8')}") from e
    except json.JSONDecodeError as e:
        raise HTTPException(status_code=500, detail=f"Failed to parse analysis output: {str(e)}") from e
    finally:
        # Clean up temporary directories
        if os.path.exists(temp_dir_decompilation):
            shutil.rmtree(temp_dir_decompilation, ignore_errors=True)
        if os.path.exists(temp_dir_analysis):
            shutil.rmtree(temp_dir_analysis, ignore_errors=True)


@app.get("/file/{object_id}")
async def analyze_file(object_id: str):
    try:
        logger.info("Processing .NET assembly", object_id=object_id)
        with storage.download(object_id) as temp_file:
            # Run dotnet processing
            results = process_dotnet(temp_file.name)
            logger.info("Completed .NET processing", object_id=object_id)
            return JSONResponse(content=results)

    except Exception as e:
        import traceback

        logger.error(
            "Error in analyze_file endpoint", error=str(e), traceback=traceback.format_exc(), object_id=object_id
        )
        raise HTTPException(status_code=500, detail=f"Error processing file: {str(e)}") from e


@app.api_route("/healthz", methods=["GET", "HEAD"])
async def healthcheck():
    """Health check endpoint for Docker healthcheck."""
    return {"status": "healthy"}
