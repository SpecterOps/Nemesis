"""PDF conversion activities."""

import os

import document_conversion.global_vars as global_vars
import httpx
from common.helpers import can_convert_to_pdf
from common.logger import get_logger
from common.models import Transform
from common.state_helpers import get_file_enriched_async
from common.storage import StorageMinio
from common.workflows.setup import workflow_activity
from dapr.ext.workflow.workflow_activity_context import WorkflowActivityContext

logger = get_logger(__name__)

storage = StorageMinio()


@workflow_activity
async def convert_to_pdf(ctx: WorkflowActivityContext, file_input: dict) -> dict | None:
    """Convert file to PDF using Gotenberg."""
    object_id = file_input.get("object_id")
    result = None

    try:
        file_enriched = await get_file_enriched_async(object_id, global_vars.asyncpg_pool)

        if not can_convert_to_pdf(file_enriched.file_name):
            return None

        # excel docs need to be shown in landscape
        landscape = f"{file_enriched.extension}".lower() in [
            ".xls",
            ".xlsb",
            ".xlsm",
            ".xlsx",
            ".xlt",
            ".xltm",
            ".xltx",
            ".xlw",
        ]

        with storage.download(file_enriched.object_id) as temp_file:
            temp_file_with_ext = f"{temp_file.name}.{file_enriched.extension}"
            os.rename(temp_file.name, temp_file_with_ext)

            try:
                with open(temp_file_with_ext, "rb") as file_data:
                    files = {"file": file_data}
                    data = {}

                    if landscape:
                        data["landscape"] = "true"

                    # Use httpx async client instead of requests
                    async with httpx.AsyncClient(timeout=180.0) as client:
                        response = await client.post(
                            global_vars.gotenberg_url,
                            files=files,
                            data=data,
                        )

                    if response.status_code == 200:
                        object_id = storage.upload(response.content)

                        transform = Transform(
                            type="converted_pdf",
                            object_id=str(object_id),
                            metadata={
                                "file_name": f"{file_enriched.file_name}.pdf",
                                "display_type_in_dashboard": "pdf",
                                "display_title": "Converted PDF",
                            },
                        )

                        # Record success in database
                        async with global_vars.asyncpg_pool.acquire() as conn:
                            await conn.execute(
                                """
                                UPDATE workflows
                                SET enrichments_success = array_append(enrichments_success, $1)
                                WHERE object_id = $2
                                """,
                                "convert_to_pdf",
                                file_enriched.object_id,
                            )

                        logger.debug(
                            "File successfully converted to PDF with Gotenberg", object_id=file_enriched.object_id
                        )

                        result = transform.model_dump()
                        return result
                    else:
                        logger.error(
                            "Error calling Gotenberg",
                            status_code=response.status_code,
                            response_text=response.text,
                        )

                        # Record failure in database due to Gotenberg error
                        async with global_vars.asyncpg_pool.acquire() as conn:
                            await conn.execute(
                                """
                                UPDATE workflows
                                SET enrichments_failure = array_append(enrichments_failure, $1)
                                WHERE object_id = $2
                                """,
                                f"convert_to_pdf:Gotenberg returned status code {response.status_code}",
                                file_enriched.object_id,
                            )

                        return None

            finally:
                os.rename(temp_file_with_ext, temp_file.name)

    except Exception as e:
        logger.exception(message="Error in PDF conversion", object_id=object_id)

        # Record failure in database
        try:
            async with global_vars.asyncpg_pool.acquire() as conn:
                await conn.execute(
                    """
                    UPDATE workflows
                    SET enrichments_failure = array_append(enrichments_failure, $1)
                    WHERE object_id = $2
                    """,
                    f"convert_to_pdf:{str(e)[:100]}",
                    object_id,
                )
        except Exception as db_error:
            logger.error(f"Failed to update convert_to_pdf failure in database: {str(db_error)}")

        raise
