"""Text extraction activities."""

import asyncio

import document_conversion.global_vars as global_vars
from common.logger import get_logger
from common.models import Transform
from common.state_helpers import get_file_enriched_async
from common.storage import StorageMinio
from common.workflows.setup import workflow_activity
from dapr.ext.workflow.workflow_activity_context import WorkflowActivityContext

logger = get_logger(__name__)

storage = StorageMinio()


@workflow_activity
async def extract_text(ctx: WorkflowActivityContext, file_input: dict) -> dict | None:
    """Extract text using Tika."""
    object_id = file_input.get("object_id")
    result = None

    try:
        file_enriched = await get_file_enriched_async(object_id, global_vars.asyncpg_pool)

        if not can_extract_plaintext(file_enriched.mime_type):
            return None

        with storage.download(file_enriched.object_id) as temp_file:
            extracted_text: str | None = None
            try:
                # Run Tika parsing in a thread since it's a blocking operation
                java_file = global_vars.JavaFile(temp_file.name)
                java_text = await asyncio.to_thread(global_vars.tika.parseToString, java_file)
                extracted_text = str(java_text)

            except Exception as e:
                logger.warning(
                    "Tika extraction failed",
                    object_id=file_enriched.object_id,
                    error=str(e),
                )
                # Record success in database
                async with global_vars.asyncpg_pool.acquire() as conn:
                    await conn.execute(
                        """
                        UPDATE workflows
                        SET enrichments_failure = array_append(enrichments_failure, $1)
                        WHERE object_id = $2
                        """,
                        "extract_tika_text",
                        file_enriched.object_id,
                    )

            if not extracted_text:
                logger.debug("Text extraction complete: no text extracted.")
                return None

            # Upload extracted text
            object_id = storage.upload(extracted_text.encode("utf-8"))

            transform = Transform(
                type="extracted_text",
                object_id=str(object_id),
                metadata={
                    "file_name": "extracted_plaintext.txt",
                    "display_type_in_dashboard": "monaco",
                    "display_title": "Extracted Plaintext",
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
                    "extract_tika_text",
                    file_enriched.object_id,
                )

            logger.debug("Text extracted to extracted_plaintext.txt with Tika", object_id=file_enriched.object_id)

            result = transform.model_dump()
            return result

    except Exception as e:
        logger.exception(message="Unexpected error performing text extraction", object_id=object_id)

        # Record failure in database
        try:
            async with global_vars.asyncpg_pool.acquire() as conn:
                await conn.execute(
                    """
                    UPDATE workflows
                    SET enrichments_failure = array_append(enrichments_failure, $1)
                    WHERE object_id = $2
                    """,
                    f"extract_tika_text:{str(e)[:100]}",
                    object_id,
                )
        except Exception as db_error:
            logger.error(f"Failed to update extract_tika_text failure in database: {str(db_error)}")

        raise


def can_extract_plaintext(mime_type: str) -> bool:
    """Returns True if the file's mime type can be used with Tika."""

    # from https://tika.apache.org/2.8.0/formats.html#Full_list_of_Supported_Formats_in_standard_artifacts
    supported_mime_types = {
        "text/csv": 1,
        # "text/plain": 1,
        "text/html": 1,
        "application/vnd.wap.xhtml+xml": 1,
        "application/x-asp": 1,
        "application/xhtml+xml": 1,
        "image/png": 1,
        "image/vnd.wap.wbmp": 1,
        "image/x-jbig2": 1,
        "image/bmp": 1,
        "image/x-xcf": 1,
        "image/gif": 1,
        "image/x-ms-bmp": 1,
        "image/jpeg": 1,
        # "application/mbox": 1,
        "image/emf": 1,
        # "application/x-msaccess": 1,
        "application/x-tika-msoffice-embedded; format=ole10_native": 1,
        "application/msword": 1,
        "application/vnd.visio": 1,
        "application/x-tika-ole-drm-encrypted": 1,
        "application/vnd.ms-project": 1,
        "application/x-tika-msworks-spreadsheet": 1,
        "application/x-mspublisher": 1,
        "application/vnd.ms-powerpoint": 1,
        "application/x-tika-msoffice": 1,
        "application/sldworks": 1,
        "application/x-tika-ooxml-protected": 1,
        "application/vnd.ms-excel": 1,
        # "application/vnd.ms-outlook": 1,
        "application/vnd.ms-excel.workspace.3": 1,
        "application/vnd.ms-excel.workspace.4": 1,
        "application/vnd.ms-excel.sheet.2": 1,
        "application/vnd.ms-excel.sheet.3": 1,
        "application/vnd.ms-excel.sheet.4": 1,
        "image/wmf": 1,
        "application/vnd.ms-htmlhelp": 1,
        "application/x-chm": 1,
        "application/chm": 1,
        "application/onenote; format=one": 1,
        "application/vnd.ms-powerpoint.template.macroenabled.12": 1,
        "application/vnd.ms-excel.addin.macroenabled.12": 1,
        "application/vnd.openxmlformats-officedocument.wordprocessingml.template": 1,
        "application/vnd.ms-excel.sheet.binary.macroenabled.12": 1,
        "application/vnd.openxmlformats-officedocument.wordprocessingml.document": 1,
        "application/vnd.ms-powerpoint.slide.macroenabled.12": 1,
        "application/vnd.ms-visio.drawing": 1,
        "application/vnd.ms-powerpoint.slideshow.macroenabled.12": 1,
        "application/vnd.ms-powerpoint.presentation.macroenabled.12": 1,
        "application/vnd.openxmlformats-officedocument.presentationml.slide": 1,
        "application/vnd.ms-excel.sheet.macroenabled.12": 1,
        "application/vnd.ms-word.template.macroenabled.12": 1,
        "application/vnd.ms-word.document.macroenabled.12": 1,
        "application/vnd.ms-powerpoint.addin.macroenabled.12": 1,
        "application/vnd.openxmlformats-officedocument.spreadsheetml.template": 1,
        "application/vnd.ms-xpsdocument": 1,
        "application/vnd.ms-visio.drawing.macroenabled.12": 1,
        "application/vnd.ms-visio.template.macroenabled.12": 1,
        "model/vnd.dwfx+xps": 1,
        "application/vnd.openxmlformats-officedocument.presentationml.template": 1,
        "application/vnd.openxmlformats-officedocument.presentationml.presentation": 1,
        "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet": 1,
        "application/vnd.ms-visio.stencil": 1,
        "application/vnd.ms-visio.template": 1,
        "application/vnd.openxmlformats-officedocument.presentationml.slideshow": 1,
        "application/vnd.ms-visio.stencil.macroenabled.12": 1,
        "application/vnd.ms-excel.template.macroenabled.12": 1,
        "application/vnd.ms-word2006ml": 1,
        "application/vnd.ms-outlook-pst": 1,
        "application/rtf": 1,
        "application/vnd.ms-wordml": 1,
        "image/ocr-x-portable-pixmap": 1,
        "image/ocr-jpx": 1,
        "image/x-portable-pixmap": 1,
        "image/ocr-jpeg": 1,
        "image/ocr-jp2": 1,
        "image/jpx": 1,
        "image/ocr-png": 1,
        "image/ocr-tiff": 1,
        "image/ocr-gif": 1,
        "image/ocr-bmp": 1,
        "image/jp2": 1,
        "application/pdf": 1,
        "application/vnd.wordperfect; version=5.1": 1,
        "application/vnd.wordperfect; version=5.0": 1,
        "application/vnd.wordperfect; version=6.x": 1,
        "application/xml": 1,
    }

    return mime_type in supported_mime_types
