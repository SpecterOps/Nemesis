"""Text extraction activities."""

import asyncio
import os
import tempfile
from types import SimpleNamespace

import document_conversion.global_vars as global_vars
import jpype
import jpype.imports  # noqa: F401
from common.logger import get_logger
from common.models import Transform
from common.state_helpers import get_file_enriched_async
from common.storage import StorageMinio
from common.workflows.setup import workflow_activity
from dapr.ext.workflow.workflow_activity_context import WorkflowActivityContext

logger = get_logger(__name__)

storage = StorageMinio()
java = SimpleNamespace()  # Java types namespace - initialized in init_jvm
tika_instance: jpype.JClass | None = None  # Initialized by init_tika()


@workflow_activity
async def extract_text(ctx: WorkflowActivityContext, file_input: dict) -> dict | None:
    """Extract text using Tika."""
    global tika_instance

    if not tika_instance:
        raise ValueError("Tika is not initialized")

    object_id = file_input.get("object_id")
    result = None

    try:
        file_enriched = await get_file_enriched_async(object_id, global_vars.asyncpg_pool)

        if not can_extract_plaintext(file_enriched.mime_type):
            return None

        with storage.download(file_enriched.object_id) as temp_file:
            extracted_text: str | None = None
            try:
                java_file = java.File(temp_file.name)
                java_text = await asyncio.to_thread(tika_instance.parseToString, java_file)
                extracted_text = str(java_text)

            except Exception as e:
                logger.warning(
                    "Tika extraction failed",
                    object_id=file_enriched.object_id,
                    error=str(e),
                )
                # Record failure in database
                await global_vars.tracking_service.update_enrichment_results(
                    instance_id=ctx.workflow_id,
                    failure_list=["extract_tika_text"],
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
            await global_vars.tracking_service.update_enrichment_results(
                instance_id=ctx.workflow_id,
                success_list=["extract_tika_text"],
            )

            logger.debug("Text extracted to extracted_plaintext.txt with Tika", object_id=file_enriched.object_id)

            result = transform.model_dump()
            return result

    except Exception as e:
        logger.exception(message="Unexpected error performing text extraction", object_id=object_id)

        # Record failure in database
        try:
            await global_vars.tracking_service.update_enrichment_results(
                instance_id=ctx.workflow_id,
                failure_list=[f"extract_tika_text:{str(e)[:100]}"],
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


def init_jvm():
    """Initialize Java Virtual Machine and load Java classes."""
    if not jpype.isJVMStarted():
        logger.info("Starting JVM")
        jpype.startJVM(
            # "-Dorg.slf4j.simpleLogger.defaultLogLevel=debug",
            "-Dorg.slf4j.simpleLogger.showDateTime=true",
            "-Dorg.slf4j.simpleLogger.dateTimeFormat=yyyy-MM-dd HH:mm:ss:SSS",
            "-Dorg.slf4j.simpleLogger.showLogName=true",
            "-Dorg.slf4j.simpleLogger.logFile=System.out",  # Write to stdout instead of stderr
            classpath=["/tika-server-standard.jar"],
        )
        logger.info("JVM started successfully")
    else:
        logger.info("JVM already running")

    java.Logger = jpype.JClass("java.util.logging.Logger")
    java.Level = jpype.JClass("java.util.logging.Level")
    java.TikaConfig = jpype.JClass("org.apache.tika.config.TikaConfig")
    java.Tika = jpype.JClass("org.apache.tika.Tika")
    java.File = jpype.JClass("java.io.File")

    pdfbox_logger = java.Logger.getLogger("org.apache.pdfbox")
    pdfbox_logger.setLevel(java.Level.SEVERE)

    logger.info("Java classes loaded and configured")


def init_tika():
    """Initialize Tika with OCR configuration."""
    global tika_instance
    init_jvm()

    # Get OCR language from environment variable
    #   Note: Use underscores for language types, not hyphens (chi_sim not chi-sim)
    ocr_languages = os.getenv("TIKA_OCR_LANGUAGES", "eng").replace("-", "_").replace(" ", "+")
    logger.info(f"Configuring Tika with OCR languages: {ocr_languages}")

    # Read the static XML config and substitute the language parameter
    with open("/tika-config.xml") as f:
        config_xml = f.read()

    # Replace the hardcoded language with the environment variable value
    config_xml = config_xml.replace(">eng<", f">{ocr_languages}<")

    # Write the modified config to a temporary file
    with tempfile.NamedTemporaryFile(mode="w", suffix=".xml", delete=False) as temp_config:
        temp_config.write(config_xml)
        temp_config.flush()
        temp_config_path = temp_config.name

    try:
        config = java.TikaConfig(java.File(temp_config_path))
        tika_instance = java.Tika(config)
        logger.info(
            "Tika initialized successfully with OCR languages", config=temp_config_path, ocr_languages=ocr_languages
        )
    except Exception as e:
        logger.exception("Failed to load Tika config", ocr_languages=ocr_languages, config_xml=config_xml)
        raise e
