"""Handler for file_enriched subscription events."""

import fitz  # PyMuPDF
from common.logger import get_logger
from common.models import CloudEvent, FileEnriched
from minio.error import S3Error

logger = get_logger(__name__)


def is_pdf_encrypted(pdf_path):
    try:
        with fitz.open(pdf_path) as doc:
            return doc.is_encrypted

    except Exception:
        logger.exception("Error checking PDF")
        return None


def check_office_encryption(file_path: str):
    """Check if an Office file is encrypted."""
    import msoffcrypto

    with open(file_path, "rb") as f:
        try:
            office_file = msoffcrypto.OfficeFile(f)
            return office_file.is_encrypted()
        except Exception:
            return False


def check_rms_protected(file_path: str):
    """Check if a file is RMS protected by looking for the DRMEncryptedTransform folder"""
    import zipfile

    import olefile

    try:
        with zipfile.ZipFile(file_path, "r") as zip_ref:
            file_list = zip_ref.namelist()

            # Check for the specific folder path that indicates RMS protection
            for file in file_list:
                if "DRMEncryptedTransform" in file:
                    return True

    except Exception:
        pass

    # Try OLE approach if ZIP check failed or returned False
    try:
        if olefile.isOleFile(file_path):
            ole = olefile.OleFileIO(file_path)
            if ole.exists("\x06DataSpaces/TransformInfo/DRMEncryptedTransform"):
                return True
            ole.close()
    except Exception:
        pass

    return False


def is_encrypted_file(file_data: FileEnriched):
    """Uses the magic type to determine if the file is encrypted"""
    from common.storage import StorageMinio

    storage = StorageMinio()

    if "Security: 1" in file_data.magic_type or "CDFV2 Encrypted" in file_data.magic_type:
        return True

    # Check if file exists before attempting download
    if not storage.check_file_exists(file_data.object_id):
        logger.warning("File does not exist in MinIO", object_id=file_data.object_id)
        raise S3Error(
            code="NoSuchKey",
            message=f"Object {file_data.object_id} does not exist",
            resource=file_data.object_id,
            request_id="",
            host_id="",
            response=None,  # pyright: ignore[reportArgumentType]
        )

    with storage.download(file_data.object_id) as temp_file:
        if "pdf document" in file_data.magic_type.lower():
            return is_pdf_encrypted(temp_file.name)
        else:
            if check_office_encryption(temp_file.name) or check_rms_protected(temp_file.name):
                return True
    return False


async def file_enriched_subscription_handler(event: CloudEvent[FileEnriched]):
    """Handler for file_enriched events with semaphore-based concurrency control."""
    from ..workflow_manager import start_workflow_with_concurrency_control

    file_enriched = event.data

    try:
        logger.debug("Received file_enriched event", object_id=file_enriched.object_id)

        # If the file is encrypted, skip
        if is_encrypted_file(file_enriched):
            logger.warning(
                "Skipping document_conversion_workflow - file is encrypted or protected",
                object_id=file_enriched.object_id,
                path=file_enriched.path,
            )
            return

        # Start workflow with semaphore control for backpressure
        await start_workflow_with_concurrency_control(file_enriched)

    except S3Error as e:
        # Handle MinIO-specific errors
        if e.code in ["NoSuchKey", "NoSuchBucket"]:
            # Non-retryable error: file doesn't exist in MinIO
            logger.error(
                "File not found in MinIO - dropping message to prevent retry loop",
                object_id=file_enriched.object_id,
                error_code=e.code,
                error_message=str(e),
            )
            # Return success to Dapr to acknowledge and drop the message
            # This prevents infinite retries for missing files
            return
        else:
            # Retryable MinIO error (network issues, auth failures, etc.)
            logger.exception(
                message="Retryable MinIO error - message will be requeued",
                object_id=file_enriched.object_id,
                error_code=e.code,
            )
            raise

    except Exception:
        # Catch-all for unexpected errors - these should be retried
        logger.exception(
            message="Unexpected error handling file_enriched event - message will be requeued",
            object_id=file_enriched.object_id,
        )
        raise
