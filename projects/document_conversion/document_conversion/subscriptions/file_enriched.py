"""Handler for file_enriched subscription events."""

import asyncio
import re
from functools import cache

import fitz  # PyMuPDF
from common.helpers import can_convert_to_pdf
from common.logger import get_logger
from common.models import CloudEvent, FileEnriched
from common.storage import StorageS3
from minio.error import S3Error

from ..activities.extract_text import can_extract_plaintext

logger = get_logger(__name__)

# Only these can be password- or RMS-protected in a way the checks below detect (PDF, OLE/CDFV2 Office files, and
# zip-based OOXML, which `file` may report as a plain zip); everything else (binaries, archives, images, ...) would
# be downloaded just to fail the PDF and Office parsers
_MAYBE_PROTECTED = re.compile(r"pdf document|composite document file|cdfv2|microsoft|(?<!7-)zip archive")


@cache
def _storage() -> StorageS3:
    """One S3 client per process (each StorageS3 opens a Dapr client to read the S3 secrets)."""
    return StorageS3()


def _may_be_protected(magic_type: str) -> bool:
    magic = (magic_type or "").lower()
    return not magic or _MAYBE_PROTECTED.search(magic) is not None


def has_conversion_work(file_data: FileEnriched) -> bool:
    """Whether any workflow step applies, by the steps' own checks: strings (anything but a container), text
    extraction (a Tika type) or PDF conversion (a convertible extension). An archive matches none of them; its
    extracted files arrive as files of their own."""
    return (
        not file_data.is_container
        or can_extract_plaintext(file_data.mime_type)
        or can_convert_to_pdf(file_data.file_name)
    )


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
    """Whether the file is encrypted or RMS protected: from the magic type, else by opening PDFs and Office files.

    Blocking (S3 download and parsing): call it from a worker thread. Raises S3Error (NoSuchKey) if the object is gone.
    """
    if "Security: 1" in file_data.magic_type or "CDFV2 Encrypted" in file_data.magic_type:
        return True

    if not _may_be_protected(file_data.magic_type):
        return False

    with _storage().download(file_data.object_id) as temp_file:
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

        if not has_conversion_work(file_enriched):
            logger.debug(
                "Skipping document_conversion_workflow - no step applies to this file type",
                object_id=file_enriched.object_id,
                mime_type=file_enriched.mime_type,
            )
            return

        # If the file is encrypted, skip
        if await asyncio.to_thread(is_encrypted_file, file_enriched):
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
