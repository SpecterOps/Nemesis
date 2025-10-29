# src/workflow/containers.py
import json
import os
import pathlib
import shutil
import struct
import tarfile
import uuid
import zipfile
import zlib
from io import SEEK_END

import py7zr
from common.logger import get_logger
from common.models import File, FileEnriched
from dapr.clients import DaprClient

logger = get_logger(__name__)


class FileNotSupportedException(Exception):
    """Raised when a file is not supported"""

    pass


class ArchiveExtractionError(Exception):
    """Raised when there's an error during archive extraction"""

    pass


def is_safe_path(base_path, path_to_check):
    """
    Ensure the path doesn't escape the base directory.

    Args:
        base_path: The base directory that should contain all files
        path_to_check: The path to validate

    Returns:
        bool: True if the path is safe, False otherwise
    """
    # Convert to absolute paths and normalize
    base_path = os.path.abspath(base_path)
    path_to_check = os.path.abspath(path_to_check)
    # Check if the path is within the base directory
    return path_to_check.startswith(base_path)


def estimate_container_size(path: str) -> int:
    """
    Tries to estimate a container's size.

    NOTE: not 100% reliable against malicious inputs! (i.e., we can still get zip-bombed)
    """
    try:
        if zipfile.is_zipfile(path):
            with zipfile.ZipFile(path) as f:
                # Check for unreasonable compression ratio
                total_size = sum(zinfo.file_size for zinfo in f.filelist)
                compressed_size = sum(zinfo.compress_size for zinfo in f.filelist)
                if compressed_size > 0 and total_size / compressed_size > 1000:
                    logger.warning(f"Suspicious compression ratio detected: {total_size / compressed_size}")
                return total_size
        elif py7zr.is_7zfile(path):
            with py7zr.SevenZipFile(path) as f:
                return f.archiveinfo().uncompressed
        elif tarfile.is_tarfile(path):
            return estimate_uncompressed_gz_size(path)
        else:
            # File is not a supported archive format
            return -1
    except Exception as e:
        logger.warning(f"Error in estimate_container_size: {e}")
        return -1


def estimate_uncompressed_gz_size(filename) -> int:
    """Estimates a gzip uncompressed size.

    Directly from https://stackoverflow.com/a/68939759
    """
    try:
        # From the input file, get some data:
        # - the 32 LSB from the gzip stream
        # - 1MB sample of compressed data
        # - compressed file size
        with open(filename, "rb") as gz_in:
            sample = gz_in.read(1000000)
            gz_in.seek(-4, SEEK_END)
            lsb = struct.unpack("I", gz_in.read(4))[0]
            file_size = os.fstat(gz_in.fileno()).st_size

        # Estimate the total size by decompressing the sample to get the
        # compression ratio so we can extrapolate the uncompressed size
        # using the compression ratio and the real file size
        dobj = zlib.decompressobj(31)
        d_sample = dobj.decompress(sample)

        compressed_len = len(sample) - len(dobj.unconsumed_tail)
        decompressed_len = len(d_sample)

        # Check for unreasonable compression ratio
        if compressed_len > 0 and decompressed_len / compressed_len > 1000:
            logger.warning(f"Suspicious compression ratio detected: {decompressed_len / compressed_len}")
            return -1

        estimate = int(file_size * decompressed_len / compressed_len)

        # 32 LSB to zero
        mask = ~0xFFFFFFFF

        # Kill the 32 LSB to be substituted by the data read from the file
        adjusted_estimate = (estimate & mask) | lsb

        return adjusted_estimate

    except Exception as e:
        logger.warning(f"Error in estimate_uncompressed_gz_size: {e}")
        return -1


def safe_extract_archive(path: str, extract_dir: str) -> bool:
    """
    Safely extracts an archive file with additional security measures

    Args:
        path: Path to the archive file
        extract_dir: Directory to extract to

    Returns:
        bool: True if extraction was successful, False otherwise
    """
    max_files = 10000  # Adjust based on your requirements
    max_total_size = 2_147_483_648  # 2GB example

    try:
        if zipfile.is_zipfile(path):
            with zipfile.ZipFile(path) as zf:
                # Check number of files
                if len(zf.namelist()) > max_files:
                    logger.warning(f"Too many files in archive ({len(zf.namelist())}), possible zip bomb")
                    return False

                # Filter out unsafe paths
                safe_members = []
                for member in zf.infolist():
                    if member.filename.startswith("/") or ".." in member.filename:
                        logger.warning(f"Unsafe path in archive: {member.filename}")
                        continue

                    # Check for extremely long filenames
                    if len(os.path.basename(member.filename)) > 255:
                        logger.warning(f"Filename too long, may be malicious: {member.filename}")
                        continue

                    safe_members.append(member)

                # Extract only safe members
                total_extracted = 0
                for member in safe_members:
                    if total_extracted > max_total_size:
                        logger.warning("Max extraction size exceeded, possible zip bomb")
                        return False

                    extract_path = os.path.join(extract_dir, member.filename)
                    if not is_safe_path(extract_dir, extract_path):
                        logger.warning(f"Path traversal attempt detected: {member.filename}")
                        continue

                    zf.extract(member, extract_dir)
                    total_extracted += member.file_size

            return True

        elif py7zr.is_7zfile(path):
            with py7zr.SevenZipFile(path) as sz:
                # Get the list of files
                file_list = sz.getnames()

                # Check number of files
                if len(file_list) > max_files:
                    logger.warning(f"Too many files in archive ({len(file_list)}), possible archive bomb")
                    return False

                # Filter out unsafe paths
                safe_members = []
                for filename in file_list:
                    if filename.startswith("/") or ".." in filename:
                        logger.warning(f"Unsafe path in archive: {filename}")
                        continue

                    # Check for extremely long filenames
                    if len(os.path.basename(filename)) > 255:
                        logger.warning(f"Filename too long, may be malicious: {filename}")
                        continue

                    safe_members.append(filename)

                # Extract only safe members if supported by library
                sz.extract(path=extract_dir, targets=safe_members)

            # Verify all extracted paths for safety after extraction
            for root, dirs, files in os.walk(extract_dir):
                for item in dirs + files:
                    item_path = os.path.join(root, item)
                    if not is_safe_path(extract_dir, item_path):
                        logger.warning(f"Unsafe path found after extraction: {item_path}")
                        shutil.rmtree(extract_dir, ignore_errors=True)
                        return False

            return True

        elif tarfile.is_tarfile(path):
            with tarfile.open(path) as tf:
                # Check number of files
                members = tf.getmembers()
                if len(members) > max_files:
                    logger.warning(f"Too many files in archive ({len(members)}), possible archive bomb")
                    return False

                # Filter out unsafe members
                safe_members = []
                for member in members:
                    # Check for absolute paths and path traversal
                    if member.name.startswith("/") or ".." in member.name:
                        logger.warning(f"Unsafe path in archive: {member.name}")
                        continue

                    # Check for long filenames
                    if len(os.path.basename(member.name)) > 255:
                        logger.warning(f"Filename too long, may be malicious: {member.name}")
                        continue

                    # Check for dangerous file types (symlinks, devices, etc.)
                    if member.type not in (tarfile.REGTYPE, tarfile.DIRTYPE):
                        logger.warning(f"Unsafe file type in archive: {member.name}, type {member.type}")
                        continue

                    # Check final path after extraction
                    extract_path = os.path.join(extract_dir, member.name)
                    if not is_safe_path(extract_dir, extract_path):
                        logger.warning(f"Path traversal attempt detected: {member.name}")
                        continue

                    safe_members.append(member)

                # Extract only safe members
                total_extracted = 0
                for member in safe_members:
                    if member.type == tarfile.REGTYPE:  # Regular file
                        if total_extracted > max_total_size:
                            logger.warning("Max extraction size exceeded, possible archive bomb")
                            return False
                        total_extracted += member.size

                    tf.extract(member, extract_dir)

            return True
        else:
            raise FileNotSupportedException("File is not a supported archive format")

    except Exception:
        logger.exception(message="Error in safe_extract_archive")
        return False


def extract_archive(path: str) -> str:
    """
    Extracts an archive file to a temporary directory and returns the
    temporary directory name
    """
    # Create temporary directory
    tmp_dir = f"/tmp/{uuid.uuid4()}"
    os.makedirs(tmp_dir, exist_ok=True)

    # Extract using safe extraction
    if not safe_extract_archive(path, tmp_dir):
        if os.path.exists(tmp_dir):
            shutil.rmtree(tmp_dir, ignore_errors=True)
        raise ArchiveExtractionError("Failed to safely extract archive")

    return tmp_dir


class ContainerExtractor:
    def __init__(
        self,
        storage,
        dapr_client: DaprClient,
        extracted_archive_size_limit: int = 1_073_741_824,  # 1GB default
        allowed_extensions: set = None,  # Optional whitelist of allowed file extensions
    ):
        """Initialize the ContainerProcessor with its dependencies.

        Args:
            storage: Storage backend for file operations
            dapr_client: Dapr client for message publishing
            extracted_archive_size_limit: Maximum size in bytes for extracted archives
            allowed_extensions: Set of allowed file extensions (e.g., {'.txt', '.pdf'})
        """
        self.storage = storage
        self.dapr_client = dapr_client
        self.extracted_archive_size_limit = extracted_archive_size_limit
        self.allowed_extensions = allowed_extensions

    def should_extract_archive(self, archive_size):
        """Check if archive should be extracted based on size."""
        if archive_size <= 0:
            logger.warning("Unable to determine archive size, extraction skipped")
            return False

        return archive_size < self.extracted_archive_size_limit

    def extract_archive(self, temp_file, file_enriched):
        """Extract the archive and handle extraction errors."""
        try:
            return extract_archive(temp_file.name)
        except FileNotSupportedException:
            logger.warning(
                "File is not a supported archive format",
                path=file_enriched.path,
                file_path_on_disk=temp_file.name,
            )
        except ArchiveExtractionError:
            logger.warning(
                "Failed to safely extract archive",
                path=file_enriched.path,
                file_path_on_disk=temp_file.name,
            )
        except RuntimeError as e:
            if "encrypted, password required for extraction" in str(e):
                logger.info("Archive is encrypted", path=file_enriched.path, file_path_on_disk=temp_file.name)
            else:
                logger.exception(
                    e,
                    message="RuntimeError extracting archive",
                    path=file_enriched.path,
                    file_path_on_disk=temp_file.name,
                )
        return None

    def get_real_path(self, extracted_path, tmp_dir, file_enriched):
        """Calculate the real path for the extracted file with sanitization."""
        # Get the relative path from the extraction directory
        try:
            rel_path = os.path.relpath(extracted_path, tmp_dir)

            # Reject paths that try to go up the directory tree
            if rel_path.startswith(".."):
                logger.warning(f"Rejecting suspicious relative path: {rel_path}", archive_file_path=file_enriched.path)
                return None

            # Join with the destination base path
            base_dir = os.path.dirname(file_enriched.path)
            real_path = os.path.join(base_dir, rel_path)

            # Handle Windows path conversion if necessary
            if "\\" in file_enriched.path:
                real_path = real_path.replace("/", "\\")

            return real_path
        except Exception as e:
            logger.exception(
                e,
                message="Error calculating real path",
                extracted_path=extracted_path,
                archive_file_path=file_enriched.path,
            )
            return None

    def publish_file_message(self, file_message: File):
        """Publish file message to the message bus."""
        data = json.dumps(file_message.model_dump(exclude_unset=True, mode="json"))
        self.dapr_client.publish_event(
            pubsub_name="pubsub",
            topic_name="file",
            data=data,
            data_content_type="application/json",
        )

    def process_extracted_file(self, extracted_file_path, tmp_dir, file_enriched):
        """Process a single extracted file with security checks."""
        try:
            # Skip if not a file or empty
            if not os.path.isfile(extracted_file_path) or os.path.getsize(extracted_file_path) <= 0:
                return False

            # Verify path is safe
            if not is_safe_path(tmp_dir, extracted_file_path):
                logger.warning(
                    f"Possible path traversal attempt: {extracted_file_path}", archive_file_path=file_enriched.path
                )
                return False

            # Check for symbolic links
            if os.path.islink(extracted_file_path):
                link_target = os.path.realpath(extracted_file_path)
                if not is_safe_path(tmp_dir, link_target):
                    logger.warning(
                        f"Potentially unsafe symbolic link: {extracted_file_path} -> {link_target}",
                        archive_file_path=file_enriched.path,
                    )
                    return False

            # Check filename length
            if len(os.path.basename(extracted_file_path)) > 255:
                logger.warning(
                    f"Filename too long, may be malicious: {extracted_file_path}", archive_file_path=file_enriched.path
                )
                return False

            # Check file extension if whitelist is provided
            if self.allowed_extensions:
                file_ext = os.path.splitext(extracted_file_path)[1].lower()
                if file_ext not in self.allowed_extensions:
                    logger.warning(
                        f"File has disallowed extension: {file_ext}",
                        extracted_file_path=extracted_file_path,
                        archive_file_path=file_enriched.path,
                    )
                    return False

            # Get the size after all checks
            extracted_file_size = os.path.getsize(extracted_file_path)

            # Calculate the real path
            real_path = self.get_real_path(extracted_file_path, tmp_dir, file_enriched)
            if not real_path:
                return False

            # Process the file
            object_id = self.storage.upload_file(extracted_file_path)
            nesting_level = (file_enriched.nesting_level or 0) + 1

            file_message = File(
                object_id=str(object_id),
                agent_id=file_enriched.agent_id,
                source=file_enriched.source,
                project=file_enriched.project,
                timestamp=file_enriched.timestamp,
                expiration=file_enriched.expiration,
                path=real_path,
                originating_object_id=file_enriched.object_id,
                nesting_level=nesting_level,
            )

            self.publish_file_message(file_message)

            logger.info(
                f"Submitted extracted file '{real_path}' to Nemesis",
                originating_object_id=file_enriched.object_id,
            )
            return True

        except Exception as e:
            logger.exception(
                e,
                message="process_archive error",
                extracted_file_path=extracted_file_path,
                archive_file_path=file_enriched.path,
            )

        return False

    def extract(self, file_enriched: FileEnriched):
        """Process a container file and extract its contents."""
        try:
            with self.storage.download(file_enriched.object_id) as temp_file:
                archive_size = estimate_container_size(temp_file.name)

                if not self.should_extract_archive(archive_size):
                    logger.warning(
                        f"process_archive: '{file_enriched.path}' ({temp_file.name}) is over the projected decompressed limit of {self.extracted_archive_size_limit} bytes or size could not be determined"
                    )
                    return

                tmp_dir = self.extract_archive(temp_file, file_enriched)
                if not tmp_dir:
                    return

                try:
                    processed_files = 0
                    max_files_to_process = 10000  # Safety limit

                    # Use a safer method to walk the directory
                    for extracted_file_path in pathlib.Path(tmp_dir).glob("**/*"):
                        if processed_files >= max_files_to_process:
                            logger.warning(
                                f"Reached maximum number of files to process ({max_files_to_process})",
                                archive_file_path=file_enriched.path,
                            )
                            break

                        if self.process_extracted_file(str(extracted_file_path), tmp_dir, file_enriched):
                            processed_files += 1

                    logger.info(
                        "Files processed from archive",
                        archive_file_path=file_enriched.path,
                        processed_files=processed_files,
                    )
                finally:
                    # Clean up the extracted directory
                    if os.path.exists(tmp_dir):
                        shutil.rmtree(tmp_dir, ignore_errors=True)

        except Exception:
            logger.exception("Error processing container", file_enriched=file_enriched)
            raise
