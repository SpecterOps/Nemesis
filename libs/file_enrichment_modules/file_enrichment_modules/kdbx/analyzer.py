# enrichment_modules/kdbx/analyzer.py
import struct
import tempfile
import uuid
from typing import Any

from common.logger import get_logger
from common.models import EnrichmentResult, FileObject, Finding, FindingCategory, FindingOrigin, Transform
from common.state_helpers import get_file_enriched_async
from common.storage import StorageMinio
from file_enrichment_modules.kdbx.keepass2john import process_database
from file_enrichment_modules.module_loader import EnrichmentModule

logger = get_logger(__name__)


def get_encryption_algorithm_name(uuid_str: str) -> str:
    """Map encryption algorithm UUID to human-readable name."""
    uuid_map = {"31c1f2e6-bf71-4350-be58-05216afc5aff": "AES-256", "d6038a2b-8b6f-4cb5-a524-339a31dbb59a": "ChaCha20"}
    return uuid_map.get(uuid_str.lower(), uuid_str)


def get_kdf_algorithm_name(uuid_str: str) -> str:
    """Map KDF algorithm UUID to human-readable name."""
    uuid_map = {
        "c9d9f39a-628a-4460-bf74-0d08c18a4fea": "AES-KDF",
        "ef636ddf-8c29-444b-91f7-a9a403e30a0c": "Argon2d",
        "9e298b19-56db-4773-b23d-fc3ec6f0a1e6": "Argon2id",
    }
    return uuid_map.get(uuid_str.lower(), uuid_str)


def parse_kdbx_file(file_path: str) -> dict[str, Any]:
    """
    Parse a KDBX file and return its metadata and encryption information.

    Args:
        file_path (str): Path to the KDBX file

    Returns:
        Dict[str, Any]: Dictionary containing parsed KDBX data
    """

    # Initialize return dictionary with default values
    parsed_data = {
        "is_encrypted": True,  # KDBX files are always encrypted
        "encryption_hash": None,
        "format_version": None,
        "major_version": None,
        "minor_version": None,
        "encryption_algorithm": None,
        "compression_algorithm": None,
        "kdf_algorithm": None,
        "kdf_rounds": None,
        "kdf_memory": None,
        "kdf_parallelism": None,
        "transform_seed": None,
        "master_seed": None,
    }

    try:
        with open(file_path, "rb") as f:
            # Read and verify KDBX signatures
            sig1 = struct.unpack("<I", f.read(4))[0]
            sig2 = struct.unpack("<I", f.read(4))[0]

            if sig1 != 0x9AA2D903 or sig2 != 0xB54BFB67:
                parsed_data["error"] = "Invalid KDBX file signatures"
                return parsed_data

            # Read format version
            version = struct.unpack("<I", f.read(4))[0]
            parsed_data["format_version"] = version
            parsed_data["major_version"] = (version >> 16) & 0xFFFF
            parsed_data["minor_version"] = version & 0xFFFF

            # Parse header fields
            header_data = {}
            while True:
                # Read field ID (1 byte)
                field_id_bytes = f.read(1)
                if not field_id_bytes:  # EOF reached
                    break
                field_id = struct.unpack("<B", field_id_bytes)[0]

                # Read field size (4 bytes)
                field_size_bytes = f.read(4)
                if len(field_size_bytes) < 4:  # Not enough data
                    break
                field_size = struct.unpack("<I", field_size_bytes)[0]

                # Read field data
                field_data = f.read(field_size)
                if len(field_data) < field_size:  # Not enough data
                    break

                if field_id == 0:  # End of header
                    break
                elif field_id == 2:  # Encryption algorithm
                    if len(field_data) >= 16:
                        encryption_uuid = uuid.UUID(bytes=field_data[:16])
                        uuid_str = str(encryption_uuid)
                        parsed_data["encryption_algorithm"] = get_encryption_algorithm_name(uuid_str)
                elif field_id == 3:  # Compression algorithm
                    if len(field_data) >= 4:
                        compression = struct.unpack("<I", field_data[:4])[0]
                        parsed_data["compression_algorithm"] = "GZip" if compression == 1 else "None"
                elif field_id == 4:  # Master seed
                    parsed_data["master_seed"] = field_data.hex()
                elif field_id == 11:  # KDF parameters (KDBX 4.x)
                    kdf_params = parse_variant_dictionary(field_data)
                    if "$UUID" in kdf_params:
                        kdf_uuid = kdf_params["$UUID"]
                        if isinstance(kdf_uuid, bytes) and len(kdf_uuid) >= 16:
                            uuid_str = str(uuid.UUID(bytes=kdf_uuid[:16]))
                            parsed_data["kdf_algorithm"] = get_kdf_algorithm_name(uuid_str)
                    if "R" in kdf_params:
                        parsed_data["kdf_rounds"] = kdf_params["R"]
                    if "M" in kdf_params:
                        parsed_data["kdf_memory"] = kdf_params["M"]
                    if "P" in kdf_params:
                        parsed_data["kdf_parallelism"] = kdf_params["P"]
                    if "S" in kdf_params:
                        parsed_data["transform_seed"] = (
                            kdf_params["S"].hex() if isinstance(kdf_params["S"], bytes) else kdf_params["S"]
                        )
                elif field_id == 5:  # Transform seed (KDBX 3.x)
                    parsed_data["transform_seed"] = field_data.hex()
                elif field_id == 6:  # Transform rounds (KDBX 3.x)
                    if len(field_data) >= 8:
                        parsed_data["kdf_rounds"] = struct.unpack("<Q", field_data[:8])[0]

                header_data[field_id] = field_data

        # Generate hash for cracking
        try:
            hash_value = process_database(file_path)
            if hash_value:
                parsed_data["encryption_hash"] = hash_value.strip()
        except Exception as e:
            parsed_data["hash_error"] = f"Failed to generate hash: {str(e)}"

    except Exception as e:
        logger.exception(e, message="Error parsing KDBX file")
        parsed_data["error"] = f"Error parsing KDBX file: {str(e)}"

    return parsed_data


def parse_variant_dictionary(data: bytes) -> dict[str, Any]:
    """
    Parse a variant dictionary from KDBX format.

    Args:
        data (bytes): Raw variant dictionary data

    Returns:
        dict: Parsed variant dictionary
    """
    result = {}
    offset = 0

    try:
        # Read version
        if len(data) < 2:
            return result

        version = struct.unpack("<H", data[offset : offset + 2])[0]
        offset += 2

        while offset < len(data):
            if offset + 1 >= len(data):
                break

            # Read value type
            value_type = data[offset]
            offset += 1

            if value_type == 0:  # End marker
                break

            # Read name size
            if offset + 4 > len(data):
                break
            name_size = struct.unpack("<I", data[offset : offset + 4])[0]
            offset += 4

            # Read name
            if offset + name_size > len(data):
                break
            name = data[offset : offset + name_size].decode("utf-8", errors="ignore")
            offset += name_size

            # Read value size
            if offset + 4 > len(data):
                break
            value_size = struct.unpack("<I", data[offset : offset + 4])[0]
            offset += 4

            # Read value
            if offset + value_size > len(data):
                break
            value_data = data[offset : offset + value_size]
            offset += value_size

            # Parse value based on type
            if value_type == 0x04:  # UInt32
                if len(value_data) >= 4:
                    result[name] = struct.unpack("<I", value_data[:4])[0]
            elif value_type == 0x05:  # UInt64
                if len(value_data) >= 8:
                    result[name] = struct.unpack("<Q", value_data[:8])[0]
            elif value_type == 0x08:  # Bool
                if len(value_data) >= 1:
                    result[name] = value_data[0] != 0
            elif value_type == 0x0C:  # String
                result[name] = value_data.decode("utf-8", errors="ignore")
            elif value_type == 0x42:  # ByteArray
                result[name] = value_data
            else:
                result[name] = value_data

    except Exception as e:
        logger.exception(e, message="Error parsing variant dictionary")

    return result


class KDBXAnalyzer(EnrichmentModule):
    name: str = "kdbx_analyzer"
    dependencies: list[str] = []
    def __init__(self):
        self.storage = StorageMinio()
        # the workflows this module should automatically run in
        self.workflows = ["default"]

    async def should_process(self, object_id: str, file_path: str | None = None) -> bool:
        # Get the current file_enriched from the database backend
        file_enriched = await get_file_enriched_async(object_id)

        if file_enriched.magic_type:
            return "keepass" in file_enriched.magic_type.lower() and "kdbx" in file_enriched.magic_type.lower()
        else:
            return False

    def _analyze_kdbx(self, file_path: str, file_enriched) -> EnrichmentResult | None:
        """Analyze KDBX file and generate enrichment result.

        Args:
            file_path: Path to the KDBX file to analyze
            file_enriched: File enrichment data

        Returns:
            EnrichmentResult or None if analysis fails
        """

        analysis = parse_kdbx_file(file_path)

        enrichment_result = EnrichmentResult(module_name=self.name)
        enrichment_result.results = analysis

        if "encryption_hash" in enrichment_result.results and enrichment_result.results["encryption_hash"]:
            encryption_hash = enrichment_result.results["encryption_hash"]

            # Create summary with additional metadata
            summary_parts = ["# Encrypted KeePass Database\n"]
            summary_parts.append("The database is encrypted. Attempt to crack it using the following hash:\n")
            summary_parts.append(f"```\n{encryption_hash}\n```\n")

            # Add metadata if available
            if analysis.get("format_version"):
                summary_parts.append(f"**Format Version:** {analysis['major_version']}.{analysis['minor_version']}  \n")
            if analysis.get("encryption_algorithm"):
                summary_parts.append(f"**Encryption Algorithm:** {analysis['encryption_algorithm']}  \n")
            if analysis.get("kdf_algorithm"):
                summary_parts.append(f"**KDF Algorithm:** {analysis['kdf_algorithm']}  \n")
            if analysis.get("kdf_rounds"):
                summary_parts.append(f"**KDF Rounds:** {analysis['kdf_rounds']:,}  \n")
            if analysis.get("kdf_memory"):
                summary_parts.append(f"**KDF Memory:** {analysis['kdf_memory']:,} bytes  \n")
            if analysis.get("compression_algorithm"):
                summary_parts.append(f"**Compression:** {analysis['compression_algorithm']}  \n")

            summary_markdown = "".join(summary_parts)

            display_data = FileObject(type="finding_summary", metadata={"summary": summary_markdown})

            finding = Finding(
                category=FindingCategory.EXTRACTED_HASH,
                finding_name="encrypted_kdbx",
                origin_type=FindingOrigin.ENRICHMENT_MODULE,
                origin_name=self.name,
                object_id=file_enriched.object_id,
                severity=5,
                raw_data={"encryption_hash": encryption_hash},
                data=[display_data],
            )

            with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8") as tmp_display_file:
                tmp_display_file.write(summary_markdown)
                tmp_display_file.flush()

                object_id = self.storage.upload_file(tmp_display_file.name)

                displayable_parsed = Transform(
                    type="displayable_parsed",
                    object_id=f"{object_id}",
                    metadata={
                        "file_name": f"{file_enriched.file_name}.md",
                        "display_type_in_dashboard": "markdown",
                        "default_display": True,
                    },
                )

            enrichment_result.transforms = [displayable_parsed]
            enrichment_result.findings = [finding]

        return enrichment_result

    async def process(self, object_id: str, file_path: str | None = None) -> EnrichmentResult | None:
        """Process KDBX file and extract encryption information.

        Args:
            object_id: The object ID of the file
            file_path: Optional path to already downloaded file

        Returns:
            EnrichmentResult or None if processing fails
        """
        try:
            # get the current `file_enriched` from the database backend
            file_enriched = await get_file_enriched_async(object_id)

            # Use provided file_path if available, otherwise download
            if file_path:
                return self._analyze_kdbx(file_path, file_enriched)
            else:
                with self.storage.download(file_enriched.object_id) as file:
                    return self._analyze_kdbx(file.name, file_enriched)

        except Exception as e:
            logger.exception(e, message="Error processing KDBX file")
            return None


def create_enrichment_module() -> EnrichmentModule:
    return KDBXAnalyzer()
