# enrichment_modules/office_doc/analyzer.py
import datetime
import tempfile
import xml.dom.minidom
import zipfile
from typing import Any

import msoffcrypto
import olefile
import structlog
from common.models import EnrichmentResult, FileObject, Finding, FindingCategory, FindingOrigin, Transform
from common.state_helpers import get_file_enriched
from common.storage import StorageMinio
from file_enrichment_modules.module_loader import EnrichmentModule
from file_enrichment_modules.office_doc.office2john import extract_file_encryption_hash
from oletools.olevba import VBA_Parser

logger = structlog.get_logger(module=__name__)


def create_encryption_finding(file_enriched, encryption_hash: str, module_name: str) -> Finding:
    """Create a standardized finding for encrypted Office documents."""
    summary_markdown = f"""
# Encrypted Document
The document is encrypted. Attempt to crack it using the following hash:
```
{encryption_hash}
```
"""
    display_data = FileObject(type="finding_summary", metadata={"summary": summary_markdown})

    return Finding(
        category=FindingCategory.EXTRACTED_HASH,
        finding_name="encrypted_office_document",
        origin_type=FindingOrigin.ENRICHMENT_MODULE,
        origin_name=module_name,
        object_id=file_enriched.object_id,
        severity=5,
        raw_data={"encryption_hash": encryption_hash},
        data=[display_data],
    )


def create_macro_finding(file_enriched, macro_count: int, module_name: str) -> Finding:
    """Create a standardized finding for documents containing macros."""
    summary_markdown = f"""
# Macro Detected
The document contains {macro_count} macro(s). Macros can potentially contain malicious code.

Review the extracted macro code in the document transforms for analysis.
"""
    display_data = FileObject(type="finding_summary", metadata={"summary": summary_markdown})

    return Finding(
        category=FindingCategory.MISC,
        finding_name="macro_detected",
        origin_type=FindingOrigin.ENRICHMENT_MODULE,
        origin_name=module_name,
        object_id=file_enriched.object_id,
        severity=3,
        raw_data={"macro_count": macro_count},
        data=[display_data],
    )


def create_rms_protection_finding(file_enriched, module_name: str) -> Finding:
    """Create a standardized finding for RMS protected Office documents."""
    summary_markdown = """
# RMS Protected Document
The document is likely protected by a Rights Management System.

Analyze any file in [0]DataSpaces/TransformInfo/DRMEncryptedTransform/* for more information.
"""
    display_data = FileObject(type="finding_summary", metadata={"summary": summary_markdown})

    return Finding(
        category=FindingCategory.MISC,
        finding_name="rms_protected",
        origin_type=FindingOrigin.ENRICHMENT_MODULE,
        origin_name=module_name,
        object_id=file_enriched.object_id,
        severity=4,
        raw_data={},
        data=[display_data],
    )


def check_encryption(file_path: str) -> tuple[bool, str | None]:
    """Check if an Office file is encrypted and return its hash if present."""

    is_encrypted = False
    enc_hash = None

    with open(file_path, "rb") as f:
        try:
            office_file = msoffcrypto.OfficeFile(f)
            is_encrypted = office_file.is_encrypted()
        except:
            pass

    if is_encrypted:
        enc_hash = extract_file_encryption_hash(file_path)
        is_encrypted = bool(enc_hash and enc_hash.startswith("$o"))

    return is_encrypted, enc_hash if is_encrypted else None


def check_rms_protected(file_path):
    """Check if a file is RMS protected by looking for the DRMEncryptedTransform folder"""
    try:
        with zipfile.ZipFile(file_path, "r") as zip_ref:
            file_list = zip_ref.namelist()

            # Check for the specific folder path that indicates RMS protection
            for file in file_list:
                if "DRMEncryptedTransform" in file:
                    return True

    except:
        pass

    # Try OLE approach if ZIP check failed or returned False
    try:
        if olefile.isOleFile(file_path):
            ole = olefile.OleFileIO(file_path)
            if ole.exists("\x06DataSpaces/TransformInfo/DRMEncryptedTransform"):
                return True
            ole.close()
    except:
        pass

    return False


def extract_macros(file_path: str) -> list[dict[str, Any]]:
    """Extract macro code from Office documents."""
    macros = []

    try:
        vba_parser = VBA_Parser(file_path)
        if vba_parser.detect_vba_macros():
            for filename, stream_path, vba_filename, vba_code in vba_parser.extract_macros():
                if vba_code:
                    macros.append(
                        {
                            "filename": filename,
                            "stream_path": stream_path,
                            "vba_filename": vba_filename,
                            "vba_code": vba_code,
                        }
                    )
        vba_parser.close()
    except Exception as e:
        logger.warning("Error extracting macros", error=str(e), file_path=file_path)

    return macros


def parse_office_ole_file(file_path: str) -> dict[str, Any]:
    """
    Parse an OLE Office file (doc, xls, ppt) and return its metadata.
    """
    parsed_data = {
        "is_encrypted": False,
        "encryption_hash": None,
        "is_rms_protected": False,
        "title": None,
        "creator": None,
        "created": None,
        "modified": None,
        "keywords": None,
        "comments": None,
        "last_modified_by": None,
        "subject": None,
        "creating_application": None,
        "total_edit_time": None,
        "num_pages": None,
        "num_slides": None,
        "num_chars": None,
        "has_macros": False,
        "macros": [],
    }

    try:
        # Check encryption first
        is_encrypted, enc_hash = check_encryption(file_path)

        if is_encrypted:
            parsed_data["is_encrypted"] = True
            parsed_data["encryption_hash"] = enc_hash
            return parsed_data

        if check_rms_protected(file_path):
            parsed_data["is_rms_protected"] = True
            # return parsed_data

        if not olefile.isOleFile(file_path):
            parsed_data["error"] = "Not a valid OLE format file"
            return parsed_data

        with olefile.OleFileIO(file_path) as ole:
            meta = ole.get_metadata()

            # Map metadata fields with proper decoding
            metadata_fields = {
                "title": ("title", str),
                "creator": ("author", str),
                "keywords": ("keywords", str),
                "comments": ("comments", str),
                "last_modified_by": ("last_saved_by", str),
                "subject": ("subject", str),
                "creating_application": ("creating_application", str),
            }

            for field, (meta_attr, type_converter) in metadata_fields.items():
                try:
                    value = getattr(meta, meta_attr).decode("utf-8")
                    parsed_data[field] = type_converter(value) if value else None
                except (AttributeError, UnicodeDecodeError):
                    continue

            # Handle numeric fields
            numeric_fields = ["total_edit_time", "num_pages", "num_slides", "num_chars"]
            for field in numeric_fields:
                try:
                    parsed_data[field] = getattr(meta, field)
                except AttributeError:
                    continue

            # Handle dates
            try:
                parsed_data["created"] = meta.create_time.isoformat() if meta.create_time else None
                parsed_data["modified"] = meta.last_saved_time.isoformat() if meta.last_saved_time else None
            except AttributeError:
                pass

            # Extract macros if not encrypted
            if not parsed_data["is_encrypted"]:
                macros = extract_macros(file_path)
                parsed_data["has_macros"] = len(macros) > 0
                parsed_data["macros"] = macros

    except Exception as e:
        logger.exception(e, message="Error parsing Office OLE file")
        parsed_data["error"] = f"Error parsing Office OLE file: {str(e)}"

    return parsed_data


def parse_office_new_file(file_path: str) -> dict[str, Any]:
    """
    Parse a new Office file (docx, xlsx, pptx) and return its metadata.
    """
    parsed_data = {
        "is_encrypted": False,
        "encryption_hash": None,
        "is_rms_protected": False,
        "title": None,
        "subject": None,
        "creator": None,
        "keywords": None,
        "description": None,
        "last_modified_by": None,
        "revision": None,
        "created": None,
        "modified": None,
        "has_macros": False,
        "macros": [],
    }

    try:
        # Check encryption first
        is_encrypted, enc_hash = check_encryption(file_path)
        if is_encrypted:
            parsed_data["is_encrypted"] = True
            parsed_data["encryption_hash"] = enc_hash
            return parsed_data

        if check_rms_protected(file_path):
            parsed_data["is_rms_protected"] = True

        # If not encrypted, extract metadata
        with zipfile.ZipFile(file_path, "r") as myFile:
            doc = xml.dom.minidom.parseString(myFile.read("docProps/core.xml"))

            # Extract metadata fields
            metadata_fields = {
                "title": ("dc:title", str),
                "subject": ("dc:subject", str),
                "creator": ("dc:creator", str),
                "keywords": ("cp:keywords", str),
                "description": ("dc:description", str),
                "last_modified_by": ("cp:lastModifiedBy", str),
                "revision": ("cp:revision", int),
            }

            for field, (tag, type_converter) in metadata_fields.items():
                try:
                    value = doc.getElementsByTagName(tag)[0].childNodes[0].data
                    parsed_data[field] = type_converter(value) if value else None
                except (IndexError, AttributeError):
                    continue

            # Handle dates
            for date_field, tag in [("created", "dcterms:created"), ("modified", "dcterms:modified")]:
                try:
                    date_string = doc.getElementsByTagName(tag)[0].childNodes[0].data
                    dt = datetime.datetime.strptime(date_string, "%Y-%m-%dT%H:%M:%Sz")
                    parsed_data[date_field] = dt.isoformat()
                except (IndexError, AttributeError, ValueError):
                    continue

            # Extract macros if not encrypted
            if not parsed_data["is_encrypted"]:
                macros = extract_macros(file_path)
                parsed_data["has_macros"] = len(macros) > 0
                parsed_data["macros"] = macros

    except Exception as e:
        logger.exception(e, message="Error parsing new Office file")
        parsed_data["error"] = f"Error parsing Office file: {str(e)}"

    return parsed_data


class OfficeAnalyzer(EnrichmentModule):
    def __init__(self):
        super().__init__("office_analyzer")
        self.storage = StorageMinio()
        # the workflows this module should automatically run in
        self.workflows = ["default"]

    def should_process(self, object_id: str, file_path: str | None = None) -> bool:
        """Determine if this module should run based on file extension and type."""
        file_enriched = get_file_enriched(object_id)

        # Check file extension
        path = file_enriched.path.lower() if file_enriched.path else ""
        valid_extensions = (".doc", ".docx", ".ppt", ".pptx", ".xls", ".xlsx")
        has_valid_extension = any(path.endswith(ext) for ext in valid_extensions)

        # Check magic type (if available)
        magic_type = file_enriched.magic_type.lower() if file_enriched.magic_type else ""
        is_office_type = any(
            office_type in magic_type for office_type in ["word", "excel", "powerpoint", "composite document"]
        )

        should_run = has_valid_extension or is_office_type
        return should_run

    def _analyze_office_document(self, file_path: str, file_enriched) -> EnrichmentResult | None:
        """Analyze Office document and generate enrichment result.

        Args:
            file_path: Path to the Office document to analyze
            file_enriched: File enrichment data

        Returns:
            EnrichmentResult or None if analysis fails
        """
        enrichment_result = EnrichmentResult(module_name=self.name)

        try:
            # Determine file type and use appropriate parser
            if "openxmlformats" in file_enriched.mime_type.lower():
                analysis = parse_office_new_file(file_path)
            else:
                analysis = parse_office_ole_file(file_path)

            enrichment_result.results = analysis

            findings = []
            # transforms = []

            # Create finding if document is encrypted
            if analysis.get("encryption_hash"):
                finding = create_encryption_finding(file_enriched, analysis["encryption_hash"], self.name)
                findings.append(finding)

            if analysis.get("is_rms_protected"):
                finding = create_rms_protection_finding(file_enriched, self.name)
                findings.append(finding)

            # Create transforms and finding for macros
            if analysis.get("has_macros") and analysis.get("macros"):
                macros = analysis["macros"]

                macro_text = ""

                for i, macro in enumerate(macros):
                    stream_path = macro["stream_path"]
                    macro_text += f"'Macro: {stream_path}\n"
                    macro_text += macro["vba_code"] + "\n\n"

                with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8") as tmp_display_file:
                    tmp_display_file.write(macro_text)
                    tmp_display_file.flush()
                    object_id = self.storage.upload_file(tmp_display_file.name)

                    displayable_parsed = Transform(
                        type="extracted_macros",
                        object_id=f"{object_id}",
                        metadata={"file_name": "macros.vb", "display_type_in_dashboard": "monaco"},
                    )
                    enrichment_result.transforms = [displayable_parsed]

                # Create finding for macro detection
                macro_finding = create_macro_finding(file_enriched, len(macros), self.name)
                findings.append(macro_finding)

            enrichment_result.findings = findings

            return enrichment_result

        except Exception as e:
            logger.exception(e, message=f"Error analyzing Office document for {file_enriched.file_name}")
            return None

    def process(self, object_id: str, file_path: str | None = None) -> EnrichmentResult | None:
        """Process Office file using the storage system.

        Args:
            object_id: The object ID of the file
            file_path: Optional path to already downloaded file

        Returns:
            EnrichmentResult or None if processing fails
        """
        try:
            file_enriched = get_file_enriched(object_id)

            # Use provided file_path if available, otherwise download
            if file_path:
                return self._analyze_office_document(file_path, file_enriched)
            else:
                with self.storage.download(file_enriched.object_id) as file:
                    return self._analyze_office_document(file.name, file_enriched)

        except Exception as e:
            logger.exception(e, message="Error processing Office file")
            return None


def create_enrichment_module() -> EnrichmentModule:
    return OfficeAnalyzer()
