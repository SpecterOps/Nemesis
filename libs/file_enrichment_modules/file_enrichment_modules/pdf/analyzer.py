# enrichment_modules/pdf/analyzer.py
import xml.etree.ElementTree as ET
from datetime import datetime
from typing import Any

import fitz  # PyMuPDF
from common.logger import get_logger
from common.models import EnrichmentResult, FileObject, Finding, FindingCategory, FindingOrigin
from common.state_helpers import get_file_enriched_async
from common.storage import StorageMinio
from file_enrichment_modules.module_loader import EnrichmentModule
from file_enrichment_modules.pdf.pdf2john import PdfParser

logger = get_logger(__name__)


def parse_xmp_to_structured_data(xmp_xml: str | None) -> dict[str, Any]:
    """
    Extract structured metadata from XMP XML.

    This function reduces XMP storage size from 1MB+ to ~700 bytes (99.9% reduction)
    while preserving critical metadata fields for forensic analysis.

    Args:
        xmp_xml: Full XMP metadata XML string (or None)

    Returns:
        Dictionary with extracted fields and statistics
    """
    result = {
        # Core identification
        "document_id": None,
        "instance_id": None,
        "original_document_id": None,
        # Creator/tool information
        "creator_tool": None,
        "producer": None,
        "format": None,
        # Dates (ISO 8601 format)
        "create_date": None,
        "modify_date": None,
        "metadata_date": None,
        # Document properties
        "trapped": None,
        "rendition_class": None,
        # Statistics (counts instead of full data)
        "history_event_count": 0,
        "manifest_item_count": 0,
        "font_count": 0,
        "color_swatch_count": 0,
        "embedded_image_count": 0,
        # XMP metadata about itself
        "xmp_size_bytes": 0,
        "namespace_count": 0,
    }

    if not xmp_xml:
        return result

    result["xmp_size_bytes"] = len(xmp_xml)

    try:
        root = ET.fromstring(xmp_xml)

        # Count unique namespaces
        unique_namespaces = set()
        for elem in root.iter():
            if "}" in elem.tag:
                namespace = elem.tag.split("}")[0][1:]
                unique_namespaces.add(namespace)
        result["namespace_count"] = len(unique_namespaces)

        # Extract text content from key elements
        field_map = {
            "DocumentID": "document_id",
            "InstanceID": "instance_id",
            "OriginalDocumentID": "original_document_id",
            "CreatorTool": "creator_tool",
            "Producer": "producer",
            "CreateDate": "create_date",
            "ModifyDate": "modify_date",
            "MetadataDate": "metadata_date",
            "Trapped": "trapped",
            "RenditionClass": "rendition_class",
        }

        for elem in root.iter():
            tag_name = elem.tag.split("}")[-1] if "}" in elem.tag else elem.tag

            # Extract text values
            if tag_name in field_map and elem.text and elem.text.strip():
                result_key = field_map[tag_name]
                if not result[result_key]:
                    result[result_key] = elem.text.strip()

            # Extract format (might be in dc:format element)
            if tag_name == "format" and elem.text and elem.text.strip():
                if elem.text.strip() == "application/pdf":
                    result["format"] = elem.text.strip()

        # Count history events
        history_events = [e for e in root.iter() if e.tag.endswith("action")]
        result["history_event_count"] = len(history_events)

        # Count manifest items
        manifest_items = [e for e in root.iter() if e.tag.endswith("documentID") and e.text]
        result["manifest_item_count"] = len([m for m in manifest_items if m.text and m.text.startswith("xmp.")])

        # Count fonts
        font_names = [e for e in root.iter() if e.tag.endswith("fontName")]
        result["font_count"] = len(font_names)

        # Count color swatches
        swatches = [e for e in root.iter() if e.tag.endswith("swatchName")]
        result["color_swatch_count"] = len(swatches)

        # Count embedded images
        images = [e for e in root.iter() if e.tag.endswith("image") and e.text]
        result["embedded_image_count"] = len([img for img in images if img.text and len(img.text) > 100])

    except ET.ParseError:
        result["parse_error"] = "XML parsing failed"
    except Exception as e:
        result["parse_error"] = str(e)

    return result


def _get_pdf_version(doc: fitz.Document, file_path: str) -> str | None:
    """Extract PDF version from document metadata or file header.

    Args:
        doc: PyMuPDF document object
        file_path: Path to the PDF file

    Returns:
        PDF version string (e.g., "1.7") or None if not found
    """
    try:
        # Try to get version from metadata
        if doc.metadata and doc.metadata.get("format"):
            format_str = doc.metadata["format"]
            if format_str.startswith("PDF "):
                return format_str.split(" ")[1]

        # For encrypted PDFs, metadata may be None, so read version from file header
        with open(file_path, "rb") as f:
            header = f.read(20)
            if header.startswith(b"%PDF-"):
                return header[5:8].decode("ascii")
    except Exception as e:
        logger.debug(f"Could not extract PDF version: {e}")

    return None


def _extract_basic_metadata(doc: fitz.Document) -> dict[str, Any]:
    """Extract basic metadata from unencrypted PDF.

    Args:
        doc: PyMuPDF document object

    Returns:
        Dictionary with title, author, subject, creator, producer, keywords, trapped
    """
    metadata = {
        "title": None,
        "author": None,
        "subject": None,
        "creator": None,
        "producer": None,
        "created": None,
        "modified": None,
        "keywords": None,
        "trapped": None,
        "encryption_method": None,
    }

    try:
        meta = doc.metadata
        if not meta:
            return metadata

        metadata["title"] = meta.get("title", None) or None
        metadata["author"] = meta.get("author", None) or None
        metadata["subject"] = meta.get("subject", None) or None
        metadata["creator"] = meta.get("creator", None) or None
        metadata["producer"] = meta.get("producer", None) or None
        metadata["keywords"] = meta.get("keywords", None) or None
        metadata["trapped"] = meta.get("trapped", None) or None
        metadata["encryption_method"] = meta.get("encryption", None)

        # Handle creation date
        if "creationDate" in meta and meta["creationDate"]:
            try:
                date_str = meta["creationDate"]
                if date_str.startswith("D:"):
                    date_str = date_str[2:]
                if len(date_str) >= 14:
                    metadata["created"] = datetime.strptime(date_str[:14], "%Y%m%d%H%M%S").isoformat()
                else:
                    metadata["created"] = date_str
            except Exception:
                metadata["created"] = meta["creationDate"]

        # Handle modification date
        if "modDate" in meta and meta["modDate"]:
            try:
                date_str = meta["modDate"]
                if date_str.startswith("D:"):
                    date_str = date_str[2:]
                if len(date_str) >= 14:
                    metadata["modified"] = datetime.strptime(date_str[:14], "%Y%m%d%H%M%S").isoformat()
                else:
                    metadata["modified"] = date_str
            except Exception:
                metadata["modified"] = meta["modDate"]

    except Exception as e:
        logger.debug(f"Error extracting basic metadata: {e}")

    return metadata


def _extract_page_info(doc: fitz.Document) -> dict[str, Any]:
    """Extract page size and rotation from first page.

    Args:
        doc: PyMuPDF document object

    Returns:
        Dictionary with page_size and page_rotation, or empty dict if extraction fails
    """
    page_info = {}

    try:
        if doc.page_count > 0:
            first_page = doc[0]
            rect = first_page.rect
            page_info["page_size"] = {"width": round(rect.width, 2), "height": round(rect.height, 2), "unit": "points"}
            page_info["page_rotation"] = first_page.rotation
    except Exception as e:
        logger.debug(f"Error extracting page info: {e}")

    return page_info


def _detect_pdf_a(doc: fitz.Document) -> bool:
    """Detect if PDF is PDF/A compliant.

    Args:
        doc: PyMuPDF document object

    Returns:
        True if PDF/A compliant, False otherwise
    """
    try:
        xref_stream = doc.xref_stream(1)
        if xref_stream and b"PDF/A" in xref_stream:
            return True
    except Exception as e:
        logger.debug(f"Error detecting PDF/A: {e}")

    return False


def _detect_table_of_contents(doc: fitz.Document) -> bool:
    """Detect if PDF has a table of contents.

    Args:
        doc: PyMuPDF document object

    Returns:
        True if TOC exists, False otherwise
    """
    try:
        toc = doc.get_toc()
        return bool(toc)
    except Exception as e:
        # get_toc() raises ValueError on encrypted PDFs
        logger.debug(f"Error detecting TOC: {e}")

    return False


def _extract_xmp_metadata(doc: fitz.Document) -> dict[str, Any] | None:
    """Extract and parse XMP metadata to structured format.

    Args:
        doc: PyMuPDF document object

    Returns:
        Parsed XMP summary dictionary or None if extraction fails
    """
    try:
        xmp_meta = doc.get_xml_metadata()
        if xmp_meta:
            return parse_xmp_to_structured_data(xmp_meta)
    except Exception as e:
        logger.debug(f"Error extracting XMP metadata: {e}")

    return None


def _count_images(doc: fitz.Document) -> int:
    """Count total images across all pages.

    Args:
        doc: PyMuPDF document object

    Returns:
        Total number of images, or 0 if counting fails
    """
    try:
        total_images = 0
        for page_num in range(doc.page_count):
            images = doc.get_page_images(page_num)
            total_images += len(images)
        return total_images
    except Exception as e:
        # get_page_images() raises ValueError on encrypted PDFs
        logger.debug(f"Error counting images: {e}")

    return 0


def _extract_embedded_files(doc: fitz.Document) -> list[dict[str, Any]]:
    """Extract information about embedded files.

    Args:
        doc: PyMuPDF document object

    Returns:
        List of embedded file dictionaries
    """
    embedded_files = []

    try:
        embfile_names = doc.embfile_names()
        if embfile_names:
            for i, name in enumerate(embfile_names):
                try:
                    info = doc.embfile_info(i)
                    embedded_files.append(
                        {
                            "name": name,
                            "filename": info.get("filename"),
                            "ufilename": info.get("ufilename"),
                            "description": info.get("desc"),
                            "size": info.get("size"),
                            "creation_date": info.get("creationDate"),
                            "modification_date": info.get("modDate"),
                        }
                    )
                except Exception:
                    # If we can't get info, at least record the name
                    embedded_files.append({"name": name})
    except Exception as e:
        logger.debug(f"Error extracting embedded files: {e}")

    return embedded_files


def _detect_signatures(doc: fitz.Document) -> bool:
    """Detect if PDF has digital signatures.

    Args:
        doc: PyMuPDF document object

    Returns:
        True if signatures are detected, False otherwise
    """
    try:
        sigflags = doc.get_sigflags()
        return sigflags >= 0
    except Exception as e:
        logger.debug(f"Error detecting signatures: {e}")

    return False


def _extract_encryption_info(doc: fitz.Document, file_path: str) -> dict[str, Any]:
    """Extract encryption hash for encrypted PDFs.

    Args:
        doc: PyMuPDF document object
        file_path: Path to the PDF file

    Returns:
        Dictionary with encryption_hash and encryption_method
    """
    encryption_info = {
        "encryption_hash": None | str,
        "encryption_method": None,
    }

    try:
        # Extract encryption hash using pdf2john
        parser = PdfParser(file_path)
        try:
            hash_value = parser.parse()
            if hash_value:
                encryption_info["encryption_hash"] = hash_value.strip()
        except Exception as e:
            logger.debug(f"Failed to extract encryption hash: {e}")

        # Extract encryption method from metadata if available
        if doc.metadata and doc.metadata.get("encryption"):
            encryption_info["encryption_method"] = doc.metadata["encryption"]

    except Exception as e:
        logger.debug(f"Error extracting encryption info: {e}")

    return encryption_info


def parse_pdf_file(file_path: str) -> dict[str, Any]:
    """
    Parse a PDF file and return its metadata and encryption information.

    This function is now more robust with smaller helper functions that won't
    break all parsing if one component fails.

    Args:
        file_path (str): Path to the PDF file

    Returns:
        Dict[str, Any]: Dictionary containing parsed PDF data
    """

    # Initialize return dictionary with default values so we always have these keys present
    parsed_data = {
        "is_encrypted": False,
        "encryption_hash": None,
        "num_pages": None,
        "pdf_version": None,
        "page_size": None,
        "page_layout": None,
        "page_mode": None,
        "language": None,
        "is_pdf_a": False,
        "is_linearized": False,
        "is_repaired": False,
        "has_embedded_files": False,
        "has_forms": False,
        "has_signatures": False,
        "has_table_of_contents": False,
        "permissions": None,
        "page_rotation": None,
        "xmp_summary": None,  # Structured XMP data instead of full XML
        "embedded_files": [],
        "total_images": 0,
        "metadata": {
            "title": None,
            "author": None,
            "subject": None,
            "creator": None,
            "producer": None,
            "created": None,
            "modified": None,
            "keywords": None,
            "trapped": None,
            "encryption_method": None,
        },
    }

    try:
        # Attempt to open the PDF file
        try:
            doc = fitz.open(file_path)
        except fitz.FileDataError as e:
            # Handle corrupted, truncated, or invalid PDF files
            logger.warning(f"Unable to open PDF file (corrupted/truncated/invalid): {file_path}", exc_info=False)
            parsed_data["error"] = f"Corrupted or invalid PDF file: {str(e)}"
            parsed_data["parse_status"] = "failed_to_open"
            return parsed_data
        except Exception as e:
            # Handle other file opening errors
            logger.error(f"Unexpected error opening PDF file: {file_path}", exc_info=True)
            parsed_data["error"] = f"Failed to open PDF: {str(e)}"
            parsed_data["parse_status"] = "failed_to_open"
            return parsed_data

        # Extract basic information (works for both encrypted and unencrypted)
        try:
            parsed_data["is_encrypted"] = doc.is_encrypted
            parsed_data["num_pages"] = doc.page_count
            parsed_data["pdf_version"] = _get_pdf_version(doc, file_path)
            parsed_data["is_linearized"] = bool(doc.is_fast_webaccess)
            parsed_data["has_embedded_files"] = doc.embfile_count() > 0
            parsed_data["is_repaired"] = doc.is_repaired
        except Exception as e:
            logger.debug(f"Error extracting basic PDF properties: {e}")

        # Extract document-level properties (works for both encrypted and unencrypted)
        try:
            parsed_data["page_layout"] = doc.pagelayout if doc.pagelayout else None
            parsed_data["page_mode"] = doc.pagemode if doc.pagemode else None
            parsed_data["language"] = doc.language if doc.language else None
        except Exception as e:
            logger.debug(f"Error extracting document properties: {e}")

        # Extract signatures (works for both encrypted and unencrypted)
        parsed_data["has_signatures"] = _detect_signatures(doc)

        # Extract embedded files (works for both encrypted and unencrypted)
        parsed_data["embedded_files"] = _extract_embedded_files(doc)

        if parsed_data["is_encrypted"]:
            # Handle encrypted PDFs
            encryption_info = _extract_encryption_info(doc, file_path)
            parsed_data["encryption_hash"] = encryption_info["encryption_hash"]
            parsed_data["metadata"]["encryption_method"] = encryption_info["encryption_method"]
        else:
            # Handle unencrypted PDFs - extract detailed metadata
            parsed_data["metadata"] = _extract_basic_metadata(doc)

            # Extract page information
            page_info = _extract_page_info(doc)
            parsed_data["page_size"] = page_info.get("page_size")
            parsed_data["page_rotation"] = page_info.get("page_rotation")

            # Detect various PDF features (only for unencrypted PDFs)
            parsed_data["has_forms"] = doc.is_form_pdf > 0
            parsed_data["is_pdf_a"] = _detect_pdf_a(doc)
            parsed_data["has_table_of_contents"] = _detect_table_of_contents(doc)

            # Extract XMP metadata (only for unencrypted PDFs)
            parsed_data["xmp_summary"] = _extract_xmp_metadata(doc)

            # Count images (only for unencrypted PDFs)
            parsed_data["total_images"] = _count_images(doc)

        doc.close()
        parsed_data["parse_status"] = "success"

    except Exception as e:
        logger.exception(message="Unexpected error parsing PDF", path=file_path)
        parsed_data["error"] = f"Error parsing PDF file: {str(e)}"
        parsed_data["parse_status"] = "failed"

    return parsed_data


class PDFAnalyzer(EnrichmentModule):
    name: str = "pdf_analyzer"
    dependencies: list[str] = []

    def __init__(self):
        self.storage = StorageMinio()

        self.asyncpg_pool = None  # type: ignore
        # the workflows this module should automatically run in
        self.workflows = ["default"]

    async def should_process(self, object_id: str, file_path: str | None = None) -> bool:
        # Get the current file_enriched from the database backend
        file_enriched = await get_file_enriched_async(object_id, self.asyncpg_pool)
        return "pdf document" in file_enriched.magic_type.lower()

    def _analyze_pdf(self, file_path: str, file_enriched) -> EnrichmentResult | None:
        """Analyze PDF file and generate enrichment result.

        Args:
            file_path: Path to the PDF file to analyze
            file_enriched: File enrichment data

        Returns:
            EnrichmentResult or None if analysis fails
        """
        try:
            analysis = parse_pdf_file(file_path)

            enrichment_result = EnrichmentResult(module_name=self.name)
            enrichment_result.results = analysis

            if "encryption_hash" in enrichment_result.results and enrichment_result.results["encryption_hash"]:
                encryption_hash = enrichment_result.results["encryption_hash"]
                summary_markdown = f"""
# Encrypted PDF
The document is encrypted. Attempt to crack it using the following hash:
```
{encryption_hash}
```
"""
                display_data = FileObject(type="finding_summary", metadata={"summary": summary_markdown})

                finding = Finding(
                    category=FindingCategory.EXTRACTED_HASH,
                    finding_name="encrypted_pdf",
                    origin_type=FindingOrigin.ENRICHMENT_MODULE,
                    origin_name=self.name,
                    object_id=file_enriched.object_id,
                    severity=5,
                    raw_data={"encryption_hash": encryption_hash},
                    data=[display_data],
                )

                if not enrichment_result.findings:
                    enrichment_result.findings = []

                enrichment_result.findings.append(finding)

            return enrichment_result

        except Exception:
            logger.exception(message=f"Error analyzing PDF file for {file_enriched.file_name}")
            return None

    async def process(self, object_id: str, file_path: str | None = None) -> EnrichmentResult | None:
        """Process PDF file.

        Args:
            object_id: The object ID of the file
            file_path: Optional path to already downloaded file

        Returns:
            EnrichmentResult or None if processing fails
        """
        try:
            # get the current `file_enriched` from the database backend
            file_enriched = await get_file_enriched_async(object_id, self.asyncpg_pool)

            # Use provided file_path if available, otherwise download
            if file_path:
                return self._analyze_pdf(file_path, file_enriched)
            else:
                with self.storage.download(file_enriched.object_id) as file:
                    return self._analyze_pdf(file.name, file_enriched)

        except Exception:
            logger.exception(message="Error processing PDF file")
            return None


def create_enrichment_module() -> EnrichmentModule:
    return PDFAnalyzer()
