# enrichment_modules/pdf/analyzer.py
import xml.etree.ElementTree as ET
from datetime import datetime
from typing import Any, Optional

import fitz  # PyMuPDF
from common.logger import get_logger
from common.models import EnrichmentResult, FileObject, Finding, FindingCategory, FindingOrigin
from common.state_helpers import get_file_enriched_async
from common.storage import StorageMinio
from file_enrichment_modules.module_loader import EnrichmentModule
from file_enrichment_modules.pdf.pdf2john import PdfParser

logger = get_logger(__name__)


def parse_xmp_to_structured_data(xmp_xml: Optional[str]) -> dict[str, Any]:
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
            if '}' in elem.tag:
                namespace = elem.tag.split('}')[0][1:]
                unique_namespaces.add(namespace)
        result["namespace_count"] = len(unique_namespaces)

        # Extract text content from key elements
        field_map = {
            'DocumentID': 'document_id',
            'InstanceID': 'instance_id',
            'OriginalDocumentID': 'original_document_id',
            'CreatorTool': 'creator_tool',
            'Producer': 'producer',
            'CreateDate': 'create_date',
            'ModifyDate': 'modify_date',
            'MetadataDate': 'metadata_date',
            'Trapped': 'trapped',
            'RenditionClass': 'rendition_class',
        }

        for elem in root.iter():
            tag_name = elem.tag.split('}')[-1] if '}' in elem.tag else elem.tag

            # Extract text values
            if tag_name in field_map and elem.text and elem.text.strip():
                result_key = field_map[tag_name]
                if not result[result_key]:
                    result[result_key] = elem.text.strip()

            # Extract format (might be in dc:format element)
            if tag_name == 'format' and elem.text and elem.text.strip():
                if elem.text.strip() == 'application/pdf':
                    result["format"] = elem.text.strip()

        # Count history events
        history_events = [e for e in root.iter() if e.tag.endswith('action')]
        result["history_event_count"] = len(history_events)

        # Count manifest items
        manifest_items = [e for e in root.iter() if e.tag.endswith('documentID') and e.text]
        result["manifest_item_count"] = len([m for m in manifest_items if m.text and m.text.startswith('xmp.')])

        # Count fonts
        font_names = [e for e in root.iter() if e.tag.endswith('fontName')]
        result["font_count"] = len(font_names)

        # Count color swatches
        swatches = [e for e in root.iter() if e.tag.endswith('swatchName')]
        result["color_swatch_count"] = len(swatches)

        # Count embedded images
        images = [e for e in root.iter() if e.tag.endswith('image') and e.text]
        result["embedded_image_count"] = len([img for img in images if img.text and len(img.text) > 100])

    except ET.ParseError:
        result["parse_error"] = "XML parsing failed"
    except Exception as e:
        result["parse_error"] = str(e)

    return result


def parse_pdf_file(file_path: str) -> dict[str, Any]:
    """
    Parse a PDF file and return its metadata and encryption information.

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
        "has_javascript": False,
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
        }
    }

    try:
        doc = fitz.open(file_path)
        parsed_data["is_encrypted"] = doc.is_encrypted
        parsed_data["num_pages"] = doc.page_count

        # Extract PDF version from metadata format field
        if doc.metadata and doc.metadata.get("format"):
            format_str = doc.metadata["format"]
            if format_str.startswith("PDF "):
                parsed_data["pdf_version"] = format_str.split(" ")[1]
        else:
            # For encrypted PDFs, metadata may be None, so read version from file header
            try:
                with open(file_path, 'rb') as f:
                    header = f.read(20)
                    if header.startswith(b'%PDF-'):
                        parsed_data["pdf_version"] = header[5:8].decode('ascii')
            except Exception:
                pass

        parsed_data["is_linearized"] = bool(doc.is_fast_webaccess)
        parsed_data["has_embedded_files"] = doc.embfile_count() > 0
        parsed_data["is_repaired"] = doc.is_repaired

        # Extract document-level properties
        parsed_data["page_layout"] = doc.pagelayout if doc.pagelayout else None
        parsed_data["page_mode"] = doc.pagemode if doc.pagemode else None
        parsed_data["language"] = doc.language if doc.language else None

        # Extract digital signature information (works on both encrypted and unencrypted PDFs)
        try:
            sigflags = doc.get_sigflags()
            parsed_data["has_signatures"] = sigflags >= 0
        except Exception:
            pass

        # Extract embedded file details (works on both encrypted and unencrypted PDFs)
        try:
            embfile_names = doc.embfile_names()
            if embfile_names:
                embedded_files_list = []
                for i, name in enumerate(embfile_names):
                    try:
                        info = doc.embfile_info(i)
                        embedded_files_list.append({
                            "name": name,
                            "filename": info.get("filename"),
                            "ufilename": info.get("ufilename"),
                            "description": info.get("desc"),
                            "size": info.get("size"),
                            "creation_date": info.get("creationDate"),
                            "modification_date": info.get("modDate"),
                        })
                    except Exception:
                        # If we can't get info, at least record the name
                        embedded_files_list.append({"name": name})
                parsed_data["embedded_files"] = embedded_files_list
        except Exception:
            pass

        if parsed_data["is_encrypted"]:
            # Handle encrypted PDFs
            parser = PdfParser(file_path)
            try:
                hash_value = parser.parse()
                if hash_value:
                    parsed_data["encryption_hash"] = hash_value.strip()
            except Exception as e:
                parsed_data["error"] = f"Failed to extract hash: {str(e)}"

            # Extract encryption method from metadata if available
            if doc.metadata and doc.metadata.get("encryption"):
                parsed_data["metadata"]["encryption_method"] = doc.metadata["encryption"]

            # Extract permissions information for encrypted PDFs
            parsed_data["permissions"] = {
                "print": doc.permissions & fitz.PDF_PERM_PRINT != 0,  # type: ignore[attr-defined]
                "modify": doc.permissions & fitz.PDF_PERM_MODIFY != 0,  # type: ignore[attr-defined]
                "copy": doc.permissions & fitz.PDF_PERM_COPY != 0,  # type: ignore[attr-defined]
                "annotate": doc.permissions & fitz.PDF_PERM_ANNOTATE != 0,  # type: ignore[attr-defined]
                "form": doc.permissions & fitz.PDF_PERM_FORM != 0,  # type: ignore[attr-defined]
                "accessibility": doc.permissions & fitz.PDF_PERM_ACCESSIBILITY != 0,  # type: ignore[attr-defined]
                "assemble": doc.permissions & fitz.PDF_PERM_ASSEMBLE != 0,  # type: ignore[attr-defined]
                "print_hq": doc.permissions & fitz.PDF_PERM_PRINT_HQ != 0,  # type: ignore[attr-defined]
            }
        else:
            # Handle unencrypted PDFs - extract metadata
            meta = doc.metadata
            if meta:
                parsed_data["metadata"]["title"] = meta.get("title", None) or None
                parsed_data["metadata"]["author"] = meta.get("author", None) or None
                parsed_data["metadata"]["subject"] = meta.get("subject", None) or None
                parsed_data["metadata"]["creator"] = meta.get("creator", None) or None
                parsed_data["metadata"]["producer"] = meta.get("producer", None) or None
                parsed_data["metadata"]["keywords"] = meta.get("keywords", None) or None
                parsed_data["metadata"]["trapped"] = meta.get("trapped", None) or None
                parsed_data["metadata"]["encryption_method"] = meta.get("encryption", None)

                # Handle creation and modification dates
                if "creationDate" in meta and meta["creationDate"]:
                    try:
                        # PyMuPDF returns dates in PDF format like "D:20240101120000"
                        date_str = meta["creationDate"]
                        if date_str.startswith("D:"):
                            date_str = date_str[2:]
                        # Parse the date string (format: YYYYMMDDHHmmss)
                        if len(date_str) >= 14:
                            parsed_data["metadata"]["created"] = datetime.strptime(date_str[:14], "%Y%m%d%H%M%S").isoformat()
                        else:
                            parsed_data["metadata"]["created"] = date_str
                    except Exception:
                        parsed_data["metadata"]["created"] = meta["creationDate"]

                if "modDate" in meta and meta["modDate"]:
                    try:
                        date_str = meta["modDate"]
                        if date_str.startswith("D:"):
                            date_str = date_str[2:]
                        if len(date_str) >= 14:
                            parsed_data["metadata"]["modified"] = datetime.strptime(date_str[:14], "%Y%m%d%H%M%S").isoformat()
                        else:
                            parsed_data["metadata"]["modified"] = date_str
                    except Exception:
                        parsed_data["metadata"]["modified"] = meta["modDate"]

            # Extract page size and rotation from first page
            if doc.page_count > 0:
                first_page = doc[0]
                rect = first_page.rect
                parsed_data["page_size"] = {
                    "width": round(rect.width, 2),
                    "height": round(rect.height, 2),
                    "unit": "points"
                }
                parsed_data["page_rotation"] = first_page.rotation

            # Check for JavaScript by scanning PDF objects
            try:
                has_js = False
                for xref in range(1, doc.xref_length()):
                    # Check for /JavaScript key in object
                    js = doc.xref_get_key(xref, "JS")
                    if js[0] != "null":
                        has_js = True
                        break
                    # Also check for /JavaScript string in object definition
                    try:
                        obj_str = doc.xref_object(xref)
                        if obj_str and "/JavaScript" in obj_str:
                            has_js = True
                            break
                    except Exception:
                        pass
                parsed_data["has_javascript"] = has_js
            except Exception:
                pass

            # Check for forms (AcroForm)
            try:
                if hasattr(doc, 'is_form_pdf'):
                    parsed_data["has_forms"] = doc.is_form_pdf
            except Exception:
                pass

            # Check if PDF/A compliant
            try:
                xref_stream = doc.xref_stream(1)
                if xref_stream and b"PDF/A" in xref_stream:
                    parsed_data["is_pdf_a"] = True
            except Exception:
                pass

            # Extract Table of Contents (only for unencrypted PDFs - fails on encrypted)
            try:
                toc = doc.get_toc()
                parsed_data["has_table_of_contents"] = bool(toc)
            except Exception:
                # get_toc() raises ValueError on encrypted PDFs
                pass

            # Extract XMP metadata (works better on unencrypted PDFs)
            # Parse to structured format instead of storing full XML (99.9% size reduction)
            try:
                xmp_meta = doc.get_xml_metadata()
                if xmp_meta:
                    parsed_data["xmp_summary"] = parse_xmp_to_structured_data(xmp_meta)
            except Exception:
                pass

            # Count total images across all pages (only for unencrypted PDFs - fails on encrypted)
            try:
                total_images = 0
                for page_num in range(doc.page_count):
                    images = doc.get_page_images(page_num)
                    total_images += len(images)
                parsed_data["total_images"] = total_images
            except Exception:
                # get_page_images() raises ValueError on encrypted PDFs
                pass

        doc.close()

    except Exception as e:
        logger.exception(message="Error in PyMuPDF")
        parsed_data["error"] = f"Error parsing PDF file: {str(e)}"

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
