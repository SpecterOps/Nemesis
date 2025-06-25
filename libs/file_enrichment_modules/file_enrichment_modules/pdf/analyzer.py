# enrichment_modules/pdf/analyzer.py
from datetime import datetime
from typing import Any

import structlog
from common.helpers import escape_markdown
from common.models import EnrichmentResult, FileObject, Finding, FindingCategory, FindingOrigin
from common.state_helpers import get_file_enriched
from common.storage import StorageMinio
from pypdf import PdfReader

from file_enrichment_modules.module_loader import EnrichmentModule
from file_enrichment_modules.pdf.pdf2john import PdfParser

logger = structlog.get_logger(module=__name__)


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
        "title": None,
        "author": None,
        "subject": None,
        "creator": None,
        "producer": None,
        "created": None,
        "modified": None,
    }

    try:
        reader = PdfReader(file_path)
        parsed_data["is_encrypted"] = reader.is_encrypted

        if reader.is_encrypted:
            # Handle encrypted PDFs
            parser = PdfParser(file_path)
            try:
                hash_value = parser.parse()
                if hash_value:
                    parsed_data["encryption_hash"] = hash_value.strip()
            except Exception as e:
                parsed_data["error"] = f"Failed to extract hash: {str(e)}"

        else:
            # Handle unencrypted PDFs
            meta = reader.metadata
            if meta:
                parsed_data["num_pages"] = len(reader.pages)
                parsed_data["title"] = meta.title
                parsed_data["author"] = meta.author
                parsed_data["subject"] = meta.subject
                parsed_data["creator"] = meta.creator
                parsed_data["producer"] = meta.producer
                try:
                    parsed_data["created"] = f"{meta.creation_date}"
                except:
                    try:
                        parsed_data["created"] = (
                            f"{datetime.strptime(meta.creation_date.replace('D:', '').replace('Z', ''), '%Y%m%d%H%M%S')}"
                        )
                    except:
                        pass
                try:
                    parsed_data["modified"] = f"{meta.modification_date}"
                except:
                    try:
                        parsed_data["creamodifiedted"] = (
                            f"{datetime.strptime(meta.modification_date.replace('D:', '').replace('Z', ''), '%Y%m%d%H%M%S')}"
                        )
                    except:
                        pass

    except Exception as e:
        logger.exception(e, message="Error in PdfReader")
        parsed_data["error"] = f"Error parsing PDF file: {str(e)}"

    return parsed_data


class PDFAnalyzer(EnrichmentModule):
    def __init__(self):
        super().__init__("pdf_analyzer")
        self.storage = StorageMinio()
        # the workflows this module should automatically run in
        self.workflows = ["default"]

    def should_process(self, object_id: str) -> bool:
        # Get the current file_enriched from the database backend
        file_enriched = get_file_enriched(object_id)

        if file_enriched.magic_type:
            should_run = "pdf document" in file_enriched.magic_type.lower()
        else:
            should_run = False

        logger.debug(f"PDFAnalyzer should_run: {should_run}")
        return should_run

    def process(self, object_id: str) -> EnrichmentResult | None:
        # get the current `file_enriched` from the database backend
        file_enriched = get_file_enriched(object_id)

        with self.storage.download(file_enriched.object_id) as file:
            analysis = parse_pdf_file(file.name)

            enrichment_result = EnrichmentResult(module_name=self.name)
            enrichment_result.results = analysis

            if "encryption_hash" in enrichment_result.results and enrichment_result.results["encryption_hash"]:
                encryption_hash = enrichment_result.results["encryption_hash"]
                summary_markdown = f"""
# Encrypted PDF
The document is encrypted. Attempt to crack it using the following hash:
```
{escape_markdown(encryption_hash)}
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


def create_enrichment_module() -> EnrichmentModule:
    return PDFAnalyzer()
