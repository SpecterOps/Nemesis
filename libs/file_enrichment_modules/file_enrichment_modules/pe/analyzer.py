# enrichment_modules/pe_analyzer/analzyer.py
from pathlib import Path
from typing import Any

import lief
import yara_x
from common.logger import get_logger
from common.models import EnrichmentResult
from common.state_helpers import get_file_enriched_async
from common.storage import StorageMinio
from file_enrichment_modules.module_loader import EnrichmentModule

logger = get_logger(__name__)


# # simpler but may have additional information we often don't care about
# def parse_pe_file(file_path: str) -> Dict[str, Any]:
#     try:
#         binary = lief.parse(file_path)
#         return json.loads(lief.to_json(binary))
#     except Exception as e:
#         logger.exception(message="Error in process()")
#         return None


# more selective output but has some lingering issues
def parse_pe_file(file_path: str) -> dict[str, Any]:
    """
    Parse a PE file using LIEF and return detailed information as JSON.

    Args:
        file_path (str): Path to the PE file to analyze

    Returns:
        Dict[str, Any]: Dictionary containing parsed PE information

    Raises:
        lief.format_error: If the file is not a valid PE
        FileNotFoundError: If the file doesn't exist
        Exception: For other parsing errors
    """
    try:
        # Verify file exists
        if not Path(file_path).is_file():
            raise FileNotFoundError(f"File not found: {file_path}")

        # Parse the PE file
        binary = lief.parse(file_path)

        if binary is None:
            raise lief.lief_errors.parsing_error("Failed to parse PE file")

        # Initialize the result dictionary
        result = {
            "general_info": {},
            "headers": {},
            "sections": [],
            "imports": [],
            "exports": [],
            "tls": {},
            "resources": [],
            "debug": [],
            "signatures": [],
            "dotnet": {},
        }

        try:
            is_dotnet = binary.has_configuration and bool(
                binary.data_directories.get(lief.PE.DATA_DIRECTORY.CLR_RUNTIME_HEADER, None)
            )
        except Exception:
            is_dotnet = False

        # General Information
        result["general_info"] = {
            "file_path": file_path,
            "file_size": Path(file_path).stat().st_size,
            "is_64": binary.header.machine == lief.PE.Header.MACHINE_TYPES.AMD64,
            "is_32": binary.header.machine == lief.PE.Header.MACHINE_TYPES.I386,
            "has_debug": binary.has_debug,
            "has_imports": binary.has_imports,
            "has_exports": binary.has_exports,
            "has_tls": binary.has_tls,
            "is_dotnet": is_dotnet,
            "has_resources": binary.has_resources,
            "has_signature": binary.has_signatures,
            "has_exceptions": binary.has_exceptions,
            "format": str(binary.format),
        }

        # Headers
        try:
            dos_header = binary.dos_header
            result["headers"]["dos_header"] = {
                "magic": dos_header.magic,
                "used_bytes_in_last_page": dos_header.used_bytes_in_last_page,
                "file_size_in_pages": dos_header.file_size_in_pages,
                "numberof_relocation": dos_header.numberof_relocation,
                "header_size_in_paragraphs": dos_header.header_size_in_paragraphs,
                "minimum_extra_paragraphs": dos_header.minimum_extra_paragraphs,
                "maximum_extra_paragraphs": dos_header.maximum_extra_paragraphs,
                "initial_relative_ss": dos_header.initial_relative_ss,
                "initial_sp": dos_header.initial_sp,
                "checksum": dos_header.checksum,
                "initial_ip": dos_header.initial_ip,
                "initial_relative_cs": dos_header.initial_relative_cs,
                "addressof_relocation_table": dos_header.addressof_relocation_table,
                "overlay_number": dos_header.overlay_number,
                "oem_id": dos_header.oem_id,
                "oem_info": dos_header.oem_info,
                "addressof_new_exeheader": dos_header.addressof_new_exeheader,
            }
        except Exception as e:
            logger.warning("Exception parsing dos_header", e=e)

        try:
            header = binary.header
            result["headers"]["file_header"] = {
                "machine": str(header.machine),
                "numberof_sections": header.numberof_sections,
                "time_date_stamps": header.time_date_stamps,
                "pointerto_symbol_table": header.pointerto_symbol_table,
                "numberof_symbols": header.numberof_symbols,
                "sizeof_optional_header": header.sizeof_optional_header,
                "characteristics": [str(c) for c in header.characteristics_list],
            }
        except Exception as e:
            logger.warning("Exception parsing file_header", e=e)

        try:
            optional_header = binary.optional_header
            result["headers"]["optional_header"] = {
                "magic": str(optional_header.magic),
                "major_linker_version": optional_header.major_linker_version,
                "minor_linker_version": optional_header.minor_linker_version,
                "sizeof_code": optional_header.sizeof_code,
                "sizeof_initialized_data": optional_header.sizeof_initialized_data,
                "sizeof_uninitialized_data": optional_header.sizeof_uninitialized_data,
                "addressof_entrypoint": optional_header.addressof_entrypoint,
                "baseof_code": optional_header.baseof_code,
                "imagebase": optional_header.imagebase,
                "section_alignment": optional_header.section_alignment,
                "file_alignment": optional_header.file_alignment,
                "major_operating_system_version": optional_header.major_operating_system_version,
                "minor_operating_system_version": optional_header.minor_operating_system_version,
                "major_image_version": optional_header.major_image_version,
                "minor_image_version": optional_header.minor_image_version,
                "major_subsystem_version": optional_header.major_subsystem_version,
                "minor_subsystem_version": optional_header.minor_subsystem_version,
                "win32_version_value": optional_header.win32_version_value,
                "sizeof_image": optional_header.sizeof_image,
                "sizeof_headers": optional_header.sizeof_headers,
                "checksum": optional_header.checksum,
                "subsystem": str(optional_header.subsystem),
                "dll_characteristics": [str(c) for c in optional_header.dll_characteristics_lists],
                "sizeof_stack_reserve": optional_header.sizeof_stack_reserve,
                "sizeof_stack_commit": optional_header.sizeof_stack_commit,
                "sizeof_heap_reserve": optional_header.sizeof_heap_reserve,
                "sizeof_heap_commit": optional_header.sizeof_heap_commit,
                "loader_flags": optional_header.loader_flags,
                "numberof_rva_and_size": optional_header.numberof_rva_and_size,
            }
        except Exception as e:
            logger.warning("Exception parsing optional_header", e=e)

        # Sections
        for section in binary.sections:
            try:
                section_data = {
                    "name": section.name,
                    "virtual_address": section.virtual_address,
                    "virtual_size": section.virtual_size,
                    "size": section.size,
                    "offset": section.offset,
                    "characteristics": [str(c) for c in section.characteristics_lists],
                    "entropy": section.entropy,
                }
                result["sections"].append(section_data)
            except Exception as e:
                logger.warning("Exception parsing section", section_name=section.name, e=e)

        # Imports
        if binary.has_imports:
            for import_entry in binary.imports:
                try:
                    import_data = {"name": import_entry.name, "entries": []}
                    for function in import_entry.entries:
                        function_data = {
                            "name": function.name if function.name else None,
                            "hint": function.hint,
                            "iat_address": function.iat_address,
                            "data": function.data,
                        }
                        import_data["entries"].append(function_data)
                    result["imports"].append(import_data)
                except Exception as e:
                    logger.warning("Exception parsing import", import_name=import_entry.name, e=e)

        # Exports
        if binary.has_exports:
            try:
                exports = binary.get_export()
                result["exports"] = {
                    "name": exports.name,
                    "export_flags": exports.export_flags,
                    "timestamp": exports.timestamp,
                    "major_version": exports.major_version,
                    "minor_version": exports.minor_version,
                    "ordinal_base": exports.ordinal_base,
                    "entries": [],
                }
                for entry in exports.entries:
                    entry_data = {
                        "name": entry.name,
                        "ordinal": entry.ordinal,
                        "address": entry.address,
                        "is_extern": entry.is_extern,
                    }
                    result["exports"]["entries"].append(entry_data)
            except Exception as e:
                logger.warning("Exception parsing export", import_name=exports.name, e=e)

        # TLS
        if binary.has_tls:
            try:
                tls = binary.tls
                result["tls"] = {
                    "callbacks": list(tls.callbacks),
                    "addressof_raw_data": {
                        "start": tls.addressof_raw_data.start if tls.addressof_raw_data else None,
                        "end": tls.addressof_raw_data.end if tls.addressof_raw_data else None,
                    },
                    "addressof_index": tls.addressof_index,
                    "addressof_callbacks": tls.addressof_callbacks,
                    "sizeof_zero_fill": tls.sizeof_zero_fill,
                    "characteristics": tls.characteristics,
                }
            except Exception as e:
                logger.warning("Exception parsing rls", e=e)

        # Resources
        if binary.has_resources:
            for resource_type in binary.resources.childs:
                for resource_id in resource_type.childs:
                    for resource_lang in resource_id.childs:
                        try:
                            resource_data = {
                                "type": str(resource_type.id),
                                "id": resource_id.id,
                                "language": resource_lang.id,
                                "size": resource_lang.content.nbytes,
                            }
                            result["resources"].append(resource_data)
                        except Exception as e:
                            logger.warning("Exception parsing resource", e=e)

        # Debug
        if binary.has_debug:
            try:
                for entry in binary.debug:
                    debug_data = {
                        "characteristics": entry.characteristics,
                        "timestamp": entry.timestamp,
                        "major_version": entry.major_version,
                        "minor_version": entry.minor_version,
                        "type": str(entry.type),
                        "sizeof_data": entry.sizeof_data,
                        "addressof_rawdata ": entry.addressof_rawdata,
                        "pointerto_rawdata ": entry.pointerto_rawdata,
                    }
                    result["debug"].append(debug_data)
            except Exception as e:
                logger.warning("Exception parsing debug", e=e)

        # Signatures
        # Parse .NET metadata if present
        try:
            if result["general_info"]["is_dotnet"]:
                clr_header = binary.data_directories[lief.PE.DATA_DIRECTORY.CLR_RUNTIME_HEADER]
                result["dotnet"] = {
                    "header_size": clr_header.size,
                    "virtual_address": clr_header.rva,
                }

                # Try to parse more detailed .NET information
                try:
                    # Get CLR metadata
                    clr = binary.get_configuration()
                    if clr:
                        result["dotnet"].update(
                            {
                                "version_major": clr.major_version,
                                "version_minor": clr.minor_version,
                                "version_build": clr.build_number,
                                "version_revision": clr.revision_number,
                                "flags": clr.flags,
                                "runtime_version": f"{clr.major_runtime_version}.{clr.minor_runtime_version}",
                            }
                        )
                except Exception as e:
                    logger.warning(f"Could not parse detailed .NET metadata: {str(e)}")
        except Exception as e:
            logger.warning("Exception parsing .NET metadata", e=e)

        if binary.has_signatures:
            result["signatures"] = []

            for signature in binary.signatures:
                try:
                    signature_data = {
                        "version": signature.version,
                        "digest_algorithm": str(signature.digest_algorithm),
                        "digest": signature.digest,
                        "certificates": [],
                    }
                    for cert in signature.certificates:
                        cert_data = {
                            "version": cert.version,
                            "serial_number": cert.serial_number,
                            "issuer": str(cert.issuer),
                            "subject": str(cert.subject),
                            "valid_from": str(cert.valid_from),
                            "valid_to": str(cert.valid_to),
                        }
                        signature_data["certificates"].append(cert_data)
                    result["signatures"].append(signature_data)
                except Exception as e:
                    logger.warning("Exception parsing signature", e=e)

        return result

    except Exception as e:
        logger.exception(message="Error parsing PE file")
        return {"error": str(e)}


class PEAnalyzer(EnrichmentModule):
    name: str = "pe_analyzer"
    dependencies: list[str] = []
    def __init__(self):
        self.storage = StorageMinio()
        # the workflows this module should automatically run in
        self.workflows = ["default"]

        self.yara_rule = yara_x.compile("""
import "pe"

rule is_pe
{
    condition:
        pe.is_pe
}
        """)

    async def should_process(self, object_id: str, file_path: str | None = None) -> bool:
        """Uses a Yara run to determine if this module should run."""
        # Get the current file_enriched from the database backend
        file_enriched = await get_file_enriched_async(object_id)

        # download a max of 1000 bytes
        num_bytes = file_enriched.size if file_enriched.size < 1000 else 1000

        if file_path:
            # Use provided file path - read only the needed bytes
            with open(file_path, "rb") as f:
                file_bytes = f.read(num_bytes)
        else:
            # Fallback to downloading the file itself
            file_bytes = self.storage.download_bytes(file_enriched.object_id, length=num_bytes)

        should_run = len(self.yara_rule.scan(file_bytes).matching_rules) > 0
        return should_run

    def _analyze_pe(self, file_path: str, file_enriched) -> EnrichmentResult | None:
        """Analyze PE file and generate enrichment result.

        Args:
            file_path: Path to the PE file to analyze
            file_enriched: File enrichment data

        Returns:
            EnrichmentResult or None if analysis fails
        """
        try:
            enrichment_result = EnrichmentResult(module_name=self.name)
            enrichment_result.results = parse_pe_file(file_path)
            return enrichment_result
        except Exception:
            logger.exception(message=f"Error analyzing PE file for {file_enriched.file_name}")
            return None

    async def process(self, object_id: str, file_path: str | None = None) -> EnrichmentResult | None:
        """Process file using.

        Args:
            object_id: The object ID of the file
            file_path: Optional path to already downloaded file

        Returns:
            EnrichmentResult or None if processing fails
        """
        try:
            # Get the current file_enriched from the database backend
            file_enriched = await get_file_enriched_async(object_id)

            # Use provided file_path if available, otherwise download
            if file_path:
                return self._analyze_pe(file_path, file_enriched)
            else:
                with self.storage.download(file_enriched.object_id) as file:
                    return self._analyze_pe(file.name, file_enriched)

        except Exception:
            logger.exception(message="Error in PE file analysis", file_object_id=object_id)
            return None


def create_enrichment_module() -> EnrichmentModule:
    return PEAnalyzer()
