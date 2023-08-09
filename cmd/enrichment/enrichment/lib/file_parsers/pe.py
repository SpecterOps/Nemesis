# Standard Libraries
import datetime
import json

# 3rd Party Libraries
import enrichment.lib.file_parsers.Meta as Meta
import enrichment.lib.helpers as helpers
import lief
import nemesispb.nemesis_pb2 as pb
import structlog

logger = structlog.get_logger(module=__name__)


def format_optional_header(pe, parsed_data):
    parsed_data.pe.header.major_image_version = pe.optional_header.major_image_version
    parsed_data.pe.header.major_linker_version = pe.optional_header.major_linker_version
    parsed_data.pe.header.major_operating_system_version = pe.optional_header.major_operating_system_version
    parsed_data.pe.header.major_subsystem_version = pe.optional_header.major_subsystem_version
    parsed_data.pe.header.minor_image_version = pe.optional_header.minor_image_version
    parsed_data.pe.header.minor_linker_version = pe.optional_header.minor_linker_version
    parsed_data.pe.header.minor_operating_system_version = pe.optional_header.minor_operating_system_version
    parsed_data.pe.header.minor_subsystem_version = pe.optional_header.minor_subsystem_version
    parsed_data.pe.header.time_date_stamp.FromDatetime(datetime.datetime.fromtimestamp(pe.header.time_date_stamps))


def format_export(pe, parsed_data):
    for entry in pe.exported_functions:
        symbol = parsed_data.pe.exports.symbols.add()
        symbol.func_name = entry.name
        symbol.offset = pe.optional_header.imagebase + entry.address


def format_import(pe, parsed_data):
    for imp in pe.imports:
        dll = parsed_data.pe.imports.dlls.add()
        dll.name = imp.name

        for entry in imp.entries:
            if entry.name:
                func = dll.symbols.add()
                func.func_name = entry.name
                func.offset = entry.iat_value


def format_signatures(pe, parsed_data):
    for sig in pe.signatures:
        signature = parsed_data.pe.signatures.add()
        signature.version = sig.version

        for signer in sig.signers:
            signature.signers.extend([signer.issuer])

        signature.verification_flags = sig.check()


def format_version_info(pe, parsed_data):
    if pe.resources:
        raw = json.loads(lief.to_json(pe.resources_manager.version.string_file_info))
        version_info_json = raw["langcode_items"][0]["items"]

        if "Assembly Version" in version_info_json:
            parsed_data.pe.version_info.assembly_version = version_info_json["Assembly Version"]
        if "Comments" in version_info_json:
            parsed_data.pe.version_info.comments = version_info_json["Comments"]
        if "CompanyName" in version_info_json:
            parsed_data.pe.version_info.company_name = version_info_json["CompanyName"]
        if "FileDescription" in version_info_json:
            parsed_data.pe.version_info.file_description = version_info_json["FileDescription"]
        if "FileVersion" in version_info_json:
            parsed_data.pe.version_info.file_version = version_info_json["FileVersion"]
        if "InternalName" in version_info_json:
            parsed_data.pe.version_info.internal_name = version_info_json["InternalName"]
        if "LegalCopyright" in version_info_json:
            parsed_data.pe.version_info.legal_copyright = version_info_json["LegalCopyright"]
        if "LegalTrademarks" in version_info_json:
            parsed_data.pe.version_info.legal_trademarks = version_info_json["LegalTrademarks"]
        if "OriginalFilename" in version_info_json:
            parsed_data.pe.version_info.original_filename = version_info_json["OriginalFilename"]
        if "PrivateBuild" in version_info_json:
            parsed_data.pe.version_info.private_build = version_info_json["PrivateBuild"]
        if "ProductName" in version_info_json:
            parsed_data.pe.version_info.product_name = version_info_json["ProductName"]
        if "ProductVersion" in version_info_json:
            parsed_data.pe.version_info.product_version = version_info_json["ProductVersion"]
        if "SpecialBuild" in version_info_json:
            parsed_data.pe.version_info.special_build = version_info_json["SpecialBuild"]


def parse_pe(filename: str) -> pb.ParsedData:
    """
    Parses a PE to a formatted protobuf.
    """
    try:
        parsed_data = pb.ParsedData()

        pe = lief.parse(filename)

        try:
            format_import(pe, parsed_data)
        except Exception as e:
            logger.exception(e, message="Exception parsing imports in parse_pe()")

        try:
            format_optional_header(pe, parsed_data)
        except Exception as e:
            logger.exception(e, message="Exception parsing optional headers in parse_pe()")

        try:
            format_export(pe, parsed_data)
        except Exception as e:
            logger.exception(e, message="Exception parsing exports in parse_pe()")

        try:
            format_version_info(pe, parsed_data)
        except Exception as e:
            logger.exception(e, message="Exception parsing version_info in parse_pe()")

        try:
            format_signatures(pe, parsed_data)
        except Exception as e:
            logger.exception(e, message="Exception parsing signatures in parse_pe()")

        return parsed_data

    except Exception as e:
        logger.exception(e, message="Exception parsing PE file", filename=filename)
        return helpers.nemesis_parsed_data_error(f"error parsing pe file {filename} : {e}")


class pe(Meta.FileType):
    def __init__(self, file_path: str, file_data: pb.FileDataEnriched, metadata: pb.Metadata):
        if type(file_data) == pb.FileDataEnriched:
            self.file_data = file_data
            self.metadata = metadata
            self.file_path = file_path
        else:
            raise Exception("Input was not a file_data object")

    def check_path(self) -> bool:
        """
        Returns True if the internal File path matches our target criteria.
        """
        return helpers.is_pe_extension(self.file_data.path)

    def check_content(self) -> bool:
        """
        Returns True if the internal File contents matches our target criteria.
        """
        is_pe = helpers.scan_with_yara(self.file_path, "pe")
        is_assembly = helpers.is_dotnet_assembly(self.file_path)

        if is_pe:
            if is_assembly:
                # return False here so the dotnet_assembly module can take precedence
                return False
            else:
                return True
        else:
            return False

    def parse(self) -> tuple[pb.ParsedData, pb.AuthenticationDataIngestionMessage]:
        """
        Parses the file if parsing is defined, including any reversible decryption.
        """
        return (parse_pe(self.file_path), pb.AuthenticationDataIngestionMessage())
