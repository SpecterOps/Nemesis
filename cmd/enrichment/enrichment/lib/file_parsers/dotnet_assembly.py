# Standard Libraries
import datetime
import hashlib
import json

# 3rd Party Libraries
import dnfile
import enrichment.lib.file_parsers.Meta as Meta
import enrichment.lib.helpers as helpers
import lief
import nemesispb.nemesis_pb2 as pb
import structlog

logger = structlog.get_logger(module=__name__)


def format_optional_header(pe, parsed_data):
    parsed_data.dotnet_assembly.header.major_image_version = pe.optional_header.major_image_version
    parsed_data.dotnet_assembly.header.major_linker_version = pe.optional_header.major_linker_version
    parsed_data.dotnet_assembly.header.major_operating_system_version = (
        pe.optional_header.major_operating_system_version
    )
    parsed_data.dotnet_assembly.header.major_subsystem_version = pe.optional_header.major_subsystem_version
    parsed_data.dotnet_assembly.header.minor_image_version = pe.optional_header.minor_image_version
    parsed_data.dotnet_assembly.header.minor_linker_version = pe.optional_header.minor_linker_version
    parsed_data.dotnet_assembly.header.minor_operating_system_version = (
        pe.optional_header.minor_operating_system_version
    )
    parsed_data.dotnet_assembly.header.minor_subsystem_version = pe.optional_header.minor_subsystem_version
    parsed_data.dotnet_assembly.header.time_date_stamp.FromDatetime(
        datetime.datetime.fromtimestamp(pe.header.time_date_stamps)
    )


def format_export(pe, parsed_data):
    for entry in pe.exported_functions:
        symbol = parsed_data.dotnet_assembly.exports.symbols.add()
        symbol.func_name = entry.name
        symbol.offset = pe.optional_header.imagebase + entry.address


def format_import(pe, parsed_data):
    for imp in pe.imports:
        dll = parsed_data.dotnet_assembly.imports.dlls.add()
        dll.name = imp.name

        for entry in imp.entries:
            if entry.name:
                func = dll.symbols.add()
                func.func_name = entry.name
                func.offset = entry.iat_value


def format_signatures(pe, parsed_data):
    for sig in pe.signatures:
        signature = parsed_data.dotnet_assembly.signatures.add()
        signature.version = sig.version

        for signer in sig.signers:
            signature.signers.extend([signer.issuer])

        signature.verification_flags = sig.check()


def format_version_info(pe, parsed_data):
    raw = json.loads(lief.to_json(pe.resources_manager.version.string_file_info))
    version_info_json = raw["langcode_items"][0]["items"]

    if "Assembly Version" in version_info_json:
        parsed_data.dotnet_assembly.version_info.assembly_version = version_info_json["Assembly Version"]
    if "Comments" in version_info_json:
        parsed_data.dotnet_assembly.version_info.comments = version_info_json["Comments"]
    if "CompanyName" in version_info_json:
        parsed_data.dotnet_assembly.version_info.company_name = version_info_json["CompanyName"]
    if "FileDescription" in version_info_json:
        parsed_data.dotnet_assembly.version_info.file_description = version_info_json["FileDescription"]
    if "FileVersion" in version_info_json:
        parsed_data.dotnet_assembly.version_info.file_version = version_info_json["FileVersion"]
    if "InternalName" in version_info_json:
        parsed_data.dotnet_assembly.version_info.internal_name = version_info_json["InternalName"]
    if "LegalCopyright" in version_info_json:
        parsed_data.dotnet_assembly.version_info.legal_copyright = version_info_json["LegalCopyright"]
    if "LegalTrademarks" in version_info_json:
        parsed_data.dotnet_assembly.version_info.legal_trademarks = version_info_json["LegalTrademarks"]
    if "OriginalFilename" in version_info_json:
        parsed_data.dotnet_assembly.version_info.original_filename = version_info_json["OriginalFilename"]
    if "PrivateBuild" in version_info_json:
        parsed_data.dotnet_assembly.version_info.private_build = version_info_json["PrivateBuild"]
    if "ProductName" in version_info_json:
        parsed_data.dotnet_assembly.version_info.product_name = version_info_json["ProductName"]
    if "ProductVersion" in version_info_json:
        parsed_data.dotnet_assembly.version_info.product_version = version_info_json["ProductVersion"]
    if "SpecialBuild" in version_info_json:
        parsed_data.dotnet_assembly.version_info.special_build = version_info_json["SpecialBuild"]


def get_typerefs(pe):
    # ref - https://github.com/malwarefrank/dnfile/blob/master/examples/typeref-list.py

    # shortcut to the TypeRef table
    tr = pe.net.mdtables.TypeRef
    if not tr or tr.num_rows < 1 or not tr.rows:
        # if empty table (possible error with file), skip file
        return {"error": "empty TypeRef table"}

    typerefs = {}

    # for each entry in the TypeRef table
    for row in tr:
        # # if the ResolutionScope includes a reference to another table
        # if row.ResolutionScope and row.ResolutionScope.table:
        #     # make note of the table name
        #     res_table = row.ResolutionScope.table.name
        #     # and resolve it to a string
        #     try:
        #         res_name = getattr(row.ResolutionScope.row, "Name") or getattr(
        #             row.ResolutionScope.row, "TypeName"
        #         )
        #     except:
        #         pass
        # else:
        #     # otherwise
        #     res_table = None
        #     res_name = None

        if row.TypeNamespace in typerefs:
            typerefs[row.TypeNamespace].append(row.TypeName)
        else:
            typerefs[row.TypeNamespace] = [row.TypeName]

    return typerefs


def process_resources(pe):
    # # ref - https://github.com/malwarefrank/dnfile#quick-start
    # # access the streams
    # for s in pe.net.metadata.streams_list:
    #     if isinstance(s, dnfile.stream.MetaDataTables):
    #         # how many Metadata tables are defined in the binary?
    #         num_of_tables = len(s.tables_list)

    # # the last Metadata tables stream can also be accessed by a shortcut
    # num_of_tables = len(pe.net.mdtables.tables_list)

    # create a set to hold the hashes of all resources
    resources = {}

    for r in pe.net.resources:
        # if resource data is a simple byte stream
        if isinstance(r.data, bytes):
            resources[r.name] = [
                hashlib.md5(r.data).hexdigest(),
                hashlib.sha1(r.data).hexdigest(),
                hashlib.sha256(r.data).hexdigest(),
            ]
        # if resource data is a ResourceSet, a dotnet-specific datatype
        elif isinstance(r.data, dnfile.resource.ResourceSet):
            # if there are no entries, skip it
            if not r.data.entries:
                continue
            # for each entry in the ResourceSet
            for entry in r.data.entries:
                # if it has data
                if entry.data:
                    # hash it and add the hash to the set
                    resources[r.name] = [
                        hashlib.md5(entry.data).hexdigest(),
                        hashlib.sha1(entry.data).hexdigest(),
                        hashlib.sha256(entry.data).hexdigest(),
                    ]

    return resources


def parse_assembly(filename: str) -> pb.ParsedData:
    """
    Parses an assembly fileto a formatted protobuf.
    """

    parsed_data = pb.ParsedData()

    try:
        pe = lief.parse(filename)

        # general PE fields
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

        assembly: dnfile.dnPE | None = None
        try:
            # .NET specific things
            assembly = dnfile.dnPE(filename)
        except Exception as e:
            logger.exception(e, message="Exception parsing assembly in parse_pe()")

        if assembly is None:
            return parsed_data

        if assembly.net:
            # .NET version
            if assembly.net.metadata and assembly.net.metadata.struct:
                parsed_data.dotnet_assembly.dotnet_version = str(assembly.net.metadata.struct.Version)

            # P/Invoke type signatures
            try:
                if assembly.net.mdtables.ImplMap:
                    for row in assembly.net.mdtables.ImplMap:
                        impl_entry = pb.ImplMapEntry()

                        if row.ImportScope.row and row.ImportScope.row.Name:
                            impl_entry.module_name = row.ImportScope.row.Name
                        impl_entry.function_name = row.ImportName
                        parsed_data.dotnet_assembly.impl_map_entries.append(impl_entry)
            except Exception as e:
                logger.exception(e, message="Exception parsing impl entries in parse_pe()")

        # PDB string
        #   TODO: possible in regular PEs?
        try:
            debug_info = []
            for entry in pe.DIRECTORY_ENTRY_DEBUG:
                debug_info.append(entry.entry.dump_dict())
            parsed_data.dotnet_assembly.pdb_string = debug_info[0]["PdbFileName"]["Value"].rstrip("\\x00")
        except:
            pass

        try:
            # resource names + hashes
            for name, hashes in process_resources(assembly).items():
                resource = parsed_data.dotnet_assembly.resources.add()
                resource.name = name
                resource.md5 = hashes[0]
                resource.sha1 = hashes[1]
                resource.sha256 = hashes[2]
        except Exception as e:
            logger.exception(e, message="Exception parsing resource names/hashes in parse_pe()")

        try:
            # typerefs
            for library, functions in get_typerefs(assembly).items():
                for function in functions:
                    typeref = parsed_data.dotnet_assembly.typerefs.add()
                    typeref.module_name = library
                    typeref.function_name = function
        except Exception as e:
            logger.exception(e, message="Exception parsing typerefs in parse_pe()")

    except Exception as e:
        # return helpers.nemesis_parsed_data_error(f"error parsing pe file {filename} : {e}")
        logger.exception(e, message="error parsing pe file", filename=filename)

    return parsed_data


class dotnet_assembly(Meta.FileType):
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
        Returns True if the internal File contents matches our target criteria
        using the associated Yara rule.
        """
        return helpers.scan_with_yara(self.file_path, "dotnet_assembly")

    def parse(self) -> tuple[pb.ParsedData, pb.AuthenticationDataIngestionMessage]:
        """
        Parses the file if parsing is defined, including any reversible decryption.
        """
        return (parse_assembly(self.file_path), pb.AuthenticationDataIngestionMessage())
