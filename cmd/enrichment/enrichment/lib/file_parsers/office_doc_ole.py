# Standard Libraries
import re

# 3rd Party Libraries
import enrichment.lib.file_parsers.Meta as Meta
import enrichment.lib.helpers as helpers
import nemesispb.nemesis_pb2 as pb
import olefile
import structlog
from enrichment.lib.ext_tools.office2john import extract_file_encryption_hash

logger = structlog.get_logger(module=__name__)


def get_office_ole_metadata(file_path: str) -> pb.ParsedData:
    """
    Gets some basic office metadata.
    """

    parsed_data = pb.ParsedData()

    try:
        if not olefile.isOleFile(file_path):
            return helpers.nemesis_parsed_data_error(f"office document {file_path} is not OLE format")

        with olefile.OleFileIO(file_path) as ole:
            meta = ole.get_metadata()

            try:
                parsed_data.office_doc_ole.title = meta.title.decode("utf-8")
            except:
                pass

            try:
                parsed_data.office_doc_ole.creator = meta.author.decode("utf-8")
            except:
                pass

            try:
                parsed_data.office_doc_ole.created = meta.create_time
            except:
                pass

            try:
                parsed_data.office_doc_ole.modified = meta.last_saved_time
            except:
                pass

            try:
                parsed_data.office_doc_ole.keywords = meta.keywords.decode("utf-8")
            except:
                pass

            try:
                parsed_data.office_doc_ole.comments = meta.comments.decode("utf-8")
            except:
                pass

            try:
                parsed_data.office_doc_ole.last_modified_by = meta.last_saved_by.decode("utf-8")
            except:
                pass

            try:
                parsed_data.office_doc_ole.subject = meta.subject.decode("utf-8")
            except:
                pass

            try:
                parsed_data.office_doc_ole.creating_application = meta.creating_application.decode("utf-8")
            except:
                pass

            try:
                parsed_data.office_doc_ole.total_edit_time = meta.total_edit_time
            except:
                pass

            try:
                parsed_data.office_doc_ole.num_pages = meta.num_pages
            except:
                pass

            try:
                parsed_data.office_doc_ole.num_slides = meta.num_slides
            except:
                pass

            try:
                parsed_data.office_doc_ole.num_chars = meta.num_chars
            except:
                pass

            try:
                parsed_data.office_doc_ole.is_encrypted = meta.security == 1
                parsed_data.is_encrypted = parsed_data.office_doc_ole.is_encrypted

                # if the document is encrypted, extract its hash
                enc_hash = extract_file_encryption_hash(file_path)

                if enc_hash and enc_hash.startswith("$o"):
                    parsed_data.office_doc_ole.encryption_hash = enc_hash
            except:
                pass

    except Exception as e:
        logger.exception(e, message="error parsing office ole file", file_path=file_path)
        return helpers.nemesis_parsed_data_error(f"error parsing office ole file {file_path} : {e}")

    return parsed_data


class office_doc_ole(Meta.FileType):
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
        office_regex = "^.*\\.(doc|ppt|xls)$"
        return re.match(office_regex, self.file_data.path, re.IGNORECASE) is not None

    def check_content(self) -> bool:
        """
        Returns True if the internal File contents matches our target criteria.
        """
        return helpers.scan_with_yara(self.file_path, "office_doc_ole")

    def parse(self) -> tuple[pb.ParsedData, pb.AuthenticationDataIngestionMessage]:
        """
        Parses the file if parsing is defined, including any reversible decryption.
        """

        auth_data_msg = pb.AuthenticationDataIngestionMessage()
        parsed_data = get_office_ole_metadata(self.file_path)

        if helpers.pb_has_field(parsed_data.office_doc_ole, "encryption_hash"):
            auth_data_msg.metadata.CopyFrom(self.metadata)
            auth_data = auth_data_msg.data.add()
            auth_data.data = parsed_data.office_doc_ole.encryption_hash
            auth_data.type = "hash_ms_office"
            auth_data.notes = "hash extracted from file_processor->office_doc_ole"
            auth_data.originating_object_id = self.file_data.object_id

        return (parsed_data, auth_data_msg)
