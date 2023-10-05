# Standard Libraries
import datetime
import re
import xml.dom.minidom
import zipfile

# 3rd Party Libraries
import enrichment.lib.file_parsers.Meta as Meta
import enrichment.lib.helpers as helpers
import nemesispb.nemesis_pb2 as pb
from enrichment.lib.ext_tools.office2john import extract_file_encryption_hash


def get_office_metadata(file_path: str) -> pb.ParsedData:
    """Gets some basic office metadata.

    Ref - https://github.com/profHajal/Microsoft-Office-Documents-Metadata-with-Python/blob/main/mso_md.py
          No license
    """

    parsed_data = pb.ParsedData()

    try:
        # try to extract the hash for this document, if it's successful we know it was encrypted
        #   I know this is a hack but it's here because the "CDFV2 Encrypted" encrypted .docx/etc. format doesn't play nicely as a ZIP
        # Note: if the doc is encrypted, we can't get any metadata from it like we could the old OLE office format(s)
        enc_hash = extract_file_encryption_hash(file_path)
        if enc_hash and enc_hash.startswith("$o"):
            parsed_data.is_encrypted = True
            parsed_data.office_doc_new.is_encrypted = True
            parsed_data.office_doc_new.encryption_hash = enc_hash
    except:
        pass

    if not parsed_data.office_doc_new.is_encrypted:
        try:
            myFile = zipfile.ZipFile(file_path, "r")
            doc = xml.dom.minidom.parseString(myFile.read("docProps/core.xml"))
            xml.dom.minidom.parseString(myFile.read("docProps/core.xml")).toprettyxml()
        except:
            pass

        try:
            parsed_data.office_doc_new.title = doc.getElementsByTagName("dc:title")[0].childNodes[0].data
        except:
            pass

        try:
            parsed_data.office_doc_new.subject = doc.getElementsByTagName("dc:subject")[0].childNodes[0].data
        except:
            pass

        try:
            parsed_data.office_doc_new.creator = doc.getElementsByTagName("dc:creator")[0].childNodes[0].data
        except:
            pass

        try:
            parsed_data.office_doc_new.keywords = doc.getElementsByTagName("cp:keywords")[0].childNodes[0].data
        except:
            pass

        try:
            parsed_data.office_doc_new.description = doc.getElementsByTagName("dc:description")[0].childNodes[0].data
        except:
            pass

        try:
            parsed_data.office_doc_new.last_modified_by = doc.getElementsByTagName("cp:lastModifiedBy")[0].childNodes[0].data
        except:
            pass

        try:
            parsed_data.office_doc_new.revision = int(doc.getElementsByTagName("cp:revision")[0].childNodes[0].data)
        except:
            pass

        try:
            dateString = doc.getElementsByTagName("dcterms:created")[0].childNodes[0].data
            dt = datetime.datetime.strptime(dateString, "%Y-%m-%dT%H:%M:%Sz")
            parsed_data.office_doc_new.created.FromDatetime(dt)
        except:
            pass

        try:
            dateString = doc.getElementsByTagName("dcterms:modified")[0].childNodes[0].data
            dt = datetime.datetime.strptime(dateString, "%Y-%m-%dT%H:%M:%Sz")
            parsed_data.office_doc_new.modified.FromDatetime(dt)
        except:
            pass

    return parsed_data


class office_doc_new(Meta.FileType):
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
        regex_string = "\\.(docx|pptx|xlsx)$"
        return re.match(regex_string, self.file_data.path, re.IGNORECASE) is not None

    def check_content(self) -> bool:
        """
        Returns True if the internal File contents matches our target criteria.
        """
        # right now only handles .docx, .xlxs, and .pptx (zip formats)
        #   TODO: expand formats
        return helpers.scan_with_yara(self.file_path, "office_doc_new")

    def parse(self) -> tuple[pb.ParsedData, pb.AuthenticationDataIngestionMessage]:
        """
        Parses the file if parsing is defined, including any reversible decryption.
        """

        auth_data_msg = pb.AuthenticationDataIngestionMessage()
        parsed_data = get_office_metadata(self.file_path)

        if parsed_data.office_doc_new.HasField("encryption_hash"):
            auth_data_msg.metadata.CopyFrom(self.metadata)
            auth_data = auth_data_msg.data.add()
            auth_data.data = parsed_data.office_doc_new.encryption_hash
            auth_data.type = "hash_ms_office"
            auth_data.notes = "hash extracted from file_processor->office_doc_new"
            auth_data.originating_object_id = self.file_data.object_id

        return (parsed_data, auth_data_msg)
