# 3rd Party Libraries
import enrichment.lib.file_parsers.Meta as Meta
import enrichment.lib.helpers as helpers
import nemesispb.nemesis_pb2 as pb
from enrichment.lib.ext_tools.pdf2john import PdfParser

# from pypdf import PdfReader
from pypdf import PdfReader


class pdf(Meta.FileType):
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
        return self.file_data.path.lower().endswith(".pdf")

    def check_content(self) -> bool:
        """
        Returns True if the internal File contents matches our target criteria.
        """
        return "pdf document" in self.file_data.magic_type.lower()

    def parse(self) -> tuple[pb.ParsedData, pb.AuthenticationDataIngestionMessage]:
        """
        Parses the file if parsing is defined, including any reversible decryption.
        """

        parsed_data = pb.ParsedData()
        auth_data_msg = pb.AuthenticationDataIngestionMessage()

        try:
            auth_data_msg.metadata.CopyFrom(self.metadata)

            reader = PdfReader(self.file_path)

            parsed_data.pdf.is_encrypted = reader.is_encrypted
            parsed_data.is_encrypted = reader.is_encrypted

            if parsed_data.pdf.is_encrypted:
                # if the doc is encrypted we can't read the metadata

                # our encrypted parser
                parser = PdfParser(self.file_path)

                try:
                    hash = parser.parse()
                    if hash:
                        parsed_data.pdf.encryption_hash = hash.strip()
                        auth_data = auth_data_msg.data.add()
                        auth_data.data = parsed_data.pdf.encryption_hash
                        auth_data.type = "hash_pdf"
                        auth_data.notes = "hash extracted from file_processor->pdf"
                        auth_data.originating_object_id = self.file_data.object_id
                except:
                    pass

                return (parsed_data, auth_data_msg)

            else:
                # if the doc is NOT encrypted we CAN read the metadata
                meta = reader.metadata

                if not meta:
                    return (parsed_data, pb.AuthenticationDataIngestionMessage())

                parsed_data.pdf.num_pages = len(reader.pages)

                if meta.title:
                    parsed_data.pdf.title = meta.title

                if meta.author:
                    parsed_data.pdf.author = meta.author

                if meta.subject:
                    parsed_data.pdf.subject = meta.subject

                if meta.creator:
                    parsed_data.pdf.creator = meta.creator

                if meta.producer:
                    parsed_data.pdf.producer = meta.producer

                if meta.creation_date:
                    parsed_data.pdf.created.FromDatetime(meta.creation_date)

                if meta.modification_date:
                    parsed_data.pdf.modified.FromDatetime(meta.modification_date)

                return (parsed_data, pb.AuthenticationDataIngestionMessage())

        except Exception as e:
            return (
                helpers.nemesis_parsed_data_error(f"error parsing pdf file {self.file_data.object_id} : {e}"),
                pb.AuthenticationDataIngestionMessage(),
            )
