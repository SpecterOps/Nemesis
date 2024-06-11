# Standard Libraries
import tarfile
import datetime
import ntpath
import re
import subprocess
import zipfile

# 3rd Party Libraries
import enrichment.lib.file_parsers.Meta as Meta
import enrichment.lib.helpers as helpers
import nemesispb.nemesis_pb2 as pb
import py7zr


class archive(Meta.FileType):
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

        if re.match(".*\\.(zip|tar\\.gz|tar\\.bz2|7z)$", self.file_data.path):
            return True
        else:
            return False

    def check_content(self) -> bool:
        """
        Returns True if the internal File contents matches our target criteria
        using the associated Yara rule.
        """

        return helpers.is_archive(self.file_path)

    def parse(self) -> tuple[pb.ParsedData, pb.AuthenticationDataIngestionMessage]:
        """
        Parses the file if parsing is defined, including any reversible decryption.
        """

        if zipfile.is_zipfile(self.file_path):
            return self.parse_zip()
        elif py7zr.is_7zfile(self.file_path):
            return self.parse_7z()
        elif tarfile.is_tarfile(self.file_path):
            return self.parse_tar()
        else:
            return (helpers.nemesis_parsed_data_error(f"file is not a supported archive: {self.file_data.object_id}"), pb.AuthenticationDataIngestionMessage())

    def parse_tar(self) -> tuple[pb.ParsedData, pb.AuthenticationDataIngestionMessage]:
        """
        Helper to parse a tar file.
        """

        parsed_data = pb.ParsedData()
        auth_data_msg = pb.AuthenticationDataIngestionMessage()

        try:
            auth_data_msg.metadata.CopyFrom(self.metadata)
            parsed_data.archive.type = "tar"
            parsed_data.archive.uncompressed_size = helpers.get_archive_size(self.file_path)

            with tarfile.open(self.file_path, "r") as tar_obj:
                for elem in tar_obj.getmembers():
                    entry = parsed_data.archive.entries.add()
                    entry.name = elem.name
                    entry.is_dir = elem.isdir()
                    entry.last_modified.FromDatetime(datetime.datetime.fromtimestamp(elem.mtime))
                    entry.compress_size = elem.size
                    entry.uncompress_size = elem.size

            return (parsed_data, auth_data_msg)

        except Exception as e:
            return (helpers.nemesis_parsed_data_error(f"error parsing tar file {self.file_data.object_id} : {e}"), auth_data_msg)

    def parse_zip(self) -> tuple[pb.ParsedData, pb.AuthenticationDataIngestionMessage]:
        """
        Helper to parse a file zip.
        """

        parsed_data = pb.ParsedData()
        auth_data_msg = pb.AuthenticationDataIngestionMessage()

        try:
            auth_data_msg.metadata.CopyFrom(self.metadata)
            parsed_data.archive.type = "zip"
            parsed_data.archive.uncompressed_size = helpers.get_archive_size(self.file_path)
            enc_file_path = ""

            with zipfile.ZipFile(self.file_path, "r") as zipObj:
                for elem in zipObj.infolist():
                    entry = parsed_data.archive.entries.add()
                    entry.name = elem.filename
                    entry.is_dir = elem.is_dir()
                    entry.last_modified.FromDatetime(datetime.datetime(*elem.date_time))
                    entry.compress_size = elem.compress_size
                    entry.uncompress_size = elem.file_size

                    # ref https://hg.python.org/cpython/file/2.7/Lib/zipfile.py#l985
                    # if we don't already have a hash extracted, and this elem is a file and encrypted
                    if not parsed_data.archive.is_encrypted and not elem.is_dir() and elem.flag_bits & 0x1:
                        parsed_data.is_encrypted = True
                        parsed_data.archive.is_encrypted = True
                        # save this path so we can efficiently use zip2john on just this file
                        #   instead of iterating over several internal files
                        enc_file_path = elem.filename

            if parsed_data.archive.is_encrypted and enc_file_path != "":
                result = subprocess.run(
                    ["/opt/john/run/zip2john", self.file_path, "-o", enc_file_path],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                )
                jtr_output = result.stdout.decode("utf-8").strip()

                # valid results start with ID/subfile
                if jtr_output.startswith(f"{ntpath.basename(self.file_path)}/{enc_file_path}"):
                    parsed_data.archive.encryption_hash = jtr_output

                    auth_data = auth_data_msg.data.add()
                    auth_data.data = parsed_data.archive.encryption_hash
                    auth_data.type = "hash_archive"
                    auth_data.notes = "hash extracted from file_processor->archive"
                    auth_data.originating_object_id = self.file_data.object_id

            return (parsed_data, auth_data_msg)

        except Exception as e:
            return (helpers.nemesis_parsed_data_error(f"error parsing zip file {self.file_data.object_id} : {e}"), auth_data_msg)

    def parse_7z(self) -> tuple[pb.ParsedData, pb.AuthenticationDataIngestionMessage]:
        """
        Helper to parse a 7zip file.
        """

        parsed_data = pb.ParsedData()
        auth_data_msg = pb.AuthenticationDataIngestionMessage()

        try:
            auth_data_msg.metadata.CopyFrom(self.metadata)
            parsed_data.archive.uncompressed_size = helpers.get_archive_size(self.file_path)
            parsed_data.archive.type = "7z"

            with py7zr.SevenZipFile(self.file_path, "r") as zipObj:
                parsed_data.is_encrypted = zipObj.password_protected
                parsed_data.archive.is_encrypted = zipObj.password_protected

                for elem in zipObj.files:
                    entry = parsed_data.archive.entries.add()
                    entry.name = elem.filename
                    entry.is_dir = elem.is_directory
                    if elem.lastwritetime:
                        entry.last_modified.FromDatetime(elem.lastwritetime.as_datetime())
                    if elem.compressed:
                        entry.compress_size = elem.compressed
                    if elem.uncompressed:
                        entry.uncompress_size = elem.uncompressed

            if parsed_data.archive.is_encrypted:
                result = subprocess.run(
                    ["/opt/john/run/7z2john.pl", self.file_path],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                )
                jtr_output = result.stdout.decode("utf-8").strip()

                if jtr_output.startswith(f"{ntpath.basename(self.file_path)}"):
                    parsed_data.archive.encryption_hash = jtr_output

                    auth_data = auth_data_msg.data.add()
                    auth_data.data = parsed_data.archive.encryption_hash
                    auth_data.type = "hash_archive"
                    auth_data.notes = "hash extracted from file_processor->archive"
                    auth_data.originating_object_id = self.file_data.object_id

            return (parsed_data, auth_data_msg)

        except Exception as e:
            return (helpers.nemesis_parsed_data_error(f"error parsing 7z file {self.file_data.object_id} : {e}"), auth_data_msg)
