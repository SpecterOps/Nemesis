# Standard Libraries
import os

# 3rd Party Libraries
import enrichment.lib.file_parsers.Meta as Meta
import enrichment.lib.helpers as helpers
import nemesispb.nemesis_pb2 as pb


class passwd(Meta.FileType):
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
        return self.file_data.path.lower().endswith("/passwd")

    def check_content(self) -> bool:
        """
        Returns True if the internal File contents matches our target criteria.
        """

        if os.path.getsize(self.file_path) > 1000000:
            return False

        if self.file_data.magic_type != "ASCII text":
            return False

        return helpers.scan_with_yara(self.file_path, "passwd")

    def parse(self) -> tuple[pb.ParsedData, pb.AuthenticationDataIngestionMessage]:
        """
        Parses the file if parsing is defined, including any reversible decryption.
        """
        try:
            parsed_data = pb.ParsedData()

            with open(self.file_path, "r") as f:

                lines = f.readlines()

                for line in lines:
                    if line.startswith("#"):
                        continue

                    if line.strip() == "":
                        continue

                    fields = line.split(":")

                    if len(fields) != 7:
                        continue

                    shell = fields[6].strip()

                    if shell.endswith("nologin") or shell.endswith("false"):
                        continue

                    else:
                        entry = parsed_data.passwd.entries.add()
                        entry.username = fields[0]
                        entry.user_id = fields[2]
                        entry.group_id = fields[3]
                        entry.home_directory = fields[5]
                        entry.shell = shell

            return (parsed_data, pb.AuthenticationDataIngestionMessage())

        except Exception as e:
            return (helpers.nemesis_parsed_data_error(f"error parsing passwd file {self.file_data.object_id} : {e}"), pb.AuthenticationDataIngestionMessage())
