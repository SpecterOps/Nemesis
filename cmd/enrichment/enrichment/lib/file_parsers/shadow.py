# Standard Libraries
import datetime
import os

# 3rd Party Libraries
import enrichment.lib.file_parsers.Meta as Meta
import enrichment.lib.helpers as helpers
import nemesispb.nemesis_pb2 as pb


class shadow(Meta.FileType):
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
        return self.file_data.path.lower().endswith("/shadow")

    def check_content(self) -> bool:
        """
        Returns True if the internal File contents matches our target criteria.
        """

        if os.path.getsize(self.file_path) > 1000000:
            return False

        if self.file_data.magic_type != "ASCII text":
            return False

        return helpers.scan_with_yara(self.file_path, "shadow")

    def parse(self) -> tuple[pb.ParsedData, pb.AuthenticationDataIngestionMessage]:
        """
        Parses the file if parsing is defined, including any reversible decryption.
        """

        parsed_data = pb.ParsedData()
        auth_data_msg = pb.AuthenticationDataIngestionMessage()

        try:
            auth_data_msg.metadata.CopyFrom(self.metadata)

            with open(self.file_path, "r") as f:

                lines = f.readlines()

                for line in lines:
                    if line.startswith("#"):
                        continue

                    if line.strip() == "":
                        continue

                    fields = line.split(":")

                    if len(fields) < 4:
                        continue

                    # *nix start date, pwd last changed is days since this epoch
                    start = datetime.datetime.strptime("01/01/70", "%m/%d/%y")

                    try:
                        days = int(fields[2])
                    except:
                        days = 0

                    end = start + datetime.timedelta(days=days)
                    password_last_changed = end
                    # password_last_changed = end.strftime("%Y-%m-%dT%H:%M:%S")

                    username = fields[0]
                    password = fields[1]

                    if password != "*" and password != "!" and password != "!!" and len(password) > 5:
                        entry = parsed_data.shadow.entries.add()
                        entry.username = username
                        entry.password = password
                        entry.password_last_changed.FromDatetime(password_last_changed)

                        # signal that we do have parsed credentials
                        parsed_data.has_parsed_credentials = True

                        # can't do this because this auth data isn't decrypted - TODO: redo with new hash data
                        auth_data = auth_data_msg.data.add()
                        auth_data.data = password
                        auth_data.type = "hash_crypt"
                        auth_data.username = username
                        auth_data.notes = f"credential parsed from file_processor->shadow\nLast Changed: {password_last_changed}"
                        auth_data.originating_object_id = self.file_data.object_id

            return (parsed_data, auth_data_msg)

        except Exception as e:
            return (helpers.nemesis_parsed_data_error(f"error parsing shadow file {self.file_data.object_id} : {e}"), pb.AuthenticationDataIngestionMessage())
