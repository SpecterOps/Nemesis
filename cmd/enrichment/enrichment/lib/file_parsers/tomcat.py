# Standard Libraries
import os
import re
import xml.etree.ElementTree as ET

# 3rd Party Libraries
import enrichment.lib.file_parsers.Meta as Meta
import enrichment.lib.helpers as helpers
import nemesispb.nemesis_pb2 as pb


class tomcat(Meta.FileType):
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
        regex_string = "(.*/|^)tomcat-users\\.xml$"
        return re.search(regex_string, self.file_data.path, re.IGNORECASE) is not None

    def check_content(self) -> bool:
        """
        Returns True if the internal File contents matches our target criteria.
        """
        if os.path.getsize(self.file_path) > 1000000:
            return False

        return helpers.scan_with_yara(self.file_path, "tomcat")

    def parse(self) -> tuple[pb.ParsedData, pb.AuthenticationDataIngestionMessage]:
        """
        Parses the file if parsing is defined, including any reversible decryption.
        """

        parsed_data = pb.ParsedData()
        auth_data_msg = pb.AuthenticationDataIngestionMessage()

        try:
            auth_data_msg.metadata.CopyFrom(self.metadata)

            with open(self.file_path, "rb") as f:
                data = f.read()

                try:
                    roles_iter = ET.fromstring(data).iter("role")
                    for r in roles_iter:
                        parsed_data.tomcat.roles.extend([r.attrib["rolename"]])
                except ET.ParseError:
                    pass

                try:
                    users_iter = ET.fromstring(data).iter("user")

                    for user in users_iter:
                        entry = parsed_data.tomcat.entries.add()
                        entry.username = user.attrib["username"]
                        entry.password = user.attrib["password"]

                        if "roles" in user.attrib:
                            user_roles = user.attrib["roles"].split(",")
                            entry.roles.extend(user_roles)
                            user_roles_str = user.attrib["roles"]
                        else:
                            user_roles_str = ""

                        if entry.password != "":
                            # signal that we do have parsed credentials
                            parsed_data.has_parsed_credentials = True

                            auth_data = auth_data_msg.data.add()
                            auth_data.data = entry.password
                            auth_data.type = "password"
                            auth_data.username = entry.username
                            if user_roles_str and user_roles_str != "":
                                auth_data.notes = (
                                    f"credential parsed from file_processor->tomcat\nUser roles: {user_roles_str}"
                                )
                            else:
                                auth_data.notes = "credential parsed from file_processor->tomcat"
                            auth_data.originating_object_id = self.file_data.object_id

                except ET.ParseError:
                    pass

            return (parsed_data, auth_data_msg)

        except Exception as e:
            return (
                helpers.nemesis_parsed_data_error(f"error parsing tomcat file {self.file_data.object_id} : {e}"),
                pb.AuthenticationDataIngestionMessage(),
            )
