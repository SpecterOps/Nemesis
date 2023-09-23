# Standard Libraries
import json
import os
import re

# 3rd Party Libraries
import enrichment.lib.file_parsers.Meta as Meta
import enrichment.lib.helpers as helpers
import nemesispb.nemesis_pb2 as pb
import structlog

logger = structlog.get_logger(module=__name__)


def parenthetic_contents(string):
    stack = []
    for i, c in enumerate(string):
        if c == "(":
            stack.append(i)
        elif c == ")" and stack:
            start = stack.pop()
            s = string[start + 1 : i]
            temp = s.split("=")
            if len(temp) == 1:
                yield (temp[0], "")
            else:
                yield (temp[0], temp[1])


class appsettings(Meta.FileType):
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
        regex_string = "(.*/)?.*(appsettings).*\\.json"
        return re.search(regex_string, self.file_data.path, re.IGNORECASE) is not None

    def check_content(self) -> bool:
        """
        Returns True if the internal File contents matches our target criteria.
        """
        if os.path.getsize(self.file_path) > 1000000:
            return False

        return helpers.scan_with_yara(self.file_path, "appsettings")

    def parse(self) -> tuple[pb.ParsedData, pb.AuthenticationDataIngestionMessage]:
        """
        Parses the file if parsing is defined, including any reversible decryption.
        """

        parsed_data = pb.ParsedData()
        auth_data_msg = pb.AuthenticationDataIngestionMessage()

        try:
            auth_data_msg.metadata.CopyFrom(self.metadata)

            with open(self.file_path, "r") as f:
                json_data = json.loads(f.read())

                if "ConnectionStrings" in json_data:
                    for key in json_data["ConnectionStrings"].keys():
                        try:
                            connection_string_raw = json_data["ConnectionStrings"][key]

                            connection_string = parsed_data.appsettings.connection_strings.add()
                            connection_string.name = key

                            for part in connection_string_raw.split(";"):
                                # special exception for Oracle
                                temp = part.split(")(")
                                if len(temp) > 3:
                                    contents = list(parenthetic_contents(part))
                                    for content in contents:
                                        if content[0].lower() == "host":
                                            connection_string.database_credential.server = content[1]
                                        elif content[0].lower() == "port":
                                            connection_string.database_credential.server = f"{connection_string.database_credential.server}:{content[1]}"
                                        elif content[0].lower() == "service_name":
                                            connection_string.database_credential.database = content[1]
                                else:
                                    temp = part.split("=")
                                    if len(temp) > 1:
                                        key = temp[0]
                                        value = "=".join(temp[1:])
                                        if re.match("^(User Id|UID)$", key, re.IGNORECASE):
                                            connection_string.database_credential.username = value
                                        elif re.match("^(Server|HOST|Data Source)$", key, re.IGNORECASE):
                                            connection_string.database_credential.server = value
                                        elif re.match("^(port)$", key, re.IGNORECASE):
                                            connection_string.database_credential.server = f"{connection_string.database_credential.server}:{value}"
                                        elif re.match("^Database$", key, re.IGNORECASE):
                                            connection_string.database_credential.database = value
                                        elif re.match("^(password|PWD)$", key, re.IGNORECASE):
                                            connection_string.database_credential.password = value
                                            if value != "":
                                                # signal that we do have parsed credentials
                                                parsed_data.has_parsed_credentials = True

                            if connection_string.database_credential.server and connection_string.database_credential.username and connection_string.database_credential.password:
                                auth_data = auth_data_msg.data.add()
                                auth_data.data = connection_string.database_credential.password
                                auth_data.type = "password"
                                if connection_string.database_credential.database:
                                    auth_data.uri = f"db://{connection_string.database_credential.server}/{connection_string.database_credential.database}"
                                else:
                                    auth_data.uri = f"db://{connection_string.database_credential.server}"
                                auth_data.username = connection_string.database_credential.database
                                auth_data.notes = "database credential parsed from file_processor->appsettings"
                                auth_data.originating_object_id = self.file_data.object_id

                        except Exception as e:
                            logger.exception(e, message="appsettings.py parse() error on ConnectionString")

                elif "JwtToken" in json_data:
                    try:
                        jwt_token_data = json_data["JwtToken"]
                        jwt_token = parsed_data.appsettings.jwt_tokens.add()

                        auth_data = auth_data_msg.data.add()
                        auth_data.type = "password"
                        auth_data.data = jwt_token_data
                        auth_data.notes = "JWT parsed from file_processor->appsettings"
                        auth_data.originating_object_id = self.file_data.object_id

                        if "key" in jwt_token_data:
                            jwt_token.key = jwt_token_data["key"]
                        if "issuer" in jwt_token_data:
                            jwt_token.issuer = jwt_token_data["issuer"]
                        if "audience" in jwt_token_data:
                            jwt_token.audience = jwt_token_data["audience"]
                        if "minutestoexpiration" in jwt_token_data:
                            jwt_token.minutes_to_expiration = jwt_token_data["minutestoexpiration"]

                    except Exception as e:
                        logger.exception(e, message="appsettings.py parse() error on JwtToken")

            return (parsed_data, auth_data_msg)

        except Exception as e:
            logger.exception(e, message="appsettings.py parse() error", file_uuid=self.file_data.object_id, auth_data=auth_data_msg)
            return (helpers.nemesis_parsed_data_error(f"error parsing appsettings file {self.file_data.object_id} : {e}"), auth_data_msg)
