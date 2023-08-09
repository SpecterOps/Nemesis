# Standard Libraries
import base64
import datetime
import os
import re
from xml.dom import minidom

# 3rd Party Libraries
import chardet
import enrichment.lib.file_parsers.Meta as Meta
import enrichment.lib.helpers as helpers
import nemesispb.nemesis_pb2 as pb
import structlog
from Cryptodome.Cipher import AES
from Cryptodome.Util.Padding import unpad

logger = structlog.get_logger(module=__name__)


def decrypt_cpassword(pw_enc_b64):
    """
    Helper that decrypts a single Group Policy Preferences password.

    From https://github.com/ShutdownRepo/Get-GPPPassword/blob/main/Get-GPPPassword.py
         License: GPLv3
    """
    if len(pw_enc_b64) != 0:
        # thank you MS for publishing the key :) (https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-gppref/2c15cbf0-f086-4c74-8b70-1f2fa45dd4be)
        key = b"\x4e\x99\x06\xe8\xfc\xb6\x6c\xc9\xfa\xf4\x93\x10\x62\x0f\xfe\xe8\xf4\x96\xe8\x06\xcc\x05\x79\x90\x20" b"\x9b\x09\xa4\x33\xb6\x6c\x1b"
        # thank you MS for using a fixed IV :)
        iv = b"\x00" * 16
        pad = len(pw_enc_b64) % 4
        if pad == 1:
            pw_enc_b64 = pw_enc_b64[:-1]
        elif pad == 2 or pad == 3:
            pw_enc_b64 += "=" * (4 - pad)
        pw_enc = base64.b64decode(pw_enc_b64)
        ctx = AES.new(key, AES.MODE_CBC, iv)
        pw_dec = unpad(ctx.decrypt(pw_enc), ctx.block_size)
        return pw_dec.decode("utf-16-le")
    else:
        return ""


def parse_gpp_xml(filename, originating_object_id, metadata) -> tuple[pb.ParsedData, pb.AuthenticationDataIngestionMessage]:
    """
    Decrypes a cpassword group policy preferences .xml file, returning any decrypted passwords.

    Adapted from https://github.com/ShutdownRepo/Get-GPPPassword/blob/main/Get-GPPPassword.py
                 License: GPLv3
    """

    parsed_data = pb.ParsedData()
    auth_data_msg = pb.AuthenticationDataIngestionMessage()

    try:
        auth_data_msg.metadata.CopyFrom(metadata)

        if not os.path.exists(filename):
            filename = filename.replace("/", "\\")

        with open(filename, "rb") as f:
            data = f.read()

        encoding = chardet.detect(data)["encoding"]
        if encoding is not None:
            filecontent = data.decode(encoding).rstrip()
            if "cpassword" in filecontent:
                try:
                    root = minidom.parseString(filecontent)
                    properties_list = root.getElementsByTagName("Properties")

                    # function to get attribute if it exists, returns "" if empty
                    read_or_empty = lambda element, attribute: (element.getAttribute(attribute) if element.getAttribute(attribute) is not None else "")

                    for properties in properties_list:
                        entry = parsed_data.group_policy_preferences.entries.add()
                        entry.username = read_or_empty(properties, "userName")
                        entry.cpassword = read_or_empty(properties, "cpassword")
                        entry.password = decrypt_cpassword(read_or_empty(properties, "cpassword"))
                        entry.action = read_or_empty(properties, "action")
                        entry.description = read_or_empty(properties, "description")

                        if entry.password != "":
                            # signal that we do have parsed credentials
                            parsed_data.has_parsed_credentials = True

                        if read_or_empty(properties, "acctDisabled") != "":
                            entry.disabled = bool(int(read_or_empty(properties, "acctDisabled")))
                        if read_or_empty(properties, "neverExpires") != "":
                            entry.never_expires = bool(int(read_or_empty(properties, "neverExpires")))

                        if read_or_empty(properties.parentNode, "changed") != "":
                            dateString = read_or_empty(properties.parentNode, "changed")
                            dt = datetime.datetime.strptime(dateString, "%Y-%m-%d %H:%M:%S")
                            entry.changed.FromDatetime(dt)

                        if entry.username and entry.password and entry.disabled is not True:
                            auth_data = auth_data_msg.data.add()
                            auth_data.data = entry.password
                            auth_data.username = entry.username
                            auth_data.type = "password"
                            if entry.description and entry.description != "":
                                auth_data.notes = f"cpassword decrypted from file_processor->group_policy_preferences\nparsed description: {entry.description}"
                            else:
                                auth_data.notes = "cpassword decrypted from file_processor->group_policy_preferences"
                            auth_data.originating_object_id = originating_object_id

                except Exception as e:
                    logger.exception(e, message="Error in parse_gpp_xml")

        return (parsed_data, auth_data_msg)

    except Exception as e:
        return (helpers.nemesis_parsed_data_error(f"error parsing McAfee sitelist.xml file {filename} : {e}"), auth_data_msg)


class group_policy_preferences(Meta.FileType):
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
        regex_string = ".*/(Groups|Services|Scheduledtasks|DataSources|Printers|Drives)\\.xml$"
        return re.search(regex_string, self.file_data.path, re.IGNORECASE) is not None

    def check_content(self) -> bool:
        """
        Returns True if the internal File contents matches our target criteria.
        """
        if os.path.getsize(self.file_path) > 1000000:
            return False

        return helpers.scan_with_yara(self.file_path, "group_policy_preferences")

    def parse(self) -> tuple[pb.ParsedData, pb.AuthenticationDataIngestionMessage]:
        """
        Parses the file if parsing is defined, including any reversible decryption.
        """
        return parse_gpp_xml(self.file_path, self.file_data.object_id, self.metadata)
