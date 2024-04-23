# Standard Libraries
import base64
import codecs
import os
import re
import xml.etree.ElementTree as ET
from typing import Callable, Tuple

# 3rd Party Libraries
import enrichment.lib.file_parsers.Meta as Meta
import enrichment.lib.helpers as helpers
import nemesispb.nemesis_pb2 as pb
import structlog
from Cryptodome.Cipher import DES3
from Cryptodome.Hash import SHA

logger = structlog.get_logger(module=__name__)


def sitelist_xor(xs: bytes) -> bytes:
    """
    Decryption helper.

    Adapted to Python3 from https://github.com/funoverip/mcafee-sitelist-pwd-decryption/blob/master/mcafee_sitelist_pwd_decrypt.py
    Credit to funoverip
    No license
    """

    decode_hex: Callable[[bytes], Tuple[bytes, int]] = codecs.getdecoder("hex_codec")  # type: ignore

    # hardcoded XOR key
    KEY: bytes = decode_hex(b"12150F10111C1A060A1F1B1817160519")[0]

    return bytes([c ^ KEY[i % 16] for i, c in enumerate(xs)])


def decrypt_sitelist_password(b64data: str) -> str:
    """
    Helper that decrypts a single base64 encypted sitelist password.

    Adapted to Python3 from https://github.com/funoverip/mcafee-sitelist-pwd-decryption/blob/master/mcafee_sitelist_pwd_decrypt.py
    Credit to funoverip
    No license
    """

    data = sitelist_xor(base64.b64decode(b64data))
    decode_hex = codecs.getdecoder("hex_codec")

    # hardcoded 3DES key
    key = SHA.new(b"<!@#$%^>").digest() + decode_hex(b"00000000")[0]  # type: ignore

    try:
        des3 = DES3.new(key, DES3.MODE_ECB, None)
    except:
        des3 = DES3.new(key, DES3.MODE_ECB)

    decrypted = des3.decrypt(bytes(data))

    # quick hack to ignore padding
    return decrypted[0 : decrypted.find(b"\x00")].decode("utf-8") or "<empty>"


def process_sitelist_xml(
    file_path, originating_object_id, metadata
) -> tuple[pb.ParsedData, pb.AuthenticationDataIngestionMessage]:
    """
    Parses a McAfee Sitelist.xml file, extracts all data to a structured
    format, and decrypts any encrypted passwords.

    Adapted to Python3 from https://github.com/funoverip/mcafee-sitelist-pwd-decryption/blob/master/mcafee_sitelist_pwd_decrypt.py
    Credit to funoverip
    No license
    """

    parsed_data = pb.ParsedData()
    auth_data_msg = pb.AuthenticationDataIngestionMessage()

    try:
        auth_data_msg.metadata.CopyFrom(metadata)

        my_tree = ET.parse(file_path)
        root = my_tree.getroot()

        for sitelist in list(root):
            nodes = list(sitelist)

            for node in nodes:
                try:
                    entry = parsed_data.mcafee_sitelist.entries.add()

                    type = node.get("Type")
                    if type:
                        entry.type = type

                    name = node.get("Name")
                    if name:
                        entry.name = name

                    server = node.get("Server")
                    if server:
                        entry.server = server

                    enabled = node.get("Enabled")
                    if enabled:
                        entry.enabled = bool(int(enabled))

                    local = node.get("Local")
                    if local:
                        entry.local = bool(int(local))

                    for element in list(node):
                        name = element.tag
                        data = element.text

                        if data:
                            if name.lower() == "password":
                                if element.get("Encrypted") == "1":
                                    entry.password_encrypted = data
                                    dec_pass = decrypt_sitelist_password(data)
                                    entry.password = dec_pass
                                else:
                                    entry.password = data

                                # signal that we do have parsed credentials
                                parsed_data.has_parsed_credentials = True

                            if re.search("^UserName$", name, re.IGNORECASE):
                                entry.username = data
                            elif re.search("^DomainName$", name, re.IGNORECASE):
                                entry.domain_name = data
                            elif re.search("^ShareName$", name, re.IGNORECASE):
                                entry.share_name = data
                            elif re.search("^RelativePath$", name, re.IGNORECASE):
                                entry.relativepath = data
                            elif re.search("^UseAuth$", name, re.IGNORECASE):
                                entry.useauth = bool(int(data))
                            elif re.search("^UseLoggedonUserAccount$", name, re.IGNORECASE):
                                entry.used_loggedon_user_account = bool(int(data))

                    if entry.password and entry.password != "":
                        auth_data = auth_data_msg.data.add()
                        auth_data.data = entry.password
                        if entry.domain_name and entry.domain_name != "":
                            auth_data.uri = f"{entry.username}@{entry.domain_name}"
                            auth_data.username = f"{entry.domain_name}\\{entry.username}"
                        else:
                            auth_data.username = entry.username
                        auth_data.type = "password"
                        auth_data.notes = f"decrypted from file_processor->mcafee_sitelist\nType: {entry.type}\nName: {entry.name}\nServer: {entry.server}\nEnabled: {entry.enabled}\nLocal: {entry.local}"
                        auth_data.originating_object_id = originating_object_id

                except Exception as e:
                    logger.exception(e, message="Error in process_sitelist_xml")

        return (parsed_data, auth_data_msg)

    except Exception as e:
        return (
            helpers.nemesis_parsed_data_error(f"error parsing McAfee sitelist.xml file {file_path} : {e}"),
            pb.AuthenticationDataIngestionMessage(),
        )


class mcafee_sitelist(Meta.FileType):
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
        regex_string = "(.*/)?SiteList\\.xml$"
        return re.search(regex_string, self.file_data.path, re.IGNORECASE) is not None

    def check_content(self) -> bool:
        """Returns True if the internal File contents matches our target criteria."""
        if os.path.getsize(self.file_path) > 1000000:
            return False

        return helpers.scan_with_yara(self.file_path, "mcafee_sitelist")

    def parse(self) -> tuple[pb.ParsedData, pb.AuthenticationDataIngestionMessage]:
        """
        Parses the file if parsing is defined, including any reversible decryption.
        """
        return process_sitelist_xml(self.file_path, self.file_data.object_id, self.metadata)
