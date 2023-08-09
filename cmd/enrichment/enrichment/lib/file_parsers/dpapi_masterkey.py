# Standard Libraries
import sys
from typing import List

# 3rd Party Libraries
import enrichment.lib.file_parsers.Meta as Meta
import enrichment.lib.helpers as helpers
import nemesispb.nemesis_pb2 as pb
import structlog
from enrichment.lib.ext_tools.DPAPImk2john import MasterKeyFile

logger = structlog.get_logger(module=__name__)


class dpapi_masterkey(Meta.FileType):
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
        path_out = helpers.parse_masterkey_file_path(self.file_data.path)
        return (path_out is not None) and (path_out != {})

    def check_content(self) -> bool:
        """
        Returns True if the internal File contents matches our target criteria
        using the associated Yara rule.
        """
        return helpers.scan_with_yara(self.file_path, "dpapi_masterkey")

    def extract_hash(self, context) -> List[str]:
        """Uses DPAPImk2john to extract one or more hashes for this masterkey."""

        path_out = helpers.parse_masterkey_file_path(self.file_data.path)

        if (path_out is not None) and (path_out != {}) and path_out["sid"]:
            sid = path_out["sid"]

            with open(self.file_path, "rb") as f:
                mkdata = f.read()

            try:
                mk = MasterKeyFile(raw=mkdata, SID=sid, context=context)
                return [hash for hash in mk.masterkey.jhash().split("\n") if hash.startswith("$DPAPImk$")]

            except Exception as e:
                logger.exception(e)
                return []
        else:
            logger.warning("User SID not populated from original file path")
            return []

    def parse(self) -> tuple[pb.ParsedData, pb.AuthenticationDataIngestionMessage] | pb.ParsedData:
        """
        Parses the file if parsing is defined, including any reversible decryption.
        """
        try:
            dpapi_masterkey = helpers.process_masterkey_file(self.file_data.object_id, self.file_path, self.file_data.path, self.metadata)

            if not dpapi_masterkey:
                return helpers.nemesis_parsed_data_error(f"Could not find a masterkey in the file. File ID: {self.file_data.object_id}")

            if dpapi_masterkey.domain_backupkey_guid:
                context = "domain"
            else:
                context = "local"

            hashes = self.extract_hash(context)

            auth_data_msg = pb.AuthenticationDataIngestionMessage()
            if hashes:
                auth_data_msg.metadata.CopyFrom(self.metadata)
                for hash in hashes:
                    auth_data = auth_data_msg.data.add()
                    auth_data.data = hash
                    auth_data.type = "hash_dpapi_masterkey"
                    auth_data.notes = "hash extracted from file_processor->dpapi_masterkey"
                    auth_data.originating_object_id = self.file_data.object_id

            parsed_data = pb.ParsedData()
            parsed_data.dpapi_masterkey.CopyFrom(dpapi_masterkey)
            return (parsed_data, auth_data_msg)

        except Exception as e:
            return (
                helpers.nemesis_parsed_data_error(f"error parsing masterkey file {self.file_data.object_id} : {e}"),
                pb.AuthenticationDataIngestionMessage(),
            )
