# Standard Libraries
import os
import re

# 3rd Party Libraries
import enrichment.lib.file_parsers.Meta as Meta
import enrichment.lib.helpers as helpers
import nemesispb.nemesis_pb2 as pb
import structlog
from enrichment.lib.secretsdump import LocalOperations
from Registry import Registry

logger = structlog.get_logger(module=__name__)


class reg_hive_system(Meta.FileType):
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
        return re.search(".*/system$", self.file_data.path, re.IGNORECASE) is not None

    def check_content(self) -> bool:
        """
        Returns True if the internal File contents matches our target criteria.
        """
        if os.path.getsize(self.file_path) > 300000000:
            return False

        if helpers.get_magic_type(self.file_path).startswith("MS Windows registry file"):
            return Registry.Registry(self.file_path).hive_type() == Registry.HiveType.SYSTEM
        else:
            return False

    def parse(self) -> tuple[pb.ParsedData, pb.AuthenticationDataIngestionMessage]:
        """
        Parses the file if parsing is defined, including any reversible decryption.
        """

        parsed_data = pb.ParsedData()

        try:
            localOperations = LocalOperations(self.file_path)
            parsed_data.reg_hive_system.boot_key = localOperations.getBootKey()
            return (parsed_data, pb.AuthenticationDataIngestionMessage())

        except Exception as e:
            logger.exception(e, message="reg_hive_system.py parse() error", file_uuid=self.file_data.object_id)
            return (
                helpers.nemesis_parsed_data_error(f"error parsing reg_hive_system file {self.file_data.object_id} : {e}"),
                pb.AuthenticationDataIngestionMessage(),
            )
