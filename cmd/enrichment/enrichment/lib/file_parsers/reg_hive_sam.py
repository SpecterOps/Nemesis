# Standard Libraries
import ntpath
import os
import re

# 3rd Party Libraries
import enrichment.lib.file_parsers.Meta as Meta
import enrichment.lib.helpers as helpers
import nemesispb.nemesis_pb2 as pb
import structlog
from enrichment.lib.secretsdump import SAMHashes
from Registry import Registry

logger = structlog.get_logger(module=__name__)


class reg_hive_sam(Meta.FileType):
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
        return re.search(".*/sam$", self.file_data.path, re.IGNORECASE) is not None

    def check_content(self) -> bool:
        """
        Returns True if the internal File contents matches our target criteria.
        """
        if os.path.getsize(self.file_path) > 300000000:
            return False

        if helpers.get_magic_type(self.file_path).startswith("MS Windows registry file"):
            return Registry.Registry(self.file_path).hive_type() == Registry.HiveType.SAM
        else:
            return False

    def parse(self) -> tuple[pb.ParsedData, pb.AuthenticationDataIngestionMessage]:
        """
        Parses the file if parsing is defined, including any reversible decryption.
        """

        parsed_data = pb.ParsedData()

        try:
            sam = SAMHashes(self.file_path)

            F = sam.getValue(ntpath.join(r"SAM\Domains\Account", "F"))[1]
            parsed_data.reg_hive_sam.f_bytes = F

            for userName, rid, encLMHash, encNTHash, newStyle in sam.dumpEnc():
                sam_hash = parsed_data.reg_hive_sam.sam_hashes.add()
                sam_hash.new_style = newStyle
                sam_hash.username = userName
                sam_hash.rid = rid
                sam_hash.lm_hash_enc = encLMHash
                sam_hash.nt_hash_enc = encNTHash
                # NOTE: for decryption later:
                # decLMHash = decryptSAMHash(rid, encLMHash, hashedBootKey, False)
                # if decLMHash == b'':
                #     decLMHash = ntlm.LMOWFv1('','')
                # decNTHash = decryptSAMHash(rid, encNTHash, hashedBootKey, True)
                # if decNTHash == b'':
                #     decNTHash = ntlm.NTOWFv1('','')
                # lmHasStr = hexlify(decLMHash).decode('utf-8')
                # ntHashStr = hexlify(decNTHash).decode('utf-8')
                # answer = f"{userName}:{rid}:{lmHasStr}:{ntHashStr}:::"

            return (parsed_data, pb.AuthenticationDataIngestionMessage())

        except Exception as e:
            logger.exception(e, message="reg_hive_sam.py parse() error", file_uuid=self.file_data.object_id)
            return (
                helpers.nemesis_parsed_data_error(f"error parsing reg_hive_sam file {self.file_data.object_id} : {e}"),
                pb.AuthenticationDataIngestionMessage(),
            )
