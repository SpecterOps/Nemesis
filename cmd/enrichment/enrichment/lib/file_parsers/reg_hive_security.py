# Standard Libraries
import json
import os
import re

# 3rd Party Libraries
import enrichment.lib.file_parsers.Meta as Meta
import enrichment.lib.helpers as helpers
from enrichment.lib.secretsdump import LSASecrets
import nemesispb.nemesis_pb2 as pb
import structlog
from Registry import Registry

logger = structlog.get_logger(module=__name__)


class reg_hive_security(Meta.FileType):
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
        return re.search(".*/security$", self.file_data.path, re.IGNORECASE) is not None

    def check_content(self) -> bool:
        """
        Returns True if the internal File contents matches our target criteria.
        """
        if os.path.getsize(self.file_path) > 300000000:
            return False

        if helpers.get_magic_type(self.file_path).startswith("MS Windows registry file"):
            return Registry.Registry(self.file_path).hive_type() == Registry.HiveType.SECURITY
        else:
            return False

    def parse(self) -> tuple[pb.ParsedData, pb.AuthenticationDataIngestionMessage]:
        """
        Parses the file if parsing is defined, including any reversible decryption.
        """

        parsed_data = pb.ParsedData()

        try:
            lsa = LSASecrets(self.file_path)
            (vista_style, lsa_sec_key_enc_bytes) = lsa.getLSASecretKeyEnc()
            # NOTE: for decryption later:
            #   lsa_sec_key_dec_bytes = decryptLSA(lsa_sec_key_enc_bytes, boot_key, vista_style)

            parsed_data.reg_hive_security.vista_style = vista_style
            parsed_data.reg_hive_security.lsa_secret_key_enc = lsa_sec_key_enc_bytes

            parsed_data.reg_hive_security.nlkm_secret_enc = lsa.getNLKMSecretEnc()
            # NOTE: for decryption later:
            #   nlkm_secret_dec = decryptLSASecret(NKLMKeyEnc, lsa_sec_key_dec_bytes, vista_style, True)

            for (secret_name, secret_enc_bytes) in lsa.dumpSecretsEnc():
                lsa_secret = parsed_data.reg_hive_security.lsa_secrets.add()
                lsa_secret.name = secret_name
                lsa_secret.value_enc = secret_enc_bytes
                # NOTE: for decryption later:
                #   secret_dec_bytes = decryptLSASecret(secret_enc_bytes, lsa_sec_key_dec_bytes, vista_style)

            for (iteration_count, enc_raw_value) in lsa.dumpCachedHashesEnc():
                cached_entry = parsed_data.reg_hive_security.domain_cached_credentials.add()
                cached_entry.iteration_count = iteration_count
                cached_entry.enc_raw_value = enc_raw_value
                # NOTE: for decryption later:
                #   dec = decryptCachedEntry(enc_value, nlkm_secret_dec, iteration_count, vista_style)

            return (parsed_data, pb.AuthenticationDataIngestionMessage())

        except Exception as e:
            logger.exception(e, message="reg_hive_security.py parse() error", file_uuid=self.file_data.object_id)
            return (
                helpers.nemesis_parsed_data_error(f"error parsing reg_hive_security file {self.file_data.object_id} : {e}"),
                pb.AuthenticationDataIngestionMessage()
            )
