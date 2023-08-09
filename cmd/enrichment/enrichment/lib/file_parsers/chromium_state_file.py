# Standard Libraries
import asyncio
import base64
import json
from datetime import datetime

# 3rd Party Libraries
import enrichment.lib.file_parsers.Meta as Meta
import enrichment.lib.helpers as helpers
import nemesispb.nemesis_pb2 as pb


class chromium_state_file(Meta.FileType):
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
        chromium_file_path = helpers.parse_chromium_file_path(self.file_data.path)
        if chromium_file_path.success and chromium_file_path.file_type == "state":
            return True
        else:
            return False

    def check_content(self) -> bool:
        """
        Returns True if the internal File contents matches our target criteria
        using the associated Yara rule.
        """
        return helpers.scan_with_yara(self.file_path, "chromium_state_file")

    def parse(self) -> tuple[pb.ParsedData, pb.AuthenticationDataIngestionMessage] | pb.ParsedData:
        """
        Parses the file if parsing is defined, including any reversible decryption.
        """
        # build protobuf w/o the actual entries, detect/reprocess on the file side

        parsed_data = pb.ParsedData()

        chromium_file_path = helpers.parse_chromium_file_path(self.file_data.path)
        parsed_data.chromium_state_file.user_data_directory = chromium_file_path.user_data_directory
        parsed_data.chromium_state_file.browser = chromium_file_path.browser
        parsed_data.chromium_state_file.username = chromium_file_path.username
        parsed_data.chromium_state_file.originating_object_id = self.file_data.object_id
        parsed_data.chromium_state_file.masterkey_guid = "00000000-0000-0000-0000-000000000000"  # default null for UUID

        try:
            with open(self.file_path, "r") as f:
                state_file_json = json.loads(f.read())
                os_crypt = state_file_json["os_crypt"]

                if "app_bound_fixed_data" in os_crypt:
                    app_bound_fixed_data_enc = base64.b64decode(os_crypt["app_bound_fixed_data"])
                    parsed_data.chromium_state_file.app_bound_fixed_data_enc = app_bound_fixed_data_enc

                if "encrypted_key" in os_crypt:
                    key_bytes_enc = base64.b64decode(os_crypt["encrypted_key"])

                    if key_bytes_enc[0:5] == b"DPAPI":
                        key_bytes_enc = key_bytes_enc[5:]
                        parsed_data.chromium_state_file.key_bytes_enc = key_bytes_enc

                        # run this async function synchronously
                        key_bytes_info = helpers.parse_dpapi_blob_sync(key_bytes_enc)

                        if key_bytes_info.success:
                            parsed_data.chromium_state_file.masterkey_guid = key_bytes_info.dpapi_master_key_guid
                    else:
                        # Unknown encryption type
                        parsed_data.chromium_state_file.key_bytes_enc = key_bytes_enc

                if "uninstall_metrics" in state_file_json:
                    if "installation_date2" in state_file_json["uninstall_metrics"]:
                        try:
                            installation_date = datetime.fromtimestamp(int(state_file_json["uninstall_metrics"]["installation_date2"]))
                            parsed_data.chromium_state_file.installation_date.FromDatetime(installation_date)
                        except:
                            pass
                    if "launch_count" in state_file_json["uninstall_metrics"]:
                        try:
                            parsed_data.chromium_state_file.launch_count = int(state_file_json["uninstall_metrics"]["launch_count"])
                        except:
                            pass

                return (parsed_data, pb.AuthenticationDataIngestionMessage())

        except Exception as e:
            return (
                helpers.nemesis_parsed_data_error(f"error parsing Chromium 'Local State' file {self.file_data.object_id} : {e}"),
                pb.AuthenticationDataIngestionMessage(),
            )
