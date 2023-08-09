# Standard Libraries
import json
import re
from datetime import datetime, timezone

# 3rd Party Libraries
import enrichment.lib.file_parsers.Meta as Meta
import enrichment.lib.helpers as helpers
import nemesispb.nemesis_pb2 as pb


class slack_workspaces(Meta.FileType):
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
        regex_string = ".*/Slack/storage/slack-workspaces$"
        return re.search(regex_string, self.file_data.path, re.IGNORECASE) is not None

    def check_content(self) -> bool:
        """
        Returns True if the internal File contents matches our target criteria
        using the associated Yara rule.
        """
        return helpers.scan_with_yara(self.file_path, "slack_workspaces")

    def parse(self) -> tuple[pb.ParsedData, pb.AuthenticationDataIngestionMessage] | pb.ParsedData:
        """
        Parses the file if parsing is defined, including any reversible decryption.
        """
        # build protobuf w/o the actual entries, detect/reprocess on the file side

        parsed_data = pb.ParsedData()
        username = helpers.get_username_from_slack_file_path(self.file_path)

        try:
            with open(self.file_path, "r") as f:
                workspaces_json = json.loads(f.read())
                for workspace_id in workspaces_json:
                    workspace_data = workspaces_json[workspace_id]

                    workspace_pd = parsed_data.slack_workspaces.workspaces.add()
                    workspace_pd.username = username
                    workspace_pd.workspace_id = workspace_id

                    if "domain" in workspace_data:
                        workspace_pd.workspace_domain = workspace_data["domain"]
                    if "name" in workspace_data:
                        workspace_pd.workspace_name = workspace_data["name"]
                    if "icon" in workspace_data and "image_original" in workspace_data["icon"]:
                        workspace_pd.workspace_icon_url = workspace_data["icon"]["image_original"]

                return (parsed_data, pb.AuthenticationDataIngestionMessage())

        except Exception as e:
            return (
                helpers.nemesis_parsed_data_error(f"error parsing  'slack-workspaces' file {self.file_data.object_id} : {e}"),
                pb.AuthenticationDataIngestionMessage(),
            )
