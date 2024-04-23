# Standard Libraries
import json
import re
from datetime import datetime, timezone

# 3rd Party Libraries
import enrichment.lib.file_parsers.Meta as Meta
import enrichment.lib.helpers as helpers
import nemesispb.nemesis_pb2 as pb


class slack_downloads(Meta.FileType):
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
        regex_string = ".*/Slack/storage/slack-downloads$"
        return re.search(regex_string, self.file_data.path, re.IGNORECASE) is not None

    def check_content(self) -> bool:
        """
        Returns True if the internal File contents matches our target criteria
        using the associated Yara rule.
        """
        return helpers.scan_with_yara(self.file_path, "slack_downloads")

    def parse(self) -> tuple[pb.ParsedData, pb.AuthenticationDataIngestionMessage] | pb.ParsedData:
        """
        Parses the file if parsing is defined, including any reversible decryption.
        """
        # build protobuf w/o the actual entries, detect/reprocess on the file side

        parsed_data = pb.ParsedData()
        username = helpers.get_username_from_slack_file_path(self.file_path)

        try:
            with open(self.file_path, "r") as f:
                downloads_json = json.loads(f.read())
                for workspace_id in downloads_json:
                    downloads = downloads_json[workspace_id]
                    for download_id in downloads:
                        download = downloads[download_id]
                        download_pb = parsed_data.slack_downloads.downloads.add()
                        download_pb.username = username
                        download_pb.workspace_id = workspace_id
                        download_pb.download_id = download_id

                        if "teamId" in download:
                            download_pb.team_id = download["teamId"]
                        if "userId" in download:
                            download_pb.user_id = download["userId"]
                        if "url" in download:
                            download_pb.url = download["url"]
                        if "downloadPath" in download:
                            download_pb.download_path = download["downloadPath"].replace("\\", "/")
                        if "downloadState" in download:
                            download_pb.download_state = download["downloadState"]
                        if "startTime" in download:
                            start_time_str = download["startTime"]
                            epoch = int(start_time_str) / 1000
                            start_dt = datetime.fromtimestamp(epoch, tz=timezone.utc)
                            download_pb.start_time.FromDatetime(start_dt)
                        if "endTime" in download:
                            end_time_str = download["endTime"]
                            epoch = int(end_time_str) / 1000
                            end_dt = datetime.fromtimestamp(epoch, tz=timezone.utc)
                            download_pb.end_time.FromDatetime(end_dt)

                return (parsed_data, pb.AuthenticationDataIngestionMessage())

        except Exception as e:
            return (
                helpers.nemesis_parsed_data_error(
                    f"error parsing  'slack-downloads' file {self.file_data.object_id} : {e}"
                ),
                pb.AuthenticationDataIngestionMessage(),
            )
