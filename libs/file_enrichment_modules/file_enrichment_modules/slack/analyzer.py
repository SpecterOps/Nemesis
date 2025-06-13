# enrichment_modules/slack/root_state_analyzer.py
import csv
import json
import tempfile
from datetime import datetime
import structlog
import yara_x
from common.models import EnrichmentResult, Transform
from common.state_helpers import get_file_enriched
from common.storage import StorageMinio

from file_enrichment_modules.module_loader import EnrichmentModule

logger = structlog.get_logger(module=__name__)


class SlackRootStateParser(EnrichmentModule):
    def __init__(self):
        super().__init__("slack_root_state_parser")
        self.storage = StorageMinio()

        # the workflows this module should automatically run in
        self.workflows = ["default"]

        # Yara rule to detect Slack root-state.json files
        self.yara_rule = yara_x.compile("""
rule Detect_Slack_RootState {
    meta:
        description = "Detects Slack root-state.json configuration files"
        author = "Claude"
        severity = "Medium"

    strings:
        // JSON structure indicators
        $json_start = "{"

        // Slack-specific sections
        $workspaces = "workspaces" nocase
        $downloads = "downloads" nocase

        // Common Slack data structures
        $team_id = "teamId" nocase
        $user_id = "userId" nocase

    condition:
        $json_start and
        ($workspaces and $downloads) and
        ($team_id and $user_id)
}
        """)

    def should_process(self, object_id: str) -> bool:
        """Determine if this module should run."""
        file_enriched = get_file_enriched(object_id)

        # Initial checks for file type and name
        if file_enriched.file_name.lower() != "root-state.json":
            return False

        if "json" not in file_enriched.magic_type.lower():
            return False

        # Run Yara check
        file_bytes = self.storage.download_bytes(file_enriched.object_id)
        should_run = len(self.yara_rule.scan(file_bytes).matching_rules) > 0

        logger.debug(f"SlackRootStateParser should_run: {should_run}")
        return should_run

    def _parse_timestamp(self, timestamp):
        """Convert timestamp to readable format."""
        if timestamp:
            try:
                return datetime.fromtimestamp(timestamp / 1000).isoformat()
            except (ValueError, TypeError):
                return ""
        return ""

    def process(self, object_id: str) -> EnrichmentResult | None:
        """Process Slack root-state.json file."""
        try:
            file_enriched = get_file_enriched(object_id)
            enrichment_result = EnrichmentResult(module_name=self.name, dependencies=self.dependencies)
            transforms = []

            with self.storage.download(file_enriched.object_id) as temp_file:
                # Load JSON data
                with open(temp_file.name, 'r', encoding='utf-8') as f:
                    data = json.load(f)

                # Extract workspaces data
                workspaces_data = []
                workspaces = data.get('workspaces', {})

                for workspace_id, workspace_info in workspaces.items():
                    workspaces_data.append({
                        'domain': workspace_info.get('domain', ''),
                        'id': workspace_info.get('id', workspace_id),
                        'name': workspace_info.get('name', ''),
                        'url': workspace_info.get('url', '')
                    })

                # Create workspaces CSV
                with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", newline="") as tmp_workspaces_csv:
                    writer = csv.writer(tmp_workspaces_csv)

                    # Write header
                    writer.writerow(['domain', 'id', 'name', 'url'])

                    # Write workspace data
                    for workspace in workspaces_data:
                        writer.writerow([
                            workspace['domain'],
                            workspace['id'],
                            workspace['name'],
                            workspace['url']
                        ])

                    tmp_workspaces_csv.flush()
                    workspaces_csv_id = self.storage.upload_file(tmp_workspaces_csv.name)

                    transforms.append(
                        Transform(
                            type="slack_workspaces",
                            object_id=f"{workspaces_csv_id}",
                            metadata={
                                "file_name": f"{file_enriched.file_name}_workspaces.csv",
                                "offer_as_download": True,
                            },
                        )
                    )

                # Extract downloads data
                downloads_data = []
                downloads = data.get('downloads', {})

                # Create team name lookup for correlation
                team_name_lookup = {ws['id']: ws['name'] for ws in workspaces_data}

                for team_id, team_downloads in downloads.items():
                    for download_id, download_info in team_downloads.items():
                        downloads_data.append({
                            'id': download_info.get('id', download_id),
                            'teamId': download_info.get('teamId', team_id),
                            'team_name': team_name_lookup.get(download_info.get('teamId', team_id), ''),
                            'userId': download_info.get('userId', ''),
                            'downloadPath': download_info.get('downloadPath', ''),
                            'url': download_info.get('url', ''),
                            'downloadState': download_info.get('downloadState', ''),
                            'startTime': self._parse_timestamp(download_info.get('startTime')),
                            'endTime': self._parse_timestamp(download_info.get('endTime'))
                        })

                # Create downloads CSV
                with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", newline="") as tmp_downloads_csv:
                    writer = csv.writer(tmp_downloads_csv)

                    # Write header
                    writer.writerow(['id', 'teamId', 'team_name', 'userId', 'downloadPath', 'url', 'downloadState', 'startTime', 'endTime'])

                    # Write downloads data
                    for download in downloads_data:
                        writer.writerow([
                            download['id'],
                            download['teamId'],
                            download['team_name'],
                            download['userId'],
                            download['downloadPath'],
                            download['url'],
                            download['downloadState'],
                            download['startTime'],
                            download['endTime']
                        ])

                    tmp_downloads_csv.flush()
                    downloads_csv_id = self.storage.upload_file(tmp_downloads_csv.name)

                    transforms.append(
                        Transform(
                            type="slack_downloads",
                            object_id=f"{downloads_csv_id}",
                            metadata={
                                "file_name": f"{file_enriched.file_name}_downloads.csv",
                                "offer_as_download": True,
                            },
                        )
                    )

                enrichment_result.transforms = transforms
                return enrichment_result

        except Exception as e:
            logger.exception(e, message="Error processing Slack root-state.json file")
            return None


def create_enrichment_module() -> EnrichmentModule:
    return SlackRootStateParser()