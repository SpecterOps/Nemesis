# Standard Libraries
import sqlite3

# 3rd Party Libraries
import enrichment.lib.file_parsers.Meta as Meta
import enrichment.lib.helpers as helpers
import nemesispb.nemesis_pb2 as pb


class chromium_cookies(Meta.FileType):
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
        if chromium_file_path.success and chromium_file_path.file_type == "cookies":
            return True
        else:
            return False

    def check_content(self) -> bool:
        """
        Returns True if the internal File contents matches our target criteria
        using the associated Yara rule.
        """
        return helpers.scan_with_yara(self.file_path, "chromium_cookies")

    def parse(self) -> tuple[pb.ParsedData, pb.AuthenticationDataIngestionMessage] | pb.ParsedData:
        """
        Parses the file if parsing is defined, including any reversible decryption.
        """
        # build protobuf w/o the actual entries, detect/reprocess on the file side

        parsed_data = pb.ParsedData()

        chromium_file_path = helpers.parse_chromium_file_path(self.file_data.path)
        parsed_data.chromium_cookies.user_data_directory = chromium_file_path.user_data_directory
        parsed_data.chromium_cookies.browser = chromium_file_path.browser
        parsed_data.chromium_cookies.username = chromium_file_path.username

        try:
            with sqlite3.connect(self.file_path) as con:
                cur = con.cursor()
                res = cur.execute("SELECT Count(*) FROM cookies")
                cookies_count = res.fetchone()
                if cookies_count:
                    parsed_data.chromium_cookies.cookies_count = cookies_count[0]
                return (parsed_data, pb.AuthenticationDataIngestionMessage())

        except Exception as e:
            return (
                helpers.nemesis_parsed_data_error(f"error parsing Chromium 'Cookies' file {self.file_data.object_id} : {e}"),
                pb.AuthenticationDataIngestionMessage(),
            )
