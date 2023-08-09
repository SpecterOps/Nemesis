# Standard Libraries

# 3rd Party Libraries
import enrichment.lib.file_parsers.Meta as Meta
import enrichment.lib.helpers as helpers
import LnkParse3
import nemesispb.nemesis_pb2 as pb


class lnk(Meta.FileType):
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
        return self.file_data.path.lower().endswith(".lnk")

    def check_content(self) -> bool:
        """
        Returns True if the internal File contents matches our target criteria.
        """
        return helpers.get_magic_type(self.file_path).startswith("MS Windows shortcut")

    def parse(self) -> tuple[pb.ParsedData, pb.AuthenticationDataIngestionMessage]:
        """
        Parses the file if parsing is defined, including any reversible decryption.
        """

        parsed_data = pb.ParsedData()

        try:
            with open(self.file_path, "rb") as f:
                lnk = LnkParse3.lnk_file(f)

            lnk_json = lnk.get_json()

            if "working_directory" in lnk_json["data"]:
                parsed_data.lnk.working_directory = lnk_json["data"]["working_directory"]

            if "description" in lnk_json["data"]:
                parsed_data.lnk.comment = lnk_json["data"]["description"]

            if "command_line_arguments" in lnk_json["data"]:
                parsed_data.lnk.command_line_arguments = lnk_json["data"]["command_line_arguments"]

            if (
                "extra" in lnk_json
                and "DISTRIBUTED_LINK_TRACKER_BLOCK" in lnk_json["extra"]
                and "machine_identifier" in lnk_json["extra"]["DISTRIBUTED_LINK_TRACKER_BLOCK"]
            ):
                parsed_data.lnk.machine_identifier = lnk_json["extra"]["DISTRIBUTED_LINK_TRACKER_BLOCK"]["machine_identifier"]

            if "file_size" in lnk_json["header"]:
                parsed_data.lnk.target_file_size = lnk_json["header"]["file_size"]

            if "link_flags" in lnk_json["header"] and "RunAsUser" in lnk_json["header"]["link_flags"]:
                parsed_data.lnk.run_as_admin = True

            if "location" in lnk_json["link_info"]:
                parsed_data.lnk.location = lnk_json["link_info"]["location"].lower()

                if parsed_data.lnk.location == "local":
                    if "local_base_path" in lnk_json["link_info"]:
                        parsed_data.lnk.target = lnk_json["link_info"]["local_base_path"]
                    else:
                        parsed_data.lnk.target = "ERROR: no local_base_path"
                elif parsed_data.lnk.location == "network":
                    if "net_name" in lnk_json["link_info"]["location_info"] and "common_path_suffix" in lnk_json["link_info"]:
                        base = lnk_json["link_info"]["location_info"]["net_name"]
                        target = lnk_json["link_info"]["common_path_suffix"]
                        parsed_data.lnk.target = f"{base}\\{target}"
                    else:
                        parsed_data.lnk.target = "ERROR: network net_name"
                else:
                    parsed_data.lnk.target = "ERROR: not local or network"

            if "creation_time" in lnk_json["header"]:
                # dt = datetime.datetime.strptime(lnk_json["header"]["creation_time"], "%Y-%m-%dT%H:%M:%S%z")
                parsed_data.lnk.creation_time.FromDatetime(lnk_json["header"]["creation_time"])

            if "accessed_time" in lnk_json["header"]:
                parsed_data.lnk.accessed_time.FromDatetime(lnk_json["header"]["accessed_time"])

            if "modified_time" in lnk_json["header"]:
                parsed_data.lnk.modified_time.FromDatetime(lnk_json["header"]["modified_time"])

            return (parsed_data, pb.AuthenticationDataIngestionMessage())

        except Exception as e:
            return (
                helpers.nemesis_parsed_data_error(f"error parsing lnk file {self.file_data.object_id} : {e}"),
                pb.AuthenticationDataIngestionMessage(),
            )
